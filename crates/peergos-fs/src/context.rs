//! `UserContext`: the top-level handle to a Peergos account, in the spirit of
//! Java's `UserContext`. It bundles the network handles (block store, mutable
//! pointers, HTTP poster) with the signed-in identity (or a secret-link
//! capability) and hands out [`FileWrapper`]s for navigating the filesystem.
//!
//! Create one by [`UserContext::sign_in`], [`UserContext::sign_up`], or
//! [`UserContext::from_secret_link`]. A full sign-in carries the home directory,
//! which anchors crash-safe multi-chunk uploads (the `.transactions` directory);
//! a secret-link context has no home, so its uploads stay atomic — matching Java,
//! where a public/secret link has a `null` transaction service.

use crate::cache::CryptreeCache;
use crate::capability::AbsoluteCapability;
use crate::filewrapper::FileWrapper;
use crate::login::{login, LoggedInUser, MfaResponder};
use crate::mfa::{MultiFactorAuthResponse, MultiFactorAuthRequest, WebauthnResponse};
use crate::signup::signup;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::error::{Error, Result};
use peergos_core::auth::{BatId, BatWithId};
use peergos_core::keys::SecretSigningKey;
use peergos_core::mutable::MutablePointers;
use peergos_core::storage::{url_encode, ContentAddressedStorage};
use peergos_core::HttpPoster;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SPACE_USAGE_URL: &str = "peergos/v0/storage/";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `TimeLimitedClient.signNow`: sign `CborLong(now_millis)` with the identity key —
/// the auth token the space-usage endpoints expect.
fn signed_now(secret: &SecretSigningKey) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    Ok(to_hex(&secret.sign_message(&CborObject::Long(now).to_bytes())?))
}

fn parse_cbor_long(res: &[u8]) -> Result<i64> {
    CborObject::from_bytes(res)?
        .as_long()
        .ok_or_else(|| Error::Protocol("expected a CBOR long response".into()))
}

/// The payload signed and sent to `requestQuota`, mirroring `QuotaControl.SpaceRequest`.
struct SpaceRequest {
    username: String,
    bytes: i64,
    annual: bool,
    utc_millis: i64,
    payment_proof: Option<Vec<u8>>,
}

impl Cborable for SpaceRequest {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("u", CborObject::Str(self.username.clone()))
            .put("s", CborObject::Long(self.bytes))
            .put("a", CborObject::Boolean(self.annual))
            .put("t", CborObject::Long(self.utc_millis))
            .put_opt("p", self.payment_proof.as_ref().map(|p| CborObject::ByteString(p.clone())))
            .build()
    }
}

/// The response from `requestQuota`, mirroring `PaymentProperties`.
#[derive(Debug, Clone)]
pub struct PaymentProperties {
    pub payment_server_url: Option<String>,
    pub client_secret: Option<String>,
    pub error: Option<String>,
    pub free_quota: i64,
    pub desired_quota: i64,
    pub annual: bool,
    pub expiry_epoch_secs: Option<i64>,
    pub next_charge: i64,
}

impl PaymentProperties {
    fn from_cbor(cbor: &CborObject) -> Result<Self> {
        Ok(PaymentProperties {
            payment_server_url: cbor.get("url").and_then(|v| v.as_string().map(|s| s.to_string())),
            client_secret: cbor.get("client_secret").and_then(|v| v.as_string().map(|s| s.to_string())),
            error: cbor.get("err").and_then(|v| v.as_string().map(|s| s.to_string())),
            free_quota: cbor.get("freeQuota").and_then(|v| v.as_long()).unwrap_or(0),
            desired_quota: cbor.get("desiredQuota").and_then(|v| v.as_long()).unwrap_or(0),
            annual: cbor.get("annual").and_then(|v| v.as_bool()).unwrap_or(false),
            expiry_epoch_secs: cbor.get("expiry").and_then(|v| v.as_long()),
            next_charge: cbor.get("nextCharge").and_then(|v| v.as_long()).unwrap_or(0),
        })
    }
}

impl Cborable for PaymentProperties {
    fn to_cbor(&self) -> CborObject {
        let b = CborObject::map()
            .put("freeQuota", CborObject::Long(self.free_quota))
            .put("desiredQuota", CborObject::Long(self.desired_quota))
            .put("annual", CborObject::Boolean(self.annual))
            .put("nextCharge", CborObject::Long(self.next_charge));
        let b = match &self.payment_server_url {
            Some(url) => b.put("url", CborObject::Str(url.clone())),
            None => b,
        };
        let b = match &self.error {
            Some(err) => b.put("err", CborObject::Str(err.clone())),
            None => b,
        };
        let b = match &self.client_secret {
            Some(s) => b.put("client_secret", CborObject::Str(s.clone())),
            None => b,
        };
        let b = match self.expiry_epoch_secs {
            Some(e) => b.put("expiry", CborObject::Long(e)),
            None => b,
        };
        b.build()
    }
}

/// A handle to a Peergos account (full login) or a shared capability (secret link).
#[derive(Clone)]
pub struct UserContext {
    /// The signed-in user (identity, keys, entry points). `None` for a secret link.
    user: Option<LoggedInUser>,
    /// Root capabilities of a secret-link context (empty for a full login).
    link_caps: Vec<AbsoluteCapability>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: Arc<dyn MutablePointers>,
    poster: Arc<dyn HttpPoster>,
    /// One decrypted-cryptree-node cache shared by every `FileWrapper` this context
    /// hands out (Java's `NetworkAccess.cache`).
    cache: CryptreeCache,
}

impl UserContext {
    /// Sign in with a username and password (`UserContext.signIn`).
    ///
    /// Since it isn't known ahead of time whether the account has a second factor,
    /// every sign-in is MFA-capable: `mfa` is invoked only if the server requests a
    /// second factor (see [`crate::mfa`]). Pass `None` if you can't answer one, or
    /// use [`UserContext::sign_in_with_totp`] for the TOTP case.
    pub async fn sign_in(
        username: &str,
        password: &str,
        mfa: Option<&MfaResponder<'_>>,
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<UserContext> {
        let user = login(username, password, poster.as_ref(), store.clone(), mutable.as_ref(), mfa).await?;
        Ok(UserContext { user: Some(user), link_caps: Vec::new(), store, mutable, poster, cache: CryptreeCache::new() })
    }

    /// Sign in to a TOTP-protected account, generating the current code from the
    /// authenticator `totp_secret` (the raw key bytes, e.g. [`TotpKey.key`]).
    pub async fn sign_in_with_totp(
        username: &str,
        password: &str,
        totp_secret: &[u8],
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<UserContext> {
        let secret = totp_secret.to_vec();
        let responder = move |req: &crate::mfa::MultiFactorAuthRequest| {
            let method = req
                .totp_method()
                .ok_or_else(|| Error::Protocol("server did not offer a TOTP factor".into()))?;
            Ok(MultiFactorAuthResponse::new_totp(
                method.credential_id.clone(),
                crate::mfa::current_totp(&secret),
            ))
        };
        Self::sign_in(username, password, Some(&responder), poster, store, mutable).await
    }

    /// Sign in to a WebAuthn-protected account. `webauthn_responder` is called
    /// with the server's [`MultiFactorAuthRequest`] (which carries the challenge
    /// and the list of registered WebAuthn credentials); it should perform the
    /// WebAuthn `navigator.credentials.get()` ceremony and return the assertion
    /// response.
    pub async fn sign_in_with_webauthn<F>(
        username: &str,
        password: &str,
        webauthn_responder: F,
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<UserContext>
    where
        F: Fn(&MultiFactorAuthRequest) -> Result<WebauthnResponse>,
    {
        let responder = move |req: &MultiFactorAuthRequest| {
            let method = req
                .webauthn_method()
                .ok_or_else(|| Error::Protocol("server did not offer a WebAuthn factor".into()))?;
            let webauthn_resp = webauthn_responder(req)?;
            Ok(MultiFactorAuthResponse::new_webauthn(
                method.credential_id.clone(),
                webauthn_resp,
            ))
        };
        Self::sign_in(username, password, Some(&responder), poster, store, mutable).await
    }

    /// Register a new account then sign in (`UserContext.signUp`).
    pub async fn sign_up(
        username: &str,
        password: &str,
        token: Option<&str>,
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<UserContext> {
        signup(username, password, token, poster.as_ref(), store.as_ref()).await?;
        Self::sign_in(username, password, None, poster, store, mutable).await
    }

    /// Open a read/write context over a secret link (`UserContext.fromSecretLink`).
    /// `user_password` is required only if the link was locked with one.
    pub async fn from_secret_link(
        link: &str,
        user_password: Option<&str>,
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<UserContext> {
        let cap = crate::retrieve_secret_link_capability(link, store.as_ref(), user_password).await?;
        Ok(UserContext { user: None, link_caps: vec![cap], store, mutable, poster, cache: CryptreeCache::new() })
    }

    /// Rebuild a context from a previously-saved [`LoggedInUser`] session, skipping
    /// the password KDF and login round-trips entirely (`stay logged in`). The
    /// caller is responsible for having obtained the session securely; the entry
    /// points may be slightly stale (e.g. a friend added since it was saved).
    pub fn from_session(
        user: LoggedInUser,
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> UserContext {
        UserContext { user: Some(user), link_caps: Vec::new(), store, mutable, poster, cache: CryptreeCache::new() }
    }

    // ---- accessors ---------------------------------------------------------

    /// The signed-in username, if this is a full login.
    pub fn username(&self) -> Option<&str> {
        self.user.as_ref().map(|u| u.username.as_str())
    }

    /// The underlying signed-in user (for the social / sharing APIs).
    pub fn user(&self) -> Option<&LoggedInUser> {
        self.user.as_ref()
    }

    /// True for a secret-link context (no identity / home directory).
    pub fn is_secret_link(&self) -> bool {
        self.user.is_none()
    }

    pub fn store(&self) -> Arc<dyn ContentAddressedStorage> {
        self.store.clone()
    }
    pub fn mutable(&self) -> Arc<dyn MutablePointers> {
        self.mutable.clone()
    }
    /// The logged-in user's mirror BAT id (hash form), threaded into block writes
    /// so raw fragments and cryptree nodes are gated for the storage mirror.
    pub fn mirror_bat_id(&self) -> Option<BatId> {
        self.user.as_ref().and_then(|u| u.mirror_bat_id())
    }
    pub fn poster(&self) -> Arc<dyn HttpPoster> {
        self.poster.clone()
    }

    /// Wrap this context's storage + mutable-pointer layers in the client-side
    /// caches — a small in-RAM cbor block cache and a pointer cache (7s TTL,
    /// invalidated on writes) — and return the cached context.
    ///
    /// Intended for a **single-user interactive session** (a CLI, a desktop app):
    /// it cuts the redundant round-trips a single operation makes re-resolving the
    /// same writer pointer + `WriterData`. Do **not** use it in a process that
    /// drives several users against one server — the pointer TTL would hide another
    /// user's concurrent writes for up to 7 seconds.
    pub fn with_session_caches(mut self) -> UserContext {
        self.mutable = Arc::new(peergos_core::CachedMutablePointers::new(self.mutable.clone()));
        self.store = Arc::new(peergos_core::CachedStorage::new(self.store.clone()));
        self
    }

    // ---- filesystem --------------------------------------------------------

    /// The user's home directory as a [`FileWrapper`] (errors on a secret-link
    /// context, which has no home).
    pub async fn get_home(&self) -> Result<FileWrapper> {
        let user = self
            .user
            .as_ref()
            .ok_or_else(|| Error::Protocol("no home directory in a secret-link context".into()))?;
        Ok(FileWrapper::home(user, self.store.clone(), self.mutable.clone()).await?.with_cache(self.cache.clone()))
    }

    /// The entry-point roots of this context: the home + accepted friend roots for
    /// a full login (named by owner), or the shared capability for a secret link.
    pub async fn roots(&self) -> Result<Vec<FileWrapper>> {
        let mut out = Vec::new();
        if let Some(user) = &self.user {
            // `.transactions` always lives under our own home, whichever root we
            // are looking at, so every root carries our home as its upload anchor.
            let home = user.home().cloned();
            for e in &user.entries {
                let signer = crate::recover_signer(&e.pointer, self.store.clone(), self.mutable.as_ref())
                    .await
                    .ok();
                out.push(
                    FileWrapper::from_cap(
                        e.pointer.clone(),
                        e.owner_name.clone(),
                        e.owner_name.clone(),
                        signer,
                        home.clone(),
                        self.store.clone(),
                        self.mutable.clone(),
                    )
                    .await?
                    .with_cache(self.cache.clone())
                    .with_mirror_bat(self.mirror_bat_id()),
                );
            }
        } else {
            for cap in &self.link_caps {
                let signer =
                    crate::recover_signer(cap, self.store.clone(), self.mutable.as_ref()).await.ok();
                out.push(
                    FileWrapper::from_link_cap(cap.clone(), signer, self.store.clone(), self.mutable.clone())
                        .await?
                        .with_cache(self.cache.clone()),
                );
            }
        }
        Ok(out)
    }

    /// Resolve a path (`UserContext.getByPath`). Accepts an absolute path whose
    /// first component names a root (`/username/a/b`), a path into a directory a
    /// friend has shared with us (`/friend/.../shared/...`), or — for a logged-in
    /// user — a path relative to home (`a/b`). For a secret-link context a bare path
    /// is resolved relative to the shared root.
    ///
    /// Friend paths are resolved the way Java's entry-point trie does: the
    /// capabilities friends have shared with us carry their absolute path, so a
    /// query is matched against the deepest such capability that is an ancestor of
    /// it, and the remainder is navigated through the real filesystem.
    pub async fn get_by_path(&self, path: &str) -> Result<Option<FileWrapper>> {
        let comps: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
        let roots = self.roots().await?;

        if comps.is_empty() {
            return if self.user.is_some() {
                Ok(Some(self.get_home().await?))
            } else {
                Ok(roots.into_iter().next())
            };
        }

        // First component names a root?
        if let Some(root) = roots.iter().find(|r| r.name() == comps[0]) {
            if let Some(found) = root.get_by_path(&comps[1..].join("/")).await? {
                return Ok(Some(found));
            }
        }
        if self.user.is_some() {
            // A logged-in user: try relative to home, then fall back to a directory
            // a friend has shared with us (their absolute path).
            if let Some(found) = self.get_home().await?.get_by_path(&comps.join("/")).await? {
                return Ok(Some(found));
            }
            if let Some(found) = self.resolve_shared_with_us(&comps).await? {
                return Ok(Some(found));
            }
            return Ok(None);
        }
        // Single secret-link root: treat as relative to it.
        if roots.len() == 1 {
            return roots.into_iter().next().unwrap().get_by_path(&comps.join("/")).await;
        }
        Ok(None)
    }

    /// Resolve a path into a directory a friend has shared with us. The first
    /// component names the friend; among the capabilities they've shared, pick the
    /// deepest whose path is an ancestor of (or equal to) the query and navigate the
    /// remaining components from there.
    async fn resolve_shared_with_us(&self, comps: &[&str]) -> Result<Option<FileWrapper>> {
        let user = match &self.user {
            Some(u) => u,
            None => return Ok(None),
        };
        let owner = comps[0];
        if Some(owner) == self.username() {
            return Ok(None);
        }
        let friend = match crate::get_friends(user, self.store.clone(), self.mutable.as_ref())
            .await?
            .into_iter()
            .find(|e| e.owner_name == owner)
        {
            Some(f) => f,
            None => return Ok(None),
        };

        // All capabilities this friend has shared with us, each with its path.
        let mut shared = crate::load_read_access_sharing_links(&friend.pointer, 0, self.store.clone(), self.mutable.as_ref())
            .await?
            .capabilities;
        shared.extend(
            crate::load_write_access_sharing_links(&friend.pointer, 0, self.store.clone(), self.mutable.as_ref())
                .await?
                .capabilities,
        );

        // Find the deepest shared cap whose path is an ancestor of the query.
        let mut best: Option<(usize, AbsoluteCapability, String)> = None;
        for cwp in &shared {
            let cap_comps: Vec<&str> = cwp.path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
            if cap_comps.len() <= comps.len() && cap_comps[..] == comps[..cap_comps.len()] {
                let deeper = best.as_ref().map(|(n, _, _)| cap_comps.len() > *n).unwrap_or(true);
                if deeper {
                    let name = cap_comps.last().copied().unwrap_or(owner).to_string();
                    best = Some((cap_comps.len(), cwp.cap.clone(), name));
                }
            }
        }
        let (matched, cap, name) = match best {
            Some(b) => b,
            None => return Ok(None),
        };

        let home_cap = user.home().cloned();
        let dir = FileWrapper::from_cap(
            cap,
            name,
            comps[..matched].join("/"),
            None,
            home_cap,
            self.store.clone(),
            self.mutable.clone(),
        )
        .await?
        .with_cache(self.cache.clone())
        .with_mirror_bat(self.mirror_bat_id());
        dir.get_by_path(&comps[matched..].join("/")).await
    }

    /// The children of the directory at `path` (`getChildren`). Empty if the path
    /// doesn't resolve, or resolves to a file.
    pub async fn get_children(&self, path: &str) -> Result<Vec<FileWrapper>> {
        match self.get_by_path(path).await? {
            Some(dir) if dir.is_directory() => dir.children().await,
            _ => Ok(Vec::new()),
        }
    }

    /// Mirror this account's login data onto the current server so it can serve
    /// logins after a migration (`mirrorLoginData`). Non-legacy accounts only.
    pub async fn mirror_login_data(&self, password: &str, mfa: Option<&MfaResponder<'_>>) -> Result<bool> {
        let user = self.require_user()?;
        crate::login::mirror_login_data(
            &user.username,
            password,
            &user.signer,
            mfa,
            self.poster.as_ref(),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await
    }

    /// Ask the current server to mirror this account's data, authorised by a signed
    /// timestamp + proof-of-work (`mirrorOnThisServer`, unpaid path). Requires a
    /// mirror BAT.
    pub async fn mirror_on_this_server(&self) -> Result<bool> {
        let user = self.require_user()?;
        let mirror_bat = user.mirror_bat.clone().ok_or_else(|| Error::Protocol("You need a mirror bat!".into()))?;
        crate::migrate::start_mirror(self.poster.as_ref(), &user.username, &mirror_bat, &user.signer).await
    }

    /// Migrate this account's home server to the current server
    /// (`migrateToThisServer`): fetch the username claim chain, append a link naming
    /// this server as the storage provider, and commit it. Returns the raw
    /// `UserSnapshot` cbor the server returns. `password`/`mfa` are accepted for
    /// signature parity with the Java API (the current session's identity signer is
    /// used to sign the new claim).
    pub async fn migrate_to_this_server(&self, _password: &str, _mfa: Option<&MfaResponder<'_>>) -> Result<CborObject> {
        let user = self.require_user()?;
        let existing = crate::migrate::get_chain(self.poster.as_ref(), &user.username).await?;
        let last = existing.last().ok_or_else(|| Error::Protocol("empty claim chain".into()))?;
        let original_node_id = crate::migrate::claim_storage_provider(last)?;
        let usage = self.get_usage().await?;
        let this_server = self.store.id().await?;
        let new_chain = crate::migrate::build_migration_chain(&existing, &this_server, &user.signer.secret)?;
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        crate::migrate::migrate_user(
            self.poster.as_ref(),
            &user.username,
            &new_chain,
            &original_node_id,
            user.mirror_bat.as_ref(),
            now_secs,
            usage,
        )
        .await
    }

    /// The user's mirror BAT (`getMirrorBat`), fetched from the server's bats
    /// endpoint and authorised by a time-limited signed request. `None` if the
    /// account has no registered BAT. Used to keep secret-link data private.
    pub async fn get_mirror_bat(&self) -> Result<Option<BatWithId>> {
        // Fetched once at login and cached on the user.
        Ok(self.require_user()?.mirror_bat.clone())
    }

    /// Generate a shareable secret link to the file/dir at `path`
    /// (`UserContext.createSecretLink`). `user_password` may be empty (no extra
    /// password); `expiry` (epoch seconds) and `max_retrievals` are optional
    /// server-enforced limits. Returns the link string
    /// `secret/z<owner>/<label>#<password>`, resolvable via
    /// [`crate::retrieve_secret_link_capability`] / [`UserContext::from_secret_link`].
    ///
    /// A `writable` link grants write access, so — matching Java — the target is
    /// first relocated into its own writing space (its keys rotate if it was sharing
    /// the parent's writer); every EXISTING share and secret link to it is then
    /// re-sent / re-minted to the new capability before the new link is minted, so
    /// nothing breaks. We assert the target's writer differs from its parent's.
    pub async fn create_secret_link(
        &self,
        path: &str,
        writable: bool,
        user_password: &str,
        expiry_epoch_secs: Option<i64>,
        max_retrievals: Option<i64>,
    ) -> Result<String> {
        let user = self.require_user()?;
        let mirror = self.get_mirror_bat().await?;
        let cap = if writable {
            // shareWriteAccessWith(file, {}) — ensure the target has its own writer.
            let trimmed = path.trim_matches('/');
            let (parent_path, name) = match trimmed.rsplit_once('/') {
                Some((p, n)) => (p, n),
                None => ("", trimmed),
            };
            let parent = self
                .get_by_path(parent_path)
                .await?
                .ok_or_else(|| Error::Protocol(format!("no parent directory for {path}")))?;
            let parent_cap = parent.capability().clone();
            let target = parent
                .child(name)
                .await?
                .ok_or_else(|| Error::Protocol(format!("no file at {path}")))?;
            let mb = self.require_user()?.mirror_bat_id();
            let writable_cap = if target.is_directory() {
                crate::move_dir_to_own_writer(&parent_cap, name, parent.signer().cloned(), mb.as_ref(), self.store.clone(), self.mutable.as_ref()).await?
            } else {
                crate::move_file_to_own_writer(&parent_cap, name, parent.signer().cloned(), mb.as_ref(), self.store.clone(), self.mutable.as_ref()).await?
            };
            // The relocation should have given it its own writer; assert the invariant.
            if writable_cap.writer == parent_cap.writer {
                return Err(Error::Protocol(
                    "a writable secret link's target must be in a different writing space to its parent".into(),
                ));
            }
            // Rotation invalidated the old cap: re-send all existing shares and
            // re-mint all existing links to the new one (Java reSendAllSharesAndLinks).
            self.reshare_all_shares_and_links(path).await?;
            writable_cap
        } else {
            self.get_by_path(path)
                .await?
                .ok_or_else(|| Error::Protocol(format!("no file at {path}")))?
                .capability()
                .read_only()
        };
        let link = crate::create_secret_link(
            &cap,
            user_password,
            expiry_epoch_secs,
            max_retrievals,
            &user.signer,
            mirror.as_ref(),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        // Record the link so a future rotation re-mints it (Java addSecretLink).
        crate::record_link(
            user,
            path,
            crate::LinkProperties {
                label: link.label,
                link_password: link.link_password.clone(),
                user_password: user_password.to_string(),
                writable,
                open: false,
                max_retrievals,
                expiry_epoch_secs,
            },
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        Ok(link.to_link())
    }

    /// A snapshot of the user's social state (`getSocialState`): pending incoming
    /// follow requests + friend/following roots. See [`crate::SocialState`] for the
    /// fields Java includes that this subset does not yet populate.
    pub async fn social_state(&self) -> Result<crate::SocialState> {
        let user = self.require_user()?;
        let (store, mutable) = (self.store.clone(), self.mutable.as_ref());
        let pending_incoming_requests = crate::get_follow_requests(user, self.poster.as_ref()).await?;
        let pending_outgoing = crate::get_pending_outgoing(user, store.clone(), mutable).await?;
        let following = crate::get_following(user, store.clone(), mutable).await?;
        let followers = crate::get_follower_names(user, store.clone(), mutable).await?;
        let blocked = crate::get_blocked(user, store.clone(), mutable).await?;
        let friends = crate::get_friends(user, store, mutable).await?;
        Ok(crate::SocialState {
            pending_incoming_requests,
            pending_outgoing,
            following,
            followers,
            blocked,
            friends,
        })
    }

    /// Block/unfollow `username` (`unfollow`): adds them to the blocked list.
    pub async fn unfollow(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::unfollow(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The sharing state of every child of the directory at home-relative `dir_path`
    /// (`getDirectorySharingState`) — read/write recipients and links per child.
    pub async fn get_directory_sharing_state(&self, dir_path: &str) -> Result<crate::SharedWithState> {
        let user = self.require_user()?;
        crate::get_directory_sharing_state(user, dir_path, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The usernames the user has blocked (`getBlocked`).
    pub async fn get_blocked(&self) -> Result<Vec<String>> {
        let user = self.require_user()?;
        crate::get_blocked(user, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Block `username` so their shared entry points are no longer honoured.
    pub async fn block(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::block(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Unblock `username` (`unblock`): remove them from the blocked list.
    pub async fn unblock(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::unblock(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The user's friend annotations, keyed by username (`getFriendAnnotations`).
    pub async fn get_friend_annotations(&self) -> Result<std::collections::BTreeMap<String, crate::FriendAnnotation>> {
        let user = self.require_user()?;
        crate::get_friend_annotations(user, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Add or replace a friend annotation (`addFriendAnnotation`).
    pub async fn add_friend_annotation(&self, annotation: crate::FriendAnnotation) -> Result<()> {
        let user = self.require_user()?;
        crate::add_friend_annotation(user, annotation, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Remove `username` as a follower (`removeFollower`): revoke every file ever
    /// shared with them (rotating each file's keys and re-sharing to the remaining
    /// recipients) and delete their `/shared/<username>` folder.
    pub async fn remove_follower(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        let (store, mutable) = (self.store.clone(), self.mutable.as_ref());
        // Revoke everything shared with them.
        for (dir_path, child, access) in crate::collect_shares_for_user(user, username, store.clone(), mutable).await? {
            let parent = self
                .get_by_path(&dir_path)
                .await?
                .ok_or_else(|| Error::Protocol(format!("shared dir {dir_path} not found")))?;
            let parent_cap = parent.capability().clone();
            let revoked = [username.to_string()];
            match access {
                crate::Access::Read => {
                    crate::unshare_read_access(user, &dir_path, &parent_cap, &child, &revoked, store.clone(), mutable).await?;
                }
                crate::Access::Write => {
                    crate::unshare_write_access(user, &dir_path, &parent_cap, &child, &revoked, store.clone(), mutable).await?;
                }
            }
        }
        // Delete their sharing folder /<us>/shared/<username>.
        if let Some(shared) = self.get_home().await?.child("shared").await? {
            if shared.child(username).await?.is_some() {
                shared.remove_child(username).await?;
            }
        }
        Ok(())
    }

    /// Change this account's password (`changePassword`). Re-derives the login key
    /// from `new_password` (keeping the salt; the identity is unchanged) and pushes
    /// the re-encrypted login data to the server. After it returns, sign in again
    /// with the new password. `mfa` answers a second-factor challenge if required.
    pub async fn change_password(
        &self,
        old_password: &str,
        new_password: &str,
        mfa: Option<&crate::MfaResponder<'_>>,
    ) -> Result<()> {
        let user = self.require_user()?;
        crate::change_password(
            &user.username,
            old_password,
            new_password,
            mfa,
            self.poster.as_ref(),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await
    }

    /// Delete this account's filesystem (`deleteAccount`) — nulls the home and
    /// identity pointers. IRREVERSIBLE.
    pub async fn delete_account(&self) -> Result<()> {
        let user = self.require_user()?;
        let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?.clone();
        crate::delete_account(&user.identity, &user.signer, &home, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Delete a secret link by its `label` (`deleteSecretLink`): remove it from the
    /// identity writer's link CHAMP so it no longer resolves, and forget it from the
    /// shared-with cache for `path` (so a later rotation won't re-mint it).
    pub async fn delete_secret_link(&self, path: &str, label: i64) -> Result<()> {
        let user = self.require_user()?;
        let mirror = self.get_mirror_bat().await?;
        crate::delete_secret_link(
            &user.identity,
            &user.signer,
            label,
            mirror.as_ref(),
            &self.store,
            self.mutable.as_ref(),
        )
        .await?;
        crate::remove_link(user, path, label, self.store.clone(), self.mutable.as_ref()).await
    }

    /// After a target's keys rotate, re-send every recorded read/write share and
    /// re-mint every recorded secret link so they point at the new capability
    /// (Java `reSendAllSharesAndLinksRecursive` → `reshareAndUpdateLinks`).
    async fn reshare_all_shares_and_links(&self, path: &str) -> Result<()> {
        let user = self.require_user()?;
        let new_cap = self
            .get_by_path(path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no file at {path} after rotation")))?
            .capability()
            .clone();
        let trimmed = path.trim_matches('/');
        let (parent_path, name) = match trimmed.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", trimmed),
        };
        let parent_cap = self
            .get_by_path(parent_path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no parent for {path}")))?
            .capability()
            .clone();
        for u in crate::get_shared_with(user, path, crate::Access::Read, self.store.clone(), self.mutable.as_ref()).await? {
            crate::share_read_access(user, path, &new_cap, &u, self.store.clone(), self.mutable.as_ref()).await?;
        }
        for u in crate::get_shared_with(user, path, crate::Access::Write, self.store.clone(), self.mutable.as_ref()).await? {
            crate::share_write_access(user, parent_path, &parent_cap, name, &u, self.store.clone(), self.mutable.as_ref()).await?;
        }
        let mirror = self.get_mirror_bat().await?;
        for lp in crate::get_links(user, path, self.store.clone(), self.mutable.as_ref()).await? {
            let link_cap = if lp.writable { new_cap.clone() } else { new_cap.read_only() };
            let link = crate::SecretLink { owner: new_cap.owner.clone(), label: lp.label, link_password: lp.link_password.clone() };
            crate::put_secret_link(
                &link_cap,
                &link,
                &lp.user_password,
                lp.expiry_epoch_secs,
                lp.max_retrievals,
                &user.signer,
                mirror.as_ref(),
                self.store.clone(),
                self.mutable.as_ref(),
            )
            .await?;
        }
        Ok(())
    }

    /// Open the incoming-capability cache — your local mirror of everything shared
    /// with you (`IncomingCapCache`). Call `update_from_friend` on it to pull a
    /// friend's newly-shared caps into the mirror, then `get_by_path`/`get_children`.
    pub async fn incoming_cap_cache(&self) -> Result<crate::IncomingCapCache> {
        let user = self.require_user()?;
        crate::IncomingCapCache::build(user, self.store.clone(), self.mutable.clone()).await
    }

    // ---- storage quota / usage --------------------------------------------

    /// The storage quota granted to this account, in bytes (`getQuota`).
    pub async fn get_quota(&self) -> Result<i64> {
        let user = self.require_user()?;
        let auth = signed_now(&user.signer.secret)?;
        let url = format!(
            "{SPACE_USAGE_URL}quota?owner={}&auth={auth}",
            url_encode(&user.identity.to_string()),
        );
        parse_cbor_long(&self.poster.get(&url).await?)
    }

    /// The hostname serving this user's secret/public links (`getLinkHost`), for
    /// building shareable link URLs. `"localhost"` when the store isn't a Peergos
    /// server.
    pub async fn get_link_host(&self) -> Result<String> {
        let user = self.require_user()?;
        self.store.link_host(&user.identity).await
    }

    /// The storage currently used by this account across the network, in bytes
    /// (`getSpaceUsage`).
    pub async fn get_usage(&self) -> Result<i64> {
        self.usage(false).await
    }

    /// The storage used by this account on this server only, in bytes
    /// (`getSpaceUsage(localUsage = true)`).
    pub async fn get_local_usage(&self) -> Result<i64> {
        self.usage(true).await
    }

    async fn usage(&self, local: bool) -> Result<i64> {
        let user = self.require_user()?;
        let auth = signed_now(&user.signer.secret)?;
        let url = format!(
            "{SPACE_USAGE_URL}usage?owner={}&local={local}&auth={auth}",
            url_encode(&user.identity.to_string()),
        );
        parse_cbor_long(&self.poster.get(&url).await?)
    }

    /// Request additional storage quota (`requestSpace`). The server may grant it
    /// immediately (returning updated `PaymentProperties` with the new `free_quota`)
    /// or redirect to a payment page (`payment_server_url`).
    pub async fn request_quota(&self, requested_quota: i64, annual: bool) -> Result<PaymentProperties> {
        let user = self.require_user()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let req = SpaceRequest {
            username: user.username.clone(),
            bytes: requested_quota,
            annual,
            utc_millis: now,
            payment_proof: None,
        };
        let signed = user.signer.secret.sign_message(&req.serialize())?;
        let auth = to_hex(&signed);
        let url = format!(
            "{SPACE_USAGE_URL}request?owner={}&req={auth}",
            url_encode(&user.identity.to_string()),
        );
        let res = self.poster.get(&url).await?;
        PaymentProperties::from_cbor(&CborObject::from_bytes(&res)?)
    }

    /// Fetch payment properties (`getPaymentProperties`). Returns the account's
    /// current quota info, payment server URL (if applicable), and billing details.
    /// Pass `new_client_secret = true` to request a fresh client secret for a
    /// payment session.
    pub async fn get_payment_properties(&self, new_client_secret: bool) -> Result<PaymentProperties> {
        let user = self.require_user()?;
        let auth = signed_now(&user.signer.secret)?;
        let url = format!(
            "{SPACE_USAGE_URL}payment-properties?owner={}&new-client-secret={new_client_secret}&auth={auth}",
            url_encode(&user.identity.to_string()),
        );
        let res = self.poster.get(&url).await?;
        PaymentProperties::from_cbor(&CborObject::from_bytes(&res)?)
    }

    // ---- admin operations --------------------------------------------------

    /// Get the server's version info (`version`).
    pub async fn get_version_info(&self) -> Result<crate::admin::VersionInfo> {
        crate::admin::get_version_info(self.poster.as_ref()).await
    }

    /// Check whether the server is accepting signups (`signups`).
    pub async fn accepting_signups(&self) -> Result<crate::admin::AllowedSignups> {
        crate::admin::accepting_signups(self.poster.as_ref()).await
    }

    /// Add an email to the server's waitlist (`waitlist`).
    pub async fn add_to_waitlist(&self, email: &str) -> Result<bool> {
        crate::admin::add_to_waitlist(email, self.poster.as_ref()).await
    }

    /// Get the list of pending space requests (`pending`). The signed-in user must
    /// be an admin on the server identified by `instance` (its peer ID).
    pub async fn get_pending_space_requests(&self, instance: &peergos_multiformats::Cid) -> Result<Vec<crate::admin::LabelledSignedSpaceRequest>> {
        let user = self.require_user()?;
        crate::admin::get_pending_space_requests(user, instance, self.poster.as_ref()).await
    }

    /// Approve a pending space request (`approve`). The signed-in user must be an
    /// admin on the server identified by `instance`.
    pub async fn approve_space_request(&self, instance: &peergos_multiformats::Cid, request: &crate::admin::LabelledSignedSpaceRequest) -> Result<bool> {
        let user = self.require_user()?;
        crate::admin::approve_space_request(user, instance, request, self.poster.as_ref()).await
    }

    // ---- second-factor (MFA) management -----------------------------------

    /// The account's registered second factors (`listMfa`).
    pub async fn list_second_factors(&self) -> Result<Vec<crate::mfa::MultiFactorAuthMethod>> {
        let user = self.require_user()?;
        crate::account::list_second_factors(user, self.poster.as_ref()).await
    }

    /// Enrol a TOTP second factor and activate it in one step: `addTotp` to obtain
    /// the shared secret, then `enableTotp` proving the current code. Returns the
    /// [`TotpKey`](crate::mfa::TotpKey) (store its `key`, or show `otpauth_uri`, so
    /// future logins can generate codes).
    pub async fn enroll_totp(&self) -> Result<crate::mfa::TotpKey> {
        let user = self.require_user()?;
        let key = crate::account::add_totp_factor(user, self.poster.as_ref()).await?;
        let accepted =
            crate::account::enable_totp_factor(user, &key.credential_id, &key.current_code(), self.poster.as_ref())
                .await?;
        if !accepted {
            return Err(Error::Protocol("server rejected the TOTP enrollment code".into()));
        }
        Ok(key)
    }

    /// Remove a registered second factor by credential id (`deleteMfa`).
    pub async fn delete_second_factor(&self, credential_id: &[u8]) -> Result<bool> {
        let user = self.require_user()?;
        crate::account::delete_second_factor(user, credential_id, self.poster.as_ref()).await
    }

    // ---- WebAuthn security key registration --------------------------------

    /// Start WebAuthn security key registration (`registerWebauthnStart`):
    /// returns the 32-byte challenge from the server. Pass it to
    /// `navigator.credentials.create()`, then call
    /// [`register_security_key_complete`] with the resulting credential.
    pub async fn register_security_key_start(&self) -> Result<Vec<u8>> {
        let user = self.require_user()?;
        crate::account::register_security_key_start(user, self.poster.as_ref()).await
    }

    /// Complete WebAuthn security key registration (`registerWebauthnComplete`).
    /// `key_name` is a human-readable label; `response` contains the credential
    /// from the WebAuthn ceremony wrapped in a [`MultiFactorAuthResponse`].
    pub async fn register_security_key_complete(
        &self,
        key_name: &str,
        response: &MultiFactorAuthResponse,
    ) -> Result<bool> {
        let user = self.require_user()?;
        crate::account::register_security_key_complete(user, key_name, response, self.poster.as_ref()).await
    }

    fn require_user(&self) -> Result<&LoggedInUser> {
        self.user
            .as_ref()
            .ok_or_else(|| Error::Protocol("operation requires a signed-in user".into()))
    }

    /// The in-progress / failed uploads recorded in `.transactions`
    /// (`TransactionService.getOpenTransactions`). Empty for a secret-link context.
    pub async fn list_open_transactions(&self) -> Result<Vec<crate::FileUploadTransaction>> {
        match self.user.as_ref().and_then(|u| u.home()) {
            Some(home) => crate::list_open_transactions(home, self.store.clone(), self.mutable.as_ref()).await,
            None => Ok(Vec::new()),
        }
    }
}
