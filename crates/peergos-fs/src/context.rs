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

fn split_home_path(path: &str) -> (&str, &str) {
    let trimmed = path.trim_matches('/');
    trimmed.rsplit_once('/').unwrap_or(("", trimmed))
}

/// A link can hold this many items; the real limit is that the serialised link fits
/// in one block, which [`crate::put_secret_link`] enforces.
pub const MAX_LINK_MEMBERS: usize = 100;

pub const UPGRADING_MESSAGE: &str = "Upgrading to post-quantum signatures, please wait.";

/// One of the owner's secret links, deduplicated across the paths it is recorded
/// under (`SecretLinkSummary`).
#[derive(Debug, Clone)]
pub struct SecretLinkSummary {
    pub props: crate::LinkProperties,
    /// A home-relative path this link was recorded under, used when the link
    /// predates member lists.
    pub recorded_under: String,
    username: String,
}

impl SecretLinkSummary {
    fn new(props: crate::LinkProperties, recorded_under: String, username: &str) -> SecretLinkSummary {
        SecretLinkSummary { props, recorded_under, username: username.to_string() }
    }

    /// What is in the link, home-relative: its members, or the one path it was
    /// recorded under if it has none.
    pub fn paths(&self) -> Vec<String> {
        if self.props.members.is_empty() {
            return vec![self.recorded_under.clone()];
        }
        let prefix = format!("/{}/", self.username);
        self.props
            .members
            .iter()
            .map(|m| m.path.strip_prefix(&prefix).unwrap_or(&m.path).to_string())
            .collect()
    }

    pub fn item_count(&self) -> usize {
        self.props.members.len().max(1)
    }

    /// Whether this link already contains the home-relative `path`.
    pub fn contains(&self, path: &str) -> bool {
        self.paths().iter().any(|p| p == path.trim_matches('/'))
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `TimeLimitedClient.signNow`: sign `CborLong(now_millis)` with the identity key —
/// the auth token the space-usage endpoints expect.
fn signed_now(secret: &SecretSigningKey) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    Ok(to_hex(&secret.sign_message(&CborObject::Long(now).to_bytes(), peergos_core::SigningDomain::TimeLimited)?))
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
    /// Root capabilities of a single-link secret-link context (empty for a full
    /// login or a multi-link context — see `link_mounts`).
    link_caps: Vec<AbsoluteCapability>,
    /// Secret links mounted at their true absolute paths (`/username/a/b`), for a
    /// multi-link context. Each entry is `(absolute path, capability)`; the deepest
    /// matching mount wins during path resolution, so a writable child link
    /// supersedes a read-only parent link at the overlapping path.
    link_mounts: Vec<(String, AbsoluteCapability)>,
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
        let mut user = login(username, password, poster.as_ref(), store.clone(), mutable.as_ref(), mfa).await?;
        if peergos_core::keys::hybrid_writers() {
            user = Self::move_to_hybrid_writers(user, password, mfa, &poster, &store, &mutable).await?;
        }
        Ok(UserContext { user: Some(user), link_caps: Vec::new(), link_mounts: Vec::new(), store, mutable, poster, cache: CryptreeCache::new() })
    }

    /// Move an old account's writing spaces to hybrid writers: the home first, then
    /// the rest from a fresh login, which reaches the new home through the link the
    /// old one holds until our entry point names it. A failure leaves the account
    /// usable, and the next login carries on.
    async fn move_to_hybrid_writers(
        mut user: LoggedInUser,
        password: &str,
        mfa: Option<&MfaResponder<'_>>,
        poster: &Arc<dyn HttpPoster>,
        store: &Arc<dyn ContentAddressedStorage>,
        mutable: &Arc<dyn MutablePointers>,
    ) -> Result<LoggedInUser> {
        let relogin = |u: &LoggedInUser| {
            let username = u.username.clone();
            async move { login(&username, password, poster.as_ref(), store.clone(), mutable.as_ref(), mfa).await }
        };
        if user.home().is_some_and(|h| h.writer.is_identity()) {
            log::info!("{UPGRADING_MESSAGE}");
            let ctx = Self::for_user(user.clone(), poster, store, mutable);
            match ctx.switch_home_to_hybrid_writer().await {
                Ok(()) => user = relogin(&user).await?,
                Err(e) => {
                    log::warn!("Couldn't move our home to a hybrid writer: {e}");
                    return Ok(user);
                }
            }
        }
        let moving = user.stored_home.as_ref().is_some_and(|h| h.writer.is_identity())
            && user.home().is_some_and(|h| !h.writer.is_identity());
        if moving {
            log::info!("{UPGRADING_MESSAGE}");
            let ctx = Self::for_user(user.clone(), poster, store, mutable);
            match ctx.finish_move_to_hybrid_writers(password, mfa).await {
                Ok(()) => user = relogin(&user).await?,
                Err(e) => log::warn!("Couldn't finish moving to hybrid writers, which the next login retries: {e}"),
            }
        }
        Ok(user)
    }

    fn sharing(&self, prefix: &str) -> Arc<crate::filewrapper::Sharing> {
        Arc::new(crate::filewrapper::Sharing {
            user: self.user.clone().expect("only a login has a home"),
            poster: self.poster.clone(),
            prefix: prefix.to_string(),
        })
    }

    pub(crate) fn for_user(
        user: LoggedInUser,
        poster: &Arc<dyn HttpPoster>,
        store: &Arc<dyn ContentAddressedStorage>,
        mutable: &Arc<dyn MutablePointers>,
    ) -> UserContext {
        UserContext {
            user: Some(user),
            link_caps: Vec::new(),
            link_mounts: Vec::new(),
            store: store.clone(),
            mutable: mutable.clone(),
            poster: poster.clone(),
            cache: CryptreeCache::new(),
        }
    }

    /// Move our home's writing space to a new hybrid writer
    /// (`switchHomeToHybridWriter`), so a quantum computer can't forge its pointers.
    /// Friends hold entry points to our sharing folders, which nothing sends again,
    /// so those get links in the old writer too.
    async fn switch_home_to_hybrid_writer(&self) -> Result<()> {
        let user = self.require_user()?;
        let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?.clone();
        let mut sharing_dirs = Vec::new();
        let shared = crate::list_directory(&home, self.store.clone(), self.mutable.as_ref())
            .await?
            .into_iter()
            .find(|e| e.name == "shared");
        if let Some(shared) = shared {
            for d in crate::list_directory(&shared.cap, self.store.clone(), self.mutable.as_ref()).await? {
                if d.cap.writer != home.writer || !d.cap.is_writable() {
                    continue;
                }
                let (_, props) = crate::retrieve_file_metadata(&d.cap, self.store.clone(), self.mutable.as_ref()).await?;
                if props.is_directory && !props.is_link {
                    sharing_dirs.push(d.cap);
                }
            }
        }
        let mirror = user.mirror_bat_id();
        crate::writing_space::switch_writer(&home, &user.signer, None, &sharing_dirs, mirror.as_ref(), self.store.clone(), self.mutable.clone())
            .await?;
        Ok(())
    }

    /// Move each writing space nested in our home to a new hybrid writer, send
    /// shares and links again and republish with the new caps, then point our entry
    /// point at the new home (`finishMoveToHybridWriters`). Each step can be redone,
    /// and the entry point goes last, so a login that stops part way is finished by
    /// the next.
    async fn finish_move_to_hybrid_writers(&self, password: &str, mfa: Option<&MfaResponder<'_>>) -> Result<()> {
        let user = self.require_user()?;
        let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?.clone();
        let stored = user.stored_home.clone().ok_or_else(|| Error::Protocol("our home hasn't moved".into()))?;
        let quotas: std::collections::HashMap<_, _> = crate::writer_quota::get_writer_quotas(&user.signer, self.poster.as_ref())
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|q| q.quota.map(|b| (q.writer, b)))
            .collect();
        let home_signer = crate::recover_signer(&home, self.store.clone(), self.mutable.as_ref()).await?;
        self.switch_nested_spaces(&home, &home_signer, &quotas).await?;
        self.reshare_after_move().await?;
        self.update_published_caps("").await?;
        crate::login::replace_home_entry_point(
            &user.username,
            password,
            mfa,
            &user.signer,
            &stored,
            &home,
            self.poster.as_ref(),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await
    }

    /// Switch the Ed25519 writing spaces nested in a space to hybrid writers, top
    /// down, including those nested in spaces that are hybrid already.
    fn switch_nested_spaces<'a>(
        &'a self,
        space: &'a AbsoluteCapability,
        space_signer: &'a peergos_core::SigningPrivateKeyAndPublicHash,
        quotas: &'a std::collections::HashMap<peergos_core::PublicKeyHash, i64>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
        Box::pin(async move {
            let user = self.require_user()?;
            let mut found = Vec::new();
            crate::writing_space::find_nested_writing_spaces(space, &mut found, &self.store, self.mutable.as_ref()).await?;
            for (cap, holder) in found {
                if !cap.is_writable() {
                    continue;
                }
                let Ok((_, props)) = crate::retrieve_file_metadata(&cap, self.store.clone(), self.mutable.as_ref()).await else {
                    continue;
                };
                let moved = if cap.writer.is_identity() {
                    let n = crate::writing_space::NestedSpace { cap: cap.clone(), holder, holder_signer: space_signer.clone() };
                    let mirror = user.mirror_bat_id();
                    let new_cap = crate::writing_space::switch_writer(
                        &cap,
                        space_signer,
                        Some(&n),
                        &[],
                        mirror.as_ref(),
                        self.store.clone(),
                        self.mutable.clone(),
                    )
                    .await?;
                    if let Some(q) = quotas.get(&cap.writer) {
                        crate::writer_quota::set_writer_quota(&user.signer, &new_cap.writer, Some(*q), self.poster.as_ref()).await?;
                        let _ = crate::writer_quota::set_writer_quota(&user.signer, &cap.writer, None, self.poster.as_ref()).await;
                    }
                    new_cap
                } else {
                    cap
                };
                if props.is_directory {
                    let signer = crate::recover_signer(&moved, self.store.clone(), self.mutable.as_ref()).await?;
                    self.switch_nested_spaces(&moved, &signer, quotas).await?;
                }
            }
            Ok(())
        })
    }

    /// Send every share and link again with the caps they have after moving to
    /// hybrid writers. One that can't be sent, e.g. to a former friend or of a file
    /// that is gone, mustn't stop the others.
    async fn reshare_after_move(&self) -> Result<()> {
        let user = self.require_user()?;
        let mut targets: Vec<String> = Vec::new();
        for (dir, state) in crate::get_all_shares(user, self.store.clone(), self.mutable.as_ref()).await? {
            for name in state.read_shares().keys().chain(state.write_shares().keys()).chain(state.links().keys()) {
                let full = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
                if !targets.contains(&full) {
                    targets.push(full);
                }
            }
        }
        let mut sent = std::collections::HashSet::new();
        for t in targets {
            if let Err(e) = self.reshare_with(&t, &mut sent).await {
                log::warn!("Couldn't send the shares of {t} again after moving to hybrid writers: {e}");
            }
        }
        Ok(())
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
        let mut caps = crate::retrieve_secret_link_capabilities(link, store.as_ref(), user_password).await?;
        if caps.len() > 1 {
            // A multi item link mounts each item at its own path; the first is where it
            // lands, and is first in `link_mount_paths`.
            return Self::from_link_caps(caps, poster, store, mutable).await;
        }
        let cap = caps.pop().ok_or_else(|| Error::Protocol("Secret link has no capabilities".into()))?;
        Ok(UserContext { user: None, link_caps: vec![cap], link_mounts: Vec::new(), store, mutable, poster, cache: CryptreeCache::new() })
    }

    /// Open a context spanning several already-resolved secret-link capabilities
    /// at once (Java `fromSecretLinks`). Each cap is mounted at its true absolute
    /// path — recovered by walking cryptree parent links ([`crate::reconstruct_link_path`])
    /// — so the caps sit in a single coherent tree. The caps may be nested (e.g. a
    /// writable link to a subdirectory plus a read-only link to its parent); the
    /// deepest mount wins during resolution, so the writable child supersedes the
    /// read-only parent at the overlapping path. Callers resolve the links with
    /// [`crate::retrieve_secret_link_capability`] (handling any per-link user
    /// password themselves) and pass the caps here.
    pub async fn from_link_caps(
        caps: Vec<AbsoluteCapability>,
        poster: Arc<dyn HttpPoster>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<UserContext> {
        let mut link_mounts = Vec::with_capacity(caps.len());
        for cap in caps {
            let path = crate::reconstruct_link_path(&cap, store.clone(), mutable.as_ref()).await?;
            link_mounts.push((path, cap));
        }
        Ok(UserContext { user: None, link_caps: Vec::new(), link_mounts, store, mutable, poster, cache: CryptreeCache::new() })
    }

    /// The absolute paths at which this context's secret links are mounted, in the
    /// order supplied. Used by shells to render the virtual directory tree spanning
    /// the links.
    pub fn link_mount_paths(&self) -> Vec<String> {
        self.link_mounts.iter().map(|(p, _)| p.clone()).collect()
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
        UserContext { user: Some(user), link_caps: Vec::new(), link_mounts: Vec::new(), store, mutable, poster, cache: CryptreeCache::new() }
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
        Ok(FileWrapper::home(user, self.store.clone(), self.mutable.clone())
            .await?
            .with_cache(self.cache.clone())
            .with_sharing(Some(self.sharing(""))))
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
                    .with_mirror_bat(self.mirror_bat_id())
                    .with_sharing((e.owner_name == user.username && Some(&e.pointer) == home.as_ref()).then(|| self.sharing(&user.username))),
                );
            }
        } else {
            for cap in &self.link_caps {
                out.push(
                    FileWrapper::from_link_cap(cap.clone(), self.store.clone(), self.mutable.clone())
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

        // A multi-link context resolves against its mounted absolute paths.
        if !self.link_mounts.is_empty() {
            return self.resolve_link_mount(&comps).await;
        }

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

    /// Resolve a path within a multi-link context: pick the deepest mounted link
    /// whose absolute path is an ancestor of (or equal to) the query, then navigate
    /// the remaining components from it. A query that is only a virtual ancestor of
    /// some mount (an intermediate directory with no capability of its own) does not
    /// resolve to a node — shells list those from [`Self::link_mount_paths`].
    async fn resolve_link_mount(&self, comps: &[&str]) -> Result<Option<FileWrapper>> {
        let mut best: Option<(usize, &AbsoluteCapability)> = None;
        for (mpath, cap) in &self.link_mounts {
            let mc: Vec<&str> = mpath.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
            if mc.len() <= comps.len() && mc[..] == comps[..mc.len()] {
                let deeper = best.as_ref().map(|(n, _)| mc.len() > *n).unwrap_or(true);
                if deeper {
                    best = Some((mc.len(), cap));
                }
            }
        }
        let (matched, cap) = match best {
            Some(b) => b,
            None => return Ok(None),
        };
        let root = FileWrapper::from_link_cap(cap.clone(), self.store.clone(), self.mutable.clone())
            .await?
            .with_cache(self.cache.clone());
        root.get_by_path(&comps[matched..].join("/")).await
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
    /// See [`UserContext::create_secret_link_to`] for a link over several items.
    pub async fn create_secret_link(
        &self,
        path: &str,
        writable: bool,
        user_password: &str,
        expiry_epoch_secs: Option<i64>,
        max_retrievals: Option<i64>,
    ) -> Result<String> {
        let writable_paths: Vec<String> = if writable { vec![path.to_string()] } else { Vec::new() };
        let props = self
            .create_secret_link_to(&[path.to_string()], &writable_paths, user_password, expiry_epoch_secs, max_retrievals)
            .await?;
        self.secret_link_string(&props)
    }

    /// Create a link over several files and directories (home-relative `paths`, in
    /// the order they should be listed), each read-only or, if in `writable_paths`,
    /// writable (`UserContext.createSecretLinkTo`). The link opens on the first.
    pub async fn create_secret_link_to(
        &self,
        paths: &[String],
        writable_paths: &[String],
        user_password: &str,
        expiry_epoch_secs: Option<i64>,
        max_retrievals: Option<i64>,
    ) -> Result<crate::LinkProperties> {
        let user = self.require_user()?;
        let link = crate::SecretLink::create(user.identity.clone())?;
        let props = crate::LinkProperties::build(&link, user_password, max_retrievals, expiry_epoch_secs, Vec::new());
        self.set_secret_link_members(paths, writable_paths, props).await
    }

    /// The shareable string for a link (`getLinkString`).
    pub fn secret_link_string(&self, props: &crate::LinkProperties) -> Result<String> {
        Ok(props.to_link(&self.require_user()?.identity).to_link())
    }

    /// Rewrite a link's membership (`setSecretLinkMembers`). The label and password
    /// do not change, so the link string stays exactly as it was and anyone already
    /// holding it gets the new members.
    ///
    /// A writable member must first be in its own writing space, which rewrites keys
    /// and can fail, so that all happens before the payload is touched: a failure
    /// part way through leaves the link as it was.
    pub async fn set_secret_link_members(
        &self,
        paths: &[String],
        writable_paths: &[String],
        props: crate::LinkProperties,
    ) -> Result<crate::LinkProperties> {
        if paths.is_empty() {
            return Err(Error::Protocol("A secret link must contain at least one item!".into()));
        }
        if paths.len() > MAX_LINK_MEMBERS {
            return Err(Error::Protocol(format!(
                "A secret link can hold at most {MAX_LINK_MEMBERS} items, not {}. Share a folder instead.",
                paths.len()
            )));
        }
        let paths: Vec<String> = paths.iter().map(|p| p.trim_matches('/').to_string()).collect();
        let writable: std::collections::HashSet<String> =
            writable_paths.iter().map(|p| p.trim_matches('/').to_string()).collect();
        if paths.iter().any(|p| writable.contains(p)) {
            // an interrupted grant leaves an owned writer with no pointer, so clear any
            // before adding another; once for the batch, not once per member
            if let Err(e) = self.remove_orphaned_writers().await {
                log::warn!("Couldn't remove orphaned writers: {e}");
            }
        }
        for path in paths.iter().filter(|p| writable.contains(*p)) {
            self.split_into_own_writing_space(path).await?;
        }
        let mut candidates = paths.clone();
        candidates.extend(props.members.iter().filter_map(|m| self.home_relative(&m.path).ok()));
        let old = self.recorded_link(props.label, &candidates).await?;
        let old_members = match &old {
            Some(o) => self.link_members(o).await?,
            None => Vec::new(),
        };
        // whatever the link no longer gives: a removed member, one made read only, or
        // every member when the password changes
        let password_changed = old.as_ref().is_some_and(|o| o.user_password != props.user_password);
        let lost: Vec<crate::LinkMember> = old_members
            .iter()
            .filter(|m| password_changed || !paths.contains(&m.path) || (m.writable && !writable.contains(&m.path)))
            .cloned()
            .collect();
        // or sending the link again after a rotation would bring a removed member back
        let mut removed: Vec<String> = old_members.iter().map(|m| m.path.clone()).collect();
        removed.extend(props.members.iter().filter_map(|m| self.home_relative(&m.path).ok()));
        if let Some(o) = &old {
            removed.extend(o.members.iter().filter_map(|m| self.home_relative(&m.path).ok()));
        }
        removed.retain(|p| !paths.contains(p));
        removed.sort();
        removed.dedup();
        let minted = self.mint_link(&paths, &writable, props).await?;
        let user = self.require_user()?;
        for gone in &removed {
            crate::remove_link(user, gone, minted.label, self.store.clone(), self.mutable.as_ref()).await?;
        }
        if lost.is_empty() {
            return Ok(minted);
        }
        self.revoke_link_access(&lost).await?;
        // rotating sends this link again, which replaces the value we wrote
        Ok(crate::get_links(user, &paths[0], self.store.clone(), self.mutable.as_ref())
            .await?
            .into_iter()
            .find(|l| l.label == minted.label)
            .unwrap_or(minted))
    }

    /// The owner's record of a link, preferring one that knows its members.
    async fn recorded_link(&self, label: i64, paths: &[String]) -> Result<Option<crate::LinkProperties>> {
        let user = self.require_user()?;
        let mut found: Option<crate::LinkProperties> = None;
        for path in paths {
            if found.as_ref().is_some_and(|f| !f.members.is_empty()) {
                break;
            }
            let here = crate::get_links(user, path.trim_matches('/'), self.store.clone(), self.mutable.as_ref())
                .await?
                .into_iter()
                .find(|l| l.label == label);
            if let Some(h) = here {
                if found.is_none() || !h.members.is_empty() {
                    found = Some(h);
                }
            }
        }
        Ok(found)
    }

    /// What a link holds now, with home-relative paths, read from the champ rather
    /// than the server so an expired link can still be read. A member that has since
    /// been deleted has no keys left to rotate.
    async fn link_members(&self, props: &crate::LinkProperties) -> Result<Vec<crate::LinkMember>> {
        let user = self.require_user()?;
        let link = props.to_link(&user.identity);
        let mirror = self.get_mirror_bat().await?;
        let caps = crate::secret_link_capabilities_from_champ(
            &user.identity, &link, &props.user_password, mirror.as_ref(), &self.store, self.mutable.as_ref(),
        )
        .await?;
        let mut members = Vec::with_capacity(caps.len());
        for cap in caps {
            let Ok(path) = crate::reconstruct_link_path(&cap, self.store.clone(), self.mutable.as_ref()).await else { continue };
            let Ok(path) = self.home_relative(&path) else { continue };
            members.push(crate::LinkMember { path, writable: cap.w_base_key.is_some() });
        }
        Ok(members)
    }

    /// Rotate the keys of members (home-relative paths) a link no longer gives, then
    /// send every other share and link of them again. Writable members get a new
    /// signer too. A read only member that is public anyway is left alone, and
    /// anything published at or below a rotated path is published with its new cap.
    async fn revoke_link_access(&self, lost: &[crate::LinkMember]) -> Result<()> {
        let mut by_path: Vec<(String, bool)> = Vec::new();
        for m in lost {
            match by_path.iter_mut().find(|(p, _)| *p == m.path) {
                Some((_, w)) => *w |= m.writable,
                None => by_path.push((m.path.clone(), m.writable)),
            }
        }
        for (path, writable) in by_path {
            self.rotate_for_link(&path, writable).await?;
        }
        Ok(())
    }

    async fn rotate_for_link(&self, path: &str, writable: bool) -> Result<()> {
        if !writable && self.is_public(path).await? {
            return Ok(());
        }
        if self.get_by_path(path).await?.is_none() {
            return Ok(());
        }
        let user = self.require_user()?;
        let (parent_path, name) = split_home_path(path);
        let parent = self
            .get_by_path(parent_path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no parent directory for {path}")))?;
        let mb = user.mirror_bat_id();
        let rotate_signers = writable;
        let quotas = if rotate_signers { self.writer_quota_map().await.unwrap_or_default() } else { Default::default() };
        let net = peergos_core::BufferedNetwork::with_defaults(self.store.clone(), self.mutable.clone());
        let bstore: Arc<dyn ContentAddressedStorage> = net.storage();
        let (_, rotated) = crate::rotate::rotate_child(
            parent.capability(), name, parent.signer().cloned(), rotate_signers, mb.as_ref(), &bstore, net.pointers().as_ref(),
        )
        .await?;
        net.commit(&user.identity).await?;
        for (old_writer, new_writer) in rotated {
            if let Some(quota) = quotas.get(&old_writer) {
                crate::writer_quota::set_writer_quota(&user.signer, &new_writer, Some(*quota), self.poster.as_ref()).await?;
                if let Err(e) = crate::writer_quota::set_writer_quota(&user.signer, &old_writer, None, self.poster.as_ref()).await {
                    log::warn!("Couldn't remove the cap of rotated signer {old_writer}: {e}");
                }
            }
        }
        self.reshare_all_shares_and_links_recursive(path).await?;
        Box::pin(self.update_published_caps(path)).await
    }

    /// Delete every link that has expired, rotating the keys of what it held
    /// (`deleteExpiredSecretLinks`). Returns how many were deleted.
    pub async fn delete_expired_secret_links(&self) -> Result<usize> {
        let now = crate::now_epoch();
        let expired: Vec<SecretLinkSummary> = self
            .get_all_secret_links()
            .await?
            .into_iter()
            .filter(|l| l.props.expiry_epoch_secs.is_some_and(|e| e < now))
            .collect();
        for l in &expired {
            self.delete_secret_link_from(l.props.label, &l.paths()).await?;
        }
        Ok(expired.len())
    }

    /// Append one file or folder to a link that already exists (`addToSecretLink`).
    /// The link string does not change, so whoever already holds it gets this too.
    pub async fn add_to_secret_link(
        &self,
        link: &SecretLinkSummary,
        path: &str,
        writable: bool,
    ) -> Result<crate::LinkProperties> {
        let path = path.trim_matches('/').to_string();
        if path.is_empty() {
            return Err(Error::Protocol("No file given to add to this link.".into()));
        }
        let mut paths = link.paths();
        if paths.contains(&path) {
            return Err(Error::Protocol(format!("{path} is already in this link.")));
        }
        let mut writable_paths: Vec<String> = if link.props.members.is_empty() {
            if link.props.writable { paths.clone() } else { Vec::new() }
        } else {
            link.props
                .members
                .iter()
                .filter(|m| m.writable)
                .filter_map(|m| self.home_relative(&m.path).ok())
                .collect()
        };
        paths.push(path.clone());
        if writable {
            writable_paths.push(path);
        }
        self.set_secret_link_members(&paths, &writable_paths, link.props.clone()).await
    }

    /// Every secret link this user has, once each (`getAllSecretLinks`). A link is
    /// recorded under each path it contains; records are deduplicated by label,
    /// keeping whichever knows its members.
    pub async fn get_all_secret_links(&self) -> Result<Vec<SecretLinkSummary>> {
        let user = self.require_user()?;
        let mut by_label: Vec<SecretLinkSummary> = Vec::new();
        for (dir, state) in crate::get_all_shares(user, self.store.clone(), self.mutable.as_ref()).await? {
            for (name, links) in state.links() {
                let path = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
                for props in links {
                    match by_label.iter_mut().find(|s| s.props.label == props.label) {
                        Some(existing) => {
                            if existing.props.members.is_empty() && !props.members.is_empty() {
                                *existing = SecretLinkSummary::new(props.clone(), path.clone(), &user.username);
                            }
                        }
                        None => by_label.push(SecretLinkSummary::new(props.clone(), path.clone(), &user.username)),
                    }
                }
            }
        }
        Ok(by_label)
    }

    /// What a link actually contains, with each member's absolute path as it is now
    /// (`getSecretLinkMembers`). Read from the payload, whose capabilities survive a
    /// rename, rather than from the recorded paths, which do not.
    pub async fn get_secret_link_members(&self, props: &crate::LinkProperties) -> Result<Vec<crate::LinkMember>> {
        let link = props.to_link(&self.require_user()?.identity).to_link();
        let pw = if props.user_password.is_empty() { None } else { Some(props.user_password.as_str()) };
        let caps = crate::retrieve_secret_link_capabilities(&link, self.store.as_ref(), pw).await?;
        let mut members = Vec::with_capacity(caps.len());
        for cap in caps {
            let path = crate::reconstruct_link_path(&cap, self.store.clone(), self.mutable.as_ref()).await?;
            members.push(crate::LinkMember { path, writable: cap.w_base_key.is_some() });
        }
        Ok(members)
    }

    /// Grant `friend` write access to the file or directory at home-relative `path`
    /// (`shareWriteAccessWith`). If the item has to move into a writing space of its
    /// own, its capability changes, so every existing share and link to it is re-sent.
    pub async fn share_write_access(&self, path: &str, friend: &str) -> Result<()> {
        let user = self.require_user()?;
        let path = path.trim_matches('/');
        let (parent_path, name) = match path.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", path),
        };
        self.split_into_own_writing_space(path).await?;
        let parent = self
            .get_by_path(parent_path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no parent directory for {path}")))?;
        crate::share_write_access(user, parent_path, parent.capability(), name, friend, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Revoke read access to the item at home-relative `path` from `users`, which
    /// may include group uids (`unShareReadAccessWith`).
    pub async fn unshare_read_access(&self, path: &str, users: &[String]) -> Result<()> {
        let user = self.require_user()?;
        let (parent_path, name) = split_home_path(path);
        let parent = self
            .get_by_path(parent_path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no parent directory for {path}")))?;
        crate::unshare_read_access(user, parent_path, parent.capability(), name, users, self.store.clone(), self.mutable.as_ref())
            .await
    }

    /// Revoke write access to the item at home-relative `path` from `users`, which
    /// may include group uids (`unShareWriteAccessWith`). This moves the item to a
    /// new writing space, which keeps any cap on the space the old one could use.
    pub async fn unshare_write_access(&self, path: &str, users: &[String]) -> Result<()> {
        let user = self.require_user()?;
        let (parent_path, name) = split_home_path(path);
        let parent = self
            .get_by_path(parent_path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no parent directory for {path}")))?;
        let old_writer = self
            .get_by_path(path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("Specified un-shareWith path {path} does not exist")))?
            .capability()
            .writer
            .clone();
        let quotas = self.writer_quota_map().await.unwrap_or_default();
        crate::unshare_write_access(user, parent_path, parent.capability(), name, users, self.store.clone(), self.mutable.as_ref())
            .await?;
        if let Some(quota) = quotas.get(&old_writer) {
            if let Some(moved) = self.get_by_path(path).await? {
                crate::writer_quota::set_writer_quota(&user.signer, &moved.capability().writer, Some(*quota), self.poster.as_ref())
                    .await?;
                // the old signer is only de-authorised, not emptied, so the server can't
                // tell it has gone and its cap is removed here
                if let Err(e) = crate::writer_quota::set_writer_quota(&user.signer, &old_writer, None, self.poster.as_ref()).await {
                    log::warn!("Couldn't remove the cap of rotated signer {old_writer}: {e}");
                }
            }
        }
        Ok(())
    }

    /// Remove every writer this user's writers own that has no pointer
    /// (`removeOrphanedWriters`): left behind by a grant of write access that was
    /// interrupted before the new writer's first commit. Returns how many.
    pub async fn remove_orphaned_writers(&self) -> Result<usize> {
        let user = self.require_user()?;
        let mut signers = vec![user.signer.clone()];
        if let Some(home) = user.home() {
            signers.push(crate::recover_signer(home, self.store.clone(), self.mutable.as_ref()).await?);
        }
        // writers nested below home are reached through what has been shared from it
        for (dir, state) in crate::get_all_shares(user, self.store.clone(), self.mutable.as_ref()).await? {
            let names = state
                .write_shares()
                .keys()
                .chain(state.links().iter().filter(|(_, ls)| ls.iter().any(|l| l.writable)).map(|(n, _)| n));
            for name in names {
                let path = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
                if let Some(f) = self.get_by_path(&path).await? {
                    if let Ok(s) = crate::recover_signer(f.capability(), self.store.clone(), self.mutable.as_ref()).await {
                        if !signers.iter().any(|x| x.public_key_hash == s.public_key_hash) {
                            signers.push(s);
                        }
                    }
                }
            }
        }
        let mut removed = 0;
        for s in &signers {
            let orphans = crate::writing_space::orphaned_writers(s, &user.identity, &self.store, self.mutable.as_ref()).await?;
            removed += crate::writing_space::remove_orphans(s, &user.identity, &orphans, &self.store, self.mutable.as_ref()).await?;
        }
        Ok(removed)
    }

    /// Ensure the item at `path` is in its own writing space, so a writable link or
    /// share can be granted to it. If it moves, every existing share and link to it
    /// is re-sent to the new capability.
    async fn split_into_own_writing_space(&self, path: &str) -> Result<AbsoluteCapability> {
        let (parent_path, name) = match path.rsplit_once('/') {
            Some((p, n)) => (p, n),
            None => ("", path),
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
        let before = target.capability().writer.clone();
        let mb = self.require_user()?.mirror_bat_id();
        let writable_cap = if target.is_directory() {
            crate::move_dir_to_own_writer(&parent_cap, name, parent.signer().cloned(), mb.as_ref(), self.store.clone(), self.mutable.as_ref()).await?
        } else {
            crate::move_file_to_own_writer(&parent_cap, name, parent.signer().cloned(), mb.as_ref(), self.store.clone(), self.mutable.as_ref()).await?
        };
        if writable_cap.writer == parent_cap.writer {
            return Err(Error::Protocol(
                "a writable secret link's target must be in a different writing space to its parent".into(),
            ));
        }
        if writable_cap.writer != before {
            self.reshare_all_shares_and_links(path).await?;
        }
        Ok(writable_cap)
    }

    /// Write a link's payload for `paths` under its existing label and password, and
    /// record it under every member. Writable members must already be in their own
    /// writing space.
    async fn mint_link(
        &self,
        paths: &[String],
        writable: &std::collections::HashSet<String>,
        props: crate::LinkProperties,
    ) -> Result<crate::LinkProperties> {
        let user = self.require_user()?;
        let mut caps = Vec::with_capacity(paths.len());
        let mut members = Vec::with_capacity(paths.len());
        for path in paths {
            let file = self
                .get_by_path(path)
                .await?
                .ok_or_else(|| Error::Protocol(format!("Couldn't retrieve {path}")))?;
            let is_writable = writable.contains(path);
            let cap = if is_writable {
                let cap = file.capability().clone();
                if cap.w_base_key.is_none() {
                    return Err(Error::Protocol(format!("{path} is not writable")));
                }
                cap
            } else {
                file.capability().read_only()
            };
            // A link carries one owner, and expiry, retrieval limits and revocation are
            // all enforced against that owner's record.
            if cap.owner != user.identity {
                return Err(Error::Protocol(format!(
                    "A secret link can only contain your own files. {path} belongs to someone else - ask them for a link to it."
                )));
            }
            caps.push(cap);
            members.push(crate::LinkMember { path: format!("/{}/{path}", user.username), writable: is_writable });
        }
        let mirror = self.get_mirror_bat().await?;
        let link = props.to_link(&user.identity);
        let target = crate::put_secret_link(
            &caps,
            &link,
            &props.user_password,
            props.expiry_epoch_secs,
            props.max_retrievals,
            &user.signer,
            mirror.as_ref(),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        let mut props = props.with_members(members);
        props.existing = Some(target.to_bytes());
        // the champ is what resolves the link and the records are the owner's listing,
        // so the champ goes first: a crash between them under-reports membership
        for path in paths {
            crate::record_link(user, path, props.clone(), self.store.clone(), self.mutable.as_ref()).await?;
        }
        Ok(props)
    }

    /// An absolute `/owner/a/b` path as a home-relative one, for this user's files.
    fn home_relative(&self, path: &str) -> Result<String> {
        let username = &self.require_user()?.username;
        let trimmed = path.trim_start_matches('/');
        match trimmed.split_once('/') {
            Some((owner, rest)) if owner == username => Ok(rest.to_string()),
            None if trimmed == username => Ok(String::new()),
            _ => Err(Error::Protocol(format!("{path} is not in {username}'s home"))),
        }
    }

    /// The user's social state (`getSocialState`). This first acts on follow
    /// requests that don't need the user (see [`crate::process_follow_requests`]),
    /// finishes any interrupted block, and reconciles the built-in groups with who
    /// our followers and friends are; failures of the last two are only logged.
    pub async fn social_state(&self) -> Result<crate::SocialState> {
        let user = self.require_user()?;
        let (store, mutable) = (self.store.clone(), self.mutable.as_ref());
        let pending_incoming_requests =
            crate::process_follow_requests(user, self.poster.as_ref(), store.clone(), mutable).await?;
        if let Err(e) = crate::complete_blocks(user, store.clone(), mutable).await {
            log::warn!("Couldn't complete blocks: {e}");
        }
        let following = crate::get_following(user, store.clone(), mutable).await?;
        let following_set = following.iter().cloned().collect();
        if let Err(e) = crate::reconcile_groups(user, &following_set, store.clone(), mutable).await {
            log::warn!("Couldn't reconcile social groups: {e}");
        }
        let pending_outgoing = crate::get_pending_outgoing(user, store.clone(), mutable).await?;
        let followers = crate::get_follower_names(user, store.clone(), mutable).await?;
        let blocked = crate::get_blocked(user, store.clone(), mutable).await?;
        let unfollowed = crate::get_unfollowed(user, store.clone(), mutable).await?;
        let friends = crate::get_friends(user, store.clone(), mutable).await?;
        let groups = crate::get_or_create_groups(user, store, mutable).await?.uid_to_name;
        Ok(crate::SocialState {
            pending_incoming_requests,
            pending_outgoing,
            following,
            followers,
            blocked,
            unfollowed,
            friends,
            groups,
        })
    }

    /// Stop seeing what `username` shares with us directly (`unfollow`). They may
    /// still follow us; see [`UserContext::block`] to stop that too.
    pub async fn unfollow(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::unfollow(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Start seeing what an unfollowed user shares with us directly again (`followAgain`).
    pub async fn follow_again(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::follow_again(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The users we have unfollowed (`getUnfollowed`).
    pub async fn get_unfollowed(&self) -> Result<Vec<String>> {
        let user = self.require_user()?;
        crate::get_unfollowed(user, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The sharing state of every child of the directory at home-relative `dir_path`
    /// (`getDirectorySharingState`) — read/write recipients and links per child.
    pub async fn get_directory_sharing_state(&self, dir_path: &str) -> Result<crate::SharedWithState> {
        let user = self.require_user()?;
        crate::get_directory_sharing_state(user, dir_path, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The users we have blocked (`getBlocked`).
    pub async fn get_blocked(&self) -> Result<Vec<String>> {
        let user = self.require_user()?;
        crate::get_blocked(user, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Never see anything from `username`, even via someone else, and stop them
    /// following us (`block`).
    pub async fn block(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::block(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Unblock `username` (`unblock`). They stay unfollowed until [`UserContext::follow_again`].
    pub async fn unblock(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::unblock(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    /// The user's friend annotations, keyed by username (`getFriendAnnotations`).
    pub async fn get_friend_annotations(&self) -> Result<std::collections::BTreeMap<String, crate::FriendAnnotation>> {
        let user = self.require_user()?;
        crate::get_friend_annotations(user, self.store.clone(), self.mutable.as_ref()).await
    }

    /// "verified", "unverified", or "changed" if the friend's identity is no longer the one that was verified
    /// (`verificationStatus`).
    pub async fn verification_status(&self, friend: &str, annotation: Option<&crate::FriendAnnotation>) -> Result<&'static str> {
        let Some(annotation) = annotation.filter(|a| a.is_verified) else {
            return Ok("unverified");
        };
        let id = crate::login::get_public_key_hash(self.poster.as_ref(), friend).await?;
        Ok(if id.is_some_and(|id| annotation.is_verified_for(&id)) { "verified" } else { "changed" })
    }

    /// Add or replace a friend annotation (`addFriendAnnotation`).
    pub async fn add_friend_annotation(&self, annotation: crate::FriendAnnotation) -> Result<()> {
        let user = self.require_user()?;
        crate::add_friend_annotation(user, annotation, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Remove `username` as a follower (`removeFollower`): remove them from every
    /// group, revoke everything ever shared with them (rotating keys and re-sharing
    /// with the remaining recipients) and delete their `/shared/<username>` folder.
    /// Resumable: an interrupted removal is completed by [`UserContext::social_state`].
    pub async fn remove_follower(&self, username: &str) -> Result<()> {
        let user = self.require_user()?;
        crate::revoke_follower(user, username, self.store.clone(), self.mutable.as_ref()).await
    }

    // ---- sharing groups ---------------------------------------------------

    /// Create a custom sharing group of followers (`createGroup`), returning its uid.
    pub async fn create_group(&self, name: &str, members: &[String]) -> Result<String> {
        crate::create_group(self.require_user()?, name, members, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Change our label for a custom group (`renameGroup`).
    pub async fn rename_group(&self, group_uid: &str, new_name: &str) -> Result<()> {
        crate::rename_group(self.require_user()?, group_uid, new_name, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Who is in a group (`getGroupMembers`).
    pub async fn get_group_members(&self, group_uid: &str) -> Result<std::collections::BTreeSet<String>> {
        crate::get_group_members(self.require_user()?, group_uid, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Add followers to a custom group (`addGroupMembers`).
    pub async fn add_group_members(&self, group_uid: &str, members: &[String]) -> Result<()> {
        crate::add_group_members(self.require_user()?, group_uid, members, self.store.clone(), self.mutable.as_ref()).await
    }

    /// Remove a member from a custom group (`removeGroupMember`); see
    /// [`crate::remove_group_member`] for what `revoke_shared` does.
    pub async fn remove_group_member(&self, group_uid: &str, member: &str, revoke_shared: bool) -> Result<()> {
        crate::remove_group_member(self.require_user()?, group_uid, member, revoke_shared, self.store.clone(), self.mutable.as_ref())
            .await
    }

    /// Delete a custom group (`deleteGroup`); see [`crate::delete_group`].
    pub async fn delete_group(&self, group_uid: &str, revoke_shared: bool, progress: impl FnMut()) -> Result<()> {
        crate::delete_group(self.require_user()?, group_uid, revoke_shared, progress, self.store.clone(), self.mutable.as_ref())
            .await
    }

    /// How many files and folders are shared with a group (`countSharedWithGroup`).
    pub async fn count_shared_with_group(&self, group_uid: &str) -> Result<usize> {
        crate::count_shared_with_group(self.require_user()?, group_uid, self.store.clone(), self.mutable.as_ref()).await
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

    /// Delete a secret link by its `label` (`deleteSecretLink`), found recorded under
    /// `path`: remove it from the identity writer's link CHAMP so it no longer
    /// resolves, and forget it from every item it held.
    pub async fn delete_secret_link(&self, path: &str, label: i64) -> Result<()> {
        let user = self.require_user()?;
        let path = path.trim_matches('/').to_string();
        let recorded = crate::get_links(user, &path, self.store.clone(), self.mutable.as_ref()).await?;
        let mut paths: Vec<String> = recorded
            .iter()
            .find(|l| l.label == label)
            .map(|l| l.members.iter().filter_map(|m| self.home_relative(&m.path).ok()).collect())
            .unwrap_or_default();
        if !paths.contains(&path) {
            paths.push(path);
        }
        self.delete_secret_link_from(label, &paths).await
    }

    /// Delete a link, clear it from every path it contained, and rotate the keys of
    /// its members (`deleteSecretLinkFrom`). Deleting the champ entry only stops new
    /// visitors: anyone who opened the link holds its capabilities, so they are only
    /// revoked by rotating keys. The records go first, or the rotation would send
    /// this link again.
    pub async fn delete_secret_link_from(&self, label: i64, member_paths: &[String]) -> Result<()> {
        let recorded = self.recorded_link(label, member_paths).await?;
        let members = match &recorded {
            Some(r) => self.link_members(r).await?,
            None => Vec::new(),
        };
        let mut paths: Vec<String> = member_paths.iter().map(|p| p.trim_matches('/').to_string()).collect();
        if let Some(r) = &recorded {
            for p in r.members.iter().filter_map(|m| self.home_relative(&m.path).ok()) {
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
        self.forget_secret_link(label, &paths).await?;
        self.revoke_link_access(&members).await
    }

    /// Delete a link without rotating anything, for a link that never handed out a
    /// capability.
    pub(crate) async fn forget_secret_link(&self, label: i64, member_paths: &[String]) -> Result<()> {
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
        for path in member_paths {
            crate::remove_link(user, path.trim_matches('/'), label, self.store.clone(), self.mutable.as_ref()).await?;
        }
        Ok(())
    }

    /// After a target's keys rotate, re-send every recorded read/write share and
    /// re-mint every recorded secret link so they point at the new capability
    /// (Java `reSendAllSharesAndLinksRecursive` → `reshareAndUpdateLinks`).
    async fn reshare_all_shares_and_links(&self, path: &str) -> Result<()> {
        self.reshare_with(path, &mut std::collections::HashSet::new()).await
    }

    /// [`Self::reshare_all_shares_and_links`] for `path` and everything shared below
    /// it, whose keys a rotation of `path` changed too. A link is sent once, however
    /// many of its members are below.
    pub(crate) async fn reshare_all_shares_and_links_recursive(&self, path: &str) -> Result<()> {
        let user = self.require_user()?;
        let trimmed = path.trim_matches('/');
        let prefix = format!("{trimmed}/");
        let mut targets: Vec<String> = Vec::new();
        for (dir, state) in crate::get_all_shares(user, self.store.clone(), self.mutable.as_ref()).await? {
            let names = state.read_shares().keys().chain(state.write_shares().keys()).chain(state.links().keys());
            for name in names {
                let full = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
                if (full == trimmed || full.starts_with(&prefix) || trimmed.is_empty()) && !targets.contains(&full) {
                    targets.push(full);
                }
            }
        }
        let mut sent = std::collections::HashSet::new();
        for t in targets {
            // a record can outlive what it was for
            if self.get_by_path(&t).await?.is_none() {
                continue;
            }
            self.reshare_with(&t, &mut sent).await?;
        }
        Ok(())
    }

    async fn reshare_with(&self, path: &str, sent_links: &mut std::collections::HashSet<i64>) -> Result<()> {
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
        // Re-sign each link keeping whatever membership it already has, so re-minting
        // one item of a multi-item link does not drop the others.
        for lp in crate::get_links(user, path, self.store.clone(), self.mutable.as_ref()).await? {
            if !sent_links.insert(lp.label) {
                continue;
            }
            let (paths, writable): (Vec<String>, std::collections::HashSet<String>) = if lp.members.is_empty() {
                let p = trimmed.to_string();
                let w = if lp.writable { [p.clone()].into_iter().collect() } else { Default::default() };
                (vec![p], w)
            } else {
                let paths = lp.members.iter().map(|m| self.home_relative(&m.path)).collect::<Result<Vec<_>>>()?;
                let writable = lp
                    .members
                    .iter()
                    .filter(|m| m.writable)
                    .map(|m| self.home_relative(&m.path))
                    .collect::<Result<_>>()?;
                (paths, writable)
            };
            self.mint_link(&paths, &writable, lp).await?;
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
        let signed = user.signer.secret.sign_message(&req.serialize(), peergos_core::SigningDomain::SpaceRequest)?;
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

    /// Whether the signed-in user is an admin on the server we are connected to (`isAdmin`).
    pub async fn is_admin(&self) -> Result<bool> {
        crate::admin::is_admin(self.require_user()?, self.poster.as_ref()).await
    }

    /// Create `count` single use signup tokens (`createSignupTokens`), each of
    /// which lets one new user sign up. Requires admin.
    pub async fn create_signup_tokens(&self, count: u32) -> Result<Vec<String>> {
        let user = self.require_user()?;
        let instance = self.store.id().await?;
        crate::admin::create_signup_tokens(user, &instance, count, self.poster.as_ref()).await
    }

    /// The signup tokens nobody has used yet (`listSignupTokens`). Requires admin.
    pub async fn list_signup_tokens(&self) -> Result<Vec<String>> {
        crate::admin::list_signup_tokens(self.require_user()?, self.poster.as_ref()).await
    }

    /// Withdraw an unused signup token (`revokeSignupToken`); whether there was one.
    pub async fn revoke_signup_token(&self, token: &str) -> Result<bool> {
        crate::admin::revoke_signup_token(self.require_user()?, token, self.poster.as_ref()).await
    }

    /// The latest release published under `/peergos/releases` if it is newer than
    /// this server (`newerRelease`). Any failure is treated as no newer release.
    pub async fn newer_release(&self) -> Option<crate::admin::Version> {
        let current = crate::admin::Version::parse(&self.get_version_info().await.ok()?.version)?;
        let releases = self.get_public_capability("/peergos/releases").await.ok()?;
        let latest = crate::list_directory(&releases, self.store.clone(), self.mutable.as_ref())
            .await
            .ok()?
            .into_iter()
            .filter(|e| e.is_dir != Some(false))
            .filter_map(|e| e.name.strip_prefix('v').and_then(crate::admin::Version::parse))
            .max()?;
        (current < latest).then_some(latest)
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

    /// Generate a fresh set of single use backup codes (`generateBackupCodes`),
    /// replacing any earlier set. The plaintext codes are only available now.
    pub async fn generate_backup_codes(&self) -> Result<crate::mfa::BackupCodes> {
        let user = self.require_user()?;
        crate::account::generate_backup_codes(user, self.poster.as_ref()).await
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
