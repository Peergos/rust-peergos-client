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
use crate::mfa::MultiFactorAuthResponse;
use crate::signup::signup;
use peergos_cbor::CborObject;
use peergos_core::error::{Error, Result};
use peergos_core::auth::BatWithId;
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
            Ok(MultiFactorAuthResponse::totp(
                method.credential_id.clone(),
                crate::mfa::current_totp(&secret),
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
    pub fn poster(&self) -> Arc<dyn HttpPoster> {
        self.poster.clone()
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
                    .with_cache(self.cache.clone()),
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
    /// first component names a root (`/username/a/b`, `/friend/shared/...`) or, for
    /// a logged-in user, a path relative to home (`a/b`). For a secret-link context
    /// a bare path is resolved relative to the shared root.
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
            return root.get_by_path(&comps[1..].join("/")).await;
        }
        // Logged-in user: treat as relative to home.
        if self.user.is_some() {
            return self.get_home().await?.get_by_path(&comps.join("/")).await;
        }
        // Single secret-link root: treat as relative to it.
        if roots.len() == 1 {
            return roots.into_iter().next().unwrap().get_by_path(&comps.join("/")).await;
        }
        Ok(None)
    }

    /// The user's mirror BAT (`getMirrorBat`), fetched from the server's bats
    /// endpoint and authorised by a time-limited signed request. `None` if the
    /// account has no registered BAT. Used to keep secret-link data private.
    pub async fn get_mirror_bat(&self) -> Result<Option<BatWithId>> {
        let user = self.require_user()?;
        let path = "peergos/v0/bats/getUserBats";
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let req = CborObject::map()
            .put("p", CborObject::Str(path.to_string()))
            .put("t", CborObject::Long(now))
            .build();
        let auth = to_hex(&user.signer.secret.sign_message(&req.to_bytes())?);
        let url = format!("{path}?username={}&auth={auth}", url_encode(&user.username));
        let raw = self.poster.get(&url).await?;
        match CborObject::from_bytes(&raw)? {
            CborObject::List(items) => items.last().map(BatWithId::from_cbor).transpose(),
            _ => Ok(None),
        }
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
            let writable_cap = if target.is_directory() {
                crate::move_dir_to_own_writer(&parent_cap, name, parent.signer().cloned(), self.store.clone(), self.mutable.as_ref()).await?
            } else {
                crate::move_file_to_own_writer(&parent_cap, name, parent.signer().cloned(), self.store.clone(), self.mutable.as_ref()).await?
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
