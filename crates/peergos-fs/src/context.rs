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
