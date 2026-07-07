//! User login (`UserContext.signIn`), ported from `peergos.shared.user`.
//!
//! The flow, mirroring the Java client:
//!  1. `CoreNode.getPublicKeyHash(username)` → the user's identity key hash (owner).
//!  2. Fetch the owner's `WriterData` (via the mutable pointer) to read the
//!     `SecretGenerationAlgorithm` (scrypt params) used to derive their keys.
//!  3. `UserUtil.generateUser` — scrypt(username+extraSalt, password) → a login
//!     signing keypair (+ boxing pair) and the root symmetric key.
//!  4. `Account.getLoginData` — GET `login/getLogin` authenticated by a signed
//!     timestamp; returns the `UserStaticData` (encrypted entry points).
//!  5. Decrypt the entry points with the root key to recover the identity signing
//!     key and the capabilities to the user's filesystem roots.
//!
//! MFA-protected accounts and legacy accounts (with `static` inside `WriterData`)
//! are handled; the hybrid post-quantum boxing upgrade is not (read-only login
//! doesn't need it).

use crate::capability::AbsoluteCapability;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{
    PublicKeyHash, PublicSigningKey, SecretSigningKey, SigningKeyPair,
    SigningPrivateKeyAndPublicHash,
};
use peergos_core::mutable::MutablePointers;
use peergos_core::poster::HttpPoster;
use peergos_core::storage::ContentAddressedStorage;
use peergos_core::symmetric::SymmetricKey;
use peergos_crypto::hash::hash_to_key_bytes;
use peergos_crypto::sign::keypair_from_seed;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const CORE_URL: &str = "peergos/v0/core/";
const LOGIN_URL: &str = "peergos/v0/login/";

/// One decrypted entry point: a capability into a filesystem root plus the name
/// of the account that owns it (`EntryPoint`).
#[derive(Debug, Clone)]
pub struct EntryPoint {
    pub pointer: AbsoluteCapability,
    pub owner_name: String,
}

impl EntryPoint {
    pub(crate) fn from_cbor(cbor: &CborObject) -> Result<EntryPoint> {
        let pointer = cbor
            .get("c")
            .ok_or_else(|| Error::Cbor("EntryPoint missing 'c'".into()))
            .and_then(AbsoluteCapability::from_cbor)?;
        let owner_name = cbor
            .get("n")
            .and_then(|c| c.as_string())
            .ok_or_else(|| Error::Cbor("EntryPoint missing 'n'".into()))?
            .to_string();
        Ok(EntryPoint { pointer, owner_name })
    }

    pub(crate) fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("c", self.pointer.to_cbor())
            .put("n", CborObject::Str(self.owner_name.clone()))
            .build()
    }
}

/// A logged-in user: the identity signer, the login root key and the decrypted
/// filesystem entry points.
#[derive(Debug, Clone)]
pub struct LoggedInUser {
    pub username: String,
    /// The owner/identity public key hash (`WriterData.controller`).
    pub identity: PublicKeyHash,
    /// The identity signing key (used to authorize writes to the user's subspace).
    pub signer: SigningPrivateKeyAndPublicHash,
    /// The login root symmetric key.
    pub root_key: SymmetricKey,
    /// Our boxing keypair (for follow requests / sharing); absent on legacy accounts.
    pub boxer: Option<peergos_core::boxing::BoxingKeyPair>,
    pub entries: Vec<EntryPoint>,
    /// The account mirror BAT — every block we write is tagged with its id so the
    /// server can mirror the data. `None` if the account has none.
    pub mirror_bat: Option<peergos_core::auth::BatWithId>,
}

impl LoggedInUser {
    /// The mirror BAT's id (hash form), used to tag written blocks.
    pub fn mirror_bat_id(&self) -> Option<peergos_core::auth::BatId> {
        self.mirror_bat.as_ref().map(|b| b.id())
    }
}

impl LoggedInUser {
    /// The capability to the user's own home directory (`/username`).
    pub fn home(&self) -> Option<&AbsoluteCapability> {
        self.entries
            .iter()
            .find(|e| e.owner_name == self.username)
            .map(|e| &e.pointer)
    }
}

/// The scrypt parameters + extra salt for key derivation (`ScryptGenerator`).
struct ScryptParams {
    memory_cost: u8,
    cpu_cost: u32,
    parallelism: u32,
    output_bytes: usize,
    extra_salt: String,
}

impl ScryptParams {
    fn from_writer_data(wd: &CborObject) -> Result<ScryptParams> {
        let algo = wd
            .get("algorithm")
            .ok_or_else(|| Error::Protocol("No login algorithm specified in user data!".into()))?;
        let get_long = |k: &str| algo.get(k).and_then(|c| c.as_long());
        Ok(ScryptParams {
            memory_cost: get_long("m")
                .ok_or_else(|| Error::Cbor("scrypt missing 'm'".into()))? as u8,
            cpu_cost: get_long("c").ok_or_else(|| Error::Cbor("scrypt missing 'c'".into()))? as u32,
            parallelism: get_long("p")
                .ok_or_else(|| Error::Cbor("scrypt missing 'p'".into()))? as u32,
            output_bytes: get_long("o")
                .ok_or_else(|| Error::Cbor("scrypt missing 'o'".into()))? as usize,
            extra_salt: algo
                .get("s")
                .and_then(|c| c.as_string())
                .unwrap_or("")
                .to_string(),
        })
    }
}

/// The derived login credentials (`UserWithRoot`).
struct GeneratedUser {
    login_pub: PublicSigningKey,
    login_secret: SecretSigningKey,
    root: SymmetricKey,
}

/// `UserUtil.generateUser`: scrypt(username+extraSalt, password) → login signing
/// keypair + root key. The boxing key derivation is skipped (unused for login).
fn generate_user(username: &str, password: &str, algo: &ScryptParams) -> Result<GeneratedUser> {
    if password == username {
        return Err(Error::Protocol(
            "Your password cannot be the same as your username!".into(),
        ));
    }
    let salt = format!("{username}{}", algo.extra_salt);
    let key_bytes = hash_to_key_bytes(
        &salt,
        password,
        algo.memory_cost,
        algo.cpu_cost,
        algo.parallelism,
        algo.output_bytes,
    )?;

    let has_boxer = algo.output_bytes == 96;
    let sign_seed = &key_bytes[0..32];
    let root_off = if has_boxer { 64 } else { 32 };
    let root_bytes = key_bytes[root_off..root_off + 32].to_vec();

    let (public, secret64) = keypair_from_seed(sign_seed)?;
    Ok(GeneratedUser {
        login_pub: PublicSigningKey::new(public.to_vec()),
        login_secret: SecretSigningKey::new(secret64.to_vec()),
        root: SymmetricKey::new(root_bytes, false)?,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `Serialize.serialize(String)`: 4-byte big-endian char count, then UTF-8 bytes.
fn serialize_string(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + s.len());
    out.extend_from_slice(&(s.chars().count() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    out
}

/// `CoreNode.getPublicKeyHash` — POST `core/getPublicKey`, response is a boolean
/// (present) followed by a length-prefixed `PublicKeyHash` cbor.
pub async fn get_public_key_hash(
    poster: &dyn HttpPoster,
    username: &str,
) -> Result<Option<PublicKeyHash>> {
    let url = format!("{CORE_URL}getPublicKey");
    let res = poster.post_unzip(&url, serialize_string(username), 15_000).await?;
    if res.is_empty() || res[0] == 0 {
        return Ok(None);
    }
    // [1 byte bool][4 byte BE length][cbor bytes]
    if res.len() < 5 {
        return Err(Error::Protocol("truncated getPublicKey response".into()));
    }
    let len = u32::from_be_bytes([res[1], res[2], res[3], res[4]]) as usize;
    let raw = res
        .get(5..5 + len)
        .ok_or_else(|| Error::Protocol("truncated getPublicKey key bytes".into()))?;
    let cbor = CborObject::from_bytes(raw)?;
    Ok(Some(PublicKeyHash::from_cbor(&cbor)?))
}

/// `TimeLimitedClient.signNow`: sign `CborLong(now_millis)` with the login key.
fn sign_now(login_secret: &SecretSigningKey) -> Result<Vec<u8>> {
    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let time = CborObject::Long(now_millis).to_bytes();
    login_secret.sign_message(&time)
}

/// A callback that answers a second-factor challenge during login (e.g. reads a
/// TOTP code from the user or an authenticator secret). Invoked only when the
/// server requests MFA. See [`login_with_mfa`] and [`mfa`](crate::mfa).
pub type MfaResponder<'a> =
    dyn Fn(&crate::mfa::MultiFactorAuthRequest) -> Result<crate::mfa::MultiFactorAuthResponse> + 'a;

/// GET `login/getLogin`, optionally carrying an MFA response, decoding the
/// `LoginResponse` cbor `{"a": bool, "r": UserStaticData | MultiFactorAuthRequest}`.
async fn fetch_login(
    poster: &dyn HttpPoster,
    username: &str,
    author: &str,
    auth: &str,
    mfa: Option<&crate::mfa::MultiFactorAuthResponse>,
) -> Result<CborObject> {
    let mut url =
        format!("{LOGIN_URL}getLogin?username={username}&author={author}&auth={auth}&proxy=false");
    if let Some(m) = mfa {
        url.push_str(&format!("&mfa={}", to_hex(&m.serialize())));
    }
    Ok(CborObject::from_bytes(&poster.get(&url).await?)?)
}

/// `Account.getLoginData` — fetch and decrypt the encrypted entry points. If the
/// server requires a second factor, `mfa` is invoked with the challenge and the
/// login is retried with the response (`getLogin` again). Returns the raw
/// `EntryPoints` cbor.
async fn get_login_data(
    poster: &dyn HttpPoster,
    username: &str,
    creds: &GeneratedUser,
    mfa: Option<&MfaResponder<'_>>,
) -> Result<CborObject> {
    // The signed timestamp authorises both the initial request and the MFA retry.
    let auth = to_hex(&sign_now(&creds.login_secret)?);
    let author = to_hex(&creds.login_pub.serialize());

    let resp = fetch_login(poster, username, &author, &auth, None).await?;
    // LoginResponse: {"a": bool, "r": UserStaticData | MultiFactorAuthRequest}
    if resp.get("a").and_then(|c| c.as_bool()).unwrap_or(false) {
        let static_data = resp.get("r").ok_or_else(|| Error::Cbor("LoginResponse missing 'r'".into()))?;
        // UserStaticData is a PaddedCipherText; decrypt with the root key → EntryPoints.
        return decrypt_entry_points(static_data, &creds.root);
    }

    // Second factor required.
    let req = crate::mfa::MultiFactorAuthRequest::from_cbor(
        resp.get("r").ok_or_else(|| Error::Cbor("LoginResponse missing 'r'".into()))?,
    )?;
    let responder = mfa.ok_or_else(|| {
        Error::Protocol("Account requires multi-factor authentication".into())
    })?;
    let answer = responder(&req)?;

    let resp2 = fetch_login(poster, username, &author, &auth, Some(&answer)).await?;
    if !resp2.get("a").and_then(|c| c.as_bool()).unwrap_or(false) {
        return Err(Error::Protocol("Multi-factor authentication failed".into()));
    }
    let static_data = resp2.get("r").ok_or_else(|| Error::Cbor("LoginResponse missing 'r'".into()))?;
    decrypt_entry_points(static_data, &creds.root)
}

/// UserStaticData padding block size (`UserStaticData`), same as signup.
const USER_STATIC_DATA_PADDING: usize = 4096;

/// Fetch the user's mirror BAT (`getUserBats`) — the last registered BAT — from the
/// bats endpoint, authorised by a time-limited identity signature. Every block a user
/// writes is tagged with this BAT's id so the server can mirror it.
pub async fn fetch_mirror_bat(
    username: &str,
    identity: &SigningPrivateKeyAndPublicHash,
    poster: &dyn HttpPoster,
) -> Result<Option<peergos_core::auth::BatWithId>> {
    let path = "peergos/v0/bats/getUserBats";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let req = CborObject::map()
        .put("p", CborObject::Str(path.to_string()))
        .put("t", CborObject::Long(now))
        .build();
    let auth = to_hex(&identity.secret.sign_message(&req.to_bytes())?);
    let url = format!(
        "{path}?username={}&auth={auth}",
        peergos_core::storage::url_encode(username)
    );
    match CborObject::from_bytes(&poster.get(&url).await?)? {
        CborObject::List(items) => items.last().map(peergos_core::auth::BatWithId::from_cbor).transpose(),
        _ => Ok(None),
    }
}

/// Change the account password (`UserContext.changePassword`), non-legacy accounts.
/// Re-derives the login key from `new_password` (keeping the existing salt — the
/// identity key and WriterData are unchanged), re-encrypts the entry points under
/// the new root key, and pushes the new login data to the account endpoint. After
/// this succeeds, sign in again with `new_password`.
pub async fn change_password(
    username: &str,
    old_password: &str,
    new_password: &str,
    mfa: Option<&MfaResponder<'_>>,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if old_password == new_password {
        return Err(Error::Protocol("You must change to a different password.".into()));
    }
    let owner = get_public_key_hash(poster, username)
        .await?
        .ok_or_else(|| Error::Protocol(format!("Unknown username: {username}")))?;
    let pointer = mutable.get_pointer_target(&owner, &owner, store.as_ref()).await?;
    let wd_cid = pointer.updated.ok_or_else(|| Error::Protocol("User has been deleted".into()))?;
    let wd = store.get(&owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data block missing".into()))?;
    if wd.get("static").is_some() {
        return Err(Error::Protocol("changing the password of a legacy account is not supported".into()));
    }
    let controller = wd
        .get("controller")
        .ok_or_else(|| Error::Cbor("WriterData missing 'controller'".into()))
        .and_then(PublicKeyHash::from_cbor)?;
    let algo = ScryptParams::from_writer_data(&wd)?;

    // Verify the old password and fetch the current (decrypted) entry points.
    let old_creds = generate_user(username, old_password, &algo)?;
    let entry_points_cbor = get_login_data(poster, username, &old_creds, mfa).await?;
    let (_, identity, _) = parse_entry_points(&entry_points_cbor)?;
    let identity = identity.ok_or_else(|| Error::Protocol("No identity key in login data".into()))?;
    let signer = SigningPrivateKeyAndPublicHash::new(controller, identity.secret);

    // Re-key: new login keypair + root from the new password (same salt), then
    // re-encrypt the same entry points under the new root and re-sign the login data.
    let new_creds = generate_user(username, new_password, &algo)?;
    let new_static =
        crate::cryptree::PaddedCipherText::build(&new_creds.root, &entry_points_cbor, USER_STATIC_DATA_PADDING)?.to_cbor();
    let login_data = CborObject::map()
        .put("u", CborObject::Str(username.to_string()))
        .put("e", new_static)
        .put("r", new_creds.login_pub.to_cbor())
        .build();
    let auth = to_hex(&signer.secret.signature_only(&login_data.to_bytes())?);
    let url = format!("{LOGIN_URL}setLogin?username={username}&auth={auth}&local=false");
    let res = poster.post_unzip(&url, login_data.to_bytes(), 0).await?;
    if res.first().copied() != Some(1) {
        return Err(Error::Protocol("server rejected the password change".into()));
    }
    Ok(())
}

/// Decrypt a `UserStaticData` (PaddedCipherText) to its `EntryPoints` cbor.
fn decrypt_entry_points(static_data: &CborObject, root: &SymmetricKey) -> Result<CborObject> {
    crate::cryptree::PaddedCipherText::from_cbor(static_data)?
        .decrypt(root, |c| Ok(c.clone()))
        .map_err(|_| Error::Protocol("Incorrect username or password".into()))
}

/// Parse the decrypted `EntryPoints` cbor into (entries, identity keypair, boxer).
fn parse_entry_points(
    cbor: &CborObject,
) -> Result<(Vec<EntryPoint>, Option<SigningKeyPair>, Option<peergos_core::boxing::BoxingKeyPair>)> {
    let entries = cbor
        .get("e")
        .and_then(|c| c.as_list())
        .ok_or_else(|| Error::Cbor("EntryPoints missing 'e'".into()))?
        .iter()
        .map(EntryPoint::from_cbor)
        .collect::<Result<Vec<_>>>()?;
    let identity = cbor.get("i").map(SigningKeyPair::from_cbor).transpose()?;
    let boxer = cbor.get("b").map(peergos_core::boxing::BoxingKeyPair::from_cbor).transpose()?;
    Ok((entries, identity, boxer))
}

/// Log in as `username` with `password` against the Peergos server behind
/// `poster` (and its block store / mutable pointers).
///
/// `store`/`mutable` fetch the user's `WriterData`; `poster` is used directly for
/// the core-node and account (login) endpoints.
///
/// Because whether an account has a second factor isn't known ahead of time, every
/// login goes through the MFA-capable path: `mfa` is a callback invoked *only* if
/// the server requests a second factor, receiving the
/// [`MultiFactorAuthRequest`](crate::mfa::MultiFactorAuthRequest) and returning a
/// [`MultiFactorAuthResponse`](crate::mfa::MultiFactorAuthResponse) (for TOTP, the
/// current code — see [`crate::mfa`]). Pass `None` only when you have no way to
/// answer a challenge; login then fails if the server requires one.
pub async fn login(
    username: &str,
    password: &str,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    mfa: Option<&MfaResponder<'_>>,
) -> Result<LoggedInUser> {
    // 1. username → owner identity key hash.
    let owner = get_public_key_hash(poster, username)
        .await?
        .ok_or_else(|| Error::Protocol(format!("Unknown username: {username}")))?;

    // 2. Fetch the owner's WriterData (self-signed pointer → cbor block).
    let pointer = mutable.get_pointer_target(&owner, &owner, store.as_ref()).await?;
    let wd_cid = pointer
        .updated
        .ok_or_else(|| Error::Protocol("User has been deleted".into()))?;
    let wd = store
        .get(&owner, &wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("writer data block missing".into()))?;
    let controller = wd
        .get("controller")
        .ok_or_else(|| Error::Cbor("WriterData missing 'controller'".into()))
        .and_then(PublicKeyHash::from_cbor)?;

    // 3. Derive login credentials from the password.
    let algo = ScryptParams::from_writer_data(&wd)?;
    let creds = generate_user(username, password, &algo)?;

    // 4./5. Get the entry points — either legacy (inside WriterData.static) or via
    // the login endpoint — and decrypt them with the root key.
    let (entry_points_cbor, legacy) = match wd.get("static") {
        Some(sd) => (decrypt_entry_points(sd, &creds.root)?, true),
        None => (get_login_data(poster, username, &creds, mfa).await?, false),
    };
    let (entries, identity, boxer) = parse_entry_points(&entry_points_cbor)?;

    // The identity signer: derived login key for legacy accounts, otherwise the
    // identity key stored (encrypted) in the entry points.
    let signer = if legacy {
        SigningPrivateKeyAndPublicHash::new(controller.clone(), creds.login_secret.clone())
    } else {
        let identity = identity
            .ok_or_else(|| Error::Protocol("No identity key in login data".into()))?;
        SigningPrivateKeyAndPublicHash::new(controller.clone(), identity.secret)
    };

    // The mirror BAT (used to tag every block this user writes). Best-effort:
    // legacy/BAT-less accounts simply get None.
    let mirror_bat = fetch_mirror_bat(username, &signer, poster).await.ok().flatten();

    Ok(LoggedInUser {
        username: username.to_string(),
        identity: controller,
        signer,
        root_key: creds.root,
        boxer,
        entries,
        mirror_bat,
    })
}
