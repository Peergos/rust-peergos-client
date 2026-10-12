//! Admin operations: pending space requests, approval, server version, signups.
//! Ported from `HttpInstanceAdmin` and `InstanceAdmin`.

use crate::login::LoggedInUser;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::error::{Error, Result};
use peergos_core::storage::url_encode;
use peergos_core::HttpPoster;
use peergos_multiformats::Cid;
use std::time::{SystemTime, UNIX_EPOCH};

const ADMIN_URL: &str = "peergos/v0/admin/";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn signed_now(secret: &peergos_core::keys::SecretSigningKey) -> Result<String> {
    Ok(to_hex(&secret.sign_message(&CborObject::Long(now_millis()).to_bytes())?))
}

/// A `TimeLimitedClient.SignedRequest` for `ADMIN_URL + endpoint`.
fn signed_request(secret: &peergos_core::keys::SecretSigningKey, endpoint: &str) -> Result<String> {
    let req = CborObject::map()
        .put("p", CborObject::Str(format!("{ADMIN_URL}{endpoint}")))
        .put("t", CborObject::Long(now_millis()))
        .build();
    Ok(to_hex(&secret.sign_message(&req.to_bytes())?))
}

fn parse_bool(res: &[u8]) -> Result<bool> {
    CborObject::from_bytes(res)?
        .as_bool()
        .ok_or_else(|| Error::Protocol("expected a boolean response".into()))
}

fn parse_strings(res: &[u8]) -> Result<Vec<String>> {
    CborObject::from_bytes(res)?
        .as_list()
        .ok_or_else(|| Error::Protocol("expected a CBOR list".into()))?
        .iter()
        .map(|c| c.as_string().map(str::to_string).ok_or_else(|| Error::Protocol("expected a string".into())))
        .collect()
}

// ---- types ----------------------------------------------------------------

/// A pending space request from a user, mirroring `LabelledSignedSpaceRequest`.
#[derive(Debug, Clone)]
pub struct LabelledSignedSpaceRequest {
    pub username: String,
    pub signed_request: Vec<u8>,
}

impl LabelledSignedSpaceRequest {
    fn from_cbor(cbor: &CborObject) -> Result<Self> {
        Ok(LabelledSignedSpaceRequest {
            username: cbor.get("u").and_then(|v| v.as_string()).ok_or_else(|| Error::Protocol("missing 'u' in LabelledSignedSpaceRequest".into()))?.to_string(),
            signed_request: cbor.get("r").and_then(|v| v.as_bytes()).ok_or_else(|| Error::Protocol("missing 'r' in LabelledSignedSpaceRequest".into()))?.to_vec(),
        })
    }
}

impl Cborable for LabelledSignedSpaceRequest {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("u", CborObject::Str(self.username.clone()))
            .put("r", CborObject::ByteString(self.signed_request.clone()))
            .build()
    }
}

/// Server version info, mirroring `VersionInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VersionInfo {
    pub version: String,
    pub source_version: String,
}

impl VersionInfo {
    fn from_cbor(cbor: &CborObject) -> Result<Self> {
        Ok(VersionInfo {
            version: cbor.get("v").and_then(|v| v.as_string()).unwrap_or("").to_string(),
            source_version: cbor.get("s").and_then(|v| v.as_string()).unwrap_or("").to_string(),
        })
    }
}

/// Whether signups are allowed, mirroring `AllowedSignups`.
#[derive(Debug, Clone)]
pub struct AllowedSignups {
    pub free: bool,
    pub paid: bool,
}

impl AllowedSignups {
    fn from_cbor(cbor: &CborObject) -> Result<Self> {
        Ok(AllowedSignups {
            free: cbor.get("f").and_then(|v| v.as_bool()).unwrap_or(false),
            paid: cbor.get("p").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }
}

// ---- unauthenticated endpoints -------------------------------------------

/// Get the server's version info (`version`).
pub async fn get_version_info(poster: &dyn HttpPoster) -> Result<VersionInfo> {
    let url = format!("{ADMIN_URL}version");
    let res = poster.get(&url).await?;
    VersionInfo::from_cbor(&CborObject::from_bytes(&res)?)
}

/// Check whether the server is accepting signups (`signups`).
pub async fn accepting_signups(poster: &dyn HttpPoster) -> Result<AllowedSignups> {
    let url = format!("{ADMIN_URL}signups");
    let res = poster.get(&url).await?;
    AllowedSignups::from_cbor(&CborObject::from_bytes(&res)?)
}

/// Add an email to the server's waitlist (`waitlist`).
pub async fn add_to_waitlist(email: &str, poster: &dyn HttpPoster) -> Result<bool> {
    let url = format!("{ADMIN_URL}waitlist?email={}", url_encode(email));
    let res = poster.get(&url).await?;
    CborObject::from_bytes(&res)?
        .as_bool()
        .ok_or_else(|| Error::Protocol("expected a boolean response".into()))
}

// ---- admin-authenticated endpoints ---------------------------------------

/// Get the list of pending space requests (`pending`). Requires admin auth.
pub async fn get_pending_space_requests(
    admin: &LoggedInUser,
    instance: &Cid,
    poster: &dyn HttpPoster,
) -> Result<Vec<LabelledSignedSpaceRequest>> {
    let auth = signed_now(&admin.signer.secret)?;
    let url = format!(
        "{ADMIN_URL}pending?admin={}&instance={}&auth={auth}",
        url_encode(&admin.identity.to_string()),
        url_encode(&instance.to_string()),
    );
    let res = poster.get(&url).await?;
    let cbor = CborObject::from_bytes(&res)?;
    let list = cbor
        .as_list()
        .ok_or_else(|| Error::Protocol("expected a CBOR list".into()))?;
    list.iter().map(LabelledSignedSpaceRequest::from_cbor).collect()
}

/// Approve a pending space request (`approve`). The admin signs the
/// `LabelledSignedSpaceRequest` and sends it as the `req` parameter.
pub async fn approve_space_request(
    admin: &LoggedInUser,
    instance: &Cid,
    request: &LabelledSignedSpaceRequest,
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let signed = admin.signer.secret.sign_message(&request.serialize())?;
    let auth = to_hex(&signed);
    let url = format!(
        "{ADMIN_URL}approve?admin={}&instance={}&req={auth}",
        url_encode(&admin.identity.to_string()),
        url_encode(&instance.to_string()),
    );
    let res = poster.get(&url).await?;
    CborObject::from_bytes(&res)?
        .as_bool()
        .ok_or_else(|| Error::Protocol("expected a boolean response".into()))
}

/// Whether the signed-in user is an admin on this server (`isadmin`). Only its
/// owner may ask, so who the admins are stays hidden.
pub async fn is_admin(user: &LoggedInUser, poster: &dyn HttpPoster) -> Result<bool> {
    let auth = signed_request(&user.signer.secret, "isadmin")?;
    let url = format!("{ADMIN_URL}isadmin?admin={}&auth={auth}", url_encode(&user.identity.to_string()));
    parse_bool(&poster.get(&url).await?)
}

/// Create `count` single use signup tokens (`tokens`): each lets one new user sign
/// up, even when the instance is not otherwise accepting signups.
pub async fn create_signup_tokens(
    admin: &LoggedInUser,
    instance: &Cid,
    count: u32,
    poster: &dyn HttpPoster,
) -> Result<Vec<String>> {
    let auth = signed_request(&admin.signer.secret, "tokens")?;
    let url = format!(
        "{ADMIN_URL}tokens?admin={}&instance={}&auth={auth}&count={count}",
        url_encode(&admin.identity.to_string()),
        url_encode(&instance.to_string()),
    );
    parse_strings(&poster.get(&url).await?)
}

/// The signup tokens nobody has used yet (`listtokens`).
pub async fn list_signup_tokens(admin: &LoggedInUser, poster: &dyn HttpPoster) -> Result<Vec<String>> {
    let auth = signed_request(&admin.signer.secret, "listtokens")?;
    let url = format!("{ADMIN_URL}listtokens?admin={}&auth={auth}", url_encode(&admin.identity.to_string()));
    parse_strings(&poster.get(&url).await?)
}

/// Withdraw a signup token nobody has used yet (`revoketoken`). Returns whether
/// there was such a token.
pub async fn revoke_signup_token(admin: &LoggedInUser, token: &str, poster: &dyn HttpPoster) -> Result<bool> {
    let auth = signed_request(&admin.signer.secret, &format!("revoketoken/{token}"))?;
    let url = format!(
        "{ADMIN_URL}revoketoken?admin={}&token={}&auth={auth}",
        url_encode(&admin.identity.to_string()),
        url_encode(token),
    );
    parse_bool(&poster.get(&url).await?)
}

/// A release version `major.minor.patch[-suffix]` (`Version`). A version with a
/// suffix sorts before the same version without one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub suffix: String,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let (core, suffix) = s.split_once('-').unwrap_or((s, ""));
        let mut parts = core.split('.').map(|p| p.parse::<u32>().ok());
        let (major, minor, patch) = (parts.next()??, parts.next()??, parts.next()??);
        if parts.next().is_some() {
            return None;
        }
        Some(Version { major, minor, patch, suffix: suffix.to_string() })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)).then_with(|| {
            if self.suffix.is_empty() || other.suffix.is_empty() {
                other.suffix.len().cmp(&self.suffix.len())
            } else {
                self.suffix.cmp(&other.suffix)
            }
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.suffix.is_empty() {
            write!(f, "-{}", self.suffix)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn versions_order_numerically_with_suffixes_first() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("1.9.0") < v("1.10.0"));
        assert!(v("1.38.0-rc1") < v("1.38.0"));
        assert!(v("1.38.0-a") < v("1.38.0-b"));
        assert_eq!(v("1.2.3-x").to_string(), "1.2.3-x");
        assert!(Version::parse("1.2").is_none());
    }
}
