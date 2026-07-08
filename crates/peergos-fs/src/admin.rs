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
#[derive(Debug, Clone)]
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
