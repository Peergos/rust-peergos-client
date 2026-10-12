//! Caps on the space a writing space, and every writing space it owns, can use,
//! ported from `WriterQuotaRequest`, `WriterUsageInfo` and the writer quota
//! endpoints of `SpaceUsage`. An owner caps a folder they have shared with write
//! access, so whoever they shared it with can't fill their storage.

use crate::context::UserContext;
use crate::FileWrapper;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicKeyHash, SecretSigningKey, SigningPrivateKeyAndPublicHash};
use peergos_core::storage::url_encode;
use peergos_core::HttpPoster;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const SPACE_USAGE_URL: &str = "peergos/v0/storage/";

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A `TimeLimitedClient.SignedRequest` for `path`.
fn signed_request(secret: &SecretSigningKey, path: &str) -> Result<String> {
    let req = CborObject::map()
        .put("p", CborObject::Str(path.to_string()))
        .put("t", CborObject::Long(now_millis()))
        .build();
    Ok(to_hex(&secret.sign_message(&req.to_bytes())?))
}

/// A request, signed by an owner's identity key, to cap the space used by a
/// writing space and all the writing spaces it owns (`WriterQuotaRequest`). An
/// absent size removes the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterQuotaRequest {
    pub owner: PublicKeyHash,
    pub writer: PublicKeyHash,
    pub bytes: Option<i64>,
    pub utc_millis: i64,
}

impl WriterQuotaRequest {
    pub fn new(owner: PublicKeyHash, writer: PublicKeyHash, bytes: Option<i64>) -> Result<WriterQuotaRequest> {
        if bytes.is_some_and(|b| b < 0) {
            return Err(Error::Protocol("Negative quota!".into()));
        }
        Ok(WriterQuotaRequest { owner, writer, bytes, utc_millis: now_millis() })
    }
}

impl Cborable for WriterQuotaRequest {
    fn to_cbor(&self) -> CborObject {
        let mut m = CborObject::map().put("o", self.owner.to_cbor()).put("w", self.writer.to_cbor());
        if let Some(b) = self.bytes {
            m = m.put("s", CborObject::Long(b));
        }
        m.put("t", CborObject::Long(self.utc_millis)).build()
    }
}

/// The space cap on a writing space, and how much of it is used
/// (`WriterUsageInfo`). `quota` and `used` describe the writer's own subtree, and
/// `quota` is only present if the writer itself is capped. `available` is the
/// least space left under any cap that applies to the writer, including those of
/// its ancestors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterUsageInfo {
    pub writer: PublicKeyHash,
    pub quota: Option<i64>,
    pub used: i64,
    pub available: Option<i64>,
}

impl WriterUsageInfo {
    pub fn from_cbor(cbor: &CborObject) -> Result<WriterUsageInfo> {
        Ok(WriterUsageInfo {
            writer: PublicKeyHash::from_cbor(
                cbor.get("w").ok_or_else(|| Error::Cbor("WriterUsageInfo missing 'w'".into()))?,
            )?,
            quota: cbor.get("q").and_then(|c| c.as_long()),
            used: cbor.get("u").and_then(|c| c.as_long()).ok_or_else(|| Error::Cbor("WriterUsageInfo missing 'u'".into()))?,
            available: cbor.get("a").and_then(|c| c.as_long()),
        })
    }
}

/// Set or remove the cap on `writer` and all the writing spaces it owns
/// (`set-writer-quota`).
pub async fn set_writer_quota(
    identity: &SigningPrivateKeyAndPublicHash,
    writer: &PublicKeyHash,
    bytes: Option<i64>,
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let req = WriterQuotaRequest::new(identity.public_key_hash.clone(), writer.clone(), bytes)?;
    let signed = identity.secret.sign_message(&req.serialize())?;
    let url = format!(
        "{SPACE_USAGE_URL}set-writer-quota?owner={}&req={}",
        url_encode(&identity.public_key_hash.to_string()),
        to_hex(&signed)
    );
    CborObject::from_bytes(&poster.get(&url).await?)?
        .as_bool()
        .ok_or_else(|| Error::Protocol("expected a boolean response".into()))
}

/// Every capped writing space of the owner (`writer-quotas`).
pub async fn get_writer_quotas(
    identity: &SigningPrivateKeyAndPublicHash,
    poster: &dyn HttpPoster,
) -> Result<Vec<WriterUsageInfo>> {
    let auth = signed_request(&identity.secret, &format!("{SPACE_USAGE_URL}writer-quotas"))?;
    let url = format!(
        "{SPACE_USAGE_URL}writer-quotas?owner={}&auth={auth}",
        url_encode(&identity.public_key_hash.to_string())
    );
    CborObject::from_bytes(&poster.get(&url).await?)?
        .as_list()
        .ok_or_else(|| Error::Protocol("expected a CBOR list".into()))?
        .iter()
        .map(WriterUsageInfo::from_cbor)
        .collect()
}

/// The cap on and usage of `writer` (`writer-usage`), signed by the writer or by
/// the owner's identity key.
pub async fn get_writer_usage(
    owner: &PublicKeyHash,
    writer: &PublicKeyHash,
    signer: &SecretSigningKey,
    poster: &dyn HttpPoster,
) -> Result<WriterUsageInfo> {
    let auth = signed_request(signer, &format!("{SPACE_USAGE_URL}writer-usage/{owner}/{writer}"))?;
    let url = format!(
        "{SPACE_USAGE_URL}writer-usage?owner={}&writer={}&auth={auth}",
        url_encode(&owner.to_string()),
        url_encode(&writer.to_string())
    );
    WriterUsageInfo::from_cbor(&CborObject::from_bytes(&poster.get(&url).await?)?)
}

impl UserContext {
    /// The root of a writing space we own which has been shared with write access.
    async fn write_share_root(&self, path: &str) -> Result<FileWrapper> {
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let trimmed = path.trim_matches('/');
        let (parent_path, _) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
        let parent = self
            .get_by_path(parent_path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("Unable to read {parent_path}")))?;
        let file = self.get_by_path(trimmed).await?.ok_or_else(|| Error::Protocol(format!("Unable to read {path}")))?;
        if file.capability().owner != user.identity {
            return Err(Error::Protocol("Only the owner can limit the space of a shared folder".into()));
        }
        if file.capability().writer == parent.capability().writer {
            return Err(Error::Protocol("Share with write access first".into()));
        }
        Ok(file)
    }

    /// Limit the space that a folder shared with write access, and everything in
    /// it, can use (`setWriteShareQuota`); `None` removes the limit.
    pub async fn set_write_share_quota(&self, path: &str, bytes: Option<i64>) -> Result<bool> {
        let file = self.write_share_root(path).await?;
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        set_writer_quota(&user.signer, &file.capability().writer, bytes, self.poster().as_ref()).await
    }

    /// The limit on, and usage of, a folder we have shared with write access
    /// (`getWriteShareQuota`).
    pub async fn get_write_share_quota(&self, path: &str) -> Result<WriterUsageInfo> {
        let file = self.write_share_root(path).await?;
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        get_writer_usage(&user.identity, &file.capability().writer, &user.signer.secret, self.poster().as_ref()).await
    }

    /// Every writing space of ours with a limit on its space (`getWriteShareQuotas`).
    pub async fn get_write_share_quotas(&self) -> Result<Vec<WriterUsageInfo>> {
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        get_writer_quotas(&user.signer, self.poster().as_ref()).await
    }

    /// For a folder someone shared with us with write access: how much space is
    /// left in it, if its owner has limited it (`getWriteUsageInfo`).
    pub async fn get_write_usage_info(&self, file: &FileWrapper) -> Result<WriterUsageInfo> {
        if !file.is_writable() {
            return Err(Error::Protocol(format!("Not writable: {}", file.name())));
        }
        let signer = crate::recover_signer(file.capability(), self.store(), self.mutable().as_ref()).await?;
        get_writer_usage(&file.capability().owner, &file.capability().writer, &signer.secret, self.poster().as_ref()).await
    }

    /// The caps on our writing spaces, by writer.
    pub(crate) async fn writer_quota_map(&self) -> Result<HashMap<PublicKeyHash, i64>> {
        Ok(self
            .get_write_share_quotas()
            .await?
            .into_iter()
            .filter_map(|i| i.quota.map(|q| (i.writer, q)))
            .collect())
    }
}
