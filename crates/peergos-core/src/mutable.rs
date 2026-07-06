//! Mutable pointers, ported from `peergos.shared.mutable`.
//!
//! A mutable pointer maps a writer's public key to the current root hash of
//! their data, updated via a signed compare-and-swap ([`PointerUpdate`]). The
//! stored value is the writer's signature over the CBOR of the CAS pair; reading
//! the target therefore requires the writer's public signing key to unwrap it.

use crate::error::{Error, Result};
use crate::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use crate::poster::HttpPoster;
use crate::storage::{get_signing_key, ContentAddressedStorage};
use async_trait::async_trait;
use peergos_cbor::{CborObject, Cborable};
use peergos_multiformats::Cid;
use std::sync::Arc;

pub const MUTABLE_POINTERS_URL: &str = "peergos/v0/mutable/";

// ---- MaybeMultihash (Option<Cid>) cbor helpers -----------------------------

fn maybe_to_cbor(hash: &Option<Cid>) -> CborObject {
    match hash {
        Some(c) => CborObject::ByteString(c.to_bytes()),
        None => CborObject::Null,
    }
}

fn maybe_from_cbor(cbor: &CborObject) -> Result<Option<Cid>> {
    if cbor.is_null() {
        return Ok(None);
    }
    let bytes = cbor
        .as_bytes()
        .ok_or_else(|| Error::Cbor("Incorrect cbor for MaybeMultihash".into()))?;
    Ok(Some(Cid::cast(bytes)?))
}

/// `PointerUpdate` — a signed compare-and-swap from `original` to `updated`,
/// with an optional monotonic `sequence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerUpdate {
    pub original: Option<Cid>,
    pub updated: Option<Cid>,
    pub sequence: Option<i64>,
}

impl PointerUpdate {
    pub fn new(original: Option<Cid>, updated: Option<Cid>, sequence: Option<i64>) -> PointerUpdate {
        PointerUpdate { original, updated, sequence }
    }

    pub fn empty() -> PointerUpdate {
        PointerUpdate { original: None, updated: None, sequence: None }
    }

    /// `increment`: bump the sequence (starting at 1 when absent).
    pub fn increment(sequence: Option<i64>) -> Option<i64> {
        Some(sequence.map(|s| s + 1).unwrap_or(1))
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<PointerUpdate> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Incorrect cbor for PointerUpdate".into()))?;
        if list.len() < 2 {
            return Err(Error::Cbor("PointerUpdate needs at least 2 elements".into()));
        }
        let sequence = if list.len() < 3 {
            None
        } else {
            Some(
                list[2]
                    .as_long()
                    .ok_or_else(|| Error::Cbor("bad sequence in PointerUpdate".into()))?,
            )
        };
        Ok(PointerUpdate::new(
            maybe_from_cbor(&list[0])?,
            maybe_from_cbor(&list[1])?,
            sequence,
        ))
    }
}

impl Cborable for PointerUpdate {
    fn to_cbor(&self) -> CborObject {
        let mut items = vec![maybe_to_cbor(&self.original), maybe_to_cbor(&self.updated)];
        if let Some(seq) = self.sequence {
            items.push(CborObject::Long(seq));
        }
        CborObject::List(items)
    }
}

/// `SignedPointerUpdate` — a writer plus their signed CAS payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPointerUpdate {
    pub writer: PublicKeyHash,
    pub signed: Vec<u8>,
}

impl SignedPointerUpdate {
    pub fn new(writer: PublicKeyHash, signed: Vec<u8>) -> SignedPointerUpdate {
        SignedPointerUpdate { writer, signed }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<SignedPointerUpdate> {
        let writer = cbor
            .get("w")
            .ok_or_else(|| Error::Cbor("missing 'w' in SignedPointerUpdate".into()))
            .and_then(PublicKeyHash::from_cbor)?;
        let signed = cbor
            .get("s")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing 's' in SignedPointerUpdate".into()))?
            .to_vec();
        Ok(SignedPointerUpdate::new(writer, signed))
    }
}

impl Cborable for SignedPointerUpdate {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("w", self.writer.to_cbor())
            .put("s", CborObject::ByteString(self.signed.clone()))
            .build()
    }
}

/// `MultiWriterCommit` — the body of a `setPointers` batch update.
pub struct MultiWriterCommit {
    pub updates: Vec<SignedPointerUpdate>,
}

impl Cborable for MultiWriterCommit {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put(
                "p",
                CborObject::List(self.updates.iter().map(|u| u.to_cbor()).collect()),
            )
            .build()
    }
}

#[async_trait]
pub trait MutablePointers: Send + Sync {
    /// Update the hash a writer maps to (CAS). `writer_signed_payload` is the
    /// writer's signature over the CBOR of a [`PointerUpdate`].
    async fn set_pointer(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        writer_signed_payload: Vec<u8>,
    ) -> Result<bool>;

    /// Atomically update several writers under one owner.
    async fn set_pointers(
        &self,
        owner: &PublicKeyHash,
        updates: Vec<SignedPointerUpdate>,
    ) -> Result<bool>;

    /// The current signed CAS value for a writer, or `None` if unset.
    async fn get_pointer(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
    ) -> Result<Option<Vec<u8>>>;

    /// Sign and submit a [`PointerUpdate`] as the given writer.
    async fn set_pointer_update(
        &self,
        owner: &PublicKeyHash,
        writer: &SigningPrivateKeyAndPublicHash,
        cas_update: &PointerUpdate,
    ) -> Result<bool> {
        let signed = writer.secret.sign_message(&cas_update.serialize())?;
        self.set_pointer(owner, &writer.public_key_hash, signed).await
    }

    /// Resolve the current [`PointerUpdate`] for a writer, unwrapping the
    /// signature using the writer's public key fetched from `ipfs`.
    async fn get_pointer_target(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        ipfs: &dyn ContentAddressedStorage,
    ) -> Result<PointerUpdate> {
        match self.get_pointer(owner, writer).await? {
            Some(cas) => parse_pointer_target(&cas, owner, writer, ipfs).await,
            None => Ok(PointerUpdate::empty()),
        }
    }
}

/// Verify and decode a signed pointer CAS into a [`PointerUpdate`].
pub async fn parse_pointer_target(
    pointer_cas: &[u8],
    owner: &PublicKeyHash,
    writer_key_hash: &PublicKeyHash,
    ipfs: &dyn ContentAddressedStorage,
) -> Result<PointerUpdate> {
    match get_signing_key(ipfs, owner, writer_key_hash).await? {
        Some(writer_key) => {
            let signed = writer_key.unsign_message(pointer_cas)?;
            PointerUpdate::from_cbor(&CborObject::from_bytes(&signed)?)
        }
        None => Ok(PointerUpdate::empty()),
    }
}

/// HTTP-backed mutable pointers (`HttpMutablePointers`, direct path only).
pub struct HttpMutablePointers {
    poster: Arc<dyn HttpPoster>,
}

impl HttpMutablePointers {
    pub fn new(poster: Arc<dyn HttpPoster>) -> HttpMutablePointers {
        HttpMutablePointers { poster }
    }
}

/// `DataInputStream.readBoolean`: first byte non-zero => true.
fn read_boolean(res: &[u8]) -> bool {
    res.first().is_some_and(|b| *b != 0)
}

#[async_trait]
impl MutablePointers for HttpMutablePointers {
    async fn set_pointer(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        writer_signed_payload: Vec<u8>,
    ) -> Result<bool> {
        let url = format!("{MUTABLE_POINTERS_URL}setPointer?owner={owner}&writer={writer}");
        let res = self.poster.post_unzip(&url, writer_signed_payload, 60_000).await?;
        Ok(read_boolean(&res))
    }

    async fn set_pointers(
        &self,
        owner: &PublicKeyHash,
        updates: Vec<SignedPointerUpdate>,
    ) -> Result<bool> {
        let url = format!("{MUTABLE_POINTERS_URL}setPointers?owner={owner}");
        let body = MultiWriterCommit { updates }.serialize();
        let res = self.poster.post_unzip(&url, body, 60_000).await?;
        Ok(read_boolean(&res))
    }

    async fn get_pointer(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
    ) -> Result<Option<Vec<u8>>> {
        let url = format!("{MUTABLE_POINTERS_URL}getPointer?owner={owner}&writer={writer}");
        let res = self.poster.get(&url).await?;
        Ok(if res.is_empty() { None } else { Some(res) })
    }
}
