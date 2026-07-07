//! `DirectS3Storage`: a `ContentAddressedStorage` wrapper that, when the Peergos
//! server exposes an S3-backed block store, reads and writes large blocks
//! **directly to S3** (via presigned URLs) instead of proxying every byte through
//! the server — ported from Java's `DirectS3BlockStore`.
//!
//! On construction it fetches the server's [`BlockStoreProperties`]
//! (`blockstore/props`). If S3 is not enabled (as on an IPFS-backed server, where
//! all properties are false) every operation transparently delegates to the
//! `fallback` storage, so this wrapper is always safe to use.
//!
//! Routing (matching Java):
//! - **reads** (`get_raw`): `publicReads` → GET `basePublicReadUrl + hashToKey`;
//!   else `authedReads` → `authReads` presigns a GET, then fetch it; on any failure
//!   fall back to the server. Identity (inline) hashes are returned directly.
//! - **writes** (`put_raw`): blocks < `MAX_SMALL_BLOCK_SIZE` (100 KiB) go to the
//!   server (S3 latency isn't worth it for tiny blocks); larger raw blocks with
//!   `directWrites` → `authWrites` presigns PUTs, then upload each to S3.
//! - cbor `put`, transactions, ids, sizes, secret links → `fallback`.

use crate::auth::{BatId, BatWithId};
use crate::error::{Error, Result};
use crate::keys::PublicKeyHash;
use crate::poster::HttpPoster;
use crate::storage::{url_encode, ContentAddressedStorage, TransactionId, API_PREFIX};
use async_trait::async_trait;
use peergos_cbor::{Cborable, CborObject};
use peergos_multiformats::bases::{base32_decode, base32_encode};
use peergos_multiformats::{Cid, Multihash};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Raw blocks below this size are written to the server, not S3 (Java's
/// `DirectS3BlockStore.MAX_SMALL_BLOCK_SIZE`).
pub const MAX_SMALL_BLOCK_SIZE: usize = 100 * 1024;

const RAW_BLOCK_MAGIC_PREFIX: [u8; 8] = [0x71, 0x1d, 0x10, 0xcf, 0x3d, 0x32, 0x2f, 0x2b];

const BLOCKSTORE_PROPERTIES: &str = "blockstore/props";
const AUTH_READS: &str = "blockstore/auth-reads";
const AUTH_WRITES: &str = "blockstore/auth";

/// The S3 key for a block: uppercase RFC-4648 base32 of the CID bytes, no padding
/// (`DirectS3BlockStore.hashToKey`, IPFS-compatible).
pub fn hash_to_key(hash: &Cid) -> String {
    base32_encode(&hash.to_bytes())
}

/// The CID for an S3 key (`DirectS3BlockStore.keyToHash`).
pub fn key_to_hash(key: &str) -> Result<Cid> {
    let bytes = base32_decode(key).map_err(|e| Error::Protocol(format!("bad S3 key base32: {e}")))?;
    Cid::cast(&bytes).map_err(Into::into)
}

/// The BAT ids embedded in a raw block's prefix (`Bat.getRawBlockBats`).
fn raw_block_bats(block: &[u8]) -> Vec<BatId> {
    if block.len() < RAW_BLOCK_MAGIC_PREFIX.len() || block[..8] != RAW_BLOCK_MAGIC_PREFIX {
        return Vec::new();
    }
    match CborObject::from_bytes(&block[8..]) {
        Ok(cbor) => cbor
            .as_list()
            .map(|l| l.iter().filter_map(|c| BatId::from_cbor(c).ok()).collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Whether/how the server's block store is S3-backed (`BlockStoreProperties`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockStoreProperties {
    pub direct_writes: bool,
    pub public_reads: bool,
    pub authed_reads: bool,
    pub base_public_read_url: Option<String>,
    pub base_authed_url: Option<String>,
}

impl BlockStoreProperties {
    pub fn empty() -> BlockStoreProperties {
        BlockStoreProperties::default()
    }

    /// True if S3 is used for reads or writes.
    pub fn use_direct_block_store(&self) -> bool {
        self.direct_writes || self.public_reads
    }

    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("w", CborObject::Boolean(self.direct_writes))
            .put("pr", CborObject::Boolean(self.public_reads))
            .put("ar", CborObject::Boolean(self.authed_reads))
            .put_opt("b", self.base_public_read_url.clone().map(CborObject::Str))
            .put_opt("ba", self.base_authed_url.clone().map(CborObject::Str))
            .build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<BlockStoreProperties> {
        let b = |k: &str| cbor.get(k).and_then(|c| c.as_bool()).unwrap_or(false);
        let s = |k: &str| cbor.get(k).and_then(|c| c.as_string()).map(str::to_string);
        Ok(BlockStoreProperties {
            direct_writes: b("w"),
            public_reads: b("pr"),
            authed_reads: b("ar"),
            base_public_read_url: s("b"),
            base_authed_url: s("ba"),
        })
    }
}

/// A presigned S3 request: the URL plus the headers/fields to send (`PresignedUrl`).
#[derive(Debug, Clone)]
pub struct PresignedUrl {
    pub base: String,
    pub fields: BTreeMap<String, String>,
}

impl PresignedUrl {
    pub fn from_cbor(cbor: &CborObject) -> Result<PresignedUrl> {
        let base = cbor
            .get("b")
            .and_then(|c| c.as_string())
            .ok_or_else(|| Error::Cbor("PresignedUrl missing 'b'".into()))?
            .to_string();
        let mut fields = BTreeMap::new();
        if let Some(m) = cbor.get("h").and_then(|c| c.as_map()) {
            for (k, v) in m {
                if let Some(val) = v.as_string() {
                    fields.insert(k.as_str().to_string(), val.to_string());
                }
            }
        }
        Ok(PresignedUrl { base, fields })
    }

    fn header_pairs(&self) -> Vec<(String, String)> {
        self.fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

/// A block + optional BAT to authorise a direct read (`BlockMirrorCap`).
struct BlockMirrorCap {
    hash: Cid,
    bat: Option<BatWithId>,
}

impl BlockMirrorCap {
    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("h", CborObject::ByteString(self.hash.to_bytes()));
        if let Some(bat) = &self.bat {
            b = b.put("b", bat.to_cbor());
        }
        b.build()
    }
}

/// The signatures + sizes + BAT ids authorising a batch of direct writes
/// (`WriteAuthRequest`).
struct WriteAuthRequest {
    signatures: Vec<Vec<u8>>,
    sizes: Vec<i64>,
    bat_ids: Vec<Vec<BatId>>,
}

impl WriteAuthRequest {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("s", CborObject::List(self.signatures.iter().cloned().map(CborObject::ByteString).collect()))
            .put("l", CborObject::List(self.sizes.iter().map(|s| CborObject::Long(*s)).collect()))
            .put(
                "b",
                CborObject::List(
                    self.bat_ids
                        .iter()
                        .map(|ids| CborObject::List(ids.iter().map(|id| id.to_cbor()).collect()))
                        .collect(),
                ),
            )
            .build()
    }
}

fn parse_presigned_list(raw: &[u8]) -> Result<Vec<PresignedUrl>> {
    CborObject::from_bytes(raw)?
        .as_list()
        .ok_or_else(|| Error::Cbor("expected a list of PresignedUrl".into()))?
        .iter()
        .map(PresignedUrl::from_cbor)
        .collect()
}

// ---------------------------------------------------------------------------
// The storage wrapper
// ---------------------------------------------------------------------------

/// A `ContentAddressedStorage` that reads/writes large blocks directly to S3 when
/// the server allows, and delegates everything else to `fallback`.
pub struct DirectS3Storage {
    props: BlockStoreProperties,
    /// Poster for the Peergos server (blockstore/props, auth-reads, auth).
    server: Arc<dyn HttpPoster>,
    /// Poster for the raw (absolute) presigned S3 URLs.
    direct: Arc<dyn HttpPoster>,
    fallback: Arc<dyn ContentAddressedStorage>,
}

impl DirectS3Storage {
    /// Build a direct-S3 store, fetching the server's block-store properties. If the
    /// properties can't be fetched or S3 is disabled, it behaves exactly like
    /// `fallback`.
    pub async fn build(
        server: Arc<dyn HttpPoster>,
        direct: Arc<dyn HttpPoster>,
        fallback: Arc<dyn ContentAddressedStorage>,
    ) -> DirectS3Storage {
        let props = Self::fetch_properties(server.as_ref()).await.unwrap_or_default();
        DirectS3Storage { props, server, direct, fallback }
    }

    /// Construct with already-known properties (e.g. from a cached login).
    pub fn with_properties(
        props: BlockStoreProperties,
        server: Arc<dyn HttpPoster>,
        direct: Arc<dyn HttpPoster>,
        fallback: Arc<dyn ContentAddressedStorage>,
    ) -> DirectS3Storage {
        DirectS3Storage { props, server, direct, fallback }
    }

    pub fn properties(&self) -> &BlockStoreProperties {
        &self.props
    }

    /// GET `blockstore/props` (`blockStoreProperties`).
    pub async fn fetch_properties(server: &dyn HttpPoster) -> Result<BlockStoreProperties> {
        let raw = server.get(&format!("{API_PREFIX}{BLOCKSTORE_PROPERTIES}")).await?;
        BlockStoreProperties::from_cbor(&CborObject::from_bytes(&raw)?)
    }

    /// POST `blockstore/auth-reads` → presigned GET URLs (`authReads`).
    async fn auth_reads(&self, owner: &PublicKeyHash, blocks: &[BlockMirrorCap]) -> Result<Vec<PresignedUrl>> {
        let body = CborObject::List(blocks.iter().map(|b| b.to_cbor()).collect()).to_bytes();
        let url = format!("{API_PREFIX}{AUTH_READS}?owner={}", url_encode(&owner.to_string()));
        parse_presigned_list(&self.server.post_unzip(&url, body, 30_000).await?)
    }

    /// POST `blockstore/auth` → presigned PUT URLs (`authWrites`).
    async fn auth_writes(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signatures: Vec<Vec<u8>>,
        sizes: Vec<i64>,
        bat_ids: Vec<Vec<BatId>>,
        is_raw: bool,
        tid: &TransactionId,
    ) -> Result<Vec<PresignedUrl>> {
        let body = WriteAuthRequest { signatures, sizes, bat_ids }.to_cbor().to_bytes();
        let url = format!(
            "{API_PREFIX}{AUTH_WRITES}?owner={}&writer={}&transaction={}&raw={is_raw}",
            url_encode(&owner.to_string()),
            url_encode(&writer.to_string()),
            url_encode(&tid.to_string()),
        );
        parse_presigned_list(&self.server.post_unzip(&url, body, 60_000).await?)
    }
}

#[async_trait]
impl ContentAddressedStorage for DirectS3Storage {
    async fn id(&self) -> Result<Cid> {
        self.fallback.id().await
    }
    async fn ids(&self) -> Result<Vec<Cid>> {
        self.fallback.ids().await
    }
    async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId> {
        self.fallback.start_transaction(owner).await
    }
    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool> {
        self.fallback.close_transaction(owner, tid).await
    }
    async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
        self.fallback.get_size(owner, block).await
    }
    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject> {
        self.fallback.get_secret_link(owner, label).await
    }
    async fn link_host(&self, owner: &PublicKeyHash) -> Result<String> {
        self.fallback.link_host(owner).await
    }

    async fn get(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<CborObject>> {
        match self.get_raw(owner, hash, bat).await? {
            Some(raw) => Ok(Some(CborObject::from_bytes(&raw)?)),
            None => Ok(None),
        }
    }

    async fn get_raw(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<Vec<u8>>> {
        if hash.multihash.is_identity() {
            return Ok(Some(hash.get_hash().to_vec()));
        }
        // Public S3 read.
        if self.props.public_reads {
            if let Some(base) = &self.props.base_public_read_url {
                if let Ok(bytes) = self.direct.get(&format!("{base}{}", hash_to_key(hash))).await {
                    if !bytes.is_empty() {
                        return Ok(Some(bytes));
                    }
                }
            }
        }
        // Authed S3 read (server presigns, we fetch).
        if self.props.authed_reads {
            let cap = BlockMirrorCap { hash: hash.clone(), bat: bat.cloned() };
            if let Ok(urls) = self.auth_reads(owner, std::slice::from_ref(&cap)).await {
                if let Some(u) = urls.first() {
                    if let Ok(bytes) = self.direct.get(&u.base).await {
                        if !bytes.is_empty() {
                            return Ok(Some(bytes));
                        }
                    }
                }
            }
        }
        // Anything else, or any failure above: go through the server.
        self.fallback.get_raw(owner, hash, bat).await
    }

    async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        // dag-cbor blocks are always small; write them via the server.
        self.fallback.put(owner, writer, signed_hashes, blocks, tid).await
    }

    async fn put_raw(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        // Small blocks aren't worth the S3 round-trip latency.
        let all_small = blocks.iter().all(|b| b.len() < MAX_SMALL_BLOCK_SIZE);
        if all_small || !self.props.direct_writes {
            return self.fallback.put_raw(owner, writer, signed_hashes, blocks, tid).await;
        }

        // Presign each block, then upload directly to S3.
        let sizes: Vec<i64> = blocks.iter().map(|b| b.len() as i64).collect();
        let bat_ids: Vec<Vec<BatId>> = blocks.iter().map(|b| raw_block_bats(b)).collect();
        let urls = match self
            .auth_writes(owner, writer, signed_hashes.clone(), sizes, bat_ids, true, tid)
            .await
        {
            Ok(u) if u.len() == blocks.len() => u,
            // On any auth failure, fall back to the server.
            _ => return self.fallback.put_raw(owner, writer, signed_hashes, blocks, tid).await,
        };

        let mut cids = Vec::with_capacity(blocks.len());
        for (block, url) in blocks.into_iter().zip(urls.into_iter()) {
            let key = url.base.rsplit('/').next().unwrap_or("").to_string();
            let cid = key_to_hash(&key)?;
            self.direct.put(&url.base, block, url.header_pairs()).await?;
            cids.push(cid);
        }
        Ok(cids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_store_properties_roundtrip() {
        // The exact bytes an IPFS-backed server returns: {w:false, ar:false, pr:false}.
        let disabled = BlockStoreProperties::from_cbor(
            &CborObject::from_bytes(&[0xa3, 0x61, 0x77, 0xf4, 0x62, 0x61, 0x72, 0xf4, 0x62, 0x70, 0x72, 0xf4]).unwrap(),
        )
        .unwrap();
        assert_eq!(disabled, BlockStoreProperties::empty());
        assert!(!disabled.use_direct_block_store());

        let enabled = BlockStoreProperties {
            direct_writes: true,
            public_reads: true,
            authed_reads: false,
            base_public_read_url: Some("https://s3.example/bucket/".into()),
            base_authed_url: None,
        };
        let reparsed = BlockStoreProperties::from_cbor(&enabled.to_cbor()).unwrap();
        assert_eq!(reparsed, enabled);
        assert!(enabled.use_direct_block_store());
    }

    #[test]
    fn presigned_url_from_cbor() {
        let cbor = CborObject::map()
            .put("b", CborObject::Str("https://s3.example/bucket/KEY".into()))
            .put("h", CborObject::map().put("x-amz-acl", CborObject::Str("private".into())).build())
            .build();
        let u = PresignedUrl::from_cbor(&cbor).unwrap();
        assert_eq!(u.base, "https://s3.example/bucket/KEY");
        assert_eq!(u.fields.get("x-amz-acl").map(String::as_str), Some("private"));
    }

    #[test]
    fn raw_block_bats_of_plain_block_is_empty() {
        assert!(raw_block_bats(b"not a raw peergos block").is_empty());
    }
}
