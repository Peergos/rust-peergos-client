//! `ContentAddressedStorage` — the block store client, ported from
//! `ContentAddressedStorage.HTTP`. Covers the direct-to-Peergos-server path:
//! id/ids, transactions, block get/put (dag-cbor and raw) and stat.
//!
//! Not yet ported (later increments): BAT block-access-token auth, direct-S3
//! writes, champ lookups, caching layers, and the proxying variant.

use crate::auth::{current_datetime, BatWithId};
use crate::champ::{Champ, Payload, BIT_WIDTH};
use crate::error::{Error, Result};
use crate::keys::{PublicKeyHash, PublicSigningKey, SigningPrivateKeyAndPublicHash};
use crate::poster::HttpPoster;
use async_trait::async_trait;
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::hash::sha256;
use peergos_multiformats::bases::multibase_encode_base58btc;
use peergos_multiformats::{Cid, Codec, Multihash, MultihashType, CID_V1};
use std::collections::HashSet;
use std::sync::Arc;

/// The maximum number of champ lookups to batch into a single `champ/get/bulk`
/// call (`ContentAddressedStorage.MAX_CHAMP_GETS`).
pub const MAX_CHAMP_GETS: usize = 20;

/// A single chunk's champ lookup key + its block-access token (`ChunkMirrorCap`).
#[derive(Debug, Clone)]
pub struct ChunkMirrorCap {
    pub map_key: Vec<u8>,
    pub bat: Option<BatWithId>,
}

impl ChunkMirrorCap {
    pub fn new(map_key: Vec<u8>, bat: Option<BatWithId>) -> ChunkMirrorCap {
        ChunkMirrorCap { map_key, bat }
    }

    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("m", CborObject::ByteString(self.map_key.clone()))
            .put_opt("b", self.bat.as_ref().map(|b| b.to_cbor()))
            .build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<ChunkMirrorCap> {
        let map_key = cbor
            .get("m")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("ChunkMirrorCap missing 'm'".into()))?
            .to_vec();
        let bat = cbor.get("b").map(BatWithId::from_cbor).transpose()?;
        Ok(ChunkMirrorCap { map_key, bat })
    }
}

pub const API_PREFIX: &str = "api/v0/";
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024 + 100; // Fragment.MAX_LENGTH_WITH_BAT_PREFIX

/// A write-grouping transaction handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionId(pub String);

impl std::fmt::Display for TransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `BlockWriteGroup` — cbor `{b: [blocks], s: [signatures]}`.
pub struct BlockWriteGroup {
    pub blocks: Vec<Vec<u8>>,
    pub signatures: Vec<Vec<u8>>,
}

impl Cborable for BlockWriteGroup {
    fn to_cbor(&self) -> CborObject {
        let to_list =
            |v: &[Vec<u8>]| CborObject::List(v.iter().map(|b| CborObject::ByteString(b.clone())).collect());
        CborObject::map()
            .put("b", to_list(&self.blocks))
            .put("s", to_list(&self.signatures))
            .build()
    }
}

impl BlockWriteGroup {
    pub fn from_cbor(cbor: &CborObject) -> Result<BlockWriteGroup> {
        let list = |field: &str| -> Result<Vec<Vec<u8>>> {
            Ok(cbor
                .get(field)
                .and_then(|c| c.as_list())
                .ok_or_else(|| Error::Cbor(format!("BlockWriteGroup missing '{field}'")))?
                .iter()
                .filter_map(|b| b.as_bytes().map(|x| x.to_vec()))
                .collect())
        };
        Ok(BlockWriteGroup { blocks: list("b")?, signatures: list("s")? })
    }
}

/// Build a CIDv1 (sha2-256) for a block, dag-cbor or raw.
pub fn build_cid(sha256_hash: Vec<u8>, is_raw: bool) -> Result<Cid> {
    let codec = if is_raw { Codec::Raw } else { Codec::DagCbor };
    Ok(Cid::new(CID_V1, codec, MultihashType::Sha2_256, sha256_hash)?)
}

/// Hash a block's bytes into its CID (`hashToCid`).
pub fn hash_to_cid(input: &[u8], is_raw: bool) -> Result<Cid> {
    build_cid(sha256(input), is_raw)
}

/// Sign a single block for writing: the writer signs `sha256(block)`, yielding a
/// NaCl attached signature (`sig || hash`), matching the default `put`.
pub fn sign_block(writer: &SigningPrivateKeyAndPublicHash, block: &[u8]) -> Result<Vec<u8>> {
    writer.secret.sign_message(&sha256(block))
}

/// `application/x-www-form-urlencoded` component encoding, matching Java's
/// `URLEncoder.encode(_, "UTF-8")`. For CID strings this is effectively a no-op.
pub fn url_encode(component: &str) -> String {
    let mut out = String::with_capacity(component.len());
    for &b in component.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[async_trait]
pub trait ContentAddressedStorage: Send + Sync {
    /// The identity (public-key hash) of this server.
    async fn id(&self) -> Result<Cid>;

    /// All current and previous identities of this server.
    async fn ids(&self) -> Result<Vec<Cid>>;

    async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId>;

    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool>;

    /// Fetch a dag-cbor block, deserialized, or `None` if absent.
    async fn get(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>)
        -> Result<Option<CborObject>>;

    /// Fetch a raw (non-cbor) block, or `None` if absent.
    async fn get_raw(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>)
        -> Result<Option<Vec<u8>>>;

    /// Write dag-cbor blocks; `signed_hashes[i]` authorizes `blocks[i]`.
    async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>>;

    /// Write raw (non-cbor) blocks.
    async fn put_raw(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>>;

    /// Size in bytes of a block, or `None` if absent.
    async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>>;

    /// Fetch the encrypted capability behind a secret link label (`link/get`).
    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject>;

    /// The hostname that serves `owner`'s secret/public links (`linkHost`). The
    /// default (and non-Peergos-server case) is `"localhost"`; the [`HttpStorage`]
    /// override asks the server, and buffering/fallback wrappers delegate.
    async fn link_host(&self, _owner: &PublicKeyHash) -> Result<String> {
        Ok("localhost".to_string())
    }

    /// Look up a set of champ keys under `root`, returning every block on each
    /// key's path plus its value block, in one call (`getChampLookup` /
    /// `champ/get/bulk`). The default walks the champ locally; the peergos-server
    /// [`HttpStorage`] override has the server do the walk. Callers must verify the
    /// result by re-running the lookup locally against the returned blocks (see
    /// [`champ_lookup_local`], and `RamStorage::load_verified`).
    async fn get_champ_lookup(
        &self,
        owner: &PublicKeyHash,
        root: &Cid,
        caps: &[ChunkMirrorCap],
        committed_root: Option<&Cid>,
    ) -> Result<Vec<Vec<u8>>> {
        champ_lookup_local(self, owner, root, caps, committed_root).await
    }
}

/// Walk the champ under `root` locally, collecting the blocks on each cap's path
/// and the value block it points at. Used both as the default `get_champ_lookup`
/// and as the server-side equivalent. Uses identity key hashing (the writer-data
/// file tree). O(depth) blocks per cap — identical subtrees are never touched.
pub async fn champ_lookup_local<S: ContentAddressedStorage + ?Sized>(
    store: &S,
    owner: &PublicKeyHash,
    root: &Cid,
    caps: &[ChunkMirrorCap],
    _committed_root: Option<&Cid>,
) -> Result<Vec<Vec<u8>>> {
    let mut recorded = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for cap in caps {
        champ_walk_one(store, owner, root, &cap.map_key, cap.bat.as_ref(), &mut recorded, &mut seen).await?;
    }
    Ok(recorded)
}

#[allow(clippy::too_many_arguments)]
async fn champ_walk_one<S: ContentAddressedStorage + ?Sized>(
    store: &S,
    owner: &PublicKeyHash,
    root: &Cid,
    map_key: &[u8],
    bat: Option<&BatWithId>,
    recorded: &mut Vec<Vec<u8>>,
    seen: &mut HashSet<Vec<u8>>,
) -> Result<()> {
    let mut current = root.clone();
    let mut depth = 0usize;
    loop {
        let bytes = match store.get_raw(owner, &current, None).await? {
            Some(b) => b,
            None => return Ok(()), // path node absent — nothing more to collect
        };
        if seen.insert(current.to_bytes()) {
            recorded.push(bytes.clone());
        }
        let champ = Champ::from_cbor(&CborObject::from_bytes(&bytes)?)?;
        let bit = Champ::mask(map_key, depth, BIT_WIDTH); // identity hasher: hash == key
        if bit_set(&champ.data_map, bit) {
            // The key, if present, is inline in this node's data payload.
            let di = popcount_below(&champ.data_map, bit);
            if let Some(Payload::Mappings(mappings)) = champ.contents.get(di) {
                for m in mappings {
                    if m.key == map_key {
                        if let Some(link) = m.value.as_ref().and_then(|v| v.as_link()) {
                            let vcid = Cid::cast(link)?;
                            if let Some(vb) = store.get_raw(owner, &vcid, bat).await? {
                                if seen.insert(vcid.to_bytes()) {
                                    recorded.push(vb);
                                }
                            }
                        }
                        return Ok(());
                    }
                }
            }
            return Ok(()); // slot present but key not here
        } else if bit_set(&champ.node_map, bit) {
            // Descend into the child shard.
            let ni = popcount_below(&champ.node_map, bit);
            let link_idx = champ.contents.len() - 1 - ni;
            match champ.contents.get(link_idx) {
                Some(Payload::Link(c)) => {
                    current = c.clone();
                    depth += 1;
                }
                _ => return Ok(()),
            }
        } else {
            return Ok(()); // key absent
        }
    }
}

fn bit_set(bitmap: &[u8], pos: usize) -> bool {
    let byte = pos / 8;
    byte < bitmap.len() && (bitmap[byte] >> (pos % 8)) & 1 == 1
}

/// Number of set bits at positions `[0, pos)`.
fn popcount_below(bitmap: &[u8], pos: usize) -> usize {
    (0..pos).filter(|&p| bit_set(bitmap, p)).count()
}

/// Reads served from `primary` first (e.g. verified `champ/get` blocks), falling
/// back to `secondary` for anything absent (e.g. buffered-but-uncommitted nodes).
/// All writes and other operations go to `secondary`. Mirrors the `combined`
/// `DelegatingStorage` in Java's `retrieveAllMetadata`.
pub struct FallbackStorage {
    primary: Arc<dyn ContentAddressedStorage>,
    secondary: Arc<dyn ContentAddressedStorage>,
}

impl FallbackStorage {
    pub fn new(primary: Arc<dyn ContentAddressedStorage>, secondary: Arc<dyn ContentAddressedStorage>) -> FallbackStorage {
        FallbackStorage { primary, secondary }
    }
}

#[async_trait]
impl ContentAddressedStorage for FallbackStorage {
    async fn id(&self) -> Result<Cid> {
        self.secondary.id().await
    }
    async fn ids(&self) -> Result<Vec<Cid>> {
        self.secondary.ids().await
    }
    async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId> {
        self.secondary.start_transaction(owner).await
    }
    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool> {
        self.secondary.close_transaction(owner, tid).await
    }
    async fn get(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<CborObject>> {
        match self.primary.get(owner, hash, bat).await? {
            Some(b) => Ok(Some(b)),
            None => self.secondary.get(owner, hash, bat).await,
        }
    }
    async fn get_raw(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<Vec<u8>>> {
        match self.primary.get_raw(owner, hash, bat).await? {
            Some(b) => Ok(Some(b)),
            None => self.secondary.get_raw(owner, hash, bat).await,
        }
    }
    async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.secondary.put(owner, writer, signed_hashes, blocks, tid).await
    }
    async fn put_raw(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.secondary.put_raw(owner, writer, signed_hashes, blocks, tid).await
    }
    async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
        self.secondary.get_size(owner, block).await
    }
    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject> {
        self.secondary.get_secret_link(owner, label).await
    }
    async fn link_host(&self, owner: &PublicKeyHash) -> Result<String> {
        self.secondary.link_host(owner).await
    }
}

/// HTTP-backed content addressed storage (`ContentAddressedStorage.HTTP`).
pub struct HttpStorage {
    poster: Arc<dyn HttpPoster>,
    is_peergos_server: bool,
}

impl HttpStorage {
    pub fn new(poster: Arc<dyn HttpPoster>, is_peergos_server: bool) -> HttpStorage {
        HttpStorage { poster, is_peergos_server }
    }

    async fn bulk_put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signatures: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        format: &str,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        if blocks.len() != signatures.len() {
            return Err(Error::Protocol("blocks/signatures length mismatch".into()));
        }
        if self.is_peergos_server && signatures.iter().any(|s| s.is_empty()) {
            return Err(Error::Protocol("Empty signature in block write!".into()));
        }
        // Group so each request stays within MAX_BLOCK_SIZE, preserving order.
        let mut result = Vec::with_capacity(blocks.len());
        let mut group_blocks: Vec<Vec<u8>> = Vec::new();
        let mut group_sigs: Vec<Vec<u8>> = Vec::new();
        let mut group_size = 0usize;
        for (block, sig) in blocks.into_iter().zip(signatures.into_iter()) {
            if block.len() > MAX_BLOCK_SIZE {
                return Err(Error::Protocol(format!(
                    "Invalid block size: {}, blocks must be smaller than 1MiB!",
                    block.len()
                )));
            }
            if group_size + block.len() > MAX_BLOCK_SIZE && !group_blocks.is_empty() {
                result.extend(
                    self.put_group(owner, writer, &group_sigs, &group_blocks, format, tid)
                        .await?,
                );
                group_blocks.clear();
                group_sigs.clear();
                group_size = 0;
            }
            group_size += block.len();
            group_blocks.push(block);
            group_sigs.push(sig);
        }
        if !group_blocks.is_empty() {
            result.extend(
                self.put_group(owner, writer, &group_sigs, &group_blocks, format, tid)
                    .await?,
            );
        }
        Ok(result)
    }

    async fn put_group(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signatures: &[Vec<u8>],
        blocks: &[Vec<u8>],
        format: &str,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        let body = BlockWriteGroup {
            blocks: blocks.to_vec(),
            signatures: signatures.to_vec(),
        }
        .serialize();
        let url = format!(
            "{API_PREFIX}block/put/bulk?format={format}&owner={}&transaction={}&writer={}",
            url_encode(&owner.to_string()),
            url_encode(&tid.to_string()),
            url_encode(&writer.to_string()),
        );
        let raw = self.poster.post(&url, body, false, 30_000).await?;
        let hashes = parse_hash_stream(&raw)?;
        if hashes.len() != blocks.len() {
            return Err(Error::Protocol(format!(
                "Incorrect number of hashes returned from bulk write: {} != {}",
                hashes.len(),
                blocks.len()
            )));
        }
        Ok(hashes)
    }

    async fn get_bytes(
        &self,
        owner: &PublicKeyHash,
        hash: &Cid,
        bat: Option<&BatWithId>,
    ) -> Result<Option<Vec<u8>>> {
        let owner_enc = url_encode(&owner.to_string());
        let url = if self.is_peergos_server {
            // The server does the S3 signing; we just pass the BAT along.
            let bat_param = bat.map(|b| format!("&bat={}", b.encode())).unwrap_or_default();
            format!("{API_PREFIX}block/get?arg={hash}&owner={owner_enc}{bat_param}")
        } else {
            // Direct-to-S3 path: we compute the SigV4 auth ourselves.
            let auth = match bat {
                Some(b) => {
                    let our_id = self.id().await?;
                    b.bat
                        .generate_auth(hash, &our_id, 300, &current_datetime(), &b.id)?
                        .encode()
                }
                None => String::new(),
            };
            format!("{API_PREFIX}block/get?arg={hash}&owner={owner_enc}&auth={auth}")
        };
        let raw = self.poster.get(&url).await?;
        Ok(if raw.is_empty() { None } else { Some(raw) })
    }
}

#[async_trait]
impl ContentAddressedStorage for HttpStorage {
    async fn id(&self) -> Result<Cid> {
        let raw = self.poster.get(&format!("{API_PREFIX}id")).await?;
        let json: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| Error::Protocol(format!("bad id json: {e}")))?;
        let s = json
            .get("ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Protocol("missing ID field".into()))?;
        Ok(Cid::decode_peer_id(s)?)
    }

    async fn ids(&self) -> Result<Vec<Cid>> {
        let raw = self.poster.get(&format!("{API_PREFIX}ids")).await?;
        let json: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| Error::Protocol(format!("bad ids json: {e}")))?;
        let arr = json
            .get("IDS")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Protocol("missing IDS field".into()))?;
        arr.iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| Error::Protocol("non-string peer id".into()))
                    .and_then(|s| Cid::decode_peer_id(s).map_err(Into::into))
            })
            .collect()
    }

    async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId> {
        if !self.is_peergos_server {
            return Ok(TransactionId("0".into()));
        }
        let url = format!(
            "{API_PREFIX}transaction/start?owner={}",
            url_encode(&owner.to_string())
        );
        let raw = self.poster.get(&url).await?;
        Ok(TransactionId(String::from_utf8_lossy(&raw).to_string()))
    }

    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool> {
        if !self.is_peergos_server {
            return Ok(true);
        }
        let url = format!(
            "{API_PREFIX}transaction/close?arg={tid}&owner={}",
            url_encode(&owner.to_string())
        );
        let raw = self.poster.get(&url).await?;
        Ok(String::from_utf8_lossy(&raw) == "1")
    }

    async fn get(
        &self,
        owner: &PublicKeyHash,
        hash: &Cid,
        bat: Option<&BatWithId>,
    ) -> Result<Option<CborObject>> {
        if hash.multihash.is_identity() {
            return Ok(Some(CborObject::from_bytes(hash.get_hash())?));
        }
        match self.get_bytes(owner, hash, bat).await? {
            Some(raw) => Ok(Some(CborObject::from_bytes(&raw)?)),
            None => Ok(None),
        }
    }

    async fn get_raw(
        &self,
        owner: &PublicKeyHash,
        hash: &Cid,
        bat: Option<&BatWithId>,
    ) -> Result<Option<Vec<u8>>> {
        if hash.multihash.is_identity() {
            return Ok(Some(hash.get_hash().to_vec()));
        }
        self.get_bytes(owner, hash, bat).await
    }

    async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.bulk_put(owner, writer, signed_hashes, blocks, "dag-cbor", tid).await
    }

    async fn put_raw(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.bulk_put(owner, writer, signed_hashes, blocks, "raw", tid).await
    }

    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject> {
        let url = format!(
            "{API_PREFIX}link/get?label={label}&owner={}",
            url_encode(&owner.to_string())
        );
        let raw = self.poster.get(&url).await?;
        Ok(CborObject::from_bytes(&raw)?)
    }

    async fn link_host(&self, owner: &PublicKeyHash) -> Result<String> {
        let url = format!("{API_PREFIX}link-host?owner={}", url_encode(&owner.to_string()));
        let raw = self.poster.get(&url).await?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    async fn get_champ_lookup(
        &self,
        owner: &PublicKeyHash,
        root: &Cid,
        caps: &[ChunkMirrorCap],
        committed_root: Option<&Cid>,
    ) -> Result<Vec<Vec<u8>>> {
        // Only a peergos server exposes champ/get/bulk; otherwise walk locally.
        if !self.is_peergos_server {
            return champ_lookup_local(self, owner, root, caps, committed_root).await;
        }
        if caps.is_empty() {
            return Ok(Vec::new());
        }
        let caps_cbor = CborObject::List(caps.iter().map(|c| c.to_cbor()).collect());
        let encoded = multibase_encode_base58btc(&caps_cbor.serialize());
        let url = format!(
            "{API_PREFIX}champ/get/bulk?arg={root}&owner={}&caps={encoded}",
            url_encode(&owner.to_string())
        );
        let raw = self.poster.get(&url).await?;
        match CborObject::from_bytes(&raw)? {
            CborObject::List(items) => items
                .into_iter()
                .map(|c| {
                    c.as_bytes()
                        .map(|b| b.to_vec())
                        .ok_or_else(|| Error::Protocol("champ/get item is not a byte array".into()))
                })
                .collect(),
            _ => Err(Error::Protocol("champ/get response is not a list".into())),
        }
    }

    async fn get_size(&self, _owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
        if block.is_identity() {
            return Ok(Some(block.get_hash().len() as u64));
        }
        let url = format!("{API_PREFIX}block/stat?arg={block}&auth=letmein");
        let raw = self.poster.get(&url).await?;
        let json: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| Error::Protocol(format!("bad stat json: {e}")))?;
        Ok(json.get("Size").and_then(|v| v.as_u64()))
    }
}

/// Sign and write a single dag-cbor block, returning its CID (the default
/// signing `put`: sign `sha256(block)` with the writer, then `put`).
pub async fn put_block_signed(
    store: &dyn ContentAddressedStorage,
    owner: &PublicKeyHash,
    writer: &SigningPrivateKeyAndPublicHash,
    block: Vec<u8>,
    tid: &TransactionId,
) -> Result<Cid> {
    let sig = sign_block(writer, &block)?;
    let cids = store
        .put(owner, &writer.public_key_hash, vec![sig], vec![block], tid)
        .await?;
    cids.into_iter()
        .next()
        .ok_or_else(|| Error::Protocol("put returned no cid".into()))
}

/// Sign and write raw (non-cbor) blocks, returning their CIDs.
pub async fn put_raw_blocks_signed(
    store: &dyn ContentAddressedStorage,
    owner: &PublicKeyHash,
    writer: &SigningPrivateKeyAndPublicHash,
    blocks: Vec<Vec<u8>>,
    tid: &TransactionId,
) -> Result<Vec<Cid>> {
    if blocks.is_empty() {
        return Ok(Vec::new());
    }
    let sigs = blocks.iter().map(|b| sign_block(writer, b)).collect::<Result<Vec<_>>>()?;
    store.put_raw(owner, &writer.public_key_hash, sigs, blocks, tid).await
}

/// `ContentAddressedStorage.getSigningKey`: resolve a writer's public signing
/// key, either inlined in an identity hash or fetched as a block.
pub async fn get_signing_key(
    store: &dyn ContentAddressedStorage,
    owner: &PublicKeyHash,
    hash: &PublicKeyHash,
) -> Result<Option<PublicSigningKey>> {
    if hash.is_identity() {
        let cbor = CborObject::from_bytes(hash.target.get_hash())?;
        return Ok(Some(PublicSigningKey::from_cbor(&cbor)?));
    }
    match store.get(owner, &hash.target, None).await? {
        Some(cbor) => Ok(Some(PublicSigningKey::from_cbor(&cbor)?)),
        None => Ok(None),
    }
}

/// Parse the newline/concatenated JSON objects returned by `block/put/bulk`,
/// extracting the CID from each (`Hash`, or `Key` / `Key./`).
fn parse_hash_stream(raw: &[u8]) -> Result<Vec<Cid>> {
    let mut out = Vec::new();
    let stream = serde_json::Deserializer::from_slice(raw).into_iter::<serde_json::Value>();
    for item in stream {
        let value = item.map_err(|e| Error::Protocol(format!("bad put json: {e}")))?;
        out.push(get_object_hash(&value)?);
    }
    Ok(out)
}

fn get_object_hash(json: &serde_json::Value) -> Result<Cid> {
    let hash = if let Some(h) = json.get("Hash").and_then(|v| v.as_str()) {
        h.to_string()
    } else {
        match json.get("Key") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Object(m)) => m
                .get("/")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Protocol("Couldn't parse hash from response!".into()))?
                .to_string(),
            _ => return Err(Error::Protocol("Couldn't parse hash from response!".into())),
        }
    };
    Ok(Cid::decode(&hash)?)
}

#[cfg(test)]
mod champ_lookup_tests {
    use super::*;
    use crate::champ::{identity_key_hasher, Champ, ChampWrapper};
    use crate::keys::{PublicSigningKey, SecretSigningKey};
    use crate::ram::RamStorage;

    #[tokio::test]
    async fn champ_get_returns_path_and_value_and_is_locally_verifiable() {
        let store: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
        let (pk, sk) = peergos_crypto::sign::keypair_from_seed(&[7u8; 32]).unwrap();
        let owner = PublicSigningKey::new(pk.to_vec()).hash().unwrap();
        let signer = SigningPrivateKeyAndPublicHash::new(owner.clone(), SecretSigningKey::new(sk.to_vec()));
        let tid = store.start_transaction(&owner).await.unwrap();

        // A value block that a champ mapping will point at.
        let value_bytes = CborObject::ByteString(b"the-cryptree-node".to_vec()).serialize();
        let vcid = store.put(&owner, &owner, vec![vec![]], vec![value_bytes], &tid).await.unwrap()[0].clone();

        // A champ mapping key -> MerkleLink(value).
        let empty = put_block_signed(store.as_ref(), &owner, &signer, Champ::empty().serialize(), &tid).await.unwrap();
        let mut cw = ChampWrapper::create(owner.clone(), empty, None, store.clone(), identity_key_hasher()).await.unwrap();
        let key = vec![9u8; 32];
        cw.put(&signer, &key, &None, Some(CborObject::MerkleLink(vcid.to_bytes())), &tid).await.unwrap();
        let root = cw.root_hash().clone();

        // The server champ lookup returns the path node(s) + the value block.
        let cap = ChunkMirrorCap::new(key.clone(), None);
        let blocks = store.get_champ_lookup(&owner, &root, std::slice::from_ref(&cap), None).await.unwrap();
        assert!(blocks.len() >= 2, "expected champ node + value, got {}", blocks.len());

        // Re-run the lookup locally against ONLY the returned blocks: it resolves.
        let local = Arc::new(RamStorage::new());
        local.load_verified(blocks.clone()).unwrap();
        let cw2 = ChampWrapper::create(owner.clone(), root.clone(), None, local.clone(), identity_key_hasher()).await.unwrap();
        assert_eq!(cw2.get(&key).await.unwrap(), Some(CborObject::MerkleLink(vcid.to_bytes())));
        assert!(local.get_raw(&owner, &vcid, None).await.unwrap().is_some(), "value block present + verified");

        // Tamper with a returned block: its recomputed CID no longer matches the
        // champ link, so the local lookup can't reproduce the correct value.
        let mut bad = blocks;
        bad[0][0] ^= 0xff;
        let local_bad = Arc::new(RamStorage::new());
        local_bad.load_verified(bad).unwrap();
        // Fails closed: the corrupted root hashes to a different CID, so it isn't
        // present under `root` — either opening the tree or the lookup fails.
        let tampered = match ChampWrapper::create(owner.clone(), root.clone(), None, local_bad, identity_key_hasher()).await {
            Ok(cw) => cw.get(&key).await.ok().flatten(),
            Err(_) => None,
        };
        assert_ne!(tampered, Some(CborObject::MerkleLink(vcid.to_bytes())), "tampered lookup must not verify");
    }
}
