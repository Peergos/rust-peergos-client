//! Buffered network access, ported in spirit from Java's `BufferedNetworkAccess` /
//! `BufferedStorage` / `BufferedPointers`.
//!
//! [`BufferedStorage`] and [`BufferedPointers`] are decorators over a
//! `ContentAddressedStorage` / `MutablePointers`: block writes and pointer updates
//! are buffered in memory (and served back from the buffer so in-progress work is
//! visible), then flushed in bulk by [`BufferedNetwork::commit`]. Before flushing,
//! the block buffer is garbage-collected down to the blocks reachable from the
//! committed roots (dropping superfluous intermediate champ nodes), blocks are
//! written in parallel per writer, and pointer updates are committed with a 3-way
//! champ-merge fallback on a CAS conflict (see [`crate::champ_merge`]).
//!
//! Unlike Java this is not built on `NetworkAccess`/`Snapshot`/`Committer`; it is a
//! transparent decorator that slots into the existing `store` / `mutable` params,
//! so a caller buffers a batch of operations and calls `commit()` once.

use crate::auth::BatWithId;
use crate::champ_merge;
use crate::error::{Error, Result};
use crate::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use crate::mutable::{MutablePointers, PointerUpdate, SignedPointerUpdate};
use crate::storage::{build_cid, ContentAddressedStorage, TransactionId};
use async_trait::async_trait;
use peergos_cbor::CborObject;
use peergos_multiformats::{Cid, Multihash};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Blocks below this size flush in the "small raw" group (`DirectS3BlockStore.MAX_SMALL_BLOCK_SIZE`).
const MAX_SMALL_BLOCK_SIZE: usize = 100 * 1024;
/// Max signed raw blocks per batch (`ContentAddressedStorage.MAX_BLOCK_AUTHS`).
const MAX_BLOCK_AUTHS: usize = 50;
/// Max total bytes of a single cbor batch.
const MAX_CBOR_BATCH_SIZE: usize = 1024 * 1024;
/// Max blocks in a single cbor batch.
const MAX_CBOR_BLOCKS_PER_BATCH: usize = 1000;
/// Max batch uploads in flight at once (`BufferedNetworkAccess`).
const MAX_CONCURRENT_BATCH_UPLOADS: usize = 4;

/// A buffered, not-yet-written block.
#[derive(Clone)]
struct BufferedBlock {
    data: Vec<u8>,
    signature: Vec<u8>,
    writer: PublicKeyHash,
    is_raw: bool,
}

/// A small FIFO block read-cache (content-addressed, so eviction only affects hit
/// rate). Stands in for a block-level cryptree cache on the read path.
struct BlockCache {
    map: HashMap<Cid, Vec<u8>>,
    order: VecDeque<Cid>,
    cap: usize,
}

impl BlockCache {
    fn new(cap: usize) -> BlockCache {
        BlockCache { map: HashMap::new(), order: VecDeque::new(), cap }
    }
    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.map.get(cid).cloned()
    }
    fn put(&mut self, cid: Cid, data: Vec<u8>) {
        if self.cap == 0 || self.map.contains_key(&cid) {
            return;
        }
        while self.map.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.order.push_back(cid.clone());
        self.map.insert(cid, data);
    }
}

/// A `ContentAddressedStorage` that buffers writes until [`BufferedStorage::commit_blocks`].
pub struct BufferedStorage {
    target: Arc<dyn ContentAddressedStorage>,
    buffer: Mutex<HashMap<Cid, BufferedBlock>>,
    cache: Mutex<BlockCache>,
}

impl BufferedStorage {
    pub fn new(target: Arc<dyn ContentAddressedStorage>, read_cache_size: usize) -> BufferedStorage {
        BufferedStorage { target, buffer: Mutex::new(HashMap::new()), cache: Mutex::new(BlockCache::new(read_cache_size)) }
    }

    pub fn target(&self) -> Arc<dyn ContentAddressedStorage> {
        self.target.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.lock().unwrap().is_empty()
    }

    pub fn has_buffered_block(&self, cid: &Cid) -> bool {
        self.buffer.lock().unwrap().contains_key(cid)
    }

    /// Total buffered bytes (`BufferedStorage.totalSize`).
    pub fn total_size(&self) -> usize {
        self.buffer.lock().unwrap().values().map(|b| b.data.len()).sum()
    }

    pub fn clear(&self) {
        self.buffer.lock().unwrap().clear();
    }

    fn buffer_put(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, signed: Vec<Vec<u8>>, blocks: Vec<Vec<u8>>, is_raw: bool) -> Result<Vec<Cid>> {
        let _ = owner;
        if signed.len() != blocks.len() {
            return Err(Error::Protocol("blocks/signatures length mismatch".into()));
        }
        let mut buf = self.buffer.lock().unwrap();
        let mut cids = Vec::with_capacity(blocks.len());
        for (block, signature) in blocks.into_iter().zip(signed.into_iter()) {
            let cid = build_cid(peergos_crypto::hash::sha256(&block), is_raw)?;
            buf.insert(cid.clone(), BufferedBlock { data: block, signature, writer: writer.clone(), is_raw });
            cids.push(cid);
        }
        Ok(cids)
    }

    /// The blocks reachable from `roots` that are still buffered (`BufferedStorage.gc`).
    fn reachable(&self, roots: &[Cid]) -> HashSet<Cid> {
        let buf = self.buffer.lock().unwrap();
        let mut keep = HashSet::new();
        let mut stack: Vec<Cid> = roots.to_vec();
        while let Some(cid) = stack.pop() {
            if keep.contains(&cid) {
                continue;
            }
            let block = match buf.get(&cid) {
                Some(b) => b,
                None => continue, // already on the server; a boundary of the sub-tree
            };
            keep.insert(cid.clone());
            if !block.is_raw {
                if let Ok(cbor) = CborObject::from_bytes(&block.data) {
                    for link in cbor.links() {
                        if let Ok(c) = Cid::cast(&link) {
                            stack.push(c);
                        }
                    }
                }
            }
        }
        keep
    }

    /// GC to the blocks reachable from `roots`, then bulk-write them (in parallel
    /// per writer / codec) and clear the buffer (`gc` + `commit`).
    pub async fn commit_blocks(&self, owner: &PublicKeyHash, roots: &[Cid], tid: &TransactionId) -> Result<()> {
        let keep = self.reachable(roots);
        // Split the surviving blocks per writer into Java's three flush groups
        // (`BufferedStorage.commit`): cbor, small raw (<100KiB) and (large) raw.
        let mut cbor: HashMap<PublicKeyHash, Vec<(Vec<u8>, Vec<u8>)>> = HashMap::new();
        let mut small_raw: HashMap<PublicKeyHash, Vec<(Vec<u8>, Vec<u8>)>> = HashMap::new();
        let mut large_raw: HashMap<PublicKeyHash, Vec<(Vec<u8>, Vec<u8>)>> = HashMap::new();
        {
            let buf = self.buffer.lock().unwrap();
            for (cid, block) in buf.iter() {
                if !keep.contains(cid) {
                    continue;
                }
                let group = if !block.is_raw {
                    &mut cbor
                } else if block.data.len() < MAX_SMALL_BLOCK_SIZE {
                    &mut small_raw
                } else {
                    &mut large_raw
                };
                group.entry(block.writer.clone()).or_default().push((block.signature.clone(), block.data.clone()));
            }
        }

        // Turn each group into upload batches. Cbor batches are size-limited
        // (<=1MiB and <=1000 blocks); raw batches are capped at MAX_BLOCK_AUTHS.
        let mut batches: Vec<(PublicKeyHash, bool, Vec<Vec<u8>>, Vec<Vec<u8>>)> = Vec::new();
        for (writer, items) in cbor {
            let (mut sigs, mut blocks, mut size) = (Vec::new(), Vec::new(), 0usize);
            for (sig, block) in items {
                if !blocks.is_empty()
                    && (size + block.len() > MAX_CBOR_BATCH_SIZE || blocks.len() >= MAX_CBOR_BLOCKS_PER_BATCH)
                {
                    batches.push((writer.clone(), false, std::mem::take(&mut sigs), std::mem::take(&mut blocks)));
                    size = 0;
                }
                size += block.len();
                sigs.push(sig);
                blocks.push(block);
            }
            if !blocks.is_empty() {
                batches.push((writer, false, sigs, blocks));
            }
        }
        for group in [small_raw, large_raw] {
            for (writer, items) in group {
                let (mut sigs, mut blocks) = (Vec::new(), Vec::new());
                for (sig, block) in items {
                    sigs.push(sig);
                    blocks.push(block);
                    if blocks.len() >= MAX_BLOCK_AUTHS {
                        batches.push((writer.clone(), true, std::mem::take(&mut sigs), std::mem::take(&mut blocks)));
                    }
                }
                if !blocks.is_empty() {
                    batches.push((writer, true, sigs, blocks));
                }
            }
        }

        // Upload the batches with at most MAX_CONCURRENT_BATCH_UPLOADS in flight.
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BATCH_UPLOADS));
        let mut handles = Vec::new();
        for (writer, is_raw, sigs, blocks) in batches {
            let (target, owner, tid, sem) = (self.target.clone(), owner.clone(), tid.clone(), sem.clone());
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                if is_raw {
                    target.put_raw(&owner, &writer, sigs, blocks, &tid).await
                } else {
                    target.put(&owner, &writer, sigs, blocks, &tid).await
                }
            }));
        }
        for h in handles {
            h.await.map_err(|e| Error::Protocol(format!("block flush task panicked: {e}")))??;
        }
        self.clear();
        Ok(())
    }
}

#[async_trait]
impl ContentAddressedStorage for BufferedStorage {
    async fn id(&self) -> Result<Cid> {
        self.target.id().await
    }
    async fn ids(&self) -> Result<Vec<Cid>> {
        self.target.ids().await
    }
    async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId> {
        self.target.start_transaction(owner).await
    }
    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool> {
        self.target.close_transaction(owner, tid).await
    }
    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject> {
        self.target.get_secret_link(owner, label).await
    }
    async fn link_host(&self, owner: &PublicKeyHash) -> Result<String> {
        self.target.link_host(owner).await
    }

    async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
        if block.is_identity() {
            return Ok(Some(block.get_hash().len() as u64));
        }
        // A buffered block's size is known locally.
        for (cid, b) in self.buffer.lock().unwrap().iter() {
            if &cid.multihash == block {
                return Ok(Some(b.data.len() as u64));
            }
        }
        self.target.get_size(owner, block).await
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
        if let Some(b) = self.buffer.lock().unwrap().get(hash) {
            return Ok(Some(b.data.clone()));
        }
        if let Some(cached) = self.cache.lock().unwrap().get(hash) {
            return Ok(Some(cached));
        }
        let fetched = self.target.get_raw(owner, hash, bat).await?;
        if let Some(bytes) = &fetched {
            self.cache.lock().unwrap().put(hash.clone(), bytes.clone());
        }
        Ok(fetched)
    }

    async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        _tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.buffer_put(owner, writer, signed_hashes, blocks, false)
    }

    async fn put_raw(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        _tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.buffer_put(owner, writer, signed_hashes, blocks, true)
    }
}

// ---------------------------------------------------------------------------
// BufferedPointers
// ---------------------------------------------------------------------------

/// A buffered pointer update for one writer (`BufferedPointers.WriterUpdate`).
#[derive(Clone)]
struct WriterUpdate {
    writer: PublicKeyHash,
    update: PointerUpdate,
    signer: SigningPrivateKeyAndPublicHash,
}

/// A `MutablePointers` that buffers updates until [`BufferedPointers::commit_pointers`].
/// Updates are kept in an **ordered list** (write order matters for commit
/// sequencing); only *consecutive* writes to the same writer are condensed.
///
/// If given an auto-commit context (block buffer + threshold + safety flag), each
/// buffered pointer write flushes the whole buffer once it crosses the threshold —
/// mirroring Java's `BufferedNetworkAccess.buildCommitter` wrapping every commit
/// with `maybeCommit`. This is what bounds memory during a large multi-chunk file
/// upload (which commits per chunk), not just between files.
pub struct BufferedPointers {
    target: Arc<dyn MutablePointers>,
    updates: Mutex<Vec<WriterUpdate>>,
    auto: Option<AutoCommit>,
}

struct AutoCommit {
    blocks: Arc<BufferedStorage>,
    buffer_size: usize,
    safe: Arc<AtomicBool>,
}

impl BufferedPointers {
    pub fn new(target: Arc<dyn MutablePointers>) -> BufferedPointers {
        BufferedPointers { target, updates: Mutex::new(Vec::new()), auto: None }
    }

    /// A buffered-pointers that auto-flushes the shared block buffer once it reaches
    /// `buffer_size` and `safe` is set (used by [`BufferedNetwork`]).
    pub fn with_auto_commit(
        target: Arc<dyn MutablePointers>,
        blocks: Arc<BufferedStorage>,
        buffer_size: usize,
        safe: Arc<AtomicBool>,
    ) -> BufferedPointers {
        BufferedPointers { target, updates: Mutex::new(Vec::new()), auto: Some(AutoCommit { blocks, buffer_size, safe }) }
    }

    /// Flush the buffer (GC to roots, write blocks, commit pointers) if an
    /// auto-commit context is present, it is safe to commit, and the buffer is full.
    /// Called after each buffered pointer write.
    async fn maybe_auto_commit(&self, owner: &PublicKeyHash) -> Result<()> {
        let auto = match &self.auto {
            Some(a) => a,
            None => return Ok(()),
        };
        if !auto.safe.load(Ordering::SeqCst) || auto.blocks.total_size() < auto.buffer_size {
            return Ok(());
        }
        let roots = self.roots();
        if roots.is_empty() {
            return Ok(());
        }
        let tid = auto.blocks.target().start_transaction(owner).await?;
        auto.blocks.commit_blocks(owner, &roots, &tid).await?;
        self.commit_pointers(owner, &auto.blocks, &tid).await?;
        auto.blocks.target().close_transaction(owner, &tid).await?;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.updates.lock().unwrap().is_empty()
    }

    pub fn clear(&self) {
        self.updates.lock().unwrap().clear();
    }

    /// The new WriterData roots pointed at by the buffered updates, in order (for GC).
    pub fn roots(&self) -> Vec<Cid> {
        self.updates.lock().unwrap().iter().filter_map(|w| w.update.updated.clone()).collect()
    }

    /// Commit all buffered pointer updates in order, resolving any CAS conflict per
    /// writer via a 3-way champ merge. Sequential commit preserves the write order
    /// (needed so a parent pointer commits before a dependent child's).
    pub async fn commit_pointers(
        &self,
        owner: &PublicKeyHash,
        blocks: &BufferedStorage,
        tid: &TransactionId,
    ) -> Result<()> {
        let writes: Vec<WriterUpdate> = self.updates.lock().unwrap().clone();
        for w in &writes {
            self.commit_one_with_merge(owner, w, blocks, tid).await?;
        }
        self.clear();
        Ok(())
    }

    /// Commit one writer's pointer, merging on a CAS conflict
    /// (`commitPointerWithMerge`).
    async fn commit_one_with_merge(
        &self,
        owner: &PublicKeyHash,
        w: &WriterUpdate,
        blocks: &BufferedStorage,
        tid: &TransactionId,
    ) -> Result<()> {
        if self.target.set_pointer_update(owner, &w.signer, &w.update).await.unwrap_or(false) {
            return Ok(());
        }
        // Find where the server actually is now.
        let remote = self.target.get_pointer_target(owner, &w.writer, blocks.target().as_ref()).await?;
        if remote.updated == w.update.updated {
            return Ok(()); // already there
        }
        let (base, ours, theirs) = match (&w.update.original, &w.update.updated, &remote.updated) {
            (Some(b), Some(o), Some(t)) => (b.clone(), o.clone(), t.clone()),
            _ => return Err(Error::Protocol("pointer CAS conflict with no mergeable roots".into())),
        };
        // 3-way merge the writer's champ tree and re-point at the merge. By now the
        // buffered blocks (including `ours`) have been flushed to the target.
        let merged_wd = champ_merge::merge_writer_data(owner, &w.signer, &base, &ours, &theirs, blocks.target(), tid).await?;
        let merged_root = crate::storage::put_block_signed(blocks.target().as_ref(), owner, &w.signer, merged_wd, tid).await?;
        let seq = remote.sequence.map(|s| s + 1);
        let resolved = PointerUpdate::new(remote.updated.clone(), Some(merged_root), seq);
        if !self.target.set_pointer_update(owner, &w.signer, &resolved).await? {
            return Err(Error::Protocol("pointer commit rejected after merge".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl MutablePointers for BufferedPointers {
    async fn set_pointer(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, signed: Vec<u8>) -> Result<bool> {
        // Unbuffered callers fall through to the target.
        self.target.set_pointer(owner, writer, signed).await
    }

    async fn set_pointers(&self, owner: &PublicKeyHash, updates: Vec<SignedPointerUpdate>) -> Result<bool> {
        self.target.set_pointers(owner, updates).await
    }

    async fn get_pointer(&self, owner: &PublicKeyHash, writer: &PublicKeyHash) -> Result<Option<Vec<u8>>> {
        self.target.get_pointer(owner, writer).await
    }

    /// Buffer the update instead of writing it (`BufferedPointers.addWrite`).
    /// Only **consecutive** writes to the same writer are condensed: if the LAST
    /// buffered entry is this writer, keep its `original` + `sequence` (the committed
    /// base and single sequence bump) and just advance the target hash; otherwise
    /// append a new entry — even if this writer already appears earlier — so
    /// interleaved writes to other writers keep their order.
    async fn set_pointer_update(
        &self,
        owner: &PublicKeyHash,
        writer: &SigningPrivateKeyAndPublicHash,
        update: &PointerUpdate,
    ) -> Result<bool> {
        {
            let mut list = self.updates.lock().unwrap();
            match list.last_mut() {
                Some(last) if last.writer == writer.public_key_hash => last.update.updated = update.updated.clone(),
                _ => list.push(WriterUpdate {
                    writer: writer.public_key_hash.clone(),
                    update: update.clone(),
                    signer: writer.clone(),
                }),
            }
        }
        // Auto-flush at the buffer threshold (Java's committer → maybeCommit).
        self.maybe_auto_commit(owner).await?;
        Ok(true)
    }

    /// Reflect the latest buffered update for a writer if present, else the
    /// committed value.
    async fn get_pointer_target(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        ipfs: &dyn ContentAddressedStorage,
    ) -> Result<PointerUpdate> {
        if let Some(w) = self.updates.lock().unwrap().iter().rev().find(|w| &w.writer == writer) {
            return Ok(w.update.clone());
        }
        self.target.get_pointer_target(owner, writer, ipfs).await
    }
}

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

/// Ties a [`BufferedStorage`] and [`BufferedPointers`] together with commit gating,
/// mirroring `BufferedNetworkAccess`. Buffer a batch of filesystem operations
/// against `storage()` / `pointers()`, then `commit()` to flush in bulk.
pub struct BufferedNetwork {
    blocks: Arc<BufferedStorage>,
    pointers: Arc<BufferedPointers>,
    buffer_size: usize,
    safe_to_commit: Arc<AtomicBool>,
}

/// The buffered-block threshold before an auto-flush, matching Java's main
/// buffered client (`NetworkAccess.buildBuffered`: 20 MiB).
pub const DEFAULT_BUFFER_SIZE: usize = 20 * 1024 * 1024;

/// Default number of blocks kept in the read cache.
pub const DEFAULT_READ_CACHE_SIZE: usize = 1000;

impl BufferedNetwork {
    /// A buffered network with Java's default 20 MiB flush threshold.
    pub fn with_defaults(
        target_storage: Arc<dyn ContentAddressedStorage>,
        target_pointers: Arc<dyn MutablePointers>,
    ) -> BufferedNetwork {
        BufferedNetwork::new(target_storage, target_pointers, DEFAULT_BUFFER_SIZE, DEFAULT_READ_CACHE_SIZE)
    }

    pub fn new(
        target_storage: Arc<dyn ContentAddressedStorage>,
        target_pointers: Arc<dyn MutablePointers>,
        buffer_size: usize,
        read_cache_size: usize,
    ) -> BufferedNetwork {
        let blocks = Arc::new(BufferedStorage::new(target_storage, read_cache_size));
        let safe_to_commit = Arc::new(AtomicBool::new(true));
        let pointers = Arc::new(BufferedPointers::with_auto_commit(
            target_pointers,
            blocks.clone(),
            buffer_size,
            safe_to_commit.clone(),
        ));
        BufferedNetwork { blocks, pointers, buffer_size, safe_to_commit }
    }

    /// The buffered block store to pass as `store` to filesystem operations.
    pub fn storage(&self) -> Arc<BufferedStorage> {
        self.blocks.clone()
    }
    /// The buffered pointers to pass as `mutable` to filesystem operations.
    pub fn pointers(&self) -> Arc<BufferedPointers> {
        self.pointers.clone()
    }

    pub fn buffered_size(&self) -> usize {
        self.blocks.total_size()
    }
    pub fn is_full(&self) -> bool {
        self.buffered_size() >= self.buffer_size
    }
    pub fn disable_commits(&self) {
        self.safe_to_commit.store(false, Ordering::SeqCst);
    }
    pub fn enable_commits(&self) {
        self.safe_to_commit.store(true, Ordering::SeqCst);
    }

    /// Commit only when it is both safe and the buffer is full (`maybeCommit`).
    pub async fn maybe_commit(&self, owner: &PublicKeyHash) -> Result<bool> {
        if self.safe_to_commit.load(Ordering::SeqCst) && self.is_full() {
            self.commit(owner).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Flush all buffered blocks and pointer updates (`commit`): GC blocks to the
    /// committed roots, bulk-write them, then commit the pointers.
    pub async fn commit(&self, owner: &PublicKeyHash) -> Result<()> {
        if self.blocks.is_empty() && self.pointers.is_empty() {
            return Ok(());
        }
        let roots = self.pointers.roots();
        let tid = self.blocks.target().start_transaction(owner).await?;
        self.blocks.commit_blocks(owner, &roots, &tid).await?;
        self.pointers.commit_pointers(owner, &self.blocks, &tid).await?;
        self.blocks.target().close_transaction(owner, &tid).await?;
        Ok(())
    }

    pub fn force_clear(&self) {
        self.blocks.clear();
        self.pointers.clear();
    }
}
