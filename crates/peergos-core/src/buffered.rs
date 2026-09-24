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
use crate::bulk;
use crate::champ_merge;
use crate::error::{Error, Result};
use crate::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use crate::mutable::{MutablePointers, PointerUpdate, SignedPointerUpdate};
use crate::storage::{build_cid, ContentAddressedStorage, TransactionId};
use async_trait::async_trait;
use peergos_cbor::{CborObject, Cborable};
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
    owner: PublicKeyHash,
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
    /// Owners whose server has answered that it has no `bulk/commit`.
    bulk_unsupported: Mutex<HashSet<PublicKeyHash>>,
}

impl BufferedStorage {
    pub fn new(target: Arc<dyn ContentAddressedStorage>, read_cache_size: usize) -> BufferedStorage {
        BufferedStorage {
            target,
            buffer: Mutex::new(HashMap::new()),
            cache: Mutex::new(BlockCache::new(read_cache_size)),
            bulk_unsupported: Mutex::new(HashSet::new()),
        }
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

    /// Assign each of `owner`'s buffered blocks to the first of these roots that
    /// reaches it (`partitionByRoot`): a commit is only accepted if every block in it
    /// hangs off the root it signs, so the graph decides, not which writer wrote it.
    fn partition_by_root(&self, owner: &PublicKeyHash, roots: &[Option<Cid>]) -> Vec<Vec<(Cid, BufferedBlock)>> {
        let mut claimed: HashSet<Cid> = HashSet::new();
        let mut parts = Vec::with_capacity(roots.len());
        for root in roots {
            let reachable = match root {
                Some(r) => self.reachable(std::slice::from_ref(r)),
                None => HashSet::new(),
            };
            let buf = self.buffer.lock().unwrap();
            let mut part = Vec::new();
            for cid in reachable {
                if let Some(b) = buf.get(&cid) {
                    if &b.owner == owner && claimed.insert(cid.clone()) {
                        part.push((cid, b.clone()));
                    }
                }
            }
            parts.push(part);
        }
        parts
    }

    fn buffer_put(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, signed: Vec<Vec<u8>>, blocks: Vec<Vec<u8>>, is_raw: bool) -> Result<Vec<Cid>> {
        if signed.len() != blocks.len() {
            return Err(Error::Protocol("blocks/signatures length mismatch".into()));
        }
        let mut buf = self.buffer.lock().unwrap();
        let mut cids = Vec::with_capacity(blocks.len());
        for (block, signature) in blocks.into_iter().zip(signed.into_iter()) {
            let cid = build_cid(peergos_crypto::hash::sha256(&block), is_raw)?;
            buf.insert(cid.clone(), BufferedBlock { data: block, signature, owner: owner.clone(), writer: writer.clone(), is_raw });
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
    /// Write `owner`'s buffered blocks reachable from `roots` to `owner`'s server,
    /// leaving other owners' blocks buffered.
    pub async fn commit_blocks(&self, owner: &PublicKeyHash, roots: &[Cid], tid: &TransactionId) -> Result<()> {
        let keep: HashSet<Cid> = {
            let reachable = self.reachable(roots);
            let buf = self.buffer.lock().unwrap();
            reachable.into_iter().filter(|c| buf.get(c).is_some_and(|b| &b.owner == owner)).collect()
        };
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
        let mut buf = self.buffer.lock().unwrap();
        buf.retain(|c, _| !keep.contains(c));
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
    owner: PublicKeyHash,
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
        if self.roots().is_empty() {
            return Ok(());
        }
        flush(&auto.blocks, self, owner).await
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

    /// The roots of `owner`'s buffered updates.
    pub fn roots_for(&self, owner: &PublicKeyHash) -> Vec<Cid> {
        self.updates.lock().unwrap().iter().filter(|w| &w.owner == owner).filter_map(|w| w.update.updated.clone()).collect()
    }

    /// The owners with buffered updates, in the order first written. One operation
    /// can write to several owners' spaces, e.g. uploading a large file into a folder
    /// shared with us also writes the upload transaction to our own space.
    pub fn owners(&self) -> Vec<PublicKeyHash> {
        let mut res: Vec<PublicKeyHash> = Vec::new();
        for w in self.updates.lock().unwrap().iter() {
            if !res.contains(&w.owner) {
                res.push(w.owner.clone());
            }
        }
        res
    }

    fn writes_for(&self, owner: &PublicKeyHash) -> Vec<WriterUpdate> {
        self.updates.lock().unwrap().iter().filter(|w| &w.owner == owner).cloned().collect()
    }

    fn drop_owner(&self, owner: &PublicKeyHash) {
        self.updates.lock().unwrap().retain(|w| &w.owner != owner);
    }

    /// Commit `owner`'s buffered pointer updates in order, resolving any CAS conflict
    /// per writer via a 3-way champ merge. Sequential commit preserves the write
    /// order (needed so a parent pointer commits before a dependent child's).
    pub async fn commit_pointers(
        &self,
        owner: &PublicKeyHash,
        blocks: &BufferedStorage,
        tid: &TransactionId,
    ) -> Result<()> {
        let writes: Vec<WriterUpdate> =
            self.updates.lock().unwrap().iter().filter(|w| &w.owner == owner).cloned().collect();
        for w in &writes {
            self.commit_one_with_merge(owner, w, blocks, tid).await?;
        }
        self.updates.lock().unwrap().retain(|w| &w.owner != owner);
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
                Some(last) if last.writer == writer.public_key_hash && &last.owner == owner => {
                    last.update.updated = update.updated.clone()
                }
                _ => list.push(WriterUpdate {
                    owner: owner.clone(),
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

/// Commit every owner's buffered writes, one owner and transaction at a time, then
/// drop whatever the commits did not reach.
async fn flush(blocks: &BufferedStorage, pointers: &BufferedPointers, default_owner: &PublicKeyHash) -> Result<()> {
    let mut owners = pointers.owners();
    if owners.is_empty() {
        owners.push(default_owner.clone());
    }
    for owner in owners {
        if !blocks.bulk_unsupported.lock().unwrap().contains(&owner) {
            match bulk_commit_owner(blocks, pointers, &owner).await {
                Ok(()) => {
                    pointers.drop_owner(&owner);
                    continue;
                }
                // a server that predates the call: use the old endpoints for this owner from now on
                Err(e) if bulk::is_unimplemented(&e) => {
                    blocks.bulk_unsupported.lock().unwrap().insert(owner.clone());
                }
                // nothing was applied; the old path resolves the conflict with a merge
                Err(e) if bulk::is_pointer_cas_failure(&e) => {}
                Err(e) => return Err(e),
            }
        }
        let roots = pointers.roots_for(&owner);
        let tid = blocks.target().start_transaction(&owner).await?;
        blocks.commit_blocks(&owner, &roots, &tid).await?;
        pointers.commit_pointers(&owner, blocks, &tid).await?;
        blocks.target().close_transaction(&owner, &tid).await?;
    }
    blocks.clear();
    pointers.clear();
    Ok(())
}

/// Everything a commit carries beyond one server call: blocks-only calls are
/// signed as block lists bound to the sequence each writer's pointer is heading for.
struct Signers<'a> {
    writes: &'a [WriterUpdate],
}

impl Signers<'_> {
    fn signer(&self, writer: &PublicKeyHash) -> &SigningPrivateKeyAndPublicHash {
        &self.writes.iter().find(|w| &w.writer == writer).expect("a signer for every writer in the commit").signer
    }

    /// The sequence of this writer's first update in the commit, which is what the
    /// server checks a block list against before any of the commit's pointers land.
    fn next_sequence(&self, writer: &PublicKeyHash) -> Option<i64> {
        self.writes.iter().find(|w| &w.writer == writer).and_then(|w| w.update.sequence)
    }
}

/// Send `owner`'s buffered writes as one `bulk/commit` (`ServerBulkCommitter`):
/// blocks too large to travel inline are written first under a transaction, and a
/// commit too big for one call is split.
async fn bulk_commit_owner(blocks: &BufferedStorage, pointers: &BufferedPointers, owner: &PublicKeyHash) -> Result<()> {
    let writes = pointers.writes_for(owner);
    if writes.is_empty() {
        return Ok(());
    }
    let roots: Vec<Option<Cid>> = writes.iter().map(|w| w.update.updated.clone()).collect();
    let parts = blocks.partition_by_root(owner, &roots);
    let target = blocks.target();
    let needs_tid = parts.iter().flatten().any(|(_, b)| b.is_raw && b.data.len() >= MAX_SMALL_BLOCK_SIZE);
    let tid = if needs_tid { Some(target.start_transaction(owner).await?) } else { None };

    let result = async {
        let mut writers = Vec::with_capacity(writes.len());
        for (w, part) in writes.iter().zip(parts) {
            let (mut cbor, mut raw, mut large) = (Vec::new(), Vec::new(), Vec::new());
            for (_, b) in part {
                if !b.is_raw {
                    cbor.push(b.data);
                } else if b.data.len() < MAX_SMALL_BLOCK_SIZE {
                    raw.push(b.data);
                } else {
                    large.push(b.data);
                }
            }
            let pre_written = match &tid {
                Some(t) => pre_write(&target, owner, &w.signer, large, t).await?,
                None => Vec::new(),
            };
            let signed = w.signer.secret.sign_message(&w.update.serialize())?;
            writers.push(bulk::WriterCommit {
                writer: w.writer.clone(),
                cbor_blocks: cbor,
                raw_blocks: raw,
                pre_written,
                pointer: Some(SignedPointerUpdate::new(w.writer.clone(), signed)),
                block_list_signature: None,
            });
        }
        let commit = bulk::BulkCommit { tid: tid.clone(), writers };
        send_bulk_commit(target.as_ref(), owner, commit, &Signers { writes: &writes }, &roots).await
    }
    .await;
    if result.is_err() {
        if let Some(t) = &tid {
            let _ = target.close_transaction(owner, t).await;
        }
    }
    result
}

/// Write blocks too large to travel inline, in batches with bounded concurrency.
async fn pre_write(
    target: &Arc<dyn ContentAddressedStorage>,
    owner: &PublicKeyHash,
    signer: &SigningPrivateKeyAndPublicHash,
    large: Vec<Vec<u8>>,
    tid: &TransactionId,
) -> Result<Vec<Cid>> {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BATCH_UPLOADS));
    let mut handles = Vec::new();
    for batch in large.chunks(MAX_BLOCK_AUTHS) {
        let (target, owner, signer, tid, sem, batch) =
            (target.clone(), owner.clone(), signer.clone(), tid.clone(), sem.clone(), batch.to_vec());
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            target.put_raw_batch(&owner, &signer, batch, &tid).await
        }));
    }
    let mut cids = Vec::new();
    for h in handles {
        cids.extend(h.await.map_err(|e| Error::Protocol(format!("block write task panicked: {e}")))??);
    }
    Ok(cids)
}

/// The inline bytes a commit may carry, leaving room for its framing.
const MAX_BULK_INLINE: usize = bulk::MAX_BULK_COMMIT_SIZE - 64 * 1024;

async fn send_bulk_commit(
    target: &dyn ContentAddressedStorage,
    owner: &PublicKeyHash,
    commit: bulk::BulkCommit,
    signers: &Signers<'_>,
    roots: &[Option<Cid>],
) -> Result<()> {
    if commit.inline_size() <= MAX_BULK_INLINE
        && commit.block_count() + commit.pre_written_count() <= bulk::MAX_BULK_COMMIT_BLOCKS
    {
        target.bulk_commit(owner, &commit).await?;
        return Ok(());
    }
    // A commit too big for one call goes as several, of which only the last carries
    // the pointer updates; the earlier ones are held by a transaction until it lands.
    let started = commit.tid.is_none();
    let tid = match &commit.tid {
        Some(t) => t.clone(),
        None => target.start_transaction(owner).await?,
    };
    let (blocks_only, last) = split(commit, signers, roots, &tid)?;
    for call in &blocks_only {
        target.bulk_commit(owner, call).await?;
    }
    target.bulk_commit(owner, &last).await?;
    if started {
        target.close_transaction(owner, &tid).await?;
    }
    Ok(())
}

/// One inline block of a writer's commit, with its hash.
struct InlineBlock {
    cid: Cid,
    data: Vec<u8>,
    is_raw: bool,
}

/// Breadth first from the root, so a block never comes before the block linking to
/// it: any prefix of this order is then reachable from the root on its own.
fn from_root_first(blocks: Vec<InlineBlock>, root: &Option<Cid>) -> Vec<InlineBlock> {
    let mut by_hash: HashMap<Cid, InlineBlock> = blocks.into_iter().map(|b| (b.cid.clone(), b)).collect();
    let mut ordered = Vec::with_capacity(by_hash.len());
    let mut queue: VecDeque<Cid> = root.iter().cloned().collect();
    while let Some(next) = queue.pop_front() {
        let block = match by_hash.remove(&next) {
            Some(b) => b,
            None => continue,
        };
        if !block.is_raw {
            if let Ok(cbor) = CborObject::from_bytes(&block.data) {
                for link in cbor.links() {
                    if let Ok(c) = Cid::cast(&link) {
                        queue.push_back(c);
                    }
                }
            }
        }
        ordered.push(block);
    }
    // anything the root doesn't reach can only be deferred; the server rejects it either way
    ordered.extend(by_hash.into_values());
    ordered
}

/// Split an oversized commit: the final call takes the top of each writer's tree
/// plus the pointer updates, and the rest go ahead in blocks-only calls.
fn split(
    commit: bulk::BulkCommit,
    signers: &Signers<'_>,
    roots: &[Option<Cid>],
    tid: &TransactionId,
) -> Result<(Vec<bulk::BulkCommit>, bulk::BulkCommit)> {
    let mut budget = MAX_BULK_INLINE;
    // the pre-written hashes ride along on the final call, and count against it too
    let mut count_budget = bulk::MAX_BULK_COMMIT_BLOCKS.saturating_sub(commit.pre_written_count());
    let mut last_writers = Vec::new();
    let mut deferred: Vec<(PublicKeyHash, Vec<InlineBlock>)> = Vec::new();
    for (i, w) in commit.writers.into_iter().enumerate() {
        let mut inline = Vec::with_capacity(w.block_count());
        for (data, is_raw) in w.cbor_blocks.into_iter().map(|b| (b, false)).chain(w.raw_blocks.into_iter().map(|b| (b, true))) {
            inline.push(InlineBlock { cid: build_cid(peergos_crypto::hash::sha256(&data), is_raw)?, data, is_raw });
        }
        let mut ordered = from_root_first(inline, &roots[i]).into_iter();
        let (mut cbor, mut raw) = (Vec::new(), Vec::new());
        let mut rest = Vec::new();
        for b in ordered.by_ref() {
            if b.data.len() <= budget && count_budget > 0 {
                budget -= b.data.len();
                count_budget -= 1;
                if b.is_raw { raw.push(b.data) } else { cbor.push(b.data) }
            } else {
                rest.push(b);
                break;
            }
        }
        rest.extend(ordered);
        last_writers.push(bulk::WriterCommit {
            writer: w.writer.clone(),
            cbor_blocks: cbor,
            raw_blocks: raw,
            pre_written: w.pre_written,
            pointer: w.pointer,
            block_list_signature: None,
        });
        if !rest.is_empty() {
            deferred.push((w.writer, rest));
        }
    }

    let mut calls: Vec<Vec<bulk::WriterCommit>> = Vec::new();
    let (mut used, mut count) = (0usize, 0usize);
    for (writer, blocks) in deferred {
        let signer = signers.signer(&writer);
        let seq = signers.next_sequence(&writer);
        let mut groups: Vec<Vec<InlineBlock>> = Vec::new();
        let mut group_size = 0;
        for b in blocks {
            if groups.is_empty() || group_size + b.data.len() > MAX_BULK_INLINE || groups.last().unwrap().len() >= bulk::MAX_BULK_COMMIT_BLOCKS {
                groups.push(Vec::new());
                group_size = 0;
            }
            group_size += b.data.len();
            groups.last_mut().unwrap().push(b);
        }
        for group in groups {
            let size: usize = group.iter().map(|b| b.data.len()).sum();
            if calls.is_empty() || (used > 0 && (used + size > MAX_BULK_INLINE || count + group.len() > bulk::MAX_BULK_COMMIT_BLOCKS)) {
                calls.push(Vec::new());
                used = 0;
                count = 0;
            }
            used += size;
            count += group.len();
            let (cbor, raw): (Vec<InlineBlock>, Vec<InlineBlock>) = group.into_iter().partition(|b| !b.is_raw);
            let in_order: Vec<Cid> = cbor.iter().chain(raw.iter()).map(|b| b.cid.clone()).collect();
            let sig = signer.secret.sign_message(&bulk::WriterCommit::block_list_payload(&in_order, seq))?;
            calls.last_mut().unwrap().push(bulk::WriterCommit {
                writer: writer.clone(),
                cbor_blocks: cbor.into_iter().map(|b| b.data).collect(),
                raw_blocks: raw.into_iter().map(|b| b.data).collect(),
                pre_written: Vec::new(),
                pointer: None,
                block_list_signature: Some(sig),
            });
        }
    }
    let blocks_only = calls
        .into_iter()
        .filter(|c| !c.is_empty())
        .map(|writers| bulk::BulkCommit { tid: Some(tid.clone()), writers })
        .collect();
    Ok((blocks_only, bulk::BulkCommit { tid: commit.tid, writers: last_writers }))
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
    /// committed roots, bulk-write them, then commit the pointers. Each owner's
    /// writes go to that owner's server; `owner` is used if nothing records one.
    pub async fn commit(&self, owner: &PublicKeyHash) -> Result<()> {
        if self.blocks.is_empty() && self.pointers.is_empty() {
            return Ok(());
        }
        flush(&self.blocks, &self.pointers, owner).await
    }

    pub fn force_clear(&self) {
        self.blocks.clear();
        self.pointers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{PublicSigningKey, SecretSigningKey};
    use crate::ram::RamStorage;

    /// Records the owner every write and pointer update is sent under.
    #[derive(Default)]
    struct Recording {
        ram: RamStorage,
        puts: Mutex<Vec<PublicKeyHash>>,
        pointers: Mutex<Vec<(PublicKeyHash, PublicKeyHash)>>,
    }

    #[async_trait]
    impl ContentAddressedStorage for Recording {
        async fn id(&self) -> Result<Cid> {
            self.ram.id().await
        }
        async fn ids(&self) -> Result<Vec<Cid>> {
            self.ram.ids().await
        }
        async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId> {
            self.ram.start_transaction(owner).await
        }
        async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool> {
            self.ram.close_transaction(owner, tid).await
        }
        async fn get(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<CborObject>> {
            self.ram.get(owner, hash, bat).await
        }
        async fn get_raw(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<Vec<u8>>> {
            self.ram.get_raw(owner, hash, bat).await
        }
        async fn put(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, s: Vec<Vec<u8>>, b: Vec<Vec<u8>>, tid: &TransactionId) -> Result<Vec<Cid>> {
            self.puts.lock().unwrap().push(owner.clone());
            self.ram.put(owner, writer, s, b, tid).await
        }
        async fn put_raw(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, s: Vec<Vec<u8>>, b: Vec<Vec<u8>>, tid: &TransactionId) -> Result<Vec<Cid>> {
            self.puts.lock().unwrap().push(owner.clone());
            self.ram.put_raw(owner, writer, s, b, tid).await
        }
        async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
            self.ram.get_size(owner, block).await
        }
        async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject> {
            self.ram.get_secret_link(owner, label).await
        }
    }

    #[async_trait]
    impl MutablePointers for Recording {
        async fn set_pointer(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, _p: Vec<u8>) -> Result<bool> {
            self.pointers.lock().unwrap().push((owner.clone(), writer.clone()));
            Ok(true)
        }
        async fn set_pointers(&self, _o: &PublicKeyHash, _u: Vec<SignedPointerUpdate>) -> Result<bool> {
            Ok(true)
        }
        async fn get_pointer(&self, _o: &PublicKeyHash, _w: &PublicKeyHash) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    fn signer(seed: u8) -> SigningPrivateKeyAndPublicHash {
        let (pk, sk) = peergos_crypto::sign::keypair_from_seed(&[seed; 32]).unwrap();
        SigningPrivateKeyAndPublicHash::new(PublicSigningKey::new(pk.to_vec()).hash().unwrap(), SecretSigningKey::new(sk.to_vec()))
    }

    /// One batch writing into two owners' spaces sends each owner's blocks and
    /// pointer to that owner.
    #[tokio::test]
    async fn each_owners_writes_go_to_that_owner() {
        let target = Arc::new(Recording::default());
        let net = BufferedNetwork::new(target.clone(), target.clone(), usize::MAX, 0);
        let (alice, bob) = (signer(1), signer(2));
        let tid = TransactionId("t".into());
        for (s, byte) in [(&alice, 1u8), (&bob, 2u8)] {
            let owner = &s.public_key_hash;
            let cid = net.storage().put(owner, owner, vec![vec![0]], vec![CborObject::Long(byte as i64).to_bytes()], &tid).await.unwrap()[0].clone();
            net.pointers().set_pointer_update(owner, s, &PointerUpdate::new(None, Some(cid), Some(1))).await.unwrap();
        }
        net.commit(&alice.public_key_hash).await.unwrap();

        assert_eq!(*target.puts.lock().unwrap(), vec![alice.public_key_hash.clone(), bob.public_key_hash.clone()]);
        assert_eq!(
            *target.pointers.lock().unwrap(),
            vec![
                (alice.public_key_hash.clone(), alice.public_key_hash.clone()),
                (bob.public_key_hash.clone(), bob.public_key_hash.clone())
            ]
        );
        assert!(net.storage().is_empty() && net.pointers().is_empty());
    }
}
