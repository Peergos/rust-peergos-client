//! Client-side caches for the mutable-pointer and content-addressed-storage
//! layers, to cut the redundant round-trips a single high-level operation
//! (directory listing, path walk, ...) makes when it re-resolves the same writer
//! pointer + `WriterData` block many times.
//!
//!   - [`CachedMutablePointers`]: caches pointer lookups for a short TTL (default
//!     7 s) and drops a writer's entry whenever we write to it, so a read never
//!     serves a value we've since changed.
//!   - [`CachedStorage`]: a small in-RAM cache of **cbor** blocks. Blocks are
//!     content-addressed (immutable), so this needs no invalidation; raw blocks
//!     (file fragments) are not cached.

use crate::auth::BatWithId;
use crate::error::Result;
use crate::keys::PublicKeyHash;
use crate::mutable::{MutablePointers, SignedPointerUpdate};
use crate::storage::{ChunkMirrorCap, ContentAddressedStorage, TransactionId};
use async_trait::async_trait;
use peergos_cbor::CborObject;
use peergos_multiformats::{Cid, Multihash};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A [`MutablePointers`] that caches raw pointer lookups for a short TTL and
/// invalidates a writer's entry on any write to it.
pub struct CachedMutablePointers {
    inner: Arc<dyn MutablePointers>,
    ttl: Duration,
    cache: Mutex<HashMap<(PublicKeyHash, PublicKeyHash), (Instant, Option<Vec<u8>>)>>,
}

impl CachedMutablePointers {
    /// Cache pointer lookups for at most 7 seconds.
    pub fn new(inner: Arc<dyn MutablePointers>) -> CachedMutablePointers {
        CachedMutablePointers::with_ttl(inner, Duration::from_secs(7))
    }

    pub fn with_ttl(inner: Arc<dyn MutablePointers>, ttl: Duration) -> CachedMutablePointers {
        CachedMutablePointers { inner, ttl, cache: Mutex::new(HashMap::new()) }
    }

    fn invalidate(&self, owner: &PublicKeyHash, writer: &PublicKeyHash) {
        self.cache.lock().unwrap().remove(&(owner.clone(), writer.clone()));
    }
}

#[async_trait]
impl MutablePointers for CachedMutablePointers {
    async fn set_pointer(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        writer_signed_payload: Vec<u8>,
    ) -> Result<bool> {
        // Invalidate before and after the write so a concurrent read can't
        // repopulate a stale value around it.
        self.invalidate(owner, writer);
        let r = self.inner.set_pointer(owner, writer, writer_signed_payload).await;
        self.invalidate(owner, writer);
        r
    }

    async fn set_pointers(&self, owner: &PublicKeyHash, updates: Vec<SignedPointerUpdate>) -> Result<bool> {
        // A multi-writer commit; simplest correct thing is to drop the whole cache.
        self.cache.lock().unwrap().clear();
        let r = self.inner.set_pointers(owner, updates).await;
        self.cache.lock().unwrap().clear();
        r
    }

    async fn get_pointer(&self, owner: &PublicKeyHash, writer: &PublicKeyHash) -> Result<Option<Vec<u8>>> {
        let key = (owner.clone(), writer.clone());
        if let Some((at, val)) = self.cache.lock().unwrap().get(&key) {
            if at.elapsed() < self.ttl {
                return Ok(val.clone());
            }
        }
        let val = self.inner.get_pointer(owner, writer).await?;
        self.cache.lock().unwrap().insert(key, (Instant::now(), val.clone()));
        Ok(val)
    }
    // get_pointer_target / set_pointer_update use the trait defaults, which call
    // our cached get_pointer / invalidating set_pointer.
}

/// A tiny LRU of cbor blocks keyed by their hash (immutable → no invalidation).
struct BlockLru {
    map: HashMap<Cid, CborObject>,
    order: VecDeque<Cid>,
    cap: usize,
}

impl BlockLru {
    fn new(cap: usize) -> BlockLru {
        BlockLru { map: HashMap::new(), order: VecDeque::new(), cap: cap.max(1) }
    }
    fn get(&mut self, hash: &Cid) -> Option<CborObject> {
        self.map.get(hash).cloned()
    }
    fn put(&mut self, hash: Cid, value: CborObject) {
        if self.map.insert(hash.clone(), value).is_none() {
            self.order.push_back(hash);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

const DEFAULT_BLOCK_CACHE: usize = 4096;

/// A [`ContentAddressedStorage`] with a small in-RAM cache of cbor blocks (the
/// `get` path). Raw blocks and every other operation delegate to `inner`.
pub struct CachedStorage {
    inner: Arc<dyn ContentAddressedStorage>,
    blocks: Mutex<BlockLru>,
}

impl CachedStorage {
    pub fn new(inner: Arc<dyn ContentAddressedStorage>) -> CachedStorage {
        CachedStorage::with_capacity(inner, DEFAULT_BLOCK_CACHE)
    }

    pub fn with_capacity(inner: Arc<dyn ContentAddressedStorage>, cap: usize) -> CachedStorage {
        CachedStorage { inner, blocks: Mutex::new(BlockLru::new(cap)) }
    }
}

#[async_trait]
impl ContentAddressedStorage for CachedStorage {
    async fn id(&self) -> Result<Cid> {
        self.inner.id().await
    }
    async fn ids(&self) -> Result<Vec<Cid>> {
        self.inner.ids().await
    }
    async fn start_transaction(&self, owner: &PublicKeyHash) -> Result<TransactionId> {
        self.inner.start_transaction(owner).await
    }
    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> Result<bool> {
        self.inner.close_transaction(owner, tid).await
    }

    async fn get(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<CborObject>> {
        // Inline (identity) blocks carry their own content — no caching needed.
        if hash.multihash.is_identity() {
            return self.inner.get(owner, hash, bat).await;
        }
        if let Some(cached) = self.blocks.lock().unwrap().get(hash) {
            return Ok(Some(cached));
        }
        let res = self.inner.get(owner, hash, bat).await?;
        if let Some(block) = &res {
            self.blocks.lock().unwrap().put(hash.clone(), block.clone());
        }
        Ok(res)
    }

    async fn get_raw(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> Result<Option<Vec<u8>>> {
        self.inner.get_raw(owner, hash, bat).await
    }

    async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.inner.put(owner, writer, signed_hashes, blocks, tid).await
    }

    async fn put_raw(
        &self,
        owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.inner.put_raw(owner, writer, signed_hashes, blocks, tid).await
    }

    async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
        self.inner.get_size(owner, block).await
    }

    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> Result<CborObject> {
        self.inner.get_secret_link(owner, label).await
    }

    async fn link_host(&self, owner: &PublicKeyHash) -> Result<String> {
        self.inner.link_host(owner).await
    }

    async fn get_champ_lookup(
        &self,
        owner: &PublicKeyHash,
        root: &Cid,
        caps: &[ChunkMirrorCap],
        committed_root: Option<&Cid>,
    ) -> Result<Vec<Vec<u8>>> {
        self.inner.get_champ_lookup(owner, root, caps, committed_root).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A `MutablePointers` that counts `get_pointer` calls and serves a fixed value.
    struct Counting {
        gets: AtomicUsize,
    }

    #[async_trait]
    impl MutablePointers for Counting {
        async fn set_pointer(&self, _o: &PublicKeyHash, _w: &PublicKeyHash, _p: Vec<u8>) -> Result<bool> {
            Ok(true)
        }
        async fn set_pointers(&self, _o: &PublicKeyHash, _u: Vec<SignedPointerUpdate>) -> Result<bool> {
            Ok(true)
        }
        async fn get_pointer(&self, _o: &PublicKeyHash, _w: &PublicKeyHash) -> Result<Option<Vec<u8>>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            Ok(Some(vec![1, 2, 3]))
        }
    }

    fn key(byte: u8) -> PublicKeyHash {
        PublicKeyHash::identity(vec![byte; 4]).unwrap()
    }

    #[tokio::test]
    async fn pointer_cache_hits_then_invalidates_on_write() {
        let inner = Arc::new(Counting { gets: AtomicUsize::new(0) });
        let counter = inner.clone();
        let cache = CachedMutablePointers::with_ttl(inner, Duration::from_secs(60));
        let (o, w) = (key(1), key(2));

        // First read hits the network; the second is served from cache.
        cache.get_pointer(&o, &w).await.unwrap();
        cache.get_pointer(&o, &w).await.unwrap();
        assert_eq!(counter.gets.load(Ordering::SeqCst), 1, "second lookup should be cached");

        // A write to that writer invalidates the entry, forcing a re-fetch.
        cache.set_pointer(&o, &w, vec![9]).await.unwrap();
        cache.get_pointer(&o, &w).await.unwrap();
        assert_eq!(counter.gets.load(Ordering::SeqCst), 2, "read after write must not be stale");

        // A different writer is a separate cache entry.
        cache.get_pointer(&o, &key(3)).await.unwrap();
        assert_eq!(counter.gets.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn pointer_cache_expires_after_ttl() {
        let inner = Arc::new(Counting { gets: AtomicUsize::new(0) });
        let counter = inner.clone();
        let cache = CachedMutablePointers::with_ttl(inner, Duration::from_millis(20));
        let (o, w) = (key(1), key(2));
        cache.get_pointer(&o, &w).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        cache.get_pointer(&o, &w).await.unwrap();
        assert_eq!(counter.gets.load(Ordering::SeqCst), 2, "entry should expire after the TTL");
    }
}
