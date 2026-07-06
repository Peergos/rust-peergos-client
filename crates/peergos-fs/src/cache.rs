//! `CryptreeCache` — an LRU of DECRYPTED cryptree nodes keyed by
//! `(champ tree root, map key)`, ported from Java's `CryptreeCache` (a field on
//! `NetworkAccess`, and hence inherited by `BufferedNetworkAccess`).
//!
//! This is distinct from the block-level read cache in `BufferedStorage` (raw
//! encrypted bytes by CID). A hit here skips BOTH the `champ/get` round-trip and
//! the decrypt. The key includes the content-addressed champ root, so entries can
//! never go stale: any change to the tree produces a new root, so a subsequent
//! lookup uses a different key and misses (rather than reading outdated data).

use crate::cryptree::CryptreeNode;
use peergos_multiformats::Cid;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Default number of entries retained (`CryptreeCache` in Java).
pub const DEFAULT_CRYPTREE_CACHE_SIZE: usize = 1000;

type Key = (Cid, Vec<u8>);

struct Inner {
    /// `None` value = a negative cache entry (the key is known-absent).
    map: HashMap<Key, Option<CryptreeNode>>,
    order: VecDeque<Key>,
    cap: usize,
}

impl Inner {
    fn touch(&mut self, key: &Key) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.clone());
    }

    fn insert(&mut self, key: Key, val: Option<CryptreeNode>) {
        self.touch(&key);
        self.map.insert(key, val);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn remove(&mut self, key: &Key) {
        if self.map.remove(key).is_some() {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
    }
}

/// A shared, thread-safe LRU cache of decrypted cryptree nodes. Cheap to clone
/// (an `Arc` handle to the shared store).
#[derive(Clone)]
pub struct CryptreeCache {
    inner: Arc<Mutex<Inner>>,
}

impl Default for CryptreeCache {
    fn default() -> Self {
        CryptreeCache::with_capacity(DEFAULT_CRYPTREE_CACHE_SIZE)
    }
}

impl CryptreeCache {
    pub fn new() -> CryptreeCache {
        CryptreeCache::default()
    }

    pub fn with_capacity(cap: usize) -> CryptreeCache {
        CryptreeCache {
            inner: Arc::new(Mutex::new(Inner {
                map: HashMap::new(),
                order: VecDeque::new(),
                cap: cap.max(1),
            })),
        }
    }

    /// The cached node for `(root, map_key)`. The outer `Option` is cache presence;
    /// the inner `Option<CryptreeNode>` distinguishes a cached node from a cached
    /// "known absent". Registers an LRU access on a hit.
    pub fn get(&self, root: &Cid, map_key: &[u8]) -> Option<Option<CryptreeNode>> {
        let key = (root.clone(), map_key.to_vec());
        let mut inner = self.inner.lock().unwrap();
        if let Some(val) = inner.map.get(&key).cloned() {
            inner.touch(&key);
            Some(val)
        } else {
            None
        }
    }

    pub fn put(&self, root: &Cid, map_key: &[u8], val: Option<CryptreeNode>) {
        let mut inner = self.inner.lock().unwrap();
        inner.insert((root.clone(), map_key.to_vec()), val);
    }

    /// Migrate still-valid entries after a write changed the tree root: everything
    /// cached under `prior_root` is unchanged except the mutated key, so re-key it
    /// to `new_root` (Java's `CryptreeCache.update`). Then store the new value.
    pub fn update(&self, prior_root: Option<&Cid>, new_root: &Cid, map_key: &[u8], val: Option<CryptreeNode>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(prior) = prior_root {
            let migrated: Vec<(Vec<u8>, Option<CryptreeNode>)> = inner
                .map
                .iter()
                .filter(|((r, _), _)| r == prior)
                .map(|((_, k), v)| (k.clone(), v.clone()))
                .collect();
            for (k, v) in migrated {
                inner.insert((new_root.clone(), k), v);
            }
        }
        inner.insert((new_root.clone(), map_key.to_vec()), val);
    }

    /// The value-less form of [`update`](Self::update) used by the mutation commit
    /// path: after a write changed a writer's champ tree root from `prior_root` to
    /// `new_root`, re-key every still-valid entry forward (unchanged sibling nodes
    /// map to the same cryptree CID under the new root), EXCEPT the `changed_keys`
    /// the write touched — those are dropped so their next read refetches (we don't
    /// hold their new decrypted node here, unlike Java's per-chunk `uploadChunk`).
    pub fn migrate(&self, prior_root: &Cid, new_root: &Cid, changed_keys: &[Vec<u8>]) {
        let mut inner = self.inner.lock().unwrap();
        let migrated: Vec<(Vec<u8>, Option<CryptreeNode>)> = inner
            .map
            .iter()
            .filter(|((r, _), _)| r == prior_root)
            .filter(|((_, k), _)| !changed_keys.iter().any(|c| c == k))
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in migrated {
            inner.insert((new_root.clone(), k), v);
        }
        for k in changed_keys {
            inner.remove(&(new_root.clone(), k.clone()));
            inner.remove(&(prior_root.clone(), k.clone()));
        }
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.map.clear();
        inner.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peergos_core::build_cid;

    fn cid(seed: u8) -> Cid {
        build_cid(vec![seed; 32], false).unwrap()
    }

    // We test the keying / LRU / migration mechanics with negative (`None`) entries,
    // which exercises everything except carrying a concrete CryptreeNode value.
    #[test]
    fn hit_miss_and_key_isolation() {
        let c = CryptreeCache::new();
        let (r, k) = (cid(1), vec![9u8; 32]);
        assert!(c.get(&r, &k).is_none(), "cold miss");
        c.put(&r, &k, None);
        assert!(matches!(c.get(&r, &k), Some(None)), "cached negative");
        // Different root or key is a distinct entry.
        assert!(c.get(&cid(2), &k).is_none());
        assert!(c.get(&r, &[1u8; 32]).is_none());
    }

    #[test]
    fn lru_evicts_oldest() {
        let c = CryptreeCache::with_capacity(2);
        let r = cid(1);
        c.put(&r, &[1u8; 32], None);
        c.put(&r, &[2u8; 32], None);
        // Touch key 1 so key 2 becomes the least-recently-used.
        assert!(c.get(&r, &[1u8; 32]).is_some());
        c.put(&r, &[3u8; 32], None); // evicts key 2
        assert!(c.get(&r, &[1u8; 32]).is_some());
        assert!(c.get(&r, &[3u8; 32]).is_some());
        assert!(c.get(&r, &[2u8; 32]).is_none(), "LRU entry evicted");
    }

    #[test]
    fn migrate_keeps_siblings_and_drops_changed_keys() {
        let c = CryptreeCache::new();
        let (old_root, new_root) = (cid(1), cid(2));
        let sibling_a = [1u8; 32];
        let sibling_b = [2u8; 32];
        let mutated = [3u8; 32];
        c.put(&old_root, &sibling_a, None);
        c.put(&old_root, &sibling_b, None);
        c.put(&old_root, &mutated, None);

        c.migrate(&old_root, &new_root, &[mutated.to_vec()]);

        // Unchanged siblings are re-keyed forward to the new root...
        assert!(c.get(&new_root, &sibling_a).is_some());
        assert!(c.get(&new_root, &sibling_b).is_some());
        // ...but the mutated key is dropped under both roots (refetch next read).
        assert!(c.get(&new_root, &mutated).is_none());
        assert!(c.get(&old_root, &mutated).is_none());
    }

    #[test]
    fn update_migrates_siblings_to_new_root() {
        let c = CryptreeCache::new();
        let (old_root, new_root) = (cid(1), cid(2));
        let sibling = [7u8; 32];
        let mutated = [8u8; 32];
        c.put(&old_root, &sibling, None);
        c.put(&old_root, &mutated, None);
        // A write produced new_root; the sibling is unchanged so it re-keys forward.
        c.update(Some(&old_root), &new_root, &mutated, None);
        assert!(c.get(&new_root, &sibling).is_some(), "unchanged sibling valid under new root");
        assert!(c.get(&new_root, &mutated).is_some(), "mutated key stored under new root");
    }
}
