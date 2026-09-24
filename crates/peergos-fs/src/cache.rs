//! `CryptreeCache` — an LRU of DECRYPTED cryptree nodes keyed by
//! `(champ tree root, map key)`, ported from Java's `CryptreeCache` (a field on
//! `NetworkAccess`, and hence inherited by `BufferedNetworkAccess`).
//!
//! Entries are grouped by root, and a commit moves a root's group to the new root
//! rather than copying it. This is distinct from the block-level read cache in
//! `BufferedStorage` (raw encrypted bytes by CID). A hit here skips BOTH the `champ/get` round-trip and
//! the decrypt. The key includes the content-addressed champ root, so entries can
//! never go stale: any change to the tree produces a new root, so a subsequent
//! lookup uses a different key and misses (rather than reading outdated data).

use crate::cryptree::CryptreeNode;
use peergos_multiformats::Cid;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

/// Default number of entries retained per root (`CryptreeCache` in Java).
pub const DEFAULT_CRYPTREE_CACHE_SIZE: usize = 1000;
/// How many champ roots are kept at once (`CryptreeCache.MAX_ROOTS`).
const MAX_ROOTS: usize = 4;

/// A least-recently-used map. Access is O(1); eviction scans, but only when full.
struct Lru<K, V> {
    map: HashMap<K, (u64, V)>,
    tick: u64,
    cap: usize,
}

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    fn new(cap: usize) -> Lru<K, V> {
        Lru { map: HashMap::new(), tick: 0, cap: cap.max(1) }
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        self.tick += 1;
        let tick = self.tick;
        self.map.get_mut(key).map(|(t, v)| {
            *t = tick;
            &*v
        })
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.tick += 1;
        let tick = self.tick;
        self.map.get_mut(key).map(|(t, v)| {
            *t = tick;
            v
        })
    }

    fn insert(&mut self, key: K, val: V) {
        self.tick += 1;
        if !self.map.contains_key(&key) && self.map.len() >= self.cap {
            if let Some(oldest) = self.map.iter().min_by_key(|(_, (t, _))| *t).map(|(k, _)| k.clone()) {
                self.map.remove(&oldest);
            }
        }
        self.map.insert(key, (self.tick, val));
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key).map(|(_, v)| v)
    }
}

/// Decrypted nodes read under one champ root: `None` is a known-absent key.
type ForRoot = Lru<Vec<u8>, Option<CryptreeNode>>;

struct Inner {
    by_root: Lru<Cid, ForRoot>,
    cap: usize,
}

impl Inner {
    fn for_root(&mut self, root: &Cid) -> &mut ForRoot {
        if self.by_root.get(root).is_none() {
            self.by_root.insert(root.clone(), Lru::new(self.cap));
        }
        self.by_root.get_mut(root).expect("just inserted")
    }

    /// Carry everything read under `prior` over to `new`: a commit changes the root
    /// but leaves every other mapping as it was, so the group moves rather than copies.
    fn carry_over(&mut self, prior: &Cid, new: &Cid) {
        if prior == new {
            return;
        }
        if let Some(carried) = self.by_root.remove(prior) {
            self.by_root.insert(new.clone(), carried);
        }
    }
}

/// A shared, thread-safe cache of decrypted cryptree nodes, grouped by the champ
/// root they were read from. Cheap to clone (an `Arc` handle to the shared store).
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

    /// A cache holding up to `cap` entries for each root it keeps.
    pub fn with_capacity(cap: usize) -> CryptreeCache {
        CryptreeCache { inner: Arc::new(Mutex::new(Inner { by_root: Lru::new(MAX_ROOTS), cap: cap.max(1) })) }
    }

    /// The cached node for `(root, map_key)`. The outer `Option` is cache presence;
    /// the inner `Option<CryptreeNode>` distinguishes a cached node from a cached
    /// "known absent".
    pub fn get(&self, root: &Cid, map_key: &[u8]) -> Option<Option<CryptreeNode>> {
        let mut inner = self.inner.lock().unwrap();
        inner.by_root.get_mut(root)?.get(&map_key.to_vec()).cloned()
    }

    pub fn put(&self, root: &Cid, map_key: &[u8], val: Option<CryptreeNode>) {
        self.inner.lock().unwrap().for_root(root).insert(map_key.to_vec(), val);
    }

    /// After a write changed the tree root from `prior_root` to `new_root` by
    /// storing `val` at `map_key`: carry the other entries over and store the new
    /// value (Java's `CryptreeCache.update`).
    pub fn update(&self, prior_root: Option<&Cid>, new_root: &Cid, map_key: &[u8], val: Option<CryptreeNode>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(prior) = prior_root {
            inner.carry_over(prior, new_root);
        }
        inner.for_root(new_root).insert(map_key.to_vec(), val);
    }

    /// The value-less form of [`update`](Self::update) used by the mutation commit
    /// path: carry the entries over to `new_root` except the `changed_keys` the
    /// write touched, which are dropped so their next read refetches.
    pub fn migrate(&self, prior_root: &Cid, new_root: &Cid, changed_keys: &[Vec<u8>]) {
        let mut inner = self.inner.lock().unwrap();
        inner.carry_over(prior_root, new_root);
        if let Some(group) = inner.by_root.get_mut(new_root) {
            for k in changed_keys {
                group.remove(k);
            }
        }
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        let cap = inner.cap;
        *inner = Inner { by_root: Lru::new(MAX_ROOTS), cap };
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
    fn only_a_few_roots_are_kept() {
        let c = CryptreeCache::new();
        for i in 0..6u8 {
            c.put(&cid(i), &[i; 32], None);
        }
        assert!(c.get(&cid(0), &[0; 32]).is_none(), "the oldest root is dropped");
        assert!(c.get(&cid(5), &[5; 32]).is_some());
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
