//! The decrypted-cryptree-node cache (Java's `NetworkAccess.cache`): once a node
//! is read+decrypted, repeat reads of the same node hit the cache and issue NO
//! `champ/get`. A `CountingStore` wraps the real block store and counts the
//! `get_champ_lookup` calls so the effect is visible.
//!
//!   cargo run -p peergos-fs --example cryptree_cache -- http://localhost:7777/

use async_trait::async_trait;
use peergos_core::auth::BatWithId;
use peergos_core::keys::PublicKeyHash;
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::storage::{ChunkMirrorCap, TransactionId};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use peergos_multiformats::{Cid, Multihash};
use peergos_cbor::CborObject;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

struct CountingStore {
    inner: Arc<dyn ContentAddressedStorage>,
    champ_gets: AtomicUsize,
}

impl CountingStore {
    fn count(&self) -> usize {
        self.champ_gets.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ContentAddressedStorage for CountingStore {
    async fn id(&self) -> peergos_core::Result<Cid> {
        self.inner.id().await
    }
    async fn ids(&self) -> peergos_core::Result<Vec<Cid>> {
        self.inner.ids().await
    }
    async fn start_transaction(&self, owner: &PublicKeyHash) -> peergos_core::Result<TransactionId> {
        self.inner.start_transaction(owner).await
    }
    async fn close_transaction(&self, owner: &PublicKeyHash, tid: &TransactionId) -> peergos_core::Result<bool> {
        self.inner.close_transaction(owner, tid).await
    }
    async fn get(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> peergos_core::Result<Option<CborObject>> {
        self.inner.get(owner, hash, bat).await
    }
    async fn get_raw(&self, owner: &PublicKeyHash, hash: &Cid, bat: Option<&BatWithId>) -> peergos_core::Result<Option<Vec<u8>>> {
        self.inner.get_raw(owner, hash, bat).await
    }
    async fn put(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, s: Vec<Vec<u8>>, b: Vec<Vec<u8>>, tid: &TransactionId) -> peergos_core::Result<Vec<Cid>> {
        self.inner.put(owner, writer, s, b, tid).await
    }
    async fn put_raw(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, s: Vec<Vec<u8>>, b: Vec<Vec<u8>>, tid: &TransactionId) -> peergos_core::Result<Vec<Cid>> {
        self.inner.put_raw(owner, writer, s, b, tid).await
    }
    async fn get_size(&self, owner: &PublicKeyHash, block: &Multihash) -> peergos_core::Result<Option<u64>> {
        self.inner.get_size(owner, block).await
    }
    async fn get_secret_link(&self, owner: &PublicKeyHash, label: &str) -> peergos_core::Result<CborObject> {
        self.inner.get_secret_link(owner, label).await
    }
    async fn get_champ_lookup(&self, owner: &PublicKeyHash, root: &Cid, caps: &[ChunkMirrorCap], committed: Option<&Cid>) -> peergos_core::Result<Vec<Vec<u8>>> {
        self.champ_gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get_champ_lookup(owner, root, caps, committed).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let raw: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let counting = Arc::new(CountingStore { inner: raw, champ_gets: AtomicUsize::new(0) });
    let store: Arc<dyn ContentAddressedStorage> = counting.clone();
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dir = ctx.get_home().await?.mkdir(&format!("cache{n}")).await?;
    for i in 0..5 {
        dir.upload(&format!("f{i}.txt"), format!("body-{i}").as_bytes()).await?;
    }

    // A FRESH session (cold cache) — the setup context already warmed its own cache.
    let read_ctx = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    let dir = read_ctx.get_by_path(&format!("cache{n}")).await?.unwrap();

    let before = counting.count();
    let first = dir.children().await?;
    let after_first = counting.count();
    println!("first children(): {} entries, {} champ/get calls", first.len(), after_first - before);
    assert_eq!(first.len(), 5);
    assert!(after_first - before > 0, "first read must hit the network");

    let second = dir.children().await?;
    let after_second = counting.count();
    println!("second children(): {} entries, {} champ/get calls (cache hit)", second.len(), after_second - after_first);
    assert_eq!(second.len(), 5);
    assert_eq!(after_second - after_first, 0, "repeat read must be served entirely from the cryptree cache");

    // Reading a file twice via a cached handle: the metadata node is cached too.
    let f = dir.child("f0.txt").await?.unwrap();
    let base_reads = counting.count();
    assert_eq!(f.read().await?, b"body-0");
    let one = counting.count() - base_reads;
    assert_eq!(f.read().await?, b"body-0");
    let two = counting.count() - base_reads - one;
    println!("file read champ/get: first {one}, second {two} (metadata node cached)");
    assert_eq!(two, 0, "the file's metadata node must be cached on the second read");

    // --- migration: an unrelated write keeps untouched siblings warm ----------
    // Uploading a new file changes the directory's champ tree root. Without the
    // commit-path migration, every cache entry (keyed by the old root) would go
    // dead; with it, unchanged siblings are re-keyed to the new root.
    dir.upload("new.txt", b"new").await?;
    let before_sib = counting.count();
    assert_eq!(f.read().await?, b"body-0"); // f0 is untouched by the upload
    let sib = counting.count() - before_sib;
    println!("after an unrelated upload (tree root changed): sibling read champ/get = {sib}");
    assert_eq!(sib, 0, "migration must keep the untouched sibling warm across the write");

    println!("\nCryptreeCache OK: repeat reads = 0 champ/get, and an unrelated write migrates unchanged siblings forward (still 0).");
    Ok(())
}
