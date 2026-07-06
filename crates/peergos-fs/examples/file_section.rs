//! Random-access file I/O: read and overwrite a byte range without touching the
//! whole file. Uses a multi-chunk (11 MiB = 3 chunks) file and edits across a
//! 5 MiB chunk boundary.
//!
//!   cargo run -p peergos-fs --example file_section -- http://localhost:7777/

use async_trait::async_trait;
use peergos_cbor::CborObject;
use peergos_core::auth::BatWithId;
use peergos_core::keys::PublicKeyHash;
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::storage::{ChunkMirrorCap, TransactionId};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use peergos_multiformats::{Cid, Multihash};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const CHUNK: usize = 5 * 1024 * 1024;

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Counts `champ/get` calls (one per chunk-node lookup) to show section I/O only
/// touches the overlapping chunks.
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
    async fn start_transaction(&self, o: &PublicKeyHash) -> peergos_core::Result<TransactionId> {
        self.inner.start_transaction(o).await
    }
    async fn close_transaction(&self, o: &PublicKeyHash, t: &TransactionId) -> peergos_core::Result<bool> {
        self.inner.close_transaction(o, t).await
    }
    async fn get(&self, o: &PublicKeyHash, h: &Cid, b: Option<&BatWithId>) -> peergos_core::Result<Option<CborObject>> {
        self.inner.get(o, h, b).await
    }
    async fn get_raw(&self, o: &PublicKeyHash, h: &Cid, b: Option<&BatWithId>) -> peergos_core::Result<Option<Vec<u8>>> {
        self.inner.get_raw(o, h, b).await
    }
    async fn put(&self, o: &PublicKeyHash, w: &PublicKeyHash, s: Vec<Vec<u8>>, b: Vec<Vec<u8>>, t: &TransactionId) -> peergos_core::Result<Vec<Cid>> {
        self.inner.put(o, w, s, b, t).await
    }
    async fn put_raw(&self, o: &PublicKeyHash, w: &PublicKeyHash, s: Vec<Vec<u8>>, b: Vec<Vec<u8>>, t: &TransactionId) -> peergos_core::Result<Vec<Cid>> {
        self.inner.put_raw(o, w, s, b, t).await
    }
    async fn get_size(&self, o: &PublicKeyHash, b: &Multihash) -> peergos_core::Result<Option<u64>> {
        self.inner.get_size(o, b).await
    }
    async fn get_secret_link(&self, o: &PublicKeyHash, l: &str) -> peergos_core::Result<CborObject> {
        self.inner.get_secret_link(o, l).await
    }
    async fn get_champ_lookup(&self, o: &PublicKeyHash, r: &Cid, c: &[ChunkMirrorCap], cr: Option<&Cid>) -> peergos_core::Result<Vec<Vec<u8>>> {
        self.champ_gets.fetch_add(1, Ordering::SeqCst);
        self.inner.get_champ_lookup(o, r, c, cr).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dir = ctx.get_home().await?.mkdir(&format!("sect{n}")).await?;

    // 11 MiB file over 3 chunks (5 + 5 + 1).
    let size = 11 * 1024 * 1024;
    let mut expected = pattern(size);
    let file = dir.upload("big.bin", &expected).await?;
    println!("uploaded big.bin: {} bytes ({} chunks)", file.size(), size.div_ceil(CHUNK));
    // A freshly-written file carries a content hash-tree branch on chunk 0.
    assert!(file.properties().tree_hash.is_some(), "fresh upload should have a tree hash");

    // --- 1. section read across the first chunk boundary ----------------------
    let off = (CHUNK - 100) as u64;
    let got = file.read_section(off, 200).await?;
    assert_eq!(got, &expected[off as usize..off as usize + 200], "cross-boundary read must match");
    println!("read_section({off}, 200) across the 5 MiB boundary: matches");

    // A section fully inside the last (partial) chunk.
    let off2 = (10 * 1024 * 1024 + 1000) as u64;
    let got2 = file.read_section(off2, 512).await?;
    assert_eq!(got2, &expected[off2 as usize..off2 as usize + 512]);
    println!("read_section({off2}, 512) inside the last chunk: matches");

    // Reading past EOF is clamped.
    let tail = file.read_section((size - 10) as u64, 999).await?;
    assert_eq!(tail.len(), 10, "read past EOF is clamped to the file end");

    // --- 2. in-place overwrite across the chunk boundary ----------------------
    let edit_off = (CHUNK - 50) as u64;
    let edit = vec![0xABu8; 100]; // straddles chunk 0 and chunk 1
    file.overwrite_section(edit_off, &edit).await?;
    expected[edit_off as usize..edit_off as usize + 100].copy_from_slice(&edit);
    println!("overwrite_section({edit_off}, 100 bytes) across the boundary: done");

    // The edited range reads back as written...
    let re = file.read_section(edit_off, 100).await?;
    assert_eq!(re, edit, "edited bytes must read back");
    // ...and the whole file matches expected (size unchanged, everything else intact).
    let refetched = ctx.get_by_path(&format!("sect{n}/big.bin")).await?.unwrap();
    assert_eq!(refetched.size(), size as u64, "file size must be unchanged");
    let full = refetched.read().await?;
    assert_eq!(full.len(), size);
    assert!(full == expected, "full file must equal the expected buffer after the in-place edit");
    println!("full read after edit: all {} bytes match (size unchanged)", full.len());

    // The partial write clears the (now-stale) content hash-tree branch, matching
    // Java's overwriteSection ("remove hash from properties as we are changing the file").
    assert!(refetched.properties().tree_hash.is_none(), "partial overwrite must clear the tree hash");
    println!("tree hash cleared by the partial overwrite: {}", refetched.properties().tree_hash.is_none());

    // Growing past the end is rejected.
    let grow = file.overwrite_section((size - 5) as u64, &[0u8; 100]).await;
    assert!(grow.is_err(), "overwrite_section must refuse to grow the file");
    println!("overwrite past EOF correctly rejected");

    // --- 3. prove it only fetches the overlapping chunks ----------------------
    // Count champ/get calls (one per chunk node) for a full read vs a section read
    // that lands in the LAST chunk — the middle chunk is seeked past, not fetched.
    let path = format!("sect{n}/big.bin");
    let full_gets = {
        let cs = Arc::new(CountingStore { inner: Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true)), champ_gets: AtomicUsize::new(0) });
        let store: Arc<dyn ContentAddressedStorage> = cs.clone();
        let c = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store, mutable.clone()).await?;
        let f = c.get_by_path(&path).await?.unwrap();
        let before = cs.count();
        let _ = f.read().await?;
        cs.count() - before
    };
    let section_gets = {
        let cs = Arc::new(CountingStore { inner: Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true)), champ_gets: AtomicUsize::new(0) });
        let store: Arc<dyn ContentAddressedStorage> = cs.clone();
        let c = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store, mutable.clone()).await?;
        let f = c.get_by_path(&path).await?.unwrap();
        let before = cs.count();
        let _ = f.read_section(off2, 512).await?; // off2 is in the 3rd (last) chunk
        cs.count() - before
    };
    println!("chunk-node fetches: full read = {full_gets}, last-chunk section read = {section_gets}");
    assert!(section_gets < full_gets, "a section read must fetch fewer chunk nodes than a full read");

    println!("\nSection I/O OK: ranged read + in-place ranged overwrite touch only the overlapping chunks.");
    Ok(())
}
