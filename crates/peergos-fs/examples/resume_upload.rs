//! Auto-resume: a multi-chunk upload interrupted partway leaves an open transaction;
//! re-uploading the SAME content automatically continues from the first missing chunk
//! (matched by content hash tree) instead of re-sending everything.
//!
//! A `TestStore` counts raw (fragment) bytes written and can fail past a byte limit,
//! so we can interrupt attempt 1 and measure how much attempt 2 re-uploads.
//!
//!   cargo run -p peergos-fs --example resume_upload -- http://localhost:7777/

use async_trait::async_trait;
use peergos_cbor::CborObject;
use peergos_core::auth::BatWithId;
use peergos_core::keys::PublicKeyHash;
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::storage::{ChunkMirrorCap, TransactionId};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use peergos_multiformats::{Cid, Multihash};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MIB: usize = 1024 * 1024;

struct TestStore {
    inner: Arc<dyn ContentAddressedStorage>,
    raw_bytes: AtomicU64,
    fail_after: Option<u64>,
}
impl TestStore {
    fn raw_mib(&self) -> f64 {
        self.raw_bytes.load(Ordering::SeqCst) as f64 / MIB as f64
    }
}
#[async_trait]
impl ContentAddressedStorage for TestStore {
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
        let n: u64 = b.iter().map(|x| x.len() as u64).sum();
        let total = self.raw_bytes.fetch_add(n, Ordering::SeqCst) + n;
        if let Some(limit) = self.fail_after {
            if total > limit {
                return Err(peergos_core::Error::Protocol("simulated interruption".into()));
            }
        }
        self.inner.put_raw(o, w, s, b, t).await
    }
    async fn get_size(&self, o: &PublicKeyHash, b: &Multihash) -> peergos_core::Result<Option<u64>> {
        self.inner.get_size(o, b).await
    }
    async fn get_secret_link(&self, o: &PublicKeyHash, l: &str) -> peergos_core::Result<CborObject> {
        self.inner.get_secret_link(o, l).await
    }
    async fn get_champ_lookup(&self, o: &PublicKeyHash, r: &Cid, c: &[ChunkMirrorCap], cr: Option<&Cid>) -> peergos_core::Result<Vec<Vec<u8>>> {
        self.inner.get_champ_lookup(o, r, c, cr).await
    }
}

fn http(base: &str) -> Result<Arc<dyn ContentAddressedStorage>, Box<dyn std::error::Error>> {
    Ok(Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(base, false)?), true)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let content: Vec<u8> = (0..11 * MIB).map(|i| (i % 251) as u8).collect(); // 11 MiB = 3 chunks
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dirname = format!("resume{n}");

    // --- attempt 1: interrupt after ~1 chunk of fragment data -----------------
    let failing = Arc::new(TestStore { inner: http(&base)?, raw_bytes: AtomicU64::new(0), fail_after: Some((6 * MIB) as u64) });
    {
        let store: Arc<dyn ContentAddressedStorage> = failing.clone();
        let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
            Ok(c) => c,
            Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
        };
        let dir = ctx.get_home().await?.mkdir(&dirname).await?;
        let err = dir.upload("big.bin", &content).await;
        assert!(err.is_err(), "attempt 1 should be interrupted");
        println!("attempt 1 interrupted after {:.1} MiB of fragments (as designed)", failing.raw_mib());
    }

    // There is now an open transaction for this path.
    let ctx = UserContext::sign_in("w2", "w2pass", None, poster.clone(), http(&base)?, mutable.clone()).await?;
    let open = ctx.list_open_transactions().await?;
    assert!(open.iter().any(|t| t.path.ends_with("big.bin")), "a partial upload must be recorded");
    println!("open transactions after interruption: {}", open.len());

    // --- attempt 2: same content → auto-resume from the first missing chunk ----
    let counting = Arc::new(TestStore { inner: http(&base)?, raw_bytes: AtomicU64::new(0), fail_after: None });
    let store: Arc<dyn ContentAddressedStorage> = counting.clone();
    let ctx2 = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    let dir = ctx2.get_by_path(&dirname).await?.unwrap();
    let file = dir.upload("big.bin", &content).await?; // no error, no manual resume call
    println!("attempt 2 re-uploaded only {:.1} MiB of fragments (full file is 11 MiB)", counting.raw_mib());

    // Resumed, not restarted: attempt 2 sent well under the full 11 MiB.
    assert!(counting.raw_mib() < 9.0, "auto-resume must skip the already-uploaded chunk(s)");
    assert!(counting.raw_mib() > 3.0, "attempt 2 still uploads the remaining chunks");

    // The file is complete and correct, and the transaction is closed.
    assert_eq!(file.size(), content.len() as u64);
    let back = file.read().await?;
    assert!(back == content, "resumed file content must match");
    assert!(ctx2.list_open_transactions().await?.is_empty(), "transaction closed after a successful resume");
    println!("resumed file is complete ({} bytes) and the transaction is closed", back.len());

    println!("\nAuto-resume OK: re-uploading the same content continued the interrupted upload from where it stopped.");
    Ok(())
}
