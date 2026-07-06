//! BufferedNetwork: buffer a batch of writes and flush them in bulk, plus the
//! CAS-conflict 3-way merge.
//!
//!  1. Upload 3 files through the buffered layer: nothing hits the server until
//!     commit; the files are still readable from the buffer; after commit they are
//!     on the server.
//!  2. Buffer an upload, let an EXTERNAL client advance the same writer's pointer,
//!     then commit — the CAS conflict is resolved by a 3-way champ merge and BOTH
//!     writes survive.
//!
//!   cargo run -p peergos-fs --example buffered -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{BufferedNetwork, ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn target(base: &str) -> Result<(Arc<dyn ContentAddressedStorage>, Arc<dyn MutablePointers>, Arc<dyn HttpPoster>), Box<dyn std::error::Error>> {
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(base, false)?), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(base, false)?)));
    Ok((store, mutable, poster))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let (store, mutable, poster) = target(&base)?;

    // Make sure the account exists.
    match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(_) | Err(_) => {}
    }
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // ---- 1. buffer a batch, flush in bulk ------------------------------------
    let net = Arc::new(BufferedNetwork::new(store.clone(), mutable.clone(), 16 * 1024 * 1024, 1000));
    let bstore: Arc<dyn ContentAddressedStorage> = net.storage();
    let bmutable: Arc<dyn MutablePointers> = net.pointers();
    let ctx = UserContext::sign_in("w2", "w2pass", None, poster.clone(), bstore, bmutable).await?;
    let owner = ctx.user().unwrap().identity.clone();

    let dirname = format!("buf{n}");
    let dir = ctx.get_home().await?.mkdir(&dirname).await?;
    dir.upload("a.txt", b"AAA").await?;
    dir.upload("b.txt", b"BBB").await?;
    dir.upload("c.txt", b"CCC").await?;
    println!("buffered {} bytes across the writes (nothing on the server yet)", net.buffered_size());
    assert!(net.buffered_size() > 0);

    // Readable from the buffer before commit.
    let a_buffered = dir.child("a.txt").await?.unwrap().read().await?;
    assert_eq!(a_buffered, b"AAA");

    // A separate, unbuffered client can't see it yet.
    let peek = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    assert!(peek.get_by_path(&dirname).await?.is_none(), "uncommitted dir must not be on the server");

    net.commit(&owner).await?;
    assert_eq!(net.buffered_size(), 0, "buffer drained after commit");
    println!("committed; buffer drained");

    // Now everything is on the server.
    let after = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    for (name, want) in [("a.txt", b"AAA"), ("b.txt", b"BBB"), ("c.txt", b"CCC")] {
        let got = after.get_by_path(&format!("{dirname}/{name}")).await?.unwrap().read().await?;
        assert_eq!(got, want);
    }
    println!("a/b/c all readable via the unbuffered server after one bulk commit");

    // ---- 2. CAS conflict resolved by 3-way merge -----------------------------
    // Concurrent writes must touch DIFFERENT subtrees (writing into the same
    // directory genuinely conflicts, since both rewrite that directory's node).
    // Pre-create two sibling directories, committed.
    let (pa, pb) = (format!("pa{n}"), format!("pb{n}"));
    let setup = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    let setup_home = setup.get_home().await?;
    setup_home.mkdir(&pa).await?;
    setup_home.mkdir(&pb).await?;

    // Buffer a write into pa (based on the current home root).
    let net2 = Arc::new(BufferedNetwork::new(store.clone(), mutable.clone(), 16 * 1024 * 1024, 1000));
    let bstore2: Arc<dyn ContentAddressedStorage> = net2.storage();
    let bmutable2: Arc<dyn MutablePointers> = net2.pointers();
    let ctx_buf = UserContext::sign_in("w2", "w2pass", None, poster.clone(), bstore2, bmutable2).await?;
    ctx_buf.get_by_path(&pa).await?.unwrap().upload("fileA.txt", b"buffered-A").await?;

    // Meanwhile an external client writes into pb, advancing the home writer's
    // pointer on the server → our buffered commit will hit a CAS conflict.
    let ctx_ext = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    ctx_ext.get_by_path(&pb).await?.unwrap().upload("fileB.txt", b"external-B").await?;
    println!("\nexternal client wrote {pb}/fileB.txt; now flushing the buffered {pa}/fileA.txt ...");

    // Commit the buffered write → CAS conflict on the home writer → 3-way champ merge.
    net2.commit(&owner).await?;

    let fin = UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    let a_ok = fin.get_by_path(&format!("{pa}/fileA.txt")).await?.is_some();
    let b_ok = fin.get_by_path(&format!("{pb}/fileB.txt")).await?.is_some();
    println!("after merge: buffered {pa}/fileA.txt? {a_ok}   external {pb}/fileB.txt? {b_ok}");
    assert!(a_ok, "the buffered write must survive the merge");
    assert!(b_ok, "the concurrent external write must be preserved by the merge");

    println!("\nBufferedNetwork OK: buffered bulk commit + serve-from-buffer, and CAS 3-way merge preserved both concurrent writes.");
    Ok(())
}
