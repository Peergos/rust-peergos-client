//! UserContext: the top-level account handle. Created by sign-in / sign-up (or a
//! secret link), it hands out FileWrappers and, matching Java, routes multi-chunk
//! uploads through a crash-safe `.transactions` while single-chunk uploads stay
//! atomic.
//!
//!   cargo run -p peergos-fs --example context -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    // sign_up is idempotent-ish here: fall back to sign_in if the account exists.
    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    println!("signed in as {:?} (secret-link? {})", ctx.username(), ctx.is_secret_link());

    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let home = ctx.get_home().await?;
    let dir = home.mkdir(&format!("ctx{n}")).await?;

    // --- single-chunk upload: atomic path (no transaction) --------------------
    let small = dir.upload("small.txt", b"a single chunk stays atomic").await?;
    println!("uploaded small.txt ({} bytes)", small.size());
    assert_eq!(small.read().await?, b"a single chunk stays atomic");
    assert!(ctx.list_open_transactions().await?.is_empty(), "atomic upload must leave no transaction");

    // --- multi-chunk upload: crash-safe transactional path --------------------
    // > CHUNK_MAX_SIZE (5 MiB) => 2 chunks => routed through a transaction.
    let big_len: usize = 5 * 1024 * 1024 + 7 * 1024; // just over one chunk
    let big: Vec<u8> = (0..big_len).map(|i| (i * 31 + 7) as u8).collect();
    let big_file = dir.upload("big.bin", &big).await?;
    println!("uploaded big.bin ({} bytes, {} chunks)", big_file.size(), big_len.div_ceil(5 * 1024 * 1024));
    let read_back = big_file.read().await?;
    assert_eq!(read_back.len(), big.len(), "size mismatch on multi-chunk read");
    assert_eq!(read_back, big, "content mismatch on multi-chunk round-trip");
    // On success the transaction record is closed/removed.
    assert!(ctx.list_open_transactions().await?.is_empty(), "successful transaction should be closed");
    println!("multi-chunk round-trip OK; open transactions after success: {}", ctx.list_open_transactions().await?.len());

    // --- path navigation via the context --------------------------------------
    let by_path = ctx.get_by_path(&format!("w2/ctx{n}/big.bin")).await?.expect("absolute path resolves");
    assert_eq!(by_path.size(), big_len as u64);
    let rel = ctx.get_by_path(&format!("ctx{n}/small.txt")).await?.expect("home-relative path resolves");
    assert_eq!(rel.read().await?, b"a single chunk stays atomic");
    println!("get_by_path resolved both /w2/... and home-relative forms");

    // cleanup
    home.remove_child(&format!("ctx{n}")).await?;

    // --- storage quota + usage -------------------------------------------------
    let quota = ctx.get_quota().await?;
    let usage = ctx.get_usage().await?;
    let local = ctx.get_local_usage().await?;
    println!("\nquota={} bytes ({:.1} MiB), usage={} bytes, local_usage={}", quota, quota as f64 / (1024.0 * 1024.0), usage, local);
    assert!(quota > 0, "account should have a positive quota");
    assert!(usage >= 0 && usage <= quota, "usage should be within [0, quota]");

    println!("\nUserContext OK: sign-in, get_home, upload routing, get_by_path, quota/usage.");
    Ok(())
}
