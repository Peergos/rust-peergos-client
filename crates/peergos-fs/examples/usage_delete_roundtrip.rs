//! Storage-usage round-trip: uploading a multi-chunk file raises reported usage,
//! and deleting it returns usage to *exactly* the prior value — both for a plain
//! file and for one that has been moved into its own writer subspace (the state a
//! writable share puts it in).
//!
//!   cargo run -p peergos-fs --example usage_delete_roundtrip -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Usage the server reports can lag a write slightly; poll until it settles.
async fn settled_usage(ctx: &UserContext) -> Result<i64, Box<dyn std::error::Error>> {
    let mut last = ctx.get_usage().await?;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let now = ctx.get_usage().await?;
        if now == last {
            return Ok(now);
        }
        last = now;
    }
    Ok(last)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let username = format!("use{n}");
    let ctx = UserContext::sign_up(&username, "usepass99", None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed up {username}");

    let content: Vec<u8> = (0..11 * 1024 * 1024).map(|i| (i % 251) as u8).collect(); // 11 MiB = 3 chunks
    let home = ctx.get_home().await?;
    let signer = peergos_fs::recover_signer(home.capability(), store.clone(), mutable.as_ref()).await?;
    let mb = ctx.get_mirror_bat().await?.map(|b| b.id());

    // --- Case 1: a plain multi-chunk file -----------------------------------
    let baseline = settled_usage(&ctx).await?;
    println!("baseline usage: {baseline}");

    peergos_fs::upload_file(home.capability(), "big.bin", &content, None, Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let after_upload = settled_usage(&ctx).await?;
    println!("after uploading 11 MiB: {after_upload} (+{})", after_upload - baseline);
    assert!(after_upload > baseline, "uploading must increase usage");

    peergos_fs::delete_child(home.capability(), "big.bin", Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let after_delete = settled_usage(&ctx).await?;
    println!("after deleting: {after_delete} (baseline was {baseline})");
    assert_eq!(after_delete, baseline, "deleting a plain file must return usage to exactly the prior value");
    println!("plain file: usage round-trips exactly\n");

    // --- Case 2: a file moved into its own writer (writable-share state) -----
    let baseline2 = settled_usage(&ctx).await?;
    println!("baseline usage: {baseline2}");

    peergos_fs::upload_file(home.capability(), "shared.bin", &content, None, Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    // Move it into its own writer subspace — what write-sharing does to a file.
    peergos_fs::move_file_to_own_writer(home.capability(), "shared.bin", Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let after_share = settled_usage(&ctx).await?;
    println!("after upload + move-to-own-writer: {after_share} (+{})", after_share - baseline2);
    assert!(after_share > baseline2, "a writable-shared file must use space");

    peergos_fs::delete_child(home.capability(), "shared.bin", Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let after_delete2 = settled_usage(&ctx).await?;
    println!("after deleting: {after_delete2} (baseline was {baseline2})");
    assert_eq!(after_delete2, baseline2, "deleting a writable-shared file must return usage to exactly the prior value");
    println!("writable-shared file: usage round-trips exactly\n");

    // --- Case 3: nested own writers — a write-shared dir holding a write-shared
    // file — deleted at the top. Every descendant subspace must be reclaimed,
    // regardless of writing space. ------------------------------------------
    let baseline3 = settled_usage(&ctx).await?;
    println!("baseline usage: {baseline3}");

    peergos_fs::create_directory(home.capability(), "outer", Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    // Move `outer` into its own writer (W1).
    let outer = peergos_fs::move_dir_to_own_writer(home.capability(), "outer", Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let outer_signer = peergos_fs::recover_signer(&outer, store.clone(), mutable.as_ref()).await?;
    // Upload an 11 MiB file into W1, then move it into its OWN writer (W2).
    peergos_fs::upload_file(&outer, "inner.bin", &content, None, Some(outer_signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    peergos_fs::move_file_to_own_writer(&outer, "inner.bin", Some(outer_signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let after_nested = settled_usage(&ctx).await?;
    println!("after nested own-writer tree (home->outer(W1)->inner(W2)): {after_nested} (+{})", after_nested - baseline3);
    assert!(after_nested > baseline3, "the nested tree must use space");

    // Delete `outer` at the top — must reclaim W1 AND the nested W2.
    peergos_fs::delete_child(home.capability(), "outer", Some(signer.clone()), mb.as_ref(), store.clone(), mutable.as_ref()).await?;
    let after_delete3 = settled_usage(&ctx).await?;
    println!("after deleting outer: {after_delete3} (baseline was {baseline3})");
    assert_eq!(after_delete3, baseline3, "deleting a directory must reclaim every descendant subspace, regardless of writer");
    println!("nested own-writer tree: usage round-trips exactly");

    println!("\nUsage round-trip OK: multi-chunk upload + delete reclaims exactly — plain, writable-shared, and nested across writers.");
    Ok(())
}
