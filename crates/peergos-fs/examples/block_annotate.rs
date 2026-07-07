//! Block / unblock a user and add friend annotations (ports Java's block-list and
//! `getFriendAnnotations` / `addFriendAnnotation`).
//!
//!   cargo run -p peergos-fs --example block_annotate -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{FriendAnnotation, UserContext};
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

    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let username = format!("blk{n}");
    let ctx = UserContext::sign_up(&username, "blkpass99", None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed up {username}");

    // --- block / unblock -----------------------------------------------------
    assert!(ctx.get_blocked().await?.is_empty(), "no one blocked initially");
    ctx.block("spammer").await?;
    ctx.block("troll").await?;
    ctx.block("spammer").await?; // idempotent
    let blocked = ctx.get_blocked().await?;
    assert_eq!(blocked, vec!["spammer".to_string(), "troll".to_string()], "blocked list (sorted, deduped)");
    println!("blocked: {blocked:?}");

    ctx.unblock("spammer").await?;
    assert_eq!(ctx.get_blocked().await?, vec!["troll".to_string()], "spammer unblocked");
    ctx.unblock("nobody").await?; // no-op
    ctx.unblock("troll").await?;
    assert!(ctx.get_blocked().await?.is_empty(), "all unblocked");
    println!("unblock OK: block-list emptied");

    // --- friend annotations --------------------------------------------------
    assert!(ctx.get_friend_annotations().await?.is_empty(), "no annotations initially");
    ctx.add_friend_annotation(FriendAnnotation::new("alice", true, vec![])).await?;
    ctx.add_friend_annotation(FriendAnnotation::new("bob", false, vec![])).await?;
    let annos = ctx.get_friend_annotations().await?;
    assert_eq!(annos.len(), 2);
    assert!(annos["alice"].is_verified, "alice is verified");
    assert!(!annos["bob"].is_verified, "bob is not verified");
    println!("annotations: alice.verified={}, bob.verified={}", annos["alice"].is_verified, annos["bob"].is_verified);

    // Re-annotating the same username replaces (not duplicates).
    ctx.add_friend_annotation(FriendAnnotation::new("bob", true, vec![])).await?;
    let annos = ctx.get_friend_annotations().await?;
    assert_eq!(annos.len(), 2, "still 2 friends, bob replaced not duplicated");
    assert!(annos["bob"].is_verified, "bob now verified");
    println!("re-annotate OK: bob.verified={} (count still {})", annos["bob"].is_verified, annos.len());

    println!("\nBlock / unblock / friend-annotation OK.");
    Ok(())
}
