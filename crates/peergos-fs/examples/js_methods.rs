//! Newly-added UI methods: getOrMkdirs, getDirectChildrenCount, getContentHash,
//! truncate, getLatest, deleteChildren, deleteSecretLink, getSocialState.
//!
//!   cargo run -p peergos-fs --example js_methods -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{retrieve_secret_link_capability, SecretLink, UserContext};
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

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let root = ctx.get_home().await?.mkdir(&format!("js{n}")).await?;

    // getOrMkdirs: create a/b/c in one call, returns the leaf.
    let leaf = root.get_or_mkdirs("a/b/c").await?;
    assert_eq!(leaf.name(), "c");
    // Idempotent: second call reuses the existing dirs.
    assert_eq!(root.get_or_mkdirs("a/b/c").await?.capability().map_key, leaf.capability().map_key);
    println!("getOrMkdirs a/b/c -> leaf {:?} (idempotent)", leaf.name());

    // getDirectChildrenCount
    root.upload("f1.txt", b"one").await?;
    root.upload("f2.txt", b"two").await?;
    let count = root.get_latest().await?.direct_children_count().await?;
    println!("directChildrenCount = {count}"); // a, f1.txt, f2.txt
    assert_eq!(count, 3);

    // getContentHash (32-byte sha256, deterministic for the same content)
    let f = root.upload("hash.txt", b"hash me").await?;
    let h = f.content_hash().await?;
    assert_eq!(h.len(), 32);
    assert_eq!(h, root.get_by_path("hash.txt").await?.unwrap().content_hash().await?);
    println!("contentHash(hash.txt) = {}…", h.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>());

    // truncate
    let t = root.upload("trunc.txt", b"0123456789").await?;
    t.truncate(4).await?;
    let after = root.get_by_path("trunc.txt").await?.unwrap();
    assert_eq!(after.size(), 4);
    assert_eq!(after.read().await?, b"0123");
    println!("truncate(4): size {} content {:?}", after.size(), String::from_utf8_lossy(&after.read().await?));

    // appendFile
    let a = root.upload("app.txt", b"abc").await?;
    a.append(b"def").await?;
    assert_eq!(root.get_by_path("app.txt").await?.unwrap().read().await?, b"abcdef");
    println!("append: abc + def -> abcdef");

    // deleteChildren
    root.delete_children(&["f1.txt", "f2.txt"]).await?;
    assert!(root.get_by_path("f1.txt").await?.is_none() && root.get_by_path("f2.txt").await?.is_none());
    println!("deleteChildren removed f1.txt, f2.txt");

    // deleteSecretLink: mint a link, confirm it resolves, delete it, confirm it doesn't.
    let path = format!("js{n}/hash.txt");
    let link = ctx.create_secret_link(&path, false, "", None, None).await?;
    assert!(retrieve_secret_link_capability(&link, store.as_ref(), None).await.is_ok());
    let label = SecretLink::from_link(&link)?.label;
    ctx.delete_secret_link(&path, label).await?;
    assert!(retrieve_secret_link_capability(&link, store.as_ref(), None).await.is_err(), "deleted link must not resolve");
    println!("deleteSecretLink: link stopped resolving after deletion");

    // unfollow (block a username) + getSocialState
    ctx.unfollow("someblockeduser").await?;
    let social = ctx.social_state().await?;
    assert!(social.blocked.iter().any(|b| b == "someblockeduser"), "unfollowed user must appear in blocked");
    println!(
        "socialState: following={} followers={} blocked={} pending-in={} pending-out={}",
        social.following.len(),
        social.followers.len(),
        social.blocked.len(),
        social.pending_incoming_requests.len(),
        social.pending_outgoing.len(),
    );

    println!("\nUI methods OK: getOrMkdirs, directChildrenCount, contentHash, truncate, append, deleteChildren, deleteSecretLink, unfollow, socialState.");
    Ok(())
}
