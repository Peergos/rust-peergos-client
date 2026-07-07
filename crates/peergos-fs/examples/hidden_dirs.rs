//! Verify the special signup directories (shared, .transactions, .capabilitycache)
//! are created hidden (Java's isSystemFolder), while an ordinary mkdir is not.
//!
//!   cargo run -p peergos-fs --example hidden_dirs -- http://localhost:7777/

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
    let username = format!("hid{n}");
    let ctx = UserContext::sign_up(&username, "hidpass99", None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed up {username}");

    for dir in ["shared", ".transactions", ".capabilitycache"] {
        let w = ctx.get_by_path(dir).await?.ok_or_else(|| format!("{dir} missing"))?;
        assert!(w.properties().is_hidden, "{dir} should be hidden");
        println!("  {dir}: is_hidden={}", w.properties().is_hidden);
    }

    // A plain mkdir is not hidden.
    let plain = ctx.get_home().await?.mkdir(&format!("plain{n}")).await?;
    assert!(!plain.properties().is_hidden, "an ordinary directory must not be hidden");
    println!("  plain{n}: is_hidden={}", plain.properties().is_hidden);

    // System files are written hidden too: blocking + annotating creates them.
    ctx.block("spammer").await?;
    ctx.add_friend_annotation(FriendAnnotation::new("alice", true, vec![])).await?;
    for file in [".blocked-usernames.txt", ".annotations"] {
        let w = ctx.get_by_path(file).await?.ok_or_else(|| format!("{file} missing"))?;
        assert!(w.properties().is_hidden, "{file} should be hidden");
        println!("  {file}: is_hidden={}", w.properties().is_hidden);
    }
    // An ordinary uploaded file is not hidden.
    let doc = ctx.get_home().await?.upload("doc.txt", b"visible").await?;
    assert!(!doc.properties().is_hidden, "an ordinary file must not be hidden");
    println!("  doc.txt: is_hidden={}", doc.properties().is_hidden);

    println!("\nHidden signup directories + system files OK.");
    Ok(())
}
