//! List a live account's home directory (and one level down).
//!   cargo run -p peergos-fs --example ls_live -- <base-url> <username> <password>

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: ls_live <base> <username> <password>");
    let password = args.next().expect("usage: ls_live <base> <username> <password>");

    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = UserContext::sign_in(&username, &password, None, poster, store, mutable).await?;
    println!("signed in as {username}");

    let home = ctx.get_home().await?;
    let children = home.children().await?;
    println!("/{username} has {} entries:", children.len());
    for c in &children {
        let kind = if c.is_directory() { "dir " } else { "file" };
        let thumb = match &c.properties().thumbnail {
            Some((mime, bytes)) => format!(" [thumbnail: {mime}, {} bytes]", bytes.len()),
            None => " [no thumbnail]".to_string(),
        };
        println!("  [{kind}] {} ({} bytes){thumb}", c.name(), c.size());
        if c.is_directory() {
            if let Ok(sub) = c.children().await {
                for s in sub.iter().take(20) {
                    let k = if s.is_directory() { "dir " } else { "file" };
                    println!("      [{k}] {} ({} bytes)", s.name(), s.size());
                }
            }
        }
    }
    Ok(())
}
