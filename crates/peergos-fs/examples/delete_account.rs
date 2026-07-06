//! deleteAccount on a throwaway account: after deletion the home is unreadable.
//!   cargo run -p peergos-fs --example delete_account -- http://localhost:7777/
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let name = format!("deltest{n}");

    let ctx = UserContext::sign_up(&name, "pw", None, poster.clone(), store.clone(), mutable.clone()).await?;
    ctx.get_home().await?.upload("bye.txt", b"temporary").await?;
    assert!(ctx.get_home().await.is_ok(), "home readable before deletion");
    println!("account {name} created + file uploaded");

    ctx.delete_account().await?;
    println!("deleteAccount called");

    // The home writer's pointer is now empty, so the home can't be resolved.
    let after = UserContext::sign_in(&name, "pw", None, poster.clone(), store.clone(), mutable.clone()).await;
    let unreadable = match after {
        Ok(c) => c.get_home().await.is_err(),
        Err(_) => true,
    };
    assert!(unreadable, "home must be unreadable after deleteAccount");
    println!("after deleteAccount: account filesystem is gone (home unreadable): OK");
    Ok(())
}
