//! changePassword on a throwaway account.
//!   cargo run -p peergos-fs --example change_password -- http://localhost:7777/
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
    let name = format!("pwtest{n}");

    let ctx = UserContext::sign_up(&name, "oldpass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    ctx.get_home().await?.upload("keep.txt", b"survive the change").await?;
    println!("account {name} created with oldpass");

    ctx.change_password("oldpass", "newpass", None).await?;
    println!("changePassword old->new returned OK");

    // New password works and the data survived.
    let renew = UserContext::sign_in(&name, "newpass", None, poster.clone(), store.clone(), mutable.clone()).await?;
    let data = renew.get_by_path("keep.txt").await?.expect("file still there").read().await?;
    assert_eq!(data, b"survive the change");
    println!("sign in with newpass OK; keep.txt intact");

    // Old password no longer works.
    let old = UserContext::sign_in(&name, "oldpass", None, poster.clone(), store.clone(), mutable.clone()).await;
    assert!(old.is_err(), "old password must be rejected");
    println!("sign in with oldpass correctly rejected");

    // Account still fully usable (write after re-login).
    renew.get_home().await?.upload("after.txt", b"new writes work").await?;
    println!("upload after password change works");

    println!("\nchangePassword OK: new password works, data preserved, old password rejected.");
    Ok(())
}
