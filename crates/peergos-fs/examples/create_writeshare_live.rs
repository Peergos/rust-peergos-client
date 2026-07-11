//! Create a file in home and share it WRITABLE with a target user, on a live server.
//!   cargo run -p peergos-fs --example create_writeshare_live -- <base> <username> <password> <target>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: <base> <username> <password> <target>");
    let password = args.next().expect("usage: <base> <username> <password> <target>");
    let target = args.next().expect("usage: <base> <username> <password> <target>");

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    let name = "test.md";
    let content = b"# Test\n\nThis is a collaboratively editable test file created by the Rust Peergos client.\n";

    // Create the file in home.
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home directory")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    peergos_fs::upload_file(&home, name, content, None, Some(signer), user.mirror_bat_id().as_ref(), store.clone(), &mutable).await?;
    println!("created {name:?} ({} bytes) in /{username}", content.len());

    // Re-login for fresh state, then write-share it with the target.
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home directory")?.clone();
    peergos_fs::share_write_access(&user, "", &home, name, &target, store.clone(), &mutable).await?;
    println!("write-shared {name:?} with {target}");

    // Confirm.
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let shared = peergos_fs::get_shared_with(&user, name, peergos_fs::Access::Write, store.clone(), &mutable).await?;
    println!("{name:?} is now write-shared with: {shared:?}");
    Ok(())
}
