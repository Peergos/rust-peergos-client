//! Create a directory in home and share it WRITABLE with a target user, live.
//!   cargo run -p peergos-fs --example mkdir_writeshare_live -- <base> <username> <password> <target> <dir-name>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: <base> <username> <password> <target> <dir-name>");
    let password = args.next().expect("usage: <base> <username> <password> <target> <dir-name>");
    let target = args.next().expect("usage: <base> <username> <password> <target> <dir-name>");
    let dir = args.next().unwrap_or_else(|| "write".to_string());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    // Create the directory in home.
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home directory")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    peergos_fs::create_directory(&home, &dir, Some(signer), user.mirror_bat_id().as_ref(), store.clone(), &mutable).await?;
    println!("created directory {dir:?} in /{username}");

    // Re-login for fresh state, then write-share it with the target.
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home directory")?.clone();
    peergos_fs::share_write_access(&user, "", &home, &dir, &target, store.clone(), &mutable).await?;
    println!("write-shared {dir:?} with {target}");

    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let shared = peergos_fs::get_shared_with(&user, &dir, peergos_fs::Access::Write, store.clone(), &mutable).await?;
    println!("{dir:?} is now write-shared with: {shared:?}");
    Ok(())
}
