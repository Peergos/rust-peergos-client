//! Send a follow request to a target user on a live server.
//!   cargo run -p peergos-fs --example follow_send_live -- <base> <username> <password> <target>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: follow_send_live <base> <username> <password> <target>");
    let password = args.next().expect("usage: follow_send_live <base> <username> <password> <target>");
    let target = args.next().expect("usage: follow_send_live <base> <username> <password> <target>");

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    println!("logged in as {username}; sending a follow request to {target} ...");
    let sent = peergos_fs::send_follow_request(&user, &target, true, poster.as_ref(), store.clone(), &mutable).await?;
    println!("follow request sent = {sent}");
    if !sent {
        return Err("server rejected the follow request (already pending, or already following?)".into());
    }
    Ok(())
}
