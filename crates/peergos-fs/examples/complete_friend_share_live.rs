//! Complete a friendship (process any pending follow request from `target`) and
//! read-share a file with them, on a live server.
//!   cargo run -p peergos-fs --example complete_friend_share_live -- <base> <username> <password> <target> <file-name>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let base = args.next().unwrap_or_else(|| "https://test.peergos.net/".to_string());
    let username = args.next().expect("usage: <base> <username> <password> <target> <file-name>");
    let password = args.next().expect("usage: <base> <username> <password> <target> <file-name>");
    let target = args.next().expect("usage: <base> <username> <password> <target> <file-name>");
    let file_name = args.next().expect("usage: <base> <username> <password> <target> <file-name>");

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    println!("logged in as {username}");

    // --- Complete the friendship: handle any follow request from `target` -----
    let pending = peergos_fs::get_pending_outgoing(&user, store.clone(), &mutable).await?;
    let we_asked_them = pending.iter().any(|u| u == &target);
    let requests = peergos_fs::get_follow_requests(&user, poster.as_ref()).await?;
    let from_target = requests.into_iter().find(|r| r.sender() == Some(target.as_str()));

    match from_target {
        Some(req) => {
            if we_asked_them {
                // They accepted our request: process their reply so we follow them.
                peergos_fs::process_follow_reply(&user, &req, poster.as_ref(), store.clone(), &mutable).await?;
                println!("processed {target}'s reply to our follow request — friendship complete");
            } else {
                // A fresh request from them: accept and reciprocate.
                peergos_fs::accept_follow_request(&user, &req, true, poster.as_ref(), store.clone(), &mutable).await?;
                println!("accepted {target}'s follow request (reciprocated) — friendship complete");
            }
        }
        None => {
            println!(
                "no pending follow request from {target} yet (we_asked_them={we_asked_them}); \
                 they still need to accept before the friendship is mutual. Sharing anyway."
            );
        }
    }

    // Re-login to pick up the updated social state, then confirm friends.
    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let friends = peergos_fs::get_friends(&user, store.clone(), &mutable).await?;
    println!("friends: {:?}", friends.iter().map(|e| e.owner_name.clone()).collect::<Vec<_>>());

    // --- Share the file read-only with `target` -------------------------------
    let home = user.home().ok_or("no home directory")?;
    let entry = peergos_fs::list_directory(home, store.clone(), &mutable)
        .await?
        .into_iter()
        .find(|e| e.name == file_name)
        .ok_or_else(|| format!("no file named {file_name:?} in home"))?;
    peergos_fs::share_read_access(&user, &file_name, &entry.cap, &target, store.clone(), &mutable).await?;
    println!("read-shared {file_name:?} with {target}");

    // Show who the file is now shared with.
    let shared = peergos_fs::get_shared_with(&user, &file_name, peergos_fs::Access::Read, store.clone(), &mutable).await?;
    println!("{file_name:?} is now read-shared with: {shared:?}");
    Ok(())
}
