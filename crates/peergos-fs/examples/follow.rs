//! Social follow-request round-trip between two users.
//!  - ensures a second user `bob` exists (post-quantum signup),
//!  - `w2` sends `bob` a follow request,
//!  - `bob` fetches and decrypts pending follow requests.
//!
//!   cargo run -p peergos-fs --example follow -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    let (alice_u, alice_p) = ("w2", "w2pass");
    let (bob_u, bob_p) = ("bob", "bobpass");

    // Ensure bob exists (ignore "already exists").
    match peergos_fs::signup(bob_u, bob_p, None, poster.as_ref(), store.as_ref()).await {
        Ok(()) => println!("Signed up {bob_u:?}."),
        Err(e) if e.to_string().contains("already exists") => println!("{bob_u:?} already exists."),
        Err(e) => return Err(e.into()),
    }

    // Alice sends bob a follow request.
    let alice = peergos_fs::login(alice_u, alice_p, poster.as_ref(), store.clone(), &mutable, None).await?;
    println!("\n{alice_u:?} sending a follow request to {bob_u:?} ...");
    let sent = peergos_fs::send_follow_request(&alice, bob_u, true, poster.as_ref(), store.clone(), &mutable).await?;
    println!("  sent = {sent}");
    assert!(sent, "server rejected the follow request");

    // Bob fetches and decrypts pending follow requests.
    let bob = peergos_fs::login(bob_u, bob_p, poster.as_ref(), store.clone(), &mutable, None).await?;
    println!("\n{bob_u:?} fetching follow requests ...");
    let requests = peergos_fs::get_follow_requests(&bob, poster.as_ref()).await?;
    println!("  {} request(s):", requests.len());
    let mut saw_alice = false;
    for r in &requests {
        let sender = r.sender().unwrap_or("<none>");
        let owner = r.entry.as_ref().map(|e| e.pointer.owner.to_string()).unwrap_or_default();
        println!("    from {sender:?}  reciprocated={}  entry-owner={owner}", r.key.is_some());
        if sender == alice_u {
            saw_alice = true;
            // Confirm we can actually read the shared folder the request points to.
            let entries = peergos_fs::list_directory(&r.entry.as_ref().unwrap().pointer, store.clone(), &mutable).await?;
            println!("      shared folder readable, {} entries", entries.len());
        }
    }
    assert!(saw_alice, "bob did not receive alice's follow request");
    println!("\nFollow-request round-trip OK.");
    Ok(())
}
