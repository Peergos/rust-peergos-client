//! Full bidirectional friendship handshake with persistence:
//!  - alice (w2) sends bob a follow request,
//!  - bob accepts + reciprocates (persists alice, replies),
//!  - alice processes the reply (persists bob),
//!  - both re-login and confirm the friend is persisted,
//!  - alice shares a file; bob reads it via his persisted friend entry point.
//!
//!   cargo run -p peergos-fs --example friends -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());
    let (au, ap) = ("w2", "w2pass");
    let (bu, bp) = ("bob", "bobpass");
    for (u, p) in [(bu, bp)] {
        match peergos_fs::signup(u, p, None, poster.as_ref(), store.as_ref()).await {
            Ok(()) | Err(_) => {}
        }
    }

    // 1. Alice sends bob a follow request.
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    peergos_fs::send_follow_request(&alice, bu, true, poster.as_ref(), store.clone(), &mutable).await?;
    println!("{au:?} → {bu:?}: follow request sent");

    // 2. Bob accepts + reciprocates every pending request from alice.
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), &mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster.as_ref()).await? {
        if r.sender() == Some(au) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster.as_ref(), store.clone(), &mutable).await?;
            println!("{bu:?} accepted + reciprocated {au:?}'s request");
        }
    }

    // 3. Alice processes bob's reply.
    for r in peergos_fs::get_follow_requests(&alice, poster.as_ref()).await? {
        if r.sender() == Some(bu) {
            peergos_fs::process_follow_reply(&alice, &r, poster.as_ref(), store.clone(), &mutable).await?;
            println!("{au:?} processed {bu:?}'s reply");
        }
    }

    // 4. Re-login both and confirm the friendship is persisted.
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), &mutable, None).await?;
    let alice_friends: Vec<String> = peergos_fs::get_friends(&alice, store.clone(), &mutable).await?
        .iter().map(|e| e.owner_name.clone()).collect();
    let bob_friends: Vec<String> = peergos_fs::get_friends(&bob, store.clone(), &mutable).await?
        .iter().map(|e| e.owner_name.clone()).collect();
    println!("\nAfter re-login:");
    println!("  {au:?}'s friends: {alice_friends:?}");
    println!("  {bu:?}'s friends: {bob_friends:?}");
    assert!(alice_friends.contains(&bu.to_string()), "alice did not persist bob");
    assert!(bob_friends.contains(&au.to_string()), "bob did not persist alice");

    // 5. Alice shares a file; bob reads it via his PERSISTED friend entry point.
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let content = format!("hello friend #{nonce}");
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    let file_cap = peergos_fs::upload_file(&home, "note.txt", content.as_bytes(), None, Some(signer), None, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "note.txt", &file_cap, bu, store.clone(), &mutable).await?;
    println!("\n{au:?} shared note.txt = {content:?}");

    let alice_entry = peergos_fs::get_friends(&bob, store.clone(), &mutable).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("bob lost alice")?;
    let caps = peergos_fs::read_shared_capabilities(&alice_entry.pointer, store.clone(), &mutable).await?;
    let mut found = false;
    for cap in &caps {
        // Skip group sharing directories (not readable files).
        let data = match peergos_fs::read_file(cap, store.clone(), &mutable).await {
            Ok((_p, data)) => data,
            Err(_) => continue,
        };
        if String::from_utf8_lossy(&data) == content {
            found = true;
        }
    }
    assert!(found, "bob could not read alice's shared file via persisted friendship");
    println!("{bu:?} read the shared file via the persisted friendship ✓");
    println!("\nBidirectional friendship + persistence OK.");
    Ok(())
}
