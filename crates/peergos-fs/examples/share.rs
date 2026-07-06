//! End-to-end file sharing between two users:
//!  - `w2` uploads a file and sends `bob` a follow request (grants the sharing
//!    folder),
//!  - `w2` shares the file with `bob` (appends its cap to the capability store),
//!  - `bob` receives the follow request, reads the shared capabilities, and reads
//!    the shared file — content must match.
//!
//!   cargo run -p peergos-fs --example share -- http://localhost:7777/

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

    let (alice_u, alice_p) = ("w2", "w2pass");
    let (bob_u, bob_p) = ("bob", "bobpass");

    match peergos_fs::signup(bob_u, bob_p, None, poster.as_ref(), store.as_ref()).await {
        Ok(()) => println!("Signed up {bob_u:?}."),
        Err(e) if e.to_string().contains("already exists") => {}
        Err(e) => return Err(e.into()),
    }

    // Alice uploads a file with unique content, follows bob, and shares the file.
    let alice = peergos_fs::login(alice_u, alice_p, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let content = format!("shared secret #{nonce}");
    let filename = "shared.txt";
    let file_cap = peergos_fs::upload_file(&home, filename, content.as_bytes(), None, Some(signer.clone()), store.clone(), &mutable).await?;
    println!("{alice_u:?} uploaded {filename:?} = {content:?}");

    peergos_fs::send_follow_request(&alice, bob_u, true, poster.as_ref(), store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "shared.txt", &file_cap, bob_u, store.clone(), &mutable).await?;
    println!("{alice_u:?} shared {filename:?} with {bob_u:?}");

    // Bob receives the follow request and reads the shared file.
    let bob = peergos_fs::login(bob_u, bob_p, poster.as_ref(), store.clone(), &mutable, None).await?;
    let requests = peergos_fs::get_follow_requests(&bob, poster.as_ref()).await?;
    let from_alice = requests
        .iter()
        .filter(|r| r.sender() == Some(alice_u))
        .filter_map(|r| r.entry.as_ref())
        .next()
        .ok_or("bob has no follow request from alice")?;
    println!("\n{bob_u:?} reading capabilities shared by {alice_u:?} ...");

    let caps = peergos_fs::read_shared_capabilities(&from_alice.pointer, store.clone(), &mutable).await?;
    println!("  {} shared capabilit(y/ies)", caps.len());
    let mut found = None;
    for cap in &caps {
        // A shared cap may be a group sharing directory (from being added to a
        // friends/followers group), which isn't a readable file — skip those.
        let (props, data) = match peergos_fs::read_file(cap, store.clone(), &mutable).await {
            Ok(pd) => pd,
            Err(_) => continue,
        };
        let text = String::from_utf8_lossy(&data).to_string();
        println!("    {:?} = {text:?}", props.name);
        if text == content {
            found = Some(text);
        }
    }
    assert_eq!(found.as_deref(), Some(content.as_str()), "bob could not read the freshly shared file");
    println!("\nFile sharing OK: {bob_u:?} read {alice_u:?}'s shared file with matching content.");
    Ok(())
}
