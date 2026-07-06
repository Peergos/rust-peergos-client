//! Write-sharing: alice grants bob write access to a directory, bob (a different
//! user) writes a file into it, and alice sees bob's file.
//!
//!   cargo run -p peergos-fs --example write_share -- http://localhost:7777/

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
    let _ = peergos_fs::signup(bu, bp, None, poster.as_ref(), store.as_ref()).await;

    // Ensure a friendship exists so bob can read alice's sharing folder.
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    peergos_fs::send_follow_request(&alice, bu, true, poster.as_ref(), store.clone(), &mutable).await?;
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), &mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster.as_ref()).await? {
        if r.sender() == Some(au) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster.as_ref(), store.clone(), &mutable).await?;
        }
    }
    for r in peergos_fs::get_follow_requests(&alice, poster.as_ref()).await? {
        if r.sender() == Some(bu) {
            peergos_fs::process_follow_reply(&alice, &r, poster.as_ref(), store.clone(), &mutable).await?;
        }
    }

    // Alice creates an ordinary directory (sharing home's writer) with a file in
    // it, then grants bob write access — which rotates it into its own writer.
    let home = alice.home().ok_or("no home")?.clone();
    let signer0 = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    let collab0 = peergos_fs::create_directory(&home, "collab", Some(signer0.clone()), store.clone(), &mutable).await?;
    peergos_fs::upload_file(&collab0, "readme.txt", b"pre-existing content", None, Some(signer0), store.clone(), &mutable).await?;
    println!("{au:?} created ordinary dir 'collab' (writer == home writer: {})", collab0.writer == home.writer);

    println!("{au:?} granting {bu:?} write access to 'collab' (rotates to its own writer) ...");
    peergos_fs::share_write_access(&alice, "", &home, "collab", bu, store.clone(), &mutable).await?;

    // After rotation, home's "collab" child is a LINK NODE in the parent's writer
    // space (so the write-access holder can't rename it); follow it to the real dir.
    let collab_link = peergos_fs::list_directory(&home, store.clone(), &mutable).await?
        .into_iter().find(|e| e.name == "collab").ok_or("collab vanished")?.cap;
    let link_props = peergos_fs::retrieve_file_metadata(&collab_link, store.clone(), &mutable).await?.1;
    assert!(link_props.is_link, "collab should be a link node after rotation");
    assert_eq!(collab_link.writer, home.writer, "link node must stay in the parent's writer space");
    let collab = peergos_fs::list_directory(&collab_link, store.clone(), &mutable).await?
        .into_iter().next().ok_or("link node has no target")?.cap;
    println!("  collab is a link node (parent writer); real dir has its own writer: {}", collab.writer != home.writer);
    println!("{au:?} granted {bu:?} write access to collab");

    // Bob finds the writable cap via his friendship and writes into it.
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), &mutable, None).await?;
    let alice_entry = peergos_fs::get_friends(&bob, store.clone(), &mutable).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("bob is not friends with alice")?;
    let write_caps = peergos_fs::read_write_shared_capabilities(&alice_entry.pointer, store.clone(), &mutable).await?;
    println!("\n{bu:?} sees {} writable capabilit(y/ies) shared by {au:?}", write_caps.len());
    let collab_for_bob = write_caps.into_iter().last().ok_or("no writable cap shared with bob")?;
    assert!(collab_for_bob.is_writable(), "shared cap is not writable");

    let bob_signer = peergos_fs::recover_signer(&collab_for_bob, store.clone(), &mutable).await?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let content = format!("written by bob #{nonce}");
    peergos_fs::upload_file(&collab_for_bob, "from-bob.txt", content.as_bytes(), None, Some(bob_signer), store.clone(), &mutable).await?;
    println!("{bu:?} wrote from-bob.txt = {content:?} into {au:?}'s directory");

    // Alice re-reads collab and sees bob's file with the right content.
    let entries = peergos_fs::list_directory(&collab, store.clone(), &mutable).await?;
    println!("\n{au:?} now sees collab contents: {:?}", entries.iter().map(|e| &e.name).collect::<Vec<_>>());
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    assert!(names.contains(&"readme.txt".to_string()), "pre-existing file lost during rotation");
    let bobs = entries.into_iter().find(|e| e.name == "from-bob.txt").ok_or("alice does not see bob's file")?;
    let (_p, data) = peergos_fs::read_file(&bobs.cap, store.clone(), &mutable).await?;
    assert_eq!(String::from_utf8_lossy(&data), content, "content written by bob does not match");
    println!("{au:?} read {bu:?}'s file, content matches ✓ (pre-existing readme.txt survived rotation)");
    println!("\nWrite-sharing OK: a different user wrote into the shared directory.");
    Ok(())
}
