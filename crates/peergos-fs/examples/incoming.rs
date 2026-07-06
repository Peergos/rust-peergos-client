//! IncomingCapCache: your local mirror of everything shared with you.
//!  - alice shares /w2/projN/notes.txt with bob,
//!  - bob updates his incoming-cap cache from alice, then resolves the path in the
//!    mirror and reads the file,
//!  - get_children lists what alice shared under /w2/projN,
//!  - a second share is picked up incrementally; a third update with nothing new
//!    is a no-op (ProcessedCaps remembers our position).
//!
//!   cargo run -p peergos-fs --example incoming -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(poster.clone()));

    let (au, ap) = ("w2", "w2pass");
    let (bu, bp) = ("bob", "bobpass");
    let _ = peergos_fs::signup(bu, bp, None, poster.as_ref(), store.as_ref()).await;

    // Ensure alice and bob are friends (idempotent).
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    peergos_fs::send_follow_request(&alice, bu, true, poster.as_ref(), store.clone(), mutable.as_ref()).await?;
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster.as_ref()).await? {
        if r.sender() == Some(au) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster.as_ref(), store.clone(), mutable.as_ref()).await?;
        }
    }
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    for r in peergos_fs::get_follow_requests(&alice, poster.as_ref()).await? {
        if r.sender() == Some(bu) {
            peergos_fs::process_follow_reply(&alice, &r, poster.as_ref(), store.clone(), mutable.as_ref()).await?;
        }
    }

    // Alice shares a file in a fresh subdirectory with bob.
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await?;
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let proj = format!("proj{n}");
    let projdir = peergos_fs::create_directory(&home, &proj, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    let notes = peergos_fs::upload_file(&projdir, "notes.txt", b"project notes", None, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_read_access(&alice, &format!("{proj}/notes.txt"), &notes, bu, store.clone(), mutable.as_ref()).await?;
    println!("{au:?} shared {proj}/notes.txt with {bu:?}");

    // Bob updates his incoming cap cache from alice.
    let bob_ctx = peergos_fs::UserContext::sign_in(bu, bp, None, poster.clone(), store.clone(), mutable.clone()).await?;
    let alice_entry = peergos_fs::get_friends(bob_ctx.user().unwrap(), store.clone(), mutable.as_ref()).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("bob not friends with alice")?;
    let cache = bob_ctx.incoming_cap_cache().await?;

    let added = cache.update_from_friend(au, &alice_entry.pointer).await?;
    println!("\nbob pulled {} new cap(s) from {au}", added.len());
    assert!(added.iter().any(|c| c.path.ends_with(&format!("{proj}/notes.txt"))), "notes.txt should be pulled");

    // Resolve the path in the mirror and read the file.
    let notes_path = format!("/{au}/{proj}/notes.txt");
    let cap = cache.get_by_path(&notes_path).await?.ok_or("mirror get_by_path failed")?;
    let (_p, data) = peergos_fs::read_file(&cap, store.clone(), mutable.as_ref()).await?;
    println!("mirror get_by_path {notes_path:?} -> read {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"project notes");

    // List what alice shared under /w2/projN.
    let children = cache.get_children(&format!("/{au}/{proj}")).await?;
    println!("get_children(/{au}/{proj}) = {:?}", children.iter().map(|(n, _)| n).collect::<Vec<_>>());
    assert!(children.iter().any(|(name, _)| name == "notes.txt"));

    // Incremental: share a second file, update again — only the new one is pulled.
    let second = peergos_fs::upload_file(&projdir, "second.txt", b"more notes", None, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_read_access(&alice, &format!("{proj}/second.txt"), &second, bu, store.clone(), mutable.as_ref()).await?;
    let added2 = cache.update_from_friend(au, &alice_entry.pointer).await?;
    println!("\nafter sharing a 2nd file, bob pulled {} new cap(s)", added2.len());
    assert!(added2.iter().any(|c| c.path.ends_with(&format!("{proj}/second.txt"))));
    assert!(cache.get_by_path(&format!("/{au}/{proj}/second.txt")).await?.is_some());

    // A further update with nothing new is a no-op.
    let added3 = cache.update_from_friend(au, &alice_entry.pointer).await?;
    println!("update with nothing new pulled {} cap(s)", added3.len());
    assert!(added3.is_empty(), "ProcessedCaps should make a redundant update a no-op");

    println!("\nIncomingCapCache OK: mirror update, path lookup + read, get_children, incremental + idempotent.");
    Ok(())
}
