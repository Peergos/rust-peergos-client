//! CapabilitiesFromUser: read the capabilities a friend shared with us WITH their
//! resolved absolute paths (CapabilityWithPath), and resume from a byte offset so
//! only newly-added shares are re-read.
//!
//!  - alice creates /alice/docsN/, uploads a.txt into it, shares it with bob,
//!  - bob loads read-access links: sees path "/alice/docsN/a.txt" and reads it,
//!  - alice shares a second file b.txt,
//!  - bob loads again from the previous bytes_read: sees ONLY b.txt (incremental).
//!
//!   cargo run -p peergos-fs --example capsfromuser -- http://localhost:7777/

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

    // Ensure alice and bob are friends (idempotent).
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    peergos_fs::send_follow_request(&alice, bu, true, poster.as_ref(), store.clone(), &mutable).await?;
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), &mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster.as_ref()).await? {
        if r.sender() == Some(au) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster.as_ref(), store.clone(), &mutable).await?;
        }
    }
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&alice, poster.as_ref()).await? {
        if r.sender() == Some(bu) {
            peergos_fs::process_follow_reply(&alice, &r, poster.as_ref(), store.clone(), &mutable).await?;
        }
    }

    // Alice creates a subdirectory and shares a file inside it with bob.
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dir = format!("docs{n}");
    let docs = peergos_fs::create_directory(&home, &dir, Some(signer.clone()), None, store.clone(), &mutable).await?;
    let a_cap = peergos_fs::upload_file(&docs, "a.txt", b"first shared file", None, Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, &format!("{dir}/a.txt"), &a_cap, bu, store.clone(), &mutable).await?;
    println!("{au:?} shared {dir}/a.txt with {bu:?}");

    // Bob loads the read-access links WITH paths.
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), &mutable, None).await?;
    let alice_entry = peergos_fs::get_friends(&bob, store.clone(), &mutable).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("bob is not friends with alice")?;

    let first = peergos_fs::load_read_access_sharing_links(&alice_entry.pointer, 0, store.clone(), &mutable).await?;
    println!("\nbob loaded {} cap(s), bytes_read={}", first.capabilities.len(), first.bytes_read);
    for c in &first.capabilities {
        println!("  path={:?}", c.path);
    }
    let mine = first.capabilities.iter().find(|c| c.path.ends_with(&format!("{dir}/a.txt")))
        .ok_or("resolved path for a.txt not found")?;
    let expected_path = format!("/{au}/{dir}/a.txt");
    assert_eq!(mine.path, expected_path, "path should resolve through the subdir to the owner's home");
    let (_p, data) = peergos_fs::read_file(&mine.cap, store.clone(), &mutable).await?;
    assert_eq!(data, b"first shared file");
    println!("  -> resolved {expected_path:?} and read it back");

    // Alice shares a second file; bob resumes from the previous offset.
    let offset = first.bytes_read;
    let b_cap = peergos_fs::upload_file(&docs, "b.txt", b"second shared file", None, Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, &format!("{dir}/b.txt"), &b_cap, bu, store.clone(), &mutable).await?;
    println!("\n{au:?} shared a second file; bob resumes from bytes_read={offset}");

    let delta = peergos_fs::load_read_access_sharing_links(&alice_entry.pointer, offset, store.clone(), &mutable).await?;
    println!("  incremental load returned {} new cap(s):", delta.capabilities.len());
    for c in &delta.capabilities {
        println!("    path={:?}", c.path);
    }
    assert_eq!(delta.capabilities.len(), 1, "resuming from the offset should yield only the newly-shared file");
    assert!(delta.capabilities[0].path.ends_with(&format!("{dir}/b.txt")));
    assert!(delta.bytes_read > offset, "bytes_read should advance");

    println!("\nCapabilitiesFromUser OK: pathed caps resolve through subdirs, and offset resume is incremental.");
    Ok(())
}
