//! Query a directory's sharing state (`getDirectorySharingState`): after sharing
//! files with a friend, read back who each child is shared with.
//!
//!   cargo run -p peergos-fs --example dir_sharing_state -- http://localhost:7777/

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

    // Fresh users: the sharing state is read from an append-only cache, so a clean
    // slate keeps the assertions deterministic.
    let s = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (au, ap) = (format!("alice{s}"), "apass");
    let (bu, bp) = (format!("bob{s}"), "bpass");
    for (u, p) in [(&au, ap), (&bu, bp)] {
        peergos_fs::signup(u, p, None, poster.as_ref(), store.as_ref()).await?;
    }

    let alice = peergos_fs::login(&au, ap, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    peergos_fs::send_follow_request(&alice, &bu, true, poster.as_ref(), store.clone(), &mutable).await?;

    // alice creates docs/ with two files and shares them with bob (a.txt read,
    // b.txt write), and shares a top-level note with read access.
    let docs = peergos_fs::create_directory(&home, "docs", Some(signer.clone()), None, store.clone(), &mutable).await?;
    let a = peergos_fs::upload_file(&docs, "a.txt", b"aaa", None, Some(signer.clone()), None, store.clone(), &mutable).await?;
    let _b = peergos_fs::upload_file(&docs, "b.txt", b"bbb", None, Some(signer.clone()), None, store.clone(), &mutable).await?;
    let note = peergos_fs::upload_file(&home, "note.txt", b"hi", None, Some(signer.clone()), None, store.clone(), &mutable).await?;

    peergos_fs::share_read_access(&alice, "docs/a.txt", &a, &bu, store.clone(), &mutable).await?;
    peergos_fs::share_write_access(&alice, "docs", &docs, "b.txt", &bu, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "note.txt", &note, &bu, store.clone(), &mutable).await?;
    println!("shared docs/a.txt (read), docs/b.txt (write), note.txt (read) with {bu}");

    // --- getDirectorySharingState -------------------------------------------
    let docs_state = peergos_fs::get_directory_sharing_state(&alice, "docs", store.clone(), &mutable).await?;
    assert!(!docs_state.is_empty(), "docs/ has shares");
    assert_eq!(docs_state.read_shares().get("a.txt"), Some(&std::iter::once(bu.clone()).collect()), "a.txt read-shared with bob");
    assert!(docs_state.write_shares().get("b.txt").map(|s| s.contains(&bu)).unwrap_or(false), "b.txt write-shared with bob");
    // per-file view
    let a_view = docs_state.get("a.txt");
    assert!(a_view.read.contains(&bu) && a_view.write.is_empty(), "a.txt is read-only for bob");
    println!(
        "docs sharing state: a.txt read={:?}, b.txt write={:?}",
        docs_state.read_shares().get("a.txt").unwrap(),
        docs_state.write_shares().get("b.txt").unwrap()
    );

    // Top-level (home) directory: note.txt is read-shared.
    let home_state = peergos_fs::get_directory_sharing_state(&alice, "", store.clone(), &mutable).await?;
    assert!(home_state.read_shares().get("note.txt").map(|s| s.contains(&bu)).unwrap_or(false), "note.txt read-shared");
    println!("home sharing state: note.txt read={:?}", home_state.read_shares().get("note.txt").unwrap());

    // A directory with nothing shared under it → empty.
    let empty = peergos_fs::get_directory_sharing_state(&alice, "no/such/dir", store.clone(), &mutable).await?;
    assert!(empty.is_empty(), "unshared directory is empty");
    println!("unshared dir -> empty");

    println!("\ngetDirectorySharingState OK.");
    Ok(())
}
