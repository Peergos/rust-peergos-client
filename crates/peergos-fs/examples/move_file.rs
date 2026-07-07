//! Faithful `move` demo covering both paths:
//!  - FAST path (same writer): metadata-only move; the file's capability is
//!    unchanged, so an existing SHARE to it keeps working after the move.
//!  - SLOW path (different writer, e.g. into a write-shared own-writer dir): the
//!    subtree is copied and the old one deleted.
//!
//!   cargo run -p peergos-fs --example move_file -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

type Store = Arc<dyn ContentAddressedStorage>;

async fn befriend(a: (&str, &str), b: (&str, &str), poster: &ReqwestPoster, store: Store, mutable: &HttpMutablePointers)
    -> Result<(), Box<dyn std::error::Error>> {
    let alice = peergos_fs::login(a.0, a.1, poster, store.clone(), mutable, None).await?;
    peergos_fs::send_follow_request(&alice, b.0, true, poster, store.clone(), mutable).await?;
    let bob = peergos_fs::login(b.0, b.1, poster, store.clone(), mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster).await? {
        if r.sender() == Some(a.0) { peergos_fs::accept_follow_request(&bob, &r, true, poster, store.clone(), mutable).await?; }
    }
    let alice = peergos_fs::login(a.0, a.1, poster, store.clone(), mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&alice, poster).await? {
        if r.sender() == Some(b.0) { peergos_fs::process_follow_reply(&alice, &r, poster, store.clone(), mutable).await?; }
    }
    Ok(())
}

async fn bob_reads(name: &str, poster: &ReqwestPoster, store: Store, mutable: &HttpMutablePointers) -> Option<String> {
    let bob = peergos_fs::login("bob", "bobpass", poster, store.clone(), mutable, None).await.ok()?;
    let alice = peergos_fs::get_friends(&bob, store.clone(), mutable).await.ok()?.into_iter().find(|e| e.owner_name == "w2")?;
    for cap in peergos_fs::read_shared_capabilities(&alice.pointer, store.clone(), mutable).await.ok()? {
        if let Ok((props, data)) = peergos_fs::read_file(&cap, store.clone(), mutable).await {
            if props.name == name { return Some(String::from_utf8_lossy(&data).to_string()); }
        }
    }
    None
}

async fn names(dir: &peergos_fs::AbsoluteCapability, store: Store, mutable: &HttpMutablePointers) -> Vec<String> {
    peergos_fs::list_directory(dir, store, mutable).await.unwrap().into_iter().map(|e| e.name).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = ReqwestPoster::new(&base, false)?;
    let store: Store = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable = HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?));
    for (u, p) in [("w2", "w2pass"), ("bob", "bobpass")] {
        match peergos_fs::signup(u, p, None, &poster, store.as_ref()).await { Ok(()) | Err(_) => {} }
    }
    befriend(("w2", "w2pass"), ("bob", "bobpass"), &poster, store.clone(), &mutable).await?;

    let alice = peergos_fs::login("w2", "w2pass", &poster, store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;

    // Upload doc.txt to home, share with bob, make dest/ subdir.
    let doc = peergos_fs::upload_file(&home, "doc.txt", b"portable secret", None, Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "doc.txt", &doc, "bob", store.clone(), &mutable).await?;
    let dest = peergos_fs::create_directory(&home, "dest", Some(signer.clone()), None, store.clone(), &mutable).await?;
    println!("before: home={:?}, bob-reads-doc.txt={:?}", names(&home, store.clone(), &mutable).await, bob_reads("doc.txt", &poster, store.clone(), &mutable).await);

    // FAST move: doc.txt -> dest/ (both share home's writer).
    println!("\n== Fast move (same writer) ==");
    let moved = peergos_fs::move_to(&home, "doc.txt", &dest, true, Some(signer.clone()), None, store.clone(), &mutable).await?;
    assert_eq!(moved.map_key, doc.map_key, "fast move should keep the same capability (map key)");
    let home_names = names(&home, store.clone(), &mutable).await;
    let dest_names = names(&dest, store.clone(), &mutable).await;
    println!("  home now: {home_names:?}");
    println!("  dest now: {dest_names:?}");
    assert!(!home_names.contains(&"doc.txt".to_string()) && dest_names.contains(&"doc.txt".to_string()));
    // Content intact, read from its new location.
    let moved_cap = peergos_fs::list_directory(&dest, store.clone(), &mutable).await?.into_iter().find(|e| e.name == "doc.txt").unwrap().cap;
    let (_p, data) = peergos_fs::read_file(&moved_cap, store.clone(), &mutable).await?;
    println!("  content after move: {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"portable secret");
    // THE OPTIMISATION: bob's share still works (cap unchanged).
    let bob_after = bob_reads("doc.txt", &poster, store.clone(), &mutable).await;
    println!("  bob still reads doc.txt after move: {bob_after:?}");
    assert_eq!(bob_after.as_deref(), Some("portable secret"), "fast move broke the existing share!");

    // SLOW move: a dir into an own-writer directory (different writer -> copy+delete).
    println!("\n== Slow move (different writer) ==");
    let folder = peergos_fs::create_directory(&home, "folder", Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::upload_file(&folder, "inner.txt", b"inner data", None, Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::create_directory(&home, "vault", Some(signer.clone()), None, store.clone(), &mutable).await?;
    let vault = peergos_fs::move_dir_to_own_writer(&home, "vault", None, None, store.clone(), &mutable).await?;
    println!("  vault has its own writer: {}", vault.writer != home.writer);
    let new_folder = peergos_fs::move_to(&home, "folder", &vault, true, Some(signer.clone()), None, store.clone(), &mutable).await?;
    let home_names = names(&home, store.clone(), &mutable).await;
    let vault_names = names(&vault, store.clone(), &mutable).await;
    println!("  home now: {home_names:?}");
    println!("  vault now: {vault_names:?}  (new writer for folder: {})", new_folder.writer != home.writer);
    assert!(!home_names.contains(&"folder".to_string()) && vault_names.contains(&"folder".to_string()));
    let inner = peergos_fs::list_directory(&new_folder, store.clone(), &mutable).await?.into_iter().find(|e| e.name == "inner.txt").unwrap().cap;
    let (_p, data) = peergos_fs::read_file(&inner, store.clone(), &mutable).await?;
    println!("  folder/inner.txt after move: {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"inner data");

    println!("\nMove OK: fast path preserves the capability + shares; slow path copies across writers.");
    Ok(())
}
