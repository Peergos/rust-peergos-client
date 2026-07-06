//! FileWrapper: the ergonomic handle over a capability. Instead of threading
//! `(cap, store, mutable, entry_signer)` through free functions, you navigate and
//! mutate the filesystem with methods on a stateful handle, in the spirit of
//! Java's `FileWrapper`.
//!
//!   cargo run -p peergos-fs --example filewrapper -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use peergos_fs::FileWrapper;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = ReqwestPoster::new(&base, false)?;
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let _ = peergos_fs::signup("w2", "w2pass", None, &poster, store.as_ref()).await;
    let user = peergos_fs::login("w2", "w2pass", &poster, store.clone(), mutable.as_ref(), None).await?;

    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // Home directory as a handle -------------------------------------------------
    let home = FileWrapper::home(&user, store.clone(), mutable.clone()).await?;
    println!("home: {home:?}");
    assert!(home.is_directory() && home.is_writable());

    // mkdir + nested upload via methods -----------------------------------------
    let dir_name = format!("fw{n}");
    let dir = home.mkdir(&dir_name).await?;
    println!("mkdir -> {dir:?}");
    let sub = dir.mkdir("sub").await?;
    let file = sub.upload("hello.txt", b"hi from FileWrapper").await?;
    println!("upload -> {file:?}");
    assert!(!file.is_directory());
    assert_eq!(file.size(), b"hi from FileWrapper".len() as u64);

    // read back -----------------------------------------------------------------
    let data = file.read().await?;
    println!("read: {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"hi from FileWrapper");

    // navigation: children + get_by_path ----------------------------------------
    let kids: Vec<String> = dir.children().await?.into_iter().map(|c| c.name().to_string()).collect();
    println!("children of {dir_name}: {kids:?}");
    assert!(kids.contains(&"sub".to_string()));

    let found = home.get_by_path(&format!("{dir_name}/sub/hello.txt")).await?.expect("path should resolve");
    println!("get_by_path -> {} ({} bytes)", found.path(), found.size());
    assert_eq!(found.read().await?, b"hi from FileWrapper");
    assert!(home.get_by_path(&format!("{dir_name}/nope")).await?.is_none());

    // rename + remove -----------------------------------------------------------
    sub.rename_child("hello.txt", "renamed.txt").await?;
    assert!(sub.child("renamed.txt").await?.is_some());
    assert!(sub.child("hello.txt").await?.is_none());
    println!("renamed hello.txt -> renamed.txt");

    // copy_child + move_child ---------------------------------------------------
    let dest = home.mkdir(&format!("dest{n}")).await?;
    dir.move_child("sub", &dest, true).await?;
    assert!(dir.child("sub").await?.is_none(), "sub should have moved out");
    assert!(dest.child("sub").await?.is_some(), "sub should be in dest");
    println!("moved sub/ into dest{n}/");
    let moved_file = dest.get_by_path("sub/renamed.txt").await?.expect("file survives move");
    assert_eq!(moved_file.read().await?, b"hi from FileWrapper");

    dest.remove_child("sub").await?;
    assert!(dest.child("sub").await?.is_none());
    println!("removed sub/");

    println!("\nFileWrapper OK: home/mkdir/upload/read/children/get_by_path/rename/move/remove.");
    Ok(())
}
