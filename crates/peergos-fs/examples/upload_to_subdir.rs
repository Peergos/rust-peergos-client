//! Write a file into a *subdirectory* of a writable directory link. Subdirs hold
//! no writer link of their own, so we recover the entry point's signer and pass
//! it down.
//!
//!   cargo run -p peergos-fs --example upload_to_subdir -- <base> <link> <subdir> <name> <contents>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let subdir = args.get(3).cloned().unwrap_or_else(|| "rust-subdir".to_string());
    let name = args.get(4).cloned().unwrap_or_else(|| "nested.txt".to_string());
    let contents = args.get(5).cloned().unwrap_or_else(|| "Hello from a nested file!".to_string());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    // Follow the link node to the real entry-point directory.
    let mut entry_cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_n, props) = peergos_fs::retrieve_file_metadata(&entry_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&entry_cap, store.clone(), &mutable).await?;
        entry_cap = children.into_iter().next().ok_or("link node has no target")?.cap;
    }

    // The entry point holds the writer signing key; recover it for the subdir.
    let signer = peergos_fs::recover_signer(&entry_cap, store.clone(), &mutable).await?;

    // Find the target subdirectory among the entry point's children.
    let subdir_cap = peergos_fs::list_directory(&entry_cap, store.clone(), &mutable)
        .await?
        .into_iter()
        .find(|e| e.name == subdir && e.is_dir == Some(true))
        .ok_or_else(|| format!("subdirectory {subdir:?} not found"))?
        .cap;
    println!("Found subdir {subdir:?} (writable: {})", subdir_cap.is_writable());

    println!("\nWriting {name:?} into {subdir:?} using the entry-point signer ...");
    let file_cap = peergos_fs::upload_file(
        &subdir_cap,
        &name,
        contents.as_bytes(),
        None,
        Some(signer),
        store.clone(),
        &mutable,
    )
    .await?;

    println!("\n{subdir:?} now contains:");
    for e in peergos_fs::list_directory(&subdir_cap, store.clone(), &mutable).await? {
        println!("  {} {}", if e.is_dir == Some(true) { "[dir ]" } else { "[file]" }, e.name);
    }

    println!("\nReading the nested file back ...");
    let (p, data) = peergos_fs::read_file(&file_cap, store, &mutable).await?;
    println!("  {} = {:?}", p.name, String::from_utf8_lossy(&data));
    Ok(())
}
