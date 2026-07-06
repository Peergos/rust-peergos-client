//! Create a subdirectory inside a writable directory secret link, then verify.
//!
//!   cargo run -p peergos-fs --example mkdir -- <base> <writable-dir-link> <dirname>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let dirname = args.get(3).cloned().unwrap_or_else(|| "rust-subdir".to_string());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    // Follow the link node to the real writable directory.
    let mut dir_cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_n, props) = peergos_fs::retrieve_file_metadata(&dir_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await?;
        dir_cap = children.into_iter().next().ok_or("link node has no target")?.cap;
    }

    println!("Creating subdirectory {dirname:?} ...");
    let sub_cap = peergos_fs::create_directory(&dir_cap, &dirname, None, store.clone(), &mutable).await?;
    println!("Created (writable: {}).", sub_cap.is_writable());

    println!("\nParent directory now contains:");
    for e in peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await? {
        println!("  {} {}", if e.is_dir == Some(true) { "[dir ]" } else { "[file]" }, e.name);
    }

    println!("\nListing the new subdirectory (should be empty):");
    let sub_entries = peergos_fs::list_directory(&sub_cap, store, &mutable).await?;
    println!("  {} entries", sub_entries.len());
    Ok(())
}
