//! Upload a small text file into a writable directory secret link, then verify
//! by listing the directory and reading the new file back.
//!
//!   cargo run -p peergos-fs --example upload -- <base> <writable-dir-link> <name> <contents>

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let name = args.get(3).cloned().unwrap_or_else(|| "from-rust.txt".to_string());
    let contents = args.get(4).cloned().unwrap_or_else(|| "G'day from Rust!".to_string());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    let mut dir_cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    println!("Directory cap writable: {}", dir_cap.is_writable());

    // A writable share often resolves to a "link" node whose single child is the
    // real writable directory (which holds the writer signing key); follow it.
    let (_node, props) =
        peergos_fs::retrieve_file_metadata(&dir_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await?;
        dir_cap = children
            .into_iter()
            .next()
            .ok_or("link node has no target")?
            .cap;
        println!("Followed link to real directory (writable: {})", dir_cap.is_writable());
    }

    println!("Uploading {name:?} ({} bytes) ...", contents.len());
    let file_cap = peergos_fs::upload_file(
        &dir_cap,
        &name,
        contents.as_bytes(),
        None,
        None,
        None,
        store.clone(),
        &mutable,
    )
    .await?;
    println!("Uploaded. New file map-key: {}", hex(&file_cap.map_key));

    println!("\nRe-listing directory ...");
    let entries = peergos_fs::list_directory(&dir_cap, store.clone(), &mutable).await?;
    for e in &entries {
        println!("  {} {}", if e.is_dir == Some(true) { "[dir ]" } else { "[file]" }, e.name);
    }

    println!("\nReading the uploaded file back ...");
    let (props, data) = peergos_fs::read_file(&file_cap, store, &mutable).await?;
    println!("  {} = {:?}", props.name, String::from_utf8_lossy(&data));
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
