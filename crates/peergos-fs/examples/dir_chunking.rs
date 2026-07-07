//! Verify directory chunking: with a low per-blob limit, upload several files
//! into a fresh subdirectory (forcing it to split across chunks) and confirm the
//! listing returns every file exactly once.
//!
//!   PEERGOS_MAX_CHILD_LINKS=2 cargo run -p peergos-fs --example dir_chunking -- <base> <link> [n]

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let link = args.get(2).cloned().expect("need a writable dir link");
    let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    let limit = std::env::var("PEERGOS_MAX_CHILD_LINKS").unwrap_or_else(|_| "500".into());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster);

    let mut entry_cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_n, props) = peergos_fs::retrieve_file_metadata(&entry_cap, store.clone(), &mutable).await?;
    if props.is_link {
        let children = peergos_fs::list_directory(&entry_cap, store.clone(), &mutable).await?;
        entry_cap = children.into_iter().next().ok_or("link node has no target")?.cap;
    }
    let signer = peergos_fs::recover_signer(&entry_cap, store.clone(), &mutable).await?;

    // Fresh subdirectory (unique name each run).
    let dirname = format!("chunk-test-{}", std::process::id());
    println!("Creating subdir {dirname:?} (max child links per blob = {limit}) ...");
    let subdir = peergos_fs::create_directory(&entry_cap, &dirname, Some(signer.clone()), None, store.clone(), &mutable).await?;

    for i in 0..n {
        let name = format!("file{i:02}.txt");
        peergos_fs::upload_file(
            &subdir,
            &name,
            format!("contents of {name}").as_bytes(),
            None,
            Some(signer.clone()),
            None,
            store.clone(),
            &mutable,
        )
        .await?;
        println!("  uploaded {name}");
    }

    println!("\nListing {dirname:?} (should span multiple chunks) ...");
    let entries = peergos_fs::list_directory(&subdir, store.clone(), &mutable).await?;
    let mut names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    names.sort();
    println!("  {} entries: {:?}", names.len(), names);

    let unique: std::collections::HashSet<_> = names.iter().collect();
    println!("  unique: {}  (expected {n} files, no duplicates)", unique.len());
    assert_eq!(names.len(), n, "wrong number of entries");
    assert_eq!(unique.len(), n, "duplicate entries found!");

    // Read one back through its listed cap to confirm chunks are consistent.
    let last = entries.iter().find(|e| e.name == format!("file{:02}.txt", n - 1)).unwrap();
    let (_p, data) = peergos_fs::read_file(&last.cap, store, &mutable).await?;
    println!("  read last file: {:?}", String::from_utf8_lossy(&data));
    println!("\nOK — {n} files across chunks of ≤{limit}, all present and unique.");
    Ok(())
}
