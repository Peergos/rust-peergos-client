//! Log in, then exercise file/directory deletion: upload a file and delete it,
//! and create a non-empty subdirectory and delete it recursively.
//!
//!   cargo run -p peergos-fs --example delete -- <base> <username> <password>
//!   cargo run -p peergos-fs --example delete -- http://localhost:7777/ w2 w2pass

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let base = args.get(1).cloned().unwrap_or_else(|| "http://localhost:7777/".to_string());
    let username = args.get(2).cloned().unwrap_or_else(|| "w2".to_string());
    let password = args.get(3).cloned().unwrap_or_else(|| "w2pass".to_string());

    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable = HttpMutablePointers::new(poster.clone());

    let user = peergos_fs::login(&username, &password, poster.as_ref(), store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home entry point")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;

    async fn names(
        label: &str,
        home: &peergos_fs::AbsoluteCapability,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: &HttpMutablePointers,
    ) -> Vec<String> {
        let entries = peergos_fs::list_directory(home, store, mutable).await.unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        println!("  {label}: {names:?}");
        names
    }

    // --- File deletion --------------------------------------------------------
    println!("\n== File deletion ==");
    peergos_fs::upload_file(&home, "todelete.txt", b"delete me", None, Some(signer.clone()), store.clone(), &mutable).await?;
    let before = names("after upload", &home, store.clone(), &mutable).await;
    assert!(before.contains(&"todelete.txt".to_string()), "file should be present after upload");

    peergos_fs::delete_child(&home, "todelete.txt", Some(signer.clone()), store.clone(), &mutable).await?;
    let after = names("after delete", &home, store.clone(), &mutable).await;
    assert!(!after.contains(&"todelete.txt".to_string()), "file should be gone after delete");
    println!("  file deletion OK");

    // --- Recursive directory deletion ----------------------------------------
    println!("\n== Directory deletion ==");
    let subdir = peergos_fs::create_directory(&home, "dir-to-delete", Some(signer.clone()), store.clone(), &mutable).await?;
    // Put a file inside the subdir (subdirs share the entry point's signer).
    peergos_fs::upload_file(&subdir, "inner.txt", b"inside", None, Some(signer.clone()), store.clone(), &mutable).await?;
    let before = names("after mkdir+upload", &home, store.clone(), &mutable).await;
    assert!(before.contains(&"dir-to-delete".to_string()), "subdir should be present");

    peergos_fs::delete_child(&home, "dir-to-delete", Some(signer.clone()), store.clone(), &mutable).await?;
    let after = names("after delete", &home, store.clone(), &mutable).await;
    assert!(!after.contains(&"dir-to-delete".to_string()), "subdir should be gone after delete");
    println!("  recursive directory deletion OK");

    println!("\nAll deletion checks passed.");
    Ok(())
}
