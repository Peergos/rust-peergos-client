//! Log in, then exercise rename: rename a file (content must survive) and a
//! directory. Cleans up afterwards.
//!
//!   cargo run -p peergos-fs --example rename -- <base> <username> <password>
//!   cargo run -p peergos-fs --example rename -- http://localhost:7777/ w2 w2pass

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
        let ns: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        println!("  {label}: {ns:?}");
        ns
    }

    // --- File rename (content must survive) -----------------------------------
    println!("\n== File rename ==");
    peergos_fs::upload_file(&home, "before.txt", b"rename me", None, Some(signer.clone()), store.clone(), &mutable).await?;
    names("after upload", &home, store.clone(), &mutable).await;

    peergos_fs::rename_child(&home, "before.txt", "after.txt", Some(signer.clone()), store.clone(), &mutable).await?;
    let after = names("after rename", &home, store.clone(), &mutable).await;
    assert!(after.contains(&"after.txt".to_string()) && !after.contains(&"before.txt".to_string()), "rename did not take effect");

    // Read the renamed file back and confirm the content is intact.
    let renamed = peergos_fs::list_directory(&home, store.clone(), &mutable).await?
        .into_iter().find(|e| e.name == "after.txt").ok_or("after.txt not found")?;
    let (_p, data) = peergos_fs::read_file(&renamed.cap, store.clone(), &mutable).await?;
    println!("  after.txt content: {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"rename me", "content changed by rename!");
    println!("  file rename OK");

    // --- Directory rename -----------------------------------------------------
    println!("\n== Directory rename ==");
    peergos_fs::create_directory(&home, "olddir", Some(signer.clone()), store.clone(), &mutable).await?;
    names("after mkdir", &home, store.clone(), &mutable).await;
    peergos_fs::rename_child(&home, "olddir", "newdir", Some(signer.clone()), store.clone(), &mutable).await?;
    let after = names("after rename", &home, store.clone(), &mutable).await;
    assert!(after.contains(&"newdir".to_string()) && !after.contains(&"olddir".to_string()), "dir rename did not take effect");
    println!("  directory rename OK");

    // --- Cleanup --------------------------------------------------------------
    peergos_fs::delete_child(&home, "after.txt", Some(signer.clone()), store.clone(), &mutable).await?;
    peergos_fs::delete_child(&home, "newdir", Some(signer.clone()), store.clone(), &mutable).await?;
    names("after cleanup", &home, store.clone(), &mutable).await;

    println!("\nAll rename checks passed.");
    Ok(())
}
