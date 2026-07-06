//! Extra move/copy behaviours: copy_to (unique naming), the descendant guard,
//! keep_access=false (force slow path + drop shares on a same-writer move), and
//! the PATH-AWARE shared-with cache rewrite in move_file (the record follows the
//! file to its new directory path).
//!
//!   cargo run -p peergos-fs --example move_advanced -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type Store = Arc<dyn ContentAddressedStorage>;

async fn names(dir: &peergos_fs::AbsoluteCapability, store: Store, mutable: &HttpMutablePointers) -> Vec<String> {
    peergos_fs::list_directory(dir, store, mutable).await.unwrap().into_iter().map(|e| e.name).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = ReqwestPoster::new(&base, false)?;
    let store: Store = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable = HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?));
    let _ = peergos_fs::signup("w2", "w2pass", None, &poster, store.as_ref()).await;
    let user = peergos_fs::login("w2", "w2pass", &poster, store.clone(), &mutable, None).await?;
    let home = user.home().ok_or("no home")?.clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    // Unique per-run suffix so the demo is idempotent against a non-fresh server.
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // --- copy_to with unique naming ------------------------------------------
    println!("== copy_to (unique naming) ==");
    let c = format!("c{n}.txt");
    peergos_fs::upload_file(&home, &c, b"copy me", None, Some(s.clone()), store.clone(), &mutable).await?;
    let copy = peergos_fs::copy_to(&home, &c, &home, Some(s.clone()), store.clone(), &mutable).await?;
    let (props, data) = peergos_fs::read_file(&copy, store.clone(), &mutable).await?;
    println!("  {c:?} copied to {:?}: {:?}", props.name, String::from_utf8_lossy(&data));
    assert_eq!(props.name, format!("c{n} (copy).txt"));
    assert_eq!(data, b"copy me");

    // --- descendant guard ----------------------------------------------------
    println!("\n== descendant guard ==");
    let adir = format!("a{n}");
    let a = peergos_fs::create_directory(&home, &adir, Some(s.clone()), store.clone(), &mutable).await?;
    let b = peergos_fs::create_directory(&a, "b", Some(s.clone()), store.clone(), &mutable).await?;
    let guard = peergos_fs::move_to(&home, &adir, &b, true, Some(s.clone()), store.clone(), &mutable).await;
    println!("  move {adir}/ into {adir}/b rejected: {:?}", guard.as_ref().err().map(|e| e.to_string()));
    assert!(guard.is_err(), "should refuse to move a folder into its own descendant");

    // --- keep_access = false forces the slow path (drops shares) --------------
    println!("\n== keep_access=false (force slow path) ==");
    let kf = format!("k{n}.txt");
    let kd = format!("kdest{n}");
    let k = peergos_fs::upload_file(&home, &kf, b"drop shares", None, Some(s.clone()), store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&user, &kf, &k, "bob", store.clone(), &mutable).await?;
    let kdest = peergos_fs::create_directory(&home, &kd, Some(s.clone()), store.clone(), &mutable).await?;
    println!("  before: shared-with({kf})={:?}", peergos_fs::get_shared_with(&user, &kf, peergos_fs::Access::Read, store.clone(), &mutable).await?);
    let new_k = peergos_fs::move_file(&user, &home, "", &kf, &kdest, &kd, false, Some(s.clone()), store.clone(), &mutable).await?;
    let after = peergos_fs::get_shared_with(&user, &format!("{kd}/{kf}"), peergos_fs::Access::Read, store.clone(), &mutable).await?;
    println!("  after move (keep_access=false): cap changed? {}  shared-with({kd}/{kf})={after:?}", new_k.map_key != k.map_key);
    assert!(new_k.map_key != k.map_key, "keep_access=false must rotate keys (new cap)");
    assert!(after.is_empty(), "shares should be dropped on a keep_access=false move");
    assert!(names(&kdest, store.clone(), &mutable).await.contains(&kf));

    // --- move_file cache rewrite: the share record follows the file's path ---
    println!("\n== path-aware cache rewrite (fast move keeps shares at the new path) ==");
    let mf = format!("m{n}.txt");
    let md = format!("mdest{n}");
    let m = peergos_fs::upload_file(&home, &mf, b"keep shares", None, Some(s.clone()), store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&user, &mf, &m, "bob", store.clone(), &mutable).await?;
    let mdest = peergos_fs::create_directory(&home, &md, Some(s.clone()), store.clone(), &mutable).await?;
    let new_m = peergos_fs::move_file(&user, &home, "", &mf, &mdest, &md, true, Some(s.clone()), store.clone(), &mutable).await?;
    let at_old = peergos_fs::get_shared_with(&user, &mf, peergos_fs::Access::Read, store.clone(), &mutable).await?;
    let at_new = peergos_fs::get_shared_with(&user, &format!("{md}/{mf}"), peergos_fs::Access::Read, store.clone(), &mutable).await?;
    println!("  cap preserved? {}  shared-with({mf})={at_old:?}  shared-with({md}/{mf})={at_new:?}", new_m.map_key == m.map_key);
    assert_eq!(new_m.map_key, m.map_key);
    assert!(at_old.is_empty(), "old path should no longer hold the share record");
    assert_eq!(at_new, vec!["bob".to_string()], "share record should follow the file to its new path");

    println!("\nAdvanced move/copy OK: copy_to naming, descendant guard, keep_access, path-aware cache rewrite.");
    Ok(())
}
