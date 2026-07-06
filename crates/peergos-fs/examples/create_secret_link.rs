//! Generate a secret link to a file, then resolve it back through the server and
//! read the file — proving the create side round-trips with the read side. Also
//! generates a link that requires an extra user password.
//!
//!   cargo run -p peergos-fs --example create_secret_link -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::{retrieve_secret_link_capability, read_file, UserContext};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    let ctx = match UserContext::sign_up("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await {
        Ok(c) => c,
        Err(_) => UserContext::sign_in("w2", "w2pass", None, poster.clone(), store.clone(), mutable.clone()).await?,
    };
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let dir = ctx.get_home().await?.mkdir(&format!("link{n}")).await?;
    let content = b"shared via a secret link".to_vec();
    dir.upload("note.txt", &content).await?;
    let path = format!("link{n}/note.txt");

    // --- a plain read-only link -----------------------------------------------
    let link = ctx.create_secret_link(&path, false, "", None, None).await?;
    println!("generated link: {link}");

    // Resolve it back (fresh store, no login) and read the file.
    let cap = retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_props, got) = read_file(&cap, store.clone(), mutable.as_ref()).await?;
    assert_eq!(got, content, "content read via the secret link must match");
    println!("resolved + read back {} bytes: OK", got.len());

    // A wrong password / no password must not silently succeed for a protected link.
    // --- a link that requires a user password ---------------------------------
    let protected = ctx.create_secret_link(&path, false, "hunter2", None, None).await?;
    println!("generated password-protected link: {protected}");
    assert!(
        retrieve_secret_link_capability(&protected, store.as_ref(), None).await.is_err(),
        "a protected link must fail without the user password"
    );
    let cap2 = retrieve_secret_link_capability(&protected, store.as_ref(), Some("hunter2")).await?;
    let (_p, got2) = read_file(&cap2, store.clone(), mutable.as_ref()).await?;
    assert_eq!(got2, content);
    println!("password-protected link resolves only with the password: OK");

    // --- a WRITABLE link to a directory ---------------------------------------
    // The target is relocated into its own writing space first; the resolved cap
    // is writable and its writer differs from the parent's.
    ctx.get_home().await?.get_by_path(&format!("link{n}")).await?.unwrap().mkdir("sub").await?;
    let dir_path = format!("link{n}/sub");
    let parent_writer = ctx.get_by_path(&format!("link{n}")).await?.unwrap().capability().writer.clone();
    let wlink = ctx.create_secret_link(&dir_path, true, "", None, None).await?;
    println!("generated writable link: {wlink}");
    let wcap = retrieve_secret_link_capability(&wlink, store.as_ref(), None).await?;
    assert!(wcap.is_writable(), "writable link must resolve to a writable capability");
    assert_ne!(wcap.writer, parent_writer, "the target must be in a different writing space to its parent");
    println!("writable link resolves to a writable cap in its own writing space (writer != parent): OK");

    // --- a WRITABLE link to a FILE --------------------------------------------
    // The file is rotated into its own writer; content + normal-path access survive.
    let file_parent_writer = ctx.get_by_path(&format!("link{n}")).await?.unwrap().capability().writer.clone();
    let flink = ctx.create_secret_link(&path, true, "", None, None).await?;
    println!("generated writable FILE link: {flink}");
    let fcap = retrieve_secret_link_capability(&flink, store.as_ref(), None).await?;
    assert!(fcap.is_writable(), "writable file link must resolve to a writable capability");
    assert_ne!(fcap.writer, file_parent_writer, "the file must be in its own writing space");
    let (_p, via_link) = read_file(&fcap, store.clone(), mutable.as_ref()).await?;
    assert_eq!(via_link, content, "content read via the writable file link must match");
    // The file is still reachable + intact at its normal path after the rotation.
    let refetched = ctx.get_by_path(&path).await?.unwrap();
    assert_eq!(refetched.read().await?, content, "file still readable at its path after rotation");
    assert!(refetched.capability().is_writable(), "owner still has write access");
    println!("writable FILE link OK: file rotated to its own writer, content + path access preserved");

    // The read-only link `link` to note.txt was minted BEFORE the writable-file
    // rotation above. Java re-mints existing links on rotation, so the same link
    // string must still resolve — now to the rotated cap.
    let relinked = retrieve_secret_link_capability(&link, store.as_ref(), None).await?;
    let (_p, still) = read_file(&relinked, store.clone(), mutable.as_ref()).await?;
    assert_eq!(still, content, "a pre-existing link must survive the rotation (re-minted to the new cap)");
    assert_eq!(relinked.writer, fcap.writer, "the re-minted link points at the rotated writer");
    println!("pre-existing read-only link survived the rotation (re-minted to the new cap): OK");

    println!("\nCreate-secret-link OK: read-only, password, writable (dir + file), and rotation re-minting existing links all work.");
    Ok(())
}
