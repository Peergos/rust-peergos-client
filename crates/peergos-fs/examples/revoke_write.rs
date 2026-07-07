//! Revoke WRITE access and prove the security property:
//!  - alice write-shares a directory with bob AND carol (both can write),
//!  - alice revokes bob's write access (rotates to a new writer, deauthorises the
//!    old one),
//!  - bob can no longer write, carol still can.
//!
//!   cargo run -p peergos-fs --example revoke_write -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type Store = Arc<dyn ContentAddressedStorage>;

async fn befriend(
    a: (&str, &str),
    b: (&str, &str),
    poster: &ReqwestPoster,
    store: Store,
    mutable: &HttpMutablePointers,
) -> Result<(), Box<dyn std::error::Error>> {
    let alice = peergos_fs::login(a.0, a.1, poster, store.clone(), mutable, None).await?;
    peergos_fs::send_follow_request(&alice, b.0, true, poster, store.clone(), mutable).await?;
    let bob = peergos_fs::login(b.0, b.1, poster, store.clone(), mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster).await? {
        if r.sender() == Some(a.0) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster, store.clone(), mutable).await?;
        }
    }
    let alice = peergos_fs::login(a.0, a.1, poster, store.clone(), mutable, None).await?;
    for r in peergos_fs::get_follow_requests(&alice, poster).await? {
        if r.sender() == Some(b.0) {
            peergos_fs::process_follow_reply(&alice, &r, poster, store.clone(), mutable).await?;
        }
    }
    Ok(())
}

/// Try to write `filename` into alice's write-shared "project" dir via `writer`'s
/// friendship. Returns Ok(()) if the write succeeded.
async fn try_write(
    writer_u: &str,
    writer_p: &str,
    alice_u: &str,
    filename: &str,
    content: &[u8],
    poster: &ReqwestPoster,
    store: Store,
    mutable: &HttpMutablePointers,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer = peergos_fs::login(writer_u, writer_p, poster, store.clone(), mutable, None).await?;
    let alice_entry = peergos_fs::get_friends(&writer, store.clone(), mutable).await?
        .into_iter().find(|e| e.owner_name == alice_u).ok_or("not friends")?;
    let caps = peergos_fs::read_write_shared_capabilities(&alice_entry.pointer, store.clone(), mutable).await?;
    // Use the last writable cap that actually resolves to a live directory.
    let mut last_err: Box<dyn std::error::Error> = "no writable cap".into();
    for cap in caps.into_iter().rev() {
        let signer = match peergos_fs::recover_signer(&cap, store.clone(), mutable).await {
            Ok(s) => s,
            Err(e) => { last_err = e.into(); continue; }
        };
        match peergos_fs::upload_file(&cap, filename, content, None, Some(signer), None, store.clone(), mutable).await {
            Ok(_) => return Ok(()),
            Err(e) => last_err = e.into(),
        }
    }
    Err(last_err)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = ReqwestPoster::new(&base, false)?;
    let store: Store = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable = HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?));
    // Unique per-run usernames: this example asserts a security property that
    // depends on a clean slate. Reusing fixed names against a persistent server
    // accumulates sharing state across runs (directories are not de-duplicated by
    // name and shared-cap files only ever append), which defeats the assertion.
    let s = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (au_s, bu_s, cu_s) = (format!("alice{s}"), format!("bob{s}"), format!("carol{s}"));
    let (au, ap) = (au_s.as_str(), "w2pass");
    let (bu, bp) = (bu_s.as_str(), "bobpass");
    let (cu, cp) = (cu_s.as_str(), "carolpass");
    for (u, p) in [(au, ap), (bu, bp), (cu, cp)] {
        match peergos_fs::signup(u, p, None, &poster, store.as_ref()).await {
            Ok(()) | Err(_) => {}
        }
    }
    befriend((au, ap), (bu, bp), &poster, store.clone(), &mutable).await?;
    befriend((au, ap), (cu, cp), &poster, store.clone(), &mutable).await?;

    // Alice creates "project" and write-shares it with bob and carol.
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    peergos_fs::create_directory(&home, "project", Some(signer), None, store.clone(), &mutable).await?;
    peergos_fs::share_write_access(&alice, "", &home, "project", bu, store.clone(), &mutable).await?;
    peergos_fs::share_write_access(&alice, "", &home, "project", cu, store.clone(), &mutable).await?;
    println!("{au:?} write-shared project/ with {bu:?} and {cu:?}");
    println!("  writers: {:?}", peergos_fs::get_shared_with(&alice, "project", peergos_fs::Access::Write, store.clone(), &mutable).await?);

    // Both can write now.
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bob_ok = try_write(bu, bp, au, &format!("bob-{n}.txt"), b"by bob", &poster, store.clone(), &mutable).await;
    let carol_ok = try_write(cu, cp, au, &format!("carol-{n}.txt"), b"by carol", &poster, store.clone(), &mutable).await;
    println!("\nBefore revocation: bob-write={:?}  carol-write={:?}", bob_ok.is_ok(), carol_ok.is_ok());
    assert!(bob_ok.is_ok() && carol_ok.is_ok(), "both should be able to write initially");

    // Alice revokes bob's write access.
    println!("\n{au:?} revoking {bu:?}'s WRITE access to project ...");
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    peergos_fs::unshare_write_access(&alice, "", &home, "project", &[bu.to_string()], store.clone(), &mutable).await?;
    println!("  writers now: {:?}", peergos_fs::get_shared_with(&alice, "project", peergos_fs::Access::Write, store.clone(), &mutable).await?);

    // Bob can no longer write; carol still can.
    let bob_after = try_write(bu, bp, au, &format!("bob2-{n}.txt"), b"by bob again", &poster, store.clone(), &mutable).await;
    let carol_after = try_write(cu, cp, au, &format!("carol2-{n}.txt"), b"by carol again", &poster, store.clone(), &mutable).await;
    println!("\nAfter revocation:  bob-write={:?}  carol-write={:?}", bob_after.is_ok(), carol_after.is_ok());
    assert!(bob_after.is_err(), "REVOCATION FAILED: bob can still write!");
    assert!(carol_after.is_ok(), "carol lost write access she should still have");
    println!("\nWrite revocation OK: {bu} can no longer write, {cu} still can.");
    Ok(())
}
