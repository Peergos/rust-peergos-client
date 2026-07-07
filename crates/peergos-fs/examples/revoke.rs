//! Revoke read access and prove the security property:
//!  - alice shares a directory with bob AND carol (both can read),
//!  - alice revokes bob's read access (rotates keys),
//!  - bob's previously-obtained capability no longer works,
//!  - carol still reads it (the new keys were reshared to her).
//!
//!   cargo run -p peergos-fs --example revoke -- http://localhost:7777/

use peergos_core::mutable::HttpMutablePointers;
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;

type Store = Arc<dyn ContentAddressedStorage>;

/// Establish a two-way friendship between `a` and `b` (idempotent-ish).
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

/// Read `docs/secret.txt` via `reader`'s friendship with alice; returns the text
/// if any shared capability still works.
async fn read_shared_secret(
    reader_u: &str,
    reader_p: &str,
    alice_u: &str,
    poster: &ReqwestPoster,
    store: Store,
    mutable: &HttpMutablePointers,
) -> Option<String> {
    let reader = peergos_fs::login(reader_u, reader_p, poster, store.clone(), mutable, None).await.ok()?;
    let alice_entry = peergos_fs::get_friends(&reader, store.clone(), mutable).await.ok()?
        .into_iter().find(|e| e.owner_name == alice_u)?;
    let caps = peergos_fs::read_shared_capabilities(&alice_entry.pointer, store.clone(), mutable).await.ok()?;
    for docs in caps {
        // Each shared cap is the "docs" directory; try to read secret.txt inside.
        if let Ok(entries) = peergos_fs::list_directory(&docs, store.clone(), mutable).await {
            if let Some(f) = entries.into_iter().find(|e| e.name == "secret.txt") {
                if let Ok((_p, data)) = peergos_fs::read_file(&f.cap, store.clone(), mutable).await {
                    return Some(String::from_utf8_lossy(&data).to_string());
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = ReqwestPoster::new(&base, false)?;
    let store: Store = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable = HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?));
    let (au, ap) = ("w2", "w2pass");
    let (bu, bp) = ("bob", "bobpass");
    let (cu, cp) = ("carol", "carolpass");
    for (u, p) in [(au, ap), (bu, bp), (cu, cp)] {
        match peergos_fs::signup(u, p, None, &poster, store.as_ref()).await {
            Ok(()) => println!("signed up {u:?}"),
            Err(e) if e.to_string().contains("already exists") => {}
            Err(e) => return Err(e.into()),
        }
    }
    befriend((au, ap), (bu, bp), &poster, store.clone(), &mutable).await?;
    befriend((au, ap), (cu, cp), &poster, store.clone(), &mutable).await?;

    // Alice creates docs/secret.txt and shares docs with bob and carol.
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    let docs = peergos_fs::create_directory(&home, "docs", Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::upload_file(&docs, "secret.txt", b"top secret", None, Some(signer), None, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "docs", &docs, bu, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "docs", &docs, cu, store.clone(), &mutable).await?;
    println!("{au:?} shared docs/ with {bu:?} and {cu:?}");
    println!("  currently shared with (read): {:?}",
        peergos_fs::get_shared_with(&alice, "docs", peergos_fs::Access::Read, store.clone(), &mutable).await?);

    // Both can read it now.
    let bob_before = read_shared_secret(bu, bp, au, &poster, store.clone(), &mutable).await;
    let carol_before = read_shared_secret(cu, cp, au, &poster, store.clone(), &mutable).await;
    println!("\nBefore revocation: {bu}={bob_before:?}  {cu}={carol_before:?}");
    assert_eq!(bob_before.as_deref(), Some("top secret"));
    assert_eq!(carol_before.as_deref(), Some("top secret"));

    // Alice revokes bob's read access (rotates keys, reshares to carol).
    println!("\n{au:?} revoking {bu:?}'s read access to docs ...");
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    peergos_fs::unshare_read_access(&alice, "", &home, "docs", &[bu.to_string()], store.clone(), &mutable).await?;
    println!("  now shared with (read): {:?}",
        peergos_fs::get_shared_with(&alice, "docs", peergos_fs::Access::Read, store.clone(), &mutable).await?);

    // Bob can no longer read it; carol still can.
    let bob_after = read_shared_secret(bu, bp, au, &poster, store.clone(), &mutable).await;
    let carol_after = read_shared_secret(cu, cp, au, &poster, store.clone(), &mutable).await;
    println!("\nAfter revocation:  {bu}={bob_after:?}  {cu}={carol_after:?}");
    assert_eq!(bob_after, None, "REVOCATION FAILED: bob can still read the file!");
    assert_eq!(carol_after.as_deref(), Some("top secret"), "carol lost access she should still have");
    println!("\nRevocation OK: {bu} lost access, {cu} retained it.");
    Ok(())
}
