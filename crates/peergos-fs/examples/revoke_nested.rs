//! Write-revocation of a NESTED directory (not a direct child of home): proves the
//! entry-point-signer threading works all the way through write-share + revocation.
//!  - alice creates /parent/sub (sub is two levels below home),
//!  - alice write-shares parent/sub with bob AND carol; both write,
//!  - alice revokes bob's write access to parent/sub,
//!  - bob can no longer write, carol still can.
//!
//! Uses fresh per-run usernames so the append-only sharing.w has no stale caps.
//!
//!   cargo run -p peergos-fs --example revoke_nested -- http://localhost:7777/

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

/// Try to write `filename` into alice's write-shared directory named `target`
/// (the unique nested `sub` dir), via `writer`. Only that dir's caps are tried, so
/// other examples' live write-shares in the shared append-only `sharing.w` don't
/// interfere.
#[allow(clippy::too_many_arguments)]
async fn try_write(
    wu: &str,
    wp: &str,
    au: &str,
    target: &str,
    filename: &str,
    content: &[u8],
    poster: &ReqwestPoster,
    store: Store,
    mutable: &HttpMutablePointers,
) -> Result<(), Box<dyn std::error::Error>> {
    let writer = peergos_fs::login(wu, wp, poster, store.clone(), mutable, None).await?;
    let alice_entry = peergos_fs::get_friends(&writer, store.clone(), mutable).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("not friends")?;
    let caps = peergos_fs::read_write_shared_capabilities(&alice_entry.pointer, store.clone(), mutable).await?;
    let mut last_err: Box<dyn std::error::Error> = format!("no writable cap for {target}").into();
    for cap in caps.into_iter().rev() {
        // Only consider caps for our specific target directory.
        match peergos_fs::retrieve_file_metadata(&cap, store.clone(), mutable).await {
            Ok((_n, props)) if props.name == target => {}
            _ => continue,
        }
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

    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (au, ap) = (format!("alice{n}"), "apass".to_string());
    let (bu, bp) = (format!("bob{n}"), "bpass".to_string());
    let (cu, cp) = (format!("carol{n}"), "cpass".to_string());
    let (au, bu, cu) = (au.as_str(), bu.as_str(), cu.as_str());
    let (ap, bp, cp) = (ap.as_str(), bp.as_str(), cp.as_str());
    for (u, p) in [(au, ap), (bu, bp), (cu, cp)] {
        peergos_fs::signup(u, p, None, &poster, store.as_ref()).await?;
    }
    befriend((au, ap), (bu, bp), &poster, store.clone(), &mutable).await?;
    befriend((au, ap), (cu, cp), &poster, store.clone(), &mutable).await?;

    // Alice creates a NESTED dir /parent/sub and write-shares sub with bob + carol.
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    let parent = peergos_fs::create_directory(&home, "parent", Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::create_directory(&parent, "sub", Some(signer.clone()), None, store.clone(), &mutable).await?;
    peergos_fs::share_write_access(&alice, "parent", &parent, "sub", bu, store.clone(), &mutable).await?;
    peergos_fs::share_write_access(&alice, "parent", &parent, "sub", cu, store.clone(), &mutable).await?;
    println!("{au:?} write-shared parent/sub with {bu:?} and {cu:?}");
    println!("  writers: {:?}", peergos_fs::get_shared_with(&alice, "parent/sub", peergos_fs::Access::Write, store.clone(), &mutable).await?);

    let bob_ok = try_write(bu, bp, au, "sub", "bob.txt", b"by bob", &poster, store.clone(), &mutable).await;
    let carol_ok = try_write(cu, cp, au, "sub", "carol.txt", b"by carol", &poster, store.clone(), &mutable).await;
    println!("\nBefore revocation: bob-write={:?}  carol-write={:?}", bob_ok.is_ok(), carol_ok.is_ok());
    assert!(bob_ok.is_ok() && carol_ok.is_ok(), "both should be able to write initially");

    // Alice revokes bob's write access to the NESTED dir.
    println!("\n{au:?} revoking {bu:?}'s WRITE access to parent/sub ...");
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let parent = peergos_fs::list_directory(&home, store.clone(), &mutable).await?
        .into_iter().find(|e| e.name == "parent").ok_or("no parent")?.cap;
    peergos_fs::unshare_write_access(&alice, "parent", &parent, "sub", &[bu.to_string()], store.clone(), &mutable).await?;
    println!("  writers now: {:?}", peergos_fs::get_shared_with(&alice, "parent/sub", peergos_fs::Access::Write, store.clone(), &mutable).await?);

    let bob_after = try_write(bu, bp, au, "sub", "bob2.txt", b"by bob again", &poster, store.clone(), &mutable).await;
    let carol_after = try_write(cu, cp, au, "sub", "carol2.txt", b"by carol again", &poster, store.clone(), &mutable).await;
    println!("\nAfter revocation:  bob-write={:?}  carol-write={:?}", bob_after.is_ok(), carol_after.is_ok());
    assert!(bob_after.is_err(), "REVOCATION FAILED: bob can still write to the nested dir!");
    assert!(carol_after.is_ok(), "carol lost write access she should still have");
    println!("\nNested write revocation OK: {bu} can no longer write parent/sub, {cu} still can.");
    Ok(())
}
