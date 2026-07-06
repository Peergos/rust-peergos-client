//! IncomingCapCache, advanced: the three refinements over the basic mirror —
//!   1. writable-descendant escalation in get_by_path (a dir shared read-only is
//!      superseded by a descendant shared writable),
//!   2. social-group cap streams processed into the mirror with per-group offsets,
//!   3. the pointer-cache short-circuit making a redundant update a cheap no-op.
//!
//! NOTE: the group *sender* infrastructure (creating groups / sharing-with-a-group
//! / distributing group caps to members) is not built; here we stand in a plain
//! directory holding a `sharing.r` file as a "group" shared dir to exercise the
//! receiver plumbing.
//!
//!   cargo run -p peergos-fs --example incoming_advanced -- http://localhost:7777/

use peergos_cbor::Cborable;
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpStorage, ReqwestPoster};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(HttpStorage::new(poster.clone(), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(poster.clone()));

    let (au, ap) = ("w2", "w2pass");
    let (bu, bp) = ("bob", "bobpass");
    let _ = peergos_fs::signup(bu, bp, None, poster.as_ref(), store.as_ref()).await;

    // Befriend (idempotent).
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    peergos_fs::send_follow_request(&alice, bu, true, poster.as_ref(), store.clone(), mutable.as_ref()).await?;
    let bob = peergos_fs::login(bu, bp, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    for r in peergos_fs::get_follow_requests(&bob, poster.as_ref()).await? {
        if r.sender() == Some(au) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster.as_ref(), store.clone(), mutable.as_ref()).await?;
        }
    }
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    for r in peergos_fs::get_follow_requests(&alice, poster.as_ref()).await? {
        if r.sender() == Some(bu) {
            peergos_fs::process_follow_reply(&alice, &r, poster.as_ref(), store.clone(), mutable.as_ref()).await?;
        }
    }

    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await?;
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // --- (1) escalation: share a dir read-only, a subdir writable ------------
    let esc = format!("esc{n}");
    let escdir = peergos_fs::create_directory(&home, &esc, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::create_directory(&escdir, "sub", Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_read_access(&alice, &esc, &escdir, bu, store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_write_access(&alice, &esc, &escdir, "sub", bu, store.clone(), mutable.as_ref()).await?;
    println!("{au:?} shared {esc}/ read-only and {esc}/sub writable with {bu:?}");

    // --- (2) group stand-in: a dir with a sharing.r holding one read cap ------
    let grp = format!("grp{n}");
    let grpdir = peergos_fs::create_directory(&home, &grp, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    let gtarget = peergos_fs::upload_file(&home, &format!("gfile{n}.txt"), b"shared via a group", None, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    // A sharing file is a concatenation of AbsoluteCapability cbors.
    let sharing_r = gtarget.read_only().to_cbor().to_bytes();
    peergos_fs::upload_file(&grpdir, "sharing.r", &sharing_r, None, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    println!("{au:?} built a stand-in group dir {grp}/ sharing gfile{n}.txt");

    // Bob updates his mirror: direct shares + the group.
    let bob_ctx = peergos_fs::UserContext::sign_in(bu, bp, None, poster.clone(), store.clone(), mutable.clone()).await?;
    let alice_entry = peergos_fs::get_friends(bob_ctx.user().unwrap(), store.clone(), mutable.as_ref()).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("bob not friends with alice")?;
    let cache = bob_ctx.incoming_cap_cache().await?;

    let groups = vec![(grp.clone(), grpdir.clone())];
    let added = cache.update_from_friend_with_groups(au, &alice_entry.pointer, &groups).await?;
    println!("\nbob pulled {} new cap(s) (direct + group)", added.len());

    // (1) escalation: /w2/esc/sub must resolve to the WRITABLE cap.
    let sub = cache.get_by_path(&format!("/{au}/{esc}/sub")).await?.ok_or("esc/sub not found in mirror")?;
    println!("get_by_path(/{au}/{esc}/sub).is_writable() = {}", sub.is_writable());
    assert!(sub.is_writable(), "escalation failed: read-only ancestor should be superseded by the writable descendant");

    // (2) group: the group's file must be mirrored + resolvable.
    let gpath = format!("/{au}/gfile{n}.txt");
    let gcap = cache.get_by_path(&gpath).await?.ok_or("group file not in mirror")?;
    let (_p, data) = peergos_fs::read_file(&gcap, store.clone(), mutable.as_ref()).await?;
    println!("group file {gpath:?} -> {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"shared via a group");

    // (3) pointer-cache + per-group offsets: a redundant update is a no-op.
    let again = cache.update_from_friend_with_groups(au, &alice_entry.pointer, &groups).await?;
    println!("\nredundant update pulled {} cap(s)", again.len());
    assert!(again.is_empty(), "per-group ProcessedCaps should make a redundant group update a no-op");

    // And a redundant DIRECT-only update short-circuits via the pointer cache.
    let direct_again = cache.update_from_friend(au, &alice_entry.pointer).await?;
    assert!(direct_again.is_empty(), "pointer cache should short-circuit a redundant direct update");

    println!("\nIncomingCapCache advanced OK: escalation, group cap streams, no-op via pointer cache + per-group offsets.");
    Ok(())
}
