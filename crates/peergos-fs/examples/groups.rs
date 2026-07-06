//! Social groups (friends / followers), sender + receiver end to end:
//!  - alice initialises her two default groups (friends, followers),
//!  - alice adds bob to the "followers" group,
//!  - alice shares a file WITH THE GROUP (not bob directly),
//!  - bob updates his IncomingCapCache: it auto-discovers alice's followers group
//!    dir and pulls the group-shared file into his mirror; he reads it,
//!  - a second file shared with the group is picked up on the next update.
//!
//!   cargo run -p peergos-fs --example groups -- http://localhost:7777/

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

    // Alice sets up her groups and puts bob in "followers".
    let alice = peergos_fs::login(au, ap, poster.as_ref(), store.clone(), mutable.as_ref(), None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await?;

    let groups = peergos_fs::get_or_create_groups(&alice, store.clone(), mutable.as_ref()).await?;
    println!("alice groups: {:?}", groups.uid_to_name.values().collect::<Vec<_>>());
    assert!(groups.uid_for(peergos_fs::FRIENDS_GROUP).is_some() && groups.uid_for(peergos_fs::FOLLOWERS_GROUP).is_some());

    // bob was already added to the followers (and friends) group automatically when
    // alice accepted his follow above — no explicit add_member_to_group needed.
    let followers_uid = groups.uid_for(peergos_fs::FOLLOWERS_GROUP).unwrap();
    println!("followers group shared-with is recorded by uid: {:?}", followers_uid);

    // Alice shares a file with the followers group (not bob directly).
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let f1 = format!("group-a-{n}.txt");
    let c1 = peergos_fs::upload_file(&home, &f1, b"hello followers", None, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_read_with_group(&alice, &f1, &c1, peergos_fs::FOLLOWERS_GROUP, store.clone(), mutable.as_ref()).await?;
    println!("shared {f1:?} with the followers group");

    // The share is recorded in alice's shared-with cache under the group uid
    // (Java-compatible), so she can enumerate/revoke it later.
    let shared_with = peergos_fs::get_shared_with(&alice, &f1, peergos_fs::Access::Read, store.clone(), mutable.as_ref()).await?;
    println!("shared-with({f1}) = {shared_with:?}");
    assert!(shared_with.contains(&followers_uid), "group share should be recorded in the shared-with cache by uid");

    // Bob updates his incoming cache — the group dir is auto-discovered.
    let bob_ctx = peergos_fs::UserContext::sign_in(bu, bp, None, poster.clone(), store.clone(), mutable.clone()).await?;
    let alice_entry = peergos_fs::get_friends(bob_ctx.user().unwrap(), store.clone(), mutable.as_ref()).await?
        .into_iter().find(|e| e.owner_name == au).ok_or("bob not friends with alice")?;
    let cache = bob_ctx.incoming_cap_cache().await?;

    let added = cache.update_from_friend(au, &alice_entry.pointer).await?;
    println!("\nbob pulled {} cap(s); paths: {:?}", added.len(), added.iter().map(|c| c.path.clone()).collect::<Vec<_>>());
    assert!(added.iter().any(|c| c.path.ends_with(&f1)), "the group-shared file should reach bob via the group");
    let cap = cache.get_by_path(&format!("/{au}/{f1}")).await?.ok_or("group file not in mirror")?;
    let data = peergos_fs::read_file(&cap, store.clone(), mutable.as_ref()).await?.1;
    println!("bob read {f1:?} = {:?}", String::from_utf8_lossy(&data));
    assert_eq!(data, b"hello followers");

    // Incremental: a second file shared with the group is picked up next update.
    let f2 = format!("group-b-{n}.txt");
    let c2 = peergos_fs::upload_file(&home, &f2, b"more for followers", None, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_read_with_group(&alice, &f2, &c2, peergos_fs::FOLLOWERS_GROUP, store.clone(), mutable.as_ref()).await?;
    let added2 = cache.update_from_friend(au, &alice_entry.pointer).await?;
    println!("\nafter a 2nd group share, bob pulled {} cap(s)", added2.len());
    assert!(added2.iter().any(|c| c.path.ends_with(&f2)), "second group file should be picked up incrementally");
    assert!(cache.get_by_path(&format!("/{au}/{f2}")).await?.is_some());

    // Write-sharing WITH a group (sender side): alice write-shares a directory with
    // her friends group; the friends uid is recorded in the WRITE shared-with cache.
    let wdir = format!("wgroup-{n}");
    peergos_fs::create_directory(&home, &wdir, Some(signer.clone()), store.clone(), mutable.as_ref()).await?;
    peergos_fs::share_write_with_group(&alice, "", &home, &wdir, peergos_fs::FRIENDS_GROUP, store.clone(), mutable.as_ref()).await?;
    let friends_uid = groups.uid_for(peergos_fs::FRIENDS_GROUP).unwrap();
    let w_shared = peergos_fs::get_shared_with(&alice, &wdir, peergos_fs::Access::Write, store.clone(), mutable.as_ref()).await?;
    println!("\nwrite-shared {wdir}/ with the friends group; shared-with(write) = {w_shared:?}");
    assert!(w_shared.contains(&friends_uid), "write-to-group should record the friends uid in the write cache");

    println!("\nGroups OK: friends/followers auto-membership on accept, read + write group shares, shared-with recorded by uid, group share flows to a member's mirror.");
    Ok(())
}
