//! removeFollower: revoke everything shared with a follower + drop their sharing
//! folder. alice shares docs/ with bob and carol, then removeFollower(bob):
//! bob loses access, carol keeps it, and /alice/shared/bob is gone.
//!
//!   cargo run -p peergos-fs --example remove_follower -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;

type Store = Arc<dyn ContentAddressedStorage>;

async fn befriend(a: (&str, &str), b: (&str, &str), poster: &ReqwestPoster, store: Store, mutable: &HttpMutablePointers) -> Result<(), Box<dyn std::error::Error>> {
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

async fn can_read(reader_u: &str, reader_p: &str, alice_u: &str, poster: &ReqwestPoster, store: Store, mutable: &HttpMutablePointers) -> Option<String> {
    let reader = peergos_fs::login(reader_u, reader_p, poster, store.clone(), mutable, None).await.ok()?;
    let entry = peergos_fs::get_friends(&reader, store.clone(), mutable).await.ok()?.into_iter().find(|e| e.owner_name == alice_u)?;
    for docs in peergos_fs::read_shared_capabilities(&entry.pointer, store.clone(), mutable).await.ok()? {
        if let Ok(entries) = peergos_fs::list_directory(&docs, store.clone(), mutable).await {
            if let Some(f) = entries.into_iter().find(|e| e.name == "secret.txt") {
                if let Ok((_p, d)) = peergos_fs::read_file(&f.cap, store.clone(), mutable).await {
                    return Some(String::from_utf8_lossy(&d).to_string());
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
    let hposter: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Store = Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable = HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?));
    let hmutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));
    let (au, ap) = ("w2", "w2pass");
    let (bu, bp) = ("bob", "bobpass");
    let (cu, cp) = ("carol", "carolpass");
    for (u, p) in [(au, ap), (bu, bp), (cu, cp)] {
        match peergos_fs::signup(u, p, None, &poster, store.as_ref()).await {
            Ok(()) | Err(_) => {}
        }
    }
    befriend((au, ap), (bu, bp), &poster, store.clone(), &mutable).await?;
    befriend((au, ap), (cu, cp), &poster, store.clone(), &mutable).await?;

    // alice shares docs/ with bob and carol.
    let alice = peergos_fs::login(au, ap, &poster, store.clone(), &mutable, None).await?;
    let home = alice.home().ok_or("no home")?.clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), &mutable).await?;
    // Fresh docs each run to avoid stale state.
    let docs = peergos_fs::create_directory(&home, "docs", Some(signer.clone()), store.clone(), &mutable).await?;
    peergos_fs::upload_file(&docs, "secret.txt", b"top secret", None, Some(signer), store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "docs", &docs, bu, store.clone(), &mutable).await?;
    peergos_fs::share_read_access(&alice, "docs", &docs, cu, store.clone(), &mutable).await?;

    assert_eq!(can_read(bu, bp, au, &poster, store.clone(), &mutable).await.as_deref(), Some("top secret"));
    assert_eq!(can_read(cu, cp, au, &poster, store.clone(), &mutable).await.as_deref(), Some("top secret"));
    println!("shared docs/ with {bu} and {cu}; both can read");

    // What does the walker see is shared with bob?
    let shared_with_bob = peergos_fs::collect_shares_for_user(&alice, bu, store.clone(), &mutable).await?;
    println!("collect_shares_for_user({bu}) = {shared_with_bob:?}");
    assert!(shared_with_bob.iter().any(|(_d, c, _a)| c == "docs"));

    // removeFollower(bob).
    let ctx = UserContext::sign_in(au, ap, None, hposter.clone(), store.clone(), hmutable.clone()).await?;
    ctx.remove_follower(bu).await?;
    println!("removeFollower({bu}) done");

    // bob can no longer read; carol still can; /shared/bob is gone.
    assert_eq!(can_read(bu, bp, au, &poster, store.clone(), &mutable).await, None, "bob must lose access");
    assert_eq!(can_read(cu, cp, au, &poster, store.clone(), &mutable).await.as_deref(), Some("top secret"), "carol keeps access");
    let shared_dir = ctx.get_home().await?.child("shared").await?.unwrap();
    assert!(shared_dir.child(bu).await?.is_none(), "/shared/bob must be removed");
    println!("after removeFollower: {bu} lost access, {cu} retained it, /shared/{bu} removed");

    println!("\nremoveFollower OK.");
    Ok(())
}
