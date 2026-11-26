//! An account made with Ed25519 writers moves to hybrid writers on login. A test
//! binary of its own, as it turns the process wide switch on part way.

use peergos_core::keys::set_hybrid_writers;
use peergos_core::mutable::MutablePointers;
use peergos_core::{ContentAddressedStorage, HttpPoster};
use peergos_fs::UserContext;
use peergos_mock_server::MockServer;
use std::sync::Arc;

type Poster = Arc<dyn HttpPoster>;
type Store = Arc<dyn ContentAddressedStorage>;
type Mut = Arc<dyn MutablePointers>;

async fn befriend(a: (&str, &str), b: (&str, &str), poster: &Poster, store: &Store, mutable: &Mut) {
    let alice = peergos_fs::login(a.0, a.1, poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    peergos_fs::send_follow_request(&alice, b.0, true, poster.as_ref(), store.clone(), mutable.as_ref()).await.unwrap();
    let bob = peergos_fs::login(b.0, b.1, poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    for r in peergos_fs::get_follow_requests(&bob, poster.as_ref()).await.unwrap() {
        if r.sender() == Some(a.0) {
            peergos_fs::accept_follow_request(&bob, &r, true, poster.as_ref(), store.clone(), mutable.as_ref()).await.unwrap();
        }
    }
    let alice = peergos_fs::login(a.0, a.1, poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    for r in peergos_fs::get_follow_requests(&alice, poster.as_ref()).await.unwrap() {
        if r.sender() == Some(b.0) {
            peergos_fs::process_follow_reply(&alice, &r, poster.as_ref(), store.clone(), mutable.as_ref()).await.unwrap();
        }
    }
}

#[tokio::test]
async fn ed25519_account_moves_to_hybrid_writers_on_login() {
    set_hybrid_writers(false);
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let ctx = UserContext::sign_in("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    let home = ctx.get_home().await.unwrap();
    let docs = home.mkdir("docs").await.unwrap();
    docs.upload("note.txt", b"read shared").await.unwrap();
    home.mkdir("folder").await.unwrap().upload("inside.txt", b"write shared").await.unwrap();
    home.upload("pub.txt", b"published").await.unwrap();
    home.upload("linked.txt", b"linked").await.unwrap();
    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let note = ctx.get_by_path("docs/note.txt").await.unwrap().unwrap().capability().clone();
    peergos_fs::share_read_access(&alice, "docs/note.txt", &note, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    let home_cap = alice.home().unwrap().clone();
    peergos_fs::share_write_access(&alice, "", &home_cap, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();
    ctx.make_public("pub.txt").await.unwrap();
    let link = ctx.create_secret_link("linked.txt", false, "", None, None).await.unwrap();
    let old_home = home_cap.clone();
    assert!(old_home.writer.is_identity());

    set_hybrid_writers(true);
    let ctx = UserContext::sign_in("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    assert!(!home.writer.is_identity(), "the home moved to a hybrid writer");
    assert!(alice.stored_home.is_none(), "the entry point names the new home");
    assert_eq!(home.map_key, old_home.map_key, "the home kept its keys");

    let read = |path: &'static str| {
        let ctx = &ctx;
        async move {
            let f = ctx.get_by_path(path).await.unwrap().unwrap_or_else(|| panic!("{path} is there"));
            f.read().await.unwrap()
        }
    };
    assert_eq!(read("docs/note.txt").await, b"read shared");
    assert_eq!(read("folder/inside.txt").await, b"write shared");
    let folder = ctx.get_by_path("folder").await.unwrap().unwrap();
    assert!(!folder.capability().writer.is_identity(), "the nested writing space moved to a hybrid writer");

    // the old home cap still leads to the home
    let names: Vec<String> = peergos_fs::list_directory(&old_home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["alice".to_string()]);

    let pub_cap = ctx.get_public_capability("/alice/pub.txt").await.unwrap();
    assert!(!pub_cap.writer.is_identity());
    assert_eq!(peergos_fs::read_file(&pub_cap, store.clone(), mutable.as_ref()).await.unwrap().1, b"published");
    let linked = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await.unwrap();
    assert_eq!(peergos_fs::read_file(&linked, store.clone(), mutable.as_ref()).await.unwrap().1, b"linked");

    // bob gets the new caps through the sharing folder he already had
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let entry = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_shared_capabilities(&entry.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let shared_note = caps.iter().find(|c| c.map_key == note.map_key && !c.writer.is_identity()).expect("the new note cap");
    assert_eq!(peergos_fs::read_file(shared_note, store.clone(), mutable.as_ref()).await.unwrap().1, b"read shared");
    let mut wrote = false;
    for cap in peergos_fs::read_write_shared_capabilities(&entry.pointer, store.clone(), mutable.as_ref()).await.unwrap() {
        if cap.writer.is_identity() {
            continue;
        }
        let Ok(signer) = peergos_fs::recover_signer(&cap, store.clone(), mutable.as_ref()).await else { continue };
        if peergos_fs::upload_file(&cap, "from-bob.txt", b"hi", None, Some(signer), None, store.clone(), mutable.as_ref()).await.is_ok() {
            wrote = true;
        }
    }
    assert!(wrote, "bob can write to the folder through its new cap");
    assert_eq!(read("folder/from-bob.txt").await, b"hi");

    // a later login has nothing to move
    let again = UserContext::sign_in("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    assert_eq!(again.get_home().await.unwrap().capability(), &home);
}
