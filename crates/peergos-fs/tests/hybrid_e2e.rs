//! The mock e2e flows with hybrid Ed25519 + ML-DSA-44 writers switched on. A test
//! binary of its own, as the switch is process wide.

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
async fn hybrid_home_writer() {
    set_hybrid_writers(true);
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = UserContext::sign_up("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    let home = ctx.get_home().await.unwrap();
    let docs = home.mkdir("docs").await.unwrap();
    docs.upload("note.txt", b"post-quantum").await.unwrap();

    let ctx = UserContext::sign_in("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    let home = ctx.get_home().await.unwrap();
    assert!(!home.capability().writer.is_identity(), "the home writer is hybrid");
    let docs = home.child("docs").await.unwrap().unwrap();
    let file = docs.child("note.txt").await.unwrap().unwrap();
    assert_eq!(file.read().await.unwrap(), b"post-quantum");
}

#[tokio::test]
async fn hybrid_write_share_and_revoke() {
    set_hybrid_writers(true);
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&folder, "note.txt", b"hello", None, Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(&alice, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let entry = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_write_shared_capabilities(&entry.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let mut wrote = None;
    for cap in caps {
        let Ok(children) = peergos_fs::list_directory(&cap, store.clone(), mutable.as_ref()).await else { continue };
        if !children.iter().any(|e| e.name == "note.txt") {
            continue;
        }
        assert!(!cap.writer.is_identity(), "the shared folder has a hybrid writer");
        let signer = peergos_fs::recover_signer(&cap, store.clone(), mutable.as_ref()).await.unwrap();
        peergos_fs::upload_file(&cap, "from-bob.txt", b"hi", None, Some(signer), None, store.clone(), mutable.as_ref()).await.unwrap();
        wrote = Some(cap);
    }
    let old_cap = wrote.expect("bob wrote into the shared folder");

    peergos_fs::unshare_write_access(&alice, "", &home, "folder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::list_directory(&old_cap, store.clone(), mutable.as_ref()).await.is_err(), "the old cap is revoked");

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let folder = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap();
    // a write-shared folder is named by a link node in its parent
    let target = peergos_fs::list_directory(&folder.cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap();
    let names: Vec<String> = peergos_fs::list_directory(&target.cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().map(|e| e.name).collect();
    assert!(names.contains(&"from-bob.txt".to_string()), "{names:?}");
}

#[tokio::test]
async fn hybrid_writable_secret_link() {
    set_hybrid_writers(true);
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = UserContext::sign_up("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    let home = ctx.get_home().await.unwrap();
    home.mkdir("drop").await.unwrap();
    let link = ctx.create_secret_link("drop", true, "", None, None).await.unwrap();
    let cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await.unwrap();
    assert!(cap.is_writable());
    assert!(!cap.writer.is_identity(), "the link target has a hybrid writer");
    let signer = peergos_fs::recover_signer(&cap, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&cap, "via-link.txt", b"x", None, Some(signer), None, store.clone(), mutable.as_ref()).await.unwrap();
    let names: Vec<String> = peergos_fs::list_directory(&cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["via-link.txt".to_string()]);
}
