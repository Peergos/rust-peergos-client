//! End-to-end tests against the in-process mock Peergos server (no live server).

use peergos_core::mutable::MutablePointers;
use peergos_core::{ContentAddressedStorage, HttpPoster};
use peergos_fs::UserContext;
use peergos_mock_server::MockServer;
use std::sync::Arc;

type Poster = Arc<dyn HttpPoster>;
type Store = Arc<dyn ContentAddressedStorage>;
type Mut = Arc<dyn MutablePointers>;

/// Establish mutual friendship a <-> b.
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

/// Try to write into `owner`'s write-shared `child` dir as `writer`. Ok = wrote.
async fn try_write(writer: (&str, &str), owner: &str, name: &str, poster: &Poster, store: &Store, mutable: &Mut) -> bool {
    let w = peergos_fs::login(writer.0, writer.1, poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let entry = match peergos_fs::get_friends(&w, store.clone(), mutable.as_ref()).await.unwrap().into_iter().find(|e| e.owner_name == owner) {
        Some(e) => e,
        None => return false,
    };
    let caps = peergos_fs::read_write_shared_capabilities(&entry.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    for cap in caps.into_iter().rev() {
        let signer = match peergos_fs::recover_signer(&cap, store.clone(), mutable.as_ref()).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if peergos_fs::upload_file(&cap, name, b"x", None, Some(signer), None, store.clone(), mutable.as_ref()).await.is_ok() {
            return true;
        }
    }
    false
}

#[tokio::test]
async fn signup_login_upload_read() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();

    // Sign up, then upload a file and read it back.
    let ctx = UserContext::sign_up("alice", "alicepw", None, poster.clone(), store.clone(), mutable.clone())
        .await
        .expect("sign up");
    let home = ctx.get_home().await.expect("home");
    let dir = home.mkdir("docs").await.expect("mkdir");
    let content = b"the mock server serves blocks and pointers";
    dir.upload("note.txt", content).await.expect("upload");

    // Re-fetch via a fresh sign-in over the same server.
    let ctx2 = UserContext::sign_in("alice", "alicepw", None, poster, store, mutable).await.expect("sign in");
    let file = ctx2.get_by_path("docs/note.txt").await.expect("resolve").expect("file present");
    assert_eq!(file.read().await.expect("read"), content);
}

#[tokio::test]
async fn usage_delete_roundtrip() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = UserContext::sign_up("bob", "bobpw", None, poster, store, mutable).await.expect("sign up");

    let home = ctx.get_home().await.expect("home");
    let baseline = ctx.get_usage().await.expect("usage");

    // 11 MiB (3 chunks): usage rises, then a delete returns it to exactly baseline.
    let content = vec![9u8; 11 * 1024 * 1024];
    home.upload("big.bin", &content).await.expect("upload");
    let after = ctx.get_usage().await.expect("usage");
    assert!(after > baseline, "upload must raise usage ({after} !> {baseline})");

    home.get_latest().await.expect("latest").remove_child("big.bin").await.expect("delete");
    let after_delete = ctx.get_usage().await.expect("usage");
    assert_eq!(after_delete, baseline, "delete must return usage to exactly the prior value");
}

#[tokio::test]
async fn share_read_between_users() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.expect("sign up");
    }

    // Alice uploads a file, follows bob, and read-shares it.
    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let content = b"a shared secret";
    let cap = peergos_fs::upload_file(&home, "shared.txt", content, None, Some(signer), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::send_follow_request(&alice, "bob", true, poster.as_ref(), store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(&alice, "shared.txt", &cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob picks up the follow request and reads the shared file.
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let from_alice = peergos_fs::get_follow_requests(&bob, poster.as_ref())
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.sender() == Some("alice"))
        .and_then(|r| r.entry)
        .expect("follow request from alice");
    let caps = peergos_fs::read_shared_capabilities(&from_alice.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let mut found = None;
    for cap in &caps {
        if let Ok((_p, data)) = peergos_fs::read_file(cap, store.clone(), mutable.as_ref()).await {
            if data == content {
                found = Some(data);
            }
        }
    }
    assert_eq!(found.as_deref(), Some(content.as_slice()), "bob could not read the shared file");
}

#[tokio::test]
async fn secret_link_roundtrip() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = UserContext::sign_up("carol", "cpw", None, poster, store.clone(), mutable).await.expect("sign up");
    ctx.get_home().await.unwrap().upload("secret.txt", b"top secret").await.unwrap();

    // Read-only link resolves; a password link needs the password.
    let link = ctx.create_secret_link("secret.txt", false, "", None, None).await.expect("create link");
    let cap = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await.expect("resolve link");
    let (_p, data) = peergos_fs::read_file(&cap, store.clone(), ctx.mutable().as_ref()).await.expect("read");
    assert_eq!(data, b"top secret");

    let protected = ctx.create_secret_link("secret.txt", false, "hunter2", None, None).await.expect("create pw link");
    assert!(peergos_fs::retrieve_secret_link_capability(&protected, store.as_ref(), None).await.is_err(), "needs password");
    let cap2 = peergos_fs::retrieve_secret_link_capability(&protected, store.as_ref(), Some("hunter2")).await.expect("with pw");
    assert_eq!(peergos_fs::read_file(&cap2, store.clone(), ctx.mutable().as_ref()).await.unwrap().1, b"top secret");
}

#[tokio::test]
async fn mutate_move_rename_delete() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = UserContext::sign_up("dave", "dpw", None, poster, store, mutable).await.expect("sign up");
    let home = ctx.get_home().await.unwrap();

    home.upload("a.txt", b"aaa").await.unwrap();
    let dst = home.mkdir("dst").await.unwrap();

    // rename, then move into a subdir, then delete.
    let home = home.get_latest().await.unwrap();
    home.rename_child("a.txt", "b.txt").await.unwrap();
    let home = home.get_latest().await.unwrap();
    home.move_child("b.txt", &dst.get_latest().await.unwrap(), true).await.unwrap();
    let moved = ctx.get_by_path("dst/b.txt").await.unwrap().expect("moved file");
    assert_eq!(moved.read().await.unwrap(), b"aaa");

    dst.get_latest().await.unwrap().remove_child("b.txt").await.unwrap();
    assert!(ctx.get_by_path("dst/b.txt").await.unwrap().is_none(), "deleted");
}

#[tokio::test]
async fn change_password_then_sign_in() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    UserContext::sign_up("erin", "old-pw", None, poster.clone(), store.clone(), mutable.clone()).await.expect("sign up");
    peergos_fs::change_password("erin", "old-pw", "new-pw", None, poster.as_ref(), store.clone(), mutable.as_ref()).await.expect("change pw");

    // Old password no longer works; new one does.
    assert!(UserContext::sign_in("erin", "old-pw", None, poster.clone(), store.clone(), mutable.clone()).await.is_err());
    UserContext::sign_in("erin", "new-pw", None, poster, store, mutable).await.expect("sign in with new pw");
}

#[tokio::test]
async fn revoke_write_denies_writer() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.expect("sign up");
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    // Alice creates "project" and write-shares it with bob.
    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let signer = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::create_directory(&home, "project", Some(signer), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(&alice, "", &home, "project", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob can write; then alice revokes and bob can no longer write.
    assert!(try_write(("bob", "bpw"), "alice", "before.txt", &poster, &store, &mutable).await, "bob should write before revoke");

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    peergos_fs::unshare_write_access(&alice, "", &home, "project", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    assert!(!try_write(("bob", "bpw"), "alice", "after.txt", &poster, &store, &mutable).await, "REVOCATION FAILED: bob still wrote");
}
