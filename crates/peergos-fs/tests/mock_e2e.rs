//! End-to-end tests against the in-process mock Peergos server (no live server).

use peergos_fs::UserContext;
use peergos_mock_server::MockServer;

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
