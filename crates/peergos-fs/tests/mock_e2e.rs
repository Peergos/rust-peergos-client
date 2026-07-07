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
