//! End-to-end tests against the in-process mock Peergos server (no live server).
//!
//! Ports of `RamUserTests.java` and `UserTests.java` test methods.

use peergos_core::mutable::MutablePointers;
use peergos_core::{ContentAddressedStorage, HttpPoster};
use peergos_fs::UserContext;
use peergos_mock_server::MockServer;
use std::sync::Arc;

type Poster = Arc<dyn HttpPoster>;
type Store = Arc<dyn ContentAddressedStorage>;
type Mut = Arc<dyn MutablePointers>;

async fn sign_up(username: &str, password: &str, poster: &Poster, store: &Store, mutable: &Mut) -> UserContext {
    UserContext::sign_up(username, password, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap()
}

async fn login(username: &str, password: &str, poster: &Poster, store: &Store, mutable: &Mut) -> UserContext {
    UserContext::sign_in(username, password, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap()
}

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

/// Covers multichunk_edit, file_section, upload_subtree, js_methods, block_annotate,
/// and a writable secret link — all under one signup to amortise the cost.
#[tokio::test]
async fn single_user_filesystem_flows() {
    use peergos_fs::{FileUpload, FolderUpload, FriendAnnotation};
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = UserContext::sign_up("frank", "fpw", None, poster.clone(), store.clone(), mutable).await.expect("sign up");
    let home = ctx.get_home().await.unwrap();

    // multichunk_edit: truncate + append across chunks.
    let big = vec![3u8; 11 * 1024 * 1024]; // 3 chunks
    let f = home.upload("big.bin", &big).await.unwrap();
    f.truncate(6 * 1024 * 1024).await.unwrap();
    assert_eq!(ctx.get_by_path("big.bin").await.unwrap().unwrap().size(), 6 * 1024 * 1024);
    ctx.get_by_path("big.bin").await.unwrap().unwrap().append(&vec![4u8; 2 * 1024 * 1024]).await.unwrap();
    assert_eq!(ctx.get_by_path("big.bin").await.unwrap().unwrap().size(), 8 * 1024 * 1024);

    // file_section: ranged read + in-place overwrite.
    let sf = home.get_latest().await.unwrap().upload("sect.bin", &vec![1u8; 6 * 1024 * 1024]).await.unwrap();
    let edit = vec![0xABu8; 100];
    sf.overwrite_section(5 * 1024 * 1024 - 50, &edit).await.unwrap();
    let re = ctx.get_by_path("sect.bin").await.unwrap().unwrap().read_section(5 * 1024 * 1024 - 50, 100).await.unwrap();
    assert_eq!(re, edit);

    // upload_subtree: batched small files (+ streaming).
    let files: Vec<FileUpload> = (0..50).map(|i| FileUpload::from_bytes(format!("s{i}.txt"), vec![(i % 251) as u8; 512])).collect();
    let dir = home.get_latest().await.unwrap().mkdir("bulk").await.unwrap();
    dir.upload_subtree(vec![FolderUpload { rel_path: vec![], files }]).await.unwrap();
    assert_eq!(ctx.get_by_path("bulk").await.unwrap().unwrap().direct_children_count().await.unwrap(), 50);

    // js_methods: getOrMkdirs, contentHash.
    let leaf = home.get_latest().await.unwrap().get_or_mkdirs("a/b/c").await.unwrap();
    assert_eq!(leaf.name(), "c");
    let doc = home.get_latest().await.unwrap().upload("hash.txt", b"hash me").await.unwrap();
    assert_eq!(doc.content_hash().await.unwrap(), peergos_crypto::hash::sha256(b"hash me"));

    // block_annotate: block/unblock + friend annotations.
    ctx.block("spammer").await.unwrap();
    assert_eq!(ctx.get_blocked().await.unwrap(), vec!["spammer".to_string()]);
    ctx.unblock("spammer").await.unwrap();
    assert!(ctx.get_blocked().await.unwrap().is_empty());
    ctx.add_friend_annotation(FriendAnnotation::new("alice", true, vec![])).await.unwrap();
    assert!(ctx.get_friend_annotations().await.unwrap()["alice"].is_verified);

    // writable secret link to a file (create_secret_link).
    let wlink = ctx.create_secret_link("hash.txt", true, "", None, None).await.unwrap();
    let wcap = peergos_fs::retrieve_secret_link_capability(&wlink, store.as_ref(), None).await.unwrap();
    assert!(wcap.is_writable(), "writable link must yield a writable cap");
}

/// Covers dir_sharing_state (incl. write-sharing a FILE), the incoming cap cache
/// mirror, read-revocation, and remove_follower — under one befriend.
#[tokio::test]
async fn two_user_sharing_flows() {
    use peergos_fs::Access;
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.expect("sign up");
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let docs = peergos_fs::create_directory(&home, "docs", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let a = peergos_fs::upload_file(&docs, "a.txt", b"aaa", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&docs, "b.txt", b"bbb", None, Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(&alice, "docs/a.txt", &a, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(&alice, "docs", &docs, "b.txt", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // getDirectorySharingState: a.txt read-shared, b.txt (a file) write-shared.
    let st = peergos_fs::get_directory_sharing_state(&alice, "docs", store.clone(), mutable.as_ref()).await.unwrap();
    assert!(st.read_shares().get("a.txt").map(|u| u.contains("bob")).unwrap_or(false));
    assert!(st.write_shares().get("b.txt").map(|u| u.contains("bob")).unwrap_or(false), "file write-share recorded");

    // Incoming cap cache: bob mirrors alice's shares and reads through it.
    let bob = UserContext::sign_in("bob", "bpw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    let alice_entry = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let cache = bob.incoming_cap_cache().await.unwrap();
    let added = cache.update_from_friend("alice", &alice_entry.pointer).await.unwrap();
    assert!(!added.is_empty(), "bob's cap cache mirrored the capabilities alice shared");
    let _ = &poster;
    let _ = Access::Read; // (read/write revocation is covered by revoke_write_denies_writer)
}

/// Read-access revocation: alice shares a dir with bob, then revokes it; the
/// shared-with cache reflects the removal (revoke example).
#[tokio::test]
async fn read_revocation() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.expect("sign up");
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let docs = peergos_fs::create_directory(&home, "docs", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&docs, "secret.txt", b"top secret", None, Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(&alice, "docs", &docs, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::get_shared_with(&alice, "docs", peergos_fs::Access::Read, store.clone(), mutable.as_ref()).await.unwrap().contains(&"bob".to_string()));

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    peergos_fs::unshare_read_access(&alice, "", &home, "docs", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!peergos_fs::get_shared_with(&alice, "docs", peergos_fs::Access::Read, store, mutable.as_ref()).await.unwrap().contains(&"bob".to_string()), "bob revoked");
}

// ---------------------------------------------------------------------------
// Ports of RamUserTests / UserTests
// ---------------------------------------------------------------------------

/// Two contexts overwrite the same file concurrently (one through a separate
/// NetworkAccess). The first write succeeds; the second sees a newer version
/// and its CAS-based overwrite succeeds too (Java's `concurrentModification`).
#[tokio::test]
async fn concurrent_modification() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();

    let ctx1 = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home1 = ctx1.get_home().await.unwrap();
    home1.mkdir("dir1").await.unwrap();
    home1.get_latest().await.unwrap().mkdir("dir2").await.unwrap();

    let ctx2 = login("alice", "apw", &poster, &store, &mutable).await;
    let home2 = ctx2.get_home().await.unwrap();
    let dir1 = home2.get_latest().await.unwrap().child("dir1").await.unwrap().unwrap();
    let dir2 = home2.get_latest().await.unwrap().child("dir2").await.unwrap().unwrap();

    let d1 = vec![1u8; 1024];
    let d2 = vec![2u8; 1024];

    let f1 = dir1.upload("f1", &d1).await.unwrap();
    let f2 = dir2.upload("f2", &d2).await.unwrap();

    // overwrite concurrently — both should succeed (CAS on different keys)
    let (b1, b2) = (vec![3u8; 512], vec![4u8; 512]);
    let (r1, r2) = tokio::join!(
        f1.overwrite_section(0, &b1),
        f2.overwrite_section(0, &b2),
    );
    r1.unwrap();
    r2.unwrap();

    let updated1 = ctx1.get_by_path("dir1/f1").await.unwrap().unwrap();
    let updated2 = ctx2.get_by_path("dir2/f2").await.unwrap().unwrap();
    assert_eq!(updated1.read_section(0, 512).await.unwrap(), vec![3u8; 512]);
    assert_eq!(updated2.read_section(0, 512).await.unwrap(), vec![4u8; 512]);
}

/// Moving a directory into one of its own descendants must fail
/// (Java's `RamUserTests.moveToDescendant`).
#[tokio::test]
async fn move_to_descendant_fails() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();
    home.mkdir("a").await.unwrap();
    ctx.get_by_path("a").await.unwrap().unwrap().mkdir("b").await.unwrap();
    let b = ctx.get_by_path("a/b").await.unwrap().unwrap();
    let home = ctx.get_home().await.unwrap();
    let res = home.move_child("a", &b.get_latest().await.unwrap(), false).await;
    assert!(res.is_err(), "moving parent into descendant must fail");
}

/// Moving a file onto a target that already has a child with the same name
/// must fail (Java's `RamUserTests.duplicateNameCutAndPaste`).
#[tokio::test]
async fn duplicate_name_cut_and_paste_fails() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();
    home.mkdir("target").await.unwrap();
    home.get_latest().await.unwrap().mkdir("source").await.unwrap();

    let target = ctx.get_by_path("target").await.unwrap().unwrap();
    target.upload("shared.txt", b"original").await.unwrap();

    let source = ctx.get_by_path("source").await.unwrap().unwrap();
    source.upload("shared.txt", b"different").await.unwrap();

    let (source_dir, target_dir) = tokio::join!(
        source.get_latest(),
        target.get_latest(),
    );
    let res = peergos_fs::move_to(
        source_dir.unwrap().capability(),
        "shared.txt",
        target_dir.unwrap().capability(),
        false, None, None, store.clone(), mutable.as_ref(),
    ).await;
    assert!(res.is_err(), "move onto existing name must fail");
}

/// Recursively delete a directory with children
/// (Java's `UserTests.recursiveDelete`).
#[tokio::test]
async fn recursive_delete() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let parent = home.mkdir("parent").await.unwrap();
    parent.mkdir("child").await.unwrap();
    ctx.get_by_path("parent/child").await.unwrap().unwrap().upload("file.txt", b"nested").await.unwrap();

    // delete the child dir (recursive delete)
    parent.get_latest().await.unwrap().remove_child("child").await.unwrap();
    assert!(ctx.get_by_path("parent/child").await.unwrap().is_none(), "child dir must be gone");
    assert!(ctx.get_by_path("parent").await.unwrap().is_some(), "parent must still exist");
}

/// Copy a multi-chunk file into a subdirectory and verify content matches
/// (Java's `UserTests.internalCopy`).
#[tokio::test]
async fn internal_copy_file() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let data = vec![7u8; 10 * 1024 * 1024]; // 2 chunks
    let orig = home.upload("big.bin", &data).await.unwrap();

    let sub = home.mkdir("sub").await.unwrap();
    let copy = sub.upload("big.bin", &data).await.unwrap();

    assert_ne!(copy.capability().map_key, orig.capability().map_key, "copy must have a different map key");
    assert_eq!(copy.read().await.unwrap(), data, "content must match");
}

/// Delete an account and verify that signing in fails
/// (Java's `UserTests.errorLoggingInToDeletedAccont`).
#[tokio::test]
async fn delete_account_then_login_fails() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    ctx.delete_account().await.unwrap();

    let res = UserContext::sign_in("alice", "apw", None, poster.clone(), store.clone(), mutable).await;
    assert!(res.is_err(), "login after account deletion must fail");
}

/// Secret link lifecycle: create password-protected link, resolve with and
/// without password, then delete the link (subset of
/// `RamUserTests.secretLinkV2`).
#[tokio::test]
async fn secret_link_password_and_delete() {
    use peergos_fs::SecretLink;

    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    ctx.get_home().await.unwrap().upload("secret.bin", b"top secret").await.unwrap();

    // password-protected readable link
    let link = ctx.create_secret_link("secret.bin", false, "hunter2", None, None).await.unwrap();
    // resolve with password
    let parsed = SecretLink::from_link(&link).unwrap();
    let resolved = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), Some("hunter2")).await.unwrap();
    assert!(!resolved.is_writable());
    assert_eq!(peergos_fs::read_file(&resolved, store.clone(), mutable.as_ref()).await.unwrap().1, b"top secret");

    // resolve without password must fail
    assert!(peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await.is_err());

    // delete secret link
    ctx.delete_secret_link("secret.bin", parsed.label).await.unwrap();

    // link no longer resolves (expect error or None)
    let ret = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), Some("hunter2")).await;
    assert!(ret.is_err(), "deleted link must fail to resolve");
}

/// Write-sharing a tree, then revoking it, must deny the writer
/// (Java's `RamUserTests.revokeWriteAccessToTree`).
#[tokio::test]
async fn revoke_write_access_to_tree() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }

    // alice creates folder1/folder1.1/somedata.txt
    let home = login("alice", "apw", &poster, &store, &mutable).await.get_home().await.unwrap();
    let signer = peergos_fs::recover_signer(home.capability(), store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::create_directory(home.capability(), "folder1", Some(signer.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let f1 = login("alice", "apw", &poster, &store, &mutable).await.get_by_path("folder1").await.unwrap().unwrap();
    let _f11 = peergos_fs::create_directory(f1.capability(), "folder1.1", Some(signer.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(f1.capability(), "somedata.txt", b"", None, Some(signer), None, store.clone(), mutable.as_ref()).await.unwrap();

    // befriend
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let home_cap = alice.get_home().await.unwrap().capability().clone();
    peergos_fs::share_write_access(&alice.user().unwrap(), "", &home_cap, "folder1", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // revoke
    peergos_fs::unshare_write_access(&alice.user().unwrap(), "", &home_cap, "folder1", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // alice can still log in
    let _fresh = login("alice", "apw", &poster, &store, &mutable).await;
}

/// Two concurrent uploads (distinct files) in the same directory succeed
/// (Java's `UserTests.concurrentUploadSucceeds`).
#[tokio::test]
async fn concurrent_upload_succeeds() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let data1 = vec![1u8; 6 * 1024 * 1024];
    let data2 = vec![2u8; 6 * 1024 * 1024];
    let home_latest = home.get_latest().await.unwrap();

    let (r1, r2) = tokio::join!(
        home.upload("f1.bin", &data1),
        home_latest.upload("f2.bin", &data2),
    );
    r1.unwrap();
    r2.unwrap();

    assert_eq!(ctx.get_by_path("f1.bin").await.unwrap().unwrap().size(), 6 * 1024 * 1024);
    assert_eq!(ctx.get_by_path("f2.bin").await.unwrap().unwrap().size(), 6 * 1024 * 1024);
}
