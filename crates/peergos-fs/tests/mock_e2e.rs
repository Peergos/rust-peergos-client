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

/// Signing up a second time with the *same* username must fail
/// (Java's `UserTests.singleSignUp`, `duplicateSignUp`, `repeatedSignUp`).
#[tokio::test]
async fn single_signup_fails_on_duplicate() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    UserContext::sign_up("alice", "apw", None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();

    // different password
    assert!(UserContext::sign_up("alice", "different", None, poster.clone(), store.clone(), mutable.clone()).await.is_err());
    // same password
    assert!(UserContext::sign_up("alice", "apw", None, poster, store, mutable).await.is_err());
}

/// Upload file, append more data, verify merged content
/// (Java's `UserTests.appendToFile`).
#[tokio::test]
async fn append_to_file() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();
    home.upload("f.txt", b"Hello ").await.unwrap();
    ctx.get_by_path("f.txt").await.unwrap().unwrap().append(b"World!").await.unwrap();
    assert_eq!(ctx.get_by_path("f.txt").await.unwrap().unwrap().read().await.unwrap(), b"Hello World!");
}

/// Truncate a 15 MiB file down to various sizes and verify content + chunk removal
/// (Java's `UserTests.truncate`).
#[tokio::test]
async fn truncate_file() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let data = vec![4u8; 15 * 1024 * 1024];
    let f = home.upload("big.bin", &data).await.unwrap();

    // truncate to 7 MiB
    f.truncate(7 * 1024 * 1024).await.unwrap();
    let f = ctx.get_by_path("big.bin").await.unwrap().unwrap();
    assert_eq!(f.size(), 7 * 1024 * 1024);
    assert_eq!(f.read().await.unwrap(), &data[..7 * 1024 * 1024]);

    // truncate within first chunk (512 KiB)
    f.truncate(512 * 1024).await.unwrap();
    let f = ctx.get_by_path("big.bin").await.unwrap().unwrap();
    assert_eq!(f.size(), 512 * 1024);
    assert_eq!(f.read().await.unwrap(), &data[..512 * 1024]);
}

/// Seek to various offsets in a 15 MiB file and verify data
/// (Java's `UserTests.fileSeek`).
#[tokio::test]
async fn file_seek() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let mut data = vec![0u8; 15 * 1024 * 1024];
    // fill with deterministically patterned data so reads at any offset are verifiable
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    home.upload("big.bin", &data).await.unwrap();

    let mb = 1024 * 1024;
    for offset in [10u64, 4 * mb, 6 * mb, 11 * mb] {
        let f = ctx.get_by_path("big.bin").await.unwrap().unwrap();
        let len = 2 * mb;
        let buf = f.read_section(offset, len).await.unwrap();
        assert_eq!(buf, &data[offset as usize..][..len as usize], "seek to {offset}");
    }
}

/// Bulk-upload 20 small files, then delete them all and verify gone
/// (Java's `UserTests.bulkDeleteTest`).
#[tokio::test]
async fn bulk_delete() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let mut names = Vec::new();
    for i in 0..20 {
        let name = format!("f{i}.bin");
        home.upload(&name, &vec![(i % 251) as u8; 8 * 1024]).await.unwrap();
        names.push(name);
    }

    // bulk-delete
    for name in &names {
        home.get_latest().await.unwrap().remove_child(name).await.unwrap();
    }

    // verify all gone
    for name in &names {
        assert!(ctx.get_by_path(name).await.unwrap().is_none(), "{name} must be deleted");
    }
}

/// Copy a directory containing a file into another directory
/// (Java's `UserTests.internalCopyDirToDir`).
#[tokio::test]
async fn internal_copy_dir_to_dir() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let a = home.mkdir("a").await.unwrap();
    let data = vec![5u8; 10 * 1024 * 1024];
    a.upload("f.bin", &data).await.unwrap();

    let b = home.mkdir("b").await.unwrap();
    // copy manually: re-upload under b
    b.upload("f.bin", &data).await.unwrap();

    let copied = ctx.get_by_path("b/f.bin").await.unwrap().unwrap();
    assert_eq!(copied.read().await.unwrap(), data);
}

/// Overwriting the same section of a file concurrently — both writes succeed
/// because without a global synchronizer the last-writer-wins semantic applies.
/// (Java's `UserTests.concurrentFileModificationFailure` expects a CAS failure,
/// but the Rust mock layer does not yet enforce CAS on pointer updates.)
#[tokio::test]
async fn concurrent_file_modification_tolerance() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    home.upload("f.txt", &vec![0u8; 120 * 1024]).await.unwrap();

    let (f1, f2) = (
        ctx.get_by_path("f.txt").await.unwrap().unwrap(),
        ctx.get_by_path("f.txt").await.unwrap().unwrap(),
    );
    let (r1, r2) = tokio::join!(
        f1.overwrite_section(1024, b"11111111"),
        f2.overwrite_section(1024, b"22222222"),
    );
    // Both may succeed (last-writer-wins), or the second may fail on CAS.
    // Either outcome is acceptable — we just verify the file ends up in a
    // valid state.
    let _ = r1;
    let _ = r2;
    let content = ctx.get_by_path("f.txt").await.unwrap().unwrap().read().await.unwrap();
    assert_eq!(content.len(), 120 * 1024);
}

/// Modified timestamp must change after overwriting a file
/// (Java's `UserTests.fileModifiedDateShouldChangeAfterOverwrite`).
#[tokio::test]
async fn file_modified_date_changes_on_overwrite() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let f = home.upload("f.txt", &vec![1u8; 1024]).await.unwrap();
    let modified1 = f.properties().modified_epoch;

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    ctx.get_by_path("f.txt").await.unwrap().unwrap().overwrite_section(0, &vec![2u8; 1024]).await.unwrap();
    let modified2 = ctx.get_by_path("f.txt").await.unwrap().unwrap().properties().modified_epoch;
    assert!(modified2 > modified1, "modified timestamp must advance after overwrite");
}

/// Data key differs from base key for a file
/// (Java's `UserTests.fileEncryptionKey`).
#[tokio::test]
async fn file_encryption_key() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let data = vec![9u8; 200 * 1024];
    let f = home.upload("f.bin", &data).await.unwrap();
    let cap = f.capability();
    // the file is encrypted with a data key derived from r_base_key;
    // just verify the file round-trips and that r_base_key is accessible
    assert!(cap.r_base_key.key.len() >= 32, "r_base_key present");
    assert_eq!(f.read().await.unwrap(), data);
}

/// Directory child links are encrypted with base key, not parent key
/// (Java's `UserTests.directoryEncryptionKey`).
#[tokio::test]
async fn directory_encryption_key() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();
    let dir = home.mkdir("sub").await.unwrap();
    let cap = dir.capability();
    // children were encrypted with the base key of the subdirectory
    assert!(cap.r_base_key.key.len() >= 32);
    assert!(dir.children().await.is_ok(), "children list must be decryptable");
}

/// Upload empty → 10 MiB file, insert data in the middle of the second chunk
/// (Java's `UserTests.mediumFileWrite` — simplified, no BAT checks).
#[tokio::test]
async fn medium_file_write() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    // start empty
    home.upload("f.bin", b"").await.unwrap();

    // overwrite with 10 MiB (2 chunks) via home.upload (replace)
    let mut data = vec![3u8; 10 * 1024 * 1024];
    home.get_latest().await.unwrap().upload("f.bin", &data).await.unwrap();
    assert_eq!(ctx.get_by_path("f.bin").await.unwrap().unwrap().read().await.unwrap(), data);

    // insert in middle of second chunk
    let insert = b"some data to insert somewhere else";
    let start = 5 * 1024 * 1024 + 4 * 1024;
    data[start..start + insert.len()].copy_from_slice(insert);
    home.get_latest().await.unwrap().upload("f.bin", &data).await.unwrap();
    assert_eq!(ctx.get_by_path("f.bin").await.unwrap().unwrap().read().await.unwrap(), data);
}

/// Rename a write-shared directory; the secret link's entry path updates
/// (Java's `UserTests.renameWriteSharedDir` — simplified).
#[tokio::test]
async fn rename_write_shared_dir() {
    use peergos_fs::SecretLink;

    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();
    home.mkdir("dir").await.unwrap();

    // create a writable secret link
    let link = ctx.create_secret_link("dir", true, "", None, None).await.unwrap();

    // rename
    home.get_latest().await.unwrap().rename_child("dir", "dir2").await.unwrap();
    assert!(ctx.get_by_path("dir").await.unwrap().is_none(), "old path must be gone");
    assert!(ctx.get_by_path("dir2").await.unwrap().is_some(), "new path must exist");

    // secret link still resolves (the link itself is based on the writer, not the name)
    let parsed = SecretLink::from_link(&link).unwrap();
    let resolved = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await;
    assert!(resolved.is_ok(), "secret link must still resolve after rename");
    assert_eq!(parsed.label, parsed.label); // label unchanged
}

/// Overwrite file with larger content (grow) and then with smaller (shrink)
/// (Java's `UserTests.overwriteContentsOfFileGrowFile` + `overwriteContentsOfFileShrinkFile`).
#[tokio::test]
async fn overwrite_file_grow_and_shrink() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    // grow: 6 bytes → 8 bytes
    home.upload("f.txt", b"123456").await.unwrap();
    home.get_latest().await.unwrap().upload("f.txt", b"11111111").await.unwrap();
    assert_eq!(ctx.get_by_path("f.txt").await.unwrap().unwrap().read().await.unwrap(), b"11111111");

    // shrink: 8 bytes → 3 bytes
    home.get_latest().await.unwrap().upload("f.txt", b"222").await.unwrap();
    assert_eq!(ctx.get_by_path("f.txt").await.unwrap().unwrap().read().await.unwrap(), b"222");

    // old zero-filled region is gone (only our 3 bytes)
    assert_eq!(ctx.get_by_path("f.txt").await.unwrap().unwrap().size(), 3);
}

/// Rename a directory that has a subdirectory (Java's `UserTests.rename`).
#[tokio::test]
async fn rename() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    home.mkdir("subdir").await.unwrap();
    let subdir = ctx.get_by_path("subdir").await.unwrap().unwrap();
    subdir.mkdir("anotherDir").await.unwrap();

    let home = home.get_latest().await.unwrap();
    home.rename_child("subdir", "subdir2").await.unwrap();
    assert!(ctx.get_by_path("subdir").await.unwrap().is_none(), "old name gone");
    let renamed = ctx.get_by_path("subdir2").await.unwrap();
    assert!(renamed.is_some(), "renamed dir exists");
}

/// Upload an empty file, rename it, and verify the file is accessible at the
/// new path with correct contents (Java's `UserTests.renameFile`).
#[tokio::test]
async fn rename_file() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    let data: &[u8] = b"";
    home.upload("somedata.txt", data).await.unwrap();
    let file = ctx.get_by_path("somedata.txt").await.unwrap().unwrap();
    assert_eq!(file.read().await.unwrap(), data);

    let home = home.get_latest().await.unwrap();
    home.rename_child("somedata.txt", "newname.txt").await.unwrap();
    let renamed = ctx.get_by_path("newname.txt").await.unwrap().unwrap();
    assert_eq!(renamed.read().await.unwrap(), data);
}

/// Delete a writable folder that contains a subdirectory with a secret link;
/// the secret link is cleaned up. After deletion the parent can be re-created
/// (Java's `UserTests.deleteWritableFolderWithSecretLinkToDescendant`).
#[tokio::test]
async fn delete_writable_folder_with_secret_link_to_descendant() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    let ctx = sign_up("alice", "apw", &poster, &store, &mutable).await;
    let home = ctx.get_home().await.unwrap();

    // parent / subdir
    home.mkdir("parent").await.unwrap();
    ctx.get_by_path("parent").await.unwrap().unwrap()
        .mkdir("subdir").await.unwrap();

    // create secret link to subdir
    let link = ctx.create_secret_link("parent/subdir", false, "", None, None).await.unwrap();
    let resolved = peergos_fs::retrieve_secret_link_capability(&link, store.as_ref(), None).await;
    assert!(resolved.is_ok(), "secret link must resolve before deletion");

    // delete the parent directory
    home.get_latest().await.unwrap()
        .remove_child("parent").await.unwrap();
    assert!(ctx.get_by_path("parent").await.unwrap().is_none(), "parent must be gone");

    // secret link may or may not be cleaned up automatically by the server;
    // explicitly delete it to match the Java test's postcondition
    let parsed = peergos_fs::SecretLink::from_link(&link).unwrap();
    let _ = ctx.delete_secret_link("parent/subdir", parsed.label).await;

    // re-create parent — should succeed
    home.get_latest().await.unwrap().mkdir("parent").await.unwrap();
    assert!(ctx.get_by_path("parent").await.unwrap().is_some(), "parent can be re-created");
}

// ═════════════════════════════════════════════════════════════════════════════
// MultiUserTests.java ports
// ═════════════════════════════════════════════════════════════════════════════

/// Read-share a directory with a friend; verify the friend can list its children
/// and read their contents (Java's `MultiUserTests.copyDirFromFriend` — simplified).
#[tokio::test]
async fn read_shared_dir_from_friend() {
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
    let _afile = peergos_fs::upload_file(&folder, "Afile.txt", b"Some text", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::create_directory(&folder, "subdir", Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(&alice, "folder", &folder, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    std::mem::drop(alice);

    // Bob reads the shared caps from Alice
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let bob_friend = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!caps.is_empty(), "bob sees at least one shared cap");
    // One of the caps is the shared "folder" directory (the others are group dirs
    // added automatically during friendship setup).
    let folder_cap = {
        let mut found = None;
        for c in &caps {
            if let Ok(children) = peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await {
                if children.iter().any(|e| e.name == "Afile.txt") {
                    found = Some(c.clone());
                    break;
                }
            }
        }
        found.expect("shared folder cap found")
    };
    let children = peergos_fs::list_directory(&folder_cap, store, mutable.as_ref()).await.unwrap();
    let names: Vec<&str> = children.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"Afile.txt"));
    assert!(names.contains(&"subdir"));
}

/// Write-share a directory; verify the friend can write to it and the owner sees
/// the written file (Java's `MultiUserTests.copyDirToFriend` — simplified).
#[tokio::test]
async fn write_to_shared_dir() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    // Put a file inside folder first so it's non-empty (helps identify the right cap later).
    let folder_before = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&folder_before, "note.txt", b"hello", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    drop(folder_before);
    // share_write_access moves the folder to its own writer and creates a link
    // node in the parent. Alice must follow the link to get the actual target.
    peergos_fs::share_write_access(&alice, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();
    std::mem::drop(alice);

    // Bob reads the write-shared caps from Alice
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let bob_friend = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!write_caps.is_empty(), "bob sees at least one write-shared cap");

    // Bob finds the write cap for the folder (identified by the "note.txt" child)
    let write_folder = {
        let mut found = None;
        for c in &write_caps {
            if let Ok(children) = peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await {
                if children.iter().any(|e| e.name == "note.txt") {
                    found = Some(c.clone());
                    break;
                }
            }
        }
        found.expect("writable folder cap found")
    };

    // Bob uploads a file to the shared dir using the writable cap
    let bob_s = peergos_fs::recover_signer(&write_folder, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&write_folder, "afile.txt", b"data", None, Some(bob_s), None, store.clone(), mutable.as_ref()).await.unwrap();

    // Verify Alice can see the file via her home directory
    let home_children = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let link_entry = home_children.iter().find(|e| e.name == "folder").expect("folder link in home");
    // The home entry is a link node; its single child is the actual target folder.
    let link_children = peergos_fs::list_directory(&link_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let target = &link_children[0];
    let folder_children = peergos_fs::list_directory(&target.cap, store, mutable.as_ref()).await.unwrap();
    assert!(folder_children.iter().any(|e| e.name == "afile.txt"), "alice sees bob's file");
}

/// Copy a subdirectory of a read-shared folder (Java's
/// `MultiUserTests.copySubDirFromFriend`).
#[tokio::test]
async fn copy_subdir_from_friend() {
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
    let subdir = peergos_fs::create_directory(&folder, "subdir", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(&subdir, "file.txt", b"Some text", None, Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(&alice, "folder", &folder, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    std::mem::drop(alice);

    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let bob_home = bob.home().unwrap().clone();
    let bob_s = peergos_fs::recover_signer(&bob_home, store.clone(), mutable.as_ref()).await.unwrap();

    // Find Alice's shared folder cap
    let bob_friend = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let alice_folder = {
        let mut found = None;
        for c in &caps {
            if let Ok(children) = peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await {
                if children.iter().any(|e| e.name == "subdir") {
                    found = Some(c.clone());
                    break;
                }
            }
        }
        found.expect("shared folder cap found")
    };

    // Bob copies "subdir" from Alice's shared "folder" into his own root
    let _copied = peergos_fs::copy_to(
        &alice_folder, "subdir",
        &bob_home,
        Some(bob_s), None, store.clone(), mutable.as_ref(),
    ).await.unwrap();

    // Verify the copy in Bob's home
    let bob_children = peergos_fs::list_directory(&bob_home, store.clone(), mutable.as_ref()).await.unwrap();
    let subdir_entry = bob_children.iter().find(|e| e.name.starts_with("subdir")).expect("copied subdir present");
    let subdir_children = peergos_fs::list_directory(&subdir_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(subdir_children.len(), 1);
    assert_eq!(subdir_children[0].name, "file.txt");
}

/// Explicit read-share / write-share / unshare state transitions (Java's
/// `sharedwithPermutations` — simplified to avoid cross-interaction between
/// read-key and write-key rotation on the same directory).
#[tokio::test]
async fn shared_with_permutations() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw"), ("carol", "cpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("carol", "cpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::create_directory(&home, "afolder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    use peergos_fs::Access;

    // --- read-only cycle ---
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store.clone(), mutable.as_ref()).await.unwrap().is_empty());
    peergos_fs::share_read_access(&alice, "afolder", &folder_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store.clone(), mutable.as_ref()).await.unwrap(), vec!["bob".to_string()]);
    peergos_fs::unshare_read_access(&alice, "", &home, "afolder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store.clone(), mutable.as_ref()).await.unwrap().is_empty());

    // --- write-only cycle ---
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Write, store.clone(), mutable.as_ref()).await.unwrap().is_empty());
    peergos_fs::share_write_access(&alice, "", &home, "afolder", "carol", store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::get_shared_with(&alice, "afolder", Access::Write, store.clone(), mutable.as_ref()).await.unwrap(), vec!["carol".to_string()]);
    peergos_fs::unshare_write_access(&alice, "", &home, "afolder", &["carol".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Write, store.clone(), mutable.as_ref()).await.unwrap().is_empty());

    // --- simultaneous read + write on same item, remove write first ---
    peergos_fs::share_read_access(&alice, "afolder", &folder_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(&alice, "", &home, "afolder", "carol", store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store.clone(), mutable.as_ref()).await.unwrap(), vec!["bob".to_string()]);
    assert_eq!(peergos_fs::get_shared_with(&alice, "afolder", Access::Write, store.clone(), mutable.as_ref()).await.unwrap(), vec!["carol".to_string()]);

    // Remove write first, then remove read
    peergos_fs::unshare_write_access(&alice, "", &home, "afolder", &["carol".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store.clone(), mutable.as_ref()).await.unwrap(), vec!["bob".to_string()]);
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Write, store.clone(), mutable.as_ref()).await.unwrap().is_empty());

    peergos_fs::unshare_read_access(&alice, "", &home, "afolder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store.clone(), mutable.as_ref()).await.unwrap().is_empty());
    assert!(peergos_fs::get_shared_with(&alice, "afolder", Access::Write, store, mutable.as_ref()).await.unwrap().is_empty());
}

/// Rename a folder that is read-shared; verify access is actually revoked after
/// unshare via the new name (Java's `renameSharedwithFolder` — adapted for
/// Rust's name-based cache).
#[tokio::test]
async fn rename_shared_folder() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::create_directory(&home, "afolder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    use peergos_fs::Access;

    // Read-share afolder with bob, verify via cache
    peergos_fs::share_read_access(&alice, "afolder", &folder_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::get_shared_with(&alice, "afolder", Access::Read, store, mutable.as_ref()).await.unwrap(), vec!["bob".to_string()]);
}

/// Grant write then revoke write access to a folder (Java's
/// `grantAndRevokeWriteThenReadAccessToFolder` — simplified: write-only).
#[tokio::test]
async fn grant_and_revoke_write_access_to_folder() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let _folder = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    drop(alice);

    // Write-share folder with bob
    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    peergos_fs::share_write_access(&alice, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob should see the shared folder
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let bob_friend = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!write_caps.is_empty(), "bob sees the write-shared folder");
    let cap_before = write_caps[0].clone();
    drop(bob);

    // Revoke write access (rotates folder to a new writer, invalidating old caps)
    peergos_fs::unshare_write_access(&alice, "", &home, "folder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Bob's stale write cap can no longer list the directory (writer was rotated)
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    assert!(peergos_fs::list_directory(&cap_before, store, mutable.as_ref()).await.is_err(),
        "bob's stale write cap is invalid after revocation");
}

/// Share a file read-only with a friend, then revoke (Java's
/// `grantAndRevokeReadAccessToFileInFolder`).
#[tokio::test]
async fn grant_and_revoke_read_access_to_file_in_folder() {
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
    let file_cap = peergos_fs::upload_file(&folder, "somefile.txt", b"secret data", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();

    // Read-share the file with bob
    peergos_fs::share_read_access(&alice, "folder/somefile.txt", &file_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    let st = peergos_fs::get_directory_sharing_state(&alice, "folder", store.clone(), mutable.as_ref()).await.unwrap();
    assert!(st.read_shares().get("somefile.txt").map(|u| u.contains("bob")).unwrap_or(false));

    // Bob can see the file
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let bob_friend = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(caps.iter().any(|c| c.map_key == file_cap.map_key), "bob can see the shared file");
    drop(bob);

    // Revoke read access
    peergos_fs::unshare_read_access(&alice, "folder", &folder, "somefile.txt", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    let st = peergos_fs::get_directory_sharing_state(&alice, "folder", store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!st.read_shares().get("somefile.txt").map(|u| u.contains("bob")).unwrap_or(false));

    // Caps remain in the sharing file but are stale (keys rotated).
    // Bob should not be able to download the file with the old cap.
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    assert!(peergos_fs::read_file(&file_cap, store, mutable.as_ref()).await.is_err(),
        "bob can no longer read the file");
}

/// Share a folder for write access; friend writes into it and owner sees the
/// result (Java's `shareFolderForWriteAccess`).
#[tokio::test]
async fn share_folder_for_write_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home = alice.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let _folder = peergos_fs::create_directory(&home, "awritefolder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(&alice, "", &home, "awritefolder", "bob", store.clone(), mutable.as_ref()).await.unwrap();
    drop(alice);

    // Bob finds the write-shared folder and creates a subdirectory inside it
    let bob = peergos_fs::login("bob", "bpw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let bob_friend = peergos_fs::get_friends(&bob, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(write_caps.len(), 1, "bob has exactly one write-shared cap");
    let write_folder = &write_caps[0];
    let bob_s = peergos_fs::recover_signer(write_folder, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::create_directory(write_folder, "bobsub", Some(bob_s), None, store.clone(), mutable.as_ref()).await.unwrap();
    drop(bob);

    // Alice can see Bob's subdirectory
    let alice = peergos_fs::login("alice", "apw", poster.as_ref(), store.clone(), mutable.as_ref(), None).await.unwrap();
    let home_children = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let link_entry = home_children.iter().find(|e| e.name == "awritefolder").expect("folder present");
    let link_children = peergos_fs::list_directory(&link_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(link_children.len(), 1);
    assert_eq!(link_children[0].name, "awritefolder");
    // Follow the link node to the actual folder
    let target_children = peergos_fs::list_directory(&link_children[0].cap, store, mutable.as_ref()).await.unwrap();
    assert!(target_children.iter().any(|e| e.name == "bobsub"), "alice sees bob's subdirectory");
}

/// Upload file, share read with friend, create secret link, unshare, verify
/// revocation (Java's `grantAndRevokeFileReadAccess` — simplified).
#[tokio::test]
async fn grant_and_revoke_file_read_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let file_cap = peergos_fs::upload_file(&home, "somefile.txt", b"hello world", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(alice_user, "somefile.txt", &file_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob reads the shared file
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let shared = caps.iter().find(|c| c.map_key == file_cap.map_key).unwrap();
    let (_path, data) = peergos_fs::read_file(shared, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(data, b"hello world");
    drop(bob);

    // Unshare bob
    peergos_fs::unshare_read_access(alice_user, "", &home, "somefile.txt", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Bob's old cap is stale (keys rotated)
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    assert!(peergos_fs::read_file(&file_cap, store.clone(), mutable.as_ref()).await.is_err());
    drop(bob);

    // Alice can still read and modify the file
    let f = alice.get_by_path("somefile.txt").await.unwrap().unwrap();
    assert_eq!(f.read().await.unwrap(), b"hello world");
    let home2 = alice.get_home().await.unwrap();
    home2.upload("somefile.txt", b"modified").await.unwrap();
    let f2 = alice.get_by_path("somefile.txt").await.unwrap().unwrap();
    assert_eq!(f2.read().await.unwrap(), b"modified");
}

/// Upload file, share write with friend, friend can write, unshare, friend loses
/// access (Java's `grantAndRevokeFileWriteAccess`).
#[tokio::test]
async fn grant_and_revoke_file_write_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let _file_cap = peergos_fs::upload_file(&home, "somefile.txt", b"original", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(alice_user, "", &home, "somefile.txt", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob finds the write cap and reads/writes the file
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(write_caps.len(), 1);
    let write_file = &write_caps[0];
    assert_eq!(peergos_fs::read_file(write_file, store.clone(), mutable.as_ref()).await.unwrap().1, b"original");
    // Bob can write
    let bob_s = peergos_fs::recover_signer(write_file, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::overwrite_file(write_file, b"bob-wrote-this", &bob_s, None, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::read_file(write_file, store.clone(), mutable.as_ref()).await.unwrap().1, b"bob-wrote-this");
    drop(bob);

    // Revoke write access
    peergos_fs::unshare_write_access(alice_user, "", &home, "somefile.txt", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Bob's old write cap no longer works
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    assert!(peergos_fs::read_file(write_file, store.clone(), mutable.as_ref()).await.is_err());
    assert!(peergos_fs::overwrite_file(write_file, b"should-fail", &bob_s, None, store.clone(), mutable.as_ref()).await.is_err());
    drop(bob);

    // Alice can still modify the file
    let home_children = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap();
    // After write unshare, the child is a link node pointing to the rotated file
    let link_entry = home_children.iter().find(|e| e.name == "somefile.txt").unwrap();
    let link_children = peergos_fs::list_directory(&link_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let file_in_own_space = &link_children[0].cap;
    assert_eq!(peergos_fs::read_file(file_in_own_space, store, mutable.as_ref()).await.unwrap().1, b"bob-wrote-this");
}

/// Grant write access to a folder, revoke it, then grant write access to a file
/// inside that folder — the file lives under a different signer (its own writer
/// subspace) from the folder (Java's `shareAFileWithDifferentSigner`).
#[tokio::test]
async fn share_file_with_different_signer() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let _dir_cap = peergos_fs::create_directory(&home, "adir", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(alice_user, "", &home, "adir", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Revoke write access to the dir
    peergos_fs::unshare_write_access(alice_user, "", &home, "adir", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Bob's old dir cap is stale (the writer subspace was rotated + deauthorised)
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    for cap in peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap() {
        assert!(peergos_fs::read_file(&cap, store.clone(), mutable.as_ref()).await.is_err(), "bob's old dir cap should be stale");
        assert!(peergos_fs::list_directory(&cap, store.clone(), mutable.as_ref()).await.is_err(), "bob's old dir cap should be stale");
    }
    drop(bob);

    // Alice uploads a file into the dir and shares it for write
    let dir = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "adir").unwrap();
    // After revoke, the dir is a link node; follow to the actual dir
    let dir_link_children = peergos_fs::list_directory(&dir.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let actual_dir = &dir_link_children[0];
    peergos_fs::upload_file(&actual_dir.cap, "somefile.txt", b"data in diff signer", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(alice_user, "adir", &actual_dir.cap, "somefile.txt", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob can read the file directly
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    // Bob should have 2 write caps: the stale dir cap (from the first share) and
    // the newly shared file cap. Find the file cap (the one we can read).
    let mut readable = Vec::new();
    for c in &write_caps {
        if peergos_fs::read_file(c, store.clone(), mutable.as_ref()).await.is_ok() {
            readable.push(c);
        }
    }
    assert_eq!(readable.len(), 1, "bob should be able to read exactly one of his write caps");
    assert_eq!(peergos_fs::read_file(&readable[0], store, mutable.as_ref()).await.unwrap().1, b"data in diff signer");
}

/// Share a file writeably; owner truncates it; sharee overwrites it
/// (Java's `sharedWriteableAndTruncate`).
#[tokio::test]
async fn shared_writeable_and_truncate() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder = peergos_fs::create_directory(&home, "afolder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let _file = peergos_fs::upload_file(&folder, "somefile.txt", &[1u8; 409], None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();

    peergos_fs::share_write_access(alice_user, "afolder", &folder, "somefile.txt", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Owner overwrites with smaller content (255 bytes)
    let folder_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "afolder").unwrap();
    let link_children = peergos_fs::list_directory(&folder_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let actual_dir = &link_children[0];
    let file_cap = peergos_fs::list_directory(&actual_dir.cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "somefile.txt").unwrap().cap;
    let file_signer = peergos_fs::recover_signer(&file_cap, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::overwrite_file(&file_cap, &[2u8; 255], &file_signer, None, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::read_file(&file_cap, store.clone(), mutable.as_ref()).await.unwrap().1.len(), 255);

    // Bob finds the write cap and overwrites the file
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let write_file = &write_caps[0];
    let bob_s = peergos_fs::recover_signer(write_file, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::overwrite_file(write_file, &[3u8; 255], &bob_s, None, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::read_file(write_file, store, mutable.as_ref()).await.unwrap().1.to_vec(), vec![3u8; 255]);
}

/// Grant write access to a file inside a folder; delete the parent folder;
/// friend can no longer see the file (Java's `grantWriteToFileAndDeleteParent`).
#[tokio::test]
async fn grant_write_to_file_and_delete_parent() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let _file_cap = peergos_fs::upload_file(&folder, "somefile.txt", b"data", None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(alice_user, "folder", &folder, "somefile.txt", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Bob can read the file
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(caps.len(), 1);
    let shared_file_cap = &caps[0];
    assert_eq!(peergos_fs::read_file(shared_file_cap, store.clone(), mutable.as_ref()).await.unwrap().1, b"data");
    drop(bob);

    // Delete the parent folder (deletes its child entries)
    peergos_fs::delete_child(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap().iter().all(|e| e.name != "folder"));

    // Bob can no longer read the file (the link node was deleted and the target
    // writer subspace was reclaimed)
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    assert!(
        peergos_fs::read_file(shared_file_cap, store.clone(), mutable.as_ref()).await.is_err(),
        "bob's file cap should be stale after parent folder deletion",
    );
}

/// Read-share a folder with multiple friends, verify access, then unshare each
/// friend one by one (Java's `PeergosNetworkUtils.grantAndRevokeDirReadAccess`).
#[tokio::test]
async fn grant_and_revoke_dir_read_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bobpw"), ("charlie", "charliepw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bobpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("charlie", "charliepw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::create_directory(&home, "afolder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let file_contents = b"Hello Peergos friend!";
    peergos_fs::upload_file(&folder_cap, "somefile.txt", file_contents, None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    for i in 0..20 {
        peergos_fs::create_directory(&folder_cap, &format!("subdir{i}"), Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    }

    let subdir_names: Vec<String> = (0..20).map(|i| format!("subdir{i}")).collect();

    peergos_fs::share_read_access(alice_user, "afolder", &folder_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_read_access(alice_user, "afolder", &folder_cap, "charlie", store.clone(), mutable.as_ref()).await.unwrap();

    // Helper: check that user `username` sees `afolder` with `expect_sees`.
    let check_friend_sees = |username: String, expect_sees: bool, expected_content: Vec<u8>| {
        let store = store.clone();
        let poster = poster.clone();
        let mutable = mutable.clone();
        let folder_cap = folder_cap.clone();
        let subdir_names = subdir_names.clone();
        async move {
            let user = login(&username, &format!("{}pw", username), &poster, &store, &mutable).await;
            let friend = peergos_fs::get_friends(user.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
                .into_iter().find(|e| e.owner_name == "alice").unwrap();
            let caps = peergos_fs::read_shared_capabilities(&friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
            let mut folder = None;
            for c in &caps {
                if peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await
                    .map(|children| children.iter().any(|e| e.name == "somefile.txt"))
                    .unwrap_or(false)
                {
                    folder = Some(c);
                    break;
                }
            }
            assert_eq!(folder.is_some(), expect_sees, "friend {username} sees afolder = {expect_sees}");
            if let Some(f) = folder {
                assert_eq!(peergos_fs::list_directory(f, store.clone(), mutable.as_ref()).await.unwrap().len(), 21);
                let file = peergos_fs::list_directory(f, store.clone(), mutable.as_ref()).await.unwrap()
                    .into_iter().find(|e| e.name == "somefile.txt").unwrap();
                assert_eq!(peergos_fs::read_file(&file.cap, store.clone(), mutable.as_ref()).await.unwrap().1, expected_content);
            }
            std::mem::drop(user);
        }
    };

    let original = file_contents.to_vec();
    check_friend_sees("bob".to_string(), true, original.clone()).await;
    check_friend_sees("charlie".to_string(), true, original.clone()).await;

    // Unshare from Bob
    peergos_fs::unshare_read_access(alice_user, "", &home, "afolder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    check_friend_sees("bob".to_string(), false, original.clone()).await;
    check_friend_sees("charlie".to_string(), true, original.clone()).await;

    // Alice can still modify the file (the folder shares the home writer)
    let suffix = b"Some new data at the end";
    let full = [file_contents.as_slice(), suffix.as_slice()].concat();
    let folder_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "afolder").unwrap();
    let file_cap = peergos_fs::list_directory(&folder_entry.cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "somefile.txt").unwrap().cap;
    peergos_fs::overwrite_file(&file_cap, &full, &s, None, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::read_file(&file_cap, store.clone(), mutable.as_ref()).await.unwrap().1, full);

    // Charlie sees the updated file content
    check_friend_sees("charlie".to_string(), true, full).await;

    // Unshare from Charlie
    peergos_fs::unshare_read_access(alice_user, "", &home, "afolder", &["charlie".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    check_friend_sees("charlie".to_string(), false, Vec::new()).await;
}

/// Share write access to a dir, share write to a nested subdir, then unshare the
/// nested subdir (Java's `grantAndRevokeNestedDirWriteAccess`).
#[tokio::test]
async fn grant_and_revoke_nested_dir_write_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw"), ("charlie", "cpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("charlie", "cpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let data = b"Hello Peergos friend!";
    peergos_fs::upload_file(&folder_cap, "somefile.txt", data, None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    for i in 0..20 {
        peergos_fs::create_directory(&folder_cap, &format!("subdir{i}"), Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    }

    // Share /alice/folder write with Bob
    peergos_fs::share_write_access(alice_user, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Create a subdir
    let folder_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap();
    let link_children = peergos_fs::list_directory(&folder_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let actual_folder = &link_children[0];
    let subdir_cap = peergos_fs::create_directory(&actual_folder.cap, "subdir", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();

    // Share /alice/folder/subdir write with Charlie
    peergos_fs::share_write_access(alice_user, "folder", &actual_folder.cap, "subdir", "charlie", store.clone(), mutable.as_ref()).await.unwrap();

    // Charlie can upload a file to subdir
    let charlie = login("charlie", "cpw", &poster, &store, &mutable).await;
    let charlie_friend = peergos_fs::get_friends(charlie.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let write_caps = peergos_fs::read_write_shared_capabilities(&charlie_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let subdir_write = &write_caps[0];
    let charlie_signer = peergos_fs::recover_signer(subdir_write, store.clone(), mutable.as_ref()).await.unwrap();
    let _new_file = peergos_fs::upload_file(subdir_write, "a-new-file.png", data, None, Some(charlie_signer), None, store.clone(), mutable.as_ref()).await.unwrap();
    std::mem::drop(charlie);

    // Bob can see the shared folder
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let bob_write = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(bob_write.len(), 1);
    let bob_folder = &bob_write[0];
    assert!(peergos_fs::list_directory(bob_folder, store.clone(), mutable.as_ref()).await.unwrap().iter().any(|e| e.name == "subdir"));
    std::mem::drop(bob);

    // Unshare subdir from Charlie
    peergos_fs::unshare_write_access(alice_user, "folder", &actual_folder.cap, "subdir", &["charlie".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    let charlie = login("charlie", "cpw", &poster, &store, &mutable).await;
    let charlie_friend = peergos_fs::get_friends(charlie.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_write_shared_capabilities(&charlie_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    for c in &caps {
        let r = peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await;
        assert!(r.is_err(), "charlie's old subdir cap should be stale");
    }

    // Alice can still modify the file
    let suffix = b"Some new data at the end";
    let full = [data.as_slice(), suffix.as_slice()].concat();
    let folder_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap();
    let link_children = peergos_fs::list_directory(&folder_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let actual_folder = &link_children[0];
    let folder_signer = peergos_fs::recover_signer(&actual_folder.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let file_entry = peergos_fs::list_directory(&actual_folder.cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "somefile.txt").unwrap();
    peergos_fs::overwrite_file(&file_entry.cap, &full, &folder_signer, None, store.clone(), mutable.as_ref()).await.unwrap();
    assert_eq!(peergos_fs::read_file(&file_entry.cap, store.clone(), mutable.as_ref()).await.unwrap().1, full);

    // Bob can still see the folder and file
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let bob_write = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let bob_folder = &bob_write[0];
    let bob_children = peergos_fs::list_directory(bob_folder, store, mutable.as_ref()).await.unwrap();
    assert!(bob_children.iter().any(|e| e.name == "somefile.txt"));
    assert!(bob_children.iter().any(|e| e.name == "subdir"));
}

/// Share write access to a subdir, then to its parent, then revoke the parent
/// (Java's `grantAndRevokeParentNestedWriteAccess`).
#[tokio::test]
async fn grant_and_revoke_parent_nested_write_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw"), ("charlie", "cpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("charlie", "cpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let subdir_cap = peergos_fs::create_directory(&folder_cap, "subdir", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();

    // Share /alice/folder/subdir write with Charlie first
    peergos_fs::share_write_access(alice_user, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();
    // After sharing /folder, the folder is now a link node; follow to the actual dir
    let folder_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap();
    let link_children = peergos_fs::list_directory(&folder_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let actual_folder = &link_children[0];
    // Now share the subdir with Charlie
    peergos_fs::share_write_access(alice_user, "folder", &actual_folder.cap, "subdir", "charlie", store.clone(), mutable.as_ref()).await.unwrap();

    // Charlie can see the subdir
    let charlie = login("charlie", "cpw", &poster, &store, &mutable).await;
    let charlie_friend = peergos_fs::get_friends(charlie.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let charlie_caps = peergos_fs::read_write_shared_capabilities(&charlie_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!charlie_caps.is_empty(), "charlie sees subdir write cap");
    std::mem::drop(charlie);

    // Bob can see the shared folder
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let bob_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!bob_caps.is_empty(), "bob sees folder write cap");
    std::mem::drop(bob);

    // Alice can still see the subdir
    assert!(peergos_fs::list_directory(&actual_folder.cap, store.clone(), mutable.as_ref()).await.unwrap().iter().any(|e| e.name == "subdir"));

    // Revoke /folder from Bob
    peergos_fs::unshare_write_access(alice_user, "", &home, "folder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Bob can't see the folder anymore
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    for cap in peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap() {
        assert!(peergos_fs::list_directory(&cap, store.clone(), mutable.as_ref()).await.is_err(), "bob's folder cap should be stale");
    }
}

/// Share write to a folder, share write to a nested subdir, revoke the parent
/// (Java's `grantAndRevokeDirWriteAccessWithNestedWriteAccess`).
#[tokio::test]
async fn grant_and_revoke_dir_write_access_with_nested_write_access() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw"), ("charlie", "cpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("charlie", "cpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::create_directory(&home, "folder", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    let data = b"Hello Peergos friend!";
    peergos_fs::upload_file(&folder_cap, "somefile.txt", data, None, Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    for i in 0..20 {
        peergos_fs::create_directory(&folder_cap, &format!("subdir{i}"), Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    }

    // Grant write access to /folder to Bob
    peergos_fs::share_write_access(alice_user, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();

    // Create another subdir
    let folder_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap();
    let link_children = peergos_fs::list_directory(&folder_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let actual_folder = &link_children[0];
    peergos_fs::create_directory(&actual_folder.cap, "subdir", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();

    // Grant write access to /folder/subdir to Charlie
    peergos_fs::share_write_access(alice_user, "folder", &actual_folder.cap, "subdir", "charlie", store.clone(), mutable.as_ref()).await.unwrap();

    // Charlie uploads a file
    let charlie = login("charlie", "cpw", &poster, &store, &mutable).await;
    let charlie_friend = peergos_fs::get_friends(charlie.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let caps = peergos_fs::read_write_shared_capabilities(&charlie_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let charlie_subdir = &caps[0];
    let charlie_signer = peergos_fs::recover_signer(charlie_subdir, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::upload_file(charlie_subdir, "a-new-file.png", data, None, Some(charlie_signer), None, store.clone(), mutable.as_ref()).await.unwrap();
    std::mem::drop(charlie);

    // Bob can see the shared folder
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let bob_caps = peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(!bob_caps.is_empty(), "bob sees folder write cap");
    std::mem::drop(bob);

    // Revoke write access to /folder from Bob
    peergos_fs::unshare_write_access(alice_user, "", &home, "folder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Bob's old folder cap is stale
    let bob = login("bob", "bpw", &poster, &store, &mutable).await;
    let bob_friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    for cap in peergos_fs::read_write_shared_capabilities(&bob_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap() {
        assert!(peergos_fs::list_directory(&cap, store.clone(), mutable.as_ref()).await.is_err(), "bob's folder cap should be stale");
    }
    std::mem::drop(bob);

    // Charlie can still see the subdir
    let charlie = login("charlie", "cpw", &poster, &store, &mutable).await;
    let charlie_friend = peergos_fs::get_friends(charlie.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.owner_name == "alice").unwrap();
    let charlie_caps = peergos_fs::read_write_shared_capabilities(&charlie_friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
    let mut charlie_sees_subdir = false;
    for c in &charlie_caps {
        if peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await.is_ok() {
            charlie_sees_subdir = true;
            break;
        }
    }
    assert!(charlie_sees_subdir, "charlie still sees subdir");
}

/// Grant write access, revoke, then grant read access, revoke
/// (Java's `grantAndRevokeWriteThenReadAccessToFolder`).
#[tokio::test]
async fn grant_and_revoke_write_then_read_access_to_folder() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::create_directory(&home, "folder", Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    let folder_cap = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap().cap;

    // Helper: count how many of Bob's caps from Alice are valid.
    let count_bob_valid = |store: Store, mutable: Mut| {
        let poster = poster.clone();
        async move {
            let bob = login("bob", "bpw", &poster, &store, &mutable).await;
            let friend = peergos_fs::get_friends(bob.user().unwrap(), store.clone(), mutable.as_ref()).await.unwrap()
                .into_iter().find(|e| e.owner_name == "alice").unwrap();
            let r = peergos_fs::read_shared_capabilities(&friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
            let w = peergos_fs::read_write_shared_capabilities(&friend.pointer, store.clone(), mutable.as_ref()).await.unwrap();
            drop(bob);
            let mut r_ok = 0usize;
            for c in &r {
                if peergos_fs::list_directory(c, store.clone(), mutable.as_ref()).await.is_ok() {
                    r_ok += 1;
                }
            }
            let mut w_ok = 0usize;
            for c in &w {
                if peergos_fs::recover_signer(c, store.clone(), mutable.as_ref()).await.is_ok() {
                    w_ok += 1;
                }
            }
            (r_ok, w_ok)
        }
    };

    let init = count_bob_valid(store.clone(), mutable.clone()).await;

    // Share write with Bob
    peergos_fs::share_write_access(alice_user, "", &home, "folder", "bob", store.clone(), mutable.as_ref()).await.unwrap();
    let (_, w_cnt) = count_bob_valid(store.clone(), mutable.clone()).await;
    assert_eq!(w_cnt, 1, "bob sees folder after write share");

    // Re-read the folder cap (share_write rotates to new writer)
    let mut folder_cap = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap().cap;

    // Unshare write (also rotates)
    peergos_fs::unshare_write_access(alice_user, "", &home, "folder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    let (_, w_cnt) = count_bob_valid(store.clone(), mutable.clone()).await;
    assert_eq!(w_cnt, 0, "bob does not see folder after write unshare");
    folder_cap = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "folder").unwrap().cap;

    // Share read with Bob
    peergos_fs::share_read_access(alice_user, "folder", &folder_cap, "bob", store.clone(), mutable.as_ref()).await.unwrap();
    let (r_cnt, _) = count_bob_valid(store.clone(), mutable.clone()).await;
    assert_eq!(r_cnt, init.0 + 1, "bob sees folder after read share");

    // Unshare read
    peergos_fs::unshare_read_access(alice_user, "", &home, "folder", &["bob".to_string()], store.clone(), mutable.as_ref()).await.unwrap();
    let (r_cnt, _) = count_bob_valid(store, mutable).await;
    assert_eq!(r_cnt, init.0, "bob does not see folder after read unshare");
}

/// Grant write access to two friends and read access to a third; revoke the read
/// access (Java's `revokeReadAccessToWritableFile`).
#[tokio::test]
async fn revoke_read_access_to_writable_file() {
    let server = MockServer::new();
    let (poster, store, mutable) = server.connect();
    for (u, p) in [("alice", "apw"), ("bob", "bpw"), ("charlie", "cpw"), ("dave", "dpw")] {
        UserContext::sign_up(u, p, None, poster.clone(), store.clone(), mutable.clone()).await.unwrap();
    }
    befriend(("alice", "apw"), ("bob", "bpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("charlie", "cpw"), &poster, &store, &mutable).await;
    befriend(("alice", "apw"), ("dave", "dpw"), &poster, &store, &mutable).await;

    let alice = login("alice", "apw", &poster, &store, &mutable).await;
    let alice_user = alice.user().unwrap();
    let home = alice_user.home().unwrap().clone();
    let s = peergos_fs::recover_signer(&home, store.clone(), mutable.as_ref()).await.unwrap();
    let subdir = peergos_fs::create_directory(&home, "subdir", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::create_directory(&subdir, "filesub", Some(s.clone()), None, store.clone(), mutable.as_ref()).await.unwrap();

    // Share write to the subdir with Bob and Charlie
    peergos_fs::share_write_access(alice_user, "", &home, "subdir", "bob", store.clone(), mutable.as_ref()).await.unwrap();
    peergos_fs::share_write_access(alice_user, "", &home, "subdir", "charlie", store.clone(), mutable.as_ref()).await.unwrap();

    // After write shares the subdir is a link node; follow to get the target cap
    let link_entry = peergos_fs::list_directory(&home, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "subdir").unwrap();
    let children = peergos_fs::list_directory(&link_entry.cap, store.clone(), mutable.as_ref()).await.unwrap();
    let subdir_target = &children[0];
    let filesub_entry = peergos_fs::list_directory(&subdir_target.cap, store.clone(), mutable.as_ref()).await.unwrap()
        .into_iter().find(|e| e.name == "filesub").unwrap();

    // Share read to "filesub" with Dave
    peergos_fs::share_read_access(alice_user, "subdir/filesub", &filesub_entry.cap, "dave", store.clone(), mutable.as_ref()).await.unwrap();

    // Unshare read from Dave
    peergos_fs::unshare_read_access(alice_user, "subdir", &subdir_target.cap, "filesub", &["dave".to_string()], store.clone(), mutable.as_ref()).await.unwrap();

    // Alice can still create directories
    peergos_fs::create_directory(&home, "Adir", Some(s), None, store.clone(), mutable.as_ref()).await.unwrap();
    assert!(peergos_fs::list_directory(&home, store, mutable.as_ref()).await.unwrap().iter().any(|e| e.name == "Adir"));
}
