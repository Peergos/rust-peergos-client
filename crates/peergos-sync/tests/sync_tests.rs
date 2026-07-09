use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;

use peergos_sync::file_state::FileState;
use peergos_sync::local_fs::LocalFileSystem;
use peergos_sync::state::{RamTreeState, SyncState};
use peergos_sync::sync::sync_dir;
use rand::RngCore;
use rand::SeedableRng;

fn random_bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
}

fn create_file(base: &Path, name: &str, data: &[u8]) {
    std::fs::write(base.join(name), data).unwrap();
}

fn run_rename(filesize: usize) {
    for (old_name, new_name, sync_local_deletes, sync_remote_deletes) in [
        ("file.bin", "newfile.bin", true, true),
        ("file.bin", "newfile.bin", false, false),
        ("newfile.bin", "file.bin", true, true),
        ("newfile.bin", "file.bin", false, false),
    ] {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();

        let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
        let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
        let mut synced = RamTreeState::new();

        let log = &|_msg: &str| {};

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

            let data = random_bytes(filesize, 42);
            create_file(tmp1.path(), old_name, &data);

            sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
            assert!(synced.by_path(old_name).is_some(), "{old_name} should exist in synced");

            // rename
            std::fs::rename(tmp1.path().join(old_name), tmp1.path().join(new_name)).unwrap();
            sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
            assert!(synced.by_path(old_name).is_none(), "{old_name} should be removed from synced after rename");
            assert!(synced.by_path(new_name).is_some(), "{new_name} should exist in synced after rename");

            // stable
            sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
            assert!(synced.by_path(old_name).is_none(), "stable: {old_name} should remain removed");
            assert!(synced.by_path(new_name).is_some(), "stable: {new_name} should remain in synced");
        });
    }
}

/// Port of SyncTests.rename() — rename a file on the local side and verify it's synced to remote.
#[test]
fn rename_small() {
    run_rename(1024);
}

#[test]
fn rename_large() {
    run_rename(6 * 1024 * 1024);
}

#[test]
fn renames_with_duplicates() {
    let filesize = 1024;
    for copies in 2..15 {
        for renames in 1..=copies {
            let tmp1 = tempfile::tempdir().unwrap();
            let tmp2 = tempfile::tempdir().unwrap();

            let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
            let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
            let mut synced = RamTreeState::new();

            let ops = RefCell::new(Vec::new());
            let log = &|msg: &str| ops.borrow_mut().push(msg.to_string());

            tokio::runtime::Runtime::new().unwrap().block_on(async {
                sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();

                let data = random_bytes(filesize, 42);
                for i in 0..copies {
                    create_file(tmp1.path(), &format!("{i}_file.bin"), &data);
                }

                sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
                for i in 0..copies {
                    assert!(synced.by_path(&format!("{i}_file.bin")).is_some(), "copy {i} should exist");
                }
                assert_eq!(synced.all_file_paths().len(), copies as usize);

                ops.borrow_mut().clear();
                for i in 0..renames {
                    std::fs::rename(tmp1.path().join(format!("{i}_file.bin")), tmp1.path().join(format!("{i}_newfile.bin"))).unwrap();
                }
                sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
                for i in 0..renames {
                    assert!(synced.by_path(&format!("{i}_file.bin")).is_none(), "renamed {i} old should be removed");
                    assert!(synced.by_path(&format!("{i}_newfile.bin")).is_some(), "renamed {i} new should exist");
                }
                let collected: Vec<String> = ops.borrow().clone();
                assert!(collected.iter().all(|op| !op.contains("upload")), "no upload ops expected: {collected:?}");
                assert!(collected.iter().any(|op| op.contains("Moving")), "Moving ops expected: {collected:?}");

                ops.borrow_mut().clear();
                sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
                for i in 0..renames {
                    assert!(synced.by_path(&format!("{i}_file.bin")).is_none(), "stable: old should be removed");
                    assert!(synced.by_path(&format!("{i}_newfile.bin")).is_some(), "stable: new should exist");
                }
            });
        }
    }
}

#[test]
fn rename_ignoring_deletes() {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, false, false, &mut synced, log).await.unwrap();

        let data = random_bytes(6 * 1024 * 1024, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, false, false, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        std::fs::rename(tmp1.path().join("file.bin"), tmp1.path().join("newfile.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, false, false, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_none());
        assert!(synced.by_path("newfile.bin").is_some());

        sync_dir(&local_fs, &remote_fs, false, false, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_none());
        assert!(synced.by_path("newfile.bin").is_some());
    });
}

#[test]
fn moves() {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();

        let data = random_bytes(6 * 1024 * 1024, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        // move to subdir
        let subdir = tmp1.path().join("subdir");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::rename(tmp1.path().join("file.bin"), subdir.join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_none());
        let file_rel_path = "subdir/file.bin";
        assert!(synced.by_path(file_rel_path).is_some(), "file should be at {file_rel_path}");

        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_none());
        assert!(synced.by_path(file_rel_path).is_some());

        // move back
        std::fs::rename(subdir.join("file.bin"), tmp1.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.by_path(file_rel_path).is_none());

        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.by_path(file_rel_path).is_none());

        assert!(synced.get_in_progress_copies().is_empty());
    });
}

#[test]
fn android_mod_time() {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();

        let data = random_bytes(6 * 1024, 42);
        create_file(tmp2.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        // local gets the file (as synced copy)
        std::fs::write(tmp1.path().join("file.bin"), &data).unwrap();
        // modify remote
        let mut remote_data = data.clone();
        remote_data.extend_from_slice(b"add to end");
        std::fs::write(tmp2.path().join("file.bin"), &remote_data).unwrap();

        let ops = RefCell::new(Vec::new());
        let log = &|msg: &str| ops.borrow_mut().push(msg.to_string());

        sync_dir(&local_fs, &remote_fs, true, true, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert_eq!(synced.all_file_paths().len(), 1);
    });
}

fn run_ignore_local_delete_before_conflict(file_size: usize) {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = false;
    let sync_remote_deletes = true;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        // delete local, verify remote not deleted
        std::fs::remove_file(tmp1.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(tmp2.path().join("file.bin").exists());
        assert!(!tmp1.path().join("file.bin").exists());
        assert!(synced.has_local_delete("file.bin"));

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.has_local_delete("file.bin"));
        assert!(tmp2.path().join("file.bin").exists());
        assert!(!tmp1.path().join("file.bin").exists());

        // add a different local file with same name (should be renamed, then remote synced)
        let data2 = random_bytes(file_size + 1024 * 1024, 28);
        create_file(tmp1.path(), "file.bin", &data2);
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let remote_bytes = std::fs::read(tmp2.path().join("file.bin")).unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("file.bin")).unwrap();
        assert_eq!(remote_bytes, data, "remote should have original data");
        assert_eq!(local_bytes, data, "local should have original data (remote copied back)");
        assert!(!synced.has_local_delete("file.bin"));
        assert_eq!(synced.all_file_paths().len(), 2);
    });
}

#[test]
fn ignore_local_delete_before_conflict_small() {
    run_ignore_local_delete_before_conflict(1024);
}

#[test]
fn ignore_local_delete_before_conflict_large() {
    run_ignore_local_delete_before_conflict(6 * 1024 * 1024);
}

fn run_ignore_local_delete_before_restore(file_size: usize) {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = false;
    let sync_remote_deletes = true;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        std::fs::remove_file(tmp1.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(tmp2.path().join("file.bin").exists());
        assert!(synced.has_local_delete("file.bin"));

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.has_local_delete("file.bin"));
        assert!(tmp2.path().join("file.bin").exists());

        // restore local file
        create_file(tmp1.path(), "file.bin", &data);
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        let remote_bytes = std::fs::read(tmp2.path().join("file.bin")).unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("file.bin")).unwrap();
        assert_eq!(remote_bytes, data);
        assert_eq!(local_bytes, data);
        assert!(!synced.has_local_delete("file.bin"));
        assert_eq!(synced.all_file_paths().len(), 1);
    });
}

#[test]
fn ignore_local_delete_before_restore_small() {
    run_ignore_local_delete_before_restore(1024);
}

#[test]
fn ignore_local_delete_before_restore_large() {
    run_ignore_local_delete_before_restore(6 * 1024 * 1024);
}

fn run_ignore_local_delete_before_remote_modification(file_size: usize) {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = false;
    let sync_remote_deletes = true;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        std::fs::remove_file(tmp1.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(tmp2.path().join("file.bin").exists());
        assert!(synced.has_local_delete("file.bin"));

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.has_local_delete("file.bin"));
        assert!(tmp2.path().join("file.bin").exists());

        // modify remote (should be copied to local)
        let data2 = random_bytes(file_size + 1024 * 1024, 28);
        std::fs::remove_file(tmp2.path().join("file.bin")).unwrap();
        create_file(tmp2.path(), "file.bin", &data2);
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let remote_bytes = std::fs::read(tmp2.path().join("file.bin")).unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("file.bin")).unwrap();
        assert_eq!(remote_bytes, data2);
        assert_eq!(local_bytes, data2);
        assert!(!synced.has_local_delete("file.bin"));
        assert_eq!(synced.all_file_paths().len(), 1);
    });
}

#[test]
fn ignore_local_delete_before_remote_modification_small() {
    run_ignore_local_delete_before_remote_modification(1024);
}

#[test]
fn ignore_local_delete_before_remote_modification_large() {
    run_ignore_local_delete_before_remote_modification(6 * 1024 * 1024);
}

fn run_ignore_remote_delete_before_conflict(file_size: usize) {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = true;
    let sync_remote_deletes = false;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        std::fs::remove_file(tmp2.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(tmp1.path().join("file.bin").exists());
        assert!(synced.has_remote_delete("file.bin"));

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.has_remote_delete("file.bin"));
        assert!(tmp1.path().join("file.bin").exists());

        // add a different remote file with same name (local should be renamed, then new remote synced)
        let data2 = random_bytes(file_size + 1024 * 1024, 28);
        create_file(tmp2.path(), "file.bin", &data2);
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let remote_bytes = std::fs::read(tmp2.path().join("file.bin")).unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("file.bin")).unwrap();
        assert_eq!(remote_bytes, data2);
        assert_eq!(local_bytes, data2);
        assert!(!synced.has_remote_delete("file.bin"));

        let paths: HashSet<String> = synced.all_file_paths().into_iter().collect();
        assert_eq!(paths.len(), 2);
        let renamed = paths.iter().find(|p| *p != "file.bin").unwrap();
        let renamed_local = std::fs::read(tmp1.path().join(&renamed)).unwrap();
        let renamed_remote = std::fs::read(tmp2.path().join(&renamed)).unwrap();
        assert_eq!(renamed_local, data);
        assert_eq!(renamed_remote, data);
    });
}

#[test]
fn ignore_remote_delete_before_conflict_small() {
    run_ignore_remote_delete_before_conflict(1024);
}

#[test]
fn ignore_remote_delete_before_conflict_large() {
    run_ignore_remote_delete_before_conflict(6 * 1024 * 1024);
}

fn run_ignore_remote_delete_before_restore(file_size: usize) {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = true;
    let sync_remote_deletes = false;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        std::fs::remove_file(tmp2.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(tmp1.path().join("file.bin").exists());
        assert!(synced.has_remote_delete("file.bin"));

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.has_remote_delete("file.bin"));
        assert!(tmp1.path().join("file.bin").exists());

        // restore remote
        create_file(tmp2.path(), "file.bin", &data);
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        let remote_bytes = std::fs::read(tmp2.path().join("file.bin")).unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("file.bin")).unwrap();
        assert_eq!(remote_bytes, data);
        assert_eq!(local_bytes, data);
        assert!(!synced.has_remote_delete("file.bin"));
        assert_eq!(synced.all_file_paths().len(), 1);
    });
}

#[test]
fn ignore_remote_delete_before_restore_small() {
    run_ignore_remote_delete_before_restore(1024);
}

#[test]
fn ignore_remote_delete_before_restore_large() {
    run_ignore_remote_delete_before_restore(6 * 1024 * 1024);
}

fn run_ignore_remote_delete_before_remote_modification(file_size: usize) {
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = true;
    let sync_remote_deletes = false;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "file.bin", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());

        std::fs::remove_file(tmp2.path().join("file.bin")).unwrap();
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(tmp1.path().join("file.bin").exists());
        assert!(synced.has_remote_delete("file.bin"));

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        assert!(synced.by_path("file.bin").is_some());
        assert!(synced.has_remote_delete("file.bin"));
        assert!(tmp1.path().join("file.bin").exists());

        // modify local (should be copied to remote)
        let data2 = random_bytes(file_size + 1024 * 1024, 28);
        std::fs::remove_file(tmp1.path().join("file.bin")).unwrap();
        create_file(tmp1.path(), "file.bin", &data2);
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let remote_bytes = std::fs::read(tmp2.path().join("file.bin")).unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("file.bin")).unwrap();
        assert_eq!(remote_bytes, data2);
        assert_eq!(local_bytes, data2);
        assert!(!synced.has_remote_delete("file.bin"));
        assert_eq!(synced.all_file_paths().len(), 1);
    });
}

#[test]
fn ignore_remote_delete_before_remote_modification_small() {
    run_ignore_remote_delete_before_remote_modification(1024);
}

#[test]
fn ignore_remote_delete_before_remote_modification_large() {
    run_ignore_remote_delete_before_remote_modification(6 * 1024 * 1024);
}

#[test]
fn modify_large_file() {
    let file_size = 6 * 1024 * 1024;
    let tmp1 = tempfile::tempdir().unwrap();
    let tmp2 = tempfile::tempdir().unwrap();

    let local_fs = LocalFileSystem::new(tmp1.path().to_path_buf()).unwrap();
    let remote_fs = LocalFileSystem::new(tmp2.path().to_path_buf()).unwrap();
    let mut synced = RamTreeState::new();

    let sync_local_deletes = true;
    let sync_remote_deletes = true;
    let log = &|_msg: &str| {};

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();

        let data = random_bytes(file_size, 42);
        create_file(tmp1.path(), "document.txt", &data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        let synced1 = synced.by_path("document.txt");
        assert!(synced1.is_some());

        std::thread::sleep(std::time::Duration::from_millis(10));
        let new_data = random_bytes(file_size + 1024, 99);
        create_file(tmp1.path(), "document.txt", &new_data);

        sync_dir(&local_fs, &remote_fs, sync_local_deletes, sync_remote_deletes, &mut synced, log).await.unwrap();
        let local_bytes = std::fs::read(tmp1.path().join("document.txt")).unwrap();
        let remote_bytes = std::fs::read(tmp2.path().join("document.txt")).unwrap();
        assert_eq!(local_bytes, new_data);
        assert_eq!(remote_bytes, new_data);
    });
}

#[test]
fn tree_state_store() {
    let mut synced = RamTreeState::new();
    assert!(!synced.has_completed_sync());
    synced.set_completed_sync(true);
    assert!(synced.has_completed_sync());

    let path = "some-path".to_string();
    let state1 = FileState::new(path.clone(), 12345000, 12345, [1u8; 32]);
    synced.add(state1.clone());
    let retrieved = synced.by_path(&path).unwrap();
    assert_eq!(retrieved.modification_time, state1.modification_time);
    assert_eq!(retrieved.size, state1.size);

    let state2 = FileState::new(path.clone(), 12346000, 12346, [2u8; 32]);
    synced.add(state2.clone());
    let retrieved2 = synced.by_path(&path).unwrap();
    assert_eq!(retrieved2.modification_time, state2.modification_time);
    assert_eq!(retrieved2.size, state2.size);

    assert_eq!(synced.all_file_paths().len(), 1);
}
