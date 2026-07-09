use std::collections::{HashMap, HashSet, BTreeSet};
use std::path::Path;

use log::info;
use peergos_core::error::Result;

use crate::file_state::FileState;
use crate::filesystem::{FileProps, SyncFilesystem, UploadFile, UploadFolder};
use crate::state::SyncState;

const CHUNK_MAX_SIZE: u64 = 5 * 1024 * 1024;
const BATCH_MAX_COUNT: u64 = 1_000;
const BATCH_MAX_SIZE: u64 = 100 * 1024 * 1024;

/// Convenience wrapper: build_dir_state for a local or remote filesystem.
///
/// Walks the subtree via `apply_to_subtree`, re-uses `synced` entries when
/// size+mtime match, otherwise hashes the file and creates a new `FileState`.
pub async fn build_dir_state(
    fs: &dyn SyncFilesystem,
    res: &mut dyn SyncState,
    synced: &dyn SyncState,
) -> Result<()> {
    let btree: std::sync::Mutex<Vec<FileState>> = std::sync::Mutex::new(Vec::new());

    fs.apply_to_subtree(
        &mut |props: FileProps| {
            let at_sync = synced.by_path(&props.rel_path);
            if let Some(synced_fs) = at_sync {
                if synced_fs.modification_time == props.modified_time && synced_fs.size == props.size {
                    btree.lock().unwrap().push(synced_fs.clone());
                    return;
                }
            }
            btree.lock().unwrap().push(FileState::new(
                props.rel_path,
                props.modified_time,
                props.size,
                [0u8; 32],
            ));
        },
        &mut |props: FileProps| {
            res.add_dir(props.rel_path);
        },
    )
    .await?;

    let pending: Vec<(String, i64, u64)> = {
        let guard = btree.lock().unwrap();
        guard
            .iter()
            .filter(|f| f.hash == [0u8; 32])
            .map(|f| (f.rel_path.clone(), f.modification_time, f.size))
            .collect()
    };

    for (rel_path, mtime, size) in pending {
        let hash = fs.hash_file(&std::path::PathBuf::from(&rel_path), size).await?;
        let f = FileState::new(rel_path, mtime, size, hash);
        res.add(f);
    }

    let final_entries = btree.lock().unwrap().clone();
    for f in final_entries {
        if f.hash != [0u8; 32] {
            res.add(f);
        }
    }

    Ok(())
}

fn is_ignored(name: &str) -> bool {
    matches!(name, ".DS_Store")
}

/// Main sync loop: compare local ↔ remote states, diff against `synced`, and
/// apply uploads / downloads / deletes.
pub async fn sync_dir(
    local: &dyn SyncFilesystem,
    remote: &dyn SyncFilesystem,
    sync_local_deletes: bool,
    sync_remote_deletes: bool,
    synced: &mut dyn SyncState,
    log: &dyn Fn(&str),
) -> Result<()> {
    let mut local_state = crate::state::RamTreeState::new();
    build_dir_state(local, &mut local_state, synced).await?;

    let mut remote_state = crate::state::RamTreeState::new();
    build_dir_state(remote, &mut remote_state, synced).await?;

    let local_files = local_state.files_count();
    let remote_files = remote_state.files_count();
    info!("Local files: {local_files}, Remote files: {remote_files}");

    let all_paths: BTreeSet<String> = {
        let mut s = BTreeSet::new();
        for p in local_state.all_file_paths() {
            s.insert(p);
        }
        for p in remote_state.all_file_paths() {
            s.insert(p);
        }
        s
    };

    // ---- first pass: remove identical / already-synced / ignored paths ----
    let mut all_changed_paths: Vec<String> = Vec::new();
    for path in &all_paths {
        let local_fs = local_state.by_path(path);
        let remote_fs = remote_state.by_path(path);
        let synced_fs = synced.by_path(path);

        if let (Some(l), Some(r)) = (local_fs, remote_fs) {
            if l.hash == r.hash && l.modification_time == r.modification_time && l.size == r.size {
                if synced_fs.is_none() {
                    synced.add(l.clone());
                }
                if !sync_local_deletes && synced.has_local_delete(path) {
                    synced.remove_local_delete(path);
                }
                if !sync_remote_deletes && synced.has_remote_delete(path) {
                    synced.remove_remote_delete(path);
                }
                continue;
            }
        }

        if let (Some(l), Some(r), Some(s)) = (local_fs, remote_fs, synced_fs) {
            if l.hash == r.hash && (s.equals_ignore_modtime(l) || s.equals_ignore_modtime(r)) {
                if !sync_local_deletes && synced.has_local_delete(path) {
                    synced.remove_local_delete(path);
                }
                if !sync_remote_deletes && synced.has_remote_delete(path) {
                    synced.remove_remote_delete(path);
                }
                continue;
            }
        }

        let fname = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if is_ignored(&fname) {
            continue;
        }

        all_changed_paths.push(path.clone());
    }

    // ---- second pass: classify into small-file batches, local deletes, and per-file sync ----
    let mut small_file_batches: Vec<Vec<String>> = vec![Vec::new()];
    let mut current_small_batch_count = 0u64;
    let mut current_small_batch_size = 0u64;
    let mut local_deletes: Vec<String> = Vec::new();
    let mut done_files: HashSet<String> = HashSet::new();

    for rel_path in &all_changed_paths {
        let synced_fs = synced.by_path(rel_path);
        let local_fs = local_state.by_path(rel_path);
        let remote_fs = remote_state.by_path(rel_path);

        // ---- small-file bulk-upload classification ----
        let is_small_remote_copy = synced_fs.is_none()
            && remote_fs.is_none()
            && local_fs.map(|l| l.size < CHUNK_MAX_SIZE).unwrap_or(false);
        if is_small_remote_copy {
            let local = local_fs.unwrap();
            let l_hash = local.hash;
            let remote_by_hash = remote_state.by_hash(&l_hash);
            let local_by_hash = local_state.by_hash(&l_hash);

            let extra_remote: Vec<&FileState> = remote_by_hash.iter()
                .filter(|f| !local_by_hash.contains(f))
                .copied()
                .collect();
            let extra_local: Vec<&FileState> = local_by_hash.iter()
                .filter(|f| !remote_by_hash.contains(f))
                .copied()
                .collect();
            let index = extra_local.iter().position(|f| f.rel_path == *rel_path);
            let local_at_hashed_path = if extra_remote.len() == extra_local.len() {
                index.and_then(|i| {
                    if i < extra_remote.len() {
                        local_state.by_path(&extra_remote[i].rel_path)
                    } else {
                        None
                    }
                })
            } else {
                None
            };

            // Only batch when hash-rename detection shows no match — if every
            // hash-sibling has a counterpart on the other side this is a rename
            // and will be handled by sync_file.
            if extra_remote.len() != extra_local.len() || local_at_hashed_path.is_some() {
                current_small_batch_count += 1;
                current_small_batch_size += local.size;
                if current_small_batch_count >= BATCH_MAX_COUNT
                    || current_small_batch_size >= BATCH_MAX_SIZE
                {
                    small_file_batches.push(Vec::new());
                    current_small_batch_count = 0;
                    current_small_batch_size = 0;
                }
                small_file_batches.last_mut().unwrap().push(rel_path.clone());
                done_files.insert(rel_path.clone());
                continue;
            }
        }

        // ---- local-delete classification ----
        let is_local_delete = local_fs.is_none()
            && remote_fs.is_some()
            && synced_fs.is_some()
            && remote_fs.unwrap().equals_ignore_modtime(synced_fs.unwrap());
        if is_local_delete {
            let remote = remote_fs.unwrap();
            let r_hash = remote.hash;
            let remote_by_hash = remote_state.by_hash(&r_hash);
            let local_by_hash = local_state.by_hash(&r_hash);

            let extra_local: Vec<&FileState> = local_by_hash.iter()
                .filter(|f| !remote_by_hash.contains(f))
                .copied()
                .collect();
            let extra_remote: Vec<&FileState> = remote_by_hash.iter()
                .filter(|f| !local_by_hash.contains(f))
                .copied()
                .collect();
            let index = extra_remote.iter().position(|f| f.rel_path == *rel_path);
            let remote_at_hashed_path = if extra_local.len() == extra_remote.len() {
                index.and_then(|i| {
                    if i < extra_local.len() {
                        remote_state.by_path(&extra_local[i].rel_path)
                    } else {
                        None
                    }
                })
            } else {
                None
            };

            if extra_local.len() != extra_remote.len() || remote_at_hashed_path.is_some() {
                local_deletes.push(rel_path.clone());
                done_files.insert(rel_path.clone());
            }
        }
    }

    // ---- process small-file bulk upload batches ----
    for batch in &small_file_batches {
        if batch.is_empty() {
            continue;
        }
        log(&format!("Remote: bulk uploading {} small files", batch.len()));
        let mut folders: HashMap<String, UploadFolder> = HashMap::new();
        for rel_path in batch {
            let local_fs = local_state.by_path(rel_path).unwrap();
            let data = local.read(&std::path::PathBuf::from(rel_path)).await?;
            let (dir, fname) = split_path(rel_path);
            let folder = folders.entry(dir.clone()).or_insert_with(|| {
                let path_comps = if dir.is_empty() {
                    Vec::new()
                } else {
                    dir.split('/').map(|s| s.to_string()).collect()
                };
                UploadFolder { rel_path: path_comps, files: Vec::new() }
            });
            folder.files.push(UploadFile {
                name: fname,
                size: local_fs.size,
                data,
            });
        }
        let folder_list: Vec<UploadFolder> = folders.into_values().collect();
        remote.upload_subtree(folder_list).await?;
        for rel_path in batch {
            synced.add(local_state.by_path(rel_path).cloned().unwrap());
        }
    }

    // ---- process local deletes (bulk) ----
    if !local_deletes.is_empty() {
        let mut by_folder: HashMap<String, HashSet<String>> = HashMap::new();
        for rel_path in &local_deletes {
            if !sync_local_deletes {
                log(&format!("Sync ignore local delete {rel_path}"));
                synced.add_local_delete(rel_path.clone());
                continue;
            }
            let (dir, fname) = split_path(rel_path);
            by_folder.entry(dir).or_default().insert(fname);
        }
        for (dir, files) in &by_folder {
            log(&format!("REMOTE: bulk deleting {} from {}", files.len(), dir));
            let dir_path = if dir.is_empty() {
                std::path::PathBuf::from(".")
            } else {
                std::path::PathBuf::from(dir)
            };
            let children: Vec<String> = files.iter().cloned().collect();
            remote.bulk_delete(&dir_path, &children).await?;
            for fname in &children {
                let full = if dir.is_empty() {
                    fname.clone()
                } else {
                    format!("{dir}/{fname}")
                };
                log(&format!("REMOTE: deleted {full}"));
                synced.remove(&full);
            }
        }
    }

    // ---- per-file sync for everything not handled above ----
    for rel_path in &all_changed_paths {
        if done_files.contains(rel_path) {
            continue;
        }
        let synced_fs = synced.by_path(rel_path).cloned();
        let local_fs = local_state.by_path(rel_path).cloned();
        let remote_fs = remote_state.by_path(rel_path).cloned();

        sync_file(
            synced_fs.as_ref(),
            local_fs.as_ref(),
            remote_fs.as_ref(),
            local,
            remote,
            synced,
            &local_state,
            &remote_state,
            sync_local_deletes,
            sync_remote_deletes,
            log,
        )
        .await?;
    }

    // ---- directory sync ----
    let all_dirs: BTreeSet<String> = {
        let mut s = BTreeSet::new();
        for d in local_state.get_dirs() {
            s.insert(d);
        }
        for d in remote_state.get_dirs() {
            s.insert(d);
        }
        for d in synced.get_dirs() {
            s.insert(d);
        }
        s
    };

    let mut dirs: Vec<&String> = all_dirs.iter().collect();
    dirs.sort_by(|a, b| b.len().cmp(&a.len()).then(b.cmp(a)));

    for dir_path in dirs {
        let has_local = local_state.has_dir(dir_path);
        let has_remote = remote_state.has_dir(dir_path);
        let has_synced = synced.has_dir(dir_path);

        if has_local && has_remote {
            synced.add_dir(dir_path.clone());
        } else if !has_local && !has_remote {
            synced.remove_dir(dir_path);
        } else if has_local {
            if has_synced {
                if sync_remote_deletes {
                    log(&format!("Sync local: delete dir {dir_path}"));
                    local.delete(std::path::Path::new(dir_path)).await?;
                    synced.remove_dir(dir_path);
                }
            } else {
                log(&format!("Sync Remote: mkdir {dir_path}"));
                remote.mkdirs(std::path::Path::new(dir_path)).await?;
                synced.add_dir(dir_path.clone());
            }
        } else {
            if has_synced {
                if sync_local_deletes {
                    log(&format!("Sync Remote: delete dir {dir_path}"));
                    remote.delete(std::path::Path::new(dir_path)).await?;
                    synced.remove_dir(dir_path);
                }
            } else {
                log(&format!("Sync Local: mkdir {dir_path}"));
                local.mkdirs(std::path::Path::new(dir_path)).await?;
                synced.add_dir(dir_path.clone());
            }
        }
    }

    Ok(())
}

async fn sync_file(
    synced: Option<&FileState>,
    local: Option<&FileState>,
    remote: Option<&FileState>,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    local_tree: &dyn SyncState,
    remote_tree: &dyn SyncState,
    sync_local_deletes: bool,
    sync_remote_deletes: bool,
    log: &dyn Fn(&str),
) -> Result<()> {
    match synced {
        None => {
            match (local, remote) {
                (None, Some(r)) => {
                    handle_remote_addition(r, local_fs, remote_fs, synced_state, remote_tree, local_tree, log).await?;
                }
                (Some(l), None) => {
                    handle_local_addition(l, local_fs, remote_fs, synced_state, local_tree, remote_tree, log).await?;
                }
                (Some(l), Some(r)) => {
                    handle_concurrent_addition(l, r, local_fs, remote_fs, synced_state, log).await?;
                }
                (None, None) => {}
            }
        }
        Some(s) => {
            match (local, remote) {
                (None, None) => {
                    log(&format!("Sync Concurrent delete on {}", s.rel_path));
                    synced_state.remove(&s.rel_path);
                }
                (None, Some(r)) => {
                    handle_local_delete(s, r, local_fs, remote_fs, synced_state, remote_tree, local_tree, sync_local_deletes, log).await?;
                }
                (Some(l), None) => {
                    handle_remote_delete(s, l, local_fs, remote_fs, synced_state, local_tree, remote_tree, sync_remote_deletes, log).await?;
                }
                (Some(l), Some(r)) => {
                    handle_both_exist(s, l, r, local_fs, remote_fs, synced_state, local_tree, remote_tree, sync_local_deletes, sync_remote_deletes, log).await?;
                }
            }
        }
    }
    Ok(())
}

async fn handle_remote_addition(
    remote: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    remote_tree: &dyn SyncState,
    local_tree: &dyn SyncState,
    log: &dyn Fn(&str),
) -> Result<()> {
    let r_hash = remote.hash;
    let remote_by_hash = remote_tree.by_hash(&r_hash);
    let local_by_hash = local_tree.by_hash(&r_hash);

    let extra_local: Vec<&FileState> = local_by_hash.iter()
        .filter(|f| !remote_by_hash.contains(f))
        .copied()
        .collect();
    let extra_remote: Vec<&FileState> = remote_by_hash.iter()
        .filter(|f| !local_by_hash.contains(f))
        .copied()
        .collect();

    let index = extra_remote.iter().position(|f| f.rel_path == remote.rel_path);
    let remote_at_hashed_path = if extra_local.len() == extra_remote.len() {
        index.and_then(|i| {
            if i < extra_local.len() {
                remote_tree.by_path(&extra_local[i].rel_path)
            } else {
                None
            }
        })
    } else {
        None
    };

    if extra_local.len() == extra_remote.len() && remote_at_hashed_path.is_none() {
        let idx = index.unwrap();
        let to_move = extra_local[idx];
        let remote_path = std::path::Path::new(&remote.rel_path);
        if !remote_fs.exists(remote_path).await.unwrap_or(false) {
            return Ok(());
        }
        log(&format!("Sync Local: Moving {} ==> {}", to_move.rel_path, remote.rel_path));
        let src = std::path::PathBuf::from(&to_move.rel_path);
        let dst = std::path::PathBuf::from(&remote.rel_path);
        local_fs.move_to(&src, &dst).await?;
        synced_state.remove(&to_move.rel_path);
        synced_state.add(remote.clone());
    } else {
        log(&format!("Sync Local: Copying {}", remote.rel_path));
        let p = std::path::PathBuf::from(&remote.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                local_fs.mkdirs(parent).await?;
            }
        }
        let data = remote_fs.read(&p).await?;
        local_fs.write(&p, &data, 0).await?;
        synced_state.add(remote.clone());
    }
    Ok(())
}

async fn handle_local_addition(
    local: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    local_tree: &dyn SyncState,
    remote_tree: &dyn SyncState,
    log: &dyn Fn(&str),
) -> Result<()> {
    let l_hash = local.hash;
    let remote_by_hash = remote_tree.by_hash(&l_hash);
    let local_by_hash = local_tree.by_hash(&l_hash);

    let extra_remote: Vec<&FileState> = remote_by_hash.iter()
        .filter(|f| !local_by_hash.contains(f))
        .copied()
        .collect();
    let extra_local: Vec<&FileState> = local_by_hash.iter()
        .filter(|f| !remote_by_hash.contains(f))
        .copied()
        .collect();

    let index = extra_local.iter().position(|f| f.rel_path == local.rel_path);
    let local_at_hashed_path = if extra_remote.len() == extra_local.len() {
        index.and_then(|i| {
            if i < extra_remote.len() {
                local_tree.by_path(&extra_remote[i].rel_path)
            } else {
                None
            }
        })
    } else {
        None
    };

    if extra_remote.len() == extra_local.len() && local_at_hashed_path.is_none() {
        let idx = index.unwrap();
        let to_move = extra_remote[idx];
        let local_path = std::path::Path::new(&local.rel_path);
        if !local_fs.exists(local_path).await.unwrap_or(false) {
            return Ok(());
        }
        log(&format!("Sync Remote: Moving {} ==> {}", to_move.rel_path, local.rel_path));
        let src = std::path::PathBuf::from(&to_move.rel_path);
        let dst = std::path::PathBuf::from(&local.rel_path);
        remote_fs.move_to(&src, &dst).await?;
        synced_state.remove(&to_move.rel_path);
        synced_state.add(local.clone());
    } else {
        log(&format!("Sync Remote: Copying {}", local.rel_path));
        let p = std::path::PathBuf::from(&local.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                remote_fs.mkdirs(parent).await?;
            }
        }
        let data = local_fs.read(&p).await?;
        remote_fs.write(&p, &data, 0).await?;
        synced_state.add(local.clone());
    }
    Ok(())
}

async fn handle_concurrent_addition(
    local: &FileState,
    remote: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    log: &dyn Fn(&str),
) -> Result<()> {
    if local.hash == remote.hash {
        if local.modification_time > remote.modification_time {
            log(&format!("Remote: Set mod time {}", local.rel_path));
            let p = std::path::PathBuf::from(&local.rel_path);
            remote_fs.set_modification_time(&p, local.modification_time).await?;
            synced_state.add(local.clone());
        } else if remote.modification_time > local.modification_time {
            log(&format!("Sync Local: Set mod time {}", local.rel_path));
            let p = std::path::PathBuf::from(&local.rel_path);
            local_fs.set_modification_time(&p, remote.modification_time).await?;
            synced_state.add(remote.clone());
        } else {
            synced_state.add(local.clone());
        }
    } else {
        log(&format!("Sync Remote: Concurrent file addition: {} renaming local version", local.rel_path));
        let renamed = rename_on_conflict(local_fs, std::path::Path::new(&local.rel_path), local).await?;
        let p = std::path::PathBuf::from(&remote.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                local_fs.mkdirs(parent).await?;
            }
        }
        let data = remote_fs.read(&p).await?;
        local_fs.write(&p, &data, 0).await?;
        synced_state.add(remote.clone());

        let rp = std::path::PathBuf::from(&renamed.rel_path);
        if let Some(parent) = rp.parent() {
            let s = parent.to_string_lossy();
            if !s.is_empty() {
                remote_fs.mkdirs(parent).await?;
            }
        }
        let data = local_fs.read(&rp).await?;
        remote_fs.write(&rp, &data, 0).await?;
        synced_state.add(renamed);
    }
    Ok(())
}

async fn handle_local_delete(
    synced: &FileState,
    remote: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    remote_tree: &dyn SyncState,
    local_tree: &dyn SyncState,
    sync_local_deletes: bool,
    log: &dyn Fn(&str),
) -> Result<()> {
    if synced.equals_ignore_modtime(remote) {
        let r_hash = remote.hash;
        let remote_by_hash = remote_tree.by_hash(&r_hash);
        let local_by_hash = local_tree.by_hash(&r_hash);

        let extra_remote: Vec<&FileState> = remote_by_hash.iter()
            .filter(|f| !local_by_hash.contains(f))
            .copied()
            .collect();
        let extra_local: Vec<&FileState> = local_by_hash.iter()
            .filter(|f| !remote_by_hash.contains(f))
            .copied()
            .collect();

        let index = extra_local.iter().position(|f| f.rel_path == synced.rel_path);
        let local_at_hashed_path = if extra_remote.len() == extra_local.len() {
            index.and_then(|i| {
                if i < extra_remote.len() {
                    local_tree.by_path(&extra_remote[i].rel_path)
                } else {
                    None
                }
            })
        } else {
            None
        };

        if extra_remote.len() == extra_local.len() && local_at_hashed_path.is_none() {
            // rename handled by new path entry
        } else {
            if sync_local_deletes {
                log(&format!("Sync Remote: delete {}", synced.rel_path));
                let p = std::path::PathBuf::from(&synced.rel_path);
                remote_fs.delete(&p).await?;
                synced_state.remove(&synced.rel_path);
            } else {
                log(&format!("Sync ignore local delete {}", synced.rel_path));
                synced_state.add_local_delete(synced.rel_path.clone());
            }
        }
    } else if remote.hash == synced.hash {
        synced_state.add(remote.clone());
    } else {
        log(&format!("Sync Local: deleted, copying changed remote {}", remote.rel_path));
        let p = std::path::PathBuf::from(&remote.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                local_fs.mkdirs(parent).await?;
            }
        }
        let data = remote_fs.read(&p).await?;
        local_fs.write(&p, &data, 0).await?;
        synced_state.add(remote.clone());
        if !sync_local_deletes && synced_state.has_local_delete(&remote.rel_path) {
            synced_state.remove_local_delete(&remote.rel_path);
        }
    }
    Ok(())
}

async fn handle_remote_delete(
    synced: &FileState,
    local: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    local_tree: &dyn SyncState,
    remote_tree: &dyn SyncState,
    sync_remote_deletes: bool,
    log: &dyn Fn(&str),
) -> Result<()> {
    if synced.equals_ignore_modtime(local) {
        let l_hash = local.hash;
        let local_by_hash = local_tree.by_hash(&l_hash);
        let remote_by_hash = remote_tree.by_hash(&l_hash);

        let extra_local: Vec<&FileState> = local_by_hash.iter()
            .filter(|f| !remote_by_hash.contains(f))
            .copied()
            .collect();
        let extra_remote: Vec<&FileState> = remote_by_hash.iter()
            .filter(|f| !local_by_hash.contains(f))
            .copied()
            .collect();

        let index = extra_remote.iter().position(|f| f.rel_path == synced.rel_path);
        let remote_at_hashed_path = if extra_local.len() == extra_remote.len() {
            index.and_then(|i| {
                if i < extra_local.len() {
                    remote_tree.by_path(&extra_local[i].rel_path)
                } else {
                    None
                }
            })
        } else {
            None
        };

        if extra_local.len() == extra_remote.len() && remote_at_hashed_path.is_none() {
            // rename handled by new path entry
        } else {
            if sync_remote_deletes {
                log(&format!("Sync Local: delete {}", synced.rel_path));
                let p = std::path::PathBuf::from(&synced.rel_path);
                local_fs.delete(&p).await?;
                synced_state.remove(&synced.rel_path);
            } else {
                log(&format!("Sync ignore remote delete {}", synced.rel_path));
                synced_state.add_remote_delete(synced.rel_path.clone());
            }
        }
    } else if local.hash == synced.hash {
        synced_state.add(local.clone());
    } else {
        log(&format!("Sync Remote: deleted, copying changed local {}", local.rel_path));
        let p = std::path::PathBuf::from(&local.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                remote_fs.mkdirs(parent).await?;
            }
        }
        let data = local_fs.read(&p).await?;
        remote_fs.write(&p, &data, 0).await?;
        synced_state.add(local.clone());
        if !sync_remote_deletes && synced_state.has_remote_delete(&local.rel_path) {
            synced_state.remove_remote_delete(&local.rel_path);
        }
    }
    Ok(())
}

async fn handle_both_exist(
    synced: &FileState,
    local: &FileState,
    remote: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    _local_tree: &dyn SyncState,
    _remote_tree: &dyn SyncState,
    sync_local_deletes: bool,
    sync_remote_deletes: bool,
    log: &dyn Fn(&str),
) -> Result<()> {
    if synced.equals_ignore_modtime(local) {
        // remote-only change (synced matches local, remote differs)
        if remote.hash == local.hash {
            synced_state.add(local.clone());
            if !sync_local_deletes && synced_state.has_local_delete(&remote.rel_path) {
                synced_state.remove_local_delete(&remote.rel_path);
            }
            if !sync_remote_deletes && synced_state.has_remote_delete(&remote.rel_path) {
                synced_state.remove_remote_delete(&remote.rel_path);
            }
        } else if synced_state.has_remote_delete(&remote.rel_path) {
            log(&format!("Sync Remote: Concurrent change: {} renaming local version after remote delete", local.rel_path));
            let renamed = rename_on_conflict(local_fs, std::path::Path::new(&local.rel_path), local).await?;
            let p = std::path::PathBuf::from(&remote.rel_path);
            if let Some(parent) = p.parent() {
                if !parent.to_string_lossy().is_empty() {
                    local_fs.mkdirs(parent).await?;
                }
            }
            let data = remote_fs.read(&p).await?;
            local_fs.write(&p, &data, 0).await?;
            synced_state.add(remote.clone());

            let rp = std::path::PathBuf::from(&renamed.rel_path);
            if let Some(parent) = rp.parent() {
                let s = parent.to_string_lossy();
                if !s.is_empty() {
                    remote_fs.mkdirs(parent).await?;
                }
            }
            let data = local_fs.read(&rp).await?;
            remote_fs.write(&rp, &data, 0).await?;
            synced_state.add(renamed);
            synced_state.remove_remote_delete(&remote.rel_path);
        } else {
            log(&format!("Sync Local: Copying changes to {}", remote.rel_path));
            let p = std::path::PathBuf::from(&remote.rel_path);
            if let Some(parent) = p.parent() {
                if !parent.to_string_lossy().is_empty() {
                    local_fs.mkdirs(parent).await?;
                }
            }
            let data = remote_fs.read(&p).await?;
            local_fs.write(&p, &data, 0).await?;
            synced_state.add(remote.clone());
        }
    } else if synced.equals_ignore_modtime(remote) {
        // local-only change (synced matches remote, local differs)
        if local.hash == remote.hash {
            synced_state.add(local.clone());
            if !sync_local_deletes && synced_state.has_local_delete(&local.rel_path) {
                synced_state.remove_local_delete(&local.rel_path);
            }
            if !sync_remote_deletes && synced_state.has_remote_delete(&local.rel_path) {
                synced_state.remove_remote_delete(&local.rel_path);
            }
        } else if synced_state.has_local_delete(&local.rel_path) {
            log(&format!("Sync Remote: Concurrent change: {} renaming local version after local delete", local.rel_path));
            let renamed = rename_on_conflict(local_fs, std::path::Path::new(&local.rel_path), local).await?;
            let p = std::path::PathBuf::from(&remote.rel_path);
            if let Some(parent) = p.parent() {
                if !parent.to_string_lossy().is_empty() {
                    local_fs.mkdirs(parent).await?;
                }
            }
            let data = remote_fs.read(&p).await?;
            local_fs.write(&p, &data, 0).await?;
            synced_state.add(remote.clone());

            let rp = std::path::PathBuf::from(&renamed.rel_path);
            if let Some(parent) = rp.parent() {
                let s = parent.to_string_lossy();
                if !s.is_empty() {
                    remote_fs.mkdirs(parent).await?;
                }
            }
            let data = local_fs.read(&rp).await?;
            remote_fs.write(&rp, &data, 0).await?;
            synced_state.add(renamed);
            synced_state.remove_local_delete(&local.rel_path);
        } else {
            log(&format!("Sync Remote: Copying changes to {}", local.rel_path));
            let p = std::path::PathBuf::from(&local.rel_path);
            if let Some(parent) = p.parent() {
                if !parent.to_string_lossy().is_empty() {
                    remote_fs.mkdirs(parent).await?;
                }
            }
            let data = local_fs.read(&p).await?;
            remote_fs.write(&p, &data, 0).await?;
            synced_state.add(local.clone());
        }
    } else {
        handle_concurrent_change(synced, local, remote, local_fs, remote_fs, synced_state, log).await?;
    }
    Ok(())
}

async fn handle_concurrent_change(
    synced: &FileState,
    local: &FileState,
    remote: &FileState,
    local_fs: &dyn SyncFilesystem,
    remote_fs: &dyn SyncFilesystem,
    synced_state: &mut dyn SyncState,
    log: &dyn Fn(&str),
) -> Result<()> {
    if local == remote {
        synced_state.add(local.clone());
    } else if synced.hash == remote.hash {
        log(&format!("Sync Remote: Copying changes to {}", local.rel_path));
        let p = std::path::PathBuf::from(&local.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                remote_fs.mkdirs(parent).await?;
            }
        }
        let data = local_fs.read(&p).await?;
        remote_fs.write(&p, &data, 0).await?;
        synced_state.add(local.clone());
    } else {
        log(&format!("Sync Remote: Concurrent change: {} renaming local version", local.rel_path));
        let renamed = rename_on_conflict(local_fs, std::path::Path::new(&local.rel_path), local).await?;
        let p = std::path::PathBuf::from(&remote.rel_path);
        if let Some(parent) = p.parent() {
            if !parent.to_string_lossy().is_empty() {
                local_fs.mkdirs(parent).await?;
            }
        }
        let data = remote_fs.read(&p).await?;
        local_fs.write(&p, &data, 0).await?;
        synced_state.add(remote.clone());

        let rp = std::path::PathBuf::from(&renamed.rel_path);
        if let Some(parent) = rp.parent() {
            let s = parent.to_string_lossy();
            if !s.is_empty() {
                remote_fs.mkdirs(parent).await?;
            }
        }
        let data = local_fs.read(&rp).await?;
        remote_fs.write(&rp, &data, 0).await?;
        synced_state.add(renamed);
    }
    Ok(())
}

async fn rename_on_conflict(
    fs: &dyn SyncFilesystem,
    path: &Path,
    state: &FileState,
) -> Result<FileState> {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let parent = path.parent().unwrap_or(Path::new("."));
    let new_name = if let Some(cs) = name.find("[conflict-") {
        let before = &name[..cs];
        let after = cs + name[cs..].find(']').map(|i| i + 1).unwrap_or(name.len());
        let rest = &name[after..];
        let ver: u32 = name[cs + "[conflict-".len()..name[cs..].find(']').map(|i| cs + i).unwrap_or(name.len())]
            .parse()
            .unwrap_or(0);
        loop {
            let candidate = format!("{before}[conflict-{}]{rest}", ver + 1);
            if !fs.exists(&parent.join(&candidate)).await.unwrap_or(false) {
                break candidate;
            }
        }
    } else {
        let mut version = 0u32;
        loop {
            let candidate = if let Some(dot) = name.rfind('.') {
                format!("{}[conflict-{version}]{}", &name[..dot], &name[dot..])
            } else {
                format!("{name}[conflict-{version}]")
            };
            if !fs.exists(&parent.join(&candidate)).await.unwrap_or(false) {
                break candidate;
            }
            version += 1;
        }
    };

    let new_path = parent.join(&new_name);
    fs.move_to(path, &new_path).await?;
    let new_mtime = fs.get_last_modified(&new_path).await.unwrap_or(state.modification_time);
    let name_old = path.file_name().unwrap().to_string_lossy();
    let new_rel_path = if let Some(prefix) = state.rel_path.strip_suffix(name_old.as_ref()) {
        format!("{prefix}{new_name}")
    } else {
        new_name.clone()
    };
    Ok(FileState::new(new_rel_path, new_mtime, state.size, state.hash))
}

fn split_path(path: &str) -> (String, String) {
    if let Some(slash) = path.rfind('/') {
        (path[..slash].to_string(), path[slash + 1..].to_string())
    } else {
        (String::new(), path.to_string())
    }
}
