use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::file_state::FileState;

/// A file copy (upload or download) that may have been interrupted.
/// Ported from Java's `CopyOp`.
#[derive(Debug, Clone)]
pub struct CopyOp {
    /// true = download (remote→local), false = upload (local→remote)
    pub is_local_target: bool,
    pub source: PathBuf,
    pub target: PathBuf,
    pub source_state: FileState,
    pub target_state: FileState,
}

/// SyncState interface: tracks file states, directories, pending deletes, and
/// in-progress copy operations. Ported from Java's `SyncState`.
pub trait SyncState: Send + Sync {
    fn has_completed_sync(&self) -> bool;
    fn set_completed_sync(&mut self, done: bool);
    fn files_count(&self) -> usize;
    fn all_file_paths(&self) -> Vec<String>;
    fn add(&mut self, fs: FileState);
    fn remove(&mut self, path: &str);
    fn by_path(&self, path: &str) -> Option<&FileState>;
    fn by_hash(&self, hash: &[u8; 32]) -> Vec<&FileState>;
    fn add_dir(&mut self, path: String);
    fn remove_dir(&mut self, path: &str);
    fn has_dir(&self, path: &str) -> bool;
    fn get_dirs(&self) -> Vec<String>;
    fn add_local_delete(&mut self, path: String);
    fn remove_local_delete(&mut self, path: &str);
    fn has_local_delete(&self, path: &str) -> bool;
    fn add_remote_delete(&mut self, path: String);
    fn remove_remote_delete(&mut self, path: &str);
    fn has_remote_delete(&self, path: &str) -> bool;
    fn start_copies(&mut self, ops: Vec<CopyOp>);
    fn finish_copies(&mut self, ops: Vec<CopyOp>);
    fn get_in_progress_copies(&self) -> Vec<CopyOp>;
}

/// In-memory implementation of SyncState, matching Java's `RamTreeState`.
#[derive(Default)]
pub struct RamTreeState {
    pub files_by_path: HashMap<String, FileState>,
    pub files_by_hash: HashMap<[u8; 32], Vec<String>>,
    pub dirs: HashSet<String>,
    pub local_deletes: HashSet<String>,
    pub remote_deletes: HashSet<String>,
    pub completed_sync: bool,
    pub in_progress_copies: Vec<CopyOp>,
}

impl RamTreeState {
    pub fn new() -> Self {
        RamTreeState::default()
    }
}

impl SyncState for RamTreeState {
    fn has_completed_sync(&self) -> bool {
        self.completed_sync
    }

    fn set_completed_sync(&mut self, done: bool) {
        self.completed_sync = done;
    }

    fn files_count(&self) -> usize {
        self.files_by_path.len()
    }

    fn all_file_paths(&self) -> Vec<String> {
        self.files_by_path.keys().cloned().collect()
    }

    fn add(&mut self, fs: FileState) {
        let hash = fs.hash;
        let rel = fs.rel_path.clone();
        // remove old entry for this path (Java's Map.put overwrite semantics)
        if let Some(old) = self.files_by_path.remove(&rel) {
            if let Some(paths) = self.files_by_hash.get_mut(&old.hash) {
                paths.retain(|p| p != &rel);
                if paths.is_empty() {
                    self.files_by_hash.remove(&old.hash);
                }
            }
        }
        self.files_by_path.insert(rel.clone(), fs);
        self.files_by_hash.entry(hash).or_default().push(rel);
    }

    fn remove(&mut self, path: &str) {
        if let Some(fs) = self.files_by_path.remove(path) {
            if let Some(paths) = self.files_by_hash.get_mut(&fs.hash) {
                paths.retain(|p| p != path);
                if paths.is_empty() {
                    self.files_by_hash.remove(&fs.hash);
                }
            }
        }
    }

    fn by_path(&self, path: &str) -> Option<&FileState> {
        self.files_by_path.get(path)
    }

    fn by_hash(&self, hash: &[u8; 32]) -> Vec<&FileState> {
        self.files_by_hash
            .get(hash)
            .map(|paths| paths.iter().filter_map(|p| self.files_by_path.get(p)).collect())
            .unwrap_or_default()
    }

    fn add_dir(&mut self, path: String) {
        self.dirs.insert(path);
    }

    fn remove_dir(&mut self, path: &str) {
        self.dirs.remove(path);
    }

    fn has_dir(&self, path: &str) -> bool {
        self.dirs.contains(path)
    }

    fn get_dirs(&self) -> Vec<String> {
        self.dirs.iter().cloned().collect()
    }

    fn add_local_delete(&mut self, path: String) {
        self.local_deletes.insert(path);
    }

    fn remove_local_delete(&mut self, path: &str) {
        self.local_deletes.remove(path);
    }

    fn has_local_delete(&self, path: &str) -> bool {
        self.local_deletes.contains(path)
    }

    fn add_remote_delete(&mut self, path: String) {
        self.remote_deletes.insert(path);
    }

    fn remove_remote_delete(&mut self, path: &str) {
        self.remote_deletes.remove(path);
    }

    fn has_remote_delete(&self, path: &str) -> bool {
        self.remote_deletes.contains(path)
    }

    fn start_copies(&mut self, ops: Vec<CopyOp>) {
        self.in_progress_copies.extend(ops);
    }

    fn finish_copies(&mut self, ops: Vec<CopyOp>) {
        for op in &ops {
            self.in_progress_copies.retain(|c| c.target != op.target);
        }
    }

    fn get_in_progress_copies(&self) -> Vec<CopyOp> {
        self.in_progress_copies.clone()
    }
}
