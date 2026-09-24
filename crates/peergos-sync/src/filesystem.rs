use std::path::Path;

use async_trait::async_trait;
use peergos_core::error::Result;

/// File properties gathered during directory traversal.
#[derive(Debug, Clone)]
pub struct FileProps {
    pub rel_path: String,
    pub modified_time: i64,
    pub size: u64,
}

/// A small file ready for bulk upload (≤5 MiB, with pre-read bytes).
#[derive(Debug, Clone)]
pub struct UploadFile {
    pub name: String,
    pub size: u64,
    pub data: Vec<u8>,
}

/// A directory relative to the sync root and the small files to place directly
/// in it.
#[derive(Debug, Clone)]
pub struct UploadFolder {
    pub rel_path: Vec<String>,
    pub files: Vec<UploadFile>,
}

/// Abstract filesystem interface for sync operations.
#[async_trait(?Send)]
pub trait SyncFilesystem: Send + Sync {
    fn get_root(&self) -> &Path;
    async fn exists(&self, p: &Path) -> Result<bool>;
    async fn mkdirs(&self, p: &Path) -> Result<()>;
    async fn delete(&self, p: &Path) -> Result<()>;
    async fn bulk_delete(&self, dir: &Path, children: &[String]) -> Result<()>;
    async fn move_to(&self, src: &Path, target: &Path) -> Result<()>;
    async fn get_last_modified(&self, p: &Path) -> Result<i64>;
    async fn set_modification_time(&self, p: &Path, t: i64) -> Result<()>;
    async fn size(&self, p: &Path) -> Result<u64>;
    async fn truncate(&self, p: &Path, size: u64) -> Result<()>;
    async fn read(&self, p: &Path) -> Result<Vec<u8>>;
    async fn write(&self, p: &Path, data: &[u8], file_offset: u64) -> Result<()>;
    /// Hash a file at `chunk_size`: the chunk size of the file it will be compared
    /// against, since the two schemes give different roots for the same bytes. A
    /// remote file knows its own chunk size and uses that instead. Returns the root
    /// and the chunk size it was built at.
    async fn hash_file(&self, p: &Path, size: u64, chunk_size: u64) -> Result<([u8; 32], u64)>;
    async fn set_hash(&self, p: &Path, hash: [u8; 32], size: u64) -> Result<()>;
    async fn files_count(&self) -> Result<usize>;
    async fn upload_subtree(&self, folders: Vec<UploadFolder>) -> Result<()>;
    async fn flush(&self) -> Result<()>;
    async fn apply_to_subtree(&self, on_file: &mut (dyn FnMut(FileProps) + Send), on_dir: &mut (dyn FnMut(FileProps) + Send)) -> Result<()>;
    async fn free_space(&self) -> Result<u64>;
    async fn total_space(&self) -> Result<u64>;
}
