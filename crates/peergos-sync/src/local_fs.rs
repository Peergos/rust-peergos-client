use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use peergos_core::error::{Error, Result};
use walkdir::WalkDir;

use crate::filesystem::{FileProps, SyncFilesystem, UploadFolder};

/// Local filesystem implementation using std::fs.
pub struct LocalFileSystem {
    root: PathBuf,
}

impl LocalFileSystem {
    pub fn new(root: PathBuf) -> Result<Self> {
        if !root.exists() {
            return Err(Error::Protocol(format!("Local dir does not exist: {}", root.display())));
        }
        Ok(LocalFileSystem { root })
    }

    fn resolve(&self, p: &Path) -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.root.join(p)
        }
    }
}

#[async_trait(?Send)]
impl SyncFilesystem for LocalFileSystem {
    fn get_root(&self) -> &Path {
        &self.root
    }

    async fn exists(&self, p: &Path) -> Result<bool> {
        Ok(self.resolve(p).exists())
    }

    async fn mkdirs(&self, p: &Path) -> Result<()> {
        let target = self.resolve(p);
        if target.is_dir() {
            return Ok(());
        }
        fs::create_dir_all(&target).map_err(|e| Error::Protocol(format!("mkdirs failed: {e}")))
    }

    async fn delete(&self, p: &Path) -> Result<()> {
        let target = self.resolve(p);
        if target.is_dir() && target.read_dir().map_err(|e| Error::Protocol(e.to_string()))?.next().is_some() {
            return Err(Error::Protocol(format!("Dir not empty: {}", target.display())));
        }
        fs::remove_file(&target).or_else(|_| fs::remove_dir(&target))
            .map_err(|e| Error::Protocol(format!("delete failed: {e}")))
    }

    async fn bulk_delete(&self, dir: &Path, children: &[String]) -> Result<()> {
        for child in children {
            let target = self.resolve(dir).join(child);
            if target.exists() {
                fs::remove_file(&target).or_else(|_| fs::remove_dir(&target))
                    .map_err(|e| Error::Protocol(format!("bulk delete failed: {e}")))?;
            }
        }
        Ok(())
    }

    async fn move_to(&self, src: &Path, target: &Path) -> Result<()> {
        let src = self.resolve(src);
        let target = self.resolve(target);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Protocol(format!("mkdir for move failed: {e}")))?;
        }
        fs::rename(&src, &target).map_err(|e| Error::Protocol(format!("move failed: {e}")))
    }

    async fn get_last_modified(&self, p: &Path) -> Result<i64> {
        let meta = fs::metadata(self.resolve(p)).map_err(|e| Error::Protocol(e.to_string()))?;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let millis = mtime.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        Ok(millis / 1000 * 1000)
    }

    async fn set_modification_time(&self, p: &Path, t: i64) -> Result<()> {
        let target = self.resolve(p);
        let secs = t.max(0) / 1000;
        let mtime = UNIX_EPOCH + std::time::Duration::from_secs(secs as u64);
        let atime = target.metadata().ok().and_then(|m| m.accessed().ok()).unwrap_or(mtime);
        filetime::set_file_times(&target, atime.into(), mtime.into())
            .map_err(|e| Error::Protocol(format!("set_modification_time failed: {e}")))
    }

    async fn size(&self, p: &Path) -> Result<u64> {
        let meta = fs::metadata(self.resolve(p)).map_err(|e| Error::Protocol(e.to_string()))?;
        Ok(meta.len())
    }

    async fn truncate(&self, p: &Path, size: u64) -> Result<()> {
        let f = OpenOptions::new().write(true).open(self.resolve(p))
            .map_err(|e| Error::Protocol(e.to_string()))?;
        f.set_len(size).map_err(|e| Error::Protocol(e.to_string()))
    }

    async fn read(&self, p: &Path) -> Result<Vec<u8>> {
        fs::read(self.resolve(p)).map_err(|e| Error::Protocol(e.to_string()))
    }

    async fn write(&self, p: &Path, data: &[u8], file_offset: u64) -> Result<()> {
        let target = self.resolve(p);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Protocol(e.to_string()))?;
        }
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&target)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        f.seek(SeekFrom::Start(file_offset)).map_err(|e| Error::Protocol(e.to_string()))?;
        f.write_all(data).map_err(|e| Error::Protocol(e.to_string()))
    }

    async fn hash_file(&self, p: &Path, size: u64) -> Result<[u8; 32]> {
        let target = self.resolve(p);
        let root = peergos_fs::hash_file_parallel(&target, size)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&root.hash);
        Ok(hash)
    }

    async fn set_hash(&self, _p: &Path, _hash: [u8; 32], _size: u64) -> Result<()> {
        // Local files don't store hashes in extended attributes — no-op.
        Ok(())
    }

    async fn files_count(&self) -> Result<usize> {
        let mut count = 0;
        for entry in WalkDir::new(&self.root).max_depth(1) {
            let entry = entry.map_err(|e| Error::Protocol(e.to_string()))?;
            if entry.file_type().is_file() {
                count += 1;
            }
        }
        Ok(count)
    }

    async fn upload_subtree(&self, folders: Vec<UploadFolder>) -> Result<()> {
        for folder in &folders {
            let dir_path: std::path::PathBuf = folder.rel_path.iter().collect();
            for file in &folder.files {
                let file_path = dir_path.join(&file.name);
                if let Some(parent) = file_path.parent() {
                    if !parent.to_string_lossy().is_empty() {
                        self.mkdirs(parent).await?;
                    }
                }
                self.write(&file_path, &file.data, 0).await?;
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        Ok(())
    }

    async fn apply_to_subtree(&self, on_file: &mut (dyn FnMut(FileProps) + Send), on_dir: &mut (dyn FnMut(FileProps) + Send)) -> Result<()> {
        apply_to_subtree_recursive(&self.root, &self.root, on_file, on_dir)
    }

    async fn free_space(&self) -> Result<u64> {
        Ok(u64::MAX)
    }

    async fn total_space(&self) -> Result<u64> {
        Ok(u64::MAX)
    }
}

fn apply_to_subtree_recursive(
    root: &Path,
    start: &Path,
    on_file: &mut dyn FnMut(FileProps),
    on_dir: &mut dyn FnMut(FileProps),
) -> Result<()> {
    let dir = fs::read_dir(start).map_err(|e| Error::Protocol(e.to_string()))?;
    for entry in dir {
        let entry = entry.map_err(|e| Error::Protocol(e.to_string()))?;
        let path = entry.path();
        let meta = fs::metadata(&path).map_err(|e| Error::Protocol(e.to_string()))?;
        if meta.is_symlink() {
            continue;
        }
        let rel_path = pathdiff::diff_paths(&path, root)
            .unwrap_or_else(|| path.file_name().unwrap().into())
            .to_string_lossy()
            .replace('\\', "/");
        if rel_path.starts_with('.') || rel_path.contains("/.") {
            continue;
        }
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let millis = mtime.duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
        let props = FileProps {
            rel_path,
            modified_time: millis / 1000 * 1000,
            size: meta.len(),
        };
        if meta.is_dir() {
            on_dir(props);
            apply_to_subtree_recursive(root, &path, on_file, on_dir)?;
        } else if meta.is_file() {
            on_file(props);
        }
    }
    Ok(())
}
