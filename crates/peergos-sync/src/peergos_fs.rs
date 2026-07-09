use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use peergos_core::auth::BatWithId;
use peergos_core::error::{Error, Result};
use peergos_core::keys::PublicKeyHash;
use peergos_core::keys::SigningPrivateKeyAndPublicHash;
use peergos_core::mutable::MutablePointers;
use peergos_core::storage::ContentAddressedStorage;
use peergos_core::BufferedNetwork;
use peergos_fs::capability::AbsoluteCapability;
use peergos_fs::hashtree::{HashBranch, RootHash};
use peergos_fs::{list_directory, read_file, upload_file, mkdir_hidden, retrieve_file_metadata, recover_signer, delete_child, rename_child, rewrite_file_content, update_file_properties, FolderUpload, FileUpload};
use crate::filesystem::{FileProps, SyncFilesystem, UploadFolder};

/// Peergos remote filesystem implementation. All writes go through a
/// [`BufferedNetwork`] that flushes every ~20 MiB in a single CAS commit.
pub struct PeergosSyncFS {
    root: PathBuf,
    root_cap: AbsoluteCapability,
    signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<BatWithId>,
    /// Buffered network wrapping the raw store/mutable; most trait methods
    /// go through this (write, delete, mkdirs, move_to, set_hash, …).
    net: BufferedNetwork,
    /// Raw store — needed for [`peergos_fs::upload_subtree`] which creates its
    /// own `BufferedNetwork` internally.
    raw_store: Arc<dyn ContentAddressedStorage>,
    raw_mutable: Arc<dyn MutablePointers>,
}

impl PeergosSyncFS {
    pub fn new(
        root: PathBuf,
        root_cap: AbsoluteCapability,
        signer: Option<SigningPrivateKeyAndPublicHash>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
        mirror_bat: Option<BatWithId>,
    ) -> Self {
        let net = BufferedNetwork::with_defaults(store.clone(), mutable.clone());
        PeergosSyncFS { root, root_cap, signer, net, mirror_bat, raw_store: store, raw_mutable: mutable }
    }

    fn owner(&self) -> &PublicKeyHash {
        &self.root_cap.owner
    }

    fn bstore(&self) -> Arc<dyn ContentAddressedStorage> {
        self.net.storage()
    }

    fn bmutable(&self) -> Arc<dyn MutablePointers> {
        self.net.pointers()
    }

    async fn resolve_cap(&self, p: &Path) -> Result<Option<AbsoluteCapability>> {
        let path_str = p.to_string_lossy();
        let components: Vec<&str> = path_str.split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut current = self.root_cap.clone();
        for comp in &components {
            let children = list_directory(&current, self.bstore(), &*self.bmutable()).await?;
            match children.into_iter().find(|e| e.name == *comp) {
                Some(child) => current = child.cap,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    fn mirror_bat_id(&self) -> Option<peergos_core::auth::BatId> {
        self.mirror_bat.as_ref().map(|b| b.id())
    }
}

#[async_trait(?Send)]
impl SyncFilesystem for PeergosSyncFS {
    fn get_root(&self) -> &Path {
        &self.root
    }

    async fn exists(&self, p: &Path) -> Result<bool> {
        Ok(self.resolve_cap(p).await?.is_some())
    }

    async fn mkdirs(&self, p: &Path) -> Result<()> {
        let p_str = p.to_string_lossy();
        if p_str.is_empty() || p == Path::new(".") || p == Path::new("/") {
            return Ok(());
        }
        let components: Vec<&str> = p_str.split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut current = self.root_cap.clone();
        for comp in &components {
            let children = list_directory(&current, self.bstore(), &*self.bmutable()).await?;
            if let Some(child) = children.into_iter().find(|e| e.name == *comp) {
                current = child.cap;
            } else {
                let new_cap = mkdir_hidden(&current, comp, self.signer.clone(), self.mirror_bat_id().as_ref(), self.bstore(), &*self.bmutable()).await?;
                current = new_cap;
            }
        }
        Ok(())
    }

    async fn delete(&self, p: &Path) -> Result<()> {
        self.resolve_cap(p).await?
            .ok_or_else(|| Error::Protocol(format!("not found: {}", p.display())))?;
        let parent_path = p.parent().map(|pp| {
            let s = pp.to_string_lossy();
            if s.is_empty() { PathBuf::from(".") } else { pp.to_path_buf() }
        }).unwrap_or_else(|| PathBuf::from("."));
        let parent = self.resolve_cap(&parent_path).await?
            .ok_or_else(|| Error::Protocol("parent not found".into()))?;
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        let signer = recover_signer(&parent, self.bstore(), &*self.bmutable()).await?;
        delete_child(&parent, &fname, Some(signer), self.mirror_bat_id().as_ref(), self.bstore(), &*self.bmutable()).await?;
        Ok(())
    }

    async fn bulk_delete(&self, dir: &Path, children: &[String]) -> Result<()> {
        for child in children {
            self.delete(&dir.join(child)).await?;
        }
        Ok(())
    }

    async fn move_to(&self, src: &Path, target: &Path) -> Result<()> {
        let src_parent = src.parent().unwrap_or(Path::new("."));
        let tgt_parent = target.parent().unwrap_or(Path::new("."));
        let src_name = src.file_name().unwrap().to_string_lossy().to_string();
        let tgt_name = target.file_name().unwrap().to_string_lossy().to_string();

        if src_parent == tgt_parent && src_name == tgt_name {
            return Ok(());
        }

        if src_parent == tgt_parent {
            // Same-directory rename — atomic metadata-only
            let parent = self.resolve_cap(src_parent).await?
                .ok_or_else(|| Error::Protocol("move_to: parent not found".into()))?;
            let signer = recover_signer(&parent, self.bstore(), &*self.bmutable()).await?;
            rename_child(&parent, &src_name, &tgt_name, Some(signer), self.mirror_bat_id().as_ref(), self.bstore(), &*self.bmutable()).await?;
            return Ok(());
        }

        // Cross-directory move: ensure target parent exists
        if !tgt_parent.to_string_lossy().is_empty() {
            self.mkdirs(tgt_parent).await?;
        }

        let src_parent_cap = self.resolve_cap(src_parent).await?
            .ok_or_else(|| Error::Protocol("move_to: source parent not found".into()))?;
        let tgt_parent_cap = self.resolve_cap(tgt_parent).await?
            .ok_or_else(|| Error::Protocol("move_to: target parent not found".into()))?;

        let signer = recover_signer(&src_parent_cap, self.bstore(), &*self.bmutable()).await?;

        // Use peergos_fs::move_to — fast path (metadata-only) when both dirs
        // share a writer, otherwise copy-under-fresh-keys + delete.
        peergos_fs::move_to(
            &src_parent_cap, &src_name, &tgt_parent_cap, true,
            Some(signer), self.mirror_bat_id().as_ref(),
            self.bstore(), &*self.bmutable(),
        ).await?;

        // Rename the child in the target directory if the filename changed
        if src_name != tgt_name {
            let tgt_signer = recover_signer(&tgt_parent_cap, self.bstore(), &*self.bmutable()).await?;
            rename_child(
                &tgt_parent_cap, &src_name, &tgt_name,
                Some(tgt_signer), self.mirror_bat_id().as_ref(),
                self.bstore(), &*self.bmutable(),
            ).await?;
        }

        Ok(())
    }

    async fn get_last_modified(&self, p: &Path) -> Result<i64> {
        let cap = self.resolve_cap(p).await?
            .ok_or_else(|| Error::Protocol(format!("not found: {}", p.display())))?;
        let (_node, props) = retrieve_file_metadata(&cap, self.bstore(), &*self.bmutable()).await?;
        let millis = props.modified_epoch * 1000;
        Ok(millis / 1000 * 1000)
    }

    async fn set_modification_time(&self, _p: &Path, _t: i64) -> Result<()> {
        Ok(())
    }

    async fn size(&self, p: &Path) -> Result<u64> {
        let cap = self.resolve_cap(p).await?
            .ok_or_else(|| Error::Protocol(format!("not found: {}", p.display())))?;
        let (_node, props) = retrieve_file_metadata(&cap, self.bstore(), &*self.bmutable()).await?;
        Ok(props.size)
    }

    async fn truncate(&self, p: &Path, size: u64) -> Result<()> {
        let cap = self.resolve_cap(p).await?
            .ok_or_else(|| Error::Protocol(format!("truncate: not found: {}", p.display())))?;
        let (_node, props) = retrieve_file_metadata(&cap, self.bstore(), &*self.bmutable()).await?;
        if size >= props.size {
            return Ok(());
        }
        let (_full_props, data) = read_file(&cap, self.bstore(), &*self.bmutable()).await?;
        let truncated = &data[..size as usize];
        let signer = recover_signer(&cap, self.bstore(), &*self.bmutable()).await?;
        rewrite_file_content(&cap, truncated, &signer, self.mirror_bat_id().as_ref(), self.bstore(), &*self.bmutable()).await?;
        Ok(())
    }

    async fn read(&self, p: &Path) -> Result<Vec<u8>> {
        let cap = self.resolve_cap(p).await?
            .ok_or_else(|| Error::Protocol(format!("not found: {}", p.display())))?;
        let (_props, data) = read_file(&cap, self.bstore(), &*self.bmutable()).await?;
        Ok(data)
    }

    async fn write(&self, p: &Path, data: &[u8], _file_offset: u64) -> Result<()> {
        let parent_path = p.parent().map(|pp| {
            let s = pp.to_string_lossy();
            if s.is_empty() { PathBuf::from(".") } else { pp.to_path_buf() }
        }).unwrap_or_else(|| PathBuf::from("."));
        let parent = self.resolve_cap(&parent_path).await?
            .ok_or_else(|| Error::Protocol("parent not found".into()))?;
        let fname = p.file_name().unwrap().to_string_lossy().to_string();
        let signer = recover_signer(&parent, self.bstore(), &*self.bmutable()).await?;
        upload_file(&parent, &fname, data, None, Some(signer), self.mirror_bat_id().as_ref(), self.bstore(), &*self.bmutable()).await?;

        Ok(())
    }

    async fn hash_file(&self, p: &Path, _size: u64) -> Result<[u8; 32]> {
        let data = self.read(p).await?;
        let root = peergos_fs::content_root_hash(&data)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&root.hash);
        Ok(hash)
    }

    async fn set_hash(&self, p: &Path, hash: [u8; 32], _size: u64) -> Result<()> {
        let cap = self.resolve_cap(p).await?
            .ok_or_else(|| Error::Protocol(format!("set_hash: not found: {}", p.display())))?;
        let (_node, props) = retrieve_file_metadata(&cap, self.bstore(), &*self.bmutable()).await?;
        if props.is_directory {
            return Err(Error::Protocol("cannot set hash on a directory".into()));
        }
        let parent_path = p.parent().map(|pp| {
            let s = pp.to_string_lossy();
            if s.is_empty() { std::path::PathBuf::from(".") } else { pp.to_path_buf() }
        }).unwrap_or_else(|| std::path::PathBuf::from("."));
        let dir_cap = self.resolve_cap(&parent_path).await?
            .ok_or_else(|| Error::Protocol("set_hash: parent not found".into()))?;
        let signer = recover_signer(&dir_cap, self.bstore(), &*self.bmutable()).await?;
        let branch = HashBranch {
            root_hash: RootHash { hash: hash.to_vec() },
            level1: None,
            level2: None,
            level3: None,
        };
        let mut new_props = props.clone();
        new_props.tree_hash = Some(branch);
        update_file_properties(
            &dir_cap,
            &cap,
            Some(signer),
            self.mirror_bat_id().as_ref(),
            new_props,
            self.bstore(),
            &*self.bmutable(),
        ).await?;
        Ok(())
    }

    async fn files_count(&self) -> Result<usize> {
        let count = std::sync::atomic::AtomicUsize::new(0);
        self.apply_to_subtree(
            &mut |_fp: FileProps| { count.fetch_add(1, std::sync::atomic::Ordering::Relaxed); },
            &mut |_fp: FileProps| {},
        ).await?;
        Ok(count.load(std::sync::atomic::Ordering::Relaxed))
    }

    async fn upload_subtree(&self, folders: Vec<UploadFolder>) -> Result<()> {
        let signer = self.signer.clone()
            .ok_or_else(|| Error::Protocol("upload_subtree: no signer".into()))?;
        let pfolders: Vec<FolderUpload> = folders.into_iter().map(|f| {
            let files: Vec<FileUpload> = f.files.into_iter().map(|uf| {
                FileUpload::from_bytes(uf.name, uf.data)
            }).collect();
            FolderUpload { rel_path: f.rel_path, files }
        }).collect();
        peergos_fs::upload_subtree(
            &self.root_cap,
            &self.root_cap,
            "",
            signer,
            self.mirror_bat_id().as_ref(),
            pfolders,
            self.raw_store.clone(),
            self.raw_mutable.clone(),
        ).await
    }

    async fn flush(&self) -> Result<()> {
        self.net.commit(self.owner()).await
    }

    async fn apply_to_subtree(&self, on_file: &mut (dyn FnMut(FileProps) + Send), on_dir: &mut (dyn FnMut(FileProps) + Send)) -> Result<()> {
        apply_to_subtree_recursive(
            PathBuf::new(), &self.root_cap, &self.bstore(), &*self.bmutable(), on_file, on_dir,
        ).await
    }

    async fn free_space(&self) -> Result<u64> {
        Ok(u64::MAX)
    }

    async fn total_space(&self) -> Result<u64> {
        Ok(u64::MAX)
    }
}

async fn apply_to_subtree_recursive(
    rel: PathBuf,
    cap: &AbsoluteCapability,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    on_file: &mut (dyn FnMut(FileProps) + Send),
    on_dir: &mut (dyn FnMut(FileProps) + Send),
) -> Result<()> {
    let children = list_directory(cap, store.clone(), mutable).await?;
    for child in children {
        let child_path = rel.join(&child.name);
        let rel_str = child_path.to_string_lossy().replace('\\', "/");
        let (node, props) = retrieve_file_metadata(&child.cap, store.clone(), mutable).await?;
        let millis = props.modified_epoch * 1000;
        let fp = FileProps {
            rel_path: rel_str,
            modified_time: millis / 1000 * 1000,
            size: props.size,
        };
        if node.is_directory() {
            on_dir(fp);
            Box::pin(apply_to_subtree_recursive(child_path, &child.cap, store, mutable, on_file, on_dir)).await?;
        } else {
            on_file(fp);
        }
    }
    Ok(())
}
