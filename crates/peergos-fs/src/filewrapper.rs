//! `FileWrapper`: an ergonomic handle to a file or directory, in the spirit of
//! Java's `FileWrapper`. It bundles the item's capability, its cached properties
//! and the writer signer, plus handles to the block store and mutable pointers,
//! so callers navigate and mutate the filesystem with methods instead of
//! threading `(cap, store, mutable, entry_signer)` through free functions.
//!
//! Link nodes (from write-sharing) are followed transparently, so `children()` /
//! `child()` return the real targets. Mutations delegate to the crate's free
//! functions, which recover a descendant's own writer where present and otherwise
//! use the carried signer.

use crate::cache::CryptreeCache;
use crate::capability::AbsoluteCapability;
use crate::cryptree::FileProperties;
use crate::login::LoggedInUser;
use crate::DirEntry;
use peergos_core::error::{Error, Result};
use peergos_core::keys::SigningPrivateKeyAndPublicHash;
use peergos_core::mutable::MutablePointers;
use peergos_core::storage::ContentAddressedStorage;
use std::sync::Arc;

/// Join a home-relative directory path and a child name.
fn join(dir: &str, name: &str) -> String {
    let dir = dir.trim_matches('/');
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// A handle to a file or directory.
#[derive(Clone)]
pub struct FileWrapper {
    name: String,
    cap: AbsoluteCapability,
    props: FileProperties,
    /// The writer signer for writes into this subtree (own writers are recovered
    /// automatically by the underlying functions; this is the inherited fallback).
    signer: Option<SigningPrivateKeyAndPublicHash>,
    /// Home-relative path (used for display, `get_by_path` and transaction names).
    path: String,
    /// The user's home directory, where `.transactions` lives — the anchor for
    /// routing a multi-chunk upload through a crash-safe transaction. `None` for a
    /// secret-link / public-link context (Java's `transactions == null`), where
    /// uploads are always atomic.
    home_cap: Option<AbsoluteCapability>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: Arc<dyn MutablePointers>,
    /// Session-shared decrypted-cryptree-node cache; inherited by navigation so a
    /// path walk / list / read reuses already-decrypted nodes.
    cache: CryptreeCache,
}

impl FileWrapper {
    /// The user's home directory as a `FileWrapper`.
    pub async fn home(
        user: &LoggedInUser,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<FileWrapper> {
        let cap = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?.clone();
        let cache = CryptreeCache::new();
        let props = crate::retrieve_file_metadata_cached(&cap, store.clone(), mutable.as_ref(), &cache).await?.1;
        let signer = crate::recover_signer(&cap, store.clone(), mutable.as_ref()).await.ok();
        Ok(FileWrapper {
            name: user.username.clone(),
            home_cap: Some(cap.clone()),
            cap,
            props,
            signer,
            path: String::new(),
            store,
            mutable,
            cache,
        })
    }

    /// Replace this wrapper's cryptree-node cache (used by [`crate::UserContext`] to
    /// share one cache across every wrapper it hands out).
    pub fn with_cache(mut self, cache: CryptreeCache) -> FileWrapper {
        self.cache = cache;
        self
    }

    /// Wrap a capability directly (fetching its properties). `signer` is the writer
    /// signer to use for writes into this subtree (e.g. from `recover_signer`);
    /// `home_cap` is the user's home directory (where `.transactions` lives), or
    /// `None` for a secret-link context (uploads then stay atomic).
    #[allow(clippy::too_many_arguments)]
    pub async fn from_cap(
        cap: AbsoluteCapability,
        name: impl Into<String>,
        path: impl Into<String>,
        signer: Option<SigningPrivateKeyAndPublicHash>,
        home_cap: Option<AbsoluteCapability>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<FileWrapper> {
        let cache = CryptreeCache::new();
        let props = crate::retrieve_file_metadata_cached(&cap, store.clone(), mutable.as_ref(), &cache).await?.1;
        Ok(FileWrapper { name: name.into(), cap, props, signer, path: path.into(), home_cap, store, mutable, cache })
    }

    // ---- accessors ---------------------------------------------------------
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn capability(&self) -> &AbsoluteCapability {
        &self.cap
    }
    pub fn properties(&self) -> &FileProperties {
        &self.props
    }
    pub fn is_directory(&self) -> bool {
        self.props.is_directory
    }
    pub fn size(&self) -> u64 {
        self.props.size
    }
    pub fn is_writable(&self) -> bool {
        self.cap.is_writable()
    }
    /// The writer signer carried for writes into this subtree.
    pub fn signer(&self) -> Option<&SigningPrivateKeyAndPublicHash> {
        self.signer.as_ref()
    }

    // ---- navigation --------------------------------------------------------

    /// Wrap a directory entry, transparently following a link node to its target.
    async fn wrap_child(&self, e: DirEntry) -> Result<FileWrapper> {
        let props = crate::retrieve_file_metadata_cached(&e.cap, self.store.clone(), self.mutable.as_ref(), &self.cache).await?.1;
        let (cap, props) = if props.is_link {
            let target = crate::list_directory_cached(&e.cap, self.store.clone(), self.mutable.as_ref(), &self.cache)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| Error::Protocol("link node has no target".into()))?
                .cap;
            let tprops = crate::retrieve_file_metadata_cached(&target, self.store.clone(), self.mutable.as_ref(), &self.cache).await?.1;
            (target, tprops)
        } else {
            (e.cap, props)
        };
        Ok(FileWrapper {
            path: join(&self.path, &e.name),
            name: e.name,
            cap,
            props,
            signer: self.signer.clone(),
            home_cap: self.home_cap.clone(),
            store: self.store.clone(),
            mutable: self.mutable.clone(),
            cache: self.cache.clone(),
        })
    }

    /// Build a root `FileWrapper` for a secret-link capability (no transaction
    /// anchor, so uploads stay atomic — Java's `fromSecretLink` context).
    pub(crate) async fn from_link_cap(
        cap: AbsoluteCapability,
        signer: Option<SigningPrivateKeyAndPublicHash>,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<FileWrapper> {
        let cache = CryptreeCache::new();
        let props = crate::retrieve_file_metadata_cached(&cap, store.clone(), mutable.as_ref(), &cache).await?.1;
        let name = props.name.clone();
        Ok(FileWrapper { name, cap, props, signer, path: String::new(), home_cap: None, store, mutable, cache })
    }

    /// The children of this directory (`getChildren`), link nodes followed.
    /// Resolves all child caps in batched, locally-verified `champ/get` calls
    /// (via [`crate::retrieve_all_metadata`]) rather than one round-trip per child.
    pub async fn children(&self) -> Result<Vec<FileWrapper>> {
        if !self.is_directory() {
            return Err(Error::Protocol("not a directory".into()));
        }
        let entries = crate::list_directory_cached(&self.cap, self.store.clone(), self.mutable.as_ref(), &self.cache).await?;
        let caps: Vec<_> = entries.iter().map(|e| e.cap.clone()).collect();
        let (retrieved, _absent) =
            crate::retrieve_all_metadata_cached(&caps, self.store.clone(), self.mutable.as_ref(), &self.cache).await?;
        let mut by_key: std::collections::HashMap<Vec<u8>, crate::RetrievedCapability> =
            retrieved.into_iter().map(|rc| (rc.cap.map_key.clone(), rc)).collect();

        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            match by_key.remove(&e.cap.map_key) {
                // Plain child: build directly from the batch-retrieved metadata.
                Some(rc) if !rc.properties.is_link => out.push(FileWrapper {
                    path: join(&self.path, &e.name),
                    name: e.name,
                    cap: rc.cap,
                    props: rc.properties,
                    signer: self.signer.clone(),
                    home_cap: self.home_cap.clone(),
                    store: self.store.clone(),
                    mutable: self.mutable.clone(),
                    cache: self.cache.clone(),
                }),
                // Link node (or unexpectedly absent): follow it via the per-child path.
                _ => out.push(self.wrap_child(e).await?),
            }
        }
        Ok(out)
    }

    /// The child with the given name, if present (`getChild`).
    pub async fn child(&self, name: &str) -> Result<Option<FileWrapper>> {
        let entry = crate::list_directory_cached(&self.cap, self.store.clone(), self.mutable.as_ref(), &self.cache)
            .await?
            .into_iter()
            .find(|e| e.name == name);
        match entry {
            Some(e) => Ok(Some(self.wrap_child(e).await?)),
            None => Ok(None),
        }
    }

    /// Resolve a `/`-separated path relative to this directory (`getByPath`).
    pub async fn get_by_path(&self, path: &str) -> Result<Option<FileWrapper>> {
        let mut cur = self.clone();
        for comp in path.trim_matches('/').split('/').filter(|s| !s.is_empty()) {
            match cur.child(comp).await? {
                Some(next) => cur = next,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    // ---- reading -----------------------------------------------------------

    /// Read the whole file (`getInputStream` + read to end).
    pub async fn read(&self) -> Result<Vec<u8>> {
        if self.is_directory() {
            return Err(Error::Protocol("cannot read a directory".into()));
        }
        let mut data = Vec::new();
        crate::read_file_to_cached(&self.cap, self.store.clone(), self.mutable.as_ref(), &self.cache, |chunk| {
            data.extend_from_slice(chunk);
            Ok(())
        })
        .await?;
        Ok(data)
    }

    /// Read only `[offset, offset+length)` of this file, fetching just the chunk(s)
    /// that overlap the range (`getInputStream(...).seek(offset)`).
    pub async fn read_section(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        if self.is_directory() {
            return Err(Error::Protocol("cannot read a directory".into()));
        }
        crate::read_file_section_cached(&self.cap, offset, length, self.store.clone(), self.mutable.as_ref(), &self.cache).await
    }

    /// Overwrite `[offset, offset+data.len())` of this file in place, touching only
    /// the overlapping chunk(s) (`overwriteSection`). The range must stay within the
    /// current file size. Requires write access.
    pub async fn overwrite_section(&self, offset: u64, data: &[u8]) -> Result<()> {
        if self.is_directory() {
            return Err(Error::Protocol("cannot overwrite a directory".into()));
        }
        let signer = crate::recover_signer(&self.cap, self.store.clone(), self.mutable.as_ref())
            .await
            .ok()
            .or_else(|| self.signer.clone())
            .ok_or_else(|| Error::Protocol("no writer available to overwrite this file".into()))?;
        let prior = self.writer_root().await;
        let changed = crate::overwrite_file_section(&self.cap, offset, data, &signer, self.store.clone(), self.mutable.as_ref()).await?;
        let changed_refs: Vec<&[u8]> = changed.iter().map(|k| k.as_slice()).collect();
        self.migrate_cache(prior, &changed_refs).await;
        Ok(())
    }

    /// The sha256 of this file's current contents (`getContentHash`). Reads the whole
    /// file, so prefer for modestly-sized files.
    pub async fn content_hash(&self) -> Result<Vec<u8>> {
        if self.is_directory() {
            return Err(Error::Protocol("cannot hash a directory".into()));
        }
        Ok(peergos_crypto::hash::sha256(&self.read().await?))
    }

    /// The number of direct children of this directory (`getDirectChildrenCount`),
    /// counting the child links without fetching the children themselves.
    pub async fn direct_children_count(&self) -> Result<usize> {
        if !self.is_directory() {
            return Ok(0);
        }
        Ok(crate::list_directory(&self.cap, self.store.clone(), self.mutable.as_ref()).await?.len())
    }

    /// Re-read this handle from its capability to pick up the latest committed
    /// version (`getLatest`).
    pub async fn get_latest(&self) -> Result<FileWrapper> {
        Ok(FileWrapper::from_cap(
            self.cap.clone(),
            self.name.clone(),
            self.path.clone(),
            self.signer.clone(),
            self.home_cap.clone(),
            self.store.clone(),
            self.mutable.clone(),
        )
        .await?
        .with_cache(self.cache.clone()))
    }

    // ---- mutation ----------------------------------------------------------

    /// This directory's writer's current champ tree root (for cache migration).
    async fn writer_root(&self) -> Option<peergos_multiformats::Cid> {
        crate::open_writer_root(&self.cap, &self.store, self.mutable.as_ref()).await.ok()
    }

    /// After a mutation of this directory changed its writer's tree root, migrate
    /// the shared cryptree cache forward (Java's `cache.update` at commit): unchanged
    /// siblings stay warm, the touched `changed_keys` are dropped so they refetch.
    async fn migrate_cache(&self, prior_root: Option<peergos_multiformats::Cid>, changed_keys: &[&[u8]]) {
        let Some(prior) = prior_root else { return };
        if let Ok(new) = crate::open_writer_root(&self.cap, &self.store, self.mutable.as_ref()).await {
            if new != prior {
                let keys: Vec<Vec<u8>> = changed_keys.iter().map(|k| k.to_vec()).collect();
                self.cache.migrate(&prior, &new, &keys);
            }
        }
    }

    /// Create a subdirectory and return its wrapper (`mkdir`).
    pub async fn mkdir(&self, name: &str) -> Result<FileWrapper> {
        let prior = self.writer_root().await;
        crate::create_directory(&self.cap, name, self.signer.clone(), self.store.clone(), self.mutable.as_ref())
            .await?;
        self.migrate_cache(prior, &[&self.cap.map_key]).await;
        self.child(name).await?.ok_or_else(|| Error::Protocol("mkdir did not create the directory".into()))
    }

    /// Resolve a `/`-separated path under this directory, creating any missing
    /// directories along the way, and return the leaf (`getOrMkdirs`).
    pub async fn get_or_mkdirs(&self, path: &str) -> Result<FileWrapper> {
        let mut cur = self.clone();
        for comp in path.trim_matches('/').split('/').filter(|s| !s.is_empty()) {
            cur = match cur.child(comp).await? {
                Some(c) => c,
                None => cur.mkdir(comp).await?,
            };
        }
        Ok(cur)
    }

    /// Remove several children of this directory (`deleteChildren`).
    pub async fn delete_children(&self, names: &[&str]) -> Result<()> {
        for name in names {
            self.remove_child(name).await?;
        }
        Ok(())
    }

    /// Append `data` to the end of this file (`appendFile`). Currently supports the
    /// result staying within a single chunk (<= 5 MiB). Requires write access.
    pub async fn append(&self, data: &[u8]) -> Result<()> {
        if self.is_directory() {
            return Err(Error::Protocol("cannot append to a directory".into()));
        }
        if data.is_empty() {
            return Ok(());
        }
        if self.size() + data.len() as u64 > crate::CHUNK_MAX_SIZE {
            return Err(Error::Protocol("append that would cross a chunk boundary is not supported yet".into()));
        }
        let signer = crate::recover_signer(&self.cap, self.store.clone(), self.mutable.as_ref())
            .await
            .ok()
            .or_else(|| self.signer.clone())
            .ok_or_else(|| Error::Protocol("no writer available to append to this file".into()))?;
        let mut content = self.read().await?;
        content.extend_from_slice(data);
        let prior = self.writer_root().await;
        crate::overwrite_file(&self.cap, &content, &signer, self.store.clone(), self.mutable.as_ref()).await?;
        self.migrate_cache(prior, &[&self.cap.map_key]).await;
        Ok(())
    }

    /// Shrink this file to `new_size` bytes (`truncate`). No-op if already that small
    /// or smaller. Currently supports single-chunk files (<= 5 MiB).
    pub async fn truncate(&self, new_size: u64) -> Result<()> {
        if self.is_directory() {
            return Err(Error::Protocol("cannot truncate a directory".into()));
        }
        if new_size >= self.size() {
            return Ok(());
        }
        if self.size() > crate::CHUNK_MAX_SIZE {
            return Err(Error::Protocol("truncate of multi-chunk files is not supported yet".into()));
        }
        let signer = crate::recover_signer(&self.cap, self.store.clone(), self.mutable.as_ref())
            .await
            .ok()
            .or_else(|| self.signer.clone())
            .ok_or_else(|| Error::Protocol("no writer available to truncate this file".into()))?;
        let content = self.read().await?;
        let prior = self.writer_root().await;
        crate::overwrite_file(&self.cap, &content[..new_size as usize], &signer, self.store.clone(), self.mutable.as_ref()).await?;
        self.migrate_cache(prior, &[&self.cap.map_key]).await;
        Ok(())
    }

    /// Upload a file into this directory and return its wrapper (`uploadFile`).
    /// Multi-chunk files (`> CHUNK_MAX_SIZE`) go through a crash-safe transaction;
    /// single-chunk files are written atomically — matching Java's `uploadFilePart`.
    pub async fn upload(&self, name: &str, data: &[u8]) -> Result<FileWrapper> {
        let path = join(&self.path, name);
        let prior = self.writer_root().await;
        match &self.home_cap {
            Some(home) => {
                crate::upload_file_auto(
                    home,
                    &self.cap,
                    &path,
                    name,
                    data,
                    None,
                    self.signer.clone(),
                    self.store.clone(),
                    self.mutable.as_ref(),
                )
                .await?;
            }
            None => {
                crate::upload_file(&self.cap, name, data, None, self.signer.clone(), self.store.clone(), self.mutable.as_ref())
                    .await?;
            }
        }
        self.migrate_cache(prior, &[&self.cap.map_key]).await;
        self.child(name).await?.ok_or_else(|| Error::Protocol("upload did not create the file".into()))
    }

    /// Upload from a streaming reader (bounded RAM), routing large files through a
    /// crash-safe transaction. `open` must re-yield a reader over the same content.
    pub async fn upload_streaming<R, F>(&self, name: &str, size: u64, open: F) -> Result<FileWrapper>
    where
        R: std::io::Read,
        F: Fn() -> std::io::Result<R>,
    {
        let path = join(&self.path, name);
        let prior = self.writer_root().await;
        match &self.home_cap {
            Some(home) => {
                crate::upload_file_streaming_auto(
                    home,
                    &self.cap,
                    &path,
                    name,
                    size,
                    None,
                    self.signer.clone(),
                    open,
                    self.store.clone(),
                    self.mutable.as_ref(),
                )
                .await?;
            }
            None => {
                crate::upload_file_streaming(
                    &self.cap,
                    name,
                    size,
                    None,
                    self.signer.clone(),
                    open,
                    self.store.clone(),
                    self.mutable.as_ref(),
                )
                .await?;
            }
        }
        self.migrate_cache(prior, &[&self.cap.map_key]).await;
        self.child(name).await?.ok_or_else(|| Error::Protocol("upload did not create the file".into()))
    }

    /// Remove a child (file or directory) from this directory (`remove`).
    pub async fn remove_child(&self, name: &str) -> Result<()> {
        // Resolve the child first so we can drop its own cache entry (it is removed,
        // not merely re-keyed) along with this directory's node. Best-effort.
        let child_key = self.child(name).await.ok().flatten().map(|c| c.cap.map_key.clone());
        let prior = self.writer_root().await;
        crate::delete_child(&self.cap, name, self.signer.clone(), self.store.clone(), self.mutable.as_ref()).await?;
        let mut changed: Vec<&[u8]> = vec![&self.cap.map_key];
        if let Some(k) = &child_key {
            changed.push(k);
        }
        self.migrate_cache(prior, &changed).await;
        Ok(())
    }

    /// Rename a child within this directory (`rename`).
    pub async fn rename_child(&self, old_name: &str, new_name: &str) -> Result<()> {
        let child_key = self.child(old_name).await.ok().flatten().map(|c| c.cap.map_key.clone());
        let prior = self.writer_root().await;
        crate::rename_child(&self.cap, old_name, new_name, self.signer.clone(), self.store.clone(), self.mutable.as_ref())
            .await?;
        let mut changed: Vec<&[u8]> = vec![&self.cap.map_key];
        if let Some(k) = &child_key {
            changed.push(k);
        }
        self.migrate_cache(prior, &changed).await;
        Ok(())
    }

    /// Move a child of this directory into `target` (`moveTo`). See
    /// [`crate::move_to`] for the fast/slow path semantics.
    pub async fn move_child(&self, name: &str, target: &FileWrapper, keep_access: bool) -> Result<AbsoluteCapability> {
        let child_key = self.child(name).await.ok().flatten().map(|c| c.cap.map_key.clone());
        let src_prior = self.writer_root().await;
        let dst_prior = target.writer_root().await;
        let moved = crate::move_to(&self.cap, name, &target.cap, keep_access, self.signer.clone(), self.store.clone(), self.mutable.as_ref())
            .await?;
        // Both the source directory (child removed) and destination (child added)
        // changed. They may share a writer/tree or not; migrate each independently.
        let mut src_changed: Vec<&[u8]> = vec![&self.cap.map_key];
        if let Some(k) = &child_key {
            src_changed.push(k);
        }
        self.migrate_cache(src_prior, &src_changed).await;
        target.migrate_cache(dst_prior, &[&target.cap.map_key]).await;
        Ok(moved)
    }

    /// Copy a child of this directory into `target` (`copyTo`, unique-named).
    pub async fn copy_child(&self, name: &str, target: &FileWrapper) -> Result<AbsoluteCapability> {
        crate::copy_to(&self.cap, name, &target.cap, self.signer.clone(), self.store.clone(), self.mutable.as_ref())
            .await
    }
}

impl std::fmt::Debug for FileWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWrapper")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("is_dir", &self.props.is_directory)
            .field("size", &self.props.size)
            .field("writable", &self.cap.is_writable())
            .finish()
    }
}
