//! Public publishing + website publishing, ported from Java's `makePublic` /
//! `getPublicCapability` / `InodeFileSystem`.
//!
//! Making a file public adds its read-only capability to a public path→cap map (an
//! [`InodeFileSystem`], a CHAMP of `Inode → DirectoryInode` keyed by sha256),
//! whose root is stored in `WriterData.public`. Anyone can then resolve
//! `/public/<owner>/<path>` — the gateway does exactly this and 302-redirects to a
//! secret-link URL. A website is just a public directory whose path is recorded in
//! the profile `webroot` field.

use crate::capability::AbsoluteCapability;
use crate::context::UserContext;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::champ::{ChampWrapper, KeyHasher, BIT_WIDTH, MAX_HASH_COLLISIONS_PER_LEVEL};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use peergos_core::mutable::PointerUpdate;
use peergos_core::storage::{hash_to_cid, put_block_signed, ContentAddressedStorage, TransactionId};
use peergos_core::Champ;
use peergos_multiformats::Cid;
use std::sync::Arc;

/// Once a directory has this many children they move from an inline list into an
/// inner champ (`DirectoryInode.MAX_CHILDREN_INLINED`).
const MAX_CHILDREN_INLINED: usize = 32;

fn sha256_key_hasher() -> KeyHasher {
    Arc::new(|k: &[u8]| peergos_crypto::hash::sha256(k))
}

/// The inner-champ key + hash for a child name.
fn name_key(name: &str) -> Vec<u8> {
    name.as_bytes().to_vec()
}
fn name_hash(name: &str) -> Vec<u8> {
    peergos_crypto::hash::sha256(name.as_bytes())
}
fn champ_cid(champ: &Champ) -> Result<Cid> {
    Ok(hash_to_cid(&champ.serialize(), false)?)
}

// ---------------------------------------------------------------------------
// Inode types
// ---------------------------------------------------------------------------

/// A numbered, named node in the public filesystem (`Inode`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Inode {
    inode: u64,
    name: String,
}

impl Inode {
    fn root() -> Inode {
        Inode { inode: 0, name: String::new() }
    }
    fn to_cbor(&self) -> CborObject {
        CborObject::map().put("i", CborObject::Long(self.inode as i64)).put("n", CborObject::Str(self.name.clone())).build()
    }
    fn from_cbor(cbor: &CborObject) -> Result<Inode> {
        Ok(Inode {
            inode: cbor.get("i").and_then(|c| c.as_long()).unwrap_or(0).max(0) as u64,
            name: cbor.get("n").and_then(|c| c.as_string()).unwrap_or("").to_string(),
        })
    }
    /// The champ key for this inode.
    fn key(&self) -> Vec<u8> {
        self.to_cbor().to_bytes()
    }
}

/// A child entry: an inode + (for a published file/dir) its capability (`InodeCap`).
#[derive(Debug, Clone)]
struct InodeCap {
    inode: Inode,
    cap: Option<AbsoluteCapability>,
}

impl InodeCap {
    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("i", self.inode.to_cbor());
        if let Some(cap) = &self.cap {
            b = b.put("c", cap.to_cbor());
        }
        b.build()
    }
    fn from_cbor(cbor: &CborObject) -> Result<InodeCap> {
        Ok(InodeCap {
            inode: Inode::from_cbor(cbor.get("i").ok_or_else(|| Error::Cbor("InodeCap missing 'i'".into()))?)?,
            cap: cbor.get("c").map(AbsoluteCapability::from_cbor).transpose()?,
        })
    }
}

/// A directory's children (`DirectoryInode`): an inline list while small, an inner
/// champ once past `MAX_CHILDREN_INLINED`.
#[derive(Clone)]
enum DirectoryInode {
    Inline(Vec<InodeCap>),
    Champ(Champ),
}

impl Default for DirectoryInode {
    fn default() -> DirectoryInode {
        DirectoryInode::Inline(Vec::new())
    }
}

impl DirectoryInode {
    /// Inline form is a map `{c: [...]}`; champ form is the champ root node cbor
    /// (a list) embedded directly.
    fn to_cbor(&self) -> CborObject {
        match self {
            DirectoryInode::Inline(list) => {
                CborObject::map().put("c", CborObject::List(list.iter().map(InodeCap::to_cbor).collect())).build()
            }
            DirectoryInode::Champ(champ) => champ.to_cbor(),
        }
    }
    fn from_cbor(cbor: &CborObject) -> Result<DirectoryInode> {
        match cbor {
            CborObject::Map(_) => {
                let list = cbor
                    .get("c")
                    .and_then(|c| c.as_list())
                    .ok_or_else(|| Error::Cbor("DirectoryInode map without 'c'".into()))?
                    .iter()
                    .map(InodeCap::from_cbor)
                    .collect::<Result<Vec<_>>>()?;
                Ok(DirectoryInode::Inline(list))
            }
            _ => Ok(DirectoryInode::Champ(Champ::from_cbor(cbor)?)),
        }
    }

    async fn get_child(&self, name: &str, owner: &PublicKeyHash, store: &dyn ContentAddressedStorage) -> Result<Option<InodeCap>> {
        match self {
            DirectoryInode::Inline(list) => Ok(list.iter().find(|c| c.inode.name == name).cloned()),
            DirectoryInode::Champ(champ) => match champ.get(owner, &name_key(name), &name_hash(name), 0, BIT_WIDTH, store).await? {
                Some(cbor) => Ok(Some(InodeCap::from_cbor(&cbor)?)),
                None => Ok(None),
            },
        }
    }

    async fn child_count(&self, owner: &PublicKeyHash, store: &dyn ContentAddressedStorage) -> Result<usize> {
        match self {
            DirectoryInode::Inline(list) => Ok(list.len()),
            DirectoryInode::Champ(champ) => Ok(champ.collect_mappings(owner, store).await?.len()),
        }
    }

    /// Add/replace a child by name, converting to champ form at the threshold.
    async fn add_child(
        &mut self,
        child: InodeCap,
        owner: &PublicKeyHash,
        signer: &SigningPrivateKeyAndPublicHash,
        store: &dyn ContentAddressedStorage,
        tid: &TransactionId,
    ) -> Result<()> {
        match self {
            DirectoryInode::Inline(list) => {
                let exists = list.iter().any(|c| c.inode.name == child.inode.name);
                if exists || list.len() < MAX_CHILDREN_INLINED {
                    list.retain(|c| c.inode.name != child.inode.name);
                    list.push(child);
                    return Ok(());
                }
                // Convert the inline list (+ the new child) into a champ.
                let all: Vec<InodeCap> = list.iter().cloned().chain(std::iter::once(child)).collect();
                let mut champ = Champ::empty();
                let mut root = champ_cid(&champ)?;
                let hasher = sha256_key_hasher();
                for ic in &all {
                    let (nc, ncid) = champ
                        .put(owner, signer, &name_key(&ic.inode.name), &name_hash(&ic.inode.name), 0, &None,
                            &Some(ic.to_cbor()), BIT_WIDTH, MAX_HASH_COLLISIONS_PER_LEVEL, &hasher, tid, store, &root)
                        .await?;
                    champ = nc;
                    root = ncid;
                }
                *self = DirectoryInode::Champ(champ);
                Ok(())
            }
            DirectoryInode::Champ(champ) => {
                let key = name_key(&child.inode.name);
                let hash = name_hash(&child.inode.name);
                let expected = champ.get(owner, &key, &hash, 0, BIT_WIDTH, store).await?;
                let root = champ_cid(champ)?;
                let (nc, _) = champ
                    .put(owner, signer, &key, &hash, 0, &expected, &Some(child.to_cbor()), BIT_WIDTH,
                        MAX_HASH_COLLISIONS_PER_LEVEL, &sha256_key_hasher(), tid, store, &root)
                    .await?;
                *champ = nc;
                Ok(())
            }
        }
    }

    /// Remove a child by name.
    async fn remove_child(
        &mut self,
        name: &str,
        owner: &PublicKeyHash,
        signer: &SigningPrivateKeyAndPublicHash,
        store: &dyn ContentAddressedStorage,
        tid: &TransactionId,
    ) -> Result<()> {
        match self {
            DirectoryInode::Inline(list) => {
                list.retain(|c| c.inode.name != name);
                Ok(())
            }
            DirectoryInode::Champ(champ) => {
                let key = name_key(name);
                let hash = name_hash(name);
                let expected = champ.get(owner, &key, &hash, 0, BIT_WIDTH, store).await?;
                if expected.is_none() {
                    return Ok(());
                }
                let root = champ_cid(champ)?;
                let (nc, _) = champ
                    .remove(owner, signer, &key, &hash, 0, &expected, BIT_WIDTH, MAX_HASH_COLLISIONS_PER_LEVEL, tid, store, &root)
                    .await?;
                *champ = nc;
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InodeFileSystem (champ of Inode -> DirectoryInode)
// ---------------------------------------------------------------------------

/// The public path→capability filesystem (`InodeFileSystem`).
struct InodeFileSystem {
    inode_count: u64,
    champ: ChampWrapper,
    owner: PublicKeyHash,
    store: Arc<dyn ContentAddressedStorage>,
}

fn canonical_elements(path: &str) -> Vec<String> {
    path.trim_matches('/').split('/').filter(|s| !s.is_empty()).map(String::from).collect()
}

impl InodeFileSystem {
    /// An empty public filesystem (`createEmpty`).
    async fn create_empty(
        owner: PublicKeyHash,
        signer: &SigningPrivateKeyAndPublicHash,
        store: Arc<dyn ContentAddressedStorage>,
        tid: &peergos_core::storage::TransactionId,
    ) -> Result<InodeFileSystem> {
        let root_cid = put_block_signed(store.as_ref(), &owner, signer, Champ::empty().serialize(), tid).await?;
        let champ = ChampWrapper::create(owner.clone(), root_cid, None, store.clone(), sha256_key_hasher()).await?;
        Ok(InodeFileSystem { inode_count: 0, champ, owner, store })
    }

    /// Load from an `InodeFileSystem` cbor block `{c: count, r: champ-root}` (`build`).
    async fn load(
        owner: PublicKeyHash,
        block_cid: &Cid,
        store: Arc<dyn ContentAddressedStorage>,
    ) -> Result<InodeFileSystem> {
        let cbor = store.get(&owner, block_cid, None).await?.ok_or_else(|| Error::Protocol("public data block missing".into()))?;
        let inode_count = cbor.get("c").and_then(|c| c.as_long()).unwrap_or(0).max(0) as u64;
        let root = Cid::cast(cbor.get("r").and_then(|c| c.as_link()).ok_or_else(|| Error::Cbor("InodeFileSystem missing 'r'".into()))?)?;
        let champ = ChampWrapper::create(owner.clone(), root, None, store.clone(), sha256_key_hasher()).await?;
        Ok(InodeFileSystem { inode_count, champ, owner, store })
    }

    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("c", CborObject::Long(self.inode_count as i64))
            .put("r", CborObject::MerkleLink(self.champ.root_hash().to_bytes()))
            .build()
    }

    async fn get_value(&self, inode: &Inode) -> Result<Option<DirectoryInode>> {
        match self.champ.get(&inode.key()).await? {
            Some(cbor) => Ok(Some(DirectoryInode::from_cbor(&cbor)?)),
            None => Ok(None),
        }
    }

    /// Put a directory value, incrementing the inode count when the key is new.
    async fn put_value(
        &mut self,
        inode: &Inode,
        dir: &DirectoryInode,
        signer: &SigningPrivateKeyAndPublicHash,
        tid: &peergos_core::storage::TransactionId,
    ) -> Result<()> {
        let expected = self.champ.get(&inode.key()).await?;
        let is_new = expected.is_none();
        self.champ.put(signer, &inode.key(), &expected, Some(dir.to_cbor()), tid).await?;
        if is_new {
            self.inode_count += 1;
        }
        Ok(())
    }

    /// Add `cap` at `path` (`addCap`), walking/creating directory inodes.
    async fn add_cap(
        &mut self,
        path: &str,
        cap: &AbsoluteCapability,
        signer: &SigningPrivateKeyAndPublicHash,
        tid: &peergos_core::storage::TransactionId,
    ) -> Result<()> {
        let elements = canonical_elements(path);
        if elements.len() < 2 {
            return Err(Error::Protocol("cannot publish the root directory".into()));
        }
        // Ensure the root directory exists.
        let root = Inode::root();
        if self.get_value(&root).await?.is_none() {
            self.put_value(&root, &DirectoryInode::default(), signer, tid).await?;
        }

        let owner = self.owner.clone();
        let store = self.store.clone();
        let mut parent_key = root;
        for (i, name) in elements.iter().enumerate() {
            let mut parent_dir =
                self.get_value(&parent_key).await?.ok_or_else(|| Error::Protocol("directory inode vanished".into()))?;
            let existing = parent_dir.get_child(name, &owner, store.as_ref()).await?;
            let child_key = existing
                .as_ref()
                .map(|ic| ic.inode.clone())
                .unwrap_or_else(|| Inode { inode: self.inode_count, name: name.clone() });

            if i + 1 == elements.len() {
                // Leaf: attach the capability to this child in the parent directory.
                parent_dir.add_child(InodeCap { inode: child_key, cap: Some(cap.clone()) }, &owner, signer, store.as_ref(), tid).await?;
                self.put_value(&parent_key, &parent_dir, signer, tid).await?;
            } else {
                // Interior: ensure the child directory exists and is linked.
                let child_dir_missing = self.get_value(&child_key).await?.is_none();
                if child_dir_missing {
                    self.put_value(&child_key, &DirectoryInode::default(), signer, tid).await?;
                }
                if existing.is_none() {
                    parent_dir.add_child(InodeCap { inode: child_key.clone(), cap: None }, &owner, signer, store.as_ref(), tid).await?;
                    self.put_value(&parent_key, &parent_dir, signer, tid).await?;
                }
                parent_key = child_key;
            }
        }
        Ok(())
    }

    /// Remove the cap published at `path` (`removeCap`), pruning any directory
    /// inodes that become empty as a result.
    async fn remove_cap(
        &mut self,
        path: &str,
        signer: &SigningPrivateKeyAndPublicHash,
        tid: &peergos_core::storage::TransactionId,
    ) -> Result<()> {
        let elements = canonical_elements(path);
        if elements.is_empty() {
            return Ok(());
        }
        let owner = self.owner.clone();
        let store = self.store.clone();
        let root = Inode::root();
        let mut cur_dir = match self.get_value(&root).await? {
            Some(d) => d,
            None => return Ok(()),
        };
        // Walk down, recording (dir inode, dir, child name, had-other-children) at
        // each level. Bail if any element isn't present (nothing to remove).
        let mut cur_key = root;
        let mut chain: Vec<(Inode, DirectoryInode, String, bool)> = Vec::new();
        for (i, name) in elements.iter().enumerate() {
            let child = match cur_dir.get_child(name, &owner, store.as_ref()).await? {
                Some(c) => c,
                None => return Ok(()),
            };
            let had_other = cur_dir.child_count(&owner, store.as_ref()).await? > 1;
            chain.push((cur_key.clone(), cur_dir.clone(), name.clone(), had_other));
            if i + 1 < elements.len() {
                cur_key = child.inode.clone();
                cur_dir = match self.get_value(&cur_key).await? {
                    Some(d) => d,
                    None => return Ok(()),
                };
            }
        }
        // Remove the leaf, then prune each parent whose only child we just removed.
        let mut prune = true;
        for (dir_key, mut dir, child_name, had_other_children) in chain.into_iter().rev() {
            if !prune {
                break;
            }
            dir.remove_child(&child_name, &owner, signer, store.as_ref(), tid).await?;
            self.put_value(&dir_key, &dir, signer, tid).await?;
            prune = !had_other_children;
        }
        Ok(())
    }

    /// The most-privileged capability for `path` (`getByPath`).
    async fn get_by_path(&self, path: &str) -> Result<Option<AbsoluteCapability>> {
        let elements = canonical_elements(path);
        let mut current = Inode::root();
        for name in &elements {
            let dir = match self.get_value(&current).await? {
                Some(d) => d,
                None => return Ok(None),
            };
            let child = match dir.get_child(name, &self.owner, self.store.as_ref()).await? {
                Some(c) => c,
                None => return Ok(None),
            };
            if let Some(cap) = child.cap {
                // A cap here grants access to it (and its descendants).
                return Ok(Some(cap));
            }
            current = child.inode;
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// WriterData plumbing
// ---------------------------------------------------------------------------

/// Replace/insert the `public` merkle-link in a WriterData cbor map.
fn writer_data_with_public(wd: &CborObject, public_cid: &Cid) -> Result<CborObject> {
    let mut map = match wd {
        CborObject::Map(m) => m.clone(),
        _ => return Err(Error::Cbor("WriterData is not a map".into())),
    };
    map.insert(peergos_cbor::CborString::new("public"), CborObject::MerkleLink(public_cid.to_bytes()));
    Ok(CborObject::Map(map))
}

// ---------------------------------------------------------------------------
// Public API on UserContext
// ---------------------------------------------------------------------------

impl UserContext {
    /// Make the file/directory at home-relative `path` public: add its read-only
    /// capability to our public filesystem and commit the new `WriterData.public`
    /// root (`makePublic`). Anyone can then resolve `/public/<username>/<path>`.
    pub async fn make_public(&self, path: &str) -> Result<()> {
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let username = user.username.clone();
        let owner = user.identity.clone();
        let signer = user.signer.clone();
        let store = self.store();
        let mutable = self.mutable();

        // The file's read-only capability.
        let file = self
            .get_by_path(path)
            .await?
            .ok_or_else(|| Error::Protocol(format!("no file at {path}")))?;
        let cap = file.capability().read_only();
        let public_path = format!("/{username}/{}", path.trim_start_matches('/'));

        // Load our identity WriterData.
        let pointer = mutable.get_pointer_target(&owner, &owner, store.as_ref()).await?;
        let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("no writer data".into()))?;
        let wd = store.get(&owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;

        let tid = store.start_transaction(&owner).await?;
        // Load or create the public filesystem.
        let mut fs = match wd.get("public").and_then(|c| c.as_link()) {
            Some(link) => InodeFileSystem::load(owner.clone(), &Cid::cast(link)?, store.clone()).await?,
            None => InodeFileSystem::create_empty(owner.clone(), &signer, store.clone(), &tid).await?,
        };
        fs.add_cap(&public_path, &cap, &signer, &tid).await?;

        // Store the InodeFileSystem block and update WriterData.public.
        let public_cid = put_block_signed(store.as_ref(), &owner, &signer, fs.to_cbor().to_bytes(), &tid).await?;
        let new_wd = writer_data_with_public(&wd, &public_cid)?;
        let new_wd_cid = put_block_signed(store.as_ref(), &owner, &signer, new_wd.to_bytes(), &tid).await?;
        let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
        if !mutable.set_pointer_update(&owner, &signer, &update).await? {
            return Err(Error::Protocol("public data pointer update rejected".into()));
        }
        store.close_transaction(&owner, &tid).await?;
        Ok(())
    }

    /// Make many files/directories public in a single `WriterData.public` commit
    /// (like calling [`make_public`] for each, but far fewer round-trips).
    pub async fn make_public_many(&self, paths: &[String]) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let username = user.username.clone();
        let owner = user.identity.clone();
        let signer = user.signer.clone();
        let store = self.store();
        let mutable = self.mutable();

        let pointer = mutable.get_pointer_target(&owner, &owner, store.as_ref()).await?;
        let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("no writer data".into()))?;
        let wd = store.get(&owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;

        let tid = store.start_transaction(&owner).await?;
        let mut fs = match wd.get("public").and_then(|c| c.as_link()) {
            Some(link) => InodeFileSystem::load(owner.clone(), &Cid::cast(link)?, store.clone()).await?,
            None => InodeFileSystem::create_empty(owner.clone(), &signer, store.clone(), &tid).await?,
        };
        for path in paths {
            let cap = self
                .get_by_path(path)
                .await?
                .ok_or_else(|| Error::Protocol(format!("no file at {path}")))?
                .capability()
                .read_only();
            let public_path = format!("/{username}/{}", path.trim_start_matches('/'));
            fs.add_cap(&public_path, &cap, &signer, &tid).await?;
        }

        let public_cid = put_block_signed(store.as_ref(), &owner, &signer, fs.to_cbor().to_bytes(), &tid).await?;
        let new_wd = writer_data_with_public(&wd, &public_cid)?;
        let new_wd_cid = put_block_signed(store.as_ref(), &owner, &signer, new_wd.to_bytes(), &tid).await?;
        let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
        if !mutable.set_pointer_update(&owner, &signer, &update).await? {
            return Err(Error::Protocol("public data pointer update rejected".into()));
        }
        store.close_transaction(&owner, &tid).await?;
        Ok(())
    }

    /// Resolve the public capability another user published at `path`
    /// (`/owner/...`) — the client half of the `/public/` gateway
    /// (`getPublicCapability`). `path`'s first component is the owner's username.
    pub async fn get_public_capability(&self, path: &str) -> Result<AbsoluteCapability> {
        let elements = canonical_elements(path);
        let owner_name = elements.first().ok_or_else(|| Error::Protocol("empty public path".into()))?;
        let owner = crate::login::get_public_key_hash(self.poster().as_ref(), owner_name)
            .await?
            .ok_or_else(|| Error::Protocol(format!("unknown user: {owner_name}")))?;
        let store = self.store();
        let pointer = self.mutable().get_pointer_target(&owner, &owner, store.as_ref()).await?;
        let wd_cid = pointer.updated.ok_or_else(|| Error::Protocol("owner has no writer data".into()))?;
        let wd = store.get(&owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
        let public_link = wd
            .get("public")
            .and_then(|c| c.as_link())
            .ok_or_else(|| Error::Protocol(format!("{owner_name} has not made any files public")))?;
        let fs = InodeFileSystem::load(owner, &Cid::cast(public_link)?, store).await?;
        fs.get_by_path(&format!("/{}", elements.join("/")))
            .await?
            .ok_or_else(|| Error::Protocol(format!("nothing published at {path}")))
    }

    /// Publish the directory at home-relative `path` as your website. The gateway
    /// serves `https://<username><domain-suffix>/…` by reading the (public)
    /// `.profile/webroot` field, which points at your (public) web root directory.
    /// So this: (1) makes the web root dir public, (2) records its path in
    /// `.profile/webroot`, (3) makes that field public.
    pub async fn publish_website(&self, path: &str) -> Result<()> {
        let username = self.username().ok_or_else(|| Error::Protocol("not signed in".into()))?.to_string();
        self.make_public(path).await?;
        self.set_web_root(&format!("/{username}/{}", path.trim_start_matches('/'))).await?;
        self.make_public(&format!("{}/webroot", crate::profile::PROFILE_DIR)).await
    }

    /// Un-publish the file/directory at home-relative `path` (`removeCap`): remove
    /// its cap from our public filesystem and commit the new `WriterData.public`.
    /// A no-op if nothing was published there.
    pub async fn unpublish(&self, path: &str) -> Result<()> {
        let user = self.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let username = user.username.clone();
        let owner = user.identity.clone();
        let signer = user.signer.clone();
        let store = self.store();
        let mutable = self.mutable();
        let public_path = format!("/{username}/{}", path.trim_start_matches('/'));

        let pointer = mutable.get_pointer_target(&owner, &owner, store.as_ref()).await?;
        let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("no writer data".into()))?;
        let wd = store.get(&owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
        let public_link = match wd.get("public").and_then(|c| c.as_link()) {
            Some(l) => l.to_vec(),
            None => return Ok(()), // nothing is public
        };

        let tid = store.start_transaction(&owner).await?;
        let mut fs = InodeFileSystem::load(owner.clone(), &Cid::cast(&public_link)?, store.clone()).await?;
        fs.remove_cap(&public_path, &signer, &tid).await?;

        let public_cid = put_block_signed(store.as_ref(), &owner, &signer, fs.to_cbor().to_bytes(), &tid).await?;
        let new_wd = writer_data_with_public(&wd, &public_cid)?;
        let new_wd_cid = put_block_signed(store.as_ref(), &owner, &signer, new_wd.to_bytes(), &tid).await?;
        let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
        if !mutable.set_pointer_update(&owner, &signer, &update).await? {
            return Err(Error::Protocol("public data pointer update rejected".into()));
        }
        store.close_transaction(&owner, &tid).await?;
        Ok(())
    }

    /// Take a published website offline: un-publish the web-root directory and the
    /// public `.profile/webroot` field. (The profile field value is left as-is; the
    /// gateway can no longer resolve it once it is no longer public.)
    pub async fn unpublish_website(&self, path: &str) -> Result<()> {
        self.unpublish(path).await?;
        self.unpublish(&format!("{}/webroot", crate::profile::PROFILE_DIR)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peergos_core::keys::{PublicSigningKey, SecretSigningKey};
    use peergos_core::symmetric::SymmetricKey;
    use peergos_core::RamStorage;

    fn cap(owner: &PublicKeyHash, i: usize) -> AbsoluteCapability {
        let mut map_key = vec![0u8; 32];
        map_key[0] = i as u8;
        map_key[1] = (i >> 8) as u8;
        AbsoluteCapability::new(
            owner.clone(),
            owner.clone(),
            map_key,
            None,
            SymmetricKey::new(vec![i as u8; 32], false).unwrap(),
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn champ_form_directory_scales_past_32_children() {
        let store: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
        let (pk, sk) = peergos_crypto::sign::keypair_from_seed(&[7u8; 32]).unwrap();
        let owner = PublicSigningKey::new(pk.to_vec()).hash().unwrap();
        let signer = SigningPrivateKeyAndPublicHash::new(owner.clone(), SecretSigningKey::new(sk.to_vec()));
        let tid = store.start_transaction(&owner).await.unwrap();
        let mut fs = InodeFileSystem::create_empty(owner.clone(), &signer, store.clone(), &tid).await.unwrap();

        // Publish 40 files in one directory — forces the inline→champ conversion.
        const N: usize = 40;
        for i in 0..N {
            fs.add_cap(&format!("/u/dir/file{i}"), &cap(&owner, i), &signer, &tid).await.unwrap();
        }
        // Every file resolves back to its own capability.
        for i in 0..N {
            let resolved = fs.get_by_path(&format!("/u/dir/file{i}")).await.unwrap().expect("published");
            assert_eq!(resolved.map_key, cap(&owner, i).map_key, "file{i}");
        }
        // "dir" is now stored in champ form.
        let root_dir = fs.get_value(&Inode::root()).await.unwrap().unwrap();
        let u = root_dir.get_child("u", &owner, store.as_ref()).await.unwrap().unwrap();
        let u_dir = fs.get_value(&u.inode).await.unwrap().unwrap();
        let dir = u_dir.get_child("dir", &owner, store.as_ref()).await.unwrap().unwrap();
        let dir_inode = fs.get_value(&dir.inode).await.unwrap().unwrap();
        assert!(matches!(dir_inode, DirectoryInode::Champ(_)), "dir with {N} children should be champ-form");
        assert_eq!(dir_inode.child_count(&owner, store.as_ref()).await.unwrap(), N);

        // Removing one leaves the rest intact.
        fs.remove_cap("/u/dir/file0", &signer, &tid).await.unwrap();
        assert!(fs.get_by_path("/u/dir/file0").await.unwrap().is_none());
        assert!(fs.get_by_path("/u/dir/file39").await.unwrap().is_some());
        assert_eq!(fs.get_by_path("/u/dir/file20").await.unwrap().unwrap().map_key, cap(&owner, 20).map_key);
    }
}
