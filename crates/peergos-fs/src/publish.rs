//! Public publishing + website publishing, ported from Java's `makePublic` /
//! `getPublicCapability` / `InodeFileSystem`.
//!
//! Making a file public adds its read-only capability to a public path→cap map (an
//! [`InodeFileSystem`], a CHAMP of `Inode → DirectoryInode` keyed by sha256),
//! whose root is stored in `WriterData.public`. Anyone can then resolve
//! `/public/<owner>/<path>` — the gateway does exactly this and 302-redirects to the
//! read-only secret link each path is published through ([`PublishedLink`]). A website is just a public directory whose path is recorded in
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

/// The secret link a path is published through (`PublishedLink`). Its password sits
/// in the public tree on purpose: anyone may open a published file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedLink {
    pub label: i64,
    pub link_password: String,
}

impl PublishedLink {
    pub fn to_link(&self, owner: &PublicKeyHash) -> crate::SecretLink {
        crate::SecretLink { owner: owner.clone(), label: self.label, link_password: self.link_password.clone() }
    }
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("l", CborObject::Long(self.label))
            .put("p", CborObject::Str(self.link_password.clone()))
            .build()
    }
    fn from_cbor(cbor: &CborObject) -> Result<PublishedLink> {
        Ok(PublishedLink {
            label: cbor.get("l").and_then(|c| c.as_long()).ok_or_else(|| Error::Cbor("PublishedLink missing 'l'".into()))?,
            link_password: cbor
                .get("p")
                .and_then(|c| c.as_string())
                .ok_or_else(|| Error::Cbor("PublishedLink missing 'p'".into()))?
                .to_string(),
        })
    }
}

/// A child entry: an inode + (for a published file/dir) its capability (`InodeCap`).
/// `link` is absent on anything published before links were, and on the
/// directories in between.
#[derive(Debug, Clone)]
struct InodeCap {
    inode: Inode,
    cap: Option<AbsoluteCapability>,
    link: Option<PublishedLink>,
}

impl InodeCap {
    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("i", self.inode.to_cbor());
        if let Some(cap) = &self.cap {
            b = b.put("c", cap.to_cbor());
        }
        if let Some(link) = &self.link {
            b = b.put("l", link.to_cbor());
        }
        b.build()
    }
    fn from_cbor(cbor: &CborObject) -> Result<InodeCap> {
        Ok(InodeCap {
            inode: Inode::from_cbor(cbor.get("i").ok_or_else(|| Error::Cbor("InodeCap missing 'i'".into()))?)?,
            cap: cbor.get("c").map(AbsoluteCapability::from_cbor).transpose()?,
            link: cbor.get("l").map(PublishedLink::from_cbor).transpose()?,
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
        link: Option<&PublishedLink>,
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
                parent_dir
                    .add_child(InodeCap { inode: child_key, cap: Some(cap.clone()), link: link.cloned() }, &owner, signer, store.as_ref(), tid).await?;
                self.put_value(&parent_key, &parent_dir, signer, tid).await?;
            } else {
                // Interior: ensure the child directory exists and is linked.
                let child_dir_missing = self.get_value(&child_key).await?.is_none();
                if child_dir_missing {
                    self.put_value(&child_key, &DirectoryInode::default(), signer, tid).await?;
                }
                if existing.is_none() {
                    parent_dir.add_child(InodeCap { inode: child_key.clone(), cap: None, link: None }, &owner, signer, store.as_ref(), tid).await?;
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
        // Walk down, recording (dir inode, dir, child entry, had-other-children) at
        // each level. Bail if any element isn't present (nothing to remove).
        let mut cur_key = root;
        let mut chain: Vec<(Inode, DirectoryInode, InodeCap, bool)> = Vec::new();
        for (i, name) in elements.iter().enumerate() {
            let child = match cur_dir.get_child(name, &owner, store.as_ref()).await? {
                Some(c) => c,
                None => return Ok(()),
            };
            let had_other = cur_dir.child_count(&owner, store.as_ref()).await? > 1;
            chain.push((cur_key.clone(), cur_dir.clone(), child.clone(), had_other));
            if i + 1 < elements.len() {
                cur_key = child.inode.clone();
                cur_dir = match self.get_value(&cur_key).await? {
                    Some(d) => d,
                    None => return Ok(()),
                };
            }
        }
        let (leaf_key, mut leaf_dir, leaf, leaf_had_other) = chain.pop().expect("at least one element");
        let leaf_has_descendants = match self.get_value(&leaf.inode).await? {
            Some(d) => d.child_count(&owner, store.as_ref()).await? > 0,
            None => false,
        };
        if leaf_has_descendants {
            // something below is published in its own right, so keep the node and drop
            // only its capability, or that subtree is orphaned
            leaf_dir.add_child(InodeCap { inode: leaf.inode, cap: None, link: None }, &owner, signer, store.as_ref(), tid).await?;
            self.put_value(&leaf_key, &leaf_dir, signer, tid).await?;
            return Ok(());
        }
        leaf_dir.remove_child(&leaf.inode.name, &owner, signer, store.as_ref(), tid).await?;
        self.put_value(&leaf_key, &leaf_dir, signer, tid).await?;
        // Prune each ancestor whose only child we just removed, unless it is itself
        // published: an emptied published node is a live publication.
        let mut prune = !leaf_had_other;
        for (dir_key, mut dir, child, had_other_children) in chain.into_iter().rev() {
            if !prune || child.cap.is_some() {
                break;
            }
            dir.remove_child(&child.inode.name, &owner, signer, store.as_ref(), tid).await?;
            self.put_value(&dir_key, &dir, signer, tid).await?;
            prune = !had_other_children;
        }
        Ok(())
    }

    /// The most-privileged capability for `path` (`getByPath`).
    #[cfg(test)]
    async fn get_by_path(&self, path: &str) -> Result<Option<AbsoluteCapability>> {
        Ok(self.get_published(path).await?.and_then(|ic| ic.cap))
    }

    /// The closest published ancestor of `path` (or `path` itself).
    async fn get_published(&self, path: &str) -> Result<Option<InodeCap>> {
        let mut current = Inode::root();
        for name in &canonical_elements(path) {
            let dir = match self.get_value(&current).await? {
                Some(d) => d,
                None => return Ok(None),
            };
            let child = match dir.get_child(name, &self.owner, self.store.as_ref()).await? {
                Some(c) => c,
                None => return Ok(None),
            };
            if child.cap.is_some() {
                // A cap here grants access to it (and its descendants).
                return Ok(Some(child));
            }
            current = child.inode;
        }
        Ok(None)
    }

    /// What is published at exactly `path`, where `get_published` stops at the
    /// closest published ancestor (`publishedAt`).
    async fn published_at(&self, path: &str) -> Result<Option<InodeCap>> {
        let mut current = Inode::root();
        let mut found = None;
        for name in &canonical_elements(path) {
            let dir = match self.get_value(&current).await? {
                Some(d) => d,
                None => return Ok(None),
            };
            let child = match dir.get_child(name, &self.owner, self.store.as_ref()).await? {
                Some(c) => c,
                None => return Ok(None),
            };
            current = child.inode.clone();
            found = Some(child);
        }
        Ok(found)
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

/// Our identity WriterData, loaded to change its public filesystem.
struct PublicUpdate {
    owner: PublicKeyHash,
    signer: SigningPrivateKeyAndPublicHash,
    wd_cid: Cid,
    wd: CborObject,
    sequence: Option<i64>,
    public: Option<Cid>,
}

impl PublicUpdate {
    async fn load(ctx: &UserContext) -> Result<PublicUpdate> {
        let user = ctx.user().ok_or_else(|| Error::Protocol("not signed in".into()))?;
        let owner = user.identity.clone();
        let store = ctx.store();
        let pointer = ctx.mutable().get_pointer_target(&owner, &owner, store.as_ref()).await?;
        let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("no writer data".into()))?;
        let wd = store.get(&owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
        let public = wd.get("public").and_then(|c| c.as_link()).map(Cid::cast).transpose()?;
        Ok(PublicUpdate { owner, signer: user.signer.clone(), wd_cid, wd, sequence: pointer.sequence, public })
    }

    async fn filesystem(&self, ctx: &UserContext, tid: &TransactionId) -> Result<InodeFileSystem> {
        match &self.public {
            Some(root) => InodeFileSystem::load(self.owner.clone(), root, ctx.store()).await,
            None => InodeFileSystem::create_empty(self.owner.clone(), &self.signer, ctx.store(), tid).await,
        }
    }

    async fn commit(self, ctx: &UserContext, fs: &InodeFileSystem, tid: &TransactionId) -> Result<()> {
        let store = ctx.store();
        let public_cid = put_block_signed(store.as_ref(), &self.owner, &self.signer, fs.to_cbor().to_bytes(), tid).await?;
        // committing an unchanged root is a noop pointer update
        if self.public.as_ref() == Some(&public_cid) {
            return Ok(());
        }
        let new_wd = writer_data_with_public(&self.wd, &public_cid)?;
        let new_wd_cid = put_block_signed(store.as_ref(), &self.owner, &self.signer, new_wd.to_bytes(), tid).await?;
        let update = PointerUpdate::new(Some(self.wd_cid), Some(new_wd_cid), PointerUpdate::increment(self.sequence));
        if !ctx.mutable().set_pointer_update(&self.owner, &self.signer, &update).await? {
            return Err(Error::Protocol("public data pointer update rejected".into()));
        }
        Ok(())
    }
}

impl UserContext {
    /// Make the file/directory at home-relative `path` public (`makePublic`): mint
    /// a read-only secret link to it, which is what the public file handler
    /// redirects to, and add its read-only capability and that link to our public
    /// filesystem. Anyone can then resolve `/public/<username>/<path>`.
    pub async fn make_public(&self, path: &str) -> Result<()> {
        self.make_public_many(&[path.to_string()]).await
    }

    /// Make many files/directories public in a single `WriterData.public` commit
    /// (like calling [`make_public`] for each, but far fewer round-trips).
    pub async fn make_public_many(&self, paths: &[String]) -> Result<()> {
        if paths.is_empty() {
            return Ok(());
        }
        let username = self.username().ok_or_else(|| Error::Protocol("not signed in".into()))?.to_string();
        let current = PublicUpdate::load(self).await?;
        let existing_fs = match &current.public {
            Some(root) => Some(InodeFileSystem::load(current.owner.clone(), root, self.store()).await?),
            None => None,
        };
        let mut to_publish = Vec::new();
        for path in paths {
            let path = path.trim_matches('/').to_string();
            if path.is_empty() {
                return Err(Error::Protocol("You cannot publish your home directory!".into()));
            }
            let cap = self
                .get_by_path(&path)
                .await?
                .ok_or_else(|| Error::Protocol(format!("no file at {path}")))?
                .capability()
                .read_only();
            let public_path = format!("/{username}/{path}");
            if let Some(fs) = &existing_fs {
                // the profile republishes on every change, which mustn't mint a new link each time
                if let Some(e) = fs.published_at(&public_path).await? {
                    if e.cap.as_ref() == Some(&cap) && e.link.is_some() {
                        continue;
                    }
                }
            }
            to_publish.push((path, public_path, cap));
        }
        if to_publish.is_empty() {
            return Ok(());
        }
        let mut minted: Vec<(String, PublishedLink)> = Vec::new();
        for (path, _, _) in &to_publish {
            match self.create_secret_link_to(&[path.clone()], &[], "", None, None).await {
                Ok(props) => minted.push((
                    path.clone(),
                    PublishedLink { label: props.label, link_password: props.link_password },
                )),
                Err(e) => {
                    self.forget_published_links(&minted).await;
                    return Err(e);
                }
            }
        }
        // the links were written after `current` was loaded, so reload it
        let result = async {
            let update = PublicUpdate::load(self).await?;
            let store = self.store();
            let tid = store.start_transaction(&update.owner).await?;
            let mut fs = update.filesystem(self, &tid).await?;
            let mut previous = Vec::new();
            for ((path, public_path, cap), (_, link)) in to_publish.iter().zip(&minted) {
                if let Some(old) = fs.published_at(public_path).await?.and_then(|ic| ic.link) {
                    previous.push((path.clone(), old));
                }
                fs.add_cap(public_path, cap, Some(link), &update.signer, &tid).await?;
            }
            let owner = update.owner.clone();
            update.commit(self, &fs, &tid).await?;
            store.close_transaction(&owner, &tid).await?;
            Ok::<_, Error>(previous)
        }
        .await;
        match result {
            Ok(previous) => self.drop_published_links(&previous).await,
            Err(e) => {
                // a link nothing publishes would linger as a share of its own
                self.forget_published_links(&minted).await;
                Err(e)
            }
        }
    }

    async fn forget_published_links(&self, links: &[(String, PublishedLink)]) {
        for (path, link) in links {
            if let Err(e) = self.delete_secret_link_from(link.label, &[path.clone()]).await {
                log::warn!("Couldn't delete unused public link for {path}: {e}");
            }
        }
    }

    /// A link replaced or unpublished would otherwise keep opening the file, and
    /// keep showing as a share.
    async fn drop_published_links(&self, links: &[(String, PublishedLink)]) -> Result<()> {
        for (path, link) in links {
            self.delete_secret_link_from(link.label, &[path.clone()]).await?;
        }
        Ok(())
    }

    /// Resolve the public capability another user published at `path`
    /// (`/owner/...`) — the client half of the `/public/` gateway
    /// (`getPublicCapability`). `path`'s first component is the owner's username.
    pub async fn get_public_capability(&self, path: &str) -> Result<AbsoluteCapability> {
        let (_, published) = self.get_published(path).await?;
        published.cap.ok_or_else(|| Error::Protocol(format!("nothing published at {path}")))
    }

    /// The link the closest published ancestor of `path` (`/owner/...`) is
    /// published through (`getPublishedLink`).
    pub async fn get_published_link(&self, path: &str) -> Result<crate::SecretLink> {
        let (owner, published) = self.get_published(path).await?;
        match published.link {
            Some(link) => Ok(link.to_link(&owner)),
            None => Err(Error::Protocol(format!(
                "{} published this before public links existed, and has to publish it again",
                canonical_elements(path).first().cloned().unwrap_or_default()
            ))),
        }
    }

    /// The owner, and the closest published ancestor of `path`.
    async fn get_published(&self, path: &str) -> Result<(PublicKeyHash, InodeCap)> {
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
        let fs = InodeFileSystem::load(owner.clone(), &Cid::cast(public_link)?, store).await?;
        let published = fs
            .get_published(&format!("/{}", elements.join("/")))
            .await?
            .filter(|ic| ic.cap.is_some())
            .ok_or_else(|| Error::Protocol(format!("User {owner_name} has not published a file at {path}")))?;
        Ok((owner, published))
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
    /// its cap from our public filesystem, commit the new `WriterData.public`, and
    /// delete the link it was published through. A no-op if nothing was published there.
    pub async fn unpublish(&self, path: &str) -> Result<()> {
        let username = self.username().ok_or_else(|| Error::Protocol("not signed in".into()))?.to_string();
        let path = path.trim_matches('/').to_string();
        let public_path = format!("/{username}/{path}");
        let update = PublicUpdate::load(self).await?;
        if update.public.is_none() {
            return Ok(());
        }
        let store = self.store();
        let owner = update.owner.clone();
        let tid = store.start_transaction(&owner).await?;
        let mut fs = update.filesystem(self, &tid).await?;
        let removed = fs.published_at(&public_path).await?.and_then(|ic| ic.link);
        fs.remove_cap(&public_path, &update.signer, &tid).await?;
        update.commit(self, &fs, &tid).await?;
        store.close_transaction(&owner, &tid).await?;
        match removed {
            Some(link) => self.drop_published_links(&[(path, link)]).await,
            None => Ok(()),
        }
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
            fs.add_cap(&format!("/u/dir/file{i}"), &cap(&owner, i), None, &signer, &tid).await.unwrap();
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

    /// The cap published exactly at `path`, not at an ancestor.
    async fn exact(fs: &InodeFileSystem, path: &str) -> Option<AbsoluteCapability> {
        fs.published_at(path).await.unwrap()?.cap
    }

    /// Random publish / unpublish sequences over nested paths must leave exactly the
    /// published set resolvable (WebsitePublishingFuzzTests).
    #[tokio::test]
    async fn publish_and_unpublish_sequences_over_nested_paths() {
        let paths = ["/u/a", "/u/a/b", "/u/a/b/c", "/u/a/d", "/u/e", "/u/e/f/g"];
        let store: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
        let (pk, sk) = peergos_crypto::sign::keypair_from_seed(&[9u8; 32]).unwrap();
        let owner = PublicSigningKey::new(pk.to_vec()).hash().unwrap();
        let signer = SigningPrivateKeyAndPublicHash::new(owner.clone(), SecretSigningKey::new(sk.to_vec()));
        let tid = store.start_transaction(&owner).await.unwrap();
        let mut seed: u64 = 0x2545f4914f6cdd1d;
        for _round in 0..20 {
            let mut fs = InodeFileSystem::create_empty(owner.clone(), &signer, store.clone(), &tid).await.unwrap();
            let mut published = std::collections::BTreeSet::new();
            for _step in 0..25 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let i = (seed % paths.len() as u64) as usize;
                let path = paths[i];
                if (seed >> 32) % 2 == 0 {
                    fs.add_cap(path, &cap(&owner, i), None, &signer, &tid).await.unwrap();
                    published.insert(i);
                } else {
                    fs.remove_cap(path, &signer, &tid).await.unwrap();
                    published.remove(&i);
                }
                for (j, p) in paths.iter().enumerate() {
                    let got = exact(&fs, p).await.map(|c| c.map_key);
                    let want = published.contains(&j).then(|| cap(&owner, j).map_key);
                    assert_eq!(got, want, "{p} after {:?}", published);
                }
            }
        }
    }
}
