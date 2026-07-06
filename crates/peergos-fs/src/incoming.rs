//! `IncomingCapCache`: your local mirror of the capabilities other users have
//! shared with you, ported from `peergos.shared.user.IncomingCapCache`.
//!
//! To avoid reparsing every friend's whole sharing file at each login, new caps
//! are retrieved (with their paths, via [`crate::CapabilityWithPath`]) and stored
//! in a mirror directory tree rooted at `/you/.capabilitycache/world/`. A file
//! shared at `/alice/docs/f.txt` is mirrored under `world/alice/docs/` whose
//! `items.cbor` ([`CapsInDirectory`]) lists `f.txt` → its cap + who shared it. How
//! far we have read each friend's read/write cap streams is persisted in
//! `/you/.capabilitycache/<friend>$incoming.cbor` ([`ProcessedCaps`]), so updates
//! only process newly-added caps.
//!
//! This port covers the core: incremental per-friend update into the mirror, and
//! path lookup (`get_by_path` / `get_children`), including entering a shared
//! directory cap to reach descendants. Social *groups* and the writable-descendant
//! privilege escalation of Java's `getByPath` are out of scope (see the module's
//! cbor keeps a group map, always empty here, for forward compatibility).

use crate::capability::AbsoluteCapability;
use crate::login::LoggedInUser;
use crate::social::CapabilityWithPath;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use peergos_core::mutable::MutablePointers;
use peergos_core::storage::ContentAddressedStorage;
use peergos_multiformats::Cid;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CAP_CACHE_DIR: &str = ".capabilitycache";
const WORLD_ROOT_NAME: &str = "world";
const FRIEND_STATE_SUFFIX: &str = "$incoming.cbor";
const FRIEND_GROUPS_SUFFIX: &str = "$groups.cbor";
const DIR_STATE: &str = "items.cbor";

fn split_path(path: &str) -> Vec<String> {
    path.trim_matches('/').split('/').filter(|s| !s.is_empty()).map(String::from).collect()
}

/// If `path` is a social-group sharing directory (`/owner/shared/<uid>`, uid
/// dot-prefixed), return its uid.
fn group_uid_from_path(path: &str) -> Option<String> {
    let comps = split_path(path);
    if comps.len() == 3 && comps[1] == "shared" && comps[2].starts_with('.') {
        Some(comps[2].clone())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Persisted state types
// ---------------------------------------------------------------------------

/// A mirrored child: its name, the (highest-privilege) capability, and the friends
/// who shared it (`IncomingCapCache.ChildElement`).
#[derive(Debug, Clone)]
pub struct ChildElement {
    pub name: String,
    pub cap: AbsoluteCapability,
    pub sharers: Vec<String>,
}

impl ChildElement {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("n", CborObject::Str(self.name.clone()))
            .put("c", self.cap.to_cbor())
            .put("s", CborObject::List(self.sharers.iter().map(|s| CborObject::Str(s.clone())).collect()))
            .build()
    }

    fn from_cbor(cbor: &CborObject) -> Result<ChildElement> {
        Ok(ChildElement {
            name: cbor
                .get("n")
                .and_then(|c| c.as_string())
                .ok_or_else(|| Error::Cbor("ChildElement missing 'n'".into()))?
                .to_string(),
            cap: AbsoluteCapability::from_cbor(
                cbor.get("c").ok_or_else(|| Error::Cbor("ChildElement missing 'c'".into()))?,
            )?,
            sharers: cbor
                .get("s")
                .and_then(|c| c.as_list())
                .map(|l| l.iter().filter_map(|c| c.as_string().map(String::from)).collect())
                .unwrap_or_default(),
        })
    }
}

/// The caps mirrored inside one directory (`IncomingCapCache.CapsInDirectory`),
/// serialized to `items.cbor`.
#[derive(Debug, Clone, Default)]
pub struct CapsInDirectory {
    pub children: Vec<ChildElement>,
}

impl CapsInDirectory {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("c", CborObject::List(self.children.iter().map(|c| c.to_cbor()).collect()))
            .build()
    }

    fn from_cbor(cbor: &CborObject) -> Result<CapsInDirectory> {
        let children = cbor
            .get("c")
            .and_then(|c| c.as_list())
            .ok_or_else(|| Error::Cbor("CapsInDirectory missing 'c'".into()))?
            .iter()
            .map(ChildElement::from_cbor)
            .collect::<Result<Vec<_>>>()?;
        Ok(CapsInDirectory { children })
    }

    fn get_child(&self, name: &str) -> Option<AbsoluteCapability> {
        self.children.iter().find(|c| c.name == name).map(|c| c.cap.clone())
    }

    /// Merge a newly-seen cap for `filename` shared by `sharer` (a simplified
    /// `CapsInDirectory.addChild`: same cap → union sharers; a write cap wins over
    /// a read cap; otherwise the newest cap replaces).
    fn add_child(&mut self, filename: &str, cap: AbsoluteCapability, sharer: &str) {
        if let Some(pos) = self.children.iter().position(|c| c.name == filename) {
            let current = &mut self.children[pos];
            if current.cap == cap {
                if !current.sharers.iter().any(|s| s == sharer) {
                    current.sharers.push(sharer.to_string());
                }
            } else if current.cap.is_writable() && !cap.is_writable() {
                // Keep the more-privileged writable cap we already have.
            } else {
                self.children[pos] =
                    ChildElement { name: filename.to_string(), cap, sharers: vec![sharer.to_string()] };
            }
        } else {
            self.children.push(ChildElement {
                name: filename.to_string(),
                cap,
                sharers: vec![sharer.to_string()],
            });
        }
    }
}

/// How far we have processed a friend's read/write cap streams
/// (`social.ProcessedCaps`). `read_cap_bytes`/`write_cap_bytes` are absolute byte
/// offsets into their sharing files; `groups` holds the same state per social
/// group the friend shares into.
#[derive(Debug, Clone, Default)]
pub struct ProcessedCaps {
    pub read_caps: u64,
    pub write_caps: u64,
    pub read_cap_bytes: u64,
    pub write_cap_bytes: u64,
    pub groups: std::collections::BTreeMap<String, ProcessedCaps>,
}

impl ProcessedCaps {
    pub(crate) fn to_cbor(&self) -> CborObject {
        let mut g = CborObject::map();
        for (name, pc) in &self.groups {
            g = g.put(name, pc.to_cbor());
        }
        CborObject::map()
            .put("rc", CborObject::Long(self.read_caps as i64))
            .put("wc", CborObject::Long(self.write_caps as i64))
            .put("rb", CborObject::Long(self.read_cap_bytes as i64))
            .put("wb", CborObject::Long(self.write_cap_bytes as i64))
            .put("g", g.build())
            .build()
    }

    pub(crate) fn from_cbor(cbor: &CborObject) -> Result<ProcessedCaps> {
        let get = |k: &str| cbor.get(k).and_then(|c| c.as_long()).unwrap_or(0).max(0) as u64;
        let mut groups = std::collections::BTreeMap::new();
        if let Some(map) = cbor.get("g").and_then(|c| c.as_map()) {
            for (k, v) in map {
                groups.insert(k.as_str().to_string(), ProcessedCaps::from_cbor(v)?);
            }
        }
        Ok(ProcessedCaps {
            read_caps: get("rc"),
            write_caps: get("wc"),
            read_cap_bytes: get("rb"),
            write_cap_bytes: get("wb"),
            groups,
        })
    }
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

/// Your local mirror of incoming shared capabilities.
pub struct IncomingCapCache {
    cache_root: AbsoluteCapability,
    world_root: AbsoluteCapability,
    signer: SigningPrivateKeyAndPublicHash,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: Arc<dyn MutablePointers>,
    /// Last-seen mutable-pointer target per friend sharing-dir writer, to skip an
    /// update when nothing changed (`IncomingCapCache.pointerCache`).
    pointer_cache: Mutex<HashMap<PublicKeyHash, Option<Cid>>>,
}

impl IncomingCapCache {
    /// Open (creating `world/` if needed) the cache under the user's
    /// `/username/.capabilitycache` (`IncomingCapCache.build`).
    pub async fn build(
        user: &LoggedInUser,
        store: Arc<dyn ContentAddressedStorage>,
        mutable: Arc<dyn MutablePointers>,
    ) -> Result<IncomingCapCache> {
        let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
        let signer = crate::recover_signer(home, store.clone(), mutable.as_ref()).await?;
        let cache_root = crate::list_directory(home, store.clone(), mutable.as_ref())
            .await?
            .into_iter()
            .find(|e| e.name == CAP_CACHE_DIR)
            .ok_or_else(|| Error::Protocol("no .capabilitycache directory".into()))?
            .cap;
        let mut cache = IncomingCapCache {
            world_root: cache_root.clone(),
            cache_root,
            signer,
            store,
            mutable,
            pointer_cache: Mutex::new(HashMap::new()),
        };
        cache.world_root = cache.get_or_mkdir(&cache.cache_root.clone(), WORLD_ROOT_NAME).await?;
        Ok(cache)
    }

    // ---- low-level dir helpers --------------------------------------------

    async fn find_child(&self, dir: &AbsoluteCapability, name: &str) -> Result<Option<AbsoluteCapability>> {
        Ok(crate::list_directory(dir, self.store.clone(), self.mutable.as_ref())
            .await?
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| e.cap))
    }

    async fn get_or_mkdir(&self, dir: &AbsoluteCapability, name: &str) -> Result<AbsoluteCapability> {
        match self.find_child(dir, name).await? {
            Some(cap) => Ok(cap),
            None => {
                crate::create_directory(dir, name, Some(self.signer.clone()), self.store.clone(), self.mutable.as_ref())
                    .await
            }
        }
    }

    async fn get_or_mkdirs(&self, root: &AbsoluteCapability, components: &[String]) -> Result<AbsoluteCapability> {
        let mut current = root.clone();
        for name in components {
            current = self.get_or_mkdir(&current, name).await?;
        }
        Ok(current)
    }

    async fn read_caps_in_dir(&self, dir: &AbsoluteCapability) -> Result<CapsInDirectory> {
        match self.find_child(dir, DIR_STATE).await? {
            Some(cap) => {
                let bytes = crate::read_file(&cap, self.store.clone(), self.mutable.as_ref()).await?.1;
                CapsInDirectory::from_cbor(&CborObject::from_bytes(&bytes)?)
            }
            None => Ok(CapsInDirectory::default()),
        }
    }

    async fn write_caps_in_dir(&self, dir: &AbsoluteCapability, caps: &CapsInDirectory) -> Result<()> {
        crate::upload_file(
            dir,
            DIR_STATE,
            &caps.to_cbor().to_bytes(),
            None,
            Some(self.signer.clone()),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        Ok(())
    }

    async fn read_processed(&self, friend: &str) -> Result<ProcessedCaps> {
        let name = format!("{friend}{FRIEND_STATE_SUFFIX}");
        match self.find_child(&self.cache_root, &name).await? {
            Some(cap) => {
                let bytes = crate::read_file(&cap, self.store.clone(), self.mutable.as_ref()).await?.1;
                ProcessedCaps::from_cbor(&CborObject::from_bytes(&bytes)?)
            }
            None => Ok(ProcessedCaps::default()),
        }
    }

    async fn write_processed(&self, friend: &str, state: &ProcessedCaps) -> Result<()> {
        let name = format!("{friend}{FRIEND_STATE_SUFFIX}");
        crate::upload_file(
            &self.cache_root,
            &name,
            &state.to_cbor().to_bytes(),
            None,
            Some(self.signer.clone()),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        Ok(())
    }

    // ---- update -----------------------------------------------------------

    /// Process any capabilities `friend` has newly shared via `friend_shared_dir`
    /// (their `/friend/shared/<you>` cap): resolve each to a path, add it to the
    /// world mirror, and advance our persisted position
    /// (`ensureFriendUptodate`/`getCapsFrom`/`addNewCapsToMirror`). Returns the new
    /// caps that were added.
    ///
    /// A share whose path is `/friend/shared/<uid>` is a **social-group** sharing
    /// directory (e.g. friends/followers): it is remembered (persisted per friend)
    /// and its own cap stream is polled on every update, so anything the friend
    /// shares with a group you're in flows into the mirror automatically. Group
    /// positions are tracked in [`ProcessedCaps::groups`].
    pub async fn update_from_friend(
        &self,
        friend: &str,
        friend_shared_dir: &AbsoluteCapability,
    ) -> Result<Vec<CapabilityWithPath>> {
        self.update_from_friend_with_groups(friend, friend_shared_dir, &[]).await
    }

    /// As [`update_from_friend`], additionally processing the explicit `groups`
    /// (each `(uid, group_shared_dir)`). Auto-detected group directories are merged
    /// with these and with any previously persisted for the friend.
    pub async fn update_from_friend_with_groups(
        &self,
        friend: &str,
        friend_shared_dir: &AbsoluteCapability,
        groups: &[(String, AbsoluteCapability)],
    ) -> Result<Vec<CapabilityWithPath>> {
        // Short-circuit: the friend's sharing dir AND their group dirs all live under
        // the friend's home writer, so an unchanged pointer means nothing is new.
        let writer = friend_shared_dir.writer.clone();
        let latest = self
            .mutable
            .get_pointer_target(&friend_shared_dir.owner, &writer, self.store.as_ref())
            .await?
            .updated;
        if groups.is_empty() {
            let cached = self.pointer_cache.lock().unwrap().get(&writer).cloned();
            if let Some(prev) = cached {
                if prev == latest {
                    return Ok(Vec::new());
                }
            }
        }

        let current = self.read_processed(friend).await?;
        let mut updated = current.clone();
        let mut content = Vec::new();
        // Known group directories: persisted + explicitly supplied.
        let mut group_dirs = self.read_group_dirs(friend).await?;
        for (uid, dir) in groups {
            group_dirs.insert(uid.clone(), dir.clone());
        }

        // Direct shares. Group directories are recognised and set aside (not
        // mirrored themselves) so their contents can be polled every update.
        let (read_count, write_count, read_bytes, write_bytes, direct) =
            self.load_new_caps(friend_shared_dir, current.read_cap_bytes, current.write_cap_bytes).await?;
        updated.read_caps = current.read_caps + read_count;
        updated.write_caps = current.write_caps + write_count;
        updated.read_cap_bytes = read_bytes;
        updated.write_cap_bytes = write_bytes;
        for cwp in direct {
            if let Some(uid) = group_uid_from_path(&cwp.path) {
                group_dirs.insert(uid, cwp.cap);
            } else {
                content.push(cwp);
            }
        }

        // Group shares (persisted + newly discovered + explicit).
        for (uid, dir) in &group_dirs {
            let g_current = current.groups.get(uid).cloned().unwrap_or_default();
            let (g_read, g_write, g_read_bytes, g_write_bytes, mut g_caps) =
                self.load_new_caps(dir, g_current.read_cap_bytes, g_current.write_cap_bytes).await?;
            updated.groups.insert(
                uid.clone(),
                ProcessedCaps {
                    read_caps: g_current.read_caps + g_read,
                    write_caps: g_current.write_caps + g_write,
                    read_cap_bytes: g_read_bytes,
                    write_cap_bytes: g_write_bytes,
                    groups: g_current.groups,
                },
            );
            content.append(&mut g_caps);
        }

        for cwp in &content {
            self.add_cap_to_mirror(friend, cwp).await?;
        }
        self.write_processed(friend, &updated).await?;
        self.write_group_dirs(friend, &group_dirs).await?;
        self.pointer_cache.lock().unwrap().insert(writer, latest);
        Ok(content)
    }

    /// The friend's known group sharing directories (`uid → cap`), persisted at
    /// `/you/.capabilitycache/<friend>$groups.cbor` (our `.groups-from-friends`
    /// equivalent).
    async fn read_group_dirs(&self, friend: &str) -> Result<std::collections::BTreeMap<String, AbsoluteCapability>> {
        let name = format!("{friend}{FRIEND_GROUPS_SUFFIX}");
        let mut out = std::collections::BTreeMap::new();
        if let Some(cap) = self.find_child(&self.cache_root, &name).await? {
            let bytes = crate::read_file(&cap, self.store.clone(), self.mutable.as_ref()).await?.1;
            if let Some(m) = CborObject::from_bytes(&bytes)?.as_map() {
                for (k, v) in m {
                    out.insert(k.as_str().to_string(), AbsoluteCapability::from_cbor(v)?);
                }
            }
        }
        Ok(out)
    }

    async fn write_group_dirs(
        &self,
        friend: &str,
        dirs: &std::collections::BTreeMap<String, AbsoluteCapability>,
    ) -> Result<()> {
        if dirs.is_empty() {
            return Ok(());
        }
        let mut b = CborObject::map();
        for (uid, cap) in dirs {
            b = b.put(uid, cap.to_cbor());
        }
        crate::upload_file(
            &self.cache_root,
            &format!("{friend}{FRIEND_GROUPS_SUFFIX}"),
            &b.build().to_bytes(),
            None,
            Some(self.signer.clone()),
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        Ok(())
    }

    /// Load the new read + write caps from one sharing directory since the given
    /// offsets, returning `(read_count, write_count, new_read_bytes, new_write_bytes,
    /// caps)`.
    async fn load_new_caps(
        &self,
        shared_dir: &AbsoluteCapability,
        read_offset: u64,
        write_offset: u64,
    ) -> Result<(u64, u64, u64, u64, Vec<CapabilityWithPath>)> {
        let read_new = crate::load_read_access_sharing_links(
            shared_dir,
            read_offset,
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        let write_new = crate::load_write_access_sharing_links(
            shared_dir,
            write_offset,
            self.store.clone(),
            self.mutable.as_ref(),
        )
        .await?;
        let read_count = read_new.capabilities.len() as u64;
        let write_count = write_new.capabilities.len() as u64;
        let mut caps = read_new.capabilities;
        caps.extend(write_new.capabilities);
        Ok((read_count, write_count, read_new.bytes_read, write_new.bytes_read, caps))
    }

    /// Add one shared cap to the mirror at its path (`addCapToMirror`).
    async fn add_cap_to_mirror(&self, friend: &str, cwp: &CapabilityWithPath) -> Result<()> {
        let comps = split_path(&cwp.path);
        let (filename, parents) = match comps.split_last() {
            Some((last, rest)) => (last.clone(), rest.to_vec()),
            None => return Ok(()),
        };
        let mirror_dir = self.get_or_mkdirs(&self.world_root.clone(), &parents).await?;
        let mut caps = self.read_caps_in_dir(&mirror_dir).await?;
        caps.add_child(&filename, cwp.cap.clone(), friend);
        self.write_caps_in_dir(&mirror_dir, &caps).await
    }

    // ---- lookup -----------------------------------------------------------

    /// Resolve a shared path (e.g. `/alice/docs/f.txt`) to its capability
    /// (`getByPath`). If an ancestor was shared as a directory, the remaining path
    /// is followed by entering that directory. When a directory was shared
    /// read-only but a descendant was shared with more privilege (e.g. writable),
    /// the more-privileged mirrored descendant wins. `None` if not shared with us.
    pub async fn get_by_path(&self, path: &str) -> Result<Option<AbsoluteCapability>> {
        let comps = split_path(path);
        if comps.is_empty() {
            return Ok(None);
        }
        self.resolve_in_mirror(self.world_root.clone(), comps).await
    }

    fn resolve_in_mirror(
        &self,
        mirror_dir: AbsoluteCapability,
        comps: Vec<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<AbsoluteCapability>>> + '_>> {
        Box::pin(async move {
            let comp = match comps.first() {
                Some(c) => c.clone(),
                None => return Ok(None),
            };
            let caps = self.read_caps_in_dir(&mirror_dir).await?;
            let mirror_child = self.find_child(&mirror_dir, &comp).await?;

            if let Some(cap) = caps.get_child(&comp) {
                if comps.len() == 1 {
                    return Ok(Some(cap));
                }
                // A read-only ancestor may be superseded by a more-privileged
                // descendant cap mirrored deeper — prefer that.
                if !cap.is_writable() {
                    if let Some(sub) = mirror_child {
                        if let Some(found) = self.resolve_in_mirror(sub, comps[1..].to_vec()).await? {
                            return Ok(Some(found));
                        }
                    }
                }
                return self.resolve_via_filesystem(cap, &comps[1..]).await;
            }

            match mirror_child {
                Some(sub) => self.resolve_in_mirror(sub, comps[1..].to_vec()).await,
                None => Ok(None),
            }
        })
    }

    /// Follow `rest` from a shared directory `cap` through the real filesystem.
    async fn resolve_via_filesystem(
        &self,
        cap: AbsoluteCapability,
        rest: &[String],
    ) -> Result<Option<AbsoluteCapability>> {
        let mut current = cap;
        for name in rest {
            match self.find_child(&current, name).await? {
                Some(child) => current = child,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    /// The children shared with us at `dir_path` (`getChildren`): the mirror entries
    /// at that path, or — if `dir_path` is itself a shared directory — its real
    /// children. Each is `(name, capability)`.
    pub async fn get_children(&self, dir_path: &str) -> Result<Vec<(String, AbsoluteCapability)>> {
        let comps = split_path(dir_path);
        let mut current = self.world_root.clone();
        for comp in &comps {
            let caps = self.read_caps_in_dir(&current).await?;
            if let Some(cap) = caps.get_child(comp) {
                // A directory shared with us directly: list its real children.
                return Ok(crate::list_directory(&cap, self.store.clone(), self.mutable.as_ref())
                    .await?
                    .into_iter()
                    .map(|e| (e.name, e.cap))
                    .collect());
            }
            match self.find_child(&current, comp).await? {
                Some(dir) => current = dir,
                None => return Ok(Vec::new()),
            }
        }
        let caps = self.read_caps_in_dir(&current).await?;
        Ok(caps.children.into_iter().map(|c| (c.name, c.cap)).collect())
    }
}
