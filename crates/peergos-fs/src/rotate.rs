//! Key rotation without copying data (`CryptreeNode.rotateAllKeys`): every cryptree
//! node of a subtree is written again under new keys, at new locations, but file
//! data keeps its blocks and data keys, which are marked dirty so the next write to
//! a file re-encrypts it. Nothing is downloaded or re-encrypted.

use super::*;
use futures::StreamExt;
use std::collections::HashMap;

/// A writable cap and the signer of its writer.
#[derive(Clone)]
pub(crate) struct CapAndSigner {
    pub cap: AbsoluteCapability,
    pub signer: SigningPrivateKeyAndPublicHash,
}

impl CapAndSigner {
    fn with_location(&self, map_key: Vec<u8>, bat: Option<Bat>) -> CapAndSigner {
        CapAndSigner { cap: AbsoluteCapability { map_key, bat, ..self.cap.clone() }, signer: self.signer.clone() }
    }
}

#[derive(Default)]
struct WriterChanges {
    signer: Option<SigningPrivateKeyAndPublicHash>,
    puts: Vec<(Vec<u8>, Cid)>,
    removes: Vec<Vec<u8>>,
}

/// The rotation's writes, applied to each writer's champ in one commit at the end,
/// and its reads, all of the tree as it was before.
pub(crate) struct Rotation<'a> {
    owner: PublicKeyHash,
    mirror_bat: Option<BatId>,
    store: &'a Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
    tid: TransactionId,
    old_champs: HashMap<PublicKeyHash, ChampWrapper>,
    order: Vec<PublicKeyHash>,
    changes: HashMap<PublicKeyHash, WriterChanges>,
    /// The new signer of each nested writing space whose signer was rotated.
    pub rotated_signers: HashMap<PublicKeyHash, PublicKeyHash>,
    /// The signers that were replaced.
    old_signers: Vec<SigningPrivateKeyAndPublicHash>,
}

impl<'a> Rotation<'a> {
    pub(crate) async fn start(
        owner: &PublicKeyHash,
        mirror_bat: Option<&BatId>,
        store: &'a Arc<dyn ContentAddressedStorage>,
        mutable: &'a dyn MutablePointers,
    ) -> Result<Rotation<'a>> {
        let tid = store.start_transaction(owner).await?;
        Ok(Rotation {
            owner: owner.clone(),
            mirror_bat: mirror_bat.cloned(),
            store,
            mutable,
            tid,
            old_champs: HashMap::new(),
            order: Vec::new(),
            changes: HashMap::new(),
            rotated_signers: HashMap::new(),
            old_signers: Vec::new(),
        })
    }

    fn touch(&mut self, writer: &PublicKeyHash, signer: &SigningPrivateKeyAndPublicHash) -> &mut WriterChanges {
        if !self.changes.contains_key(writer) {
            self.order.push(writer.clone());
        }
        let c = self.changes.entry(writer.clone()).or_default();
        c.signer.get_or_insert_with(|| signer.clone());
        c
    }

    async fn ensure_champ(&mut self, cap: &AbsoluteCapability) -> Result<()> {
        if !self.old_champs.contains_key(&cap.writer) {
            let champ = open_writer_champ(cap, self.store.clone(), self.mutable).await?;
            self.old_champs.insert(cap.writer.clone(), champ);
        }
        Ok(())
    }

    async fn fetch(&mut self, cap: &AbsoluteCapability) -> Result<Option<CryptreeNode>> {
        self.ensure_champ(cap).await?;
        let champ = &self.old_champs[&cap.writer];
        fetch_chunk_node(champ, cap, &cap.map_key, &cap.bat, self.store.as_ref()).await
    }

    /// A new writer owned by `parent` (`initAndAuthoriseSigner`).
    pub(crate) async fn new_writer(&mut self, parent: &SigningPrivateKeyAndPublicHash) -> Result<SigningPrivateKeyAndPublicHash> {
        let pair = SigningKeyPair::random_writer()?;
        let hash = put_signing_key(self.store.as_ref(), &self.owner, parent, &pair.public, &self.tid).await?;
        let signer = SigningPrivateKeyAndPublicHash::new(hash, pair.secret);
        writing_space::init_writer(&self.owner, parent, &signer, self.store, self.mutable, &self.tid).await?;
        Ok(signer)
    }

    /// Rotate the file or directory at `us`, which hangs off `new_parent` through
    /// `parent_link`, to `new_us` (the first chunk; the rest follow), optionally
    /// renaming it. Returns the properties of its first chunk.
    pub(crate) async fn rotate(
        &mut self,
        us: &CapAndSigner,
        new_us: &CapAndSigner,
        new_parent: &CapAndSigner,
        parent_link: RelCap,
        rename: Option<&str>,
        rotate_signers: bool,
    ) -> Result<FileProperties> {
        let node = self.fetch(&us.cap).await?.ok_or_else(|| Error::Protocol("nothing to rotate".into()))?;
        let mut props = node.get_properties(&us.cap.r_base_key)?;
        if let Some(n) = rename {
            props.name = n.to_string();
        }
        self.rotate_chunk(true, node, us, new_us, new_parent, Some(parent_link), None, rename.map(str::to_string), rotate_signers)
            .await?;
        Ok(props)
    }

    #[allow(clippy::too_many_arguments)]
    fn rotate_chunk<'b>(
        &'b mut self,
        is_first_chunk: bool,
        node: CryptreeNode,
        us: &'b CapAndSigner,
        new_us: &'b CapAndSigner,
        new_parent: &'b CapAndSigner,
        first_chunk_or_parent_cap: Option<RelCap>,
        file_stream_secret: Option<Vec<u8>>,
        rename: Option<String>,
        rotate_signers: bool,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'b>> {
        Box::pin(async move {
            let r = &us.cap.r_base_key;
            let mut props = node.get_properties(r)?;
            if let Some(n) = rename {
                props.name = n;
            }
            let is_dir = node.is_directory();
            let (next_map_key, next_bat) = match (&props.stream_secret, is_dir) {
                (Some(ss), false) => retrieve::calculate_next_map_key(ss, &us.cap.map_key, &us.cap.bat)?,
                _ => node.next_chunk_from_base(r)?,
            };
            let stream_secret = if !is_first_chunk {
                file_stream_secret
            } else if is_dir {
                None
            } else {
                Some(random_bytes(32))
            };
            let (new_next_map_key, new_next_bat) = match &stream_secret {
                Some(ss) => retrieve::calculate_next_map_key(ss, &new_us.cap.map_key, &new_us.cap.bat)?,
                None => (random_bytes(32), Some(Bat::new(random_bytes(32))?)),
            };
            let new_parent_key = if is_first_chunk {
                random_symmetric_key()?
            } else {
                first_chunk_or_parent_cap.as_ref().expect("a later chunk links to its first").r_base_key.clone()
            };
            // only first chunks have a link to their parent
            let new_parent_cap = if is_first_chunk {
                first_chunk_or_parent_cap.clone().map(|c| RelCap {
                    writer: (new_parent.cap.writer != new_us.cap.writer).then(|| new_parent.cap.writer.clone()),
                    ..c
                })
            } else {
                None
            };
            let child_cap_to_us = if is_first_chunk {
                Some(RelCap {
                    writer: None,
                    map_key: new_us.cap.map_key.clone(),
                    bat: new_us.cap.bat.clone(),
                    r_base_key: new_parent_key.clone(),
                    w_base_key_link: None,
                })
            } else {
                first_chunk_or_parent_cap
            };
            self.touch(&us.cap.writer, &us.signer).removes.push(us.cap.map_key.clone());

            // a file that fits in one chunk has no next chunk, and looking for one is a round trip per file
            let single_chunk_file = is_first_chunk
                && !is_dir
                && props.stream_secret.is_some()
                && chunk_count(props.size, props.chunk_size) <= 1;
            let next_us = us.with_location(next_map_key, next_bat);
            let new_next = new_us.with_location(new_next_map_key, new_next_bat);
            if !single_chunk_file {
                if let Some(next) = self.fetch(&next_us.cap).await?.filter(|n| n.is_directory() == is_dir) {
                    self.rotate_chunk(false, next, &next_us, &new_next, new_parent, child_cap_to_us.clone(), stream_secret.clone(), None, rotate_signers)
                        .await?;
                }
            }

            let signer_link = if is_first_chunk && new_us.cap.writer != new_parent.cap.writer {
                let w = new_us.cap.w_base_key.as_ref().ok_or_else(|| Error::Protocol("rotating to a read only cap".into()))?;
                Some(peergos_core::symmetric::CipherText::build(w, &new_us.signer)?.to_cbor())
            } else {
                None
            };
            let next_rel = RelCap::subsequent_chunk(new_next.cap.map_key.clone(), new_next.cap.bat.clone(), new_us.cap.r_base_key.clone());
            let bats = node_bats_opt(new_us.cap.bat.as_ref(), self.mirror_bat.as_ref())?;
            let new_node = if is_dir {
                let children = self.rotate_children(&node, us, new_us, child_cap_to_us.as_ref().expect("dirs link to their first chunk"), rotate_signers).await?;
                let mut from_base = CborObject::map().put("k", new_parent_key.to_cbor());
                if let Some(l) = signer_link {
                    from_base = from_base.put("w", l);
                }
                let from_base = from_base.put("n", next_rel.to_cbor()).build();
                let from_parent = CborObject::map()
                    .put_opt("p", new_parent_cap.map(|p| p.to_cbor()))
                    .put("s", props.to_cbor())
                    .build();
                let (children_data, fragments) = retrieve::FragmentedPaddedCipherText::build(
                    &new_us.cap.r_base_key,
                    &ChildrenLinks::Named(children).to_cbor(),
                    MIN_FRAGMENT_SIZE,
                    self.mirror_bat.as_ref(),
                )?;
                put_raw_blocks_signed(self.store.as_ref(), &self.owner, &new_us.signer, fragments, &self.tid).await?;
                CryptreeNode::new(
                    true,
                    bats,
                    PaddedCipherText::build(&new_us.cap.r_base_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
                    PaddedCipherText::build(&new_parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
                    children_data.to_cbor(),
                )
            } else {
                let data_key = node.get_data_key(r)?;
                let data_key = SymmetricKey::new(data_key.key.clone(), true)?;
                let mut props = props;
                if let Some(ss) = &stream_secret {
                    props.stream_secret = Some(ss.clone());
                }
                let mut from_base = CborObject::map().put("k", data_key.to_cbor());
                if let Some(l) = signer_link {
                    from_base = from_base.put("w", l);
                }
                let from_base = from_base.put("n", next_rel.to_cbor()).build();
                let from_parent = CborObject::map()
                    .put_opt("p", new_parent_cap.map(|p| p.to_cbor()))
                    .put("s", props.to_cbor())
                    .build();
                CryptreeNode::new(
                    false,
                    bats,
                    PaddedCipherText::build(&new_us.cap.r_base_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
                    PaddedCipherText::build(&new_us.cap.r_base_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
                    node.children_or_data.clone(),
                )
            };
            let cid = put_block_signed(self.store.as_ref(), &self.owner, &new_us.signer, new_node.to_cbor().to_bytes(), &self.tid).await?;
            self.touch(&new_us.cap.writer, &new_us.signer).puts.push((new_us.cap.map_key.clone(), cid));
            Ok(())
        })
    }

    /// Rotate the children in one chunk of a directory, returning their new links.
    async fn rotate_children(
        &mut self,
        dir: &CryptreeNode,
        us: &CapAndSigner,
        new_us: &CapAndSigner,
        child_cap_to_us: &RelCap,
        rotate_signers: bool,
    ) -> Result<Vec<NamedRelativeCapability>> {
        let decoded = FragmentedPaddedCipherText::from_cbor(&dir.children_or_data)?
            .get_and_decrypt(&self.owner, &us.cap.r_base_key, self.store.as_ref(), |c| Ok(c.clone()))
            .await?;
        let children = match ChildrenLinks::from_cbor(&decoded)? {
            ChildrenLinks::Named(v) => v,
            ChildrenLinks::Legacy(_) => return Err(Error::Protocol("legacy directory format not supported".into())),
        };
        let caps = children.iter().map(|c| c.cap.to_absolute(&us.cap)).collect::<Result<Vec<_>>>()?;
        for cap in &caps {
            self.ensure_champ(cap).await?;
        }
        // the rotation is sequential, so fetch the children together rather than in turn
        let nodes = {
            let champs = &self.old_champs;
            let store = self.store.as_ref();
            futures::stream::iter(caps.iter().map(|cap| async move {
                fetch_chunk_node(&champs[&cap.writer], cap, &cap.map_key, &cap.bat, store).await
            }))
            .buffered(16)
            .collect::<Vec<_>>()
            .await
        };
        let mut out = Vec::with_capacity(children.len());
        for ((child, cap), node) in children.into_iter().zip(caps).zip(nodes) {
            let Some(node) = node? else {
                log::warn!("Skipping a missing child, {}, in a rotation", child.name);
                continue;
            };
            let props = node.get_properties(&cap.r_base_key)?;
            let signer = match &cap.w_base_key {
                Some(w) => node.get_signer(&cap.r_base_key, w).unwrap_or_else(|_| us.signer.clone()),
                None => return Err(Error::Protocol("rotating a subtree needs write access to all of it".into())),
            };
            let child_us = CapAndSigner { cap, signer };
            let new_child = self.new_child_cap(&child_us, us, new_us, rotate_signers).await?;
            Box::pin(self.rotate_chunk(true, node, &child_us, &new_child, new_us, Some(child_cap_to_us.clone()), None, None, rotate_signers))
                .await?;
            out.push(NamedRelativeCapability {
                name: child.name,
                cap: relativise(&new_us.cap, &new_child.cap)?,
                is_dir: Some(props.is_directory),
                mime_type: Some(props.mime_type.clone()),
                created_epoch: Some(props.created_epoch),
            });
        }
        Ok(out)
    }

    /// `generateNewChildCap`: a child in its parent's writing space moves with it, a
    /// nested writing space keeps its signer unless signers are rotated.
    async fn new_child_cap(
        &mut self,
        child: &CapAndSigner,
        parent: &CapAndSigner,
        new_parent: &CapAndSigner,
        rotate_signers: bool,
    ) -> Result<CapAndSigner> {
        let fresh = |writer: PublicKeyHash| -> Result<AbsoluteCapability> {
            AbsoluteCapability::new(
                child.cap.owner.clone(),
                writer,
                random_bytes(32),
                Some(Bat::new(random_bytes(32))?),
                random_symmetric_key()?,
                Some(random_symmetric_key()?),
            )
        };
        if child.cap.writer == parent.cap.writer {
            return Ok(CapAndSigner { cap: fresh(new_parent.cap.writer.clone())?, signer: new_parent.signer.clone() });
        }
        if !rotate_signers {
            return Ok(CapAndSigner { cap: fresh(child.cap.writer.clone())?, signer: child.signer.clone() });
        }
        let signer = self.new_writer(&new_parent.signer).await?;
        self.rotated_signers.insert(child.cap.writer.clone(), signer.public_key_hash.clone());
        self.old_signers.push(child.signer.clone());
        Ok(CapAndSigner { cap: fresh(signer.public_key_hash.clone())?, signer })
    }

    /// Apply every writer's changes: the new nodes in, the old ones out. Returns the
    /// signers that were replaced.
    pub(crate) async fn commit(self) -> Result<Vec<SigningPrivateKeyAndPublicHash>> {
        for writer in &self.order {
            let changes = &self.changes[writer];
            let signer = changes.signer.as_ref().expect("touched writers have a signer");
            let (pointer, wd, mut tree) = writing_space::open_tree(&self.owner, writer, self.store, self.mutable).await?;
            for mk in &changes.removes {
                champ_remove_entry(&mut tree, signer, mk, &self.tid).await?;
            }
            for (mk, cid) in &changes.puts {
                let current = tree.get(mk).await?;
                tree.put(signer, mk, &current, Some(CborObject::MerkleLink(cid.to_bytes())), &self.tid).await?;
            }
            let new_wd = writer_data_with_tree(&wd, tree.root_hash())?;
            let new_wd_cid = put_block_signed(self.store.as_ref(), &self.owner, signer, new_wd.to_bytes(), &self.tid).await?;
            let update = PointerUpdate::new(pointer.updated.clone(), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
            if !self.mutable.set_pointer_update(&self.owner, signer, &update).await? {
                return Err(Error::Protocol(format!("pointer update for {writer} rejected during a rotation")));
            }
        }
        self.store.close_transaction(&self.owner, &self.tid).await?;
        Ok(self.old_signers)
    }
}

/// The link from `parent` to `child` (`AbsoluteCapability.relativise`).
pub(crate) fn relativise(parent: &AbsoluteCapability, child: &AbsoluteCapability) -> Result<RelCap> {
    let w_base_key_link = match (&parent.w_base_key, &child.w_base_key) {
        (Some(pw), Some(cw)) => Some(peergos_core::symmetric::CipherText::build(pw, cw)?.to_cbor()),
        _ => None,
    };
    Ok(RelCap {
        writer: (parent.writer != child.writer).then(|| child.writer.clone()),
        map_key: child.map_key.clone(),
        bat: child.bat.clone(),
        r_base_key: child.r_base_key.clone(),
        w_base_key_link,
    })
}

/// Rotate every key of `child_name` in `parent_cap` (`UserContext.rotateAllKeys`):
/// the symmetric keys and locations always, and with `rotate_signers` the signer of
/// every writing space in it too. A child in a writing space of its own is reached
/// through a link node in the parent's. The parent then points at the new child,
/// and the old nodes are gone. Returns the child's new cap (the target of its link
/// node, if it has one) and the new signer of each writer that was replaced.
pub(crate) async fn rotate_child(
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    rotate_signers: bool,
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(AbsoluteCapability, HashMap<PublicKeyHash, PublicKeyHash>)> {
    let owner = &parent_cap.owner;
    let in_parent = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?;
    let (_, in_parent_props) = retrieve_file_metadata(&in_parent.cap, store.clone(), mutable).await?;
    let is_link = in_parent_props.is_link;
    let file_cap = if is_link {
        list_directory(&in_parent.cap, store.clone(), mutable)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("link node has no target".into()))?
            .cap
    } else {
        in_parent.cap.clone()
    };
    let parent_signer = parent_writer_signer(parent_cap, &entry_signer, store.clone(), mutable).await?;
    let file_signer = recover_signer(&file_cap, store.clone(), mutable).await.unwrap_or_else(|_| parent_signer.clone());
    // A file in a writing space of its own is reached through a link in its parent's
    let own_space = rotate_signers || file_cap.writer != parent_cap.writer;

    let mut rot = Rotation::start(owner, mirror_bat, store, mutable).await?;
    let new_signer = if rotate_signers {
        let s = rot.new_writer(&parent_signer).await?;
        rot.rotated_signers.insert(file_cap.writer.clone(), s.public_key_hash.clone());
        rot.old_signers.push(file_signer.clone());
        s
    } else {
        file_signer.clone()
    };
    let link_keys = LinkNodeKeys::random()?;
    let (parent_dir_node, _) = retrieve_file_metadata(parent_cap, store.clone(), mutable).await?;
    let parent_link = if own_space {
        link_keys.parent_link(&parent_cap.writer)
    } else {
        RelCap {
            writer: None,
            map_key: parent_cap.map_key.clone(),
            bat: parent_cap.bat.clone(),
            r_base_key: parent_dir_node.get_parent_key(&parent_cap.r_base_key),
            w_base_key_link: None,
        }
    };
    let us = CapAndSigner { cap: file_cap.clone(), signer: file_signer.clone() };
    let new_us = CapAndSigner {
        cap: AbsoluteCapability::new(
            owner.clone(),
            new_signer.public_key_hash.clone(),
            random_bytes(32),
            Some(Bat::new(random_bytes(32))?),
            random_symmetric_key()?,
            Some(random_symmetric_key()?),
        )?,
        signer: new_signer.clone(),
    };
    let parent = CapAndSigner { cap: parent_cap.clone(), signer: parent_signer.clone() };
    let props = rot.rotate(&us, &new_us, &parent, parent_link, None, rotate_signers).await?;
    if is_link {
        rot.touch(&parent_cap.writer, &parent_signer).removes.push(in_parent.cap.map_key.clone());
    }
    let rotated = std::mem::take(&mut rot.rotated_signers);
    let old_signers = rot.commit().await?;

    if own_space {
        // the link node lives in the parent's writing space, which keeps rename access there
        create_link_node(parent_cap, child_name, &new_us.cap, &props, &link_keys, Some(parent_signer.clone()), mirror_bat, store.clone(), mutable)
            .await?;
    } else {
        replace_child_link(parent_cap, child_name, &new_us.cap, &props, &parent_signer, mirror_bat, store, mutable).await?;
    }
    retire_writers(parent_cap, &parent_signer, &old_signers, store, mutable).await?;
    Ok((new_us.cap, rotated))
}

/// Empty each replaced writer and let `parent` go of those it owns; the rest are
/// owned by one of them.
async fn retire_writers(
    parent_cap: &AbsoluteCapability,
    parent_signer: &SigningPrivateKeyAndPublicHash,
    old: &[SigningPrivateKeyAndPublicHash],
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if old.is_empty() {
        return Ok(());
    }
    for s in old {
        delete_writer_subspace(&parent_cap.owner, s, store, mutable).await?;
    }
    let tid = store.start_transaction(&parent_cap.owner).await?;
    for s in old {
        writing_space::disown_writer(&parent_cap.owner, parent_signer, &s.public_key_hash, store, mutable, &tid).await?;
    }
    store.close_transaction(&parent_cap.owner, &tid).await?;
    Ok(())
}

/// Move `child` (called `name` in `source_parent`) into `target_dir` as `new_name`
/// without keeping access to it (`FileWrapper.moveRotatingKeys`): it is rotated into
/// the target as a revocation would rotate it in place, and writing spaces nested in
/// it get new signers owned by the target's writer. Returns its new cap.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn move_rotating_keys(
    source_parent: &AbsoluteCapability,
    child: &DirEntry,
    name: &str,
    target_dir: &AbsoluteCapability,
    target_node: &CryptreeNode,
    new_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let owner = &source_parent.owner;
    let (_, in_parent_props) = retrieve_file_metadata(&child.cap, store.clone(), mutable).await?;
    let file_cap = if in_parent_props.is_link {
        list_directory(&child.cap, store.clone(), mutable)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("link node has no target".into()))?
            .cap
    } else {
        child.cap.clone()
    };
    let from = parent_writer_signer(source_parent, &entry_signer, store.clone(), mutable).await?;
    let to = recover_signer(target_dir, store.clone(), mutable)
        .await
        .ok()
        .or_else(|| entry_signer.clone().filter(|s| s.public_key_hash == target_dir.writer))
        .ok_or_else(|| Error::Protocol("no writer signer for target".into()))?;
    let file_signer = recover_signer(&file_cap, store.clone(), mutable).await.unwrap_or_else(|_| from.clone());

    let mut rot = Rotation::start(owner, mirror_bat, store, mutable).await?;
    if file_cap.writer != source_parent.writer {
        rot.old_signers.push(file_signer.clone());
    }
    let us = CapAndSigner { cap: file_cap, signer: file_signer };
    let new_us = CapAndSigner {
        cap: AbsoluteCapability::new(
            owner.clone(),
            target_dir.writer.clone(),
            random_bytes(32),
            Some(Bat::new(random_bytes(32))?),
            random_symmetric_key()?,
            Some(random_symmetric_key()?),
        )?,
        signer: to.clone(),
    };
    let parent_link = RelCap {
        writer: None,
        map_key: target_dir.map_key.clone(),
        bat: target_dir.bat.clone(),
        r_base_key: target_node.get_parent_key(&target_dir.r_base_key),
        w_base_key_link: None,
    };
    let target = CapAndSigner { cap: target_dir.clone(), signer: to.clone() };
    let props = rot.rotate(&us, &new_us, &target, parent_link, Some(new_name), true).await?;
    if in_parent_props.is_link {
        rot.touch(&source_parent.writer, &from).removes.push(child.cap.map_key.clone());
    }
    let old_signers = rot.commit().await?;

    let ctx = begin_dir_write(target_dir, Some(to), mirror_bat, store, mutable).await?;
    let link = NamedRelativeCapability {
        name: new_name.to_string(),
        cap: relativise(target_dir, &new_us.cap)?,
        is_dir: Some(props.is_directory),
        mime_type: Some(props.mime_type.clone()),
        created_epoch: Some(props.created_epoch),
    };
    finish_dir_write(ctx, target_dir, store, mutable, link).await?;
    remove_child_link(source_parent, name, entry_signer, mirror_bat, store.clone(), mutable).await?;
    retire_writers(source_parent, &from, &old_signers, store, mutable).await?;
    Ok(new_us.cap)
}

/// Point the child link called `name` in `dir_cap` at `child`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn replace_child_link(
    dir_cap: &AbsoluteCapability,
    name: &str,
    child: &AbsoluteCapability,
    props: &FileProperties,
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut ctx = begin_dir_write(dir_cap, Some(signer.clone()), mirror_bat, store, mutable).await?;
    let mut chunks = collect_dir_chunks(dir_cap, &ctx, store).await?;
    let link = NamedRelativeCapability {
        name: name.to_string(),
        cap: relativise(dir_cap, child)?,
        is_dir: Some(props.is_directory),
        mime_type: Some(props.mime_type.clone()),
        created_epoch: Some(props.created_epoch),
    };
    let found = chunks.iter_mut().enumerate().find_map(|(i, (.., children))| {
        children.iter_mut().find(|c| c.name == name).map(|c| {
            *c = link.clone();
            i
        })
    });
    let i = found.ok_or_else(|| Error::Protocol(format!("no such child: {name}")))?;
    let (map_key, node, champ_value, children) = &chunks[i];
    recommit_dir_chunk(&mut ctx, dir_cap, store, map_key, node, champ_value, children.clone()).await?;
    commit_dir_write(&ctx, dir_cap, store, mutable).await
}
