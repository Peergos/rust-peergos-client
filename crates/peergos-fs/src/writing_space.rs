//! Moving a file or directory into a writing space of its own, which is how write
//! access to it is granted (`UserContext.moveToNewWritingSpace`).
//!
//! Granting write access compromises no key, so the subtree's cryptree nodes are
//! re-homed under a new signing key unchanged rather than re-encrypted. Only the
//! subtree root is rewritten, to carry the new signer and a parent link to the link
//! node that names it in the parent. Writing spaces nested inside the subtree keep their blocks
//! and signer; only their parent link and which key owns them change. Revoking
//! access is different, and still re-keys.

use super::*;

/// Everything in a subtree that lives in the subtree's own writing space.
#[derive(Default)]
struct Subtree {
    /// Champ entries (map key, value) of every cryptree node in the subtree.
    entries: Vec<(Vec<u8>, CborObject)>,
    /// Writing spaces nested inside, whose blocks belong to another signer.
    nested: Vec<AbsoluteCapability>,
}

/// Collect every chunk under `cap` in its writer's champ, stopping at nested writing
/// spaces (`FileWrapper.copyAllChunks` traversal).
fn collect_subtree<'a>(
    cap: &'a AbsoluteCapability,
    champ: &'a ChampWrapper,
    out: &'a mut Subtree,
    store: &'a Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let node = match fetch_chunk_node(champ, cap, &cap.map_key, &cap.bat, store.as_ref()).await? {
            Some(n) => n,
            None => return Ok(()),
        };
        if !node.is_directory() {
            let props = node.get_properties(&cap.r_base_key)?;
            let n = match &props.stream_secret {
                Some(_) => chunk_count(props.size, props.chunk_size),
                None => 1,
            };
            let mut map_key = cap.map_key.clone();
            let mut bat = cap.bat.clone();
            for i in 0..n {
                if let Some(v) = champ.get(&map_key).await? {
                    out.entries.push((map_key.clone(), v));
                }
                if i + 1 < n {
                    let ss = props.stream_secret.as_ref().expect("multi-chunk file has a stream secret");
                    let (nmk, nbat) = retrieve::calculate_next_map_key(ss, &map_key, &bat)?;
                    map_key = nmk;
                    bat = nbat;
                }
            }
            return Ok(());
        }
        // every chunk of the directory
        let mut cursor = Some((cap.map_key.clone(), node));
        while let Some((map_key, node)) = cursor.take() {
            if let Some(v) = champ.get(&map_key).await? {
                out.entries.push((map_key, v));
            }
            let (next_map_key, next_bat) = node.next_chunk_from_base(&cap.r_base_key)?;
            if champ.get(&next_map_key).await?.is_some() {
                cursor = fetch_chunk_node(champ, cap, &next_map_key, &next_bat, store.as_ref())
                    .await?
                    .filter(|n| n.is_directory())
                    .map(|n| (next_map_key, n));
            }
        }
        for child in list_directory(cap, store.clone(), mutable).await? {
            if child.cap.writer == cap.writer {
                collect_subtree(&child.cap, champ, out, store, mutable).await?;
            } else {
                out.nested.push(child.cap);
            }
        }
        Ok(())
    })
}

fn set_field(map: &CborObject, key: &str, value: CborObject) -> Result<CborObject> {
    let mut m = match map {
        CborObject::Map(m) => m.clone(),
        _ => return Err(Error::Cbor("cryptree block is not a map".into())),
    };
    m.insert(peergos_cbor::CborString::new(key), value);
    Ok(CborObject::Map(m))
}

/// This node with `link` as its parent link, every other field of the parent block kept.
fn with_parent_link(node: &CryptreeNode, r_base_key: &SymmetricKey, link: &RelCap) -> Result<CryptreeNode> {
    let parent_key = node.get_parent_key(r_base_key);
    let block = node.from_parent_key.decrypt(&parent_key, |c| Ok(c.clone()))?;
    let block = set_field(&block, "p", link.to_cbor())?;
    Ok(CryptreeNode {
        from_parent_key: PaddedCipherText::build(&parent_key, &block, META_DATA_PADDING_BLOCKSIZE)?,
        ..node.clone()
    })
}

/// This node carrying a link to `signer`, readable with the write-base key.
fn with_writer_link(
    node: &CryptreeNode,
    r_base_key: &SymmetricKey,
    w_base_key: &SymmetricKey,
    signer: &SigningPrivateKeyAndPublicHash,
) -> Result<CryptreeNode> {
    let block = node.from_base_key.decrypt(r_base_key, |c| Ok(c.clone()))?;
    let link = peergos_core::symmetric::CipherText::build(w_base_key, signer)?.to_cbor();
    let block = set_field(&block, "w", link)?;
    Ok(CryptreeNode {
        from_base_key: PaddedCipherText::build(r_base_key, &block, BASE_BLOCK_PADDING_BLOCKSIZE)?,
        ..node.clone()
    })
}

/// The owned-key champ key for a writer.
fn owned_key(writer: &PublicKeyHash) -> Vec<u8> {
    let mut k = writer.to_cbor().to_bytes();
    k.reverse();
    k
}

/// Open `writer`'s WriterData and one of its champs (`field` is `tree` or `owned`).
async fn open_champ(
    owner: &PublicKeyHash,
    writer: &PublicKeyHash,
    field: &str,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(PointerUpdate, CborObject, ChampWrapper)> {
    let pointer = mutable.get_pointer_target(owner, writer, store.as_ref()).await?;
    let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol(format!("writer {writer} has no data")))?;
    let wd = store.get(owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let root = Cid::cast(
        wd.get(field)
            .and_then(|c| c.as_link())
            .ok_or_else(|| Error::Protocol(format!("writer {writer} has no {field} champ")))?,
    )?;
    let champ = ChampWrapper::create(owner.clone(), root, None, store.clone(), identity_key_hasher()).await?;
    Ok((pointer, wd, champ))
}

/// Point `writer`'s `field` at the champ's new root and commit its pointer.
#[allow(clippy::too_many_arguments)]
async fn commit_champ(
    owner: &PublicKeyHash,
    writer: &SigningPrivateKeyAndPublicHash,
    field: &str,
    pointer: &PointerUpdate,
    wd: &CborObject,
    champ: &ChampWrapper,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    tid: &TransactionId,
) -> Result<()> {
    let new_wd = set_field(wd, field, CborObject::MerkleLink(champ.root_hash().to_bytes()))?;
    let new_wd_cid = put_block_signed(store.as_ref(), owner, writer, new_wd.to_bytes(), tid).await?;
    let update = PointerUpdate::new(pointer.updated.clone(), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
    if !mutable.set_pointer_update(owner, writer, &update).await? {
        return Err(Error::Protocol(format!("pointer update for {} rejected", writer.public_key_hash)));
    }
    Ok(())
}

/// Record that `parent` owns `child` (`addOwnedKeyAndCommit`): `child` signs its
/// owner's key hash, and the proof goes in `parent`'s owned champ.
async fn add_owned_writer(
    owner: &PublicKeyHash,
    parent: &SigningPrivateKeyAndPublicHash,
    child: &SigningPrivateKeyAndPublicHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    tid: &TransactionId,
) -> Result<()> {
    let (pointer, wd, mut owned) = open_champ(owner, &parent.public_key_hash, "owned", store, mutable).await?;
    let signed = child.secret.sign_message(&parent.public_key_hash.to_cbor().to_bytes(), peergos_core::SigningDomain::OwnerProof)?;
    let proof = CborObject::map()
        .put("o", child.public_key_hash.to_cbor())
        .put("p", CborObject::ByteString(signed))
        .build();
    let proof_cid = put_block_signed(store.as_ref(), owner, parent, proof.to_bytes(), tid).await?;
    let key = owned_key(&child.public_key_hash);
    let current = owned.get(&key).await?;
    owned.put(parent, &key, &current, Some(CborObject::MerkleLink(proof_cid.to_bytes())), tid).await?;
    commit_champ(owner, parent, "owned", &pointer, &wd, &owned, store, mutable, tid).await
}

/// Remove `child` from `parent`'s owned keys (`deAuthoriseSigner`). No-op if absent.
async fn remove_owned_writer(
    owner: &PublicKeyHash,
    parent: &SigningPrivateKeyAndPublicHash,
    child: &PublicKeyHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    tid: &TransactionId,
) -> Result<bool> {
    let (pointer, wd, mut owned) = open_champ(owner, &parent.public_key_hash, "owned", store, mutable).await?;
    let key = owned_key(child);
    let current = owned.get(&key).await?;
    if current.is_none() {
        return Ok(false);
    }
    owned.remove(parent, &key, &current, tid).await?;
    commit_champ(owner, parent, "owned", &pointer, &wd, &owned, store, mutable, tid).await?;
    Ok(true)
}

/// Re-home the writing space `nested` under a new parent: its root's parent link
/// becomes `new_parent_link(old link)`, and if its owning writer changes, the new
/// owner records it before the old one lets it go. Its blocks and signer are kept.
pub(crate) async fn reparent_writing_space(
    nested: &AbsoluteCapability,
    new_parent_link: impl FnOnce(RelCap) -> RelCap,
    old_owner: &SigningPrivateKeyAndPublicHash,
    new_owner: &SigningPrivateKeyAndPublicHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    tid: &TransactionId,
) -> Result<()> {
    let owner = &nested.owner;
    let signer = recover_signer(nested, store.clone(), mutable).await?;
    let (pointer, wd, mut tree) = open_champ(owner, &nested.writer, "tree", store, mutable).await?;
    let node = fetch_chunk_node(&tree, nested, &nested.map_key, &nested.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol(format!("nested writing space {} has no root", nested.writer)))?;
    let link = node
        .parent_link(&nested.r_base_key)?
        .ok_or_else(|| Error::Protocol("Nested writing space with no parent link!".into()))?;
    let updated = with_parent_link(&node, &nested.r_base_key, &new_parent_link(link))?;
    let cid = put_block_signed(store.as_ref(), owner, &signer, updated.to_cbor().to_bytes(), tid).await?;
    let current = tree.get(&nested.map_key).await?;
    tree.put(&signer, &nested.map_key, &current, Some(CborObject::MerkleLink(cid.to_bytes())), tid).await?;
    commit_champ(owner, &signer, "tree", &pointer, &wd, &tree, store, mutable, tid).await?;
    if old_owner.public_key_hash != new_owner.public_key_hash {
        add_owned_writer(owner, new_owner, &signer, store, mutable, tid).await?;
        remove_owned_writer(owner, old_owner, &nested.writer, store, mutable, tid).await?;
    }
    Ok(())
}

/// Move `child_name` in `parent_cap`, and everything below it in the same writing
/// space, into a new writing space without changing any key. Returns its writable
/// capability, which differs from the old one only in its writer. A child that
/// already has its own writing space is returned as it is.
pub async fn move_to_new_writing_space(
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let entry = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?;
    let w_base_key = entry
        .cap
        .w_base_key
        .clone()
        .ok_or_else(|| Error::Protocol("cannot grant write access without a writable capability".into()))?;
    if entry.cap.writer != parent_cap.writer {
        return Ok(entry.cap);
    }
    let (root, props) = retrieve_file_metadata(&entry.cap, store.clone(), mutable).await?;
    if props.is_link {
        // already write-shared: the link node's single child is the target
        return list_directory(&entry.cap, store.clone(), mutable)
            .await?
            .into_iter()
            .next()
            .map(|e| e.cap)
            .ok_or_else(|| Error::Protocol("link node has no target".into()));
    }
    let owner = parent_cap.owner.clone();
    let old_signer = parent_writer_signer(parent_cap, &entry_signer, store.clone(), mutable).await?;

    let old_champ = open_writer_champ(&entry.cap, store.clone(), mutable).await?;
    let mut subtree = Subtree::default();
    collect_subtree(&entry.cap, &old_champ, &mut subtree, &store, mutable).await?;

    let new_pair = SigningKeyPair::random_writer()?;
    let tid = store.start_transaction(&owner).await?;
    let new_hash = put_signing_key(store.as_ref(), &owner, &old_signer, &new_pair.public, &tid).await?;
    let new_signer = SigningPrivateKeyAndPublicHash::new(new_hash.clone(), new_pair.secret);
    // the server checks ownership on every write, so this goes before any block
    // signed by the new writer
    add_owned_writer(&owner, &old_signer, &new_signer, &store, mutable, &tid).await?;

    // the root's parent becomes the link node that will name it in the parent
    let link_keys = LinkNodeKeys::random()?;
    let new_parent_link = link_keys.parent_link(&parent_cap.writer);
    let new_root = with_parent_link(
        &with_writer_link(&root, &entry.cap.r_base_key, &w_base_key, &new_signer)?,
        &entry.cap.r_base_key,
        &new_parent_link,
    )?;
    let root_cid = put_block_signed(store.as_ref(), &owner, &new_signer, new_root.to_cbor().to_bytes(), &tid).await?;

    let owned_root = put_block_signed(store.as_ref(), &owner, &new_signer, Champ::empty().serialize(), &tid).await?;
    let tree_root = put_block_signed(store.as_ref(), &owner, &new_signer, Champ::empty().serialize(), &tid).await?;
    let mut tree = ChampWrapper::create(owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?;
    for (map_key, value) in &subtree.entries {
        let value = if map_key == &entry.cap.map_key {
            CborObject::MerkleLink(root_cid.to_bytes())
        } else {
            value.clone()
        };
        tree.put(&new_signer, map_key, &None, Some(value), &tid).await?;
    }
    let wd = CborObject::map()
        .put("controller", new_hash.to_cbor())
        .put("owned", CborObject::MerkleLink(owned_root.to_bytes()))
        .put("tree", CborObject::MerkleLink(tree.root_hash().to_bytes()))
        .build();
    let wd_cid = put_block_signed(store.as_ref(), &owner, &new_signer, wd.to_bytes(), &tid).await?;
    if !mutable
        .set_pointer_update(&owner, &new_signer, &PointerUpdate::new(None, Some(wd_cid), PointerUpdate::increment(None)))
        .await?
    {
        return Err(Error::Protocol("new writer pointer rejected".into()));
    }
    let new_cap = AbsoluteCapability::new(
        owner.clone(),
        new_hash.clone(),
        entry.cap.map_key.clone(),
        entry.cap.bat.clone(),
        entry.cap.r_base_key.clone(),
        Some(w_base_key),
    )?;

    for nested in &subtree.nested {
        let (old_writer, new_writer) = (old_signer.public_key_hash.clone(), new_hash.clone());
        reparent_writing_space(
            nested,
            |link| {
                let writer = match link.writer {
                    Some(w) if w == old_writer => Some(new_writer),
                    other => other,
                };
                RelCap { writer, ..link }
            },
            &old_signer,
            &new_signer,
            &store,
            mutable,
            &tid,
        )
        .await?;
    }

    create_link_node(
        parent_cap,
        child_name,
        &new_cap,
        &props,
        &link_keys,
        entry_signer.clone(),
        mirror_bat,
        store.clone(),
        mutable,
    )
    .await?;
    // the old copies are unreachable now; nested writing spaces are not in this champ
    remove_orphaned_subtree(parent_cap, &entry.cap, entry_signer, mirror_bat, &store, mutable).await?;
    store.close_transaction(&owner, &tid).await?;
    Ok(new_cap)
}

/// Move `child`, which is in `source_parent`'s writing space, into `target_dir` in
/// another writing space of the same owner as `new_name`, without copying it
/// (`moveAcrossWritingSpaces`): its champ entries move to the target's writer and
/// every block is kept, so nothing is re-encrypted or uploaded again. Writing
/// spaces nested in it only change their parent link and owner. Returns its new
/// capability, which differs from the old one only in its writer.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn move_across_writing_spaces(
    source_parent: &AbsoluteCapability,
    child: &DirEntry,
    name: &str,
    target_dir: &AbsoluteCapability,
    target_node: &CryptreeNode,
    new_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let owner = source_parent.owner.clone();
    let from = parent_writer_signer(source_parent, &entry_signer, store.clone(), mutable).await?;
    let to = recover_signer(target_dir, store.clone(), mutable)
        .await
        .ok()
        .or_else(|| entry_signer.clone().filter(|s| s.public_key_hash == target_dir.writer))
        .ok_or_else(|| Error::Protocol("no writer signer for target".into()))?;

    let old_champ = open_writer_champ(&child.cap, store.clone(), mutable).await?;
    let root = fetch_chunk_node(&old_champ, &child.cap, &child.cap.map_key, &child.cap.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol("child node missing".into()))?;
    let mut subtree = Subtree::default();
    collect_subtree(&child.cap, &old_champ, &mut subtree, &store, mutable).await?;

    // the root's parent becomes the target, in the target's writing space
    let parent_key = root.get_parent_key(&child.cap.r_base_key);
    let new_parent_link = RelCap {
        writer: None,
        map_key: target_dir.map_key.clone(),
        bat: target_dir.bat.clone(),
        r_base_key: target_node.get_parent_key(&target_dir.r_base_key),
        w_base_key_link: None,
    };
    let mut props = root.get_properties(&child.cap.r_base_key)?;
    props.name = new_name.to_string();
    let block = root.from_parent_key.decrypt(&parent_key, |c| Ok(c.clone()))?;
    let block = set_field(&set_field(&block, "p", new_parent_link.to_cbor())?, "s", props.to_cbor())?;
    let new_root = CryptreeNode {
        from_parent_key: PaddedCipherText::build(&parent_key, &block, META_DATA_PADDING_BLOCKSIZE)?,
        ..root.clone()
    };

    let tid = store.start_transaction(&owner).await?;
    let root_cid = put_block_signed(store.as_ref(), &owner, &to, new_root.to_cbor().to_bytes(), &tid).await?;
    let (pointer, wd, mut tree) = open_champ(&owner, &target_dir.writer, "tree", &store, mutable).await?;
    for (map_key, value) in &subtree.entries {
        let value = if map_key == &child.cap.map_key {
            CborObject::MerkleLink(root_cid.to_bytes())
        } else {
            value.clone()
        };
        let current = tree.get(map_key).await?;
        tree.put(&to, map_key, &current, Some(value), &tid).await?;
    }
    commit_champ(&owner, &to, "tree", &pointer, &wd, &tree, &store, mutable, &tid).await?;

    for nested in &subtree.nested {
        let (old_writer, new_writer) = (from.public_key_hash.clone(), to.public_key_hash.clone());
        reparent_writing_space(
            nested,
            |link| {
                let writer = match link.writer {
                    Some(w) if w == old_writer => Some(new_writer),
                    other => other,
                };
                RelCap { writer, ..link }
            },
            &from,
            &to,
            &store,
            mutable,
            &tid,
        )
        .await?;
    }

    let new_cap = AbsoluteCapability::new(
        owner.clone(),
        target_dir.writer.clone(),
        child.cap.map_key.clone(),
        child.cap.bat.clone(),
        child.cap.r_base_key.clone(),
        child.cap.w_base_key.clone(),
    )?;
    let w_link = match (&target_dir.w_base_key, &child.cap.w_base_key) {
        (Some(pw), Some(cw)) => Some(peergos_core::symmetric::CipherText::build(pw, cw)?.to_cbor()),
        _ => None,
    };
    let child_link = NamedRelativeCapability {
        name: new_name.to_string(),
        cap: RelCap {
            writer: None,
            map_key: child.cap.map_key.clone(),
            bat: child.cap.bat.clone(),
            r_base_key: child.cap.r_base_key.clone(),
            w_base_key_link: w_link,
        },
        is_dir: child.is_dir,
        mime_type: child.mime_type.clone(),
        created_epoch: Some(props.created_epoch),
    };
    let ctx = begin_dir_write(target_dir, Some(to.clone()), mirror_bat, &store, mutable).await?;
    finish_dir_write(ctx, target_dir, &store, mutable, child_link).await?;
    remove_child_link(source_parent, name, entry_signer.clone(), mirror_bat, store.clone(), mutable).await?;
    // the old entries are unreachable now; nested writing spaces are not in that champ
    remove_orphaned_subtree(source_parent, &child.cap, entry_signer, mirror_bat, &store, mutable).await?;
    store.close_transaction(&owner, &tid).await?;
    Ok(new_cap)
}

/// Every writer `signer` owns that has no pointer: left behind by an authorisation
/// that was interrupted before the new writer's first commit (`findOrphanedWriters`).
pub(crate) async fn orphaned_writers(
    signer: &SigningPrivateKeyAndPublicHash,
    owner: &PublicKeyHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<PublicKeyHash>> {
    let (_, _, owned) = match open_champ(owner, &signer.public_key_hash, "owned", store, mutable).await {
        Ok(x) => x,
        Err(_) => return Ok(Vec::new()),
    };
    let root = store
        .get(owner, owned.root_hash(), None)
        .await?
        .ok_or_else(|| Error::Protocol("owned champ root missing".into()))?;
    let mut res = Vec::new();
    for mapping in Champ::from_cbor(&root)?.collect_mappings(owner, store.as_ref()).await? {
        let mut key = mapping.key.clone();
        key.reverse();
        let writer = PublicKeyHash::from_cbor(&CborObject::from_bytes(&key)?)?;
        if mutable.get_pointer_target(owner, &writer, store.as_ref()).await?.updated.is_none() {
            res.push(writer);
        }
    }
    Ok(res)
}

/// Remove `orphans` from `signer`'s owned keys. Returns how many were removed.
pub(crate) async fn remove_orphans(
    signer: &SigningPrivateKeyAndPublicHash,
    owner: &PublicKeyHash,
    orphans: &[PublicKeyHash],
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<usize> {
    if orphans.is_empty() {
        return Ok(0);
    }
    let tid = store.start_transaction(owner).await?;
    let mut removed = 0;
    for w in orphans {
        if remove_owned_writer(owner, signer, w, store, mutable, &tid).await? {
            removed += 1;
        }
    }
    store.close_transaction(owner, &tid).await?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use peergos_mock_server::MockServer;

    /// A writer registered as owned but never given a pointer, as an interrupted grant
    /// leaves one, is found and removed once.
    #[tokio::test]
    async fn orphaned_writers_are_removed() {
        let server = MockServer::new();
        let (poster, store, mutable) = server.connect();
        let ctx = crate::UserContext::sign_up("olga", "opw", None, poster, store.clone(), mutable.clone()).await.unwrap();
        let user = ctx.user().unwrap();
        let home_signer = recover_signer(user.home().unwrap(), store.clone(), mutable.as_ref()).await.unwrap();
        let (wpub, wsec) = peergos_crypto::sign::keypair_from_seed(&[3u8; 32]).unwrap();
        let orphan = SigningPrivateKeyAndPublicHash::new(
            peergos_core::PublicSigningKey::new(wpub.to_vec()).hash().unwrap(),
            peergos_core::SecretSigningKey::new(wsec.to_vec()),
        );
        let tid = store.start_transaction(&user.identity).await.unwrap();
        add_owned_writer(&user.identity, &home_signer, &orphan, &store, mutable.as_ref(), &tid).await.unwrap();

        assert_eq!(ctx.remove_orphaned_writers().await.unwrap(), 1);
        assert_eq!(ctx.remove_orphaned_writers().await.unwrap(), 0);
    }
}

/// A writing space nested in another, the directory or link node in the other
/// holding its cap, and that other space's signer.
pub(crate) struct NestedSpace {
    pub cap: AbsoluteCapability,
    pub holder: AbsoluteCapability,
    pub holder_signer: SigningPrivateKeyAndPublicHash,
}

/// The writing spaces nested in `dir`'s subtree, each with the directory or link
/// node holding its cap (`FileWrapper.findNestedWritingSpaces`). Files' chunks are
/// not read.
pub(crate) fn find_nested_writing_spaces<'a>(
    dir: &'a AbsoluteCapability,
    out: &'a mut Vec<(AbsoluteCapability, AbsoluteCapability)>,
    store: &'a Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        for child in list_directory(dir, store.clone(), mutable).await? {
            if child.cap.writer != dir.writer {
                out.push((child.cap, dir.clone()));
            } else if child.is_dir != Some(false) {
                match find_nested_writing_spaces(&child.cap, out, store, mutable).await {
                    Err(Error::Protocol(m)) if m.contains("points to a file") => {}
                    r => r?,
                }
            }
        }
        Ok(())
    })
}

/// Move the writing space rooted at `space` to a new writer owned by `parent`, in
/// one commit (`UserContext.switchSpace`): the new writer takes the old one's champ
/// as it is, as nodes in one writing space name their children without a writer;
/// the root is rewritten with its new signer link; the holder, if any, points at
/// it; and the old writer's champ is replaced by link nodes, under the old keys, to
/// where its root and each of `also_linked` now are, so old caps still lead there.
/// The old writer's update is from the version the new one was built from, so a
/// concurrent write fails the commit, and the move is tried again. A space that
/// has moved already is left alone. Returns the new cap of the space.
pub(crate) async fn switch_writer(
    space: &AbsoluteCapability,
    parent: &SigningPrivateKeyAndPublicHash,
    from: Option<&NestedSpace>,
    also_linked: &[AbsoluteCapability],
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: Arc<dyn MutablePointers>,
) -> Result<AbsoluteCapability> {
    let mut attempts = 5;
    loop {
        let net = BufferedNetwork::with_defaults(store.clone(), mutable.clone());
        net.disable_commits();
        let bstore: Arc<dyn ContentAddressedStorage> = net.storage();
        let bmut = net.pointers();
        let res = async {
            let new_cap = switch_writer_once(space, parent, from, also_linked, mirror_bat, &bstore, bmut.as_ref()).await?;
            net.commit(&space.owner).await?;
            Ok(new_cap)
        }
        .await;
        match res {
            Err(e) if attempts > 1 => {
                attempts -= 1;
                log::info!("Retrying the move of {} to a new writer: {e}", space.writer);
            }
            r => return r,
        }
    }
}

async fn switch_writer_once(
    space: &AbsoluteCapability,
    parent: &SigningPrivateKeyAndPublicHash,
    from: Option<&NestedSpace>,
    also_linked: &[AbsoluteCapability],
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let owner = &space.owner;
    let w_base_key = space.w_base_key.clone().ok_or_else(|| Error::Protocol("writing space is not writable".into()))?;
    let (old_pointer, old_wd, old_tree) = open_champ(owner, &space.writer, "tree", store, mutable).await?;
    let root = fetch_chunk_node(&old_tree, space, &space.map_key, &space.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol("Writing space root is missing".into()))?;
    if root.get_properties(&space.r_base_key)?.is_link {
        return list_directory(space, store.clone(), mutable)
            .await?
            .into_iter()
            .next()
            .map(|e| e.cap)
            .ok_or_else(|| Error::Protocol("link node has no target".into()));
    }
    let old_signer = root.get_signer(&space.r_base_key, &w_base_key)?;

    let new_pair = SigningKeyPair::random_writer()?;
    let tid = store.start_transaction(owner).await?;
    let new_hash = put_signing_key(store.as_ref(), owner, parent, &new_pair.public, &tid).await?;
    let new_signer = SigningPrivateKeyAndPublicHash::new(new_hash.clone(), new_pair.secret);
    add_owned_writer(owner, parent, &new_signer, store, mutable, &tid).await?;

    let mut new_root = with_writer_link(&root, &space.r_base_key, &w_base_key, &new_signer)?;
    if let Some(n) = from {
        let link = root
            .parent_link(&space.r_base_key)?
            .ok_or_else(|| Error::Protocol("Nested writing space with no parent link!".into()))?;
        let link = RelCap { writer: Some(n.holder_signer.public_key_hash.clone()), ..link };
        new_root = with_parent_link(&new_root, &space.r_base_key, &link)?;
    }
    let root_cid = put_block_signed(store.as_ref(), owner, &new_signer, new_root.to_cbor().to_bytes(), &tid).await?;
    let mut tree = ChampWrapper::create(owner.clone(), old_tree.root_hash().clone(), None, store.clone(), identity_key_hasher()).await?;
    let current = tree.get(&space.map_key).await?;
    tree.put(&new_signer, &space.map_key, &current, Some(CborObject::MerkleLink(root_cid.to_bytes())), &tid).await?;
    let owned_root = put_block_signed(store.as_ref(), owner, &new_signer, Champ::empty().serialize(), &tid).await?;
    let wd = CborObject::map()
        .put("controller", new_hash.to_cbor())
        .put("owned", CborObject::MerkleLink(owned_root.to_bytes()))
        .put("tree", CborObject::MerkleLink(tree.root_hash().to_bytes()))
        .build();
    let wd_cid = put_block_signed(store.as_ref(), owner, &new_signer, wd.to_bytes(), &tid).await?;
    if !mutable
        .set_pointer_update(owner, &new_signer, &PointerUpdate::new(None, Some(wd_cid), PointerUpdate::increment(None)))
        .await?
    {
        return Err(Error::Protocol("new writer's pointer rejected".into()));
    }
    let new_cap = AbsoluteCapability { writer: new_hash.clone(), ..space.clone() };

    if let Some(n) = from {
        point_holder_at(n, &new_cap, mirror_bat, store, mutable).await?;
    }

    // the old writer last, from the version the new one took
    let empty = put_block_signed(store.as_ref(), owner, &old_signer, Champ::empty().serialize(), &tid).await?;
    let mut links = ChampWrapper::create(owner.clone(), empty, None, store.clone(), identity_key_hasher()).await?;
    let root_parent_writer = from.map(|n| n.holder_signer.public_key_hash.clone());
    let in_place = also_linked
        .iter()
        .map(|c| (c.clone(), AbsoluteCapability { writer: new_hash.clone(), ..c.clone() }, Some(new_hash.clone())))
        .chain(std::iter::once((space.clone(), new_cap.clone(), root_parent_writer)));
    for (old, target, parent_writer) in in_place {
        let node = fetch_chunk_node(&old_tree, &old, &old.map_key, &old.bat, store.as_ref())
            .await?
            .ok_or_else(|| Error::Protocol("directory to link is missing".into()))?;
        let (link, fragments) = link_in_place_of(&node, &old, &target, parent_writer, mirror_bat)?;
        put_raw_blocks_signed(store.as_ref(), owner, &old_signer, fragments, &tid).await?;
        let cid = put_block_signed(store.as_ref(), owner, &old_signer, link.to_cbor().to_bytes(), &tid).await?;
        links.put(&old_signer, &old.map_key, &None, Some(CborObject::MerkleLink(cid.to_bytes())), &tid).await?;
    }
    commit_champ(owner, &old_signer, "tree", &old_pointer, &old_wd, &links, store, mutable, &tid).await?;
    store.close_transaction(owner, &tid).await?;
    Ok(new_cap)
}

/// A link node in place of `old`, at its location and with its keys and name, to
/// `target`. It holds the write key, so old write caps still write there.
fn link_in_place_of(
    old: &CryptreeNode,
    old_cap: &AbsoluteCapability,
    target: &AbsoluteCapability,
    parent_writer: Option<PublicKeyHash>,
    mirror_bat: Option<&BatId>,
) -> Result<(CryptreeNode, Vec<Vec<u8>>)> {
    let mut props = old.get_properties(&old_cap.r_base_key)?;
    props.is_link = true;
    // a link is a directory, which needs a parent key of its own, unlike a file
    let parent_key = random_symmetric_key()?;
    let to_parent = old.parent_link(&old_cap.r_base_key)?.map(|p| match &parent_writer {
        Some(w) => RelCap { writer: Some(w.clone()), ..p },
        None => p,
    });
    let old_w = old_cap.w_base_key.as_ref().ok_or_else(|| Error::Protocol("old cap is not writable".into()))?;
    let target_w = target.w_base_key.as_ref().ok_or_else(|| Error::Protocol("target is not writable".into()))?;
    let to_target = NamedRelativeCapability {
        name: props.name.clone(),
        cap: RelCap {
            writer: Some(target.writer.clone()),
            map_key: target.map_key.clone(),
            bat: target.bat.clone(),
            r_base_key: target.r_base_key.clone(),
            w_base_key_link: Some(peergos_core::symmetric::CipherText::build(old_w, target_w)?.to_cbor()),
        },
        is_dir: Some(props.is_directory),
        mime_type: Some(props.mime_type.clone()),
        created_epoch: Some(props.created_epoch),
    };
    let next_chunk = RelCap::subsequent_chunk(random_bytes(32), Some(Bat::new(random_bytes(32))?), old_cap.r_base_key.clone());
    let from_base = CborObject::map().put("k", parent_key.to_cbor()).put("n", next_chunk.to_cbor()).build();
    let from_parent = CborObject::map()
        .put_opt("p", to_parent.map(|p| p.to_cbor()))
        .put("s", props.to_cbor())
        .build();
    let (children_data, fragments) = retrieve::FragmentedPaddedCipherText::build(
        &old_cap.r_base_key,
        &ChildrenLinks::Named(vec![to_target]).to_cbor(),
        MIN_FRAGMENT_SIZE,
        mirror_bat,
    )?;
    let node = CryptreeNode::new(
        true,
        node_bats_opt(old_cap.bat.as_ref(), mirror_bat)?,
        PaddedCipherText::build(&old_cap.r_base_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
        PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        children_data.to_cbor(),
    );
    Ok((node, fragments))
}

/// Point the holder of a nested space, in its own space's writer, at the nested
/// space's new cap.
async fn point_holder_at(
    from: &NestedSpace,
    new_cap: &AbsoluteCapability,
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if !from.holder.is_writable() {
        return Err(Error::Protocol("Nested writing space held by a read only cap".into()));
    }
    let holder = AbsoluteCapability { writer: from.holder_signer.public_key_hash.clone(), ..from.holder.clone() };
    let mut ctx = begin_dir_write(&holder, Some(from.holder_signer.clone()), mirror_bat, store, mutable).await?;
    let mut chunks = collect_dir_chunks(&holder, &ctx, store).await?;
    let found = chunks.iter_mut().enumerate().find_map(|(i, (.., children))| {
        children.iter_mut().find(|c| c.cap.map_key == from.cap.map_key).map(|c| {
            c.cap.writer = Some(new_cap.writer.clone());
            i
        })
    });
    let i = found.ok_or_else(|| Error::Protocol("Moved holder of a nested writing space is missing its child".into()))?;
    let (map_key, node, champ_value, children) = &chunks[i];
    recommit_dir_chunk(&mut ctx, &holder, store, map_key, node, champ_value, children.clone()).await?;
    commit_dir_write(&ctx, &holder, store, mutable).await
}

/// Open `writer`'s WriterData and tree champ.
pub(crate) async fn open_tree(
    owner: &PublicKeyHash,
    writer: &PublicKeyHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(PointerUpdate, CborObject, ChampWrapper)> {
    open_champ(owner, writer, "tree", store, mutable).await
}

/// Make `child` a writer owned by `parent`, with empty champs
/// (`initAndAuthoriseSigner`, after its key is stored).
pub(crate) async fn init_writer(
    owner: &PublicKeyHash,
    parent: &SigningPrivateKeyAndPublicHash,
    child: &SigningPrivateKeyAndPublicHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    tid: &TransactionId,
) -> Result<()> {
    add_owned_writer(owner, parent, child, store, mutable, tid).await?;
    let owned = put_block_signed(store.as_ref(), owner, child, Champ::empty().serialize(), tid).await?;
    let tree = put_block_signed(store.as_ref(), owner, child, Champ::empty().serialize(), tid).await?;
    let wd = CborObject::map()
        .put("controller", child.public_key_hash.to_cbor())
        .put("owned", CborObject::MerkleLink(owned.to_bytes()))
        .put("tree", CborObject::MerkleLink(tree.to_bytes()))
        .build();
    let wd_cid = put_block_signed(store.as_ref(), owner, child, wd.to_bytes(), tid).await?;
    let update = PointerUpdate::new(None, Some(wd_cid), PointerUpdate::increment(None));
    if !mutable.set_pointer_update(owner, child, &update).await? {
        return Err(Error::Protocol("new writer's pointer rejected".into()));
    }
    Ok(())
}

/// Remove `child` from `parent`'s owned writers, if it is one.
pub(crate) async fn disown_writer(
    owner: &PublicKeyHash,
    parent: &SigningPrivateKeyAndPublicHash,
    child: &PublicKeyHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    tid: &TransactionId,
) -> Result<bool> {
    remove_owned_writer(owner, parent, child, store, mutable, tid).await
}
