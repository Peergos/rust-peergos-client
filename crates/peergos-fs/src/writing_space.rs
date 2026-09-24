//! Moving a file or directory into a writing space of its own, which is how write
//! access to it is granted (`UserContext.moveToNewWritingSpace`).
//!
//! Granting write access compromises no key, so the subtree's cryptree nodes are
//! re-homed under a new signing key unchanged rather than re-encrypted. Only the
//! subtree root is rewritten, to carry the new signer and name the parent's writer
//! in its parent link. Writing spaces nested inside the subtree keep their blocks
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
    let signed = child.secret.sign_message(&parent.public_key_hash.to_cbor().to_bytes())?;
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

    let (wpub, wsec) =
        peergos_crypto::sign::keypair_from_seed(&random_bytes(32)).map_err(|e| Error::Crypto(e.to_string()))?;
    let new_hash = PublicSigningKey::new(wpub.to_vec()).hash()?;
    let new_signer = SigningPrivateKeyAndPublicHash::new(new_hash.clone(), SecretSigningKey::new(wsec.to_vec()));

    let tid = store.start_transaction(&owner).await?;
    // the server checks ownership on every write, so this goes before any block
    // signed by the new writer
    add_owned_writer(&owner, &old_signer, &new_signer, &store, mutable, &tid).await?;

    let parent_link = root
        .parent_link(&entry.cap.r_base_key)?
        .ok_or_else(|| Error::Protocol(format!("{child_name} has no parent link")))?;
    let new_parent_link = RelCap { writer: Some(parent_cap.writer.clone()), ..parent_link };
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

    let mime = if props.is_directory { None } else { Some(props.mime_type.clone()) };
    create_link_node(
        parent_cap,
        child_name,
        &new_cap,
        props.is_directory,
        mime,
        props.created_epoch,
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
            PublicSigningKey::new(wpub.to_vec()).hash().unwrap(),
            SecretSigningKey::new(wsec.to_vec()),
        );
        let tid = store.start_transaction(&user.identity).await.unwrap();
        add_owned_writer(&user.identity, &home_signer, &orphan, &store, mutable.as_ref(), &tid).await.unwrap();

        assert_eq!(ctx.remove_orphaned_writers().await.unwrap(), 1);
        assert_eq!(ctx.remove_orphaned_writers().await.unwrap(), 0);
    }
}
