//! Three-way champ merge for CAS-conflict resolution, ported from Java's
//! `ChampUtil.merge` / `applyToDiff` + `BufferedNetworkAccess.commitPointerWithMerge`.
//!
//! When two devices commit a writer's pointer concurrently, our update (based on
//! `original`) races the remote update. We merge the writer's champ tree: apply the
//! keys the REMOTE side changed since `original` onto OUR tree, erroring if both
//! sides touched the same key.
//!
//! Crucially the diff walks the two trees in lock-step and **skips any subtree whose
//! two shard CIDs are equal without loading it** — so a merge touches only the
//! changed path (O(changes) blocks), never the whole tree.

use crate::champ::{identity_key_hasher, Champ, ChampWrapper, KeyElement, Payload};
use crate::error::{Error, Result};
use crate::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use crate::storage::{ContentAddressedStorage, TransactionId};
use peergos_cbor::CborObject;
use peergos_multiformats::Cid;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const BIT_WIDTH: usize = crate::champ::BIT_WIDTH;
/// Champ nodes have `2^bitWidth` slots.
const SLOTS: usize = 1 << BIT_WIDTH;

/// Merge the champ trees of three WriterData blocks (`base`, `ours`, `theirs`) and
/// return the serialized merged WriterData (based on `theirs`, tree replaced by the
/// merged root). New champ nodes are written to `storage`.
pub async fn merge_writer_data(
    owner: &PublicKeyHash,
    signer: &SigningPrivateKeyAndPublicHash,
    base_wd: &Cid,
    our_wd: &Cid,
    their_wd: &Cid,
    storage: Arc<dyn ContentAddressedStorage>,
    tid: &TransactionId,
) -> Result<Vec<u8>> {
    let base = get_block(owner, base_wd, storage.as_ref()).await?;
    let ours = get_block(owner, our_wd, storage.as_ref()).await?;
    let theirs = get_block(owner, their_wd, storage.as_ref()).await?;

    let merged_root =
        merge_champ(owner, signer, &tree_root(&base)?, &tree_root(&ours)?, &tree_root(&theirs)?, storage, tid).await?;
    Ok(with_tree(&theirs, &merged_root)?.to_bytes())
}

async fn get_block(owner: &PublicKeyHash, cid: &Cid, storage: &dyn ContentAddressedStorage) -> Result<CborObject> {
    storage.get(owner, cid, None).await?.ok_or_else(|| Error::Protocol(format!("block missing for merge: {cid}")))
}

fn tree_root(wd: &CborObject) -> Result<Cid> {
    Cid::cast(wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Cbor("WriterData has no champ tree".into()))?)
        .map_err(Into::into)
}

fn with_tree(wd: &CborObject, tree_root: &Cid) -> Result<CborObject> {
    let mut map = match wd {
        CborObject::Map(m) => m.clone(),
        _ => return Err(Error::Cbor("WriterData is not a map".into())),
    };
    map.insert(peergos_cbor::CborString::new("tree"), CborObject::MerkleLink(tree_root.to_bytes()));
    Ok(CborObject::Map(map))
}

/// One key that differs between two champ trees: its value in the base tree and in
/// the other tree (`None` = absent).
#[derive(Clone)]
struct DiffEntry {
    key: Vec<u8>,
    base: Option<CborObject>,
    other: Option<CborObject>,
}

/// Apply the changes the REMOTE side made (`base`→`theirs`) on top of OUR tree,
/// refusing if both sides changed the same key. Only changed nodes are loaded.
async fn merge_champ(
    owner: &PublicKeyHash,
    signer: &SigningPrivateKeyAndPublicHash,
    base: &Cid,
    ours: &Cid,
    theirs: &Cid,
    storage: Arc<dyn ContentAddressedStorage>,
    tid: &TransactionId,
) -> Result<Cid> {
    let mut our_diff = Vec::new();
    diff(owner, &Some(base.clone()), &Some(ours.clone()), 0, Vec::new(), Vec::new(), &mut our_diff, storage.as_ref()).await?;
    let mut remote_diff = Vec::new();
    diff(owner, &Some(base.clone()), &Some(theirs.clone()), 0, Vec::new(), Vec::new(), &mut remote_diff, storage.as_ref()).await?;

    let our_keys: HashSet<Vec<u8>> = our_diff.iter().map(|d| d.key.clone()).collect();
    let their_keys: HashSet<Vec<u8>> = remote_diff.iter().map(|d| d.key.clone()).collect();
    if our_keys.intersection(&their_keys).next().is_some() {
        return Err(Error::Protocol("Concurrent modification of a file or directory!".into()));
    }

    // Apply the remote changes onto our tree (our tree still holds `base` at each of
    // these keys, since the change sets are disjoint).
    let mut merged = ChampWrapper::create(owner.clone(), ours.clone(), None, storage.clone(), identity_key_hasher()).await?;
    for d in &remote_diff {
        match &d.other {
            Some(value) => {
                merged.put(signer, &d.key, &d.base, Some(value.clone()), tid).await?;
            }
            None => {
                merged.remove(signer, &d.key, &d.base, tid).await?;
            }
        }
    }
    Ok(merged.root_hash().clone())
}

fn bit_get(bitmap: &[u8], pos: usize) -> bool {
    let byte = pos / 8;
    byte < bitmap.len() && (bitmap[byte] >> (pos % 8)) & 1 == 1
}

/// The payload at champ slot `bit` (`Champ.getElement`): an inline mapping array, a
/// shard link, or nothing. `data_index`/`node_index` are the running counts of data
/// and node slots seen before `bit`.
fn get_element<'a>(bit: usize, data_index: usize, node_index: usize, champ: Option<&'a Champ>) -> Option<&'a Payload> {
    let c = champ?;
    if bit_get(&c.data_map, bit) {
        return c.contents.get(data_index);
    }
    if bit_get(&c.node_map, bit) {
        return c.contents.get(c.contents.len() - 1 - node_index);
    }
    None
}

/// Group higher-level mappings by their champ slot at `depth` (`Champ.hashAndMaskKeys`,
/// identity-hashed).
fn hash_and_mask(mappings: &[KeyElement], depth: usize) -> HashMap<usize, Vec<KeyElement>> {
    let mut out: HashMap<usize, Vec<KeyElement>> = HashMap::new();
    for m in mappings {
        let bit = Champ::mask(&m.key, depth, BIT_WIDTH); // identity hasher: hash == key
        out.entry(bit).or_default().push(m.clone());
    }
    out
}

async fn load_champ(cid: &Option<Cid>, owner: &PublicKeyHash, storage: &dyn ContentAddressedStorage) -> Result<Option<Champ>> {
    match cid {
        Some(c) => Ok(Some(Champ::from_cbor(&get_block(owner, c, storage).await?)?)),
        None => Ok(None),
    }
}

/// Collect the keys that differ between the champ trees `original` and `updated`
/// into `out` (as `DiffEntry { base: original value, other: updated value }`),
/// recursing only into subtrees whose shard CIDs differ (`ChampUtil.applyToDiff`).
fn diff<'a>(
    owner: &'a PublicKeyHash,
    original: &'a Option<Cid>,
    updated: &'a Option<Cid>,
    depth: usize,
    higher_left: Vec<KeyElement>,
    higher_right: Vec<KeyElement>,
    out: &'a mut Vec<DiffEntry>,
    storage: &'a dyn ContentAddressedStorage,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        if original == updated {
            return Ok(()); // identical subtree (same CID, or both absent) — never loaded
        }
        let left = load_champ(original, owner, storage).await?;
        let right = load_champ(updated, owner, storage).await?;
        let left_higher = hash_and_mask(&higher_left, depth);
        let right_higher = hash_and_mask(&higher_right, depth);

        let (mut ld, mut rd, mut ln, mut rn) = (0usize, 0usize, 0usize, 0usize);
        let mut deeper: Vec<(Option<Cid>, Option<Cid>, Vec<KeyElement>, Vec<KeyElement>)> = Vec::new();

        for i in 0..SLOTS {
            let lp = get_element(i, ld, ln, left.as_ref());
            let rp = get_element(i, rd, rn, right.as_ref());

            let left_mappings: Vec<KeyElement> = match lp {
                Some(Payload::Mappings(m)) => m.clone(),
                _ => left_higher.get(&i).cloned().unwrap_or_default(),
            };
            let right_mappings: Vec<KeyElement> = match rp {
                Some(Payload::Mappings(m)) => m.clone(),
                _ => right_higher.get(&i).cloned().unwrap_or_default(),
            };
            let left_shard = match lp {
                Some(Payload::Link(c)) => Some(c.clone()),
                _ => None,
            };
            let right_shard = match rp {
                Some(Payload::Link(c)) => Some(c.clone()),
                _ => None,
            };

            if left_shard.is_some() || right_shard.is_some() {
                deeper.push((left_shard, right_shard, left_mappings, right_mappings));
            } else {
                let lmap: HashMap<Vec<u8>, Option<CborObject>> =
                    left_mappings.into_iter().map(|k| (k.key, k.value)).collect();
                let rmap: HashMap<Vec<u8>, Option<CborObject>> =
                    right_mappings.into_iter().map(|k| (k.key, k.value)).collect();
                for (k, v) in &lmap {
                    match rmap.get(k) {
                        None => out.push(DiffEntry { key: k.clone(), base: v.clone(), other: None }),
                        Some(rv) if rv != v => out.push(DiffEntry { key: k.clone(), base: v.clone(), other: rv.clone() }),
                        _ => {}
                    }
                }
                for (k, v) in &rmap {
                    if !lmap.contains_key(k) {
                        out.push(DiffEntry { key: k.clone(), base: None, other: v.clone() });
                    }
                }
            }

            if let Some(p) = lp {
                if p.is_shard() {
                    ln += 1;
                } else {
                    ld += 1;
                }
            }
            if let Some(p) = rp {
                if p.is_shard() {
                    rn += 1;
                } else {
                    rd += 1;
                }
            }
        }

        for (ls, rs, lm, rm) in deeper {
            diff(owner, &ls, &rs, depth + 1, lm, rm, out, storage).await?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{PublicSigningKey, SecretSigningKey};
    use crate::storage::put_block_signed;
    use crate::RamStorage;
    use peergos_cbor::Cborable;

    async fn champ_with(
        base: Option<&Cid>,
        entries: &[(&[u8], i64)],
        owner: &PublicKeyHash,
        signer: &SigningPrivateKeyAndPublicHash,
        store: Arc<dyn ContentAddressedStorage>,
        tid: &TransactionId,
    ) -> Cid {
        let root = match base {
            Some(c) => c.clone(),
            None => put_block_signed(store.as_ref(), owner, signer, Champ::empty().serialize(), tid).await.unwrap(),
        };
        let mut cw = ChampWrapper::create(owner.clone(), root, None, store, identity_key_hasher()).await.unwrap();
        for (k, v) in entries {
            let expected = cw.get(k).await.unwrap();
            cw.put(signer, k, &expected, Some(CborObject::Long(*v)), tid).await.unwrap();
        }
        cw.root_hash().clone()
    }

    async fn setup() -> (PublicKeyHash, SigningPrivateKeyAndPublicHash, Arc<dyn ContentAddressedStorage>, TransactionId) {
        let store: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
        let (pk, sk) = peergos_crypto::sign::keypair_from_seed(&[9u8; 32]).unwrap();
        let owner = PublicSigningKey::new(pk.to_vec()).hash().unwrap();
        let signer = SigningPrivateKeyAndPublicHash::new(owner.clone(), SecretSigningKey::new(sk.to_vec()));
        let tid = store.start_transaction(&owner).await.unwrap();
        (owner, signer, store, tid)
    }

    #[tokio::test]
    async fn merge_disjoint_changes() {
        let (owner, signer, store, tid) = setup().await;
        let base = champ_with(None, &[(b"a", 1), (b"b", 2), (b"c", 3)], &owner, &signer, store.clone(), &tid).await;
        let ours = champ_with(Some(&base), &[(b"d", 4)], &owner, &signer, store.clone(), &tid).await; // +d
        let theirs = champ_with(Some(&base), &[(b"e", 5)], &owner, &signer, store.clone(), &tid).await; // +e

        let merged = merge_champ(&owner, &signer, &base, &ours, &theirs, store.clone(), &tid).await.unwrap();
        let cw = ChampWrapper::create(owner.clone(), merged, None, store.clone(), identity_key_hasher()).await.unwrap();
        for (k, v) in [(&b"a"[..], 1), (b"b", 2), (b"c", 3), (b"d", 4), (b"e", 5)] {
            assert_eq!(cw.get(k).await.unwrap(), Some(CborObject::Long(v)), "key {:?}", k);
        }
    }

    #[tokio::test]
    async fn merge_conflict_on_same_key_errors() {
        let (owner, signer, store, tid) = setup().await;
        let base = champ_with(None, &[(b"a", 1)], &owner, &signer, store.clone(), &tid).await;
        let ours = champ_with(Some(&base), &[(b"a", 2)], &owner, &signer, store.clone(), &tid).await;
        let theirs = champ_with(Some(&base), &[(b"a", 3)], &owner, &signer, store.clone(), &tid).await;
        assert!(merge_champ(&owner, &signer, &base, &ours, &theirs, store.clone(), &tid).await.is_err());
    }

    #[tokio::test]
    async fn merge_applies_a_remote_removal() {
        let (owner, signer, store, tid) = setup().await;
        let base = champ_with(None, &[(b"a", 1), (b"b", 2)], &owner, &signer, store.clone(), &tid).await;
        // theirs removes "b"
        let mut cw = ChampWrapper::create(owner.clone(), base.clone(), None, store.clone(), identity_key_hasher()).await.unwrap();
        let expected = cw.get(b"b").await.unwrap();
        cw.remove(&signer, b"b", &expected, &tid).await.unwrap();
        let theirs = cw.root_hash().clone();
        let ours = champ_with(Some(&base), &[(b"c", 3)], &owner, &signer, store.clone(), &tid).await; // +c

        let merged = merge_champ(&owner, &signer, &base, &ours, &theirs, store.clone(), &tid).await.unwrap();
        let m = ChampWrapper::create(owner.clone(), merged, None, store.clone(), identity_key_hasher()).await.unwrap();
        assert!(m.get(b"a").await.unwrap().is_some());
        assert!(m.get(b"b").await.unwrap().is_none(), "remote removal should apply");
        assert!(m.get(b"c").await.unwrap().is_some(), "our add should survive");
    }
}
