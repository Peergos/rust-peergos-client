//! CHAMP (Compressed Hash-Array Mapped Prefix-tree), ported from
//! `peergos.shared.hamt`. This is the persistent map, stored as a Merkle DAG in
//! the block store, that Peergos uses to hold writer data (path → capability).
//!
//! This module implements the read path: parsing champ nodes ([`Champ::from_cbor`]),
//! the bit-indexing (`mask`/`get_index`), and recursive lookup
//! ([`ChampWrapper::get`]). The write path (put/remove/rebalancing) is a later
//! increment.
//!
//! Values are kept as raw [`CborObject`]s (Java's champ is generic over a
//! `Cborable`; the caller interprets the value, e.g. as a Merkle link).

use crate::auth::{BatId, BatWithId};
use crate::error::{Error, Result};
use crate::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use crate::storage::{put_block_signed, ContentAddressedStorage, TransactionId};
use async_recursion::async_recursion;
use peergos_cbor::{CborObject, Cborable};
use peergos_multiformats::Cid;
use std::sync::Arc;

pub const BIT_WIDTH: usize = 3;
pub const MAX_HASH_COLLISIONS_PER_LEVEL: usize = 4;
const HASH_CODE_LENGTH: usize = 32;

/// A single key → value mapping within a champ prefix.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyElement {
    pub key: Vec<u8>,
    pub value: Option<CborObject>,
}

/// A slot in a champ node: either inline key/value mappings, or a link to a
/// child champ node (a "shard").
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Mappings(Vec<KeyElement>),
    Link(Cid),
}

impl Payload {
    pub fn is_shard(&self) -> bool {
        matches!(self, Payload::Link(_))
    }
    fn as_mappings(&self) -> Option<&Vec<KeyElement>> {
        match self {
            Payload::Mappings(m) => Some(m),
            Payload::Link(_) => None,
        }
    }
}

/// `ByteArrayWrapper.compareTo`: length first, then unsigned lexicographic.
fn byte_array_compare(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Set bit `pos` in a `BitSet.toByteArray`-style bitmap (growing as needed).
fn bit_set(bitmap: &mut Vec<u8>, pos: usize) {
    let byte = pos / 8;
    if byte >= bitmap.len() {
        bitmap.resize(byte + 1, 0);
    }
    bitmap[byte] |= 1 << (pos % 8);
}

/// Clear bit `pos`, then drop trailing zero bytes to stay canonical.
fn bit_clear(bitmap: &mut Vec<u8>, pos: usize) {
    let byte = pos / 8;
    if byte < bitmap.len() {
        bitmap[byte] &= !(1u8 << (pos % 8));
    }
    while bitmap.last() == Some(&0) {
        bitmap.pop();
    }
}

/// A single champ node.
#[derive(Debug, Clone, PartialEq)]
pub struct Champ {
    /// Bitmap (Java `BitSet.toByteArray` layout) of inline-data slots.
    pub data_map: Vec<u8>,
    /// Bitmap of child-node (shard) slots.
    pub node_map: Vec<u8>,
    /// Data payloads first (in `data_map` order), then link payloads at the tail
    /// (in `node_map` order).
    pub contents: Vec<Payload>,
    pub mirror_bat: Option<BatId>,
}

impl Champ {
    pub fn empty() -> Champ {
        Champ { data_map: Vec::new(), node_map: Vec::new(), contents: Vec::new(), mirror_bat: None }
    }

    // ---- bit indexing ------------------------------------------------------

    /// Extract the `nbits`-wide champ index for `hash` at `depth` (`Champ.mask`).
    pub fn mask(hash: &[u8], depth: usize, nbits: usize) -> usize {
        let index = (depth * nbits) / 8;
        let shift = (depth * nbits) % 8;
        let low_bits = nbits.min(8 - shift);
        let hi_bits = nbits - low_bits;
        // bytes are treated as signed and sign-extended before shifting (Java).
        let val1 = if index < hash.len() { hash[index] as i8 as i32 } else { 0 };
        let val2 = if index + 1 < hash.len() { hash[index + 1] as i8 as i32 } else { 0 };
        (((val1 >> shift) & ((1 << low_bits) - 1)) | ((val2 & ((1 << hi_bits) - 1)) << low_bits)) as usize
    }

    fn bit_get(bitmap: &[u8], pos: usize) -> bool {
        let byte = pos / 8;
        byte < bitmap.len() && (bitmap[byte] >> (pos % 8)) & 1 == 1
    }

    /// Count set bits in `[0, bitpos)` (`Champ.getIndex`).
    fn get_index(bitmap: &[u8], bitpos: usize) -> usize {
        (0..bitpos).filter(|&i| Champ::bit_get(bitmap, i)).count()
    }

    // ---- read path ---------------------------------------------------------

    async fn get_child(
        &self,
        owner: &PublicKeyHash,
        hash: &[u8],
        depth: usize,
        bit_width: usize,
        storage: &dyn ContentAddressedStorage,
    ) -> Result<Option<Champ>> {
        let bitpos = Champ::mask(hash, depth, bit_width);
        let index = self.contents.len() - 1 - Champ::get_index(&self.node_map, bitpos);
        let link = match &self.contents[index] {
            Payload::Link(cid) => cid,
            Payload::Mappings(_) => return Err(Error::Protocol("expected champ shard link".into())),
        };
        match storage.get(owner, link, None).await? {
            Some(cbor) => Ok(Some(Champ::from_cbor(&cbor)?)),
            None => Ok(None),
        }
    }

    /// Every key/value mapping in this champ (recursing into shard links).
    #[async_recursion]
    pub async fn collect_mappings(
        &self,
        owner: &PublicKeyHash,
        storage: &dyn ContentAddressedStorage,
    ) -> Result<Vec<KeyElement>> {
        let mut out = Vec::new();
        for payload in &self.contents {
            match payload {
                Payload::Mappings(ms) => out.extend(ms.iter().cloned()),
                Payload::Link(cid) => {
                    let cbor = storage
                        .get(owner, cid, None)
                        .await?
                        .ok_or_else(|| Error::Protocol(format!("champ child missing: {cid}")))?;
                    out.extend(Champ::from_cbor(&cbor)?.collect_mappings(owner, storage).await?);
                }
            }
        }
        Ok(out)
    }

    /// Look up `key` (whose champ hash is `hash`) starting at `depth`.
    #[async_recursion]
    pub async fn get(
        &self,
        owner: &PublicKeyHash,
        key: &[u8],
        hash: &[u8],
        depth: usize,
        bit_width: usize,
        storage: &dyn ContentAddressedStorage,
    ) -> Result<Option<CborObject>> {
        let bitpos = Champ::mask(hash, depth, bit_width);

        if Champ::bit_get(&self.data_map, bitpos) {
            let index = Champ::get_index(&self.data_map, bitpos);
            if let Payload::Mappings(mappings) = &self.contents[index] {
                for candidate in mappings {
                    if candidate.key == key {
                        return Ok(candidate.value.clone());
                    }
                }
            }
            return Ok(None);
        }

        if Champ::bit_get(&self.node_map, bitpos) {
            return match self.get_child(owner, hash, depth, bit_width, storage).await? {
                Some(child) => child.get(owner, key, hash, depth + 1, bit_width, storage).await,
                None => Ok(None),
            };
        }

        Ok(None)
    }

    // ---- write path --------------------------------------------------------

    async fn get_child_with_hash(
        &self,
        owner: &PublicKeyHash,
        hash: &[u8],
        depth: usize,
        bit_width: usize,
        storage: &dyn ContentAddressedStorage,
    ) -> Result<(Cid, Champ)> {
        let bitpos = Champ::mask(hash, depth, bit_width);
        let index = self.contents.len() - 1 - Champ::get_index(&self.node_map, bitpos);
        let link = match &self.contents[index] {
            Payload::Link(cid) => cid.clone(),
            Payload::Mappings(_) => return Err(Error::Protocol("expected champ shard link".into())),
        };
        let cbor = storage
            .get(owner, &link, None)
            .await?
            .ok_or_else(|| Error::Protocol(format!("champ child missing: {link}")))?;
        Ok((link, Champ::from_cbor(&cbor)?))
    }

    /// Insert/update `key`→`value` (compare-and-swap on `expected`), writing all
    /// modified nodes and returning the new node and its CID. Mirrors `Champ.put`.
    #[allow(clippy::too_many_arguments)]
    #[async_recursion]
    pub async fn put(
        &self,
        owner: &PublicKeyHash,
        writer: &SigningPrivateKeyAndPublicHash,
        key: &[u8],
        hash: &[u8],
        depth: usize,
        expected: &Option<CborObject>,
        value: &Option<CborObject>,
        bit_width: usize,
        max_collisions: usize,
        key_hasher: &KeyHasher,
        tid: &TransactionId,
        storage: &dyn ContentAddressedStorage,
        our_hash: &Cid,
    ) -> Result<(Champ, Cid)> {
        let bitpos = Champ::mask(hash, depth, bit_width);

        if Champ::bit_get(&self.data_map, bitpos) {
            let index = Champ::get_index(&self.data_map, bitpos);
            let mappings = self.contents[index]
                .as_mappings()
                .ok_or_else(|| Error::Protocol("expected champ mappings".into()))?;
            for (payload_index, mapping) in mappings.iter().enumerate() {
                if mapping.key == key {
                    if &mapping.value != expected {
                        return Err(Error::Protocol("champ CAS failed".into()));
                    }
                    let champ = self.copy_and_set_value(index, payload_index, value.clone());
                    let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
                    return Ok((champ, h));
                }
            }
            if mappings.len() < max_collisions {
                let champ = self.insert_into_prefix(index, key, value.clone());
                let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
                return Ok((champ, h));
            }
            let (child, child_hash) = self
                .push_mappings_down_a_level(
                    owner, writer, mappings, key, hash, value, depth + 1, bit_width,
                    max_collisions, key_hasher, tid, storage,
                )
                .await?;
            let champ = self.copy_and_migrate_from_inline_to_node(bitpos, child_hash);
            let _ = child;
            let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
            Ok((champ, h))
        } else if Champ::bit_get(&self.node_map, bitpos) {
            let (child_hash, child) =
                self.get_child_with_hash(owner, hash, depth, bit_width, storage).await?;
            let (_new_child, new_child_hash) = child
                .put(owner, writer, key, hash, depth + 1, expected, value, bit_width,
                    max_collisions, key_hasher, tid, storage, &child_hash)
                .await?;
            if new_child_hash == child_hash {
                return Ok((self.clone(), our_hash.clone()));
            }
            let champ = self.overwrite_child_link(bitpos, new_child_hash);
            let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
            Ok((champ, h))
        } else {
            let champ = self.add_new_prefix(bitpos, key, value.clone());
            let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
            Ok((champ, h))
        }
    }

    fn key_count(&self) -> usize {
        self.contents.iter().filter_map(Payload::as_mappings).map(|m| m.len()).sum()
    }

    fn node_count(&self) -> usize {
        self.contents.iter().filter(|p| p.is_shard()).count()
    }

    /// Remove the mapping at `payload_index` in the data slot for `bitpos`,
    /// dropping the whole slot (and clearing the data bit) if it becomes empty
    /// (`Champ.removeMapping`).
    fn remove_mapping(&self, bitpos: usize, payload_index: usize) -> Champ {
        let data_index = Champ::get_index(&self.data_map, bitpos);
        let mut dst = self.contents.clone();
        let last_in_prefix = matches!(&dst[data_index], Payload::Mappings(m) if m.len() == 1);
        let mut new_data_map = self.data_map.clone();
        if last_in_prefix {
            dst.remove(data_index);
            bit_clear(&mut new_data_map, bitpos);
        } else if let Payload::Mappings(m) = &dst[data_index] {
            let mut remaining = m.clone();
            remaining.remove(payload_index);
            dst[data_index] = Payload::Mappings(remaining);
        }
        self.with_contents(new_data_map, self.node_map.clone(), dst)
    }

    /// Inline a collapsed child node's single bucket back into this node as data
    /// at `bitpos` (`Champ.copyAndMigrateFromNodeToInline`).
    fn copy_and_migrate_from_node_to_inline(&self, bitpos: usize, node: &Champ) -> Champ {
        let old_index = self.contents.len() - 1 - Champ::get_index(&self.node_map, bitpos);
        let new_index = Champ::get_index(&self.data_map, bitpos);
        let bucket = node
            .contents
            .first()
            .and_then(Payload::as_mappings)
            .cloned()
            .unwrap_or_default();
        let mut dst = self.contents.clone();
        dst.remove(old_index);
        dst.insert(new_index, Payload::Mappings(bucket));
        let mut new_node_map = self.node_map.clone();
        bit_clear(&mut new_node_map, bitpos);
        let mut new_data_map = self.data_map.clone();
        bit_set(&mut new_data_map, bitpos);
        self.with_contents(new_data_map, new_node_map, dst)
    }

    /// Remove `key`→`expected` (CAS), writing modified nodes and returning the
    /// new node and its CID. Mirrors `Champ.remove` (with node collapsing).
    #[allow(clippy::too_many_arguments)]
    #[async_recursion]
    pub async fn remove(
        &self,
        owner: &PublicKeyHash,
        writer: &SigningPrivateKeyAndPublicHash,
        key: &[u8],
        hash: &[u8],
        depth: usize,
        expected: &Option<CborObject>,
        bit_width: usize,
        max_collisions: usize,
        tid: &TransactionId,
        storage: &dyn ContentAddressedStorage,
        our_hash: &Cid,
    ) -> Result<(Champ, Cid)> {
        let bitpos = Champ::mask(hash, depth, bit_width);

        if Champ::bit_get(&self.data_map, bitpos) {
            let data_index = Champ::get_index(&self.data_map, bitpos);
            let mappings = self.contents[data_index]
                .as_mappings()
                .ok_or_else(|| Error::Protocol("expected champ mappings".into()))?;
            for (payload_index, mapping) in mappings.iter().enumerate() {
                if mapping.key != key {
                    continue;
                }
                if &mapping.value != expected {
                    return Err(Error::Protocol("champ CAS failed on remove".into()));
                }
                let champ = if self.key_count() == max_collisions + 1 && self.node_count() == 0 && depth > 0 {
                    // Collapse all remaining mappings into a single bucket so the
                    // parent can inline this node.
                    let mut remaining: Vec<KeyElement> = self
                        .contents
                        .iter()
                        .filter_map(Payload::as_mappings)
                        .flatten()
                        .filter(|m| m.key != key)
                        .cloned()
                        .collect();
                    remaining.sort_by(|a, b| byte_array_compare(&a.key, &b.key));
                    let mut new_data_map = Vec::new();
                    bit_set(&mut new_data_map, Champ::mask(hash, 0, bit_width));
                    Champ {
                        data_map: new_data_map,
                        node_map: Vec::new(),
                        contents: vec![Payload::Mappings(remaining)],
                        mirror_bat: self.mirror_bat.clone(),
                    }
                } else {
                    self.remove_mapping(bitpos, payload_index)
                };
                let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
                return Ok((champ, h));
            }
            return Err(Error::Protocol("champ CAS failed: key not present".into()));
        } else if Champ::bit_get(&self.node_map, bitpos) {
            let (child_hash, child) =
                self.get_child_with_hash(owner, hash, depth, bit_width, storage).await?;
            let (new_child, new_child_hash) = child
                .remove(owner, writer, key, hash, depth + 1, expected, bit_width, max_collisions,
                    tid, storage, &child_hash)
                .await?;
            if new_child_hash == child_hash {
                return Ok((self.clone(), our_hash.clone()));
            }
            if new_child.contents.is_empty() {
                return Err(Error::Protocol("Sub-node must have at least one element".into()));
            }
            if new_child.node_count() == 0 && new_child.key_count() == max_collisions {
                if self.key_count() == 0 && self.node_count() == 1 {
                    // Escalate the singleton child as the new node.
                    return Ok((new_child, new_child_hash));
                }
                let champ = self.copy_and_migrate_from_node_to_inline(bitpos, &new_child);
                let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
                return Ok((champ, h));
            }
            let champ = self.overwrite_child_link(bitpos, new_child_hash);
            let h = put_block_signed(storage, owner, writer, champ.serialize(), tid).await?;
            return Ok((champ, h));
        }
        Ok((self.clone(), our_hash.clone()))
    }

    fn copy_and_set_value(&self, set_index: usize, payload_index: usize, val: Option<CborObject>) -> Champ {
        let mut dst = self.contents.clone();
        if let Payload::Mappings(ms) = &dst[set_index] {
            let mut updated = ms.clone();
            updated[payload_index].value = val;
            dst[set_index] = Payload::Mappings(updated);
        }
        self.with_contents(self.data_map.clone(), self.node_map.clone(), dst)
    }

    fn insert_into_prefix(&self, index: usize, key: &[u8], val: Option<CborObject>) -> Champ {
        let mut result = self.contents.clone();
        if let Payload::Mappings(ms) = &result[index] {
            let mut prefix = ms.clone();
            prefix.push(KeyElement { key: key.to_vec(), value: val });
            prefix.sort_by(|a, b| byte_array_compare(&a.key, &b.key));
            result[index] = Payload::Mappings(prefix);
        }
        self.with_contents(self.data_map.clone(), self.node_map.clone(), result)
    }

    fn add_new_prefix(&self, bitpos: usize, key: &[u8], val: Option<CborObject>) -> Champ {
        let insert_index = Champ::get_index(&self.data_map, bitpos);
        let mut result = self.contents.clone();
        result.insert(insert_index, Payload::Mappings(vec![KeyElement { key: key.to_vec(), value: val }]));
        let mut new_data_map = self.data_map.clone();
        bit_set(&mut new_data_map, bitpos);
        self.with_contents(new_data_map, self.node_map.clone(), result)
    }

    fn copy_and_migrate_from_inline_to_node(&self, bitpos: usize, node_hash: Cid) -> Champ {
        let old_index = Champ::get_index(&self.data_map, bitpos);
        let new_index = self.contents.len() - 1 - Champ::get_index(&self.node_map, bitpos);
        let mut dst = self.contents.clone();
        dst.remove(old_index);
        dst.insert(new_index, Payload::Link(node_hash));
        let mut new_node_map = self.node_map.clone();
        bit_set(&mut new_node_map, bitpos);
        let mut new_data_map = self.data_map.clone();
        bit_clear(&mut new_data_map, bitpos);
        self.with_contents(new_data_map, new_node_map, dst)
    }

    fn overwrite_child_link(&self, bitpos: usize, node_hash: Cid) -> Champ {
        let set_index = self.contents.len() - 1 - Champ::get_index(&self.node_map, bitpos);
        let mut dst = self.contents.clone();
        dst[set_index] = Payload::Link(node_hash);
        self.with_contents(self.data_map.clone(), self.node_map.clone(), dst)
    }

    #[allow(clippy::too_many_arguments)]
    async fn push_mappings_down_a_level(
        &self,
        owner: &PublicKeyHash,
        writer: &SigningPrivateKeyAndPublicHash,
        mappings: &[KeyElement],
        key1: &[u8],
        hash1: &[u8],
        val1: &Option<CborObject>,
        depth: usize,
        bit_width: usize,
        max_collisions: usize,
        key_hasher: &KeyHasher,
        tid: &TransactionId,
        storage: &dyn ContentAddressedStorage,
    ) -> Result<(Champ, Cid)> {
        if depth >= HASH_CODE_LENGTH {
            return Err(Error::Protocol("Hash collision!".into()));
        }
        let empty = Champ::empty().with_bat(self.mirror_bat.clone());
        let empty_hash = put_block_signed(storage, owner, writer, empty.serialize(), tid).await?;
        let (mut cur, mut cur_hash) = empty
            .put(owner, writer, key1, hash1, depth, &None, val1, bit_width, max_collisions,
                key_hasher, tid, storage, &empty_hash)
            .await?;
        for e in mappings {
            let e_hash = (key_hasher)(&e.key);
            let (c, h) = cur
                .put(owner, writer, &e.key, &e_hash, depth, &None, &e.value, bit_width,
                    max_collisions, key_hasher, tid, storage, &cur_hash)
                .await?;
            cur = c;
            cur_hash = h;
        }
        Ok((cur, cur_hash))
    }

    /// Total number of key/value mappings across the whole tree.
    #[async_recursion]
    pub async fn size(
        &self,
        owner: &PublicKeyHash,
        storage: &dyn ContentAddressedStorage,
    ) -> Result<u64> {
        let mut count = self.key_count() as u64;
        for payload in &self.contents {
            if let Payload::Link(cid) = payload {
                let cbor = storage
                    .get(owner, cid, None)
                    .await?
                    .ok_or_else(|| Error::Protocol(format!("champ child missing: {cid}")))?;
                count += Champ::from_cbor(&cbor)?.size(owner, storage).await?;
            }
        }
        Ok(count)
    }

    /// Set the mirror bat on this node (champ-level auth for mirroring).
    pub fn with_bat(mut self, bat: Option<BatId>) -> Champ {
        self.mirror_bat = bat;
        self
    }

    fn with_contents(&self, data_map: Vec<u8>, node_map: Vec<u8>, contents: Vec<Payload>) -> Champ {
        Champ { data_map, node_map, contents, mirror_bat: self.mirror_bat.clone() }
    }

    // ---- serialization -----------------------------------------------------

    pub fn from_cbor(cbor: &CborObject) -> Result<Champ> {
        // Map form carries a mirror BAT: {d: <list>, bats: [batId]}.
        if let CborObject::Map(_) = cbor {
            let mirror_bat = cbor
                .get("bats")
                .and_then(|c| c.as_list())
                .and_then(|l| l.first())
                .map(BatId::from_cbor)
                .transpose()?;
            let d = cbor
                .get("d")
                .ok_or_else(|| Error::Cbor("champ map missing 'd'".into()))?;
            let mut champ = Champ::from_cbor_list(d)?;
            champ.mirror_bat = mirror_bat;
            return Ok(champ);
        }
        Champ::from_cbor_list(cbor)
    }

    fn from_cbor_list(cbor: &CborObject) -> Result<Champ> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for CHAMP!".into()))?;
        if list.len() < 3 {
            return Err(Error::Cbor("champ list needs 3 elements".into()));
        }
        let data_map = list[0]
            .as_bytes()
            .ok_or_else(|| Error::Cbor("Invalid cbor for a champ, is this a btree?".into()))?
            .to_vec();
        let node_map = list[1]
            .as_bytes()
            .ok_or_else(|| Error::Cbor("champ nodeMap must be bytes".into()))?
            .to_vec();
        let contents_cbor = list[2]
            .as_list()
            .ok_or_else(|| Error::Cbor("champ contents must be a list".into()))?;

        let mut contents = Vec::with_capacity(contents_cbor.len());
        for element in contents_cbor {
            match element {
                CborObject::List(mappings_cbor) => {
                    if mappings_cbor.len() % 2 != 0 {
                        return Err(Error::Cbor(
                            "Invalid cbor for CHAMP mappings: odd number of elements".into(),
                        ));
                    }
                    let mut mappings = Vec::with_capacity(mappings_cbor.len() / 2);
                    for pair in mappings_cbor.chunks(2) {
                        let key = pair[0]
                            .as_bytes()
                            .ok_or_else(|| Error::Cbor("champ key must be bytes".into()))?
                            .to_vec();
                        let value = match &pair[1] {
                            CborObject::Null => None,
                            v => Some(v.clone()),
                        };
                        mappings.push(KeyElement { key, value });
                    }
                    contents.push(Payload::Mappings(mappings));
                }
                CborObject::MerkleLink(cid_bytes) => {
                    contents.push(Payload::Link(Cid::cast(cid_bytes)?));
                }
                other => {
                    return Err(Error::Cbor(format!("Invalid champ content element: {other:?}")))
                }
            }
        }
        Ok(Champ { data_map, node_map, contents, mirror_bat: None })
    }

    fn to_cbor_list(&self) -> CborObject {
        let contents = self
            .contents
            .iter()
            .map(|p| match p {
                Payload::Link(cid) => CborObject::MerkleLink(cid.to_bytes()),
                Payload::Mappings(mappings) => {
                    let mut flat = Vec::with_capacity(mappings.len() * 2);
                    for m in mappings {
                        flat.push(CborObject::ByteString(m.key.clone()));
                        flat.push(m.value.clone().unwrap_or(CborObject::Null));
                    }
                    CborObject::List(flat)
                }
            })
            .collect();
        CborObject::List(vec![
            CborObject::ByteString(self.data_map.clone()),
            CborObject::ByteString(self.node_map.clone()),
            CborObject::List(contents),
        ])
    }
}

impl Cborable for Champ {
    fn to_cbor(&self) -> CborObject {
        match &self.mirror_bat {
            Some(bat) => CborObject::map()
                .put("d", self.to_cbor_list())
                .put("bats", CborObject::List(vec![bat.to_cbor()]))
                .build(),
            None => self.to_cbor_list(),
        }
    }
}

/// A key hashing function; the read path via `getChampLookup` uses the identity
/// (keys are already hashed map-keys), so that is the default.
pub type KeyHasher = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

pub fn identity_key_hasher() -> KeyHasher {
    Arc::new(|k: &[u8]| k.to_vec())
}

/// A handle onto a champ rooted at a given hash, over a storage backend.
pub struct ChampWrapper {
    pub owner: PublicKeyHash,
    pub root: Champ,
    pub root_hash: Cid,
    storage: Arc<dyn ContentAddressedStorage>,
    key_hasher: KeyHasher,
}

impl ChampWrapper {
    /// Load the champ rooted at `root_hash` (the root fetch may use a BAT).
    pub async fn create(
        owner: PublicKeyHash,
        root_hash: Cid,
        bat: Option<&BatWithId>,
        storage: Arc<dyn ContentAddressedStorage>,
        key_hasher: KeyHasher,
    ) -> Result<ChampWrapper> {
        let raw = storage
            .get(&owner, &root_hash, bat)
            .await?
            .ok_or_else(|| Error::Protocol(format!("Champ root not present: {root_hash}")))?;
        Ok(ChampWrapper {
            owner,
            root: Champ::from_cbor(&raw)?,
            root_hash,
            storage,
            key_hasher,
        })
    }

    pub fn root_hash(&self) -> &Cid {
        &self.root_hash
    }

    /// Look up a raw key, returning its stored value cbor if present.
    pub async fn get(&self, raw_key: &[u8]) -> Result<Option<CborObject>> {
        let key_hash = (self.key_hasher)(raw_key);
        self.root
            .get(&self.owner, raw_key, &key_hash, 0, BIT_WIDTH, self.storage.as_ref())
            .await
    }

    /// Insert/update `raw_key`→`value` (CAS on `expected`), updating this
    /// wrapper's root in place and returning the new root CID.
    pub async fn put(
        &mut self,
        writer: &SigningPrivateKeyAndPublicHash,
        raw_key: &[u8],
        expected: &Option<CborObject>,
        value: Option<CborObject>,
        tid: &TransactionId,
    ) -> Result<Cid> {
        let key_hash = (self.key_hasher)(raw_key);
        let (new_root, new_root_hash) = self
            .root
            .put(
                &self.owner,
                writer,
                raw_key,
                &key_hash,
                0,
                expected,
                &value,
                BIT_WIDTH,
                MAX_HASH_COLLISIONS_PER_LEVEL,
                &self.key_hasher,
                tid,
                self.storage.as_ref(),
                &self.root_hash,
            )
            .await?;
        self.root = new_root;
        self.root_hash = new_root_hash.clone();
        Ok(new_root_hash)
    }

    /// Total number of key/value mappings in the entire champ tree.
    pub async fn size(&self) -> Result<u64> {
        self.root.size(&self.owner, self.storage.as_ref()).await
    }

    /// Remove `raw_key` (CAS on `expected`), updating this wrapper's root in place
    /// and returning the new root CID.
    pub async fn remove(
        &mut self,
        writer: &SigningPrivateKeyAndPublicHash,
        raw_key: &[u8],
        expected: &Option<CborObject>,
        tid: &TransactionId,
    ) -> Result<Cid> {
        let key_hash = (self.key_hasher)(raw_key);
        let (new_root, new_root_hash) = self
            .root
            .remove(
                &self.owner,
                writer,
                raw_key,
                &key_hash,
                0,
                expected,
                BIT_WIDTH,
                MAX_HASH_COLLISIONS_PER_LEVEL,
                tid,
                self.storage.as_ref(),
                &self.root_hash,
            )
            .await?;
        self.root = new_root;
        self.root_hash = new_root_hash.clone();
        Ok(new_root_hash)
    }
}
