//! The write protocol that takes one signature per call rather than per block:
//! `bulk/commit` (a whole logical write in one request), `block/put/bulk/v2` and
//! `blockstore/auth/v2`. Ported from `BulkCommit`, `WriterCommit`,
//! `BlockWriteAuth` and `BlockWriteBatch`.

use crate::auth::BatId;
use crate::error::{Error, Result};
use crate::keys::PublicKeyHash;
use crate::mutable::SignedPointerUpdate;
use crate::storage::TransactionId;
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::hash::sha256;
use peergos_multiformats::Cid;

/// The most a single `bulk/commit` request body may be.
pub const MAX_BULK_COMMIT_SIZE: usize = 2 * 1024 * 1024;
/// The most blocks, inline or pre-written, a single `bulk/commit` may name.
pub const MAX_BULK_COMMIT_BLOCKS: usize = 1000;

fn byte_list(blocks: &[Vec<u8>]) -> CborObject {
    CborObject::List(blocks.iter().cloned().map(CborObject::ByteString).collect())
}

fn parse_byte_list(cbor: Option<&CborObject>, what: &str) -> Result<Vec<Vec<u8>>> {
    cbor.and_then(|c| c.as_list())
        .ok_or_else(|| Error::Cbor(format!("missing {what}")))?
        .iter()
        .map(|b| b.as_bytes().map(|b| b.to_vec()).ok_or_else(|| Error::Cbor(format!("bad {what}"))))
        .collect()
}

fn link_list(cids: &[Cid]) -> CborObject {
    CborObject::List(cids.iter().map(|c| CborObject::MerkleLink(c.to_bytes())).collect())
}

fn parse_link_list(cbor: Option<&CborObject>, what: &str) -> Result<Vec<Cid>> {
    cbor.and_then(|c| c.as_list())
        .ok_or_else(|| Error::Cbor(format!("missing {what}")))?
        .iter()
        .map(|c| Cid::cast(c.as_link().ok_or_else(|| Error::Cbor(format!("bad {what}")))?).map_err(Error::from))
        .collect()
}

/// All the writes of one writer within a [`BulkCommit`] (`WriterCommit`). Small
/// blocks travel inline; large raw blocks are written beforehand and only named.
/// The pointer update signs the new root, which authenticates every block in the
/// call; without one the writer signs the block list instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterCommit {
    pub writer: PublicKeyHash,
    pub cbor_blocks: Vec<Vec<u8>>,
    pub raw_blocks: Vec<Vec<u8>>,
    pub pre_written: Vec<Cid>,
    pub pointer: Option<SignedPointerUpdate>,
    pub block_list_signature: Option<Vec<u8>>,
}

impl WriterCommit {
    /// What a blocks-only commit signs: the ordered hashes of its blocks, bound to the
    /// pointer sequence the writer is heading for so the list can't be replayed.
    pub fn block_list_payload(blocks: &[Cid], next_sequence: Option<i64>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for b in blocks {
            bytes.extend_from_slice(&b.to_bytes());
        }
        bytes.extend_from_slice(&next_sequence.unwrap_or(0).to_be_bytes());
        sha256(&bytes)
    }

    pub fn inline_size(&self) -> usize {
        self.cbor_blocks.iter().chain(&self.raw_blocks).map(|b| b.len()).sum()
    }

    pub fn block_count(&self) -> usize {
        self.cbor_blocks.len() + self.raw_blocks.len()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<WriterCommit> {
        Ok(WriterCommit {
            writer: PublicKeyHash::from_cbor(cbor.get("w").ok_or_else(|| Error::Cbor("WriterCommit missing 'w'".into()))?)?,
            cbor_blocks: parse_byte_list(cbor.get("c"), "cbor blocks")?,
            raw_blocks: parse_byte_list(cbor.get("r"), "raw blocks")?,
            pre_written: parse_link_list(cbor.get("p"), "pre-written blocks")?,
            pointer: cbor.get("u").map(SignedPointerUpdate::from_cbor).transpose()?,
            block_list_signature: cbor.get("s").and_then(|c| c.as_bytes()).map(|b| b.to_vec()),
        })
    }
}

impl Cborable for WriterCommit {
    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map()
            .put("w", self.writer.to_cbor())
            .put("c", byte_list(&self.cbor_blocks))
            .put("r", byte_list(&self.raw_blocks))
            .put("p", link_list(&self.pre_written));
        if let Some(u) = &self.pointer {
            b = b.put("u", u.to_cbor());
        }
        if let Some(s) = &self.block_list_signature {
            b = b.put("s", CborObject::ByteString(s.clone()));
        }
        b.build()
    }
}

/// A single logical write for one owner: every block and pointer update in it,
/// applied atomically by the server (`BulkCommit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkCommit {
    /// An open transaction protecting blocks written ahead of the call.
    pub tid: Option<TransactionId>,
    pub writers: Vec<WriterCommit>,
}

impl BulkCommit {
    pub fn inline_size(&self) -> usize {
        self.writers.iter().map(|w| w.inline_size()).sum()
    }

    pub fn block_count(&self) -> usize {
        self.writers.iter().map(|w| w.block_count()).sum()
    }

    pub fn pre_written_count(&self) -> usize {
        self.writers.iter().map(|w| w.pre_written.len()).sum()
    }

    pub fn has_pointer_update(&self) -> bool {
        self.writers.iter().any(|w| w.pointer.is_some())
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<BulkCommit> {
        Ok(BulkCommit {
            tid: cbor.get("t").and_then(|c| c.as_string()).map(|s| TransactionId(s.to_string())),
            writers: cbor
                .get("w")
                .and_then(|c| c.as_list())
                .ok_or_else(|| Error::Cbor("BulkCommit missing 'w'".into()))?
                .iter()
                .map(WriterCommit::from_cbor)
                .collect::<Result<_>>()?,
        })
    }
}

impl Cborable for BulkCommit {
    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("w", CborObject::List(self.writers.iter().map(|w| w.to_cbor()).collect()));
        if let Some(t) = &self.tid {
            b = b.put("t", CborObject::Str(t.to_string()));
        }
        b.build()
    }
}

/// What a batch-signed write signs: the owner whose space is written to, then the
/// ordered hashes of the blocks (`BlockWriteAuth.payload`). The owner is bound in
/// because the owner decides where a block is stored.
pub fn block_write_payload(owner: &PublicKeyHash, hashes: &[Cid]) -> Vec<u8> {
    let mut bytes = owner.target.to_bytes();
    for h in hashes {
        bytes.extend_from_slice(&h.to_bytes());
    }
    sha256(&bytes)
}

/// A request to presign a batch of raw block writes under one signature
/// (`BlockWriteAuth`, for `blockstore/auth/v2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockWriteAuth {
    pub hashes: Vec<Cid>,
    pub sizes: Vec<i64>,
    pub bat_ids: Vec<Vec<BatId>>,
    pub signature: Vec<u8>,
}

impl Cborable for BlockWriteAuth {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("h", link_list(&self.hashes))
            .put("l", CborObject::List(self.sizes.iter().map(|s| CborObject::Long(*s)).collect()))
            .put(
                "b",
                CborObject::List(
                    self.bat_ids.iter().map(|ids| CborObject::List(ids.iter().map(|i| i.to_cbor()).collect())).collect(),
                ),
            )
            .put("s", CborObject::ByteString(self.signature.clone()))
            .build()
    }
}

/// A batch of blocks written under one signature (`BlockWriteBatch`, for
/// `block/put/bulk/v2`). The server recomputes the hashes from the blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockWriteBatch {
    pub blocks: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

impl BlockWriteBatch {
    pub fn from_cbor(cbor: &CborObject) -> Result<BlockWriteBatch> {
        Ok(BlockWriteBatch {
            blocks: parse_byte_list(cbor.get("b"), "blocks")?,
            signature: cbor
                .get("s")
                .and_then(|c| c.as_bytes())
                .ok_or_else(|| Error::Cbor("BlockWriteBatch missing 's'".into()))?
                .to_vec(),
        })
    }
}

impl Cborable for BlockWriteBatch {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("b", byte_list(&self.blocks))
            .put("s", CborObject::ByteString(self.signature.clone()))
            .build()
    }
}

/// Whether an error says the server has no such call, so a newer client can fall
/// back to the older endpoints (`Exceptions.isUnimplemented`). Only an unambiguous
/// "no such call" qualifies: anything else might mean the write happened.
pub fn is_unimplemented(e: &Error) -> bool {
    let msg = e.to_string().replace('+', " ");
    msg.contains("status 404") || msg.contains("Not Found") || msg.contains("Unimplemented call")
}

/// Whether an error is the server rejecting a pointer update's compare-and-swap.
pub fn is_pointer_cas_failure(e: &Error) -> bool {
    e.to_string().contains("PointerCAS:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::hash_to_cid;

    fn writer() -> PublicKeyHash {
        PublicKeyHash::identity(vec![1, 2, 3, 4]).unwrap()
    }

    #[test]
    fn bulk_commit_round_trips() {
        let commit = BulkCommit {
            tid: Some(TransactionId("42".into())),
            writers: vec![
                WriterCommit {
                    writer: writer(),
                    cbor_blocks: vec![CborObject::Long(7).to_bytes()],
                    raw_blocks: vec![vec![1, 2, 3]],
                    pre_written: vec![hash_to_cid(b"big", true).unwrap()],
                    pointer: Some(SignedPointerUpdate::new(writer(), vec![9; 70])),
                    block_list_signature: None,
                },
                WriterCommit {
                    writer: writer(),
                    cbor_blocks: vec![],
                    raw_blocks: vec![vec![4]],
                    pre_written: vec![],
                    pointer: None,
                    block_list_signature: Some(vec![5; 80]),
                },
            ],
        };
        let parsed = BulkCommit::from_cbor(&CborObject::from_bytes(&commit.serialize()).unwrap()).unwrap();
        assert_eq!(parsed, commit);
        assert_eq!(parsed.inline_size(), 5);
        assert_eq!(parsed.block_count(), 3);
        assert_eq!(parsed.pre_written_count(), 1);
        assert!(parsed.has_pointer_update());
        let none = BulkCommit { tid: None, writers: vec![] };
        assert!(none.to_cbor().get("t").is_none());
    }

    #[test]
    fn block_write_batch_round_trips() {
        let batch = BlockWriteBatch { blocks: vec![vec![1], vec![2, 3]], signature: vec![7; 72] };
        assert_eq!(BlockWriteBatch::from_cbor(&CborObject::from_bytes(&batch.serialize()).unwrap()).unwrap(), batch);
    }

    #[test]
    fn signed_payloads_bind_what_they_should() {
        let a = hash_to_cid(b"a", false).unwrap();
        let b = hash_to_cid(b"b", true).unwrap();
        let other = PublicKeyHash::identity(vec![9, 9, 9, 9]).unwrap();
        assert_ne!(block_write_payload(&writer(), &[a.clone(), b.clone()]), block_write_payload(&other, &[a.clone(), b.clone()]));
        assert_ne!(block_write_payload(&writer(), &[a.clone(), b.clone()]), block_write_payload(&writer(), &[b.clone(), a.clone()]));
        assert_ne!(WriterCommit::block_list_payload(&[a.clone()], Some(1)), WriterCommit::block_list_payload(&[a], Some(2)));
    }

    #[test]
    fn unimplemented_and_cas_errors_are_recognised() {
        assert!(is_unimplemented(&Error::Http("status 404: no route".into())));
        assert!(is_unimplemented(&Error::Protocol("Unimplemented call!".into())));
        assert!(!is_unimplemented(&Error::Http("status 500: boom".into())));
        assert!(is_pointer_cas_failure(&Error::Http("status 500: PointerCAS:x,1,y".into())));
    }
}
