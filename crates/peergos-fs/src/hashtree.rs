//! File content hash tree, ported from `HashTree`/`HashBranch`/`ChunkHashList`/
//! `RootHash`. Each chunk gets a 32-byte value ([`chunk_hash`]); the values are
//! grouped into `ChunkHashList`s (up to 1024 each) and combined up the levels to a
//! root. Legacy (5 MiB chunk) files hash each level with sha256; files at any other
//! chunk size use BLAKE3 chaining values and merges, so the root is the file's real
//! BLAKE3 hash. Every chunk's `FileProperties` carries the branch for its position.

use peergos_cbor::CborObject;
use peergos_core::error::{Error, Result};
use peergos_crypto::hash::{blake3, blake3_chaining_value, blake3_merge_as_root, blake3_merge_subtree, sha256, BLAKE3_CHUNK_LEN};

use crate::retrieve::uses_blake3;

/// `HashTree.chunkHash`: the value stored for one chunk. The whole file hash, a
/// resumed upload and a per-chunk comparison must all agree on this exactly.
/// Legacy files use the chunk's sha256. BLAKE3 files use the chunk's chaining value,
/// which depends on its position, except a single chunk file whose value is the root.
pub fn chunk_hash(data: &[u8], chunk_index: u64, chunk_size: u64, is_only_chunk: bool) -> Vec<u8> {
    if !uses_blake3(chunk_size) {
        return sha256(data);
    }
    if is_only_chunk {
        return blake3(data);
    }
    blake3_chaining_value(data, chunk_index * (chunk_size / BLAKE3_CHUNK_LEN))
}

/// The 32-byte root of a file's hash tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootHash {
    pub hash: Vec<u8>,
}

impl RootHash {
    pub fn to_cbor(&self) -> CborObject {
        CborObject::map().put("h", CborObject::ByteString(self.hash.clone())).build()
    }
    pub fn from_cbor(cbor: &CborObject) -> Result<RootHash> {
        let hash = cbor
            .get("h")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("RootHash missing 'h'".into()))?;
        if hash.len() != 32 {
            return Err(Error::Cbor(format!("Incorrect hash length: {}", hash.len())));
        }
        Ok(RootHash { hash: hash.to_vec() })
    }
}

/// A concatenation of up to 1024 32-byte chunk hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHashList {
    pub chunk_hashes: Vec<u8>,
}

impl ChunkHashList {
    pub fn to_cbor(&self) -> CborObject {
        CborObject::map().put("h", CborObject::ByteString(self.chunk_hashes.clone())).build()
    }
    pub fn from_cbor(cbor: &CborObject) -> Result<ChunkHashList> {
        let h = cbor
            .get("h")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("ChunkHashList missing 'h'".into()))?;
        Ok(ChunkHashList { chunk_hashes: h.to_vec() })
    }
    fn serialize(&self) -> Vec<u8> {
        self.to_cbor().to_bytes()
    }
    /// The 32 byte values in this blob, in order.
    pub fn hashes(&self) -> Vec<Vec<u8>> {
        self.chunk_hashes.chunks(32).map(|h| h.to_vec()).collect()
    }
}

/// A branch of the hash tree stored on a chunk's file properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashBranch {
    pub root_hash: RootHash,
    pub level1: Option<ChunkHashList>,
    pub level2: Option<ChunkHashList>,
    pub level3: Option<ChunkHashList>,
}

impl HashBranch {
    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("r", self.root_hash.to_cbor());
        if let Some(l) = &self.level1 {
            b = b.put("l1", l.to_cbor());
        }
        if let Some(l) = &self.level2 {
            b = b.put("l2", l.to_cbor());
        }
        if let Some(l) = &self.level3 {
            b = b.put("l3", l.to_cbor());
        }
        b.build()
    }
    pub fn from_cbor(cbor: &CborObject) -> Result<HashBranch> {
        Ok(HashBranch {
            root_hash: cbor
                .get("r")
                .ok_or_else(|| Error::Cbor("HashBranch missing 'r'".into()))
                .and_then(RootHash::from_cbor)?,
            level1: cbor.get("l1").map(ChunkHashList::from_cbor).transpose()?,
            level2: cbor.get("l2").map(ChunkHashList::from_cbor).transpose()?,
            level3: cbor.get("l3").map(ChunkHashList::from_cbor).transpose()?,
        })
    }
}

/// Group 32-byte hashes into `ChunkHashList`s of up to 1024 hashes.
fn build_level(hashes: &[Vec<u8>]) -> Vec<ChunkHashList> {
    let mut level = Vec::new();
    let mut i = 0;
    while i < hashes.len() {
        let n = 1024.min(hashes.len() - i);
        let mut bytes = Vec::with_capacity(n * 32);
        for c in 0..n {
            bytes.extend_from_slice(&hashes[i + c]);
        }
        level.push(ChunkHashList { chunk_hashes: bytes });
        i += 1024;
    }
    level
}

fn hash_level(level: &[ChunkHashList]) -> Vec<Vec<u8>> {
    level.iter().map(|l| sha256(&l.serialize())).collect()
}

fn merge_blobs(level: &[ChunkHashList]) -> Vec<Vec<u8>> {
    level.iter().map(|blob| blake3_merge_subtree(&blob.hashes())).collect()
}

fn list_root(level: &[ChunkHashList]) -> RootHash {
    let list = CborObject::List(level.iter().map(|c| c.to_cbor()).collect());
    RootHash { hash: sha256(&list.to_bytes()) }
}

/// A file's content hash tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashTree {
    pub root_hash: RootHash,
    pub level1: Vec<ChunkHashList>,
    pub level2: Vec<ChunkHashList>,
    pub level3: Vec<ChunkHashList>,
}

impl HashTree {
    /// Build the tree from per-chunk values from [`chunk_hash`] (`HashTree.build`).
    pub fn build(chunk_hashes: &[Vec<u8>], chunk_size: u64) -> Result<HashTree> {
        if chunk_hashes.is_empty() {
            return Err(Error::Protocol("A file cannot have no chunk hashes".into()));
        }
        if uses_blake3(chunk_size) {
            return Self::build_blake3(chunk_hashes);
        }
        let level1 = build_level(chunk_hashes);
        if level1.len() == 1 {
            let root_hash = list_root(&level1);
            return Ok(HashTree { root_hash, level1, level2: Vec::new(), level3: Vec::new() });
        }
        let level2 = build_level(&hash_level(&level1));
        if level2.len() == 1 {
            let root_hash = list_root(&level2);
            return Ok(HashTree { root_hash, level1, level2, level3: Vec::new() });
        }
        let level3 = build_level(&hash_level(&level2));
        if level3.len() == 1 {
            let root_hash = list_root(&level3);
            return Ok(HashTree { root_hash, level1, level2, level3 });
        }
        Err(Error::Protocol("Files bigger than 5 PiB are not supported".into()))
    }

    /// `HashTree.buildBlake3`: the same 1024 per blob storage, but levels above 1 are
    /// merges rather than hashes of a serialised blob. Blob j covers chunks
    /// [1024j, 1024j + 1024), an aligned power of two, so its merge is a genuine node
    /// of the file's BLAKE3 tree.
    fn build_blake3(chunk_cvs: &[Vec<u8>]) -> Result<HashTree> {
        let level1 = build_level(chunk_cvs);
        if chunk_cvs.len() == 1 {
            let root_hash = RootHash { hash: chunk_cvs[0].clone() };
            return Ok(HashTree { root_hash, level1, level2: Vec::new(), level3: Vec::new() });
        }
        if level1.len() == 1 {
            let root_hash = RootHash { hash: blake3_merge_as_root(chunk_cvs) };
            return Ok(HashTree { root_hash, level1, level2: Vec::new(), level3: Vec::new() });
        }
        let level2_cvs = merge_blobs(&level1);
        let level2 = build_level(&level2_cvs);
        if level2.len() == 1 {
            let root_hash = RootHash { hash: blake3_merge_as_root(&level2_cvs) };
            return Ok(HashTree { root_hash, level1, level2, level3: Vec::new() });
        }
        let level3_cvs = merge_blobs(&level2);
        let level3 = build_level(&level3_cvs);
        if level3.len() == 1 {
            let root_hash = RootHash { hash: blake3_merge_as_root(&level3_cvs) };
            return Ok(HashTree { root_hash, level1, level2, level3 });
        }
        Err(Error::Protocol("Files bigger than 4 EiB are not supported in HashTree!".into()))
    }

    pub fn to_cbor(&self) -> CborObject {
        let list = |l: &[ChunkHashList]| CborObject::List(l.iter().map(|c| c.to_cbor()).collect());
        CborObject::map()
            .put("r", self.root_hash.to_cbor())
            .put("ll1", list(&self.level1))
            .put("ll2", list(&self.level2))
            .put("ll3", list(&self.level3))
            .build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<HashTree> {
        let list = |k: &str| -> Result<Vec<ChunkHashList>> {
            match cbor.get(k) {
                Some(l) => l
                    .as_list()
                    .ok_or_else(|| Error::Cbor(format!("HashTree '{k}' is not a list")))?
                    .iter()
                    .map(ChunkHashList::from_cbor)
                    .collect(),
                None => Ok(Vec::new()),
            }
        };
        Ok(HashTree {
            root_hash: cbor
                .get("r")
                .ok_or_else(|| Error::Cbor("HashTree missing 'r'".into()))
                .and_then(RootHash::from_cbor)?,
            level1: list("ll1")?,
            level2: list("ll2")?,
            level3: list("ll3")?,
        })
    }

    /// The branch stored on the first chunk of each 1024-chunk group
    /// (`HashTree.branch`).
    pub fn branch(&self, chunk_index: u64) -> HashBranch {
        HashBranch {
            root_hash: self.root_hash.clone(),
            level1: self.level1.get((chunk_index / 1024) as usize).cloned(),
            level2: self.level2.get((chunk_index / 1024 / 1024) as usize).cloned(),
            level3: self.level3.get((chunk_index / 1024 / 1024 / 1024) as usize).cloned(),
        }
    }
}
