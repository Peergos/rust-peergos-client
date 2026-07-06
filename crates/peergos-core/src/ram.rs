//! An in-memory content-addressed store (`LocalRamStorage`), useful for tests
//! and for buffering blocks. Signatures and BATs are ignored (local trust).

use crate::auth::BatWithId;
use crate::error::{Error, Result};
use crate::keys::PublicKeyHash;
use crate::storage::{build_cid, ContentAddressedStorage, TransactionId};
use async_trait::async_trait;
use peergos_cbor::CborObject;
use peergos_multiformats::{Cid, Multihash};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct RamStorage {
    blocks: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl RamStorage {
    pub fn new() -> RamStorage {
        RamStorage::default()
    }

    fn store(&self, blocks: Vec<Vec<u8>>, is_raw: bool) -> Result<Vec<Cid>> {
        let mut map = self.blocks.lock().unwrap();
        let mut out = Vec::with_capacity(blocks.len());
        for block in blocks {
            let cid = build_cid(peergos_crypto::hash::sha256(&block), is_raw)?;
            map.insert(cid.to_bytes(), block);
            out.push(cid);
        }
        Ok(out)
    }

    /// Load externally-supplied blocks (e.g. a `champ/get/bulk` response),
    /// indexing each under both its dag-cbor and raw CID. The CID is recomputed
    /// from the bytes here, so a corrupted or substituted block gets a CID that
    /// won't match any champ link and simply won't be found — this is how a
    /// server champ-lookup response is verified locally.
    pub fn load_verified(&self, blocks: Vec<Vec<u8>>) -> Result<()> {
        for block in blocks {
            self.store(vec![block.clone()], false)?;
            self.store(vec![block], true)?;
        }
        Ok(())
    }

    fn fetch(&self, hash: &Cid) -> Option<Vec<u8>> {
        if hash.multihash.is_identity() {
            return Some(hash.get_hash().to_vec());
        }
        self.blocks.lock().unwrap().get(&hash.to_bytes()).cloned()
    }
}

#[async_trait]
impl ContentAddressedStorage for RamStorage {
    async fn id(&self) -> Result<Cid> {
        build_cid(vec![0u8; 32], false)
    }
    async fn ids(&self) -> Result<Vec<Cid>> {
        Ok(vec![self.id().await?])
    }
    async fn start_transaction(&self, _owner: &PublicKeyHash) -> Result<TransactionId> {
        Ok(TransactionId("0".into()))
    }
    async fn close_transaction(&self, _owner: &PublicKeyHash, _tid: &TransactionId) -> Result<bool> {
        Ok(true)
    }
    async fn get(&self, _owner: &PublicKeyHash, hash: &Cid, _bat: Option<&BatWithId>) -> Result<Option<CborObject>> {
        match self.fetch(hash) {
            Some(raw) => Ok(Some(CborObject::from_bytes(&raw)?)),
            None => Ok(None),
        }
    }
    async fn get_raw(&self, _owner: &PublicKeyHash, hash: &Cid, _bat: Option<&BatWithId>) -> Result<Option<Vec<u8>>> {
        Ok(self.fetch(hash))
    }
    async fn put(
        &self,
        _owner: &PublicKeyHash,
        _writer: &PublicKeyHash,
        _signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        _tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.store(blocks, false)
    }
    async fn put_raw(
        &self,
        _owner: &PublicKeyHash,
        _writer: &PublicKeyHash,
        _signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        _tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        self.store(blocks, true)
    }
    async fn get_size(&self, _owner: &PublicKeyHash, block: &Multihash) -> Result<Option<u64>> {
        Ok(self
            .blocks
            .lock()
            .unwrap()
            .get(&Cid::build_v1(peergos_multiformats::Codec::DagCbor, block.hash_type, block.get_hash().to_vec())?.to_bytes())
            .map(|b| b.len() as u64))
    }
    async fn get_secret_link(&self, _owner: &PublicKeyHash, _label: &str) -> Result<CborObject> {
        Err(Error::Protocol("RamStorage has no secret links".into()))
    }
}
