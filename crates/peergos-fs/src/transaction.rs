//! File-upload transactions, ported from `peergos.shared.user.fs.transaction`.
//!
//! Before a file upload begins, a [`FileUploadTransaction`] record (holding the
//! upload's keys, stream secret, first-chunk location, properties and size) is
//! written into the user's `.transactions` directory. Chunks are then committed
//! incrementally; on success the record is removed. If the upload is interrupted
//! the record survives, so the partial upload can be listed, cleaned up, or
//! resumed later (the record has everything needed to recompute chunk locations).

use crate::cryptree::FileProperties;
use peergos_cbor::{CborObject, Cborable, CborString};
use peergos_core::auth::Bat;
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use peergos_core::storage::hash_to_cid;
use peergos_core::symmetric::SymmetricKey;
use std::collections::BTreeMap;

/// The record describing an in-progress file upload (`FileUploadTransaction`).
#[derive(Debug, Clone)]
pub struct FileUploadTransaction {
    pub start_time_ms: i64,
    /// The path of the file being uploaded (its identity).
    pub path: String,
    /// The transaction filename in `.transactions` = `hash(path)`.
    pub name: String,
    pub owner: PublicKeyHash,
    /// The writer signing key (secret included, so a resume can write).
    pub writer: SigningPrivateKeyAndPublicHash,
    /// The map key + BAT of the file's first chunk.
    pub first_map_key: Vec<u8>,
    pub first_bat: Option<Bat>,
    pub props: FileProperties,
    pub base_key: SymmetricKey,
    pub data_key: SymmetricKey,
    pub write_key: SymmetricKey,
    pub stream_secret: Vec<u8>,
    pub size: u64,
}

impl FileUploadTransaction {
    /// The transaction filename for an upload path (`hash(path)`, raw sha256 CID).
    pub fn name_for_path(path: &str) -> Result<String> {
        Ok(hash_to_cid(path.as_bytes(), true)?.to_string())
    }

    /// The number of chunks (`ceil(size / CHUNK_MAX_SIZE)`, at least one).
    pub fn chunk_count(&self) -> u64 {
        self.size.div_ceil(crate::retrieve::CHUNK_MAX_SIZE).max(1)
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut m = BTreeMap::new();
        let mut put = |k: &str, v: CborObject| {
            m.insert(CborString::new(k), v);
        };
        put("type", CborObject::Str("FILE_UPLOAD".into()));
        put("path", CborObject::Str(self.path.clone()));
        put("startTimeEpochMs", CborObject::Long(self.start_time_ms));
        put("owner", self.owner.to_cbor());
        put("writer", self.writer.to_cbor());
        put("baseKey", self.base_key.to_cbor());
        put("dataKey", self.data_key.to_cbor());
        put("writeKey", self.write_key.to_cbor());
        put("props", self.props.to_cbor());
        if let Some(b) = &self.first_bat {
            put("firstBat", b.to_cbor());
        }
        put("mapKey", CborObject::ByteString(self.first_map_key.clone()));
        put("streamSecret", CborObject::ByteString(self.stream_secret.clone()));
        put("size", CborObject::Long(self.size as i64));
        CborObject::Map(m)
    }

    pub fn from_cbor(cbor: &CborObject, name: &str) -> Result<FileUploadTransaction> {
        let g = |k: &str| cbor.get(k).ok_or_else(|| Error::Cbor(format!("transaction missing '{k}'")));
        let props = FileProperties::from_cbor(g("props")?)?;
        Ok(FileUploadTransaction {
            start_time_ms: g("startTimeEpochMs")?.as_long().ok_or_else(|| Error::Cbor("bad startTime".into()))?,
            path: g("path")?.as_string().ok_or_else(|| Error::Cbor("bad path".into()))?.to_string(),
            name: name.to_string(),
            owner: PublicKeyHash::from_cbor(g("owner")?)?,
            writer: SigningPrivateKeyAndPublicHash::from_cbor(g("writer")?)?,
            first_map_key: g("mapKey")?.as_bytes().ok_or_else(|| Error::Cbor("bad mapKey".into()))?.to_vec(),
            first_bat: cbor.get("firstBat").map(Bat::from_cbor).transpose()?,
            props,
            base_key: SymmetricKey::from_cbor(g("baseKey")?)?,
            data_key: SymmetricKey::from_cbor(g("dataKey")?)?,
            write_key: SymmetricKey::from_cbor(g("writeKey")?)?,
            stream_secret: g("streamSecret")?.as_bytes().ok_or_else(|| Error::Cbor("bad streamSecret".into()))?.to_vec(),
            size: g("size")?.as_long().ok_or_else(|| Error::Cbor("bad size".into()))? as u64,
        })
    }
}
