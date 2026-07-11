//! The cryptree: encrypted file/directory metadata nodes, ported from
//! `peergos.shared.user.fs.cryptree.CryptreeNode` and friends.
//!
//! A `CryptreeNode` holds three encrypted blocks: `fromBaseKey` (the base block:
//! parent/data key, writer link, next-chunk link), `fromParentKey` (the parent
//! block: parent link + [`FileProperties`]), and `childrenOrData` (directory
//! children, or file data — parsed in the retrieval increment).

use crate::capability::AbsoluteCapability;
use crate::hashtree::HashBranch;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::auth::Bat;
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicKeyHash, SigningPrivateKeyAndPublicHash};
use peergos_core::symmetric::{CipherText, SymmetricKey};

const CURRENT_VERSION: i64 = 1;
pub const BASE_BLOCK_PADDING_BLOCKSIZE: usize = 64;
pub const META_DATA_PADDING_BLOCKSIZE: usize = 16;

/// `PaddedCipherText` — a `CipherText` whose plaintext was zero-padded before
/// encryption. Decryption tolerates the trailing padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddedCipherText {
    pub cipher_text: CipherText,
}

impl PaddedCipherText {
    pub fn from_cbor(cbor: &CborObject) -> Result<PaddedCipherText> {
        Ok(PaddedCipherText { cipher_text: CipherText::from_cbor(cbor)? })
    }

    pub fn decrypt<T>(
        &self,
        key: &SymmetricKey,
        from_cbor: impl FnOnce(&CborObject) -> Result<T>,
    ) -> Result<T> {
        self.cipher_text.decrypt(key, from_cbor)
    }

    pub fn to_cbor(&self) -> CborObject {
        self.cipher_text.to_cbor()
    }

    /// `PaddedCipherText.build`: zero-pad the serialized secret to a multiple of
    /// `padding_block_size`, then encrypt.
    pub fn build(
        key: &SymmetricKey,
        secret: &CborObject,
        padding_block_size: usize,
    ) -> Result<PaddedCipherText> {
        let nonce = SymmetricKey::create_nonce();
        let plain = secret.to_bytes();
        let n_blocks = plain.len().div_ceil(padding_block_size);
        let mut padded = plain;
        padded.resize(n_blocks * padding_block_size, 0);
        let cipher = key.encrypt(&padded, &nonce)?;
        Ok(PaddedCipherText { cipher_text: CipherText::new(nonce, cipher) })
    }
}

/// A relative capability (`RelativeCapability`); for the read path we keep the
/// writer/mapKey/bat/rBaseKey, and the write-key link as opaque cbor.
#[derive(Debug, Clone, PartialEq)]
pub struct RelativeCapability {
    pub writer: Option<PublicKeyHash>,
    pub map_key: Vec<u8>,
    pub bat: Option<Bat>,
    pub r_base_key: SymmetricKey,
    pub w_base_key_link: Option<CborObject>,
}

impl RelativeCapability {
    pub fn from_cbor(cbor: &CborObject) -> Result<RelativeCapability> {
        let writer = cbor.get("w").map(PublicKeyHash::from_cbor).transpose()?;
        let map_key = cbor
            .get("m")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("RelativeCapability missing 'm'".into()))?
            .to_vec();
        let bat = cbor.get("a").map(Bat::from_cbor).transpose()?;
        let r_base_key = cbor
            .get("k")
            .ok_or_else(|| Error::Cbor("RelativeCapability missing 'k'".into()))
            .and_then(SymmetricKey::from_cbor)?;
        let w_base_key_link = cbor.get("l").cloned();
        Ok(RelativeCapability { writer, map_key, bat, r_base_key, w_base_key_link })
    }

    /// A relative capability to a subsequent chunk (`buildSubsequentChunk`).
    pub fn subsequent_chunk(map_key: Vec<u8>, bat: Option<Bat>, base_key: SymmetricKey) -> RelativeCapability {
        RelativeCapability { writer: None, map_key, bat, r_base_key: base_key, w_base_key_link: None }
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map();
        if let Some(w) = &self.writer {
            b = b.put("w", w.to_cbor());
        }
        b = b.put("m", CborObject::ByteString(self.map_key.clone()));
        if let Some(bat) = &self.bat {
            b = b.put("a", bat.to_cbor());
        }
        b = b.put("k", self.r_base_key.to_cbor());
        if let Some(l) = &self.w_base_key_link {
            b = b.put("l", l.clone());
        }
        b.build()
    }

    /// Resolve to an absolute capability against a source cap (`toAbsolute`).
    /// Write access is propagated when the source is writable and this link
    /// carries a write-base-key link (`SymmetricLink`).
    pub fn to_absolute(&self, source: &AbsoluteCapability) -> Result<AbsoluteCapability> {
        let writer = self.writer.clone().unwrap_or_else(|| source.writer.clone());
        let w_base_key = match (&source.w_base_key, &self.w_base_key_link) {
            (Some(src_w), Some(link)) => {
                Some(CipherText::from_cbor(link)?.decrypt(src_w, SymmetricKey::from_cbor)?)
            }
            _ => None,
        };
        AbsoluteCapability::new(
            source.owner.clone(),
            writer,
            self.map_key.clone(),
            self.bat.clone(),
            self.r_base_key.clone(),
            w_base_key,
        )
    }
}

/// A named child capability within a directory (`NamedRelativeCapability`).
#[derive(Debug, Clone, PartialEq)]
pub struct NamedRelativeCapability {
    pub name: String,
    pub cap: RelativeCapability,
    pub is_dir: Option<bool>,
    pub mime_type: Option<String>,
    pub created_epoch: Option<i64>,
}

impl NamedRelativeCapability {
    pub fn from_cbor(cbor: &CborObject) -> Result<NamedRelativeCapability> {
        let name = cbor
            .get("n")
            .and_then(|c| c.as_string())
            .ok_or_else(|| Error::Cbor("NamedRelativeCapability missing name".into()))?
            .to_string();
        Ok(NamedRelativeCapability {
            name,
            cap: RelativeCapability::from_cbor(cbor)?,
            is_dir: cbor.get("d").and_then(|c| c.as_bool()),
            mime_type: cbor.get("t").and_then(|c| c.as_string()).map(|s| s.to_string()),
            created_epoch: cbor.get("c").and_then(|c| c.as_long()),
        })
    }

    pub fn to_cbor(&self) -> CborObject {
        // Shares the relative-capability map, adding n/d/t/c (no key clashes).
        let mut cbor = self.cap.to_cbor();
        if let CborObject::Map(m) = &mut cbor {
            m.insert(peergos_cbor::CborString::new("n"), CborObject::Str(self.name.clone()));
            if let Some(d) = self.is_dir {
                m.insert(peergos_cbor::CborString::new("d"), CborObject::Boolean(d));
            }
            if let Some(t) = &self.mime_type {
                m.insert(peergos_cbor::CborString::new("t"), CborObject::Str(t.clone()));
            }
            if let Some(c) = self.created_epoch {
                m.insert(peergos_cbor::CborString::new("c"), CborObject::Long(c));
            }
        }
        cbor
    }
}

/// A directory's children links (`CryptreeNode.ChildrenLinks`). Modern data uses
/// named links; legacy data has bare relative capabilities.
#[derive(Debug, Clone, PartialEq)]
pub enum ChildrenLinks {
    Named(Vec<NamedRelativeCapability>),
    Legacy(Vec<RelativeCapability>),
}

impl ChildrenLinks {
    pub fn to_cbor(&self) -> CborObject {
        match self {
            ChildrenLinks::Named(v) => CborObject::List(v.iter().map(|n| n.to_cbor()).collect()),
            ChildrenLinks::Legacy(v) => CborObject::List(v.iter().map(|r| r.to_cbor()).collect()),
        }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<ChildrenLinks> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Incorrect cbor for ChildrenLinks".into()))?;
        if list.is_empty() {
            return Ok(ChildrenLinks::Named(Vec::new()));
        }
        // Named links carry an "n" key; legacy ones don't.
        let is_named = list[0].get("n").is_some();
        if is_named {
            Ok(ChildrenLinks::Named(
                list.iter().map(NamedRelativeCapability::from_cbor).collect::<Result<_>>()?,
            ))
        } else {
            Ok(ChildrenLinks::Legacy(
                list.iter().map(RelativeCapability::from_cbor).collect::<Result<_>>()?,
            ))
        }
    }
}

/// File/directory metadata (`FileProperties`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProperties {
    pub name: String,
    pub is_directory: bool,
    pub is_link: bool,
    pub mime_type: String,
    pub size: u64,
    pub is_hidden: bool,
    pub modified_epoch: i64,
    pub created_epoch: i64,
    /// Present for files with multiple chunks; drives next-chunk map-key derivation.
    pub stream_secret: Option<Vec<u8>>,
    /// Optional thumbnail: (mime type, bytes).
    pub thumbnail: Option<(String, Vec<u8>)>,
    /// Content hash-tree branch for this chunk's position.
    pub tree_hash: Option<HashBranch>,
}

impl FileProperties {
    pub fn from_cbor(cbor: &CborObject) -> Result<FileProperties> {
        let get_bool = |k: &str| cbor.get(k).and_then(|c| c.as_bool());
        let name = cbor
            .get("n")
            .and_then(|c| c.as_string())
            .ok_or_else(|| Error::Cbor("FileProperties missing name".into()))?
            .to_string();
        let mime_type = cbor
            .get("m")
            .and_then(|c| c.as_string())
            .unwrap_or("")
            .to_string();
        let size = cbor.get("s").and_then(|c| c.as_long()).unwrap_or(0) as u64;
        let modified_epoch = cbor.get("t").and_then(|c| c.as_long()).unwrap_or(0);
        Ok(FileProperties {
            name,
            is_directory: get_bool("d").unwrap_or(false),
            is_link: get_bool("l").unwrap_or(false),
            mime_type,
            size,
            is_hidden: get_bool("h").unwrap_or(false),
            modified_epoch,
            created_epoch: cbor.get("c").and_then(|c| c.as_long()).unwrap_or(modified_epoch),
            stream_secret: cbor.get("p").and_then(|c| c.as_bytes()).map(|b| b.to_vec()),
            thumbnail: cbor.get("i").and_then(|c| c.as_bytes()).map(|d| {
                // Thumbnails are always WebP; default accordingly if the mime is absent.
                let mime = cbor.get("im").and_then(|c| c.as_string()).unwrap_or("image/webp");
                (mime.to_string(), d.to_vec())
            }),
            tree_hash: cbor.get("th").map(HashBranch::from_cbor).transpose()?,
        })
    }

    /// Build properties for a newly-created file.
    pub fn new_file(
        name: String,
        mime_type: String,
        size: u64,
        epoch: i64,
        stream_secret: Vec<u8>,
        thumbnail: Option<(String, Vec<u8>)>,
    ) -> FileProperties {
        FileProperties {
            name,
            is_directory: false,
            is_link: false,
            mime_type,
            size,
            is_hidden: false,
            modified_epoch: epoch,
            created_epoch: epoch,
            stream_secret: Some(stream_secret),
            thumbnail,
            tree_hash: None,
        }
    }

    /// `FileProperties.EMPTY` — placeholder props for a subsequent dir chunk.
    pub fn empty_subsequent_chunk() -> FileProperties {
        FileProperties {
            name: ".subsequent-dir-chunk".to_string(),
            is_directory: true,
            is_link: false,
            mime_type: String::new(),
            size: 0,
            is_hidden: false,
            modified_epoch: 0,
            created_epoch: 0,
            stream_secret: None,
            thumbnail: None,
            tree_hash: None,
        }
    }

    /// Build properties for a newly-created directory.
    pub fn new_directory(name: String, epoch: i64) -> FileProperties {
        FileProperties {
            name,
            is_directory: true,
            is_link: false,
            mime_type: String::new(),
            size: 0,
            is_hidden: false,
            modified_epoch: epoch,
            created_epoch: epoch,
            stream_secret: None,
            thumbnail: None,
            tree_hash: None,
        }
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map()
            .put("d", CborObject::Boolean(self.is_directory))
            .put("l", CborObject::Boolean(self.is_link))
            .put("n", CborObject::Str(self.name.clone()))
            .put("m", CborObject::Str(self.mime_type.clone()))
            .put("s", CborObject::Long(self.size as i64))
            .put("t", CborObject::Long(self.modified_epoch))
            .put("tn", CborObject::Long(0))
            .put("c", CborObject::Long(self.created_epoch))
            .put("cn", CborObject::Long(0))
            .put("h", CborObject::Boolean(self.is_hidden));
        if let Some(branch) = &self.tree_hash {
            b = b.put("th", branch.to_cbor());
        }
        if let Some((mime, data)) = &self.thumbnail {
            b = b
                .put("i", CborObject::ByteString(data.clone()))
                .put("im", CborObject::Str(mime.clone()));
        }
        if let Some(secret) = &self.stream_secret {
            b = b.put("p", CborObject::ByteString(secret.clone()));
        }
        b.build()
    }
}

/// The base block, decrypted with the read-base key.
#[derive(Debug, Clone)]
pub struct FromBase {
    /// For a file, the data key; for a directory, the parent key.
    pub parent_or_data: SymmetricKey,
    pub signer: Option<CborObject>,
    pub next_chunk: RelativeCapability,
}

impl FromBase {
    fn from_cbor(cbor: &CborObject) -> Result<FromBase> {
        let parent_or_data = cbor
            .get("k")
            .ok_or_else(|| Error::Cbor("FromBase missing 'k'".into()))
            .and_then(SymmetricKey::from_cbor)?;
        let signer = cbor.get("w").cloned();
        let next_chunk = cbor
            .get("n")
            .ok_or_else(|| Error::Cbor("FromBase missing 'n'".into()))
            .and_then(RelativeCapability::from_cbor)?;
        Ok(FromBase { parent_or_data, signer, next_chunk })
    }
}

/// The parent block, decrypted with the parent key.
#[derive(Debug, Clone)]
pub struct FromParent {
    pub parent_link: Option<RelativeCapability>,
    pub properties: FileProperties,
}

impl FromParent {
    fn from_cbor(cbor: &CborObject) -> Result<FromParent> {
        let parent_link = cbor.get("p").map(RelativeCapability::from_cbor).transpose()?;
        let properties = cbor
            .get("s")
            .ok_or_else(|| Error::Cbor("FromParent missing 's'".into()))
            .and_then(FileProperties::from_cbor)?;
        Ok(FromParent { parent_link, properties })
    }
}

/// An encrypted file or directory metadata node.
#[derive(Debug, Clone)]
pub struct CryptreeNode {
    pub is_directory: bool,
    pub bats: Vec<CborObject>,
    pub from_base_key: PaddedCipherText,
    pub from_parent_key: PaddedCipherText,
    /// Directory children or file data — kept raw until the retrieval increment.
    pub children_or_data: CborObject,
}

impl CryptreeNode {
    /// Parse a cryptree node. `base` is the capability's read-base key, used to
    /// determine whether this is a directory (Java `CryptreeNode.fromCbor`).
    pub fn from_cbor(cbor: &CborObject, base: &SymmetricKey) -> Result<CryptreeNode> {
        let version = cbor
            .get("v")
            .and_then(|c| c.as_long())
            .ok_or_else(|| Error::Cbor("CryptreeNode missing version".into()))?;
        if version != CURRENT_VERSION {
            return Err(Error::Protocol(format!("Unknown cryptree version: {version}")));
        }
        let bats = cbor
            .get("bats")
            .and_then(|c| c.as_list())
            .map(|l| l.to_vec())
            .unwrap_or_default();
        let from_base_key = cbor
            .get("b")
            .ok_or_else(|| Error::Cbor("CryptreeNode missing 'b'".into()))
            .and_then(PaddedCipherText::from_cbor)?;
        let from_parent_key = cbor
            .get("p")
            .ok_or_else(|| Error::Cbor("CryptreeNode missing 'p'".into()))
            .and_then(PaddedCipherText::from_cbor)?;
        let children_or_data = cbor
            .get("d")
            .cloned()
            .ok_or_else(|| Error::Cbor("CryptreeNode missing 'd'".into()))?;

        // For a file the base key IS the parent key, so the parent block
        // decrypts; if it doesn't, this is a directory.
        let is_directory = match from_parent_key.decrypt(base, FromParent::from_cbor) {
            Ok(fp) => fp.properties.is_directory,
            Err(_) => true,
        };

        Ok(CryptreeNode { is_directory, bats, from_base_key, from_parent_key, children_or_data })
    }

    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    fn get_base_block(&self, base_key: &SymmetricKey) -> Result<FromBase> {
        self.from_base_key.decrypt(base_key, FromBase::from_cbor)
    }

    fn get_parent_block(&self, parent_key: &SymmetricKey) -> Result<FromParent> {
        self.from_parent_key.decrypt(parent_key, FromParent::from_cbor)
    }

    /// The key that decrypts the parent block (`getParentKey`).
    pub fn get_parent_key(&self, base_key: &SymmetricKey) -> SymmetricKey {
        if self.is_directory {
            if let Ok(base) = self.get_base_block(base_key) {
                return base.parent_or_data;
            }
        }
        base_key.clone()
    }

    /// The key that decrypts the file data (`getDataKey`); files only.
    pub fn get_data_key(&self, base_key: &SymmetricKey) -> Result<SymmetricKey> {
        if self.is_directory {
            return Err(Error::Protocol("Directories don't have a data key!".into()));
        }
        Ok(self.get_base_block(base_key)?.parent_or_data)
    }

    /// Decrypt the file/directory properties (`getProperties`).
    pub fn get_properties(&self, base_key: &SymmetricKey) -> Result<FileProperties> {
        let parent_key = self.get_parent_key(base_key);
        Ok(self.get_parent_block(&parent_key)?.properties)
    }

    /// The location (map-key, BAT) of the next chunk, from this node's base
    /// block — used by directories (files use the stream secret instead).
    pub fn next_chunk_from_base(&self, base_key: &SymmetricKey) -> Result<(Vec<u8>, Option<Bat>)> {
        let base = self.get_base_block(base_key)?;
        Ok((base.next_chunk.map_key.clone(), base.next_chunk.bat.clone()))
    }

    /// The full base block, for callers that need the parent key or next chunk.
    pub fn base_block(&self, base_key: &SymmetricKey) -> Result<FromBase> {
        self.get_base_block(base_key)
    }

    /// This directory's link to its parent (`getParentCapability`).
    pub fn parent_link(&self, base_key: &SymmetricKey) -> Result<Option<RelativeCapability>> {
        let parent_key = self.get_parent_key(base_key);
        Ok(self.get_parent_block(&parent_key)?.parent_link)
    }

    /// Recover the writer's signing keypair from this node's writer link
    /// (`getSigner`): decrypt the base block's `SymmetricLinkToSigner` with the
    /// write-base key.
    pub fn get_signer(
        &self,
        r_base_key: &SymmetricKey,
        w_base_key: &SymmetricKey,
    ) -> Result<SigningPrivateKeyAndPublicHash> {
        let base = self.get_base_block(r_base_key)?;
        let signer_cbor = base
            .signer
            .ok_or_else(|| Error::Protocol("No link to private signing key on this node".into()))?;
        CipherText::from_cbor(&signer_cbor)?
            .decrypt(w_base_key, SigningPrivateKeyAndPublicHash::from_cbor)
    }

    /// Construct a node directly from its encrypted parts.
    pub fn new(
        is_directory: bool,
        bats: Vec<CborObject>,
        from_base_key: PaddedCipherText,
        from_parent_key: PaddedCipherText,
        children_or_data: CborObject,
    ) -> CryptreeNode {
        CryptreeNode { is_directory, bats, from_base_key, from_parent_key, children_or_data }
    }

    /// A copy of this node with new FileProperties (no data change).
    /// Only the parent block is re-encrypted; the base block and children-or-data
    /// are preserved byte-for-byte — matching Java's `updateProperties`.
    pub fn update_properties(
        &self,
        base_key: &SymmetricKey,
        new_props: FileProperties,
    ) -> Result<CryptreeNode> {
        let parent_key = self.get_parent_key(base_key);
        let parent_link = self.parent_link(base_key)?;
        let from_parent = CborObject::map()
            .put_opt("p", parent_link.as_ref().map(|p| p.to_cbor()))
            .put("s", new_props.to_cbor())
            .build();
        Ok(CryptreeNode {
            from_parent_key: PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
            ..self.clone()
        })
    }

    /// A copy of this node with new children/data (keeping the encrypted base and
    /// parent blocks) — used when adding a child to a directory.
    pub fn with_children_or_data(&self, children_or_data: CborObject) -> CryptreeNode {
        CryptreeNode { children_or_data, ..self.clone() }
    }

    /// A copy of this **file** chunk with new data, rebuilt so its content hash-tree
    /// branch is cleared and its modified time is bumped — matching Java's
    /// `overwriteSection` ("remove hash from properties as we are changing the
    /// file"). The encrypted base block (data key, writer link, next-chunk pointer)
    /// is preserved byte-for-byte; only the parent block (properties) and data change.
    pub fn overwrite_chunk_data(
        &self,
        base_key: &SymmetricKey,
        new_data: CborObject,
        modified_epoch: i64,
    ) -> Result<CryptreeNode> {
        let parent_key = self.get_parent_key(base_key);
        let parent_link = self.parent_link(base_key)?;
        let mut props = self.get_properties(base_key)?;
        props.tree_hash = None;
        props.modified_epoch = modified_epoch;
        let from_parent = CborObject::map()
            .put_opt("p", parent_link.as_ref().map(|p| p.to_cbor()))
            .put("s", props.to_cbor())
            .build();
        Ok(CryptreeNode {
            is_directory: false,
            bats: self.bats.clone(),
            from_base_key: self.from_base_key.clone(),
            from_parent_key: PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
            children_or_data: new_data,
        })
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("v", CborObject::Long(CURRENT_VERSION));
        if !self.bats.is_empty() {
            b = b.put("bats", CborObject::List(self.bats.clone()));
        }
        b.put("b", self.from_base_key.to_cbor())
            .put("p", self.from_parent_key.to_cbor())
            .put("d", self.children_or_data.clone())
            .build()
    }
}
