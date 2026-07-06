//! Capabilities and secret links, ported from `peergos.shared.user.fs`.
//!
//! An [`AbsoluteCapability`] is a complete cryptographic capability to read (and
//! optionally write) a file or folder: the owner/writer keys, the map-key
//! locating the cryptree node, an optional BAT, and the base symmetric key(s).
//!
//! A [`SecretLink`] is the shareable v2 link; the server stores an
//! [`EncryptedCapability`] under a label, which the link password decrypts.

use peergos_cbor::{CborObject, Cborable};
use peergos_core::auth::Bat;
use peergos_core::error::{Error, Result};
use peergos_core::keys::PublicKeyHash;
use peergos_core::symmetric::{CipherText, SymmetricKey};
use peergos_crypto::hash::hash_to_key_bytes;
use peergos_crypto::random_bytes;

/// The alphabet for a link password (`EncryptedCapability.passwordCharacters`).
const PASSWORD_CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub const MAP_KEY_LENGTH: usize = 32;

/// The link-password scrypt parameters (`EncryptedCapability.LINK_KEY_GENERATOR`
/// = ScryptGenerator(15, 8, 1, 32, "")).
pub const LINK_MEMORY_COST: u8 = 15;
pub const LINK_CPU_COST: u32 = 8;
pub const LINK_PARALLELISM: u32 = 1;
pub const LINK_OUTPUT_BYTES: usize = 32;

/// A location: owner + writer + map-key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub owner: PublicKeyHash,
    pub writer: PublicKeyHash,
    pub map_key: Vec<u8>,
}

/// A complete capability to read/write a file or folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsoluteCapability {
    pub owner: PublicKeyHash,
    pub writer: PublicKeyHash,
    pub map_key: Vec<u8>,
    pub bat: Option<Bat>,
    pub r_base_key: SymmetricKey,
    pub w_base_key: Option<SymmetricKey>,
}

impl AbsoluteCapability {
    pub fn new(
        owner: PublicKeyHash,
        writer: PublicKeyHash,
        map_key: Vec<u8>,
        bat: Option<Bat>,
        r_base_key: SymmetricKey,
        w_base_key: Option<SymmetricKey>,
    ) -> Result<AbsoluteCapability> {
        if map_key.len() != MAP_KEY_LENGTH {
            return Err(Error::Protocol(format!("Invalid map key length: {}", map_key.len())));
        }
        Ok(AbsoluteCapability { owner, writer, map_key, bat, r_base_key, w_base_key })
    }

    pub fn location(&self) -> Location {
        Location {
            owner: self.owner.clone(),
            writer: self.writer.clone(),
            map_key: self.map_key.clone(),
        }
    }

    pub fn is_writable(&self) -> bool {
        self.w_base_key.is_some()
    }

    /// A read-only view of this capability (`WritableAbsoluteCapability.readOnly`):
    /// drops the write-base key, keeping owner/writer/map-key/BAT/read key.
    pub fn read_only(&self) -> AbsoluteCapability {
        AbsoluteCapability { w_base_key: None, ..self.clone() }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<AbsoluteCapability> {
        let owner = cbor
            .get("o")
            .ok_or_else(|| Error::Cbor("cap missing 'o'".into()))
            .and_then(PublicKeyHash::from_cbor)?;
        let writer = cbor
            .get("w")
            .ok_or_else(|| Error::Cbor("cap missing 'w'".into()))
            .and_then(PublicKeyHash::from_cbor)?;
        let map_key = cbor
            .get("m")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("cap missing 'm'".into()))?
            .to_vec();
        let bat = cbor.get("a").map(Bat::from_cbor).transpose()?;
        let r_base_key = cbor
            .get("k")
            .ok_or_else(|| Error::Cbor("cap missing 'k'".into()))
            .and_then(SymmetricKey::from_cbor)?;
        let w_base_key = cbor.get("b").map(SymmetricKey::from_cbor).transpose()?;
        AbsoluteCapability::new(owner, writer, map_key, bat, r_base_key, w_base_key)
    }
}

impl Cborable for AbsoluteCapability {
    fn to_cbor(&self) -> CborObject {
        let mut builder = CborObject::map()
            .put("o", self.owner.to_cbor())
            .put("w", self.writer.to_cbor())
            .put("m", CborObject::ByteString(self.map_key.clone()));
        if let Some(bat) = &self.bat {
            builder = builder.put("a", bat.to_cbor());
        }
        builder = builder.put("k", self.r_base_key.to_cbor());
        if let Some(wk) = &self.w_base_key {
            builder = builder.put("b", wk.to_cbor());
        }
        builder.build()
    }
}

/// A shareable v2 secret link: `secret/z<owner-cid>/<label>#<password>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLink {
    pub owner: PublicKeyHash,
    pub label: i64,
    pub link_password: String,
}

impl SecretLink {
    pub fn label_string(&self) -> String {
        self.label.to_string()
    }

    /// Generate a fresh link: a random positive 32-bit label and a 12-character
    /// password (`SecretLink.create` + `EncryptedCapability.createLinkPassword`).
    pub fn create(owner: PublicKeyHash) -> Result<SecretLink> {
        let b = random_bytes(4);
        let mut label =
            (b[0] as i64) | ((b[1] as i64) << 8) | ((b[2] as i64) << 16) | ((b[3] as i64) << 24);
        if label <= 0 {
            label = 1; // labels must be positive
        }
        Ok(SecretLink { owner, label, link_password: create_link_password()? })
    }

    /// The shareable link string `secret/z<owner>/<label>#<password>`.
    pub fn to_link(&self) -> String {
        format!("secret/{}/{}#{}", self.owner, self.label, self.link_password)
    }

    /// Parse a secret link. Accepts a bare `secret/...` path or a full URL
    /// containing `secret/` (with an optional leading `/`).
    pub fn from_link(link: &str) -> Result<SecretLink> {
        // Trim any host/path prefix down to the `secret/...` portion.
        let link = match link.find("secret/") {
            Some(i) => &link[i..],
            None => link.strip_prefix('/').unwrap_or(link),
        };
        let hash_index = link
            .find('#')
            .ok_or_else(|| Error::Protocol("Invalid secret link: no fragment".into()))?;
        let mut fragment = &link[hash_index + 1..];
        if let Some(q) = fragment.find('?') {
            fragment = &fragment[..q];
        }
        let parts: Vec<&str> = link[..hash_index].split('/').collect();
        if parts.len() != 3 {
            return Err(Error::Protocol("Invalid secret link".into()));
        }
        let owner = PublicKeyHash::new(
            peergos_multiformats::Cid::decode(parts[1]).map_err(|e| Error::Multiformat(e.0))?,
        )?;
        let label = parts[2]
            .parse::<i64>()
            .map_err(|_| Error::Protocol("Invalid secret link label".into()))?;
        if label <= 0 {
            return Err(Error::Protocol("Link labels must be positive!".into()));
        }
        Ok(SecretLink { owner, label, link_password: fragment.to_string() })
    }
}

/// The encrypted capability stored by the server behind a secret-link label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedCapability {
    pub payload: CipherText,
    pub has_user_password: bool,
}

impl EncryptedCapability {
    pub fn from_cbor(cbor: &CborObject) -> Result<EncryptedCapability> {
        let payload = cbor
            .get("c")
            .ok_or_else(|| Error::Cbor("EncryptedCapability missing 'c'".into()))
            .and_then(CipherText::from_cbor)?;
        let has_user_password = cbor.get("p").and_then(|c| c.as_bool()).unwrap_or(false);
        Ok(EncryptedCapability { payload, has_user_password })
    }

    /// Derive the link key from the label (salt) + password via scrypt.
    pub fn derive_key(label: &str, password: &str) -> Result<SymmetricKey> {
        let bytes = hash_to_key_bytes(
            label,
            password,
            LINK_MEMORY_COST,
            LINK_CPU_COST,
            LINK_PARALLELISM,
            LINK_OUTPUT_BYTES,
        )?;
        SymmetricKey::new(bytes, false)
    }

    /// Decrypt the capability using the label as salt and the given password.
    pub fn decrypt_from_password(&self, salt: &str, password: &str) -> Result<AbsoluteCapability> {
        let key = EncryptedCapability::derive_key(salt, password)?;
        self.payload.decrypt(&key, AbsoluteCapability::from_cbor)
    }

    /// Encrypt `cap` under a key derived from the label (salt) + password
    /// (`EncryptedCapability.createFromPassword`).
    pub fn create_from_password(
        cap: &AbsoluteCapability,
        salt: &str,
        password: &str,
        has_user_password: bool,
    ) -> Result<EncryptedCapability> {
        let key = EncryptedCapability::derive_key(salt, password)?;
        Ok(EncryptedCapability { payload: CipherText::build(&key, cap)?, has_user_password })
    }

    pub fn to_cbor(&self) -> CborObject {
        let b = CborObject::map().put("c", self.payload.to_cbor());
        // `p` is only present when a user password is required (matches Java).
        if self.has_user_password {
            b.put("p", CborObject::Boolean(true)).build()
        } else {
            b.build()
        }
    }
}

/// The value stored behind a secret-link label: the encrypted capability plus
/// optional expiry and retrieval limit (`SecretLinkTarget`).
#[derive(Debug, Clone)]
pub struct SecretLinkTarget {
    pub cap: EncryptedCapability,
    pub expiry_epoch_secs: Option<i64>,
    pub max_retrievals: Option<i64>,
}

impl SecretLinkTarget {
    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("cap", self.cap.to_cbor());
        if let Some(e) = self.expiry_epoch_secs {
            b = b.put("expiry", CborObject::Long(e));
        }
        if let Some(m) = self.max_retrievals {
            b = b.put("max", CborObject::Long(m));
        }
        b.build()
    }
}

/// 12 random characters from `[a-zA-Z0-9]` (~2^72 of entropy).
fn create_link_password() -> Result<String> {
    let bytes = random_bytes(12);
    Ok(bytes.iter().map(|b| PASSWORD_CHARACTERS[*b as usize % PASSWORD_CHARACTERS.len()] as char).collect())
}
