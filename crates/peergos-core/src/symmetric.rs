//! Symmetric encryption data types, ported from
//! `peergos.shared.crypto.symmetric` and `peergos.shared.crypto.CipherText`.
//!
//! `SymmetricKey` is a NaCl secretbox key (`TweetNaClKey`): cbor `[type, key,
//! isDirty]`. `CipherText` is a `[nonce, ciphertext]` pair.

use crate::error::{Error, Result};
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::symmetric;

pub const TWEETNACL: i64 = 0x1;
pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;

/// A NaCl secretbox symmetric key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKey {
    pub key: Vec<u8>,
    pub is_dirty: bool,
}

impl SymmetricKey {
    pub fn new(key: Vec<u8>, is_dirty: bool) -> Result<SymmetricKey> {
        if key.len() != KEY_BYTES {
            return Err(Error::Crypto(format!("Incorrect key size! ({})", key.len())));
        }
        Ok(SymmetricKey { key, is_dirty })
    }

    /// Generate a random 24-byte nonce.
    pub fn create_nonce() -> Vec<u8> {
        peergos_crypto::random_bytes(NONCE_BYTES)
    }

    pub fn encrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(symmetric::secretbox(data, nonce, &self.key)?)
    }

    pub fn decrypt(&self, cipher: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        Ok(symmetric::secretbox_open(cipher, nonce, &self.key)?)
    }

    /// `SymmetricKey.fromByteArray`: the key is itself cbor-encoded.
    pub fn from_byte_array(raw: &[u8]) -> Result<SymmetricKey> {
        SymmetricKey::from_cbor(&CborObject::from_bytes(raw)?)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<SymmetricKey> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for SymmetricKey".into()))?;
        let key = list
            .get(1)
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing symmetric key bytes".into()))?
            .to_vec();
        let is_dirty = list.get(2).and_then(|c| c.as_bool()).unwrap_or(false);
        SymmetricKey::new(key, is_dirty)
    }
}

impl Cborable for SymmetricKey {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![
            CborObject::Long(TWEETNACL),
            CborObject::ByteString(self.key.clone()),
            CborObject::Boolean(self.is_dirty),
        ])
    }
}

/// `[nonce, ciphertext]` — a symmetrically encrypted, cbor-serialized value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherText {
    pub nonce: Vec<u8>,
    pub cipher_text: Vec<u8>,
}

impl CipherText {
    pub fn new(nonce: Vec<u8>, cipher_text: Vec<u8>) -> CipherText {
        CipherText { nonce, cipher_text }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<CipherText> {
        let parts = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for cipher text".into()))?;
        let nonce = parts
            .first()
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("cipher text missing nonce".into()))?
            .to_vec();
        let cipher_text = parts
            .get(1)
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("cipher text missing ciphertext".into()))?
            .to_vec();
        Ok(CipherText::new(nonce, cipher_text))
    }

    /// Encrypt a cborable value under `key`.
    pub fn build(key: &SymmetricKey, secret: &impl Cborable) -> Result<CipherText> {
        let nonce = SymmetricKey::create_nonce();
        let cipher_text = key.encrypt(&secret.serialize(), &nonce)?;
        Ok(CipherText::new(nonce, cipher_text))
    }

    /// Decrypt and decode the contained cbor value.
    pub fn decrypt<T>(
        &self,
        key: &SymmetricKey,
        from_cbor: impl FnOnce(&CborObject) -> Result<T>,
    ) -> Result<T> {
        let secret = key.decrypt(&self.cipher_text, &self.nonce)?;
        // Tolerate trailing bytes: PaddedCipherText zero-pads the plaintext.
        from_cbor(&CborObject::from_bytes_prefix(&secret)?)
    }
}

impl Cborable for CipherText {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![
            CborObject::ByteString(self.nonce.clone()),
            CborObject::ByteString(self.cipher_text.clone()),
        ])
    }
}
