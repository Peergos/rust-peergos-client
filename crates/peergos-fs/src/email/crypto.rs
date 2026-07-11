//! Asymmetric encryption envelope for email, a faithful port of
//! `peergos.shared.crypto.SourcedAsymmetricCipherText`.
//!
//! An email or attachment is encrypted with a random ephemeral
//! [`BoxingKeyPair`] *to* the recipient's [`PublicBoxingKey`].  The sender's
//! public key travels with the ciphertext so the recipient can look it up for
//! decryption.  CBOR shape: `{"k": <public_key>, "c": <asymmetric_cipher>}`.

use peergos_cbor::{CborObject, Cborable};
use peergos_core::boxing::{BoxingKeyPair, PublicBoxingKey, SecretBoxingKey};
use peergos_core::error::Result;

/// An asymmetric ciphertext with the sender's public key attached
/// (`SourcedAsymmetricCipherText`).
#[derive(Debug, Clone)]
pub struct SourcedAsymmetricCipherText {
    pub from: PublicBoxingKey,
    pub cipher_text: Vec<u8>,
}

impl SourcedAsymmetricCipherText {
    /// Encrypt `data` to `to_key` using a fresh ephemeral `from` keypair
    /// (`SourcedAsymmetricCipherText.build`).
    pub fn encrypt(from: &BoxingKeyPair, to_key: &PublicBoxingKey, data: &[u8]) -> Result<Self> {
        let ct = to_key.encrypt(data, &from.secret)?;
        Ok(SourcedAsymmetricCipherText {
            from: from.public.clone(),
            cipher_text: ct,
        })
    }

    /// Decrypt this ciphertext with our secret key, using the embedded sender
    /// public key (`SourcedAsymmetricCipherText.decrypt`).
    pub fn decrypt(&self, to: &SecretBoxingKey) -> Result<Vec<u8>> {
        to.decrypt(&self.cipher_text, &self.from)
    }
}

impl Cborable for SourcedAsymmetricCipherText {
    /// CBOR: `{"k": <public_boxing_key>, "c": <asymmetric_ciphertext>}`
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("k", self.from.to_cbor())
            .put("c", CborObject::ByteString(self.cipher_text.clone()))
            .build()
    }
}

impl SourcedAsymmetricCipherText {
    pub fn from_cbor(cbor: &CborObject) -> Result<SourcedAsymmetricCipherText> {
        let from = cbor.get("k")
            .ok_or_else(|| peergos_core::error::Error::Cbor("SourcedAsymmetricCipherText missing 'k'".into()))
            .and_then(|c| PublicBoxingKey::from_cbor(c))?;
        let cipher_text = cbor.get("c")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| peergos_core::error::Error::Cbor("SourcedAsymmetricCipherText missing 'c'".into()))?
            .to_vec();
        Ok(SourcedAsymmetricCipherText { from, cipher_text })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let sender = BoxingKeyPair::random_curve25519();
        let recipient = BoxingKeyPair::random_curve25519();
        let plaintext = b"hello, encrypted email!";
        let ct = SourcedAsymmetricCipherText::encrypt(&sender, &recipient.public, plaintext).unwrap();
        let decrypted = ct.decrypt(&recipient.secret).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn cbor_round_trip() {
        let sender = BoxingKeyPair::random_curve25519();
        let recipient = BoxingKeyPair::random_curve25519();
        let ct = SourcedAsymmetricCipherText::encrypt(&sender, &recipient.public, b"test").unwrap();
        let cbor = ct.to_cbor();
        let decoded = SourcedAsymmetricCipherText::from_cbor(&cbor).unwrap();
        let decrypted = decoded.decrypt(&recipient.secret).unwrap();
        assert_eq!(decrypted, b"test");
    }
}
