//! Signing-key data-model types (Ed25519), ported from
//! `peergos.shared.crypto.*`. Only the pieces needed for block writes and key
//! hashing are implemented so far (boxing keys come with the social layer).

use crate::error::{Error, Result};
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::sign;
use peergos_multiformats::{Cid, Codec, MultihashType, CID_V1};

pub const ED25519: i64 = 0x1;

/// `PublicKeyHash`: a CID identifying a public key, either an identity multihash
/// embedding the key, or the sha256 of the key block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKeyHash {
    pub target: Cid,
}

impl PublicKeyHash {
    pub fn new(target: Cid) -> Result<PublicKeyHash> {
        let t = target.hash_type();
        if t != MultihashType::Sha2_256 && t != MultihashType::Id {
            return Err(Error::Protocol("Must use a safe hash for a public key!".into()));
        }
        Ok(PublicKeyHash { target })
    }

    /// `ContentAddressedStorage.hashKey`: wrap raw key-block bytes as an identity
    /// dag-cbor CID.
    pub fn identity(raw: Vec<u8>) -> Result<PublicKeyHash> {
        let cid = Cid::new(CID_V1, Codec::DagCbor, MultihashType::Id, raw)?;
        PublicKeyHash::new(cid)
    }

    pub fn is_identity(&self) -> bool {
        self.target.multihash.is_identity()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<PublicKeyHash> {
        match cbor.as_link() {
            Some(bytes) => PublicKeyHash::new(Cid::cast(bytes)?),
            None => Err(Error::Cbor(format!("Invalid cbor for PublicKeyHash: {cbor:?}"))),
        }
    }
}

impl Cborable for PublicKeyHash {
    fn to_cbor(&self) -> CborObject {
        CborObject::MerkleLink(self.target.to_bytes())
    }
}

impl std::fmt::Display for PublicKeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.target)
    }
}

/// `Ed25519PublicKey` — cbor `[type, publicKey]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSigningKey {
    pub public_key: Vec<u8>,
}

impl PublicSigningKey {
    pub fn new(public_key: Vec<u8>) -> PublicSigningKey {
        PublicSigningKey { public_key }
    }

    /// The `PublicKeyHash` of this key (identity multihash of its cbor bytes).
    pub fn hash(&self) -> Result<PublicKeyHash> {
        PublicKeyHash::identity(self.serialize())
    }

    /// `unsignMessage` — verify a NaCl attached signature and return the message.
    pub fn unsign_message(&self, signed: &[u8]) -> Result<Vec<u8>> {
        Ok(sign::crypto_sign_open(signed, &self.public_key)?)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<PublicSigningKey> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for PublicSigningKey".into()))?;
        let key = list
            .get(1)
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing ed25519 public key bytes".into()))?;
        Ok(PublicSigningKey::new(key.to_vec()))
    }
}

impl Cborable for PublicSigningKey {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![
            CborObject::Long(ED25519),
            CborObject::ByteString(self.public_key.clone()),
        ])
    }
}

/// `Ed25519SecretKey` — cbor `[type, secretKey]` where secretKey is the 64-byte
/// NaCl secret (`seed || public`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSigningKey {
    pub secret_key: Vec<u8>,
}

impl SecretSigningKey {
    pub fn new(secret_key: Vec<u8>) -> SecretSigningKey {
        SecretSigningKey { secret_key }
    }

    /// `signMessage` — NaCl attached signature `sig(64) || message`.
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(sign::crypto_sign(message, &self.secret_key)?)
    }

    /// `signatureOnly` — just the 64-byte signature.
    pub fn signature_only(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signed = self.sign_message(message)?;
        Ok(signed[..sign::SIGNATURE_BYTES].to_vec())
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<SecretSigningKey> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for SecretSigningKey".into()))?;
        let key = list
            .get(1)
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing ed25519 secret key bytes".into()))?;
        Ok(SecretSigningKey::new(key.to_vec()))
    }
}

impl Cborable for SecretSigningKey {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![
            CborObject::Long(ED25519),
            CborObject::ByteString(self.secret_key.clone()),
        ])
    }
}

/// `SigningPrivateKeyAndPublicHash` — a writer's secret key plus the public hash
/// used to authorize block writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPrivateKeyAndPublicHash {
    pub public_key_hash: PublicKeyHash,
    pub secret: SecretSigningKey,
}

impl SigningPrivateKeyAndPublicHash {
    pub fn new(public_key_hash: PublicKeyHash, secret: SecretSigningKey) -> Self {
        SigningPrivateKeyAndPublicHash { public_key_hash, secret }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<Self> {
        let p = cbor
            .get("p")
            .ok_or_else(|| Error::Cbor("missing 'p' in SigningPrivateKeyAndPublicHash".into()))?;
        let s = cbor
            .get("s")
            .ok_or_else(|| Error::Cbor("missing 's' in SigningPrivateKeyAndPublicHash".into()))?;
        Ok(SigningPrivateKeyAndPublicHash::new(
            PublicKeyHash::from_cbor(p)?,
            SecretSigningKey::from_cbor(s)?,
        ))
    }
}

impl Cborable for SigningPrivateKeyAndPublicHash {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("p", self.public_key_hash.to_cbor())
            .put("s", self.secret.to_cbor())
            .build()
    }
}

/// `OwnerProof` — a signature by an owned key over its owner's key hash, proving
/// that `owner` controls `ownedKey`. Stored inline in the owner's owned-key champ
/// and in chat `Join` messages / `Member`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerProof {
    pub owned_key: PublicKeyHash,
    pub signed_owner: Vec<u8>,
}

impl OwnerProof {
    pub fn new(owned_key: PublicKeyHash, signed_owner: Vec<u8>) -> OwnerProof {
        OwnerProof { owned_key, signed_owner }
    }

    /// `OwnerProof.build` — sign the owner's serialized key hash with the owned
    /// key's secret.
    pub fn build(owned_keypair: &SigningPrivateKeyAndPublicHash, owner: &PublicKeyHash) -> Result<OwnerProof> {
        let signed = owned_keypair.secret.sign_message(&owner.to_cbor().to_bytes())?;
        Ok(OwnerProof::new(owned_keypair.public_key_hash.clone(), signed))
    }

    /// `OwnerProof.getAndVerifyOwner` — retrieve the owned public signing key,
    /// verify the signature and return the claimed owner key hash.
    pub async fn get_and_verify_owner(
        &self,
        owner: &PublicKeyHash,
        store: &dyn crate::storage::ContentAddressedStorage,
    ) -> Result<PublicKeyHash> {
        let signer = crate::storage::get_signing_key(store, owner, &self.owned_key)
            .await?
            .ok_or_else(|| Error::Protocol(format!("Couldn't retrieve owned key: {}", self.owned_key)))?;
        let unsigned = signer.unsign_message(&self.signed_owner)?;
        PublicKeyHash::from_cbor(&CborObject::from_bytes_prefix(&unsigned)?)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<OwnerProof> {
        let owned = cbor
            .get("o")
            .ok_or_else(|| Error::Cbor("OwnerProof missing 'o'".into()))
            .and_then(PublicKeyHash::from_cbor)?;
        let signed = cbor
            .get("p")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("OwnerProof missing 'p'".into()))?
            .to_vec();
        Ok(OwnerProof::new(owned, signed))
    }
}

impl Cborable for OwnerProof {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("o", self.owned_key.to_cbor())
            .put("p", CborObject::ByteString(self.signed_owner.clone()))
            .build()
    }
}

/// A signing keypair, mirroring `SigningKeyPair` (public key + its hash + secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyPair {
    pub public: PublicSigningKey,
    pub secret: SecretSigningKey,
}

impl SigningKeyPair {
    /// A fresh random Ed25519 keypair (`SigningKeyPair.random`).
    pub fn random() -> Result<SigningKeyPair> {
        let (_public, secret64) = peergos_crypto::sign::keypair_from_seed(&peergos_crypto::random_bytes(32))
            .map_err(|e| Error::Crypto(e.to_string()))?;
        SigningKeyPair::from_secret(secret64.to_vec())
    }

    /// Build from a NaCl 64-byte secret key (`seed || public`).
    pub fn from_secret(secret_key: Vec<u8>) -> Result<SigningKeyPair> {
        let public = sign::public_from_secret(&secret_key)?;
        Ok(SigningKeyPair {
            public: PublicSigningKey::new(public.to_vec()),
            secret: SecretSigningKey::new(secret_key),
        })
    }

    pub fn to_private_and_hash(&self) -> Result<SigningPrivateKeyAndPublicHash> {
        Ok(SigningPrivateKeyAndPublicHash::new(
            self.public.hash()?,
            self.secret.clone(),
        ))
    }

    /// `SigningKeyPair.fromCbor` — cbor list `[publicSigningKey, secretSigningKey]`.
    pub fn from_cbor(cbor: &CborObject) -> Result<SigningKeyPair> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for SigningKeyPair".into()))?;
        let public = list
            .first()
            .ok_or_else(|| Error::Cbor("SigningKeyPair missing public key".into()))
            .and_then(PublicSigningKey::from_cbor)?;
        let secret = list
            .get(1)
            .ok_or_else(|| Error::Cbor("SigningKeyPair missing secret key".into()))
            .and_then(SecretSigningKey::from_cbor)?;
        Ok(SigningKeyPair { public, secret })
    }
}

impl Cborable for SigningKeyPair {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![self.public.to_cbor(), self.secret.to_cbor()])
    }
}
