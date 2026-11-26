//! Signing-key data-model types (Ed25519 and composite Ed25519 + ML-DSA-44),
//! ported from `peergos.shared.crypto.*`.

use crate::error::{Error, Result};
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::{mldsa, sign};
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

pub const HYBRID_ED25519_MLDSA: i64 = 0x2;

/// Whether new non-identity writers get composite Ed25519 + ML-DSA-44 keys, as
/// `SigningKeyPair.HYBRID_WRITERS`.
static HYBRID_WRITERS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn hybrid_writers() -> bool {
    HYBRID_WRITERS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_hybrid_writers(enabled: bool) {
    HYBRID_WRITERS.store(enabled, std::sync::atomic::Ordering::Relaxed)
}

const HYBRID_DOMAIN: &[u8] = b"peergos/ed25519+ml-dsa-44";
pub const HYBRID_SIGNATURE_BYTES: usize = sign::SIGNATURE_BYTES + mldsa::SIGNATURE_BYTES;

/// What a signature is for. Composite keys sign the domain with the message, so a
/// signature for one purpose can't be passed off as another. Ed25519 ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningDomain {
    Pointer,
    Block,
    BlockWriteAuth,
    BlockList,
    OwnerProof,
    SigningKey,
    BoxingKey,
    KeyChange,
    UsernameClaim,
    TimeLimited,
    SpaceRequest,
    SpaceRequestApproval,
    WriterQuota,
    ServerMessage,
    Chat,
    Ipns,
    Login,
    IdentityLink,
    FollowRequestRemoval,
}

impl SigningDomain {
    pub const ALL: [SigningDomain; 19] = [
        SigningDomain::Pointer,
        SigningDomain::Block,
        SigningDomain::BlockWriteAuth,
        SigningDomain::BlockList,
        SigningDomain::OwnerProof,
        SigningDomain::SigningKey,
        SigningDomain::BoxingKey,
        SigningDomain::KeyChange,
        SigningDomain::UsernameClaim,
        SigningDomain::TimeLimited,
        SigningDomain::SpaceRequest,
        SigningDomain::SpaceRequestApproval,
        SigningDomain::WriterQuota,
        SigningDomain::ServerMessage,
        SigningDomain::Chat,
        SigningDomain::Ipns,
        SigningDomain::Login,
        SigningDomain::IdentityLink,
        SigningDomain::FollowRequestRemoval,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            SigningDomain::Pointer => "pointer",
            SigningDomain::Block => "block",
            SigningDomain::BlockWriteAuth => "block-write-auth",
            SigningDomain::BlockList => "block-list",
            SigningDomain::OwnerProof => "owner-proof",
            SigningDomain::SigningKey => "signing-key",
            SigningDomain::BoxingKey => "boxing-key",
            SigningDomain::KeyChange => "key-change",
            SigningDomain::UsernameClaim => "username-claim",
            SigningDomain::TimeLimited => "time-limited-request",
            SigningDomain::SpaceRequest => "space-request",
            SigningDomain::SpaceRequestApproval => "space-request-approval",
            SigningDomain::WriterQuota => "writer-quota",
            SigningDomain::ServerMessage => "server-message",
            SigningDomain::Chat => "chat",
            SigningDomain::Ipns => "ipns",
            SigningDomain::Login => "login",
            SigningDomain::IdentityLink => "identity-link",
            SigningDomain::FollowRequestRemoval => "follow-request-removal",
        }
    }
}

/// `DOMAIN || len(label) || label || message`, which both components of a
/// composite key sign.
fn domain_separated(message: &[u8], domain: SigningDomain) -> Vec<u8> {
    let label = domain.label().as_bytes();
    let mut out = Vec::with_capacity(HYBRID_DOMAIN.len() + 1 + label.len() + message.len());
    out.extend_from_slice(HYBRID_DOMAIN);
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(message);
    out
}

/// `Ed25519PublicKey` — cbor `[1, publicKey]`, or `HybridEd25519MLDSAPublicKey` —
/// cbor `[2, {e: ed25519 key, m: ml-dsa key}]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicSigningKey {
    Ed25519(Vec<u8>),
    Hybrid { ed25519: Vec<u8>, mldsa: Vec<u8> },
}

impl PublicSigningKey {
    pub fn new(public_key: Vec<u8>) -> PublicSigningKey {
        PublicSigningKey::Ed25519(public_key)
    }

    pub fn key_type(&self) -> i64 {
        match self {
            PublicSigningKey::Ed25519(_) => ED25519,
            PublicSigningKey::Hybrid { .. } => HYBRID_ED25519_MLDSA,
        }
    }

    /// `ContentAddressedStorage.hashKey`: Ed25519 keys are inlined in an identity
    /// multihash, any other is named by the sha256 of its block.
    pub fn hash(&self) -> Result<PublicKeyHash> {
        let raw = self.serialize();
        match self {
            PublicSigningKey::Ed25519(_) => PublicKeyHash::identity(raw),
            PublicSigningKey::Hybrid { .. } => PublicKeyHash::new(Cid::new(
                CID_V1,
                Codec::DagCbor,
                MultihashType::Sha2_256,
                peergos_crypto::hash::sha256(&raw).to_vec(),
            )?),
        }
    }

    /// `unsignMessage` — verify an attached signature and return the message.
    pub fn unsign_message(&self, signed: &[u8], domain: SigningDomain) -> Result<Vec<u8>> {
        match self {
            PublicSigningKey::Ed25519(pk) => Ok(sign::crypto_sign_open(signed, pk)?),
            PublicSigningKey::Hybrid { ed25519, mldsa: mpk } => {
                if signed.len() < HYBRID_SIGNATURE_BYTES {
                    return Err(Error::Crypto("Invalid signature".into()));
                }
                let (ed_sig, rest) = signed.split_at(sign::SIGNATURE_BYTES);
                let (mldsa_sig, message) = rest.split_at(mldsa::SIGNATURE_BYTES);
                let separated = domain_separated(message, domain);
                let mut ed_signed = ed_sig.to_vec();
                ed_signed.extend_from_slice(&separated);
                sign::crypto_sign_open(&ed_signed, ed25519)?;
                if !mldsa::verify(mldsa_sig, &separated, mpk) {
                    return Err(Error::Crypto("Invalid signature".into()));
                }
                Ok(message.to_vec())
            }
        }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<PublicSigningKey> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for PublicSigningKey".into()))?;
        match list.first().and_then(|c| c.as_long()) {
            Some(HYBRID_ED25519_MLDSA) => {
                let m = list.get(1).ok_or_else(|| Error::Cbor("hybrid public key missing body".into()))?;
                let ed = m
                    .get("e")
                    .ok_or_else(|| Error::Cbor("hybrid public key missing 'e'".into()))
                    .and_then(PublicSigningKey::from_cbor)?;
                let PublicSigningKey::Ed25519(ed25519) = ed else {
                    return Err(Error::Cbor("hybrid public key needs an Ed25519 component".into()));
                };
                let mldsa = m
                    .get("m")
                    .and_then(|c| c.as_bytes())
                    .ok_or_else(|| Error::Cbor("hybrid public key missing 'm'".into()))?
                    .to_vec();
                if mldsa.len() != mldsa::PUBLIC_KEY_BYTES {
                    return Err(Error::Cbor(format!("Invalid ML-DSA-44 public key size: {}", mldsa.len())));
                }
                Ok(PublicSigningKey::Hybrid { ed25519, mldsa })
            }
            Some(ED25519) | None => {
                let key = list
                    .get(1)
                    .and_then(|c| c.as_bytes())
                    .ok_or_else(|| Error::Cbor("missing ed25519 public key bytes".into()))?;
                Ok(PublicSigningKey::new(key.to_vec()))
            }
            Some(t) => Err(Error::Cbor(format!("Unknown public signing key type: {t}"))),
        }
    }
}

impl Cborable for PublicSigningKey {
    fn to_cbor(&self) -> CborObject {
        match self {
            PublicSigningKey::Ed25519(pk) => {
                CborObject::List(vec![CborObject::Long(ED25519), CborObject::ByteString(pk.clone())])
            }
            PublicSigningKey::Hybrid { ed25519, mldsa } => CborObject::List(vec![
                CborObject::Long(HYBRID_ED25519_MLDSA),
                CborObject::map()
                    .put("e", PublicSigningKey::Ed25519(ed25519.clone()).to_cbor())
                    .put("m", CborObject::ByteString(mldsa.clone()))
                    .build(),
            ]),
        }
    }
}

/// `Ed25519SecretKey` — cbor `[1, secretKey]` where secretKey is the 64-byte NaCl
/// secret (`seed || public`), or `HybridEd25519MLDSASecretKey` — cbor
/// `[2, {e: ed25519 secret, m: ml-dsa seed}]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSigningKey {
    Ed25519(Vec<u8>),
    Hybrid { ed25519: Vec<u8>, mldsa_seed: Vec<u8> },
}

impl SecretSigningKey {
    pub fn new(secret_key: Vec<u8>) -> SecretSigningKey {
        SecretSigningKey::Ed25519(secret_key)
    }

    /// `signMessage` — attached signature `sig || message`.
    pub fn sign_message(&self, message: &[u8], domain: SigningDomain) -> Result<Vec<u8>> {
        let mut out = self.signature_only(message, domain)?;
        out.extend_from_slice(message);
        Ok(out)
    }

    /// `signatureOnly` — just the signature.
    pub fn signature_only(&self, message: &[u8], domain: SigningDomain) -> Result<Vec<u8>> {
        match self {
            SecretSigningKey::Ed25519(sk) => {
                let signed = sign::crypto_sign(message, sk)?;
                Ok(signed[..sign::SIGNATURE_BYTES].to_vec())
            }
            SecretSigningKey::Hybrid { ed25519, mldsa_seed } => {
                let separated = domain_separated(message, domain);
                let mut sig = sign::crypto_sign(&separated, ed25519)?;
                sig.truncate(sign::SIGNATURE_BYTES);
                sig.extend_from_slice(&mldsa::sign(&separated, mldsa_seed)?);
                Ok(sig)
            }
        }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<SecretSigningKey> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor("Invalid cbor for SecretSigningKey".into()))?;
        match list.first().and_then(|c| c.as_long()) {
            Some(HYBRID_ED25519_MLDSA) => {
                let m = list.get(1).ok_or_else(|| Error::Cbor("hybrid secret key missing body".into()))?;
                let ed = m
                    .get("e")
                    .ok_or_else(|| Error::Cbor("hybrid secret key missing 'e'".into()))
                    .and_then(SecretSigningKey::from_cbor)?;
                let SecretSigningKey::Ed25519(ed25519) = ed else {
                    return Err(Error::Cbor("Composite key needs an Ed25519 component".into()));
                };
                let mldsa_seed = m
                    .get("m")
                    .and_then(|c| c.as_bytes())
                    .ok_or_else(|| Error::Cbor("hybrid secret key missing 'm'".into()))?
                    .to_vec();
                if mldsa_seed.len() != mldsa::SEED_BYTES {
                    return Err(Error::Cbor(format!("Invalid ML-DSA-44 seed size: {}", mldsa_seed.len())));
                }
                Ok(SecretSigningKey::Hybrid { ed25519, mldsa_seed })
            }
            Some(ED25519) | None => {
                let key = list
                    .get(1)
                    .and_then(|c| c.as_bytes())
                    .ok_or_else(|| Error::Cbor("missing ed25519 secret key bytes".into()))?;
                Ok(SecretSigningKey::new(key.to_vec()))
            }
            Some(t) => Err(Error::Cbor(format!("Unknown secret signing key type: {t}"))),
        }
    }
}

impl Cborable for SecretSigningKey {
    fn to_cbor(&self) -> CborObject {
        match self {
            SecretSigningKey::Ed25519(sk) => {
                CborObject::List(vec![CborObject::Long(ED25519), CborObject::ByteString(sk.clone())])
            }
            SecretSigningKey::Hybrid { ed25519, mldsa_seed } => CborObject::List(vec![
                CborObject::Long(HYBRID_ED25519_MLDSA),
                CborObject::map()
                    .put("e", SecretSigningKey::Ed25519(ed25519.clone()).to_cbor())
                    .put("m", CborObject::ByteString(mldsa_seed.clone()))
                    .build(),
            ]),
        }
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
        let signed = owned_keypair.secret.sign_message(&owner.to_cbor().to_bytes(), SigningDomain::OwnerProof)?;
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
        let unsigned = signer.unsign_message(&self.signed_owner, SigningDomain::OwnerProof)?;
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

    /// `SigningKeyPair.randomHybrid` — a composite Ed25519 + ML-DSA-44 keypair.
    pub fn random_hybrid() -> Result<SigningKeyPair> {
        let ed = SigningKeyPair::random()?;
        let (PublicSigningKey::Ed25519(ed_pub), SecretSigningKey::Ed25519(ed_sec)) = (ed.public, ed.secret) else {
            unreachable!()
        };
        let seed = peergos_crypto::random_bytes(mldsa::SEED_BYTES);
        Ok(SigningKeyPair {
            public: PublicSigningKey::Hybrid { ed25519: ed_pub, mldsa: mldsa::public_key(&seed)? },
            secret: SecretSigningKey::Hybrid { ed25519: ed_sec, mldsa_seed: seed },
        })
    }

    /// `SigningKeyPair.randomWriter` — a key for a new non-identity writer.
    pub fn random_writer() -> Result<SigningKeyPair> {
        if hybrid_writers() {
            SigningKeyPair::random_hybrid()
        } else {
            SigningKeyPair::random()
        }
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
