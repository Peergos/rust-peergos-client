//! Asymmetric boxing keys and message encryption, ported from
//! `peergos.shared.crypto.asymmetric`. Supports both classical Curve25519 and
//! the post-quantum **hybrid Curve25519 + ML-KEM-1024** boxing keys used for
//! follow requests and capability sharing.
//!
//! Hybrid `encryptMessageFor` (Peergos `HybridCurve25519MLKEMPublicKey`):
//! a random 32-byte secret is boxed to the recipient's Curve25519 key, ML-KEM is
//! encapsulated to the recipient's ML-KEM key, and the two shared secrets are
//! combined via HKDF into a symmetric key that encrypts the payload. All three
//! ciphertexts travel together in a `HybridCipherText`.

use crate::error::{Error, Result};
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::boxing as prim;
use peergos_crypto::hash::hkdf_key;
use peergos_crypto::random_bytes;
use peergos_crypto::symmetric::{secretbox, secretbox_open};

const CURVE25519: i64 = 0x1;
const HYBRID: i64 = 0x2;
const BOX_NONCE_BYTES: usize = 24;
const SYM_NONCE_BYTES: usize = 24;

/// A public boxing key (`PublicBoxingKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicBoxingKey {
    Curve25519([u8; 32]),
    Hybrid { curve: [u8; 32], mlkem: Vec<u8> },
}

/// A secret boxing key (`SecretBoxingKey`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretBoxingKey {
    Curve25519([u8; 32]),
    Hybrid { curve: [u8; 32], mlkem: Vec<u8> },
}

fn to_32(bytes: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| Error::Crypto("boxing key must be 32 bytes".into()))
}

/// Parse a Curve25519 key body `[type, bytes]` → the 32-byte key.
fn curve_key_bytes(cbor: &CborObject) -> Result<[u8; 32]> {
    let list = cbor.as_list().ok_or_else(|| Error::Cbor("expected curve25519 key list".into()))?;
    let bytes = list.get(1).and_then(|c| c.as_bytes()).ok_or_else(|| Error::Cbor("curve25519 key missing bytes".into()))?;
    to_32(bytes)
}

impl PublicBoxingKey {
    pub fn from_cbor(cbor: &CborObject) -> Result<PublicBoxingKey> {
        let list = cbor.as_list().ok_or_else(|| Error::Cbor("Invalid cbor for PublicBoxingKey".into()))?;
        let ty = list.first().and_then(|c| c.as_long()).ok_or_else(|| Error::Cbor("boxing key missing type".into()))?;
        match ty {
            CURVE25519 => Ok(PublicBoxingKey::Curve25519(curve_key_bytes(cbor)?)),
            HYBRID => {
                let m = list.get(1).ok_or_else(|| Error::Cbor("hybrid key missing body".into()))?;
                let curve = curve_key_bytes(m.get("c").ok_or_else(|| Error::Cbor("hybrid missing 'c'".into()))?)?;
                let mlkem = m
                    .get("m")
                    .and_then(|mm| mm.get("p"))
                    .and_then(|c| c.as_bytes())
                    .ok_or_else(|| Error::Cbor("hybrid mlkem missing 'p'".into()))?
                    .to_vec();
                Ok(PublicBoxingKey::Hybrid { curve, mlkem })
            }
            other => Err(Error::Cbor(format!("unknown boxing key type: {other}"))),
        }
    }

    /// `encryptMessageFor(payload, from)`: encrypt to this key, from the given
    /// (ephemeral) secret key. Returns the raw ciphertext bytes.
    pub fn encrypt(&self, payload: &[u8], from: &SecretBoxingKey) -> Result<Vec<u8>> {
        match (self, from) {
            (PublicBoxingKey::Curve25519(pk), SecretBoxingKey::Curve25519(sk)) => {
                let nonce = random_bytes(BOX_NONCE_BYTES);
                let boxed = prim::crypto_box(payload, &nonce, pk, sk)?;
                Ok([boxed, nonce].concat())
            }
            (PublicBoxingKey::Hybrid { curve, mlkem }, SecretBoxingKey::Hybrid { curve: sk, .. }) => {
                let curve_shared = random_bytes(32);
                let (mlkem_shared, mlkem_ct) = prim::mlkem_encapsulate(mlkem)?;
                let combined = hkdf_key(&[curve_shared.clone(), mlkem_shared].concat());
                let box_nonce = random_bytes(BOX_NONCE_BYTES);
                let curve_ct =
                    [prim::crypto_box(&curve_shared, &box_nonce, curve, sk)?, box_nonce].concat();
                let sym_nonce = random_bytes(SYM_NONCE_BYTES);
                let encrypted = secretbox(payload, &sym_nonce, &combined)?;
                Ok(hybrid_cipher_cbor(&curve_ct, &mlkem_ct, &encrypted, &sym_nonce).to_bytes())
            }
            _ => Err(Error::Crypto("mismatched boxing key types".into())),
        }
    }
}

impl Cborable for PublicBoxingKey {
    fn to_cbor(&self) -> CborObject {
        match self {
            PublicBoxingKey::Curve25519(k) => curve_cbor(k),
            PublicBoxingKey::Hybrid { curve, mlkem } => CborObject::List(vec![
                CborObject::Long(HYBRID),
                CborObject::map()
                    .put("c", curve_cbor(curve))
                    .put("m", CborObject::map().put("p", CborObject::ByteString(mlkem.clone())).build())
                    .build(),
            ]),
        }
    }
}

impl SecretBoxingKey {
    pub fn from_cbor(cbor: &CborObject) -> Result<SecretBoxingKey> {
        let list = cbor.as_list().ok_or_else(|| Error::Cbor("Invalid cbor for SecretBoxingKey".into()))?;
        let ty = list.first().and_then(|c| c.as_long()).ok_or_else(|| Error::Cbor("boxing key missing type".into()))?;
        match ty {
            CURVE25519 => Ok(SecretBoxingKey::Curve25519(curve_key_bytes(cbor)?)),
            HYBRID => {
                let m = list.get(1).ok_or_else(|| Error::Cbor("hybrid key missing body".into()))?;
                let curve = curve_key_bytes(m.get("c").ok_or_else(|| Error::Cbor("hybrid missing 'c'".into()))?)?;
                let mlkem = m
                    .get("m")
                    .and_then(|mm| mm.get("s"))
                    .and_then(|c| c.as_bytes())
                    .ok_or_else(|| Error::Cbor("hybrid mlkem missing 's'".into()))?
                    .to_vec();
                Ok(SecretBoxingKey::Hybrid { curve, mlkem })
            }
            other => Err(Error::Cbor(format!("unknown boxing key type: {other}"))),
        }
    }

    /// `decryptMessage(cipher, from)`: decrypt a message encrypted to us by the
    /// sender whose public key is `from`.
    pub fn decrypt(&self, cipher: &[u8], from: &PublicBoxingKey) -> Result<Vec<u8>> {
        match (self, from) {
            (SecretBoxingKey::Curve25519(sk), PublicBoxingKey::Curve25519(pk)) => {
                curve_unbox(cipher, pk, sk)
            }
            (SecretBoxingKey::Hybrid { curve: sk, mlkem: mlkem_sk }, PublicBoxingKey::Hybrid { curve: pk, .. }) => {
                let hybrid = CborObject::from_bytes(cipher)?;
                let curve_ct = hybrid.get("c").and_then(|c| c.as_bytes()).ok_or_else(|| Error::Cbor("hybrid cipher missing 'c'".into()))?;
                let mlkem_ct = hybrid.get("m").and_then(|c| c.as_bytes()).ok_or_else(|| Error::Cbor("hybrid cipher missing 'm'".into()))?;
                let enc = hybrid.get("i").and_then(|c| c.as_bytes()).ok_or_else(|| Error::Cbor("hybrid cipher missing 'i'".into()))?;
                let sym_nonce = hybrid.get("n").and_then(|c| c.as_bytes()).ok_or_else(|| Error::Cbor("hybrid cipher missing 'n'".into()))?;
                let curve_shared = curve_unbox(curve_ct, pk, sk)?;
                let mlkem_shared = prim::mlkem_decapsulate(mlkem_ct, mlkem_sk)?;
                let combined = hkdf_key(&[curve_shared, mlkem_shared].concat());
                Ok(secretbox_open(enc, sym_nonce, &combined)?)
            }
            _ => Err(Error::Crypto("mismatched boxing key types".into())),
        }
    }
}

impl Cborable for SecretBoxingKey {
    fn to_cbor(&self) -> CborObject {
        match self {
            SecretBoxingKey::Curve25519(k) => curve_cbor(k),
            SecretBoxingKey::Hybrid { curve, mlkem } => CborObject::List(vec![
                CborObject::Long(HYBRID),
                CborObject::map()
                    .put("c", curve_cbor(curve))
                    .put("m", CborObject::map().put("s", CborObject::ByteString(mlkem.clone())).build())
                    .build(),
            ]),
        }
    }
}

/// A boxing keypair (`BoxingKeyPair`, cbor `[public, secret]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxingKeyPair {
    pub public: PublicBoxingKey,
    pub secret: SecretBoxingKey,
}

impl BoxingKeyPair {
    pub fn from_cbor(cbor: &CborObject) -> Result<BoxingKeyPair> {
        let list = cbor.as_list().ok_or_else(|| Error::Cbor("Invalid cbor for BoxingKeyPair".into()))?;
        let public = PublicBoxingKey::from_cbor(list.first().ok_or_else(|| Error::Cbor("boxing pair missing public".into()))?)?;
        let secret = SecretBoxingKey::from_cbor(list.get(1).ok_or_else(|| Error::Cbor("boxing pair missing secret".into()))?)?;
        Ok(BoxingKeyPair { public, secret })
    }

    /// A fresh ephemeral Curve25519 boxing keypair (`randomCurve25519`).
    pub fn random_curve25519() -> BoxingKeyPair {
        let (pk, sk) = prim::random_keypair();
        BoxingKeyPair {
            public: PublicBoxingKey::Curve25519(pk),
            secret: SecretBoxingKey::Curve25519(sk),
        }
    }

    /// A fresh ephemeral hybrid Curve25519+ML-KEM-1024 boxing keypair
    /// (`randomHybrid`).
    pub fn random_hybrid() -> BoxingKeyPair {
        let (curve_pub, curve_sec) = prim::random_keypair();
        let (mlkem_pub, mlkem_sec) = prim::mlkem_keypair();
        BoxingKeyPair {
            public: PublicBoxingKey::Hybrid { curve: curve_pub, mlkem: mlkem_pub },
            secret: SecretBoxingKey::Hybrid { curve: curve_sec, mlkem: mlkem_sec },
        }
    }
}

impl Cborable for BoxingKeyPair {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![self.public.to_cbor(), self.secret.to_cbor()])
    }
}

fn curve_cbor(key: &[u8; 32]) -> CborObject {
    CborObject::List(vec![CborObject::Long(CURVE25519), CborObject::ByteString(key.to_vec())])
}

fn hybrid_cipher_cbor(curve_ct: &[u8], mlkem_ct: &[u8], encrypted: &[u8], nonce: &[u8]) -> CborObject {
    CborObject::map()
        .put("c", CborObject::ByteString(curve_ct.to_vec()))
        .put("m", CborObject::ByteString(mlkem_ct.to_vec()))
        .put("i", CborObject::ByteString(encrypted.to_vec()))
        .put("n", CborObject::ByteString(nonce.to_vec()))
        .build()
}

/// Curve25519 unbox: the trailing `BOX_NONCE_BYTES` are the nonce (Peergos
/// appends it), the rest is the boxed `mac || ciphertext`.
fn curve_unbox(cipher: &[u8], their_public: &[u8], our_secret: &[u8]) -> Result<Vec<u8>> {
    if cipher.len() < BOX_NONCE_BYTES {
        return Err(Error::Crypto("curve box ciphertext too short".into()));
    }
    let split = cipher.len() - BOX_NONCE_BYTES;
    let (boxed, nonce) = cipher.split_at(split);
    Ok(prim::crypto_box_open(boxed, nonce, their_public, our_secret)?)
}
