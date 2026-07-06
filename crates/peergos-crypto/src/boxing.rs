//! NaCl `crypto_box` (Curve25519 + XSalsa20-Poly1305), matching the Java
//! `Curve25519` provider. Same mac-first wire layout as [`crate::symmetric`].

use crate::CryptoError;
use crypto_box::aead::AeadInPlace;
use crypto_box::{PublicKey, SalsaBox, SecretKey};

pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const MAC_BYTES: usize = 16;

fn boxer(their_public: &[u8], our_secret: &[u8]) -> Result<SalsaBox, CryptoError> {
    if their_public.len() != PUBLIC_KEY_BYTES {
        return Err(CryptoError(format!("box public key must be {PUBLIC_KEY_BYTES} bytes")));
    }
    if our_secret.len() != SECRET_KEY_BYTES {
        return Err(CryptoError(format!("box secret key must be {SECRET_KEY_BYTES} bytes")));
    }
    let pk = PublicKey::from(<[u8; 32]>::try_from(their_public).unwrap());
    let sk = SecretKey::from(<[u8; 32]>::try_from(our_secret).unwrap());
    Ok(SalsaBox::new(&pk, &sk))
}

/// `crypto_box(message, nonce, theirPublicKey, ourSecretKey)` → `mac || ciphertext`.
pub fn crypto_box(
    message: &[u8],
    nonce: &[u8],
    their_public: &[u8],
    our_secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_BYTES {
        return Err(CryptoError(format!("nonce must be {NONCE_BYTES} bytes")));
    }
    let b = boxer(their_public, our_secret)?;
    let mut buffer = message.to_vec();
    let tag = b
        .encrypt_in_place_detached(nonce.into(), b"", &mut buffer)
        .map_err(|_| CryptoError("crypto_box encrypt failed".into()))?;
    let mut out = Vec::with_capacity(MAC_BYTES + buffer.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// `crypto_box_open(cipher, nonce, theirPublicKey, ourSecretKey)` where
/// `cipher = mac || ciphertext`.
pub fn crypto_box_open(
    cipher_bytes: &[u8],
    nonce: &[u8],
    their_public: &[u8],
    our_secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_BYTES {
        return Err(CryptoError(format!("nonce must be {NONCE_BYTES} bytes")));
    }
    if cipher_bytes.len() < MAC_BYTES {
        return Err(CryptoError("ciphertext shorter than MAC".into()));
    }
    let b = boxer(their_public, our_secret)?;
    let (tag, ct) = cipher_bytes.split_at(MAC_BYTES);
    let mut buffer = ct.to_vec();
    b.decrypt_in_place_detached(nonce.into(), b"", &mut buffer, tag.into())
        .map_err(|_| CryptoError("crypto_box authentication failed".into()))?;
    Ok(buffer)
}

/// `crypto_box_keypair`: derive the public key from a 32-byte secret.
pub fn public_from_secret(secret: &[u8]) -> Result<[u8; 32], CryptoError> {
    if secret.len() != SECRET_KEY_BYTES {
        return Err(CryptoError(format!("box secret key must be {SECRET_KEY_BYTES} bytes")));
    }
    let sk = SecretKey::from(<[u8; 32]>::try_from(secret).unwrap());
    Ok(*sk.public_key().as_bytes())
}

/// Generate a fresh boxing keypair `(public, secret)` using the OS RNG.
pub fn random_keypair() -> ([u8; 32], [u8; 32]) {
    use rand_core::RngCore;
    let mut sk_bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut sk_bytes);
    let sk = SecretKey::from(sk_bytes);
    let pk = *sk.public_key().as_bytes();
    (pk, sk.to_bytes())
}

/// FIPS-203 ML-KEM-1024 encapsulation-key (public) length.
pub const MLKEM_PUBLIC_KEY_BYTES: usize = 1568;
/// FIPS-203 ML-KEM-1024 decapsulation-key (secret) length.
pub const MLKEM_SECRET_KEY_BYTES: usize = 3168;

/// Generate a fresh FIPS-203 **ML-KEM-1024** keypair, returning the standard
/// encoded `(encapsulation key = public, decapsulation key = secret)` bytes.
/// Matches Peergos' `Mlkem.generateKeyPair` (`ParameterSet.ML_KEM_1024`).
#[allow(deprecated)]
pub fn mlkem_keypair() -> (Vec<u8>, Vec<u8>) {
    use ml_kem::{ExpandedKeyEncoding, Kem, KeyExport, MlKem1024};
    let (dk, ek) = MlKem1024::generate_keypair();
    // Standard FIPS-203 encodings: encapsulation key (1568) + expanded
    // decapsulation key (3168), matching Peergos' stored key bytes.
    (ek.to_bytes().to_vec(), dk.to_expanded_bytes().to_vec())
}

/// ML-KEM-1024 encapsulate: given a peer's encapsulation (public) key bytes,
/// return `(shared_secret, ciphertext)` (`Mlkem.encapsulate`).
pub fn mlkem_encapsulate(encaps_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use ml_kem::array::Array;
    use ml_kem::kem::{Encapsulate, Kem};
    use ml_kem::MlKem1024;
    type Ek = <MlKem1024 as Kem>::EncapsulationKey;
    let key = Array::try_from(encaps_key)
        .map_err(|_| CryptoError("invalid ML-KEM encapsulation key length".into()))?;
    let ek = Ek::new(&key).map_err(|_| CryptoError("invalid ML-KEM encapsulation key".into()))?;
    let (ct, shared) = ek.encapsulate();
    Ok((shared.to_vec(), ct.to_vec()))
}

/// ML-KEM-1024 decapsulate: given a ciphertext and our expanded decapsulation
/// (secret) key bytes, return the shared secret (`Mlkem.decapsulate`).
#[allow(deprecated)]
pub fn mlkem_decapsulate(ciphertext: &[u8], decaps_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ml_kem::array::Array;
    use ml_kem::kem::{Decapsulate, Kem};
    use ml_kem::{ExpandedKeyEncoding, MlKem1024};
    type Dk = <MlKem1024 as Kem>::DecapsulationKey;
    let key = Array::try_from(decaps_key)
        .map_err(|_| CryptoError("invalid ML-KEM decapsulation key length".into()))?;
    let dk = Dk::from_expanded_bytes(&key)
        .map_err(|_| CryptoError("invalid ML-KEM decapsulation key".into()))?;
    let shared = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| CryptoError("invalid ML-KEM ciphertext length".into()))?;
    Ok(shared.to_vec())
}
