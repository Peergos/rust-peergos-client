//! NaCl `crypto_sign` (Ed25519), matching the Java `Ed25519` provider.
//!
//! TweetNaCl uses attached signatures: `crypto_sign` returns `signature(64) ||
//! message`, and the NaCl secret key is `seed(32) || public(32)`.

use crate::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 64; // seed || public
pub const SIGNATURE_BYTES: usize = 64;

/// `crypto_sign(message, secretKey)` → `signature || message`.
pub fn crypto_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret_key.len() != SECRET_KEY_BYTES {
        return Err(CryptoError(format!(
            "signing secret key must be {SECRET_KEY_BYTES} bytes"
        )));
    }
    let seed: [u8; 32] = secret_key[..32].try_into().unwrap();
    let signing = SigningKey::from_bytes(&seed);
    let sig = signing.sign(message);
    let mut out = Vec::with_capacity(SIGNATURE_BYTES + message.len());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// `crypto_sign_open(signed, publicKey)` where `signed = signature || message`;
/// verifies and returns the message.
pub fn crypto_sign_open(signed: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(CryptoError(format!(
            "signing public key must be {PUBLIC_KEY_BYTES} bytes"
        )));
    }
    if signed.len() < SIGNATURE_BYTES {
        return Err(CryptoError("signed message shorter than signature".into()));
    }
    let pk_bytes: [u8; 32] = public_key.try_into().unwrap();
    let verifying =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| CryptoError(e.to_string()))?;
    let (sig_bytes, message) = signed.split_at(SIGNATURE_BYTES);
    let sig = Signature::from_slice(sig_bytes).map_err(|e| CryptoError(e.to_string()))?;
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError("signature verification failed".into()))?;
    Ok(message.to_vec())
}

/// `crypto_sign_keypair` from a 32-byte seed → `(public(32), secret(64) = seed || public)`.
pub fn keypair_from_seed(seed: &[u8]) -> Result<([u8; 32], [u8; 64]), CryptoError> {
    if seed.len() != 32 {
        return Err(CryptoError("signing seed must be 32 bytes".into()));
    }
    let seed_arr: [u8; 32] = seed.try_into().unwrap();
    let signing = SigningKey::from_bytes(&seed_arr);
    let public = signing.verifying_key().to_bytes();
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&seed_arr);
    secret[32..].copy_from_slice(&public);
    Ok((public, secret))
}

/// Generate a fresh signing keypair using the OS RNG.
pub fn random_keypair() -> ([u8; 32], [u8; 64]) {
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    let public = signing.verifying_key().to_bytes();
    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&signing.to_bytes());
    secret[32..].copy_from_slice(&public);
    (public, secret)
}

/// Derive the public signing key from a full 64-byte NaCl secret key.
pub fn public_from_secret(secret_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    if secret_key.len() != SECRET_KEY_BYTES {
        return Err(CryptoError(format!(
            "signing secret key must be {SECRET_KEY_BYTES} bytes"
        )));
    }
    let seed: [u8; 32] = secret_key[..32].try_into().unwrap();
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}
