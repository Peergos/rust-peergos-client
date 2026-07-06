//! Cryptographic primitives for the Peergos client, matching the algorithms and
//! wire formats of the Java `peergos.shared.crypto` providers (which are backed
//! by TweetNaCl / scrypt / Blake2b).
//!
//! Byte-compatibility with the Java implementation is essential: existing
//! accounts and blocks can only be read if key derivation, cipher output and
//! hashing all match exactly. See each module for the specific mapping.
//!
//! Not yet ported: the hybrid Curve25519 + ML-KEM boxing (`Mlkem`), which is a
//! later-phase task.

use std::fmt;

pub mod boxing;
pub mod hash;
pub mod sign;
pub mod symmetric;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError(pub String);

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto error: {}", self.0)
    }
}

impl std::error::Error for CryptoError {}

/// Fill a fresh `n`-byte buffer from the OS RNG (`SafeRandom.randomBytes`).
pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut out = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests;
