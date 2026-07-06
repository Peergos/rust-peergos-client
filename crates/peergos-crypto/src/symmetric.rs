//! NaCl `secretbox` (XSalsa20-Poly1305), matching `TweetNaClKey`.
//!
//! Peergos uses the TweetNaCl "easy" wire layout: the 16-byte Poly1305 tag comes
//! FIRST, followed by the ciphertext. RustCrypto's AEAD `encrypt` appends the tag
//! instead, so we use detached mode and assemble `mac || ciphertext` ourselves.

use crate::CryptoError;
use crypto_secretbox::aead::AeadInPlace;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const MAC_BYTES: usize = 16;

fn cipher(key: &[u8]) -> Result<XSalsa20Poly1305, CryptoError> {
    if key.len() != KEY_BYTES {
        return Err(CryptoError(format!("secretbox key must be {KEY_BYTES} bytes")));
    }
    XSalsa20Poly1305::new_from_slice(key).map_err(|e| CryptoError(e.to_string()))
}

/// `secretbox(data, nonce, key)` → `mac || ciphertext`.
pub fn secretbox(data: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_BYTES {
        return Err(CryptoError(format!("nonce must be {NONCE_BYTES} bytes")));
    }
    let c = cipher(key)?;
    let mut buffer = data.to_vec();
    let tag = c
        .encrypt_in_place_detached(nonce.into(), b"", &mut buffer)
        .map_err(|_| CryptoError("secretbox encrypt failed".into()))?;
    let mut out = Vec::with_capacity(MAC_BYTES + buffer.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// `secretbox_open(cipher, nonce, key)` where `cipher = mac || ciphertext`.
pub fn secretbox_open(cipher_bytes: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_BYTES {
        return Err(CryptoError(format!("nonce must be {NONCE_BYTES} bytes")));
    }
    if cipher_bytes.len() < MAC_BYTES {
        return Err(CryptoError("ciphertext shorter than MAC".into()));
    }
    let c = cipher(key)?;
    let (tag, ct) = cipher_bytes.split_at(MAC_BYTES);
    let mut buffer = ct.to_vec();
    c.decrypt_in_place_detached(nonce.into(), b"", &mut buffer, tag.into())
        .map_err(|_| CryptoError("secretbox authentication failed".into()))?;
    Ok(buffer)
}
