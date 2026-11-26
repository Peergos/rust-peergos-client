//! ML-DSA-44 (FIPS 204), pure mode with an empty context, matching the Java `Mldsa`
//! providers. Secret keys are the 32 byte seed.

use crate::CryptoError;
use ml_dsa::{EncodedVerifyingKey, Keypair, MlDsa44, Signature, SigningKey, VerifyingKey};

pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 1312;
pub const SIGNATURE_BYTES: usize = 2420;

fn signing_key(seed: &[u8]) -> Result<SigningKey<MlDsa44>, CryptoError> {
    let seed: [u8; SEED_BYTES] = seed
        .try_into()
        .map_err(|_| CryptoError(format!("Invalid ML-DSA-44 seed size: {}", seed.len())))?;
    Ok(SigningKey::from_seed(&seed.into()))
}

pub fn public_key(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(signing_key(seed)?.verifying_key().encode().to_vec())
}

/// A hedged signature, as the JDK makes.
pub fn sign(message: &[u8], seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = signing_key(seed)?;
    let rnd: [u8; 32] = crate::random_bytes(32).try_into().unwrap();
    // M' = 0 || len(ctx) || ctx || M, with an empty ctx
    let sig = key.expanded_key().sign_internal(&[&[0u8, 0u8], message], &rnd.into());
    Ok(sig.encode().to_vec())
}

pub fn verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != SIGNATURE_BYTES || public_key.len() != PUBLIC_KEY_BYTES {
        return false;
    }
    let Ok(enc) = EncodedVerifyingKey::<MlDsa44>::try_from(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::<MlDsa44>::try_from(signature) else {
        return false;
    };
    VerifyingKey::<MlDsa44>::decode(&enc).verify_with_context(message, &[], &sig)
}
