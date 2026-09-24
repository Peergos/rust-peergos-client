//! Hashing, HMAC, scrypt login-key derivation and proof-of-work, ported from
//! `ScryptJava`/`Hash`/`ProofOfWork` in the Java client.

use crate::CryptoError;
use blake2::digest::{Update as _, VariableOutput};
use blake2::Blake2bVar;
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params};
use sha2::{Digest, Sha256};

pub const PROOF_OF_WORK_PREFIX_BYTES: usize = 8;

pub fn sha256(input: &[u8]) -> Vec<u8> {
    Sha256::digest(input).to_vec()
}

/// `Hasher.hkdfKey`: derive a 32-byte key from input keying material,
/// `HMAC(HMAC(zeros32, ikm), "peergos" || 0x01)`.
pub fn hkdf_key(ikm: &[u8]) -> Vec<u8> {
    let prk = hmac_sha256(&[0u8; 32], ikm);
    let mut info = b"peergos".to_vec();
    info.push(1);
    hmac_sha256(&prk, &info)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, message);
    mac.finalize().into_bytes().to_vec()
}

/// `HmacSHA1` — the MAC used by TOTP (`TotpKey.ALGORITHM`, fixed to SHA1 for
/// Google Authenticator compatibility).
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    Mac::update(&mut mac, message);
    mac.finalize().into_bytes().to_vec()
}

/// Unkeyed Blake2b with a caller-chosen digest length (`Blake2b.Digest.newInstance(n)`).
pub fn blake2b(input: &[u8], output_bytes: usize) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(output_bytes).expect("valid blake2b output length");
    hasher.update(input);
    let mut out = vec![0u8; output_bytes];
    hasher
        .finalize_variable(&mut out)
        .expect("output buffer sized correctly");
    out
}

pub fn blake3(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}

/// A BLAKE3 chunk, the unit the tree is built from (`Blake3.CHUNK_SIZE`).
pub const BLAKE3_CHUNK_LEN: u64 = blake3::CHUNK_LEN as u64;

/// `Blake3.tailChainingValue`: the chaining value of a piece of a larger input that
/// starts at BLAKE3 chunk `start_chunk`. The piece must be an aligned power of two
/// subtree, or the last piece of the input.
pub fn blake3_chaining_value(input: &[u8], start_chunk: u64) -> Vec<u8> {
    use blake3::hazmat::HasherExt;
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset(start_chunk * BLAKE3_CHUNK_LEN);
    hasher.update(input);
    hasher.finalize_non_root().to_vec()
}

fn to_cv(cv: &[u8]) -> blake3::hazmat::ChainingValue {
    cv.try_into().expect("a chaining value is 32 bytes")
}

/// `Blake3.mergeNonRoot`
pub fn blake3_merge_non_root(left: &[u8], right: &[u8]) -> Vec<u8> {
    blake3::hazmat::merge_subtrees_non_root(&to_cv(left), &to_cv(right), blake3::hazmat::Mode::Hash).to_vec()
}

/// `Blake3.mergeRoot`
pub fn blake3_merge_root(left: &[u8], right: &[u8]) -> Vec<u8> {
    blake3::hazmat::merge_subtrees_root(&to_cv(left), &to_cv(right), blake3::hazmat::Mode::Hash)
        .as_bytes()
        .to_vec()
}

/// BLAKE3 puts the largest power of two on the left, so the split is not pairwise.
fn left_count(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// `Blake3.mergeSubtree`: the chaining value of the subtree whose consecutive pieces
/// have these chaining values.
pub fn blake3_merge_subtree(cvs: &[Vec<u8>]) -> Vec<u8> {
    assert!(!cvs.is_empty(), "A subtree has at least one piece");
    if cvs.len() == 1 {
        return cvs[0].clone();
    }
    let left = left_count(cvs.len());
    blake3_merge_non_root(&blake3_merge_subtree(&cvs[..left]), &blake3_merge_subtree(&cvs[left..]))
}

/// `Blake3.mergeAsRoot`: the hash of a whole input from its pieces' chaining values.
/// A single piece has no merge to finalise, so needs at least two.
pub fn blake3_merge_as_root(cvs: &[Vec<u8>]) -> Vec<u8> {
    assert!(cvs.len() >= 2, "A root merge needs at least two pieces, not {}", cvs.len());
    let left = left_count(cvs.len());
    blake3_merge_root(&blake3_merge_subtree(&cvs[..left]), &blake3_merge_subtree(&cvs[left..]))
}

/// `ScryptJava.hashToKeyBytes`: the password is first SHA-256'd, the salt is the
/// (username + extraSalt) string bytes, and `N = 1 << memory_cost`.
pub fn hash_to_key_bytes(
    salt: &str,
    password: &str,
    memory_cost: u8,
    cpu_cost: u32,
    parallelism: u32,
    output_bytes: usize,
) -> Result<Vec<u8>, CryptoError> {
    let pw_hash = sha256(password.as_bytes());
    // `Params.len` is validated to 10..=64 but unused by `scrypt()`, which
    // derives the output length from the buffer, so Peergos' 96-byte outputs
    // work fine — we pass a placeholder valid `len` and size the buffer ourselves.
    let params = Params::new(memory_cost, cpu_cost, parallelism, 32)
        .map_err(|e| CryptoError(format!("invalid scrypt params: {e}")))?;
    let mut out = vec![0u8; output_bytes];
    scrypt(&pw_hash, salt.as_bytes(), &params, &mut out)
        .map_err(|e| CryptoError(format!("scrypt failed: {e}")))?;
    Ok(out)
}

/// `ProofOfWork.satisfiesDifficulty`, ported verbatim (signed arithmetic like
/// the Java `int` version). Note the partial-byte branch follows the exact
/// production formula, since the server verifies proofs the same way.
pub fn satisfies_difficulty(difficulty: i32, hash: &[u8]) -> bool {
    let mut i: i32 = 0;
    while i < difficulty {
        if i <= difficulty - 8 {
            if hash[(i / 8) as usize] != 0 {
                return false;
            }
        } else {
            let raw = hash[(i / 8) as usize] as i32 & 0xFF;
            return (0xFF & (raw << (8 - difficulty + i))) == 0;
        }
        i += 8;
    }
    true
}

/// `ScryptJava.generateProofOfWork`: brute-force an 8-byte little-endian counter
/// prefix so that `sha256(prefix || data)` meets `difficulty`. Returns the prefix.
pub fn generate_proof_of_work(difficulty: i32, data: &[u8]) -> Vec<u8> {
    let mut combined = vec![0u8; PROOF_OF_WORK_PREFIX_BYTES + data.len()];
    combined[PROOF_OF_WORK_PREFIX_BYTES..].copy_from_slice(data);
    let mut counter: u64 = 0;
    loop {
        let hash = sha256(&combined);
        if satisfies_difficulty(difficulty, &hash) {
            return combined[..PROOF_OF_WORK_PREFIX_BYTES].to_vec();
        }
        counter += 1;
        combined[..PROOF_OF_WORK_PREFIX_BYTES].copy_from_slice(&counter.to_le_bytes());
    }
}
