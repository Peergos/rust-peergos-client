//! File content retrieval, ported from `FragmentedPaddedCipherText` /
//! `EncryptedChunkRetriever`.
//!
//! A file's data is stored as one or more chunks (each ≤ 5 MiB). Each chunk's
//! ciphertext is either inlined in the cryptree node or split across fragment
//! blocks referenced by Merkle links. Currently single-chunk files are
//! supported (inline and fragmented); multi-chunk traversal is a later step.

use peergos_cbor::{CborObject, Cborable};
use peergos_core::auth::{Bat, BatId, BatWithId};
use peergos_core::error::{Error, Result};
use peergos_core::keys::PublicKeyHash;
use peergos_core::storage::{build_cid, ContentAddressedStorage};
use peergos_core::symmetric::{CipherText, SymmetricKey};
use peergos_crypto::hash::sha256;
use peergos_crypto::random_bytes;
use peergos_multiformats::Cid;

/// Max chunk size (`Chunk.MAX_SIZE`).
pub const CHUNK_MAX_SIZE: u64 = 5 * 1024 * 1024;
/// Padding block size for chunk data (`CryptreeNode.MIN_FRAGMENT_SIZE`).
pub const MIN_FRAGMENT_SIZE: usize = 4096;
/// Threshold below which a chunk is inlined rather than fragmented.
pub const INLINE_LIMIT: usize = 4096 + 6;
/// Max bytes per fragment block (`Fragment.MAX_LENGTH`).
pub const FRAGMENT_MAX_LENGTH: usize = 1024 * 1024;

/// `Bat.RAW_BLOCK_MAGIC_PREFIX` — marks a raw block carrying a BAT prefix.
const RAW_BLOCK_MAGIC_PREFIX: [u8; 8] = [0x71, 0x1d, 0x10, 0xcf, 0x3d, 0x32, 0x2f, 0x2b];

/// A chunk's encrypted, fragmented data.
#[derive(Debug, Clone)]
pub struct FragmentedPaddedCipherText {
    pub nonce: Vec<u8>,
    pub header: Option<Vec<u8>>,
    pub fragments: Vec<Cid>,
    pub bats: Vec<BatWithId>,
    pub inlined: Option<Vec<u8>>,
}

impl FragmentedPaddedCipherText {
    pub fn from_cbor(cbor: &CborObject) -> Result<FragmentedPaddedCipherText> {
        let nonce = cbor
            .get("n")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("FragmentedPaddedCipherText missing 'n'".into()))?
            .to_vec();
        let header = cbor.get("h").and_then(|c| c.as_bytes()).map(|b| b.to_vec());
        let f = cbor
            .get("f")
            .and_then(|c| c.as_list())
            .ok_or_else(|| Error::Cbor("FragmentedPaddedCipherText missing 'f'".into()))?;
        let mut fragments = Vec::new();
        let mut inlined = None;
        for item in f {
            match item {
                CborObject::MerkleLink(cid) => fragments.push(Cid::cast(cid)?),
                CborObject::ByteString(b) if inlined.is_none() => inlined = Some(b.clone()),
                _ => {}
            }
        }
        let bats = match cbor.get("bats").and_then(|c| c.as_list()) {
            Some(list) => list.iter().map(BatWithId::from_cbor).collect::<Result<_>>()?,
            None => Vec::new(),
        };
        Ok(FragmentedPaddedCipherText { nonce, header, fragments, bats, inlined })
    }

    pub fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("n", CborObject::ByteString(self.nonce.clone()));
        if let Some(h) = &self.header {
            b = b.put("h", CborObject::ByteString(h.clone()));
        }
        let inline_form = self.inlined.is_some()
            || (self.fragments.len() == 1 && self.fragments[0].multihash.is_identity());
        if inline_form {
            let value = match &self.inlined {
                Some(arr) => vec![CborObject::ByteString(arr.clone())],
                None => self
                    .fragments
                    .iter()
                    .map(|c| CborObject::ByteString(c.get_hash().to_vec()))
                    .collect(),
            };
            b = b.put("f", CborObject::List(value));
        } else {
            b = b.put(
                "f",
                CborObject::List(
                    self.fragments.iter().map(|c| CborObject::MerkleLink(c.to_bytes())).collect(),
                ),
            );
            b = b.put("bats", CborObject::List(self.bats.iter().map(|bat| bat.to_cbor()).collect()));
        }
        b.build()
    }

    /// `FragmentedPaddedCipherText.build`: pad and encrypt `secret`, then either
    /// inline it (≤ ~4 KiB) or split the ciphertext into fragment blocks.
    /// Returns the metadata plus the raw fragment blocks that must be written.
    pub fn build(
        key: &SymmetricKey,
        secret: &CborObject,
        padding_block_size: usize,
        mirror_bat: Option<&BatId>,
    ) -> Result<(FragmentedPaddedCipherText, Vec<Vec<u8>>)> {
        let nonce = SymmetricKey::create_nonce();
        let plain = secret.to_bytes();
        let overhead = if plain.len() <= padding_block_size { 0 } else { 6 };
        let n_blocks = (plain.len() - overhead).div_ceil(padding_block_size);
        let target = n_blocks * padding_block_size + overhead;
        let mut padded = plain;
        padded.resize(target, 0);
        let cipher = key.encrypt(&padded, &nonce)?;

        if padded.len() <= INLINE_LIMIT {
            return Ok((
                FragmentedPaddedCipherText {
                    nonce,
                    header: None,
                    fragments: Vec::new(),
                    bats: Vec::new(),
                    inlined: Some(cipher),
                },
                Vec::new(),
            ));
        }

        // Split into a header (the remainder modulo the padding block) plus
        // fragment blocks; each fragment block carries a raw-block BAT prefix.
        let header_size = cipher.len() % padding_block_size;
        let header = cipher[..header_size].to_vec();
        let mut fragments = Vec::new();
        let mut bats = Vec::new();
        let mut raw_blocks = Vec::new();
        for chunk in cipher[header_size..].chunks(FRAGMENT_MAX_LENGTH) {
            let block_bat = Bat::new(random_bytes(32))?;
            let mut raw = create_raw_block_prefix(&block_bat, mirror_bat)?;
            raw.extend_from_slice(chunk);
            let cid = build_cid(sha256(&raw), true)?;
            let bat_id = block_bat.calculate_id()?.id;
            fragments.push(cid);
            bats.push(BatWithId::new(block_bat, bat_id)?);
            raw_blocks.push(raw);
        }
        Ok((
            FragmentedPaddedCipherText { nonce, header: Some(header), fragments, bats, inlined: None },
            raw_blocks,
        ))
    }

    /// Convenience for callers that only handle inline data.
    pub fn build_inline(
        key: &SymmetricKey,
        secret: &CborObject,
        padding_block_size: usize,
    ) -> Result<FragmentedPaddedCipherText> {
        let (fpct, raw) = FragmentedPaddedCipherText::build(key, secret, padding_block_size, None)?;
        if !raw.is_empty() {
            return Err(Error::Protocol("data too large to inline".into()));
        }
        Ok(fpct)
    }

    /// Download (if needed), reassemble and decrypt this chunk, decoding the
    /// plaintext cbor with `from_cbor`.
    pub async fn get_and_decrypt<T>(
        &self,
        owner: &PublicKeyHash,
        key: &SymmetricKey,
        store: &dyn ContentAddressedStorage,
        from_cbor: impl FnOnce(&CborObject) -> Result<T>,
    ) -> Result<T> {
        let cipher = if let Some(inlined) = &self.inlined {
            match &self.header {
                Some(h) => [h.as_slice(), inlined].concat(),
                None => inlined.clone(),
            }
        } else {
            if self.fragments.len() != self.bats.len() {
                return Err(Error::Protocol("fragment/bat count mismatch".into()));
            }
            let mut frags = Vec::with_capacity(self.fragments.len());
            for (cid, bat) in self.fragments.iter().zip(&self.bats) {
                let raw = store
                    .get_raw(owner, cid, Some(bat))
                    .await?
                    .ok_or_else(|| Error::Protocol(format!("fragment missing: {cid}")))?;
                frags.push(remove_raw_block_bat_prefix(&raw)?);
            }
            recombine(&self.header, &frags)
        };
        CipherText::new(self.nonce.clone(), cipher).decrypt(key, from_cbor)
    }

    /// Decrypt a file chunk into its raw bytes (the plaintext is a `CborByteArray`).
    pub async fn get_and_decrypt_bytes(
        &self,
        owner: &PublicKeyHash,
        data_key: &SymmetricKey,
        store: &dyn ContentAddressedStorage,
    ) -> Result<Vec<u8>> {
        self.get_and_decrypt(owner, data_key, store, |c| {
            c.as_bytes()
                .map(|b| b.to_vec())
                .ok_or_else(|| Error::Cbor("chunk did not decrypt to a byte array".into()))
        })
        .await
    }
}

/// `FileProperties.calculateNextMapKey`: derive the next chunk's map-key (and
/// BAT) from the stream secret and the current one.
pub fn calculate_next_map_key(
    stream_secret: &[u8],
    map_key: &[u8],
    bat: &Option<Bat>,
) -> Result<(Vec<u8>, Option<Bat>)> {
    let next_map_key = sha256(&[stream_secret, map_key].concat());
    let next_bat = match bat {
        Some(b) => Some(Bat::new(sha256(&[stream_secret, &b.secret].concat()))?),
        None => None,
    };
    Ok((next_map_key, next_bat))
}

/// `Bat.createRawBlockPrefix`: the magic prefix followed by a cbor list of the
/// block's BAT ids (inline block BAT, then optional mirror BAT).
fn create_raw_block_prefix(bat: &Bat, mirror_bat: Option<&BatId>) -> Result<Vec<u8>> {
    let mut out = RAW_BLOCK_MAGIC_PREFIX.to_vec();
    let mut bat_ids = vec![BatId::inline(bat)?.to_cbor()];
    if let Some(mb) = mirror_bat {
        bat_ids.push(mb.to_cbor());
    }
    out.extend_from_slice(&CborObject::List(bat_ids).to_bytes());
    Ok(out)
}

/// `Bat.removeRawBlockBatPrefix`: strip the magic prefix + embedded BAT-id cbor.
pub fn remove_raw_block_bat_prefix(block: &[u8]) -> Result<Vec<u8>> {
    if block.len() < RAW_BLOCK_MAGIC_PREFIX.len() || block[..8] != RAW_BLOCK_MAGIC_PREFIX {
        return Ok(block.to_vec());
    }
    let bats_cbor = CborObject::from_bytes_prefix(&block[8..])?;
    let consumed = bats_cbor.to_bytes().len();
    Ok(block[8 + consumed..].to_vec())
}

/// `FragmentedPaddedCipherText.recombine`: header bytes followed by fragments.
fn recombine(header: &Option<Vec<u8>>, frags: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(h) = header {
        out.extend_from_slice(h);
    }
    for f in frags {
        out.extend_from_slice(f);
    }
    out
}
