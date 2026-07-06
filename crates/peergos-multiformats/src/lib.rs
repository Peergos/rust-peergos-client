//! Multiformats for Peergos: [`Multihash`] and [`Cid`], ported from
//! `peergos.shared.io.ipfs`. Only the (secure) subset of multihash types
//! Peergos uses is supported.

use std::cmp::Ordering;
use std::fmt;

pub mod bases;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfError(pub String);

impl fmt::Display for MfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "multiformat error: {}", self.0)
    }
}
impl std::error::Error for MfError {}

// ---- unsigned varint (multiformats flavour) --------------------------------

pub fn put_uvarint(out: &mut Vec<u8>, mut x: u64) {
    while x >= 0x80 {
        out.push((x as u8) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
}

/// Read a minimally-encoded uvarint from `buf` at `pos`, advancing `pos`.
pub fn read_uvarint(buf: &[u8], pos: &mut usize) -> Result<u64, MfError> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for i in 0..10 {
        let b = *buf.get(*pos).ok_or(MfError("EOF reading varint".into()))? as i32;
        *pos += 1;
        if b < 0x80 {
            if i == 9 && b > 1 {
                return Err(MfError("Overflow reading varint!".into()));
            } else if b == 0 && s > 0 {
                return Err(MfError("Non minimal varint encoding!".into()));
            }
            return Ok(x | ((b as u64) << s));
        }
        x |= ((b as u64) & 0x7f) << s;
        s += 7;
    }
    Err(MfError("Varint too long!".into()))
}

// ---- Multihash -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MultihashType {
    Id,
    Sha2_256,
    Sha2_512,
    Sha3,
    Blake2b,
    Blake2s,
    Blake3,
}

impl MultihashType {
    /// (multicodec index, expected hash length; -1 == variable for `id`).
    pub fn index(&self) -> u64 {
        match self {
            MultihashType::Id => 0x00,
            MultihashType::Sha2_256 => 0x12,
            MultihashType::Sha2_512 => 0x13,
            MultihashType::Sha3 => 0x14,
            MultihashType::Blake2b => 0x40,
            MultihashType::Blake2s => 0x41,
            MultihashType::Blake3 => 0x1e,
        }
    }

    pub fn length(&self) -> i32 {
        match self {
            MultihashType::Id => -1,
            MultihashType::Sha2_256 => 32,
            MultihashType::Sha2_512 => 64,
            MultihashType::Sha3 => 64,
            MultihashType::Blake2b => 64,
            MultihashType::Blake2s => 32,
            MultihashType::Blake3 => 32,
        }
    }

    pub fn lookup(t: u64) -> Result<MultihashType, MfError> {
        Ok(match t {
            0x00 => MultihashType::Id,
            0x12 => MultihashType::Sha2_256,
            0x13 => MultihashType::Sha2_512,
            0x14 => MultihashType::Sha3,
            0x40 => MultihashType::Blake2b,
            0x41 => MultihashType::Blake2s,
            0x1e => MultihashType::Blake3,
            other => return Err(MfError(format!("Unknown Multihash type: {other}"))),
        })
    }
}

const LEGACY_MAX_IDENTITY_HASH_SIZE: usize = 4112;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Multihash {
    pub hash_type: MultihashType,
    hash: Vec<u8>,
}

impl Multihash {
    pub fn new(hash_type: MultihashType, hash: Vec<u8>) -> Result<Multihash, MfError> {
        if hash.len() > 127 && hash_type != MultihashType::Id {
            return Err(MfError(format!("Unsupported hash size: {}", hash.len())));
        }
        if hash.len() > LEGACY_MAX_IDENTITY_HASH_SIZE {
            return Err(MfError(format!("Unsupported hash size: {}", hash.len())));
        }
        if hash_type != MultihashType::Id && hash.len() as i32 != hash_type.length() {
            return Err(MfError(format!(
                "Incorrect hash length: {} != {}",
                hash.len(),
                hash_type.length()
            )));
        }
        Ok(Multihash { hash_type, hash })
    }

    pub fn is_identity(&self) -> bool {
        self.hash_type == MultihashType::Id
    }

    pub fn get_hash(&self) -> &[u8] {
        &self.hash
    }

    /// `Multihash.decode`: assumes single-byte type and length prefixes.
    pub fn decode(multihash: &[u8]) -> Result<Multihash, MfError> {
        if multihash.len() < 2 {
            return Err(MfError("multihash too short".into()));
        }
        let t = MultihashType::lookup((multihash[0] & 0xff) as u64)?;
        Multihash::new(t, multihash[2..].to_vec())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint(&mut out, self.hash_type.index());
        put_uvarint(&mut out, self.hash.len() as u64);
        out.extend_from_slice(&self.hash);
        out
    }

    /// `deserializeObj`: full varint-prefixed multihash from a byte cursor.
    pub fn deserialize(buf: &[u8], pos: &mut usize) -> Result<Multihash, MfError> {
        let t = read_uvarint(buf, pos)?;
        let len = read_uvarint(buf, pos)? as usize;
        let t = MultihashType::lookup(t)?;
        let end = pos
            .checked_add(len)
            .filter(|e| *e <= buf.len())
            .ok_or(MfError("EOF reading multihash".into()))?;
        let hash = buf[*pos..end].to_vec();
        *pos = end;
        Multihash::new(t, hash)
    }

    pub fn to_base58(&self) -> String {
        bases::base58_encode(&self.to_bytes())
    }

    pub fn from_base58(base58: &str) -> Result<Multihash, MfError> {
        Multihash::decode(&bases::base58_decode(base58)?)
    }
}

impl PartialOrd for Multihash {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Multihash {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash
            .len()
            .cmp(&other.hash.len())
            .then_with(|| {
                // Byte.compare is signed in Java.
                for (a, b) in self.hash.iter().zip(&other.hash) {
                    let c = (*a as i8).cmp(&(*b as i8));
                    if c != Ordering::Equal {
                        return c;
                    }
                }
                Ordering::Equal
            })
            .then_with(|| self.hash_type.index().cmp(&other.hash_type.index()))
    }
}

impl fmt::Display for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

// ---- Cid -------------------------------------------------------------------

pub const CID_V0: u64 = 0;
pub const CID_V1: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    Raw,
    DagProtobuf,
    DagCbor,
    LibP2pKey,
}

impl Codec {
    pub fn code(&self) -> u64 {
        match self {
            Codec::Raw => 0x55,
            Codec::DagProtobuf => 0x70,
            Codec::DagCbor => 0x71,
            Codec::LibP2pKey => 0x72,
        }
    }

    pub fn lookup(c: u64) -> Result<Codec, MfError> {
        Ok(match c {
            0x55 => Codec::Raw,
            0x70 => Codec::DagProtobuf,
            0x71 => Codec::DagCbor,
            0x72 => Codec::LibP2pKey,
            other => return Err(MfError(format!("Unknown Codec type: {other}"))),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cid {
    pub version: u64,
    pub codec: Codec,
    pub multihash: Multihash,
}

impl Cid {
    pub fn new(version: u64, codec: Codec, hash_type: MultihashType, hash: Vec<u8>) -> Result<Cid, MfError> {
        Ok(Cid {
            version,
            codec,
            multihash: Multihash::new(hash_type, hash)?,
        })
    }

    pub fn build(version: u64, codec: Codec, h: &Multihash) -> Cid {
        Cid {
            version,
            codec,
            multihash: h.clone(),
        }
    }

    pub fn build_v0(h: &Multihash) -> Cid {
        Cid::build(CID_V0, Codec::DagProtobuf, h)
    }

    pub fn build_v1(codec: Codec, hash_type: MultihashType, hash: Vec<u8>) -> Result<Cid, MfError> {
        Cid::new(CID_V1, codec, hash_type, hash)
    }

    pub fn is_raw(&self) -> bool {
        self.codec == Codec::Raw
    }

    pub fn hash_type(&self) -> MultihashType {
        self.multihash.hash_type
    }

    pub fn get_hash(&self) -> &[u8] {
        self.multihash.get_hash()
    }

    /// The bare (version-less) multihash.
    pub fn bare_multihash(&self) -> Multihash {
        self.multihash.clone()
    }

    /// Base58btc of the raw CID bytes (`Multihash.toBase58` inherited by `Cid`).
    pub fn to_base58(&self) -> String {
        bases::base58_encode(&self.to_bytes())
    }

    fn to_bytes_v1(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint(&mut out, self.version);
        put_uvarint(&mut out, self.codec.code());
        out.extend_from_slice(&self.multihash.to_bytes());
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self.version {
            CID_V0 => self.multihash.to_bytes(),
            CID_V1 => self.to_bytes_v1(),
            v => panic!("Unknown cid version: {v}"),
        }
    }

    /// `Cid.cast` — decode a CID from its raw binary form (also the payload of a
    /// dag-cbor Merkle link after the multibase prefix is stripped).
    pub fn cast(data: &[u8]) -> Result<Cid, MfError> {
        if data.len() == 34 && data[0] == 18 && data[1] == 32 {
            return Ok(Cid::build_v0(&Multihash::decode(data)?));
        }
        let mut pos = 0;
        let version = read_uvarint(data, &mut pos)?;
        if version != CID_V0 && version != CID_V1 {
            return Err(MfError(format!("Invalid Cid version number: {version}")));
        }
        let codec = read_uvarint(data, &mut pos)?;
        let hash = Multihash::deserialize(data, &mut pos)?;
        Ok(Cid {
            version,
            codec: Codec::lookup(codec)?,
            multihash: hash,
        })
    }

    /// `Cid.decodePeerId` — a libp2p peer id (base58 identity multihash starting
    /// with `1`) or a normal CID string.
    pub fn decode_peer_id(peer_id: &str) -> Result<Cid, MfError> {
        if peer_id.starts_with('1') {
            let hash = Multihash::decode(&bases::base58_decode(peer_id)?)?;
            return Ok(Cid {
                version: CID_V1,
                codec: Codec::LibP2pKey,
                multihash: hash,
            });
        }
        Cid::decode(peer_id)
    }

    /// `Cid.decode` — parse a CID from its string form (legacy `Qm…` v0 or
    /// multibase v1).
    pub fn decode(v: &str) -> Result<Cid, MfError> {
        if v.len() < 2 {
            return Err(MfError("Cid too short!".into()));
        }
        if v.len() == 46 && v.starts_with("Qm") {
            return Ok(Cid::build_v0(&Multihash::from_base58(v)?));
        }
        Cid::cast(&bases::multibase_decode(v)?)
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            CID_V0 => write!(f, "{}", self.multihash.to_base58()),
            CID_V1 => write!(f, "{}", bases::multibase_encode_base58btc(&self.to_bytes_v1())),
            v => panic!("Unknown Cid version: {v}"),
        }
    }
}

#[cfg(test)]
mod tests;
