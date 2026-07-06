//! Deterministic CBOR codec, a byte-for-byte port of Peergos' Java
//! `peergos.shared.cbor` package (which is itself derived from JACOB).
//!
//! Blocks in Peergos are content addressed by the hash of their CBOR bytes, so
//! this encoder MUST produce byte-identical output to the Java implementation.
//! The two load-bearing rules are:
//!   * canonical map key ordering: keys are text strings, ordered first by their
//!     UTF-16 length, then lexicographically by UTF-16 code unit (Java
//!     `String.compareTo` semantics — see [`CborString`]).
//!   * minimal ("shortest") integer encoding.
//!
//! Merkle links use tag 42 with a byte string whose first byte is the `0x00`
//! multibase-binary prefix followed by the raw CID bytes. This crate keeps the
//! raw CID bytes opaque ([`CborObject::MerkleLink`]); parsing them into a proper
//! CID lives in `peergos-multiformats`.

use std::collections::BTreeMap;

mod decode;
mod encode;

pub use decode::CborError;

// ---- CBOR constants (see CborConstants.java) -------------------------------

pub(crate) const TYPE_UNSIGNED_INTEGER: u8 = 0x00;
pub(crate) const TYPE_NEGATIVE_INTEGER: u8 = 0x01;
pub(crate) const TYPE_BYTE_STRING: u8 = 0x02;
pub(crate) const TYPE_TEXT_STRING: u8 = 0x03;
pub(crate) const TYPE_ARRAY: u8 = 0x04;
pub(crate) const TYPE_MAP: u8 = 0x05;
pub(crate) const TYPE_TAG: u8 = 0x06;
pub(crate) const TYPE_FLOAT_SIMPLE: u8 = 0x07;

pub(crate) const ONE_BYTE: u8 = 0x18;
pub(crate) const TWO_BYTES: u8 = 0x19;
pub(crate) const FOUR_BYTES: u8 = 0x1a;
pub(crate) const EIGHT_BYTES: u8 = 0x1b;

pub(crate) const FALSE: u8 = 0x14;
pub(crate) const TRUE: u8 = 0x15;
pub(crate) const NULL: u8 = 0x16;

/// The IPLD dag-cbor tag used to mark a Merkle link.
pub const LINK_TAG: u64 = 42;

/// A CBOR map key. In dag-cbor only text strings are used as keys, and Peergos
/// orders them exactly like a Java `TreeMap<CborString>`: by UTF-16 length
/// first, then by UTF-16 code unit sequence. We store the pre-computed UTF-16
/// units so ordering is both correct and cheap.
#[derive(Clone, Debug)]
pub struct CborString {
    value: String,
    utf16: Vec<u16>,
}

impl CborString {
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let utf16 = value.encode_utf16().collect();
        CborString { value, utf16 }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn into_string(self) -> String {
        self.value
    }
}

impl PartialEq for CborString {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl Eq for CborString {}

impl PartialOrd for CborString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CborString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Mirror CborString.compareTo: length difference first, then the
        // natural (UTF-16 code unit) String.compareTo ordering.
        self.utf16
            .len()
            .cmp(&other.utf16.len())
            .then_with(|| self.utf16.cmp(&other.utf16))
    }
}

impl From<&str> for CborString {
    fn from(s: &str) -> Self {
        CborString::new(s)
    }
}
impl From<String> for CborString {
    fn from(s: String) -> Self {
        CborString::new(s)
    }
}

/// A decoded / constructable CBOR value, matching the shapes Peergos uses.
#[derive(Clone, Debug, PartialEq)]
pub enum CborObject {
    /// Major types 0 and 1 (unsigned/negative integers), stored as a signed 64.
    Long(i64),
    Boolean(bool),
    ByteString(Vec<u8>),
    Str(String),
    List(Vec<CborObject>),
    /// Text-keyed map, kept in canonical order.
    Map(BTreeMap<CborString, CborObject>),
    /// Tag 42 Merkle link, holding the raw CID bytes (no multibase prefix).
    MerkleLink(Vec<u8>),
    Null,
}

/// Anything that can be represented as a [`CborObject`], mirroring the Java
/// `Cborable` interface.
pub trait Cborable {
    fn to_cbor(&self) -> CborObject;

    fn serialize(&self) -> Vec<u8> {
        self.to_cbor().to_bytes()
    }
}

impl Cborable for CborObject {
    fn to_cbor(&self) -> CborObject {
        self.clone()
    }
}

impl CborObject {
    /// Encode to canonical CBOR bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode::write_object(&mut out, self);
        out
    }

    /// Decode from CBOR bytes, rejecting trailing garbage and lengths that
    /// exceed the input size (matching the Java `maxGroupSize` guard).
    pub fn from_bytes(bytes: &[u8]) -> Result<CborObject, CborError> {
        decode::from_bytes(bytes)
    }

    /// Decode a single CBOR value, ignoring trailing bytes (Java
    /// `fromByteArray` semantics). Use for zero-padded plaintext from
    /// `PaddedCipherText`.
    pub fn from_bytes_prefix(bytes: &[u8]) -> Result<CborObject, CborError> {
        decode::from_bytes_prefix(bytes)
    }

    /// Decode one CBOR value and report the number of bytes it consumed, for
    /// iterating a stream of concatenated values (e.g. a capability store).
    pub fn from_bytes_consumed(bytes: &[u8]) -> Result<(CborObject, usize), CborError> {
        decode::from_bytes_consumed(bytes)
    }

    /// The list of Merkle links reachable directly from this value (recursing
    /// through maps and arrays), mirroring `CborObject.links()`.
    pub fn links(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.collect_links(&mut out);
        out
    }

    fn collect_links(&self, out: &mut Vec<Vec<u8>>) {
        match self {
            CborObject::MerkleLink(cid) => out.push(cid.clone()),
            CborObject::List(items) => {
                for it in items {
                    it.collect_links(out);
                }
            }
            CborObject::Map(m) => {
                for v in m.values() {
                    v.collect_links(out);
                }
            }
            _ => {}
        }
    }

    // ---- ergonomic constructors --------------------------------------------

    pub fn map() -> CborMapBuilder {
        CborMapBuilder {
            map: BTreeMap::new(),
        }
    }

    // ---- typed accessors (return None on absence / type mismatch) ----------

    pub fn as_map(&self) -> Option<&BTreeMap<CborString, CborObject>> {
        match self {
            CborObject::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[CborObject]> {
        match self {
            CborObject::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_long(&self) -> Option<i64> {
        match self {
            CborObject::Long(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            CborObject::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            CborObject::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborObject::ByteString(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_link(&self) -> Option<&[u8]> {
        match self {
            CborObject::MerkleLink(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, CborObject::Null)
    }

    /// Fetch a value from a map by string key.
    pub fn get(&self, key: &str) -> Option<&CborObject> {
        self.as_map().and_then(|m| m.get(&CborString::new(key)))
    }
}

/// Builder for canonical maps that accepts insertion in any order.
pub struct CborMapBuilder {
    map: BTreeMap<CborString, CborObject>,
}

impl CborMapBuilder {
    pub fn put(mut self, key: &str, value: CborObject) -> Self {
        self.map.insert(CborString::new(key), value);
        self
    }

    /// Insert only if `value` is `Some`, mirroring the many optional fields in
    /// the Peergos data model.
    pub fn put_opt(self, key: &str, value: Option<CborObject>) -> Self {
        match value {
            Some(v) => self.put(key, v),
            None => self,
        }
    }

    pub fn build(self) -> CborObject {
        CborObject::Map(self.map)
    }
}

#[cfg(test)]
mod tests;
