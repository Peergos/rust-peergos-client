//! CBOR decoding, ported from `CborDecoder.java` + `CborObject.deserialize`.

use crate::*;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborError(pub String);

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cbor error: {}", self.0)
    }
}

impl std::error::Error for CborError {}

fn err<T>(msg: impl Into<String>) -> Result<T, CborError> {
    Err(CborError(msg.into()))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn read_u8(&mut self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError("EOF".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn peek_major(&self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError("EOF".into()))?;
        Ok((b & 0xff) >> 5)
    }

    fn peek_additional(&self) -> Result<u8, CborError> {
        let b = *self.buf.get(self.pos).ok_or(CborError("EOF".into()))?;
        Ok(b & 0x1f)
    }

    fn read_n(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(CborError("EOF".into()))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// `readUInt(length, breakAllowed)` — decode the payload following a
    /// length-indicator into an unsigned value. Break (indefinite) is never
    /// used by Peergos data, so we treat it as an error.
    fn read_uint(&mut self, length: u8) -> Result<u64, CborError> {
        if length < ONE_BYTE {
            Ok(length as u64)
        } else if length == ONE_BYTE {
            Ok(self.read_u8()? as u64)
        } else if length == TWO_BYTES {
            let b = self.read_n(2)?;
            Ok(((b[0] as u64) << 8) | b[1] as u64)
        } else if length == FOUR_BYTES {
            let b = self.read_n(4)?;
            Ok(((b[0] as u64) << 24) | ((b[1] as u64) << 16) | ((b[2] as u64) << 8) | b[3] as u64)
        } else if length == EIGHT_BYTES {
            let b = self.read_n(8)?;
            Ok(((b[0] as u64) << 56)
                | ((b[1] as u64) << 48)
                | ((b[2] as u64) << 40)
                | ((b[3] as u64) << 32)
                | ((b[4] as u64) << 24)
                | ((b[5] as u64) << 16)
                | ((b[6] as u64) << 8)
                | b[7] as u64)
        } else {
            err(format!("invalid cbor length indicator: {length}"))
        }
    }

    /// `readMajorType(expected)` — consume the initial byte, check the major
    /// type, return the low 5 bits (additional info).
    fn read_major_type(&mut self, expected: u8) -> Result<u8, CborError> {
        let ib = self.read_u8()?;
        if expected != ((ib >> 5) & 0x07) {
            return err(format!("unexpected cbor major type {}", (ib >> 5) & 0x07));
        }
        Ok(ib & 0x1f)
    }

    fn read_major_type_with_size(&mut self, expected: u8) -> Result<u64, CborError> {
        let len_indicator = self.read_major_type(expected)?;
        self.read_uint(len_indicator)
    }
}

pub(crate) fn from_bytes(bytes: &[u8]) -> Result<CborObject, CborError> {
    if bytes.is_empty() {
        return err("Empty cbor byte array!");
    }
    let mut r = Reader { buf: bytes, pos: 0 };
    let obj = deserialize(&mut r, bytes.len() as u64)?;
    if r.pos != bytes.len() {
        return err("trailing bytes after cbor value");
    }
    Ok(obj)
}

/// Decode a single cbor value, ignoring any trailing bytes. Mirrors Java's
/// `CborObject.fromByteArray`, which reads one object from a stream and leaves
/// the rest — needed for `PaddedCipherText`, whose plaintext is zero-padded.
pub(crate) fn from_bytes_prefix(bytes: &[u8]) -> Result<CborObject, CborError> {
    if bytes.is_empty() {
        return err("Empty cbor byte array!");
    }
    let mut r = Reader { buf: bytes, pos: 0 };
    deserialize(&mut r, bytes.len() as u64)
}

/// Decode a single cbor value and also report how many bytes it consumed, so a
/// stream of concatenated objects (e.g. a capability store) can be iterated.
pub(crate) fn from_bytes_consumed(bytes: &[u8]) -> Result<(CborObject, usize), CborError> {
    if bytes.is_empty() {
        return err("Empty cbor byte array!");
    }
    let mut r = Reader { buf: bytes, pos: 0 };
    let obj = deserialize(&mut r, bytes.len() as u64)?;
    Ok((obj, r.pos))
}

fn deserialize(r: &mut Reader, max_group_size: u64) -> Result<CborObject, CborError> {
    let major = r.peek_major()?;
    match major {
        TYPE_TEXT_STRING => {
            let len = r.read_major_type_with_size(TYPE_TEXT_STRING)?;
            if len > max_group_size {
                return err("Invalid cbor: text string longer than original bytes!");
            }
            let raw = r.read_n(len as usize)?;
            let s = std::str::from_utf8(raw)
                .map_err(|_| CborError("invalid utf-8 in text string".into()))?;
            Ok(CborObject::Str(s.to_string()))
        }
        TYPE_BYTE_STRING => {
            let len = r.read_major_type_with_size(TYPE_BYTE_STRING)?;
            if len > max_group_size {
                return err("Invalid cbor: byte string longer than original bytes!");
            }
            Ok(CborObject::ByteString(r.read_n(len as usize)?.to_vec()))
        }
        TYPE_UNSIGNED_INTEGER | TYPE_NEGATIVE_INTEGER => Ok(CborObject::Long(read_int(r)?)),
        TYPE_FLOAT_SIMPLE => {
            let additional = r.peek_additional()?;
            match additional {
                NULL => {
                    r.read_u8()?;
                    Ok(CborObject::Null)
                }
                TRUE => {
                    r.read_u8()?;
                    Ok(CborObject::Boolean(true))
                }
                FALSE => {
                    r.read_u8()?;
                    Ok(CborObject::Boolean(false))
                }
                other => err(format!("Unimplemented simple type! {other}")),
            }
        }
        TYPE_MAP => {
            let n = r.read_major_type_with_size(TYPE_MAP)?;
            if n > max_group_size {
                return err("Invalid cbor: more map elements than original bytes!");
            }
            let mut map = BTreeMap::new();
            for _ in 0..n {
                let key = deserialize(r, max_group_size)?;
                let key = match key {
                    CborObject::Str(s) => CborString::new(s),
                    _ => return err("non-string cbor map key"),
                };
                let value = deserialize(r, max_group_size)?;
                if map.insert(key, value).is_some() {
                    return err("Duplicate map key in cbor!");
                }
            }
            Ok(CborObject::Map(map))
        }
        TYPE_ARRAY => {
            let n = r.read_major_type_with_size(TYPE_ARRAY)?;
            if n > max_group_size {
                return err("Invalid cbor: more array elements than original bytes!");
            }
            let mut items = Vec::with_capacity(n as usize);
            for _ in 0..n {
                items.push(deserialize(r, max_group_size)?);
            }
            Ok(CborObject::List(items))
        }
        TYPE_TAG => {
            let len_indicator = r.read_major_type(TYPE_TAG)?;
            let tag = r.read_uint(len_indicator)?;
            if tag != LINK_TAG {
                return err(format!("Unknown TAG in CBOR: {tag}"));
            }
            let value = deserialize(r, max_group_size)?;
            match value {
                CborObject::Str(s) => {
                    // Text CIDs are base-encoded; decoding them needs the
                    // multiformats layer, so surface the bytes as-is is not
                    // possible here — Peergos only writes binary links.
                    err(format!("text merkle link not supported at cbor layer: {s}"))
                }
                CborObject::ByteString(bytes) => {
                    if bytes.first() != Some(&0) {
                        return err(format!(
                            "Unknown Multibase decoding Merkle link: {:?}",
                            bytes.first()
                        ));
                    }
                    Ok(CborObject::MerkleLink(bytes[1..].to_vec()))
                }
                other => err(format!("Invalid type for merkle link: {other:?}")),
            }
        }
        other => err(format!("Unimplemented cbor major type: {other}")),
    }
}

/// `CborDecoder.readInt` — decode major type 0/1 into a signed value.
fn read_int(r: &mut Reader) -> Result<i64, CborError> {
    let ib = r.read_u8()?;
    let major = (ib & 0xff) >> 5;
    if major != TYPE_UNSIGNED_INTEGER && major != TYPE_NEGATIVE_INTEGER {
        return err("expected integer type");
    }
    // ui is 0 for unsigned, -1 for negative; XOR performs the ones-complement.
    let ui = -(major as i64);
    let magnitude = r.read_uint(ib & 0x1f)? as i64;
    Ok(ui ^ magnitude)
}
