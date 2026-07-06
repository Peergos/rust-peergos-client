//! Canonical CBOR encoding, ported from `CborEncoder.java`.

use crate::*;

pub(crate) fn write_object(out: &mut Vec<u8>, obj: &CborObject) {
    match obj {
        CborObject::Long(v) => write_int(out, *v),
        CborObject::Boolean(v) => write_simple_type(out, TYPE_FLOAT_SIMPLE, if *v { TRUE } else { FALSE }),
        CborObject::ByteString(b) => write_string(out, TYPE_BYTE_STRING, b),
        CborObject::Str(s) => write_string(out, TYPE_TEXT_STRING, s.as_bytes()),
        CborObject::List(items) => {
            write_type(out, TYPE_ARRAY, items.len() as u64);
            for it in items {
                write_object(out, it);
            }
        }
        CborObject::Map(m) => {
            write_type(out, TYPE_MAP, m.len() as u64);
            // BTreeMap iterates in canonical (CborString) order already.
            for (k, v) in m {
                write_string(out, TYPE_TEXT_STRING, k.as_str().as_bytes());
                write_object(out, v);
            }
        }
        CborObject::MerkleLink(cid) => {
            write_type(out, TYPE_TAG, LINK_TAG);
            // 0x00 multibase-binary prefix, then the raw CID bytes.
            let mut with_prefix = Vec::with_capacity(cid.len() + 1);
            with_prefix.push(0);
            with_prefix.extend_from_slice(cid);
            write_string(out, TYPE_BYTE_STRING, &with_prefix);
        }
        CborObject::Null => write_simple_type(out, TYPE_FLOAT_SIMPLE, NULL),
    }
}

/// `CborEncoder.writeInt` — signed integer as minimal CBOR.
fn write_int(out: &mut Vec<u8>, value: i64) {
    let sign = value >> 63; // 0 or -1 (arithmetic shift)
    let mt = (sign & ((TYPE_NEGATIVE_INTEGER as i64) << 5)) as u8;
    let magnitude = (sign ^ value) as u64;
    write_uint(out, mt, magnitude);
}

fn write_simple_type(out: &mut Vec<u8>, major_type: u8, value: u8) {
    out.push((major_type << 5) | (value & 0x1f));
}

fn write_string(out: &mut Vec<u8>, major_type: u8, bytes: &[u8]) {
    write_type(out, major_type, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_type(out: &mut Vec<u8>, major_type: u8, value: u64) {
    write_uint(out, major_type << 5, value);
}

/// `CborEncoder.writeUInt` — shortest-form length/value encoding.
fn write_uint(out: &mut Vec<u8>, mt: u8, value: u64) {
    if value < 0x18 {
        out.push(mt | value as u8);
    } else if value < 0x100 {
        out.push(mt | ONE_BYTE);
        out.push(value as u8);
    } else if value < 0x10000 {
        out.push(mt | TWO_BYTES);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else if value < 0x1_0000_0000 {
        out.push(mt | FOUR_BYTES);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(mt | EIGHT_BYTES);
        out.push((value >> 56) as u8);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
}
