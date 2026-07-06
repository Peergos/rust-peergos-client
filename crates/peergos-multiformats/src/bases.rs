//! Base encodings and multibase, ported from `peergos.shared.io.ipfs.bases`.
//! Only the encodings Peergos actually uses for CIDs/peer-ids are implemented:
//! base16, base32 (RFC 4648, no padding), and base58btc.

use crate::MfError;

// ---- base58 (bitcoinj port) ------------------------------------------------

const B58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58_index(c: u8) -> i32 {
    if c >= 128 {
        return -1;
    }
    for (i, &a) in B58_ALPHABET.iter().enumerate() {
        if a == c {
            return i as i32;
        }
    }
    -1
}

/// `number` holds base-`base` digits; divide in place by `divisor`, return remainder.
fn divmod(number: &mut [u8], first_digit: usize, base: u32, divisor: u32) -> u8 {
    let mut remainder: u32 = 0;
    for d in number.iter_mut().skip(first_digit) {
        let digit = *d as u32;
        let temp = remainder * base + digit;
        *d = (temp / divisor) as u8;
        remainder = temp % divisor;
    }
    remainder as u8
}

pub fn base58_encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let mut zeros = 0;
    while zeros < input.len() && input[zeros] == 0 {
        zeros += 1;
    }
    let mut input = input.to_vec();
    let mut encoded = vec![0u8; input.len() * 2];
    let mut output_start = encoded.len();
    let mut input_start = zeros;
    while input_start < input.len() {
        output_start -= 1;
        encoded[output_start] = B58_ALPHABET[divmod(&mut input, input_start, 256, 58) as usize];
        if input[input_start] == 0 {
            input_start += 1;
        }
    }
    while output_start < encoded.len() && encoded[output_start] == B58_ALPHABET[0] {
        output_start += 1;
    }
    let mut z = zeros;
    while z > 0 {
        output_start -= 1;
        encoded[output_start] = B58_ALPHABET[0];
        z -= 1;
    }
    String::from_utf8(encoded[output_start..].to_vec()).unwrap()
}

pub fn base58_decode(input: &str) -> Result<Vec<u8>, MfError> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = input.as_bytes();
    let mut input58 = vec![0u8; bytes.len()];
    for (i, &c) in bytes.iter().enumerate() {
        let digit = b58_index(c);
        if digit < 0 {
            return Err(MfError("InvalidCharacter in base 58".into()));
        }
        input58[i] = digit as u8;
    }
    let mut zeros = 0;
    while zeros < input58.len() && input58[zeros] == 0 {
        zeros += 1;
    }
    let mut decoded = vec![0u8; bytes.len()];
    let mut output_start = decoded.len();
    let mut input_start = zeros;
    while input_start < input58.len() {
        output_start -= 1;
        decoded[output_start] = divmod(&mut input58, input_start, 58, 256);
        if input58[input_start] == 0 {
            input_start += 1;
        }
    }
    while output_start < decoded.len() && decoded[output_start] == 0 {
        output_start += 1;
    }
    Ok(decoded[output_start - zeros..].to_vec())
}

// ---- base16 (hex) ----------------------------------------------------------

pub fn base16_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn base16_decode(hex: &str) -> Result<Vec<u8>, MfError> {
    if hex.len() % 2 != 0 {
        return Err(MfError("odd length hex".into()));
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    let hexval = |c: u8| -> Result<u8, MfError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(MfError("invalid hex char".into())),
        }
    };
    for pair in bytes.chunks(2) {
        out.push((hexval(pair[0])? << 4) | hexval(pair[1])?);
    }
    Ok(out)
}

// ---- base32 (RFC 4648, standard alphabet) ----------------------------------

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode without padding, returning UPPERCASE (multibase lowercases as needed).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = (buffer >> bits) & 0x1f;
            out.push(B32_ALPHABET[idx as usize] as char);
        }
    }
    if bits > 0 {
        let idx = (buffer << (5 - bits)) & 0x1f;
        out.push(B32_ALPHABET[idx as usize] as char);
    }
    out
}

fn b32_val(c: u8) -> Result<u32, MfError> {
    match c {
        b'A'..=b'Z' => Ok((c - b'A') as u32),
        b'a'..=b'z' => Ok((c - b'a') as u32),
        b'2'..=b'7' => Ok((c - b'2' + 26) as u32),
        _ => Err(MfError("invalid base32 char".into())),
    }
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>, MfError> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        buffer = (buffer << 5) | b32_val(c)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

// ---- multibase -------------------------------------------------------------

/// Encode as multibase base58btc (prefix `z`) — the form Peergos uses for CIDv1.
pub fn multibase_encode_base58btc(data: &[u8]) -> String {
    let mut s = String::from("z");
    s.push_str(&base58_encode(data));
    s
}

/// Decode a multibase string by its single-character prefix. Supports the
/// encodings Peergos emits for CIDs: base58btc, base16, base32(+upper).
pub fn multibase_decode(data: &str) -> Result<Vec<u8>, MfError> {
    let mut chars = data.chars();
    let prefix = chars.next().ok_or(MfError("empty multibase".into()))?;
    let rest: String = chars.collect();
    match prefix {
        'z' => base58_decode(&rest),
        'f' => base16_decode(&rest),
        'b' => base32_decode(&rest),
        'B' => base32_decode(&rest.to_lowercase()),
        other => Err(MfError(format!("Unsupported multibase prefix: {other}"))),
    }
}
