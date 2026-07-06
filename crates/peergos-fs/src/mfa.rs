//! Multi-factor authentication for login, ported from `peergos.shared.login.mfa`.
//!
//! When the server has a second factor enabled, `login/getLogin` returns a
//! [`MultiFactorAuthRequest`] instead of the encrypted login data. The client
//! answers with a [`MultiFactorAuthResponse`] — for TOTP, the current 6-digit
//! code — and retries `getLogin` with it.
//!
//! TOTP here is RFC 6238 with the Google-Authenticator-compatible parameters that
//! Peergos fixes (`TotpKey.ALGORITHM = HmacSHA1`, 6 digits, 30-second step).

use peergos_cbor::CborObject;
use peergos_core::error::{Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// A registered second factor (`MultiFactorAuthMethod`).
#[derive(Debug, Clone)]
pub struct MultiFactorAuthMethod {
    pub name: String,
    pub credential_id: Vec<u8>,
    /// Days since the Unix epoch (`LocalDate.toEpochDay`).
    pub created_epoch_day: i64,
    pub kind: MfaType,
    pub enabled: bool,
}

/// The type of a second factor (`MultiFactorAuthMethod.Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaType {
    Totp,
    Webauthn,
    Unknown(i64),
}

impl MfaType {
    fn from_value(v: i64) -> MfaType {
        match v {
            0x1 => MfaType::Totp,
            0x2 => MfaType::Webauthn,
            other => MfaType::Unknown(other),
        }
    }
}

impl MultiFactorAuthMethod {
    pub fn from_cbor(cbor: &CborObject) -> Result<MultiFactorAuthMethod> {
        Ok(MultiFactorAuthMethod {
            name: cbor.get("n").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            credential_id: cbor
                .get("i")
                .and_then(|c| c.as_bytes())
                .ok_or_else(|| Error::Cbor("MultiFactorAuthMethod missing 'i'".into()))?
                .to_vec(),
            created_epoch_day: cbor.get("c").and_then(|c| c.as_long()).unwrap_or(0),
            kind: MfaType::from_value(
                cbor.get("t")
                    .and_then(|c| c.as_long())
                    .ok_or_else(|| Error::Cbor("MultiFactorAuthMethod missing 't'".into()))?,
            ),
            enabled: cbor.get("e").and_then(|c| c.as_bool()).unwrap_or(false),
        })
    }
}

/// The server's challenge for a second factor (`MultiFactorAuthRequest`).
#[derive(Debug, Clone)]
pub struct MultiFactorAuthRequest {
    pub methods: Vec<MultiFactorAuthMethod>,
    pub challenge: Vec<u8>,
}

impl MultiFactorAuthRequest {
    pub fn from_cbor(cbor: &CborObject) -> Result<MultiFactorAuthRequest> {
        let methods = cbor
            .get("m")
            .and_then(|c| c.as_list())
            .ok_or_else(|| Error::Cbor("MultiFactorAuthRequest missing 'm'".into()))?
            .iter()
            .map(MultiFactorAuthMethod::from_cbor)
            .collect::<Result<Vec<_>>>()?;
        let challenge = cbor.get("c").and_then(|c| c.as_bytes()).unwrap_or(&[]).to_vec();
        Ok(MultiFactorAuthRequest { methods, challenge })
    }

    /// The first enabled TOTP factor, if any.
    pub fn totp_method(&self) -> Option<&MultiFactorAuthMethod> {
        self.methods.iter().find(|m| m.kind == MfaType::Totp && m.enabled)
    }
}

/// A client's answer to a [`MultiFactorAuthRequest`] (`MultiFactorAuthResponse`).
/// Only the TOTP variant (a numeric code) is supported here.
#[derive(Debug, Clone)]
pub struct MultiFactorAuthResponse {
    pub credential_id: Vec<u8>,
    pub code: String,
}

impl MultiFactorAuthResponse {
    pub fn totp(credential_id: Vec<u8>, code: String) -> MultiFactorAuthResponse {
        MultiFactorAuthResponse { credential_id, code }
    }

    /// `{"i": credentialId, "r": code}` — the TOTP form (`response = Either.a(code)`).
    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("i", CborObject::ByteString(self.credential_id.clone()))
            .put("r", CborObject::Str(self.code.clone()))
            .build()
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.to_cbor().to_bytes()
    }
}

/// A TOTP shared secret returned by the server when enrolling (`TotpKey`), encoded
/// as `base32(credentialId):base32(key)`.
#[derive(Debug, Clone)]
pub struct TotpKey {
    pub credential_id: Vec<u8>,
    pub key: Vec<u8>,
}

impl TotpKey {
    /// Parse the server's `credentialId:key` base32 encoding (`TotpKey.fromString`).
    pub fn from_string(encoded: &str) -> Result<TotpKey> {
        let (cred_b32, key_b32) = encoded
            .split_once(':')
            .ok_or_else(|| Error::Protocol("invalid TotpKey encoding (no ':')".into()))?;
        let credential_id = peergos_multiformats::bases::base32_decode(cred_b32)
            .map_err(|e| Error::Protocol(format!("invalid TotpKey credential base32: {e}")))?;
        let key = peergos_multiformats::bases::base32_decode(key_b32)
            .map_err(|e| Error::Protocol(format!("invalid TotpKey key base32: {e}")))?;
        Ok(TotpKey { credential_id, key })
    }

    /// `base32(credentialId):base32(key)` (`TotpKey.encode`).
    pub fn encode(&self) -> String {
        format!(
            "{}:{}",
            peergos_multiformats::bases::base32_encode(&self.credential_id),
            peergos_multiformats::bases::base32_encode(&self.key),
        )
    }

    /// The `otpauth://` provisioning URI for authenticator apps (`getQRCode`).
    pub fn otpauth_uri(&self, username: &str) -> String {
        let issuer = "peergos";
        let secret = peergos_multiformats::bases::base32_encode(&self.key);
        format!(
            "otpauth://totp/{issuer}:{username}@peergos?secret={secret}&issuer={issuer}",
        )
    }

    /// The current TOTP code for this key.
    pub fn current_code(&self) -> String {
        generate_totp(&self.key, now_seconds())
    }
}

/// The TOTP time step in seconds (Google Authenticator default).
const TOTP_STEP_SECONDS: u64 = 30;
/// Number of digits in a TOTP code.
const TOTP_DIGITS: u32 = 6;

fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Generate an RFC 6238 TOTP code (HMAC-SHA1, `TOTP_DIGITS` digits, `TOTP_STEP_SECONDS`
/// step, T0 = 0) for `secret` at `unix_seconds`. Matches Peergos/Google Authenticator.
pub fn generate_totp(secret: &[u8], unix_seconds: u64) -> String {
    let counter = unix_seconds / TOTP_STEP_SECONDS;
    hotp(secret, counter)
}

/// The current TOTP code for `secret`.
pub fn current_totp(secret: &[u8]) -> String {
    generate_totp(secret, now_seconds())
}

/// RFC 4226 HOTP over HMAC-SHA1 with dynamic truncation to `TOTP_DIGITS` digits.
fn hotp(secret: &[u8], counter: u64) -> String {
    let mac = peergos_crypto::hash::hmac_sha1(secret, &counter.to_be_bytes());
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    let modulus = 10u32.pow(TOTP_DIGITS);
    format!("{:0width$}", bin % modulus, width = TOTP_DIGITS as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors use an 8-, 20- or 32-byte ASCII secret and
    // SHA1; the classic SHA1 vector: secret "12345678901234567890".
    #[test]
    fn rfc6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        // (unix_time, expected 8-digit code) — we take the last 6 digits.
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (t, expected8) in cases {
            let want6 = &expected8[expected8.len() - 6..];
            assert_eq!(generate_totp(secret, t), want6, "TOTP mismatch at t={t}");
        }
    }

    #[test]
    fn totp_key_roundtrip() {
        let k = TotpKey { credential_id: vec![1, 2, 3, 4], key: b"12345678901234567890".to_vec() };
        let reparsed = TotpKey::from_string(&k.encode()).unwrap();
        assert_eq!(reparsed.credential_id, k.credential_id);
        assert_eq!(reparsed.key, k.key);
    }
}
