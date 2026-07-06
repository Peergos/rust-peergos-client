//! Block Access Tokens (BATs), ported from `peergos.shared.storage.auth`.
//!
//! A BAT is a 32-byte secret used as the secret key in an AWS S3 V4 signature to
//! authorise retrieving a block. Two read paths exist:
//!   * against a Peergos server: the client just sends the [`BatWithId`] encoded
//!     as a query param (`&bat=`) and the server does the S3 signing.
//!   * direct to S3-compatible storage: the client itself computes the SigV4
//!     signature ([`Bat::generate_auth`]) and sends it as `&auth=`.

use crate::error::{Error, Result};
use peergos_cbor::{CborObject, Cborable};
use peergos_crypto::hash::{hmac_sha256, sha256};
use peergos_multiformats::bases::{base16_encode, multibase_decode, multibase_encode_base58btc};
use peergos_multiformats::{Cid, Codec, MultihashType, CID_V1};
use std::time::{SystemTime, UNIX_EPOCH};

pub const BAT_LENGTH: usize = 32;
const S3_REGION: &str = "eu-central-1";
const AWS_ALGORITHM: &str = "AWS4-HMAC-SHA256";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// A block access token: a 32-byte secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Bat {
    pub secret: Vec<u8>,
}

impl Bat {
    pub fn new(secret: Vec<u8>) -> Result<Bat> {
        if secret.len() != BAT_LENGTH {
            return Err(Error::Protocol(format!("Invalid BAT length: {}", secret.len())));
        }
        Ok(Bat { secret })
    }

    /// Multibase base58btc of the raw secret.
    pub fn encode_secret(&self) -> String {
        multibase_encode_base58btc(&self.secret)
    }

    pub fn from_string(encoded: &str) -> Result<Bat> {
        Bat::new(multibase_decode(encoded)?)
    }

    /// `calculateId`: raw-codec sha256 CID of the BAT's cbor bytes.
    pub fn calculate_id(&self) -> Result<BatId> {
        let hash = sha256(&self.serialize());
        Ok(BatId::new(Cid::new(CID_V1, Codec::Raw, MultihashType::Sha2_256, hash)?))
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<Bat> {
        let s = cbor
            .get("s")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("Incorrect cbor for Bat".into()))?;
        Bat::new(s.to_vec())
    }

    /// `generateAuth`: compute the S3 V4 signature authorising a GET of `block`
    /// from `source_node`, producing a [`BlockAuth`]. `datetime` must be the
    /// 16-char AWS format `YYYYMMDDThhmmssZ`.
    pub fn generate_auth(
        &self,
        block: &Cid,
        source_node: &Cid,
        expiry_seconds: i64,
        datetime: &str,
        bat_id: &Cid,
    ) -> Result<BlockAuth> {
        if bat_id.multihash.is_identity() {
            return Err(Error::Protocol(
                "Cannot use identity multihash in S3 signatures!".into(),
            ));
        }
        let host = source_node.bare_multihash().to_base58();
        let key = format!("api/v0/block/get?arg={}", block.to_base58());
        let signature_hex = block_get_signature(&host, &key, datetime, &self.encode_secret());
        let signature = peergos_multiformats::bases::base16_decode(&signature_hex)?;
        BlockAuth::new(signature, expiry_seconds, datetime.to_string(), bat_id.clone())
    }
}

impl Cborable for Bat {
    fn to_cbor(&self) -> CborObject {
        CborObject::map().put("s", CborObject::ByteString(self.secret.clone())).build()
    }
}

/// A `BatId` identifies a BAT: an inline (identity) or sha256 raw CID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BatId {
    pub id: Cid,
}

impl BatId {
    pub fn new(id: Cid) -> BatId {
        BatId { id }
    }

    pub fn is_inline(&self) -> bool {
        self.id.multihash.is_identity()
    }

    pub fn get_inline(&self) -> Option<Bat> {
        if self.is_inline() {
            Bat::new(self.id.get_hash().to_vec()).ok()
        } else {
            None
        }
    }

    /// `BatId.inline`: an identity raw CID embedding the secret.
    pub fn inline(bat: &Bat) -> Result<BatId> {
        Ok(BatId::new(Cid::new(
            CID_V1,
            Codec::Raw,
            MultihashType::Id,
            bat.secret.clone(),
        )?))
    }

    /// `BatId.sha256`: a raw sha256 CID of the secret.
    pub fn sha256(bat: &Bat) -> Result<BatId> {
        Ok(BatId::new(Cid::new(
            CID_V1,
            Codec::Raw,
            MultihashType::Sha2_256,
            sha256(&bat.secret),
        )?))
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<BatId> {
        let bytes = cbor
            .as_bytes()
            .ok_or_else(|| Error::Cbor("Incorrect cbor for BatId".into()))?;
        Ok(BatId::new(Cid::cast(bytes)?))
    }
}

impl Cborable for BatId {
    fn to_cbor(&self) -> CborObject {
        CborObject::ByteString(self.id.to_bytes())
    }
}

/// A BAT together with the id the server knows it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatWithId {
    pub bat: Bat,
    pub id: Cid,
}

impl BatWithId {
    pub fn new(bat: Bat, id: Cid) -> Result<BatWithId> {
        if id.multihash.is_identity() {
            return Err(Error::Protocol("Cannot use identity cid here!".into()));
        }
        if id.codec != Codec::Raw {
            return Err(Error::Protocol("BatId codec must be Raw!".into()));
        }
        Ok(BatWithId { bat, id })
    }

    pub fn id(&self) -> BatId {
        BatId::new(self.id.clone())
    }

    /// The `&bat=` query value: multibase base58btc of the cbor.
    pub fn encode(&self) -> String {
        multibase_encode_base58btc(&self.serialize())
    }

    pub fn decode(input: &str) -> Result<BatWithId> {
        BatWithId::from_cbor(&CborObject::from_bytes(&multibase_decode(input)?)?)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<BatWithId> {
        let bat = cbor
            .get("b")
            .ok_or_else(|| Error::Cbor("Incorrect cbor for BatWithId".into()))
            .and_then(Bat::from_cbor)?;
        let id_bytes = cbor
            .get("i")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing 'i' in BatWithId".into()))?;
        BatWithId::new(bat, Cid::cast(id_bytes)?)
    }
}

impl Cborable for BatWithId {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("b", self.bat.to_cbor())
            .put("i", CborObject::ByteString(self.id.to_bytes()))
            .build()
    }
}

/// The result of signing a block read: sent as the `&auth=` query value on the
/// direct-S3 path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockAuth {
    pub signature: Vec<u8>,
    pub expiry_seconds: i64,
    pub aws_datetime: String,
    pub bat_id: Cid,
}

impl BlockAuth {
    pub fn new(signature: Vec<u8>, expiry_seconds: i64, aws_datetime: String, bat_id: Cid) -> Result<BlockAuth> {
        if bat_id.multihash.is_identity() {
            return Err(Error::Protocol("Cannot inline BAT in auth!".into()));
        }
        Ok(BlockAuth { signature, expiry_seconds, aws_datetime, bat_id })
    }

    /// The `&auth=` query value: hex of the cbor.
    pub fn encode(&self) -> String {
        base16_encode(&self.serialize())
    }

    pub fn from_string(input: &str) -> Result<BlockAuth> {
        if input.is_empty() {
            return Err(Error::Protocol("Empty block auth string!".into()));
        }
        BlockAuth::from_cbor(&CborObject::from_bytes(
            &peergos_multiformats::bases::base16_decode(input)?,
        )?)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<BlockAuth> {
        let signature = cbor
            .get("s")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing 's' in BlockAuth".into()))?
            .to_vec();
        let expiry = cbor
            .get("e")
            .and_then(|c| c.as_long())
            .ok_or_else(|| Error::Cbor("missing 'e' in BlockAuth".into()))?;
        let packed = cbor
            .get("t")
            .and_then(|c| c.as_long())
            .ok_or_else(|| Error::Cbor("missing 't' in BlockAuth".into()))?;
        let bat_id_bytes = cbor
            .get("b")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("missing 'b' in BlockAuth".into()))?;
        BlockAuth::new(signature, expiry, packed_long_to_time(packed), Cid::cast(bat_id_bytes)?)
    }
}

impl Cborable for BlockAuth {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("e", CborObject::Long(self.expiry_seconds))
            .put("t", CborObject::Long(time_to_packed_long(&self.aws_datetime)))
            .put("b", CborObject::ByteString(self.bat_id.to_bytes()))
            .put("s", CborObject::ByteString(self.signature.clone()))
            .build()
    }
}

/// Pack an AWS datetime `YYYYMMDDThhmmssZ` into a long (`timeToPackedLong`).
fn time_to_packed_long(t: &str) -> i64 {
    let p = |a: usize, b: usize| t[a..b].parse::<i64>().unwrap_or(0);
    let year = p(0, 4) - 2000;
    let month = p(4, 6);
    let day = p(6, 8);
    let hour = p(9, 11);
    let minute = p(11, 13);
    let second = p(13, 15);
    second | (minute << 6) | (hour << 12) | (day << 17) | (month << 22) | (year << 26)
}

fn packed_long_to_time(packed: i64) -> String {
    let year = (packed >> 26) + 2000;
    let month = (packed >> 22) & 0xF;
    let day = (packed >> 17) & 0x1F;
    let hour = (packed >> 12) & 0x1F;
    let minute = (packed >> 6) & 0x3F;
    let second = packed & 0x3F;
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// Compute the AWS SigV4 signature (hex) for the specific block-GET request that
/// `generateAuth` builds (header-auth GET, UNSIGNED payload, no query params).
fn block_get_signature(host: &str, key: &str, datetime: &str, s3_secret_key: &str) -> String {
    let short_date = &datetime[0..8];
    let canonical_request = format!(
        "GET\n/{key}\n\nhost:{host}\nx-amz-content-sha256:{UNSIGNED_PAYLOAD}\nx-amz-date:{datetime}\n\nhost;x-amz-content-sha256;x-amz-date\n{UNSIGNED_PAYLOAD}"
    );
    let scope = format!("{short_date}/{S3_REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "{AWS_ALGORITHM}\n{datetime}\n{scope}\n{}",
        base16_encode(&sha256(canonical_request.as_bytes()))
    );
    let date_key = hmac_sha256(format!("AWS4{s3_secret_key}").as_bytes(), short_date.as_bytes());
    let date_region_key = hmac_sha256(&date_key, S3_REGION.as_bytes());
    let date_region_service_key = hmac_sha256(&date_region_key, b"s3");
    let signing_key = hmac_sha256(&date_region_service_key, b"aws4_request");
    let signature = hmac_sha256(&signing_key, string_to_sign.as_bytes());
    base16_encode(&signature)
}

/// `S3Request.currentDatetime`: current UTC time as `YYYYMMDDThhmmssZ`.
pub fn current_datetime() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = civil_from_epoch_secs(secs);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// Convert unix seconds to civil UTC (Howard Hinnant's algorithm).
fn civil_from_epoch_secs(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mm, ss)
}
