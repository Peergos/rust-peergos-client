//! Account migration + mirroring, ported from the corresponding
//! `peergos.shared.user.UserContext` methods and the `HTTPCoreNode` /
//! `HttpAccount` wire protocol:
//!
//!   - [`start_mirror`] (`mirrorOnThisServer`): ask this server to mirror the
//!     user's data, authorised by a signed timestamp + proof-of-work.
//!   - [`get_chain`] + [`build_migration_chain`] + [`migrate_user`]
//!     (`migrateToThisServer`): fetch the username claim chain, append a new link
//!     naming this server as the storage provider, and commit it on this server.
//!
//! `mirrorLoginData` lives in [`crate::login`] since it reuses the login helpers.

use crate::signup::{serialize_bytes, serialize_string};
use peergos_cbor::{Cborable, CborObject};
use peergos_core::auth::BatWithId;
use peergos_core::error::{Error, Result};
use peergos_core::keys::{SecretSigningKey, SigningPrivateKeyAndPublicHash};
use peergos_core::HttpPoster;
use peergos_multiformats::Cid;

const CORE_URL: &str = "peergos/v0/core/";

/// `HTTPCoreNode.getChain`: fetch the username's public-key-link claim chain. Each
/// returned value is a `UserPublicKeyLink` cbor map `{owner, claim}`.
pub async fn get_chain(poster: &dyn HttpPoster, username: &str) -> Result<Vec<CborObject>> {
    let mut body = Vec::new();
    serialize_string(&mut body, username);
    let res = poster.post_unzip(&format!("{CORE_URL}getChain"), body, 0).await?;
    match CborObject::from_bytes(&res)? {
        CborObject::List(items) => Ok(items),
        other => Err(Error::Cbor(format!("Invalid cbor for claim chain: {other:?}"))),
    }
}

/// `HTTPCoreNode.startMirror` (via `UserContext.mirrorOnThisServer`, unpaid path):
/// POST `core/mirror` with the username, mirror BAT, a signed timestamp and a
/// proof-of-work. Returns the server's boolean acknowledgement.
pub async fn start_mirror(
    poster: &dyn HttpPoster,
    username: &str,
    mirror_bat: &BatWithId,
    signer: &SigningPrivateKeyAndPublicHash,
) -> Result<bool> {
    let auth = sign_now(&signer.secret)?;
    // ProofOfWork.MIN_DIFFICULTY is 0, so this is a trivial proof over the username.
    let prefix = peergos_crypto::hash::generate_proof_of_work(0, username.as_bytes());
    let proof = CborObject::map()
        .put("prefix", CborObject::ByteString(prefix))
        .put("type", CborObject::Long(0x12)) // sha2-256
        .build();

    let mut body = Vec::new();
    serialize_string(&mut body, username);
    serialize_bytes(&mut body, &mirror_bat.serialize());
    serialize_bytes(&mut body, &auth);
    serialize_bytes(&mut body, &proof.to_bytes());
    let res = poster.post_unzip(&format!("{CORE_URL}mirror"), body, 0).await?;
    Ok(res.first().copied() == Some(1))
}

/// `HTTPCoreNode.migrateUser`: commit `new_chain` on this server, naming it as the
/// user's storage provider. `original_node_id` is the previous home server (whose
/// data is being migrated). Returns the raw `UserSnapshot` cbor.
#[allow(clippy::too_many_arguments)]
pub async fn migrate_user(
    poster: &dyn HttpPoster,
    username: &str,
    new_chain: &[CborObject],
    original_node_id: &Cid,
    mirror_bat: Option<&BatWithId>,
    latest_link_count_update_epoch_secs: i64,
    current_usage: i64,
) -> Result<CborObject> {
    let mut body = Vec::new();
    serialize_string(&mut body, username);
    serialize_bytes(&mut body, &CborObject::List(new_chain.to_vec()).to_bytes());
    serialize_bytes(&mut body, &original_node_id.to_bytes());
    body.push(if mirror_bat.is_some() { 1 } else { 0 });
    if let Some(bat) = mirror_bat {
        serialize_bytes(&mut body, &bat.serialize());
    }
    body.extend_from_slice(&latest_link_count_update_epoch_secs.to_be_bytes());
    body.extend_from_slice(&current_usage.to_be_bytes());
    body.push(1); // commitToPki
    let res = poster.post_unzip(&format!("{CORE_URL}migrateUser"), body, -1).await?;
    Ok(CborObject::from_bytes(&res)?)
}

/// `Migrate.buildMigrationChain`: replace the last link's claim with a new one that
/// names `new_storage_id` as the sole storage provider, expiring one day later,
/// signed by the identity key. Earlier links are unchanged.
pub fn build_migration_chain(
    existing: &[CborObject],
    new_storage_id: &Cid,
    signer: &SecretSigningKey,
) -> Result<Vec<CborObject>> {
    let last = existing.last().ok_or_else(|| Error::Protocol("empty claim chain".into()))?;
    let owner = last.get("owner").ok_or_else(|| Error::Cbor("chain link missing 'owner'".into()))?.clone();
    let claim = last
        .get("claim")
        .and_then(|c| c.as_list())
        .ok_or_else(|| Error::Cbor("chain link missing 'claim'".into()))?;
    let username = claim.first().and_then(|c| c.as_string()).ok_or_else(|| Error::Cbor("claim missing username".into()))?;
    let expiry = claim.get(1).and_then(|c| c.as_string()).ok_or_else(|| Error::Cbor("claim missing expiry".into()))?;
    let new_expiry = date_plus_days(expiry, 1)?;

    // Claim.build signed payload: serialize(username) + serialize(expiry) +
    // writeInt(providerCount) + serialize(provider) for each provider.
    let mut payload = Vec::new();
    serialize_string(&mut payload, username);
    serialize_string(&mut payload, &new_expiry);
    payload.extend_from_slice(&1u32.to_be_bytes());
    serialize_bytes(&mut payload, &new_storage_id.to_bytes());
    let signed = signer.sign_message(&payload)?;

    let new_claim = CborObject::List(vec![
        CborObject::Str(username.to_string()),
        CborObject::Str(new_expiry),
        CborObject::List(vec![CborObject::ByteString(new_storage_id.to_bytes())]),
        CborObject::ByteString(signed),
    ]);
    let updated_last = CborObject::map().put("owner", owner).put("claim", new_claim).build();

    let mut chain: Vec<CborObject> = existing[..existing.len() - 1].to_vec();
    chain.push(updated_last);
    Ok(chain)
}

/// The first storage-provider id in a chain link's claim (`claim.storageProviders`).
pub fn claim_storage_provider(link: &CborObject) -> Result<Cid> {
    let claim = link
        .get("claim")
        .and_then(|c| c.as_list())
        .ok_or_else(|| Error::Cbor("chain link missing 'claim'".into()))?;
    let providers = claim.get(2).and_then(|c| c.as_list()).ok_or_else(|| Error::Cbor("claim missing storage providers".into()))?;
    let bytes = providers.first().and_then(|c| c.as_bytes()).ok_or_else(|| Error::Cbor("no storage provider in claim".into()))?;
    Ok(Cid::cast(bytes)?)
}

/// `TimeLimitedClient.signNow`: sign `cbor(currentTimeMillis)`, returning the raw
/// NaCl attached signature bytes.
fn sign_now(secret: &SecretSigningKey) -> Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    secret.sign_message(&CborObject::Long(now).to_bytes())
}

// ---- date arithmetic on ISO `YYYY-MM-DD` claim expiries --------------------

/// `LocalDate.plusDays` on an ISO date string.
fn date_plus_days(date: &str, days: i64) -> Result<String> {
    let d = date_to_epoch_days(date).ok_or_else(|| Error::Protocol(format!("invalid claim expiry date: {date}")))?;
    Ok(epoch_days_to_date(d + days))
}

/// ISO `YYYY-MM-DD` → days since the Unix epoch (Howard Hinnant `days_from_civil`).
fn date_to_epoch_days(date: &str) -> Option<i64> {
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Days since the Unix epoch → ISO `YYYY-MM-DD` (`days_to_civil`).
fn epoch_days_to_date(days: i64) -> String {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_roundtrip_and_add() {
        assert_eq!(date_to_epoch_days("1970-01-01"), Some(0));
        assert_eq!(epoch_days_to_date(0), "1970-01-01");
        assert_eq!(date_plus_days("2024-02-28", 1).unwrap(), "2024-02-29"); // leap year
        assert_eq!(date_plus_days("2023-12-31", 1).unwrap(), "2024-01-01");
    }
}
