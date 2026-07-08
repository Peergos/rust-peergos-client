//! Account second-factor (MFA) management, ported from the `Account` interface
//! (`login/addTotp`, `enableTotp`, `listMfa`, `deleteMfa`). These endpoints are
//! authenticated by a `TimeLimitedClient.SignedRequest` — a cbor `{p: path, t:
//! now_millis}` signed with the account's *identity* key, sent as `&auth=<hex>`.

use crate::login::LoggedInUser;
use crate::mfa::{MultiFactorAuthMethod, MultiFactorAuthResponse, TotpKey};
use peergos_cbor::CborObject;
use peergos_core::error::{Error, Result};
use peergos_core::poster::HttpPoster;
use peergos_core::storage::url_encode;
use std::time::{SystemTime, UNIX_EPOCH};

const LOGIN_URL: &str = "peergos/v0/login/";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// `TimeLimitedClient.SignedRequest`: sign `{p: LOGIN_URL+endpoint, t: now}` with
/// the identity key, returning the hex `auth` the server verifies against the
/// account owner key.
fn signed_auth(user: &LoggedInUser, endpoint: &str) -> Result<String> {
    let path = format!("{LOGIN_URL}{endpoint}");
    let req = CborObject::map().put("p", CborObject::Str(path)).put("t", CborObject::Long(now_millis())).build();
    Ok(to_hex(&user.signer.secret.sign_message(&req.to_bytes())?))
}

fn parse_bool(res: &[u8]) -> Result<bool> {
    CborObject::from_bytes(res)?
        .as_bool()
        .ok_or_else(|| Error::Protocol("expected a boolean response".into()))
}

/// `Account.getSecondAuthMethods` (`listMfa`): the registered second factors.
pub async fn list_second_factors(
    user: &LoggedInUser,
    poster: &dyn HttpPoster,
) -> Result<Vec<MultiFactorAuthMethod>> {
    let auth = signed_auth(user, "listMfa")?;
    let url = format!("{LOGIN_URL}listMfa?username={}&auth={auth}", user.username);
    let res = poster.get(&url).await?;
    CborObject::from_bytes(&res)?
        .as_list()
        .ok_or_else(|| Error::Cbor("listMfa did not return a list".into()))?
        .iter()
        .map(MultiFactorAuthMethod::from_cbor)
        .collect()
}

/// `Account.addTotpFactor` (`addTotp`): enrol a new (not-yet-enabled) TOTP factor,
/// returning its shared secret. Confirm it with [`enable_totp_factor`] and the
/// current code before it becomes active.
pub async fn add_totp_factor(user: &LoggedInUser, poster: &dyn HttpPoster) -> Result<TotpKey> {
    let auth = signed_auth(user, "addTotp")?;
    let url = format!("{LOGIN_URL}addTotp?username={}&auth={auth}", user.username);
    let res = poster.get(&url).await?;
    let encoded = std::str::from_utf8(&res)
        .map_err(|_| Error::Protocol("addTotp returned non-UTF8".into()))?;
    TotpKey::from_string(encoded)
}

/// `Account.enableTotpFactor` (`enableTotp`): activate a TOTP factor by proving the
/// current `code`. Returns whether the code was accepted.
pub async fn enable_totp_factor(
    user: &LoggedInUser,
    credential_id: &[u8],
    code: &str,
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let auth = signed_auth(user, "enableTotp")?;
    let url = format!(
        "{LOGIN_URL}enableTotp?username={}&credid={}&auth={auth}&code={code}",
        user.username,
        to_hex(credential_id),
    );
    parse_bool(&poster.get(&url).await?)
}

/// `Account.deleteSecondFactor` (`deleteMfa`): remove a registered second factor.
pub async fn delete_second_factor(
    user: &LoggedInUser,
    credential_id: &[u8],
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let auth = signed_auth(user, "deleteMfa")?;
    let url = format!(
        "{LOGIN_URL}deleteMfa?username={}&credid={}&auth={auth}",
        user.username,
        to_hex(credential_id),
    );
    parse_bool(&poster.get(&url).await?)
}

/// `Account.registerSecurityKeyStart` (`registerWebauthnStart`): request a
/// WebAuthn registration challenge from the server. Returns the raw 32-byte
/// challenge, which should be passed to `navigator.credentials.create()`.
pub async fn register_security_key_start(
    user: &LoggedInUser,
    poster: &dyn HttpPoster,
) -> Result<Vec<u8>> {
    let auth = signed_auth(user, "registerWebauthnStart")?;
    let url = format!("{LOGIN_URL}registerWebauthnStart?username={}&auth={auth}", user.username);
    poster.get(&url).await
}

/// `Account.registerSecurityKeyComplete` (`registerWebauthnComplete`): submit
/// the WebAuthn credential (wrapped in a [`MultiFactorAuthResponse`]) to
/// complete registration. `key_name` is a human-readable label for the key.
pub async fn register_security_key_complete(
    user: &LoggedInUser,
    key_name: &str,
    response: &MultiFactorAuthResponse,
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let auth = signed_auth(user, "registerWebauthnComplete")?;
    let url = format!(
        "{LOGIN_URL}registerWebauthnComplete?username={}&keyname={}&auth={auth}",
        user.username,
        url_encode(key_name),
    );
    let body = response.serialize();
    parse_bool(&poster.post_unzip(&url, body, 0).await?)
}
