//! MFA login with TOTP, end to end:
//!   1. sign up a fresh account,
//!   2. enrol a TOTP second factor (addTotp + enableTotp with a generated code),
//!   3. show a plain sign-in (no MFA responder) now fails,
//!   4. sign in with the TOTP secret (generating the current code on demand).
//!
//!   cargo run -p peergos-fs --example mfa -- http://localhost:7777/

use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster};
use peergos_fs::UserContext;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> =
        Arc::new(HttpMutablePointers::new(Arc::new(ReqwestPoster::new(&base, false)?)));

    // Fresh account per run so enrollment starts clean.
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let username = format!("mfa{n}");
    let password = "mfa-pass";

    let ctx = UserContext::sign_up(&username, password, None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed up {username:?}");
    println!("second factors before enrol: {}", ctx.list_second_factors().await?.len());

    // Enrol TOTP (addTotp + enableTotp with the current code).
    let key = ctx.enroll_totp().await?;
    println!("enrolled TOTP; otpauth = {}", key.otpauth_uri(&username));
    let methods = ctx.list_second_factors().await?;
    println!("second factors after enrol: {:?}", methods.iter().map(|m| (&m.name, m.kind, m.enabled)).collect::<Vec<_>>());
    assert!(methods.iter().any(|m| m.kind == peergos_fs::MfaType::Totp && m.enabled), "TOTP should be enabled");

    // A plain sign-in (no MFA responder) must now fail — the account requires MFA.
    let plain = UserContext::sign_in(&username, password, None, poster.clone(), store.clone(), mutable.clone()).await;
    println!("\nplain sign-in (no responder) -> {:?}", plain.as_ref().map(|_| ()).map_err(|e| e.to_string()));
    assert!(plain.is_err(), "sign-in without a second factor must be rejected");

    // Sign in with the TOTP secret: the current code is generated on demand.
    let ctx2 = UserContext::sign_in_with_totp(&username, password, &key.key, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("TOTP sign-in succeeded as {:?}", ctx2.username());
    assert_eq!(ctx2.username(), Some(username.as_str()));

    // Prove the session is fully usable: write + read a file.
    let home = ctx2.get_home().await?;
    let f = home.upload("secret.txt", b"unlocked with TOTP").await?;
    assert_eq!(f.read().await?, b"unlocked with TOTP");
    println!("wrote + read a file in the MFA-authenticated session");

    println!("\nMFA/TOTP OK: enrol, plain login rejected, TOTP login accepted, session usable.");
    Ok(())
}
