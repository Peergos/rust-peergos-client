//! Peergos E2E-encrypted email protocol, a faithful port of
//! `peergos.shared.email`.
//!
//! - [`message`] — CBOR wire format for [`EmailMessage`] and [`Attachment`].
//! - [`crypto`] — Curve25519 box encrypt/decrypt via [`SourcedAsymmetricCipherText`].
//! - [`client`] — User-side email client (`EmailClient`).
//! - [`bridge`] — Bridge-side email worker (`EmailBridgeClient`).

pub mod bridge;
pub mod client;
pub mod crypto;
pub mod message;

pub use bridge::EmailBridgeClient;
pub use client::EmailClient;
pub use crypto::SourcedAsymmetricCipherText;
pub use message::{Attachment, EmailMessage, CBOR_PEERGOS_EMAIL_INT};
