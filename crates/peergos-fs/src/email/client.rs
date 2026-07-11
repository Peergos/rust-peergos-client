//! The user-side email client, a faithful port of
//! `peergos.shared.email.EmailClient`.
//!
//! All email data lives under `/$username/.apps/email/data/default/`.  The
//! bridge has write access to `pending/` via a writable secret link; the client
//! encrypts/decrypts with a Curve25519 [`BoxingKeyPair`] stored in
//! `encryption.keypair.cbor`.

use crate::context::UserContext;
use crate::email::crypto::SourcedAsymmetricCipherText;
use crate::email::message::{Attachment, EmailMessage};
use crate::filewrapper::FileWrapper;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::boxing::BoxingKeyPair;
use peergos_core::error::{Error, Result};

const ACCOUNT: &str = "default";
const KEYPAIR_PATH: &str = "encryption.keypair.cbor";
const PUBLIC_KEY_FILENAME: &str = "encryption.publickey.cbor";
const CLIENT_EMAIL_FILENAME: &str = "email.json";

/// Directories created during initialisation (`EmailClient.initialise`).
const DIRS: &[&str] = &[
    "inbox",
    "sent",
    "pending",
    "attachments",
    "pending/inbox",
    "pending/outbox",
    "pending/sent",
    "pending/inbox/attachments",
    "pending/outbox/attachments",
    "pending/sent/attachments",
];

/// The user-side email manager (`EmailClient`).
pub struct EmailClient {
    pub encryption_keys: BoxingKeyPair,
    email_root: FileWrapper,
}

impl EmailClient {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Initialise the email app: create the directory tree, generate a fresh
    /// [`BoxingKeyPair`], and store the public key for the bridge
    /// (`EmailClient.initialise`).
    pub async fn initialise(ctx: &UserContext) -> Result<EmailClient> {
        let home = ctx.get_home().await?;
        let email_root = home.get_or_mkdirs(".apps/email/data").await?;

        // Create all sub-directories.
        for d in DIRS {
            email_root.get_or_mkdirs(&format!("{ACCOUNT}/{d}")).await?;
        }

        let keys = BoxingKeyPair::random_curve25519();

        // Store the full keypair.
        let default_dir = email_root.child(ACCOUNT).await?
            .ok_or_else(|| Error::Protocol("default email dir missing".into()))?;
        default_dir.upload(KEYPAIR_PATH, &keys.to_cbor().to_bytes()).await?;

        // Store the public key for the bridge.
        let pending = default_dir.child("pending").await?
            .ok_or_else(|| Error::Protocol("pending dir missing".into()))?;
        pending.upload(PUBLIC_KEY_FILENAME, &keys.public.to_cbor().to_bytes()).await?;

        Ok(EmailClient { encryption_keys: keys, email_root })
    }

    /// Load an existing email client, or initialise if not yet set up
    /// (`EmailClient.load`).
    pub async fn load(ctx: &UserContext) -> Result<EmailClient> {
        let home = ctx.get_home().await?;
        let email_root = match home.child(".apps/email/data").await? {
            Some(r) => r,
            None => return Self::initialise(ctx).await,
        };
        let default_dir = email_root.child(ACCOUNT).await?
            .ok_or_else(|| Error::Protocol("default email dir missing".into()))?;

        match default_dir.child(KEYPAIR_PATH).await? {
            Some(f) => {
                let bytes = f.read().await?;
                let cbor = CborObject::from_bytes(&bytes)?;
                let keys = BoxingKeyPair::from_cbor(&cbor)?;
                Ok(EmailClient { encryption_keys: keys, email_root })
            }
            None => Self::initialise(ctx).await,
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// The `default` sub-directory of the email root.
    async fn default_dir(&self) -> Result<FileWrapper> {
        self.email_root.child(ACCOUNT).await?
            .ok_or_else(|| Error::Protocol("default email dir missing".into()))
    }

    /// The `pending` sub-directory.
    async fn pending_dir(&self) -> Result<FileWrapper> {
        self.default_dir().await?.child("pending").await?
            .ok_or_else(|| Error::Protocol("pending dir missing".into()))
    }

    /// The `attachments` sub-directory.
    async fn attachments_dir(&self) -> Result<FileWrapper> {
        self.default_dir().await?.child("attachments").await?
            .ok_or_else(|| Error::Protocol("attachments dir missing".into()))
    }

    /// Decrypt a `SourcedAsymmetricCipherText` to an `EmailMessage`.
    async fn decrypt_email(&self, ct: &SourcedAsymmetricCipherText) -> Result<EmailMessage> {
        let bytes = ct.decrypt(&self.encryption_keys.secret)?;
        let cbor = CborObject::from_bytes(&bytes)?;
        EmailMessage::from_cbor(&cbor)
    }

    /// Decrypt a `SourcedAsymmetricCipherText` to raw bytes (for attachments).
    async fn decrypt_attachment(&self, ct: &SourcedAsymmetricCipherText) -> Result<Vec<u8>> {
        ct.decrypt(&self.encryption_keys.secret)
    }

    /// List `.cbor` files in a directory, decrypt each, and return the emails
    /// (`EmailClient.listFiles`).
    async fn list_encrypted_emails(&self, dir: &FileWrapper) -> Result<Vec<EmailMessage>> {
        let children = dir.children().await?;
        let mut emails = Vec::new();
        for child in &children {
            if child.name().ends_with(".cbor") {
                let bytes = child.read().await?;
                let cbor = CborObject::from_bytes(&bytes)?;
                let ct = SourcedAsymmetricCipherText::from_cbor(&cbor)?;
                match self.decrypt_email(&ct).await {
                    Ok(msg) => emails.push(msg),
                    Err(_) => continue,
                }
            }
        }
        Ok(emails)
    }

    /// Write an email message to a folder as a `.cbor` file
    /// (`EmailClient.saveEmail`).
    async fn save_email(&self, folder: &str, msg: &EmailMessage) -> Result<()> {
        let dir = self.default_dir().await?.get_or_mkdirs(folder).await?;
        let filename = format!("{}.cbor", msg.id);
        dir.upload(&filename, &msg.serialize()).await?;
        Ok(())
    }

    /// Move attachments from a pending folder to a private folder, decrypting
    /// any that are wrapped in `SourcedAsymmetricCipherText`.
    async fn move_attachments_to_private(
        &self,
        attachments: &[Attachment],
        pending_folder: &str,
    ) -> Result<()> {
        let default = self.default_dir().await?;
        let private_attachments = default.child("attachments").await?
            .ok_or_else(|| Error::Protocol("attachments dir missing".into()))?;

        for att in attachments {
            let src_path = format!("pending/{pending_folder}/attachments/{}", att.uuid);
            let dest_name = &att.uuid;

            // If the destination already exists, skip.
            if private_attachments.child(dest_name).await?.is_some() {
                continue;
            }

            let src = match self.email_root.get_by_path(&format!("{ACCOUNT}/{src_path}")).await? {
                Some(f) => f,
                None => continue,
            };
            let bytes = src.read().await?;
            let cbor = CborObject::from_bytes(&bytes)?;
            let ct = SourcedAsymmetricCipherText::from_cbor(&cbor)?;
            let decrypted = self.decrypt_attachment(&ct).await?;
            private_attachments.upload(dest_name, &decrypted).await?;

            // Delete the source.
            if let Some(parent_path) = src_path.rsplit_once('/') {
                if let Some(parent) = self.email_root.get_by_path(&format!("{ACCOUNT}/{}", parent_path.0)).await? {
                    let _ = parent.remove_child(dest_name).await;
                }
            }
        }
        Ok(())
    }

    /// Move an email file from a pending path to the private folder, writing
    /// the decrypted CBOR and deleting the original.
    async fn move_to_private_dir(&self, dest_folder: &str, msg: &EmailMessage, src_relative: &str) -> Result<()> {
        let default = self.default_dir().await?;
        let dest = default.get_or_mkdirs(dest_folder).await?;
        let filename = format!("{}.cbor", msg.id);
        dest.upload(&filename, &msg.serialize()).await?;

        // Delete the source file.
        if let Some(parent) = self.email_root.get_by_path(
            &format!("{ACCOUNT}/{}", src_relative.rsplit_once('/').map(|(p, _)| p).unwrap_or("")),
        ).await? {
            let _ = parent.remove_child(&filename).await;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Upload an attachment to the outbox and return its UUID
    /// (`EmailClient.uploadAttachment`).
    pub async fn upload_attachment(&self, data: &[u8]) -> Result<String> {
        let uuid = uuid_v4();
        let pending = self.pending_dir().await?;
        let outbox = pending.get_or_mkdirs("outbox/attachments").await?;
        outbox.upload(&uuid, data).await?;
        Ok(uuid)
    }

    /// Send an email: move forwarded attachments to the outbox and save the
    /// email to `pending/outbox/{id}.cbor` (`EmailClient.send`).
    pub async fn send(&self, msg: &EmailMessage) -> Result<()> {
        // Upload forwarded attachments if present.
        if let Some(fwd) = &msg.forwarding_to_email {
            for att in &fwd.attachments {
                let src_path = format!("{ACCOUNT}/default/attachments/{}", att.uuid);
                if let Some(src) = self.email_root.get_by_path(&src_path).await? {
                    let bytes = src.read().await?;
                    let dest = self.pending_dir().await?.get_or_mkdirs("outbox/attachments").await?;
                    dest.upload(&att.uuid, &bytes).await?;
                }
            }
        }
        self.save_email("pending/outbox", msg).await
    }

    /// Retrieve and decrypt new incoming emails from the bridge
    /// (`EmailClient.getNewIncoming`).
    pub async fn get_new_incoming(&self) -> Result<Vec<EmailMessage>> {
        let pending = self.pending_dir().await?;
        let inbox = pending.child("inbox").await?
            .ok_or_else(|| Error::Protocol("pending/inbox dir missing".into()))?;
        self.list_encrypted_emails(&inbox).await
    }

    /// Retrieve and decrypt sent email confirmations from the bridge
    /// (`EmailClient.getNewSent`).
    pub async fn get_new_sent(&self) -> Result<Vec<EmailMessage>> {
        let pending = self.pending_dir().await?;
        let sent = pending.child("sent").await?
            .ok_or_else(|| Error::Protocol("pending/sent dir missing".into()))?;
        self.list_encrypted_emails(&sent).await
    }

    /// Read an attachment by UUID from the private attachments directory
    /// (`EmailClient.getAttachment`).
    pub async fn get_attachment(&self, uid: &str) -> Result<Vec<u8>> {
        let attachments = self.attachments_dir().await?;
        let file = attachments.child(uid).await?
            .ok_or_else(|| Error::Protocol(format!("attachment {uid} not found")))?;
        file.read().await
    }

    /// Move a received email from `pending/inbox` to the private `inbox`,
    /// decrypting its attachments along the way
    /// (`EmailClient.moveToPrivateInbox`).
    pub async fn move_to_private_inbox(&self, msg: &EmailMessage) -> Result<()> {
        self.move_attachments_to_private(&msg.attachments, "inbox").await?;
        let src = format!("{}/pending/inbox/{}.cbor", ACCOUNT, msg.id);
        self.move_to_private_dir("inbox", msg, &src).await
    }

    /// Move a sent email from `pending/sent` to the private `sent` folder
    /// (`EmailClient.moveToPrivateSent`).
    pub async fn move_to_private_sent(&self, msg: &EmailMessage) -> Result<()> {
        self.move_attachments_to_private(&msg.attachments, "sent").await?;
        let src = format!("{}/pending/sent/{}.cbor", ACCOUNT, msg.id);
        self.move_to_private_dir("sent", msg, &src).await
    }

    /// Read the email address the bridge has written for us
    /// (`EmailClient.getEmailAddress`).
    pub async fn get_email_address(&self) -> Result<Option<String>> {
        let pending = self.pending_dir().await?;
        let file = match pending.child(CLIENT_EMAIL_FILENAME).await? {
            Some(f) => f,
            None => return Ok(None),
        };
        let bytes = file.read().await?;
        // Parse as JSON: {"email": "user@example.com"}
        let text = String::from_utf8(bytes).map_err(|_| Error::Protocol("email.json not UTF-8".into()))?;
        // Simple JSON extraction — the bridge writes `{ "email": "..." }`.
        Ok(parse_email_json(&text))
    }

    /// Create a writable secret link for the `pending` directory so the bridge
    /// can access it (`EmailClient.connectToBridge`).
    pub async fn connect_to_bridge(&self, ctx: &UserContext) -> Result<String> {
        let pending_path = format!("/{}/.apps/email/data/{}/pending",
            ctx.username().ok_or_else(|| Error::Protocol("requires signed-in user".into()))?,
            ACCOUNT);
        ctx.create_secret_link(&pending_path, true, "", None, None).await
    }
}

/// Parse the email address from the bridge's `email.json` (`{"email":"..."}`)
fn parse_email_json(text: &str) -> Option<String> {
    let marker = "\"email\"";
    let key_pos = text.find(marker)?;
    let rest = &text[key_pos + marker.len()..];
    let colon = rest.find(':')?;
    let rest = &rest[colon + 1..];
    let start_quote = rest.find('"')?;
    let rest = &rest[start_quote + 1..];
    let end_quote = rest.find('"')?;
    Some(rest[..end_quote].to_string())
}

/// Generate a random UUID v4 string (hyphenated lowercase).
fn uuid_v4() -> String {
    let bytes = peergos_crypto::random_bytes(16);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        (bytes[6] & 0x0f) | 0x40, bytes[7],
        (bytes[8] & 0x3f) | 0x80, bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_email_json_test() {
        assert_eq!(
            parse_email_json("{ \"email\": \"user@example.com\"}"),
            Some("user@example.com".to_string())
        );
        assert_eq!(parse_email_json("nope"), None);
    }

    #[test]
    fn uuid_v4_format() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(u.chars().nth(14), Some('4')); // version nibble
        assert!(matches!(u.as_bytes()[19], b'8' | b'9' | b'a' | b'b')); // variant bits
    }
}
