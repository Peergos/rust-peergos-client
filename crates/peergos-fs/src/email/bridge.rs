//! Bridge-side email worker, a faithful port of
//! `peergos.server.apps.email.EmailBridgeClient`.
//!
//! The bridge receives a **writable** secret link to the client's `pending/`
//! directory and:
//! 1. Reads the client's public [`PublicBoxingKey`] from
//!    `encryption.publickey.cbor`.
//! 2. Lists / reads the outbox.
//! 3. Encrypts outgoing emails and attachments, then moves them to `sent/`.
//! 4. Uploads incoming attachments and emails into `inbox/`.

use crate::context::UserContext;
use crate::email::crypto::SourcedAsymmetricCipherText;
use crate::email::message::{Attachment, EmailMessage};
use crate::filewrapper::FileWrapper;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::boxing::{BoxingKeyPair, PublicBoxingKey};
use peergos_core::error::{Error, Result};

/// The bridge-side email client (`EmailBridgeClient`).
pub struct EmailBridgeClient {
    pub client_username: String,
    pending: FileWrapper,
    encryption_target: PublicBoxingKey,
}

impl EmailBridgeClient {
    /// Build from a writable secret link that points at the client's
    /// `pending/` directory (`EmailBridgeClient.build`).
    pub async fn build(
        link: &str,
        client_username: String,
        client_email_address: &str,
        poster: std::sync::Arc<dyn peergos_core::poster::HttpPoster>,
        store: std::sync::Arc<dyn peergos_core::storage::ContentAddressedStorage>,
        mutable: std::sync::Arc<dyn peergos_core::mutable::MutablePointers>,
    ) -> Result<Self> {
        let ctx = UserContext::from_secret_link(link, None, poster, store, mutable).await?;

        // Write email.json if absent (the bridge writes the client's email address).
        let pending = ctx.roots().await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("secret link must resolve to a root".into()))?;

        let email_file_path = "email.json";
        if pending.child(email_file_path).await?.is_none() {
            let contents = format!(r#"{{ "email": "{}" }}"#, client_email_address);
            pending.upload(email_file_path, contents.as_bytes()).await?;
        }

        // Read the client's public encryption key.
        let pub_key_file = pending.child("encryption.publickey.cbor").await?
            .ok_or_else(|| Error::Protocol("encryption.publickey.cbor not found in pending".into()))?;
        let pub_key_bytes = pub_key_file.read().await?;
        let pub_key_cbor = CborObject::from_bytes(&pub_key_bytes)?;
        let encryption_target = PublicBoxingKey::from_cbor(&pub_key_cbor)?;

        Ok(EmailBridgeClient { client_username, pending, encryption_target })
    }

    /// The `pending/` root directory.
    fn pending_folder(&self) -> &FileWrapper {
        &self.pending
    }

    /// List filenames in `pending/outbox/` (`EmailBridgeClient.listOutbox`).
    pub async fn list_outbox(&self) -> Result<Vec<String>> {
        let outbox = self.pending_folder().child("outbox").await?
            .ok_or_else(|| Error::Protocol("outbox directory missing".into()))?;
        let children = outbox.children().await?;
        Ok(children
            .iter()
            .filter(|f| !f.is_directory())
            .map(|f| f.name().to_string())
            .collect())
    }

    /// Read an email from `pending/outbox/{filename}`
    /// (`EmailBridgeClient.getPendingEmail`).
    pub async fn get_pending_email(&self, filename: &str) -> Result<(FileWrapper, EmailMessage)> {
        let outbox = self.pending_folder().child("outbox").await?
            .ok_or_else(|| Error::Protocol("outbox directory missing".into()))?;
        let file = outbox.child(filename).await?
            .ok_or_else(|| Error::Protocol(format!("{filename} not found in outbox")))?;
        let bytes = file.read().await?;
        let cbor = CborObject::from_bytes(&bytes)?;
        let msg = EmailMessage::from_cbor(&cbor)?;
        Ok((file, msg))
    }

    /// Read an outgoing attachment from `pending/outbox/attachments/{filename}`
    /// (`EmailBridgeClient.getOutgoingAttachment`).
    pub async fn get_outgoing_attachment(&self, filename: &str) -> Result<Vec<u8>> {
        let outbox = self.pending_folder().child("outbox").await?
            .ok_or_else(|| Error::Protocol("outbox directory missing".into()))?;
        let attachments = outbox.child("attachments").await?
            .ok_or_else(|| Error::Protocol("outbox/attachments missing".into()))?;
        let file = attachments.child(filename).await?
            .ok_or_else(|| Error::Protocol(format!("attachment {filename} not found")))?;
        file.read().await
    }

    /// Encrypt an [`EmailMessage`] with a fresh ephemeral keypair
    /// (`EmailBridgeClient.encryptEmail`).
    fn encrypt_email(&self, msg: &EmailMessage) -> Result<SourcedAsymmetricCipherText> {
        let tmp = BoxingKeyPair::random_curve25519();
        SourcedAsymmetricCipherText::encrypt(&tmp, &self.encryption_target, &msg.serialize())
    }

    /// Encrypt raw attachment bytes (`EmailBridgeClient.encryptAttachment`).
    fn encrypt_attachment(&self, data: &[u8]) -> Result<SourcedAsymmetricCipherText> {
        let tmp = BoxingKeyPair::random_curve25519();
        SourcedAsymmetricCipherText::encrypt(&tmp, &self.encryption_target, data)
    }

    /// Collect all attachment UUIDs from an email (including forwarded ones).
    fn all_attachments(msg: &EmailMessage) -> Vec<&Attachment> {
        let mut atts: Vec<&Attachment> = msg.attachments.iter().collect();
        if let Some(fwd) = &msg.forwarding_to_email {
            atts.extend(fwd.attachments.iter());
        }
        atts
    }

    /// Encrypt and move an email from `outbox/` to `sent/`, moving
    /// attachments along the way (`EmailBridgeClient.encryptAndMoveEmailToSent`).
    pub async fn encrypt_and_move_to_sent(
        &self,
        file: &FileWrapper,
        msg: &EmailMessage,
        attachments_map: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<()> {
        let sent = self.pending_folder().child("sent").await?
            .ok_or_else(|| Error::Protocol("sent directory missing".into()))?;

        // Encrypt and upload the email.
        let ct = self.encrypt_email(msg)?;
        let ct_bytes = ct.to_cbor().to_bytes();
        sent.upload(&file.name(), &ct_bytes).await?;

        // Remove the original from outbox.
        let outbox = self.pending_folder().child("outbox").await?
            .ok_or_else(|| Error::Protocol("outbox missing".into()))?;
        let _ = outbox.remove_child(file.name()).await;

        // Move attachments: encrypt and upload to sent/attachments, then delete from outbox.
        let sent_attachments = sent.get_or_mkdirs("attachments").await?;
        for att in Self::all_attachments(msg) {
            if let Some(bytes) = attachments_map.get(&att.uuid) {
                let ct = self.encrypt_attachment(bytes)?;
                let ct_bytes = ct.to_cbor().to_bytes();
                sent_attachments.upload(&att.uuid, &ct_bytes).await?;

                // Remove from outbox/attachments.
                if let Some(outbox_atts) = outbox.child("attachments").await? {
                    let _ = outbox_atts.remove_child(&att.uuid).await;
                }
            }
        }

        Ok(())
    }

    /// Encrypt an attachment and upload it to `pending/inbox/attachments/`
    /// (`EmailBridgeClient.uploadAttachment`).
    pub async fn upload_attachment(
        &self,
        filename: &str,
        size: i64,
        mime_type: &str,
        data: &[u8],
    ) -> Result<Attachment> {
        let ext = filename.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
        let ct = self.encrypt_attachment(data)?;
        let ct_bytes = ct.to_cbor().to_bytes();

        let uuid = format!("{}.{}", uuid_v4(), ext);

        let inbox = self.pending_folder().child("inbox").await?
            .ok_or_else(|| Error::Protocol("inbox directory missing".into()))?;
        let base_dir = inbox.get_or_mkdirs("attachments").await?;
        base_dir.upload(&uuid, &ct_bytes).await?;

        Ok(Attachment {
            filename: filename.to_string(),
            size,
            mime_type: mime_type.to_string(),
            uuid,
        })
    }

    /// Encrypt an email and upload it to `pending/inbox/`
    /// (`EmailBridgeClient.addToInbox`).
    pub async fn add_to_inbox(&self, msg: &EmailMessage) -> Result<()> {
        let inbox = self.pending_folder().child("inbox").await?
            .ok_or_else(|| Error::Protocol("inbox directory missing".into()))?;
        let ct = self.encrypt_email(msg)?;
        let ct_bytes = ct.to_cbor().to_bytes();
        let filename = format!("{}.cbor", msg.id);
        inbox.upload(&filename, &ct_bytes).await?;
        Ok(())
    }
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
