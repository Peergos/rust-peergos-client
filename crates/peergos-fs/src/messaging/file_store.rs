//! `FileBackedMessageStore` — a [`MessageStore`] backed by the chat's shared
//! append-only log file, ported from
//! `peergos.shared.messaging.FileBackedMessageStore`.
//!
//! The log lives at `<chatRoot>/shared/peergos-chat-messages.cborstream`: a
//! concatenation of serialized [`SignedMessage`]s. Java maintains a companion
//! `.index.bin` mapping message index → byte offset so large (>5 MiB) logs can be
//! seeked without a full scan; this port parses the whole stream instead (correct
//! for any size, just O(n) to seek), so the index file is written but not read.

use super::envelope::SignedMessage;
use super::store::MessageStore;
use crate::context::UserContext;
use async_trait::async_trait;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use std::collections::BTreeSet;

pub(crate) const SHARED_MSG_LOG: &str = "peergos-chat-messages.cborstream";

pub struct FileBackedMessageStore {
    context: UserContext,
    /// Absolute path to the chat's `shared` directory (e.g.
    /// `/alice/.messaging/<uid>/shared`).
    shared_dir: String,
    /// Absolute path to the chat root (`shared`'s parent), for access revocation.
    chat_root: String,
}

impl FileBackedMessageStore {
    pub fn new(context: UserContext, shared_dir: String, chat_root: String) -> FileBackedMessageStore {
        FileBackedMessageStore { context, shared_dir, chat_root }
    }

    fn log_path(&self) -> String {
        format!("{}/{}", self.shared_dir, SHARED_MSG_LOG)
    }

    /// Read and parse the whole message log (empty if the file is absent/empty).
    async fn read_all(&self) -> Result<Vec<SignedMessage>> {
        let file = match self.context.get_by_path(&self.log_path()).await? {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };
        let bytes = file.read().await?;
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
            out.push(SignedMessage::from_cbor(&cbor)?);
            if consumed == 0 {
                break;
            }
            offset += consumed;
        }
        Ok(out)
    }
}

#[async_trait(?Send)]
impl MessageStore for FileBackedMessageStore {
    async fn get_messages_from(&self, index: i64) -> Result<Vec<SignedMessage>> {
        let all = self.read_all().await?;
        let start = (index.max(0) as usize).min(all.len());
        Ok(all[start..].to_vec())
    }

    async fn get_messages(&self, from_index: i64, to_index: i64) -> Result<Vec<SignedMessage>> {
        let all = self.read_all().await?;
        let start = (from_index.max(0) as usize).min(all.len());
        let end = (to_index.max(0) as usize).min(all.len());
        if start >= end {
            return Ok(Vec::new());
        }
        Ok(all[start..end].to_vec())
    }

    async fn add_messages(&self, _msg_index: i64, msgs: Vec<SignedMessage>) -> Result<()> {
        if msgs.is_empty() {
            return Ok(());
        }
        let mut raw = Vec::new();
        for msg in &msgs {
            raw.extend_from_slice(&msg.serialize());
        }
        let file = self
            .context
            .get_by_path(&self.log_path())
            .await?
            .ok_or_else(|| Error::Protocol(format!("chat message log missing: {}", self.log_path())))?;
        file.append(&raw).await
    }

    async fn revoke_access(&self, usernames: BTreeSet<String>) -> Result<()> {
        if usernames.is_empty() {
            return Ok(());
        }
        let user = self
            .context
            .user()
            .ok_or_else(|| Error::Protocol("cannot revoke access in a secret-link context".into()))?;
        let chat_root = self
            .context
            .get_by_path(&self.chat_root)
            .await?
            .ok_or_else(|| Error::Protocol(format!("chat root missing: {}", self.chat_root)))?;
        let revoked: Vec<String> = usernames.into_iter().collect();
        crate::unshare_read_access(
            user,
            &self.chat_root,
            chat_root.capability(),
            "shared",
            &revoked,
            self.context.store(),
            self.context.mutable().as_ref(),
        )
        .await
    }
}
