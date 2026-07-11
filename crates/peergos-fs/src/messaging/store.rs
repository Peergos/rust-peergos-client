//! `MessageStore` — the append-only, eventually-consistent log of a chat's
//! messages, ported from `peergos.shared.messaging.MessageStore`.
//!
//! The Java interface threads a `Snapshot`/`Committer` through `addMessages` /
//! `revokeAccess` for its atomic-commit synchroniser; the Rust filesystem API
//! commits per-operation, so those parameters are dropped here. See
//! [`super::file_store::FileBackedMessageStore`] for the real implementation and
//! [`RamMessageStore`] for an in-memory one used to test the CRDT.

use super::envelope::SignedMessage;
use async_trait::async_trait;
use peergos_core::error::Result;
use std::collections::BTreeSet;
use std::sync::Mutex;

#[async_trait]
pub trait MessageStore: Send + Sync {
    /// All messages with index >= `index` (`getMessagesFrom`).
    async fn get_messages_from(&self, index: i64) -> Result<Vec<SignedMessage>>;

    /// Messages in the half-open index range `[from_index, to_index)`
    /// (`getMessages`).
    async fn get_messages(&self, from_index: i64, to_index: i64) -> Result<Vec<SignedMessage>>;

    /// Append `msgs` to the log; `msg_index` is the index the first message will
    /// occupy (`addMessages`).
    async fn add_messages(&self, msg_index: i64, msgs: Vec<SignedMessage>) -> Result<()>;

    /// Revoke read access to the shared chat state from `usernames`
    /// (`revokeAccess`).
    async fn revoke_access(&self, usernames: BTreeSet<String>) -> Result<()>;
}

/// An in-memory [`MessageStore`] for exercising the CRDT without a filesystem.
pub struct RamMessageStore {
    messages: Mutex<Vec<SignedMessage>>,
    revoked: Mutex<BTreeSet<String>>,
}

impl RamMessageStore {
    pub fn new() -> RamMessageStore {
        RamMessageStore { messages: Mutex::new(Vec::new()), revoked: Mutex::new(BTreeSet::new()) }
    }

    pub fn len(&self) -> usize {
        self.messages.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn revoked(&self) -> BTreeSet<String> {
        self.revoked.lock().unwrap().clone()
    }
}

impl Default for RamMessageStore {
    fn default() -> Self {
        RamMessageStore::new()
    }
}

#[async_trait]
impl MessageStore for RamMessageStore {
    async fn get_messages_from(&self, index: i64) -> Result<Vec<SignedMessage>> {
        let msgs = self.messages.lock().unwrap();
        let start = (index.max(0) as usize).min(msgs.len());
        Ok(msgs[start..].to_vec())
    }

    async fn get_messages(&self, from_index: i64, to_index: i64) -> Result<Vec<SignedMessage>> {
        let msgs = self.messages.lock().unwrap();
        let start = (from_index.max(0) as usize).min(msgs.len());
        let end = (to_index.max(0) as usize).min(msgs.len());
        if start >= end {
            return Ok(Vec::new());
        }
        Ok(msgs[start..end].to_vec())
    }

    async fn add_messages(&self, _msg_index: i64, msgs: Vec<SignedMessage>) -> Result<()> {
        self.messages.lock().unwrap().extend(msgs);
        Ok(())
    }

    async fn revoke_access(&self, usernames: BTreeSet<String>) -> Result<()> {
        self.revoked.lock().unwrap().extend(usernames);
        Ok(())
    }
}
