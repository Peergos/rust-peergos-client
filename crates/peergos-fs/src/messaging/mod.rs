//! Chat: a conflict-free replicated messaging layer, ported from
//! `peergos.shared.messaging.*`.
//!
//! The data model and CRDT ([`Chat`], [`TreeClock`], [`Id`], the message types)
//! are a close port of the Java classes. The API layer ([`Messenger`],
//! [`ChatController`], [`FileBackedMessageStore`]) is adapted to this crate's
//! `UserContext` / `FileWrapper` filesystem API rather than Java's
//! `Snapshot`/`Committer` synchroniser.

#[cfg(test)]
mod tests;

mod chat;
mod controller;
mod envelope;
mod file_store;
mod id;
mod member;
mod message_ref;
mod messages;
mod messenger;
mod private_state;
mod store;
mod tree_clock;

pub use chat::{Chat, ChatUpdate};
pub use controller::ChatController;
pub use envelope::{MessageEnvelope, SignedMessage};
pub use file_store::FileBackedMessageStore;
pub use id::Id;
pub use member::{GroupProperty, Member, ADMINS_STATE_KEY};
pub use message_ref::{bare_hash, MessageRef};
pub use messages::{ApplicationMessage, Message, MessageType};
pub use messenger::Messenger;
pub use private_state::PrivateChatState;
pub use store::{MessageStore, RamMessageStore};
pub use tree_clock::TreeClock;
