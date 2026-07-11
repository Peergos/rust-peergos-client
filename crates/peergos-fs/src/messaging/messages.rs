//! Chat message payloads, ported from `peergos.shared.messaging.messages.*`.
//!
//! Java models these as a `Message` interface with one class per `Type`; here they
//! are a single [`Message`] enum tagged by the same integer `c` field.

use super::id::Id;
use super::message_ref::{bare_hash, MessageRef};
use crate::feed::{Content, FileRef};
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{OwnerProof, PublicKeyHash, PublicSigningKey};

/// The message category (`Message.Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Join = 0,
    Invite = 1,
    Application = 2,
    GroupState = 3,
    ReplyTo = 4,
    Delete = 5,
    Edit = 6,
    RemoveMember = 7,
}

impl MessageType {
    pub fn value(self) -> i64 {
        self as i64
    }

    pub fn by_value(val: i64) -> Result<MessageType> {
        Ok(match val {
            0 => MessageType::Join,
            1 => MessageType::Invite,
            2 => MessageType::Application,
            3 => MessageType::GroupState,
            4 => MessageType::ReplyTo,
            5 => MessageType::Delete,
            6 => MessageType::Edit,
            7 => MessageType::RemoveMember,
            other => return Err(Error::Cbor(format!("Unknown message type: {other}"))),
        })
    }
}

/// An `ApplicationMessage` — a chat message body of inline text and file refs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationMessage {
    pub body: Vec<Content>,
}

impl ApplicationMessage {
    pub fn new(body: Vec<Content>) -> ApplicationMessage {
        ApplicationMessage { body }
    }

    /// A plain-text message (`ApplicationMessage.text`).
    pub fn text(text: impl Into<String>) -> ApplicationMessage {
        ApplicationMessage::new(vec![Content::Text(text.into())])
    }

    /// Text followed by file attachments (`ApplicationMessage.attachment`).
    pub fn attachment(text: impl Into<String>, attachments: Vec<FileRef>) -> ApplicationMessage {
        let mut body = vec![Content::Text(text.into())];
        body.extend(attachments.into_iter().map(Content::Reference));
        ApplicationMessage::new(body)
    }

    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("c", CborObject::Long(MessageType::Application.value()))
            .put("b", CborObject::List(self.body.iter().map(|c| c.to_cbor()).collect()))
            .build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<ApplicationMessage> {
        let body = cbor
            .get("b")
            .and_then(|c| c.as_list())
            .ok_or_else(|| Error::Cbor("ApplicationMessage missing 'b'".into()))?
            .iter()
            .map(Content::from_cbor)
            .collect::<Result<Vec<Content>>>()?;
        Ok(ApplicationMessage::new(body))
    }

    /// The file refs referenced by this body (attachments to mirror).
    pub fn file_refs(&self) -> Vec<FileRef> {
        self.body
            .iter()
            .filter_map(|c| match c {
                Content::Reference(r) => Some(r.clone()),
                Content::Text(_) => None,
            })
            .collect()
    }
}

/// A chat message payload (`Message`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A new member announcing their chat identity key (`Join`).
    Join {
        username: String,
        identity: PublicKeyHash,
        chat_identity: OwnerProof,
        chat_id_public: PublicSigningKey,
    },
    /// An invitation of a new member with a fresh child `Id` (`Invite`).
    Invite {
        username: String,
        identity: PublicKeyHash,
        recipient_id: Id,
    },
    /// A user-visible chat message (`ApplicationMessage`).
    Application(ApplicationMessage),
    /// Set a key/value pair in the shared group state (`SetGroupState`).
    GroupState { key: String, value: String },
    /// A reply to an earlier message (`ReplyTo`).
    ReplyTo { parent: MessageRef, content: ApplicationMessage },
    /// Delete one of our prior messages (`DeleteMessage`).
    Delete { target: MessageRef },
    /// Edit an earlier message (`EditMessage`).
    Edit { prior_version: MessageRef, content: ApplicationMessage },
    /// Remove a member from the chat (`RemoveMember`).
    RemoveMember { chat_uid: String, member_to_remove: Id },
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Join { .. } => MessageType::Join,
            Message::Invite { .. } => MessageType::Invite,
            Message::Application(_) => MessageType::Application,
            Message::GroupState { .. } => MessageType::GroupState,
            Message::ReplyTo { .. } => MessageType::ReplyTo,
            Message::Delete { .. } => MessageType::Delete,
            Message::Edit { .. } => MessageType::Edit,
            Message::RemoveMember { .. } => MessageType::RemoveMember,
        }
    }

    /// `ReplyTo.build` — reply to `parent` with `content`.
    pub fn reply_to(parent_envelope_bytes: &[u8], content: ApplicationMessage) -> Message {
        Message::ReplyTo { parent: MessageRef::new(bare_hash(parent_envelope_bytes)), content }
    }

    /// `EditMessage.build` — edit the message with the given prior envelope.
    pub fn edit(prior_envelope_bytes: &[u8], content: ApplicationMessage) -> Message {
        Message::Edit { prior_version: MessageRef::new(bare_hash(prior_envelope_bytes)), content }
    }

    /// `DeleteMessage.build` — delete the message with the given envelope.
    pub fn delete(target_envelope_bytes: &[u8]) -> Message {
        Message::Delete { target: MessageRef::new(bare_hash(target_envelope_bytes)) }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<Message> {
        let category = cbor
            .get("c")
            .and_then(|c| c.as_long())
            .ok_or_else(|| Error::Cbor(format!("Incorrect cbor for Message: {cbor:?}")))?;
        let get_str = |k: &str| {
            cbor.get(k)
                .and_then(|c| c.as_string())
                .map(|s| s.to_string())
                .ok_or_else(|| Error::Cbor(format!("Message missing '{k}'")))
        };
        let get = |k: &str| cbor.get(k).ok_or_else(|| Error::Cbor(format!("Message missing '{k}'")));
        Ok(match MessageType::by_value(category)? {
            MessageType::Join => Message::Join {
                username: get_str("u")?,
                identity: PublicKeyHash::from_cbor(get("i")?)?,
                chat_identity: OwnerProof::from_cbor(get("ci")?)?,
                chat_id_public: PublicSigningKey::from_cbor(get("p")?)?,
            },
            MessageType::Invite => Message::Invite {
                username: get_str("u")?,
                recipient_id: Id::from_cbor(get("r")?)?,
                identity: PublicKeyHash::from_cbor(get("i")?)?,
            },
            MessageType::Application => Message::Application(ApplicationMessage::from_cbor(cbor)?),
            MessageType::GroupState => Message::GroupState { key: get_str("k")?, value: get_str("v")? },
            MessageType::ReplyTo => Message::ReplyTo {
                parent: MessageRef::from_cbor(get("r")?)?,
                content: ApplicationMessage::from_cbor(get("b")?)?,
            },
            MessageType::Edit => Message::Edit {
                prior_version: MessageRef::from_cbor(get("r")?)?,
                content: ApplicationMessage::from_cbor(get("b")?)?,
            },
            MessageType::Delete => Message::Delete { target: MessageRef::from_cbor(get("r")?)? },
            MessageType::RemoveMember => Message::RemoveMember {
                chat_uid: get_str("u")?,
                member_to_remove: Id::from_cbor(get("m")?)?,
            },
        })
    }
}

impl Cborable for Message {
    fn to_cbor(&self) -> CborObject {
        let c = CborObject::Long(self.message_type().value());
        match self {
            Message::Join { username, identity, chat_identity, chat_id_public } => CborObject::map()
                .put("c", c)
                .put("u", CborObject::Str(username.clone()))
                .put("i", identity.to_cbor())
                .put("ci", chat_identity.to_cbor())
                .put("p", chat_id_public.to_cbor())
                .build(),
            Message::Invite { username, identity, recipient_id } => CborObject::map()
                .put("c", c)
                .put("u", CborObject::Str(username.clone()))
                .put("r", recipient_id.to_cbor())
                .put("i", identity.to_cbor())
                .build(),
            Message::Application(m) => m.to_cbor(),
            Message::GroupState { key, value } => CborObject::map()
                .put("c", c)
                .put("k", CborObject::Str(key.clone()))
                .put("v", CborObject::Str(value.clone()))
                .build(),
            Message::ReplyTo { parent, content } => CborObject::map()
                .put("c", c)
                .put("r", parent.to_cbor())
                .put("b", content.to_cbor())
                .build(),
            Message::Edit { prior_version, content } => CborObject::map()
                .put("c", c)
                .put("r", prior_version.to_cbor())
                .put("b", content.to_cbor())
                .build(),
            Message::Delete { target } => CborObject::map()
                .put("c", c)
                .put("r", target.to_cbor())
                .build(),
            Message::RemoveMember { chat_uid, member_to_remove } => CborObject::map()
                .put("c", c)
                .put("u", CborObject::Str(chat_uid.clone()))
                .put("m", member_to_remove.to_cbor())
                .build(),
        }
    }
}
