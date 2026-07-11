//! `MessageEnvelope` + `SignedMessage`, ported from
//! `peergos.shared.messaging.MessageEnvelope` / `SignedMessage`.

use super::id::Id;
use super::message_ref::MessageRef;
use super::messages::Message;
use super::tree_clock::TreeClock;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};

/// A signed, timestamped chat message. The `previous_messages` refs make the
/// envelopes form a merkle DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub author: Id,
    pub timestamp: TreeClock,
    /// Creation time in epoch milliseconds (UTC), accurate to the millisecond.
    pub creation_time_millis: i64,
    pub previous_messages: Vec<MessageRef>,
    pub payload: Message,
}

impl MessageEnvelope {
    pub fn new(
        author: Id,
        timestamp: TreeClock,
        creation_time_millis: i64,
        previous_messages: Vec<MessageRef>,
        payload: Message,
    ) -> MessageEnvelope {
        MessageEnvelope { author, timestamp, creation_time_millis, previous_messages, payload }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<MessageEnvelope> {
        let get = |k: &str| cbor.get(k).ok_or_else(|| Error::Cbor(format!("MessageEnvelope missing '{k}'")));
        let author = Id::from_cbor(get("a")?)?;
        let timestamp = TreeClock::from_cbor(get("t")?)?;
        let creation_time_millis = get("u")?.as_long().ok_or_else(|| Error::Cbor("MessageEnvelope 'u' not a long".into()))?;
        let previous_messages = get("r")?
            .as_list()
            .ok_or_else(|| Error::Cbor("MessageEnvelope 'r' not a list".into()))?
            .iter()
            .map(MessageRef::from_cbor)
            .collect::<Result<Vec<MessageRef>>>()?;
        let payload = Message::from_cbor(get("p")?)?;
        Ok(MessageEnvelope::new(author, timestamp, creation_time_millis, previous_messages, payload))
    }
}

impl Cborable for MessageEnvelope {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("a", self.author.to_cbor())
            .put("t", self.timestamp.to_cbor())
            .put("u", CborObject::Long(self.creation_time_millis))
            .put("r", CborObject::List(self.previous_messages.iter().map(|m| m.to_cbor()).collect()))
            .put("p", self.payload.to_cbor())
            .build()
    }
}

/// A message envelope plus its author's signature (`SignedMessage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessage {
    pub signature: Vec<u8>,
    pub msg: MessageEnvelope,
}

impl SignedMessage {
    pub fn new(signature: Vec<u8>, msg: MessageEnvelope) -> SignedMessage {
        SignedMessage { signature, msg }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<SignedMessage> {
        let list = cbor
            .as_list()
            .ok_or_else(|| Error::Cbor(format!("Incorrect cbor for SignedMessage: {cbor:?}")))?;
        let signature = list
            .first()
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("SignedMessage missing signature".into()))?
            .to_vec();
        let msg_bytes = list
            .get(1)
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("SignedMessage missing envelope".into()))?;
        let msg = MessageEnvelope::from_cbor(&CborObject::from_bytes(msg_bytes)?)?;
        Ok(SignedMessage::new(signature, msg))
    }
}

impl Cborable for SignedMessage {
    fn to_cbor(&self) -> CborObject {
        CborObject::List(vec![
            CborObject::ByteString(self.signature.clone()),
            CborObject::ByteString(self.msg.serialize()),
        ])
    }
}
