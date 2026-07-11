//! `MessageRef` — a reference to a message by the bare hash of its envelope,
//! ported from `peergos.shared.messaging.MessageRef`.
//!
//! The Java type holds a `Multihash`; we keep the raw multihash bytes (as produced
//! by `bare_hash`, `[0x12, 0x20] ++ sha256`) since that is all the CRDT ever
//! compares or serialises.

use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageRef {
    /// The multihash bytes of the referenced message envelope.
    pub envelope_hash: Vec<u8>,
}

impl MessageRef {
    pub fn new(envelope_hash: Vec<u8>) -> MessageRef {
        MessageRef { envelope_hash }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<MessageRef> {
        let h = cbor
            .get("h")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor(format!("Incorrect cbor for MessageRef: {cbor:?}")))?;
        Ok(MessageRef::new(h.to_vec()))
    }
}

impl Cborable for MessageRef {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("h", CborObject::ByteString(self.envelope_hash.clone()))
            .build()
    }
}

/// `Hasher.bareHash` — the bare sha2-256 multihash of `data`
/// (`[0x12, 0x20] ++ sha256`), used to hash message envelopes.
pub fn bare_hash(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&peergos_crypto::hash::sha256(data));
    out
}
