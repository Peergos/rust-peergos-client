//! `PrivateChatState` — our secret chat identity keypair plus the set of members
//! we've locally marked deleted. Ported from
//! `peergos.shared.messaging.PrivateChatState`.

use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicSigningKey, SigningPrivateKeyAndPublicHash};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateChatState {
    pub chat_identity: SigningPrivateKeyAndPublicHash,
    pub chat_id_public: PublicSigningKey,
    pub deleted_members: BTreeSet<String>,
}

impl PrivateChatState {
    pub fn new(
        chat_identity: SigningPrivateKeyAndPublicHash,
        chat_id_public: PublicSigningKey,
        deleted_members: BTreeSet<String>,
    ) -> PrivateChatState {
        PrivateChatState { chat_identity, chat_id_public, deleted_members }
    }

    pub fn add_deleted(&self, username: impl Into<String>) -> PrivateChatState {
        let mut deleted = self.deleted_members.clone();
        deleted.insert(username.into());
        PrivateChatState::new(self.chat_identity.clone(), self.chat_id_public.clone(), deleted)
    }

    /// Merge a newer private state into this one (`apply`): union the deleted sets,
    /// keeping the newer keypair.
    pub fn apply(&self, newer: &PrivateChatState) -> PrivateChatState {
        let mut deleted = self.deleted_members.clone();
        deleted.extend(newer.deleted_members.iter().cloned());
        PrivateChatState::new(newer.chat_identity.clone(), newer.chat_id_public.clone(), deleted)
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<PrivateChatState> {
        let get = |k: &str| cbor.get(k).ok_or_else(|| Error::Cbor(format!("PrivateChatState missing '{k}'")));
        let chat_identity = SigningPrivateKeyAndPublicHash::from_cbor(get("ci")?)?;
        let chat_id_public = PublicSigningKey::from_cbor(get("p")?)?;
        let deleted = get("d")?
            .as_list()
            .ok_or_else(|| Error::Cbor("PrivateChatState 'd' not a list".into()))?
            .iter()
            .map(|c| c.as_string().map(|s| s.to_string()).ok_or_else(|| Error::Cbor("deleted member not a string".into())))
            .collect::<Result<BTreeSet<String>>>()?;
        Ok(PrivateChatState::new(chat_identity, chat_id_public, deleted))
    }
}

impl Cborable for PrivateChatState {
    fn to_cbor(&self) -> CborObject {
        // deleted_members is a BTreeSet, so already sorted (Java sorts explicitly).
        let deleted = self.deleted_members.iter().map(|s| CborObject::Str(s.clone())).collect();
        CborObject::map()
            .put("ci", self.chat_identity.to_cbor())
            .put("p", self.chat_id_public.to_cbor())
            .put("d", CborObject::List(deleted))
            .build()
    }
}
