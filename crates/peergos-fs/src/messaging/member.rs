//! `Member` + `GroupProperty`, ported from `peergos.shared.messaging.Member` /
//! `GroupProperty`.

use super::id::Id;
use super::tree_clock::TreeClock;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{OwnerProof, PublicKeyHash};

pub const ADMINS_STATE_KEY: &str = "admins";

/// A last-writer-wins group property value, tagged with the authoring member and
/// the clock at which it was set (`GroupProperty`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupProperty {
    pub author: Id,
    pub update_timestamp: TreeClock,
    pub value: String,
}

impl GroupProperty {
    pub fn new(author: Id, update_timestamp: TreeClock, value: String) -> GroupProperty {
        GroupProperty { author, update_timestamp, value }
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<GroupProperty> {
        let get = |k: &str| cbor.get(k).ok_or_else(|| Error::Cbor(format!("GroupProperty missing '{k}'")));
        let author = Id::from_cbor(get("a")?)?;
        let timestamp = TreeClock::from_cbor(get("t")?)?;
        let value = get("v")?.as_string().ok_or_else(|| Error::Cbor("GroupProperty 'v' not a string".into()))?.to_string();
        Ok(GroupProperty::new(author, timestamp, value))
    }
}

impl Cborable for GroupProperty {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("a", self.author.to_cbor())
            .put("t", self.update_timestamp.to_cbor())
            .put("v", CborObject::Str(self.value.clone()))
            .build()
    }
}

/// A chat member (`Member`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub username: String,
    pub id: Id,
    pub identity: PublicKeyHash,
    pub chat_identity: Option<OwnerProof>,
    pub messages_merged_upto: i64,
    pub members_invited: i32,
    pub removed: bool,
}

impl Member {
    pub fn new(
        username: String,
        id: Id,
        identity: PublicKeyHash,
        chat_identity: Option<OwnerProof>,
        messages_merged_upto: i64,
        members_invited: i32,
        removed: bool,
    ) -> Member {
        Member { username, id, identity, chat_identity, messages_merged_upto, members_invited, removed }
    }

    /// The simple constructor (`Member(username, id, identity, msgs, invited)`).
    pub fn simple(username: String, id: Id, identity: PublicKeyHash, messages_merged_upto: i64, members_invited: i32) -> Member {
        Member::new(username, id, identity, None, messages_merged_upto, members_invited, false)
    }

    pub fn increment_invited(&self) -> Member {
        let mut m = self.clone();
        m.members_invited += 1;
        m
    }

    pub fn increment_messages(&self) -> Member {
        let mut m = self.clone();
        m.messages_merged_upto += 1;
        m
    }

    pub fn removed(&self, updated: bool) -> Member {
        let mut m = self.clone();
        m.removed = updated;
        m
    }

    pub fn with_chat_id(&self, proof: OwnerProof) -> Member {
        let mut m = self.clone();
        m.chat_identity = Some(proof);
        m
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<Member> {
        let get = |k: &str| cbor.get(k).ok_or_else(|| Error::Cbor(format!("Member missing '{k}'")));
        let username = get("u")?.as_string().ok_or_else(|| Error::Cbor("Member 'u' not a string".into()))?.to_string();
        let id = Id::from_cbor(get("i")?)?;
        let identity = PublicKeyHash::from_cbor(get("p")?)?;
        let chat_identity = cbor.get("s").map(OwnerProof::from_cbor).transpose()?;
        let messages_merged_upto = get("m")?.as_long().ok_or_else(|| Error::Cbor("Member 'm' not a long".into()))?;
        let members_invited = get("c")?.as_long().ok_or_else(|| Error::Cbor("Member 'c' not a long".into()))? as i32;
        let removed = get("r")?.as_bool().ok_or_else(|| Error::Cbor("Member 'r' not a bool".into()))?;
        Ok(Member::new(username, id, identity, chat_identity, messages_merged_upto, members_invited, removed))
    }
}

impl Cborable for Member {
    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("u", CborObject::Str(self.username.clone()))
            .put("i", self.id.to_cbor())
            .put("p", self.identity.to_cbor())
            .put_opt("s", self.chat_identity.as_ref().map(|c| c.to_cbor()))
            .put("m", CborObject::Long(self.messages_merged_upto))
            .put("c", CborObject::Long(self.members_invited as i64))
            .put("r", CborObject::Boolean(self.removed))
            .build()
    }
}
