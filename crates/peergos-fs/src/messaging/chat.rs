//! `Chat` — the conflict-free replicated chat state, ported from
//! `peergos.shared.messaging.Chat`, plus `ChatUpdate` (`ChatUpdate`).
//!
//! A `Chat` is one member's view of a conversation: the membership tree, the
//! shared group state (title, admins, ...), the merged vector clock and a window
//! of recent messages. Applying or merging messages produces a [`ChatUpdate`]
//! bundling the new state with the side effects (messages to append, media to
//! mirror, access to revoke, private state to persist) the caller must commit.

use super::id::Id;
use super::member::{GroupProperty, Member, ADMINS_STATE_KEY};
use super::message_ref::{bare_hash, MessageRef};
use super::messages::Message;
use super::envelope::{MessageEnvelope, SignedMessage};
use super::private_state::PrivateChatState;
use super::store::MessageStore;
use super::tree_clock::TreeClock;
use crate::feed::FileRef;
use peergos_cbor::{Cborable, CborObject, CborString};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{OwnerProof, PublicKeyHash, PublicSigningKey, SigningKeyPair, SigningPrivateKeyAndPublicHash};
use peergos_core::storage::{get_signing_key, ContentAddressedStorage};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

const MAX_RECENT: usize = 10;

/// A boxed future for the mutually-recursive apply/merge/send message paths.
type ChatFuture<'a> = Pin<Box<dyn Future<Output = Result<ChatUpdate>> + Send + 'a>>;

/// The result of applying/merging messages: the new [`Chat`] plus side effects to
/// commit (`ChatUpdate`).
#[derive(Debug, Clone)]
pub struct ChatUpdate {
    pub state: Chat,
    pub new_messages: Vec<SignedMessage>,
    pub media_to_copy: Vec<FileRef>,
    pub to_revoke_access: BTreeSet<String>,
    pub priv_state: Option<PrivateChatState>,
}

impl ChatUpdate {
    pub fn new(
        state: Chat,
        new_messages: Vec<SignedMessage>,
        media_to_copy: Vec<FileRef>,
        to_revoke_access: BTreeSet<String>,
    ) -> ChatUpdate {
        ChatUpdate { state, new_messages, media_to_copy, to_revoke_access, priv_state: None }
    }

    pub fn empty(state: Chat) -> ChatUpdate {
        ChatUpdate { state, new_messages: Vec::new(), media_to_copy: Vec::new(), to_revoke_access: BTreeSet::new(), priv_state: None }
    }

    pub fn is_empty(&self) -> bool {
        self.new_messages.is_empty()
            && self.media_to_copy.is_empty()
            && self.to_revoke_access.is_empty()
            && self.priv_state.is_none()
    }

    /// Chain another update after this one (`apply`), concatenating side effects
    /// and taking the newer state.
    pub fn apply(mut self, next: ChatUpdate) -> ChatUpdate {
        self.new_messages.extend(next.new_messages);
        self.media_to_copy.extend(next.media_to_copy);
        self.to_revoke_access.extend(next.to_revoke_access);
        let priv_state = match (self.priv_state, next.priv_state) {
            (Some(a), Some(b)) => Some(a.apply(&b)),
            _ => None,
        };
        ChatUpdate { state: next.state, new_messages: self.new_messages, media_to_copy: self.media_to_copy, to_revoke_access: self.to_revoke_access, priv_state }
    }

    pub fn with_state(mut self, c: Chat) -> ChatUpdate {
        self.state = c;
        self
    }
}

/// One member's replicated view of a conversation (`Chat`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chat {
    pub chat_uid: String,
    pub host: Id,
    pub current: TreeClock,
    pub members: BTreeMap<Id, Member>,
    pub group_state: BTreeMap<String, GroupProperty>,
    recent_messages: Vec<MessageEnvelope>,
}

impl Chat {
    pub fn new(
        chat_uid: String,
        host: Id,
        current: TreeClock,
        members: BTreeMap<Id, Member>,
        group_state: BTreeMap<String, GroupProperty>,
        recent_messages: Vec<MessageEnvelope>,
    ) -> Chat {
        Chat { chat_uid, host, current, members, group_state, recent_messages }
    }

    // ---- accessors ---------------------------------------------------------

    pub fn get_title(&self) -> String {
        self.group_state.get("title").map(|p| p.value.clone()).unwrap_or_default()
    }

    pub fn get_admins(&self) -> BTreeSet<String> {
        match self.group_state.get(ADMINS_STATE_KEY) {
            None => BTreeSet::new(),
            Some(prop) => prop.value.split(',').map(|s| s.to_string()).collect(),
        }
    }

    pub fn host(&self) -> &Member {
        self.members.get(&self.host).expect("host member present")
    }

    pub fn get_member_by_id(&self, id: &Id) -> Option<&Member> {
        self.members.get(id)
    }

    /// The member with the given username, preferring a non-removed one
    /// (`getMember(String)`).
    pub fn get_member(&self, username: &str) -> Option<&Member> {
        let matching: Vec<&Member> = self.members.values().filter(|m| m.username == username).collect();
        matching.iter().find(|m| !m.removed).copied().or_else(|| matching.first().copied())
    }

    pub fn get_recent(&self) -> Vec<MessageEnvelope> {
        self.recent_messages.clone()
    }

    // ---- functional updates -------------------------------------------------

    fn with_members(&self, updated: BTreeMap<Id, Member>) -> Chat {
        let mut c = self.clone();
        c.members = updated;
        c
    }

    fn with_time(&self, new_time: TreeClock) -> Chat {
        let mut c = self.clone();
        c.current = new_time;
        c
    }

    fn with_host(&self, host: Id) -> Chat {
        let mut c = self.clone();
        c.host = host;
        c
    }

    fn with_properties(&self, updated: BTreeMap<String, GroupProperty>) -> Chat {
        let mut c = self.clone();
        c.group_state = updated;
        c
    }

    fn add_to_recent(&self, m: MessageEnvelope) -> Chat {
        let mut updated = self.recent_messages.clone();
        if updated.len() >= MAX_RECENT {
            updated.remove(0);
        }
        updated.push(m);
        let mut c = self.clone();
        c.recent_messages = updated;
        c
    }

    fn increment_host(&self, source: &Member) -> Chat {
        let mut updated = self.members.clone();
        updated.insert(source.id.clone(), source.increment_messages());
        self.with_members(updated)
    }

    fn merge_message_timestamp(&self, timestamp: &TreeClock, source: &Member) -> Chat {
        let new_time = self.current.merge(timestamp);
        let mut updated = self.members.clone();
        let src_incremented = self.members.get(&source.id).expect("source member").increment_messages();
        updated.insert(source.id.clone(), src_incremented);
        let host_incremented = self.host().increment_messages();
        updated.insert(self.host.clone(), host_incremented);
        let mut c = self.with_members(updated);
        c.current = new_time;
        c
    }

    // ---- chat identity ------------------------------------------------------

    /// Generate a fresh chat identity keypair (`generateChatIdentity`).
    pub fn generate_chat_identity() -> Result<PrivateChatState> {
        let chat_identity = SigningKeyPair::random()?;
        let pre_hash = chat_identity.public.hash()?;
        let chat_id_with_hash = SigningPrivateKeyAndPublicHash::new(pre_hash, chat_identity.secret.clone());
        Ok(PrivateChatState::new(chat_id_with_hash, chat_identity.public.clone(), BTreeSet::new()))
    }

    // ---- sending ------------------------------------------------------------

    /// Send `body` as a new message, gathering the recent-message refs from
    /// `store` first (`sendMessage`).
    pub async fn send_message(
        &self,
        body: Message,
        signer: &SigningPrivateKeyAndPublicHash,
        user_identity: &SigningPrivateKeyAndPublicHash,
        store: &dyn MessageStore,
        cas: &dyn ContentAddressedStorage,
    ) -> Result<ChatUpdate> {
        let upto = self.host().messages_merged_upto;
        let recent = if upto > 0 { store.get_messages(upto - 1, upto).await? } else { Vec::new() };
        let recent_refs: Vec<MessageRef> = recent.iter().map(|s| MessageRef::new(bare_hash(&s.msg.serialize()))).collect();
        self.send_message_refs(body, signer, user_identity, recent_refs, cas).await
    }

    fn send_message_refs<'a>(
        &'a self,
        body: Message,
        signer: &'a SigningPrivateKeyAndPublicHash,
        user_identity: &'a SigningPrivateKeyAndPublicHash,
        recent_refs: Vec<MessageRef>,
        cas: &'a dyn ContentAddressedStorage,
    ) -> ChatFuture<'a> {
        Box::pin(async move {
            let msg_time = self.current.increment(&self.host);
            let msg = MessageEnvelope::new(self.host.clone(), msg_time, now_millis(), recent_refs, body);
            let signature = signer.secret.signature_only(&msg.serialize())?;
            let signed = SignedMessage::new(signature, msg);
            let host = self.host().clone();
            self.merge_message(signed, host, user_identity, cas).await
        })
    }

    // ---- applying / merging -------------------------------------------------

    /// Apply `signed` to this state, returning the state after applying the
    /// message plus its side effects (`applyMessage`).
    fn apply_message<'a>(
        &'a self,
        signed: SignedMessage,
        user_identity: &'a SigningPrivateKeyAndPublicHash,
        cas: &'a dyn ContentAddressedStorage,
    ) -> ChatFuture<'a> {
        Box::pin(async move {
            let msg = signed.msg.clone();
            let author = self.members.get(&msg.author).ok_or_else(|| Error::Protocol("Unknown message author".into()))?.clone();
            match &msg.payload {
                Message::Invite { username, identity, recipient_id } => {
                    let new_member = recipient_id.clone();
                    if self.members.contains_key(&new_member) {
                        return Err(Error::Protocol("Id already exists in this chat!".into()));
                    }
                    if new_member.parent() != author.id {
                        return Err(Error::Protocol("Invalid invite Id!".into()));
                    }
                    let mut updated = self.members.clone();
                    updated.insert(author.id.clone(), author.increment_invited());
                    let index_into_parent = self
                        .get_member_by_id(&new_member.parent())
                        .ok_or_else(|| Error::Protocol("Invite parent missing".into()))?
                        .messages_merged_upto;
                    let username = username.clone();
                    let identity = identity.clone();
                    // If we have been removed and re-invited, generate a new chat identity.
                    let host = self.host().clone();
                    if host.username == username && host.removed {
                        let new_identity = Chat::generate_chat_identity()?;
                        let chat_id = OwnerProof::build(user_identity, &new_identity.chat_identity.public_key_hash)?;
                        let new_host = Member::simple(username.clone(), new_member.clone(), identity, index_into_parent, 0);
                        updated.insert(new_member, new_host.clone());
                        let after_invite = ChatUpdate::new(
                            self.with_members(updated).add_to_recent(msg.clone()),
                            vec![signed.clone()],
                            Vec::new(),
                            BTreeSet::new(),
                        );
                        let join_msg = Message::Join {
                            username: host.username.clone(),
                            identity: host.identity.clone(),
                            chat_identity: chat_id,
                            chat_id_public: new_identity.chat_id_public.clone(),
                        };
                        let reff = MessageRef::new(bare_hash(&signed.msg.serialize()));
                        let next_state = after_invite
                            .state
                            .with_time(after_invite.state.current.with_member(new_host.id.clone()))
                            .with_host(new_host.id.clone());
                        let sent = next_state
                            .send_message_refs(join_msg, user_identity, user_identity, vec![reff], cas)
                            .await?;
                        return Ok(after_invite.apply(sent));
                    }
                    updated.insert(new_member.clone(), Member::simple(username, new_member, identity, index_into_parent, 0));
                    Ok(ChatUpdate::new(self.with_members(updated).add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()))
                }
                Message::Join { chat_identity, .. } => {
                    if author.chat_identity.is_none() {
                        let chat_identity = chat_identity.clone();
                        if chat_identity.owned_key != author.identity {
                            return Err(Error::Protocol("Identity keys don't match!".into()));
                        }
                        // verify signature
                        chat_identity.get_and_verify_owner(&author.identity, cas).await?;
                        let mut updated = self.members.clone();
                        updated.insert(author.id.clone(), author.with_chat_id(chat_identity));
                        return Ok(ChatUpdate::new(self.with_members(updated).add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()));
                    }
                    Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()))
                }
                Message::GroupState { key, value } => {
                    let existing = self.group_state.get(key);
                    let admins_ok = key != ADMINS_STATE_KEY || self.get_admins().contains(&author.username);
                    let wins = match existing {
                        None => true,
                        Some(existing) => {
                            admins_ok
                                && (existing.update_timestamp.is_before_or_equal(&msg.timestamp)
                                    || (existing.update_timestamp.is_concurrent_with(&msg.timestamp)
                                        && msg.author < existing.author))
                        }
                    };
                    if wins {
                        let mut updated = self.group_state.clone();
                        updated.insert(key.clone(), GroupProperty::new(msg.author.clone(), msg.timestamp.clone(), value.clone()));
                        return Ok(ChatUpdate::new(self.with_properties(updated).add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()));
                    }
                    Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()))
                }
                Message::Application(content) => {
                    if msg.author == self.host {
                        // Don't attempt to copy our own media
                        return Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()));
                    }
                    let file_refs = content.file_refs();
                    Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], file_refs, BTreeSet::new()))
                }
                Message::ReplyTo { content, .. } => {
                    let file_refs = content.file_refs();
                    Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], file_refs, BTreeSet::new()))
                }
                Message::RemoveMember { chat_uid, member_to_remove } => {
                    if *chat_uid != self.chat_uid {
                        // ignore message from incorrect chat
                        return Ok(ChatUpdate::new(self.clone(), Vec::new(), Vec::new(), BTreeSet::new()));
                    }
                    // anyone can remove themselves; an admin can remove anyone
                    if *member_to_remove == msg.author || self.get_admins().contains(&author.username) {
                        let username = self
                            .get_member_by_id(member_to_remove)
                            .ok_or_else(|| Error::Protocol("member to remove missing".into()))?
                            .username
                            .clone();
                        let updated_member = self.members.get(member_to_remove).unwrap().removed(true);
                        let mut updated = self.members.clone();
                        updated.insert(member_to_remove.clone(), updated_member);
                        let to_revoke = if username == self.host().username {
                            BTreeSet::new()
                        } else {
                            let mut s = BTreeSet::new();
                            s.insert(username);
                            s
                        };
                        return Ok(ChatUpdate::new(self.add_to_recent(msg).with_members(updated), vec![signed], Vec::new(), to_revoke));
                    }
                    Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()))
                }
                Message::Edit { .. } | Message::Delete { .. } => {
                    Ok(ChatUpdate::new(self.add_to_recent(msg), vec![signed], Vec::new(), BTreeSet::new()))
                }
            }
        })
    }

    /// Merge new messages from a mirror of `mirror_host_id` (`merge`).
    pub async fn merge(
        &self,
        mirror_host_id: &Id,
        user_identity: &SigningPrivateKeyAndPublicHash,
        mirror_store: &dyn MessageStore,
        cas: &dyn ContentAddressedStorage,
    ) -> Result<ChatUpdate> {
        let host = self.get_member_by_id(mirror_host_id).ok_or_else(|| Error::Protocol("mirror host not a member".into()))?;
        let new_messages = mirror_store.get_messages_from(host.messages_merged_upto).await?;
        let mut update = ChatUpdate::empty(self.clone());
        for msg in new_messages {
            let host_now = update
                .state
                .get_member_by_id(mirror_host_id)
                .ok_or_else(|| Error::Protocol("mirror host not a member".into()))?
                .clone();
            let step = update.state.merge_message(msg, host_now, user_identity, cas).await?;
            update = update.apply(step);
        }
        Ok(update)
    }

    fn merge_message<'a>(
        &'a self,
        signed: SignedMessage,
        host: Member,
        user_identity: &'a SigningPrivateKeyAndPublicHash,
        cas: &'a dyn ContentAddressedStorage,
    ) -> ChatFuture<'a> {
        Box::pin(async move {
            let author = self
                .members
                .get(&signed.msg.author)
                .ok_or_else(|| Error::Protocol("Unknown message author".into()))?
                .clone();
            let msg = signed.msg.clone();
            if !msg.timestamp.is_before_or_equal(&self.current) && !author.removed {
                // check signature
                let signer_hash = match &author.chat_identity {
                    Some(proof) => proof.get_and_verify_owner(&author.identity, cas).await?,
                    None => author.identity.clone(),
                };
                let signer = get_signing_key(cas, &signer_hash, &signer_hash)
                    .await?
                    .ok_or_else(|| Error::Protocol("Couldn't retrieve public signing key!".into()))?;
                // NaCl attached signature = sig || message
                let mut attached = signed.signature.clone();
                attached.extend_from_slice(&signed.msg.serialize());
                signer.unsign_message(&attached)?;
                let update = self.apply_message(signed, user_identity, cas).await?;
                let new_state = update.state.merge_message_timestamp(&msg.timestamp, &host);
                Ok(update.with_state(new_state))
            } else {
                Ok(ChatUpdate::empty(self.increment_host(&host)))
            }
        })
    }

    // ---- membership ---------------------------------------------------------

    /// Send our `Join` message after copying a chat to our space (`join`).
    pub async fn join(
        &self,
        host: &Member,
        chat_id: OwnerProof,
        chat_id_public: PublicSigningKey,
        identity: &SigningPrivateKeyAndPublicHash,
        our_store: &dyn MessageStore,
        cas: &dyn ContentAddressedStorage,
    ) -> Result<ChatUpdate> {
        let join_msg = Message::Join {
            username: host.username.clone(),
            identity: host.identity.clone(),
            chat_identity: chat_id,
            chat_id_public,
        };
        self.with_time(self.current.with_member(host.id.clone()))
            .send_message(join_msg, identity, identity, our_store, cas)
            .await
    }

    /// A copy of this chat rooted at `host` (for a joining member to mirror) (`copy`).
    pub fn copy(&self, host: Member) -> Result<Chat> {
        if !self.members.contains_key(&host.id) {
            return Err(Error::Protocol("Only an invited member can mirror a conversation!".into()));
        }
        let mut cloned: BTreeMap<Id, Member> = self.members.clone();
        cloned.insert(host.id.clone(), host.clone());
        Ok(Chat::new(self.chat_uid.clone(), host.id.clone(), self.current.clone(), cloned, self.group_state.clone(), self.recent_messages.clone()))
    }

    /// Invite a single member (`inviteMember`).
    pub async fn invite_member(
        &self,
        username: String,
        identity: PublicKeyHash,
        our_chat_identity: &SigningPrivateKeyAndPublicHash,
        user_identity: &SigningPrivateKeyAndPublicHash,
        our_store: &dyn MessageStore,
        cas: &dyn ContentAddressedStorage,
    ) -> Result<ChatUpdate> {
        self.invite_members(vec![username], vec![identity], our_chat_identity, user_identity, our_store, cas).await
    }

    /// Invite several members (`inviteMembers`).
    pub async fn invite_members(
        &self,
        usernames: Vec<String>,
        identities: Vec<PublicKeyHash>,
        our_chat_identity: &SigningPrivateKeyAndPublicHash,
        user_identity: &SigningPrivateKeyAndPublicHash,
        our_store: &dyn MessageStore,
        cas: &dyn ContentAddressedStorage,
    ) -> Result<ChatUpdate> {
        let mut update = ChatUpdate::empty(self.clone());
        for i in 0..usernames.len() {
            let username = usernames[i].clone();
            let identity = identities[i].clone();
            let us = update.state.host().clone();
            let new_member = update.state.host.fork(us.members_invited);
            let invite = Message::Invite { username, identity, recipient_id: new_member.clone() };
            let new_time = update.state.current.with_member(new_member);
            let sent = {
                let with_time = update.state.with_time(new_time);
                with_time.send_message(invite, our_chat_identity, user_identity, our_store, cas).await?
            };
            update = update.apply(sent);
        }
        Ok(update)
    }

    // ---- construction -------------------------------------------------------

    /// A brand-new single-member chat (`createNew`).
    pub fn create_new(uid: impl Into<String>, username: impl Into<String>, identity: PublicKeyHash) -> Chat {
        let creator = Id::creator();
        let us = Member::simple(username.into(), creator.clone(), identity, 0, 0);
        let mut members = BTreeMap::new();
        members.insert(creator.clone(), us.clone());
        let zero = TreeClock::init(&[us.id.clone()]);
        Chat::new(uid.into(), creator, zero, members, BTreeMap::new(), Vec::new())
    }

    /// A fixed group known at creation time — one `Chat` per initial member
    /// (`createNew` list form).
    pub fn create_new_group(uid: impl Into<String>, usernames: Vec<String>, identities: Vec<PublicKeyHash>) -> Vec<Chat> {
        let uid = uid.into();
        let mut members = BTreeMap::new();
        let mut initial = Vec::new();
        for (i, username) in usernames.into_iter().enumerate() {
            let id = Id::single(i as i32);
            initial.push(id.clone());
            members.insert(id.clone(), Member::simple(username, id, identities[i].clone(), 0, 0));
        }
        let genesis = TreeClock::init(&initial);
        initial
            .into_iter()
            .map(|id| Chat::new(uid.clone(), id, genesis.clone(), members.clone(), BTreeMap::new(), Vec::new()))
            .collect()
    }

    // ---- cbor ---------------------------------------------------------------

    pub fn from_cbor(cbor: &CborObject) -> Result<Chat> {
        let m = cbor.as_map().ok_or_else(|| Error::Cbor(format!("Incorrect cbor for Chat: {cbor:?}")))?;
        let get = |k: &str| m.get(&CborString::new(k)).ok_or_else(|| Error::Cbor(format!("Chat missing '{k}'")));
        let chat_uid = get("i")?.as_string().ok_or_else(|| Error::Cbor("Chat 'i' not a string".into()))?.to_string();
        let host = Id::from_cbor(get("h")?)?;
        let current = TreeClock::from_cbor(get("c")?)?;
        // "m" is a flat list [id0, member0, id1, member1, ...].
        let member_list = get("m")?.as_list().ok_or_else(|| Error::Cbor("Chat 'm' not a list".into()))?;
        if member_list.len() % 2 != 0 {
            return Err(Error::Cbor("Chat members list has odd length".into()));
        }
        let mut members = BTreeMap::new();
        for pair in member_list.chunks(2) {
            members.insert(Id::from_cbor(&pair[0])?, Member::from_cbor(&pair[1])?);
        }
        // "g" is a CborMap<String, GroupProperty>.
        let mut group_state = BTreeMap::new();
        if let Some(gm) = get("g")?.as_map() {
            for (k, v) in gm {
                group_state.insert(k.as_str().to_string(), GroupProperty::from_cbor(v)?);
            }
        }
        let recent = get("r")?
            .as_list()
            .ok_or_else(|| Error::Cbor("Chat 'r' not a list".into()))?
            .iter()
            .map(MessageEnvelope::from_cbor)
            .collect::<Result<Vec<MessageEnvelope>>>()?;
        Ok(Chat::new(chat_uid, host, current, members, group_state, recent))
    }
}

impl Cborable for Chat {
    fn to_cbor(&self) -> CborObject {
        // members as a flat [key, value, ...] list.
        let mut member_list = Vec::with_capacity(self.members.len() * 2);
        for (id, member) in &self.members {
            member_list.push(id.to_cbor());
            member_list.push(member.to_cbor());
        }
        // group state as a string-keyed map.
        let mut group_map = BTreeMap::new();
        for (k, v) in &self.group_state {
            group_map.insert(CborString::new(k.clone()), v.to_cbor());
        }
        CborObject::map()
            .put("v", CborObject::Long(0))
            .put("i", CborObject::Str(self.chat_uid.clone()))
            .put("h", self.host.to_cbor())
            .put("c", self.current.to_cbor())
            .put("m", CborObject::List(member_list))
            .put("g", CborObject::Map(group_map))
            .put("r", CborObject::List(self.recent_messages.iter().map(|m| m.to_cbor()).collect()))
            .build()
    }
}

/// Current UTC time in epoch milliseconds (`LocalDateTime.now(UTC)` to millis).
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
