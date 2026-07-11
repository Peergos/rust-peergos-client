//! `ChatController` — a live handle to one chat: the current [`Chat`] state, our
//! [`PrivateChatState`], and the read/modify/commit machinery over the filesystem.
//! Ported from `peergos.shared.messaging.ChatController`, adapted to this crate's
//! `UserContext`/`FileWrapper` API (no `Snapshot`/`Committer`: each mutation
//! re-reads the state file, applies the change, and commits per-operation).

use super::chat::{Chat, ChatUpdate};
use super::envelope::MessageEnvelope;
use super::file_store::FileBackedMessageStore;
use super::member::{Member, ADMINS_STATE_KEY};
use super::messages::Message;
use super::private_state::PrivateChatState;
use super::store::MessageStore;
use crate::context::UserContext;
use crate::feed::FileRef;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{OwnerProof, SigningPrivateKeyAndPublicHash};
use std::collections::BTreeSet;

pub(crate) const SHARED_CHAT_STATE: &str = "peergos-chat-state.cbor";
pub(crate) const SHARED_MSG_LOG_INDEX: &str = "peergos-chat-messages.index.bin";
pub(crate) const PRIVATE_CHAT_STATE: &str = "private-chat-state.cbor";
pub(crate) const MESSAGING_BASE_DIR: &str = ".messaging";

#[derive(Clone)]
pub struct ChatController {
    context: UserContext,
    pub chat_uuid: String,
    state: Chat,
    private_chat_state: PrivateChatState,
}

impl ChatController {
    pub(crate) fn new(context: UserContext, chat_uuid: String, state: Chat, private_chat_state: PrivateChatState) -> ChatController {
        ChatController { context, chat_uuid, state, private_chat_state }
    }

    // ---- paths / helpers ----------------------------------------------------

    fn username(&self) -> Result<&str> {
        self.context.username().ok_or_else(|| Error::Protocol("chat requires a logged-in user".into()))
    }

    pub(crate) fn chat_root_path(username: &str, chat_uuid: &str) -> String {
        format!("/{username}/{MESSAGING_BASE_DIR}/{chat_uuid}")
    }

    fn root_path(&self) -> Result<String> {
        Ok(ChatController::chat_root_path(self.username()?, &self.chat_uuid))
    }

    fn shared_path(&self) -> Result<String> {
        Ok(format!("{}/shared", self.root_path()?))
    }

    fn own_store(&self) -> Result<FileBackedMessageStore> {
        Ok(FileBackedMessageStore::new(self.context.clone(), self.shared_path()?, self.root_path()?))
    }

    fn signer(&self) -> Result<SigningPrivateKeyAndPublicHash> {
        Ok(self.context.user().ok_or_else(|| Error::Protocol("chat requires a logged-in user".into()))?.signer.clone())
    }

    /// Re-read the committed chat state from `shared/peergos-chat-state.cbor`.
    async fn latest_state(&self) -> Result<Chat> {
        ChatController::read_chat_state(&self.context, &self.shared_path()?).await
    }

    pub(crate) async fn read_chat_state(context: &UserContext, shared_path: &str) -> Result<Chat> {
        let path = format!("{shared_path}/{SHARED_CHAT_STATE}");
        let file = context.get_by_path(&path).await?.ok_or_else(|| Error::Protocol(format!("chat state missing: {path}")))?;
        Chat::from_cbor(&CborObject::from_bytes(&file.read().await?)?)
    }

    // ---- read-only accessors ------------------------------------------------

    pub fn state(&self) -> &Chat {
        &self.state
    }

    pub fn host(&self) -> &Member {
        self.state.host()
    }

    pub fn get_member(&self, username: &str) -> Option<&Member> {
        self.state.get_member(username)
    }

    pub fn get_username(&self, author: &super::id::Id) -> Option<String> {
        self.state.get_member_by_id(author).map(|m| m.username.clone())
    }

    /// Active members: not removed and not locally deleted (`getMemberNames`).
    pub fn get_member_names(&self) -> BTreeSet<String> {
        self.state
            .members
            .values()
            .filter(|m| !m.removed)
            .filter(|m| !self.private_chat_state.deleted_members.contains(&m.username))
            .map(|m| m.username.clone())
            .collect()
    }

    /// Members who have been invited but not yet announced a chat identity
    /// (`getPendingMemberNames`).
    pub fn get_pending_member_names(&self) -> BTreeSet<String> {
        self.state
            .members
            .values()
            .filter(|m| !m.removed)
            .filter(|m| m.chat_identity.is_none())
            .map(|m| m.username.clone())
            .collect()
    }

    pub fn deleted_member_names(&self) -> &BTreeSet<String> {
        &self.private_chat_state.deleted_members
    }

    pub fn get_recent(&self) -> Vec<MessageEnvelope> {
        self.state.get_recent()
    }

    pub fn get_group_property(&self, key: &str) -> Option<String> {
        self.state.group_state.get(key).map(|p| p.value.clone())
    }

    pub fn has_group_property(&self, key: &str) -> bool {
        self.state.group_state.contains_key(key)
    }

    pub fn get_title(&self) -> String {
        self.state.get_title()
    }

    pub fn get_admins(&self) -> BTreeSet<String> {
        self.state.get_admins()
    }

    pub fn is_admin(&self) -> bool {
        self.state.get_admins().contains(&self.state.host().username)
    }

    pub fn with_private(&self, priv_state: PrivateChatState) -> ChatController {
        let mut c = self.clone();
        c.private_chat_state = priv_state;
        c
    }

    pub fn private_chat_state(&self) -> &PrivateChatState {
        &self.private_chat_state
    }

    /// Fetch a range of message envelopes from the log (`getMessages`).
    pub async fn get_messages(&self, from: i64, to: i64) -> Result<Vec<MessageEnvelope>> {
        let signed = self.own_store()?.get_messages(from, to).await?;
        Ok(signed.into_iter().map(|s| s.msg).collect())
    }

    // ---- mutations ----------------------------------------------------------

    /// Send a message and commit (`sendMessage`).
    pub async fn send_message(&self, message: Message) -> Result<ChatController> {
        let state = self.latest_state().await?;
        let store = self.own_store()?;
        let signer = self.signer()?;
        let cas = self.context.store();
        let update = state
            .send_message(message, &self.private_chat_state.chat_identity, &signer, &store, cas.as_ref())
            .await?;
        let mirror = self.username()?.to_string();
        self.commit_update(update, mirror).await
    }

    /// Add `username` to the admin list (`addAdmin`).
    pub async fn add_admin(&self, username: &str) -> Result<ChatController> {
        let mut admins = self.state.get_admins();
        if !admins.is_empty() && !admins.contains(&self.state.host().username) {
            return Err(Error::Protocol("Only admins can modify the admin list!".into()));
        }
        admins.insert(username.to_string());
        self.send_message(Message::GroupState { key: ADMINS_STATE_KEY.to_string(), value: join_csv(&admins) }).await
    }

    /// Remove `username` from the admin list (`removeAdmin`).
    pub async fn remove_admin(&self, username: &str) -> Result<ChatController> {
        let mut admins = self.state.get_admins();
        if !admins.contains(&self.state.host().username) {
            return Err(Error::Protocol("Only admins can modify the admin list!".into()));
        }
        admins.remove(username);
        if admins.is_empty() {
            return Err(Error::Protocol("A chat must always have at least 1 admin".into()));
        }
        self.send_message(Message::GroupState { key: ADMINS_STATE_KEY.to_string(), value: join_csv(&admins) }).await
    }

    /// Announce our chat identity after creating/cloning the chat (`join`).
    pub async fn join(&self, identity: &SigningPrivateKeyAndPublicHash) -> Result<ChatController> {
        let chat_id = OwnerProof::build(identity, &self.private_chat_state.chat_identity.public_key_hash)?;
        let state = self.latest_state().await?;
        let store = self.own_store()?;
        let cas = self.context.store();
        let host = state.host().clone();
        let update = state
            .join(&host, chat_id, self.private_chat_state.chat_id_public.clone(), identity, &store, cas.as_ref())
            .await?;
        let mirror = self.username()?.to_string();
        self.commit_update(update, mirror).await
    }

    /// Invite members and commit; the read-share of the chat dir is done by
    /// [`super::Messenger::invite`] (`invite`).
    pub async fn invite(&self, usernames: Vec<String>, identities: Vec<peergos_core::keys::PublicKeyHash>) -> Result<ChatController> {
        let state = self.latest_state().await?;
        let store = self.own_store()?;
        let signer = self.signer()?;
        let cas = self.context.store();
        let update = state
            .invite_members(usernames, identities, &self.private_chat_state.chat_identity, &signer, &store, cas.as_ref())
            .await?;
        let mirror = self.username()?.to_string();
        self.commit_update(update, mirror).await
    }

    /// Merge new messages from `username`'s mirror store (`mergeMessages`).
    pub async fn merge_messages(&self, username: &str, mirror_store: &dyn MessageStore) -> Result<ChatController> {
        let mirror_id = self
            .state
            .get_member(username)
            .ok_or_else(|| Error::Protocol(format!("no member named {username}")))?
            .id
            .clone();
        let state = self.latest_state().await?;
        let signer = self.signer()?;
        let cas = self.context.store();
        let update = state.merge(&mirror_id, &signer, mirror_store, cas.as_ref()).await?;
        self.commit_update(update, username.to_string()).await
    }

    // ---- commit -------------------------------------------------------------

    async fn commit_update(&self, update: ChatUpdate, mirror_username: String) -> Result<ChatController> {
        if update.is_empty() && update.state == self.state {
            return Ok(self.clone());
        }
        let store = self.own_store()?;
        // 1. revoke access from removed members
        if !update.to_revoke_access.is_empty() {
            store.revoke_access(update.to_revoke_access.clone()).await?;
        }
        // 2. mirror any referenced media into our storage (best-effort)
        for r in &update.media_to_copy {
            let _ = self.mirror_media(r, &mirror_username).await;
        }
        // 3. commit any new private state
        let mut new_priv = self.private_chat_state.clone();
        if let Some(p) = &update.priv_state {
            self.write_private_state(p).await?;
            new_priv = p.clone();
        }
        // 4. append the new messages to the shared log
        store.add_messages(self.state.host().messages_merged_upto, update.new_messages.clone()).await?;
        // 5. overwrite the shared state file
        self.write_state(&update.state).await?;
        Ok(ChatController::new(self.context.clone(), self.chat_uuid.clone(), update.state, new_priv))
    }

    async fn write_state(&self, state: &Chat) -> Result<()> {
        let shared = self
            .context
            .get_by_path(&self.shared_path()?)
            .await?
            .ok_or_else(|| Error::Protocol("chat shared dir missing".into()))?;
        shared.upload(SHARED_CHAT_STATE, &state.serialize()).await?;
        Ok(())
    }

    async fn write_private_state(&self, priv_state: &PrivateChatState) -> Result<()> {
        let root = self
            .context
            .get_by_path(&self.root_path()?)
            .await?
            .ok_or_else(|| Error::Protocol("chat root dir missing".into()))?;
        root.upload(PRIVATE_CHAT_STATE, &priv_state.serialize()).await?;
        Ok(())
    }

    /// Best-effort media mirroring: copy an attachment referenced from another
    /// member's message into our own chat media directory. Java resolves the exact
    /// year/month sub-path; this simplified port copies by filename and never fails
    /// the merge (media upload isn't produced by this client yet).
    async fn mirror_media(&self, r: &FileRef, mirror_username: &str) -> Result<()> {
        if mirror_username == self.username()? {
            return Ok(());
        }
        let source = match self.context.get_by_path(&r.path).await? {
            Some(f) => f,
            None => return Ok(()),
        };
        let data = source.read().await?;
        let filename = r.path.rsplit('/').next().unwrap_or("attachment").to_string();
        let media_dir = format!("{}/shared/media/mirror", self.root_path()?);
        let home = self.context.get_home().await?;
        let rel = media_dir.trim_start_matches('/');
        // Skip the leading username component when navigating from home.
        let rel = rel.splitn(2, '/').nth(1).unwrap_or(rel);
        let dir = home.get_or_mkdirs(rel).await?;
        dir.upload(&filename, &data).await?;
        Ok(())
    }
}

/// Join a sorted set of admin names with commas (matching Java's `TreeSet` join).
fn join_csv(names: &BTreeSet<String>) -> String {
    names.iter().cloned().collect::<Vec<_>>().join(",")
}
