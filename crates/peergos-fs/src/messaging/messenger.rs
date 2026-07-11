//! `Messenger` — the top-level chat API over a `UserContext`, ported from
//! `peergos.shared.messaging.Messenger`.
//!
//! All of a user's chats live in `/$username/.messaging/`. Each chat is a
//! directory named with a uid holding:
//!   - `shared/peergos-chat-messages.cborstream` — append-only message log,
//!   - `shared/peergos-chat-messages.index.bin`   — log byte-offset index,
//!   - `shared/peergos-chat-state.cbor`           — our view of the chat state,
//!   - `shared/media/...`                         — media shared in the chat,
//!   - `private-chat-state.cbor`                  — our chat identity keypair.
//!
//! To invite a user we append an invite to our log and read-share our `shared`
//! directory with them. To join, they clone our state + log, append a join
//! message, and read-share their `shared` directory back to us.

use super::controller::{ChatController, MESSAGING_BASE_DIR, PRIVATE_CHAT_STATE, SHARED_CHAT_STATE};
use super::chat::Chat;
use super::file_store::{FileBackedMessageStore, SHARED_MSG_LOG, SHARED_MSG_LOG_INDEX};
use super::member::Member;
use super::messages::Message;
use super::private_state::PrivateChatState;
use crate::context::UserContext;
use crate::feed::FileRef;
use crate::filewrapper::FileWrapper;
use crate::mimetype::calculate_mime_type;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::PublicKeyHash;
use std::collections::BTreeSet;

pub struct Messenger {
    context: UserContext,
}

impl Messenger {
    pub fn new(context: UserContext) -> Messenger {
        Messenger { context }
    }

    fn username(&self) -> Result<&str> {
        self.context.username().ok_or_else(|| Error::Protocol("messaging requires a logged-in user".into()))
    }

    fn identity(&self) -> Result<PublicKeyHash> {
        Ok(self.context.user().ok_or_else(|| Error::Protocol("messaging requires a logged-in user".into()))?.signer.public_key_hash.clone())
    }

    // ---- creation -----------------------------------------------------------

    /// Create a new chat (`createChat`).
    pub async fn create_chat(&self) -> Result<ChatController> {
        self.init_chat(None).await
    }

    /// Create a new chat scoped to an app (`createAppChat`).
    pub async fn create_app_chat(&self, app_name: &str) -> Result<ChatController> {
        self.init_chat(Some(app_name)).await
    }

    async fn init_chat(&self, app_name: Option<&str>) -> Result<ChatController> {
        let username = self.username()?.to_string();
        let prefix = match app_name {
            Some(app) => format!("chat-{app}$"),
            None => "chat$".to_string(),
        };
        let chat_id = format!("{prefix}{username}${}", uuid());
        let chat = Chat::create_new(chat_id.clone(), username.clone(), self.identity()?);
        let private_chat_state = Chat::generate_chat_identity()?;

        // Create /$username/.messaging/$chatId/shared and populate it.
        let home = self.context.get_home().await?;
        let shared_rel = format!("{MESSAGING_BASE_DIR}/{chat_id}/shared");
        let shared = home.get_or_mkdirs(&shared_rel).await?;
        shared.upload(SHARED_MSG_LOG, &[]).await?;
        let shared = shared.get_latest().await?;
        shared.upload(SHARED_MSG_LOG_INDEX, &vec![0u8; 16]).await?;
        let shared = shared.get_latest().await?;
        shared.upload(SHARED_CHAT_STATE, &chat.serialize()).await?;

        // Write our private chat state into the chat root.
        let root_rel = format!("{MESSAGING_BASE_DIR}/{chat_id}");
        let root = home.get_by_path(&root_rel).await?.ok_or_else(|| Error::Protocol("chat root missing after create".into()))?;
        root.upload(PRIVATE_CHAT_STATE, &private_chat_state.serialize()).await?;

        let controller = ChatController::new(self.context.clone(), chat_id, chat, private_chat_state);
        let signer = self.context.user().unwrap().signer.clone();
        let controller = controller.join(&signer).await?;
        controller.add_admin(&username).await
    }

    // ---- lookup -------------------------------------------------------------

    /// Load a chat by uid (`getChat`).
    pub async fn get_chat(&self, uuid: &str) -> Result<ChatController> {
        Messenger::load_controller(&self.context, uuid).await
    }

    pub(crate) async fn load_controller(context: &UserContext, chat_uuid: &str) -> Result<ChatController> {
        let username = context.username().ok_or_else(|| Error::Protocol("messaging requires a logged-in user".into()))?;
        let root_path = ChatController::chat_root_path(username, chat_uuid);
        let shared_path = format!("{root_path}/shared");
        let state = ChatController::read_chat_state(context, &shared_path).await?;
        let priv_path = format!("{root_path}/{PRIVATE_CHAT_STATE}");
        let priv_file = context.get_by_path(&priv_path).await?.ok_or_else(|| Error::Protocol(format!("private chat state missing: {priv_path}")))?;
        let private_chat_state = PrivateChatState::from_cbor(&CborObject::from_bytes(&priv_file.read().await?)?)?;
        Ok(ChatController::new(context.clone(), chat_uuid.to_string(), state, private_chat_state))
    }

    /// All of the user's chats (`listChats`). Chats that fail to load are skipped.
    pub async fn list_chats(&self) -> Result<Vec<ChatController>> {
        let home = self.context.get_home().await?;
        let chats_root = home.get_or_mkdirs(MESSAGING_BASE_DIR).await?;
        let mut out = Vec::new();
        for child in chats_root.children().await? {
            if let Ok(c) = Messenger::load_controller(&self.context, child.name()).await {
                out.push(c);
            }
        }
        Ok(out)
    }

    // ---- membership ---------------------------------------------------------

    /// Invite members and read-share the chat with them (`invite`).
    pub async fn invite(&self, chat: &ChatController, usernames: Vec<String>, identities: Vec<PublicKeyHash>) -> Result<ChatController> {
        let updated = chat.invite(usernames.clone(), identities).await?;
        let username = self.username()?.to_string();
        let shared_path = format!("{}/shared", ChatController::chat_root_path(&username, &chat.chat_uuid));
        let shared = self.context.get_by_path(&shared_path).await?.ok_or_else(|| Error::Protocol("chat shared dir missing".into()))?;
        let user = self.context.user().ok_or_else(|| Error::Protocol("messaging requires a logged-in user".into()))?;
        for name in &usernames {
            crate::share_read_access(user, &shared_path, shared.capability(), name, self.context.store(), self.context.mutable().as_ref()).await?;
        }
        Ok(updated)
    }

    /// Remove a member (`removeMember`).
    pub async fn remove_member(&self, chat: &ChatController, username: &str) -> Result<ChatController> {
        let member = chat.get_member(username).ok_or_else(|| Error::Protocol("No member in chat with that name!".into()))?;
        let me = self.username()?;
        if username != me && !chat.get_admins().contains(me) {
            return Err(Error::Protocol("Only admins can remove other members!".into()));
        }
        let msg = Message::RemoveMember { chat_uid: chat.chat_uuid.clone(), member_to_remove: member.id.clone() };
        chat.send_message(msg).await
    }

    /// True iff every member other than us has been removed (`allOtherMembersRemoved`).
    pub fn all_other_members_removed(&self, chat: &ChatController) -> bool {
        let me = match self.username() {
            Ok(u) => u,
            Err(_) => return false,
        };
        let names = chat.get_member_names();
        names.contains(me) && names.len() == 1
    }

    // ---- merging ------------------------------------------------------------

    /// A message store reading a mirror member's shared log (`getMessageStoreMirror`).
    pub fn message_store_for(&self, username: &str, uuid: &str) -> FileBackedMessageStore {
        let root = ChatController::chat_root_path(username, uuid);
        FileBackedMessageStore::new(self.context.clone(), format!("{root}/shared"), root)
    }

    /// Merge updates from `mirror_username`'s mirror of this chat (`mergeMessages`).
    pub async fn merge_messages(&self, current: &ChatController, mirror_username: &str) -> Result<ChatController> {
        let me = self.username()?;
        if mirror_username == me
            || (current.deleted_member_names().contains(mirror_username) && !self.all_other_members_removed(current))
        {
            return Ok(current.clone());
        }
        let mirror_store = self.message_store_for(mirror_username, &current.chat_uuid);
        match current.merge_messages(mirror_username, &mirror_store).await {
            Ok(updated) => Ok(updated),
            Err(_) => {
                // The member's mirror isn't accessible: either we've been removed or
                // they deleted their mirror. Admins remove them; others stop polling.
                if !current.get_pending_member_names().contains(mirror_username) {
                    if current.is_admin() {
                        return self.remove_member(current, mirror_username).await;
                    }
                    if current.deleted_member_names().contains(mirror_username) {
                        return Ok(current.clone());
                    }
                    let updated_priv = current.private_chat_state().add_deleted(mirror_username);
                    return self.update_private_state(updated_priv, current).await;
                }
                Ok(current.clone())
            }
        }
    }

    /// Merge from every member we're following (`mergeAllUpdates`).
    pub async fn merge_all_updates(&self, current: &ChatController, following: &BTreeSet<String>) -> Result<ChatController> {
        let to_pull: Vec<String> = current.get_member_names().into_iter().filter(|n| following.contains(n)).collect();
        let pending: BTreeSet<String> = current.get_pending_member_names().into_iter().filter(|n| following.contains(n)).collect();
        let mut controller = current.clone();
        for name in to_pull {
            match self.merge_messages(&controller, &name).await {
                Ok(updated) => controller = updated,
                Err(e) => {
                    if !pending.contains(&name) {
                        return Err(e);
                    }
                }
            }
        }
        Ok(controller)
    }

    async fn update_private_state(&self, state: PrivateChatState, current: &ChatController) -> Result<ChatController> {
        let root_path = ChatController::chat_root_path(self.username()?, &current.chat_uuid);
        let root = self.context.get_by_path(&root_path).await?.ok_or_else(|| Error::Protocol("chat root missing".into()))?;
        root.upload(PRIVATE_CHAT_STATE, &state.serialize()).await?;
        Ok(current.with_private(state))
    }

    // ---- messages / properties ---------------------------------------------

    pub async fn send_message(&self, current: &ChatController, message: Message) -> Result<ChatController> {
        current.send_message(message).await
    }

    pub async fn set_group_property(&self, current: &ChatController, key: &str, value: &str) -> Result<ChatController> {
        current.send_message(Message::GroupState { key: key.to_string(), value: value.to_string() }).await
    }

    /// Upload a media file into the chat's shared media directory and return its
    /// mime type + a [`FileRef`] to embed in a message (`uploadMedia`). The file is
    /// stored at `/$user/.messaging/$chatUuid/shared/media/$year/$month/$uuid.$ext`.
    pub async fn upload_media(
        &self,
        current: &ChatController,
        media: &[u8],
        file_extension: &str,
        post_time_epoch_secs: i64,
    ) -> Result<(String, FileRef)> {
        let username = self.username()?.to_string();
        let name = format!("{}.{file_extension}", uuid());
        let (year, month) = year_month(post_time_epoch_secs);
        let dir_rel = format!("{MESSAGING_BASE_DIR}/{}/shared/media/{year}/{month}", current.chat_uuid);
        let home = self.context.get_home().await?;
        let dir = home.get_or_mkdirs(&dir_rel).await?;
        let file = dir.upload(&name, media).await?;

        let mime = calculate_mime_type(media, &name);
        let path = format!("/{username}/{dir_rel}/{name}");
        let content_hash = sha256_multihash(media);
        Ok((mime, FileRef { path, cap: file.capability().read_only(), content_hash }))
    }

    /// Delete a chat from our space (`deleteChat`).
    pub async fn delete_chat(&self, chat: &ChatController) -> Result<()> {
        let parent_path = format!("/{}/{MESSAGING_BASE_DIR}", self.username()?);
        let parent = self.context.get_by_path(&parent_path).await?.ok_or_else(|| Error::Protocol("messaging dir missing".into()))?;
        parent.remove_child(&chat.chat_uuid).await
    }

    // ---- joining an existing chat ------------------------------------------

    /// Copy a chat a friend shared with us into our space and join it
    /// (`cloneLocallyAndJoin`). `source_shared_dir` is a `FileWrapper` for the
    /// inviter's `.../$chatId/shared` directory (obtained from the read-share).
    pub async fn clone_locally_and_join(&self, source_shared_dir: &FileWrapper) -> Result<ChatController> {
        let username = self.username()?.to_string();
        let private_chat_state = Chat::generate_chat_identity()?;

        // The chatId is the name of the shared dir's parent directory.
        let chat_id = chat_id_from_shared_path(source_shared_dir.path())
            .ok_or_else(|| Error::Protocol(format!("cannot derive chatId from {}", source_shared_dir.path())))?;

        // Create our own chat root + shared dir (errors if we already have this chat).
        let home = self.context.get_home().await?;
        let shared_rel = format!("{MESSAGING_BASE_DIR}/{chat_id}/shared");
        let shared = home.get_or_mkdirs(&shared_rel).await?;

        // Copy the mirror's state, re-rooted at us.
        let mirror_state_bytes = source_shared_dir
            .child(SHARED_CHAT_STATE)
            .await?
            .ok_or_else(|| Error::Protocol("source chat state missing".into()))?
            .read()
            .await?;
        let mirror_state = Chat::from_cbor(&CborObject::from_bytes(&mirror_state_bytes)?)?;
        let our_id = mirror_state.get_member(&username).ok_or_else(|| Error::Protocol("we are not a member of this chat".into()))?.id.clone();
        let our_member = Member::new(username.clone(), our_id, self.identity()?, None, mirror_state.host().messages_merged_upto, 0, false);
        let our_version = mirror_state.copy(our_member)?;
        shared.upload(SHARED_CHAT_STATE, &our_version.serialize()).await?;

        // Copy the message log + index verbatim.
        for name in [SHARED_MSG_LOG, SHARED_MSG_LOG_INDEX] {
            let bytes = match source_shared_dir.child(name).await? {
                Some(f) => f.read().await?,
                None => Vec::new(),
            };
            let shared = shared.get_latest().await?;
            shared.upload(name, &bytes).await?;
        }

        // Write our private chat state.
        let root_rel = format!("{MESSAGING_BASE_DIR}/{chat_id}");
        let root = home.get_by_path(&root_rel).await?.ok_or_else(|| Error::Protocol("chat root missing after clone".into()))?;
        root.upload(PRIVATE_CHAT_STATE, &private_chat_state.serialize()).await?;

        // Read-share our shared dir back to the chat host.
        let shared_path = format!("/{}/shared", ChatController::chat_root_path(&username, &chat_id).trim_start_matches('/'));
        let shared = self.context.get_by_path(&shared_path).await?.ok_or_else(|| Error::Protocol("our shared dir missing".into()))?;
        let user = self.context.user().unwrap();
        if let Some(owner) = owner_from_path(source_shared_dir.path()) {
            crate::share_read_access(user, &shared_path, shared.capability(), &owner, self.context.store(), self.context.mutable().as_ref()).await?;
        }

        let controller = Messenger::load_controller(&self.context, &chat_id).await?;
        let signer = self.context.user().unwrap().signer.clone();
        controller.join(&signer).await
    }
}

/// Extract the chatId (the shared dir's parent name) from a path like
/// `/alice/.messaging/<chatId>/shared`.
fn chat_id_from_shared_path(path: &str) -> Option<String> {
    let comps: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    if comps.last() == Some(&"shared") && comps.len() >= 2 {
        Some(comps[comps.len() - 2].to_string())
    } else {
        None
    }
}

/// The owner username (first path component) of `/alice/.messaging/...`.
fn owner_from_path(path: &str) -> Option<String> {
    path.trim_matches('/').split('/').find(|s| !s.is_empty()).map(|s| s.to_string())
}

/// The bare sha2-256 multihash of `data` (`[0x12, 0x20] ++ sha256`), as stored in
/// a `FileRef` merkle link (`Hasher.hashFromStream`).
fn sha256_multihash(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x12, 0x20];
    out.extend_from_slice(&peergos_crypto::hash::sha256(data));
    out
}

/// Civil year + month (1-12) for an epoch-second timestamp (Howard Hinnant's
/// days-from-civil, inverted).
fn year_month(epoch_secs: i64) -> (i64, u32) {
    let days = epoch_secs.div_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32)
}

/// A random UUID-v4-shaped string for chat ids.
fn uuid() -> String {
    let b = peergos_crypto::random_bytes(16);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}
