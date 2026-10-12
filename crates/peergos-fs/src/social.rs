//! The social layer: follow requests, ported from `peergos.shared.social` +
//! `UserContext`.
//!
//! A follow request grants the recipient a read-only capability to the sender's
//! per-friend sharing folder (`/sender/shared/<recipient>`). It is encrypted to
//! the recipient's public boxing key (see [`peergos_core::boxing`]) and posted to
//! the social endpoint; the recipient fetches and decrypts pending requests.

use crate::capability::AbsoluteCapability;
use crate::login::{EntryPoint, LoggedInUser};
use crate::{create_directory, list_directory, recover_signer};
use peergos_core::auth::BatId;
use peergos_cbor::{CborObject, CborString, Cborable};
use peergos_core::boxing::{BoxingKeyPair, PublicBoxingKey};
use peergos_core::error::{Error, Result};
use peergos_core::keys::PublicKeyHash;
use peergos_core::mutable::MutablePointers;
use peergos_core::poster::HttpPoster;
use peergos_core::storage::ContentAddressedStorage;
use peergos_core::symmetric::SymmetricKey;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SOCIAL_URL: &str = "peergos/v0/social/";
const FOLLOW_REQUEST_PADDING: usize = 512;

/// A decrypted incoming follow request.
#[derive(Debug, Clone)]
pub struct ReceivedFollowRequest {
    /// The sender's entry point (a read cap to their sharing folder for us), if
    /// they accepted.
    pub entry: Option<EntryPoint>,
    /// A requested key, if they reciprocated.
    pub key: Option<SymmetricKey>,
    /// The raw encrypted request (needed to remove it from the server).
    pub raw_cipher: Vec<u8>,
}

impl ReceivedFollowRequest {
    /// The username of the sender (from their entry point), if present.
    pub fn sender(&self) -> Option<&str> {
        self.entry.as_ref().map(|e| e.owner_name.as_str())
    }
}

/// `getPublicKeys`: resolve a username to its identity key hash and public
/// boxing key (via the PKI + the user's `WriterData.inbound`).
pub async fn get_public_keys(
    poster: &dyn HttpPoster,
    store: &dyn ContentAddressedStorage,
    mutable: &dyn MutablePointers,
    username: &str,
) -> Result<(PublicKeyHash, PublicBoxingKey)> {
    let identity = crate::login::get_public_key_hash(poster, username)
        .await?
        .ok_or_else(|| Error::Protocol(format!("Unknown username: {username}")))?;
    let pointer = mutable.get_pointer_target(&identity, &identity, store).await?;
    let wd_cid = pointer.updated.ok_or_else(|| Error::Protocol("user has no data".into()))?;
    let wd = store
        .get(&identity, &wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("writer data block missing".into()))?;
    let boxer_hash = wd
        .get("inbound")
        .ok_or_else(|| Error::Protocol(format!("user {username} has no boxing key")))
        .and_then(PublicKeyHash::from_cbor)?;
    let boxer_cbor = if boxer_hash.is_identity() {
        CborObject::from_bytes(boxer_hash.target.get_hash())?
    } else {
        store
            .get(&identity, &boxer_hash.target, None)
            .await?
            .ok_or_else(|| Error::Protocol("boxing key block missing".into()))?
    };
    Ok((identity, PublicBoxingKey::from_cbor(&boxer_cbor)?))
}

/// `getSharingFolder().getOrMkdirs(name)`: the writable capability to the child
/// `name` under `dir_cap`, creating it if absent.
async fn get_or_mkdir(
    dir_cap: &AbsoluteCapability,
    name: &str,
    signer: &peergos_core::keys::SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let existing = list_directory(dir_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == name);
    match existing {
        Some(e) => Ok(e.cap),
        None => create_directory(dir_cap, name, Some(signer.clone()), mirror_bat, store, mutable).await,
    }
}

/// The capability to our own `shared` folder (`/username/shared`).
async fn sharing_folder(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    list_directory(home, store, mutable)
        .await?
        .into_iter()
        .find(|e| e.name == "shared")
        .map(|e| e.cap)
        .ok_or_else(|| Error::Protocol("no shared folder".into()))
}

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn url_encode(s: &str) -> String {
    peergos_core::storage::url_encode(s)
}

/// `sendFollowRequest`: grant `target_username` read access to our sharing folder
/// for them and post an (encrypted) follow request. `reciprocate` includes a
/// random key inviting them to also share with us (like `sendInitialFollowRequest`).
///
/// The request is recorded as pending before it is sent, otherwise their reply
/// can't be recognised. If anything fails, what this call added is rolled back so
/// the request can be tried again.
pub async fn send_follow_request(
    user: &LoggedInUser,
    target_username: &str,
    reciprocate: bool,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<bool> {
    if target_username == user.username {
        return Ok(false);
    }
    // following someone who doesn't follow us, e.g. after they removed us, is when a
    // request asks them to follow back
    let following = get_following(user, store.clone(), mutable).await?;
    let followers = get_follower_names(user, store.clone(), mutable).await?;
    if following.iter().any(|f| f == target_username) && followers.iter().any(|f| f == target_username) {
        return Err(Error::Protocol(format!("You are already friends with {target_username}")));
    }
    // asking to follow someone we have unfollowed means we want to follow them
    // again, but a block has to be undone explicitly
    follow_again(user, target_username, store.clone(), mutable).await?;
    let (target_identity, target_boxer) =
        get_public_keys(poster, store.as_ref(), mutable, target_username).await?;

    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let dir_existed = has_child(&sharing, target_username, store.clone(), mutable).await?;
    let pending: BTreeSet<String> = get_pending_outgoing(user, store.clone(), mutable).await?.into_iter().collect();
    let was_pending = pending.contains(target_username);

    let attempt = async {
        let friend_root =
            get_or_mkdir(&sharing, target_username, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
        let entry = EntryPoint { pointer: friend_root.read_only(), owner_name: user.username.clone() };
        let requested_key =
            if reciprocate { Some(SymmetricKey::new(peergos_crypto::random_bytes(32), false)?) } else { None };
        // FollowRequest cbor: {e: entry, k: requestedKey?}
        let mut fr = CborObject::map().put("e", entry.to_cbor());
        if let Some(k) = &requested_key {
            fr = fr.put("k", k.to_cbor());
        }
        let follow_request = fr.build();
        let mut updated = pending.clone();
        updated.insert(target_username.to_string());
        write_pending_outgoing(user, &updated, store.clone(), mutable).await?;
        // a request that reached them but whose response was lost is harmless to
        // resend, whereas rolling back our pending state would leave their reply
        // unrecognised
        let mut attempts = 3;
        loop {
            match blind_and_send(&target_identity, &target_boxer, &follow_request, poster).await {
                Ok(sent) => return Ok(sent),
                Err(e) if attempts <= 1 => return Err(e),
                Err(_) => attempts -= 1,
            }
        }
    }
    .await;
    match attempt {
        Ok(sent) => Ok(sent),
        Err(e) => {
            // an earlier request to them may still be answered, so leave its state alone
            if !was_pending {
                if let Err(re) = rollback_follow_request(user, target_username, !dir_existed, store, mutable).await {
                    log::warn!("Couldn't roll back follow request to {target_username}: {re}");
                }
            }
            Err(e)
        }
    }
}

/// Pending is cleared before the dir is removed, so a failure in between leaves
/// them looking like a follower until the request is resent, rather than pending
/// with no dir.
async fn rollback_follow_request(
    user: &LoggedInUser,
    target_username: &str,
    remove_dir: bool,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    remove_from_pending_outgoing(user, target_username, store.clone(), mutable).await?;
    if remove_dir {
        delete_shared_child(user, target_username, store, mutable).await?;
    }
    Ok(())
}

async fn has_child(
    dir: &AbsoluteCapability,
    name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<bool> {
    Ok(list_directory(dir, store, mutable).await?.iter().any(|e| e.name == name))
}

/// Delete `/username/shared/<name>` if present.
async fn delete_shared_child(
    user: &LoggedInUser,
    name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    if !has_child(&sharing, name, store.clone(), mutable).await? {
        return Ok(());
    }
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    crate::delete_child(&sharing, name, Some(signer), user.mirror_bat_id().as_ref(), store, mutable).await
}

/// `blindAndSendFollowRequest`: wrap + encrypt a follow request to the target and
/// POST it to the social endpoint.
async fn blind_and_send(
    target_identity: &PublicKeyHash,
    target_boxer: &PublicBoxingKey,
    follow_request: &CborObject,
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let blind = blind_follow_request(follow_request, target_boxer)?;
    let url = format!("{SOCIAL_URL}followRequest?owner={}", url_encode(&target_identity.to_string()));
    let res = poster.post_unzip(&url, blind.to_bytes(), 30_000).await?;
    Ok(res.first().is_some_and(|b| *b != 0))
}

/// `BlindFollowRequest.build`: wrap the follow request encrypted to `target` with
/// a fresh ephemeral boxing key, so the sender isn't revealed on the wire.
fn blind_follow_request(follow_request: &CborObject, target: &PublicBoxingKey) -> Result<CborObject> {
    let ephemeral = match target {
        PublicBoxingKey::Hybrid { .. } => BoxingKeyPair::random_hybrid(),
        PublicBoxingKey::Curve25519(_) => BoxingKeyPair::random_curve25519(),
    };
    // PaddedAsymmetricCipherText: pad the serialized request, then box it.
    let padded = pad(&follow_request.to_bytes(), FOLLOW_REQUEST_PADDING);
    let cipher = target.encrypt(&padded, &ephemeral.secret)?;
    // AsymmetricCipherText is a raw byte-array cbor.
    Ok(CborObject::map()
        .put("k", ephemeral.public.to_cbor())
        .put("f", CborObject::ByteString(cipher))
        .build())
}

/// Zero-pad to a multiple of `block` (`PaddedCipherText.pad`).
fn pad(input: &[u8], block: usize) -> Vec<u8> {
    let n = input.len().div_ceil(block).max(1);
    let mut out = input.to_vec();
    out.resize(n * block, 0);
    out
}

/// `getFollowRequests` + `processFollowRequests`: fetch pending follow requests
/// and decrypt those addressed to us with our boxing key.
pub async fn get_follow_requests(
    user: &LoggedInUser,
    poster: &dyn HttpPoster,
) -> Result<Vec<ReceivedFollowRequest>> {
    let boxer = user
        .boxer
        .as_ref()
        .ok_or_else(|| Error::Protocol("account has no boxing key (legacy?)".into()))?;

    // Authenticate with a signed timestamp.
    let signed_time = user.signer.secret.sign_message(&CborObject::Long(now_millis()).to_bytes())?;
    let url = format!(
        "{SOCIAL_URL}getFollowRequests?owner={}&auth={}",
        url_encode(&user.identity.to_string()),
        to_hex(&signed_time)
    );
    let res = poster.get(&url).await?;
    // Response is a length-prefixed byte array wrapping a cbor list.
    if res.len() < 4 {
        return Ok(Vec::new());
    }
    let len = u32::from_be_bytes([res[0], res[1], res[2], res[3]]) as usize;
    let raw = res.get(4..4 + len).ok_or_else(|| Error::Protocol("truncated follow requests".into()))?;
    let list = CborObject::from_bytes(raw)?;
    let items = list.as_list().ok_or_else(|| Error::Cbor("follow requests not a list".into()))?;

    let mut out = Vec::new();
    for blind in items {
        let raw_cipher = blind.to_bytes();
        // Decrypt with our boxer secret + the ephemeral sender key ("k").
        let dummy = blind
            .get("k")
            .ok_or_else(|| Error::Cbor("blind request missing 'k'".into()))
            .and_then(PublicBoxingKey::from_cbor)?;
        let cipher = blind
            .get("f")
            .and_then(|c| c.as_bytes())
            .ok_or_else(|| Error::Cbor("blind request missing 'f'".into()))?;
        // A request addressed to someone else won't decrypt — skip it.
        let Ok(padded) = boxer.secret.decrypt(cipher, &dummy) else { continue };
        let fr = CborObject::from_bytes_prefix(&padded)?;
        let entry = fr.get("e").map(EntryPoint::from_cbor).transpose()?;
        let key = fr.get("k").map(SymmetricKey::from_cbor).transpose()?;
        out.push(ReceivedFollowRequest { entry, key, raw_cipher });
    }
    Ok(out)
}

/// `removeFollowRequest`: delete a processed request from our inbox (signed with
/// our identity key).
pub async fn remove_follow_request(
    user: &LoggedInUser,
    raw_cipher: &[u8],
    poster: &dyn HttpPoster,
) -> Result<bool> {
    let signed = user.signer.secret.sign_message(raw_cipher)?;
    let url = format!("{SOCIAL_URL}removeFollowRequest?owner={}", url_encode(&user.identity.to_string()));
    let res = poster.post_unzip(&url, signed, 30_000).await?;
    Ok(res.first().is_some_and(|b| *b != 0))
}

/// The home file holding entry points shared with us by friends
/// (`ENTRY_POINTS_FROM_FRIENDS_FILENAME`) — an append-only stream of EntryPoint cbors.
const FROM_FRIENDS_FILE: &str = ".from-friends.cborstream";

/// Append a friend's entry point to our `.from-friends.cborstream`
/// (`addExternalEntryPoint`), persisting read access to what they share with us.
async fn persist_friend_entry_point(
    user: &LoggedInUser,
    entry: &EntryPoint,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if entry.owner_name == user.username {
        return Err(Error::Protocol("cannot add an entry point to your own filesystem".into()));
    }
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let existing = list_directory(home, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == FROM_FRIENDS_FILE);
    let mut contents = match existing {
        Some(e) => crate::read_file(&e.cap, store.clone(), mutable).await?.1,
        None => Vec::new(),
    };
    let raw = entry.to_cbor().to_bytes();
    if get_friends(user, store.clone(), mutable).await?.iter().any(|e| e.to_cbor().to_bytes() == raw) {
        return Ok(());
    }
    contents.extend_from_slice(&raw);
    crate::upload_file_hidden(home, FROM_FRIENDS_FILE, &contents, None, Some(signer), user.mirror_bat_id().as_ref(), store, mutable).await?;
    Ok(())
}

/// The entry points shared with us by friends (`getFriendsEntryPoints`): each is
/// a read cap to a friend's `/friend/shared/<us>` folder. Persisted across logins.
const SHARED_DIR: &str = "shared";
const SOCIAL_STATE_FILE: &str = ".social-state.cbor";
/// Who we have unfollowed. The name predates blocking, when this was all a block was.
const UNFOLLOWED_USERNAMES_FILE: &str = ".blocked-usernames.txt";
const BLOCKED_USERS_FILE: &str = ".blocked-users.cbor";
/// A follower's sharing dir is renamed to this prefix + their name while removing them.
const REMOVING_FOLLOWER_PREFIX: &str = ".removing-";
const FRIEND_ANNOTATIONS_FILE: &str = ".annotations";

/// A snapshot of the user's social state (`getSocialState`).
#[derive(Debug, Clone)]
pub struct SocialState {
    /// Follow requests still to be answered; replies to ours are already processed.
    pub pending_incoming_requests: Vec<ReceivedFollowRequest>,
    pub pending_outgoing: Vec<String>,
    pub following: Vec<String>,
    pub followers: Vec<String>,
    /// Who we never see anything from, even via someone else.
    pub blocked: Vec<String>,
    /// Who we don't see directly, though they may still follow us.
    pub unfollowed: Vec<String>,
    /// The friend/following entry-point roots (kept for navigation).
    pub friends: Vec<EntryPoint>,
    /// Group uid → name, built-in and custom.
    pub groups: BTreeMap<String, String>,
}

impl SocialState {
    /// Mutual friends: those we follow who also follow us.
    pub fn friend_names(&self) -> Vec<String> {
        self.following.iter().filter(|f| self.followers.contains(f)).cloned().collect()
    }

    pub fn group_uid(&self, name: &str) -> Option<String> {
        group_name_to_uid(&self.groups, name)
    }

    /// The built-in groups first, then custom groups ordered by name (`getGroupUids`).
    pub fn group_uids(&self) -> Vec<String> {
        let builtin: Vec<String> = [FRIENDS_GROUP, FOLLOWERS_GROUP].iter().filter_map(|n| self.group_uid(n)).collect();
        let mut custom: Vec<(&String, &String)> =
            self.groups.iter().filter(|(uid, _)| !builtin.contains(uid)).collect();
        custom.sort_by(|a, b| a.1.cmp(b.1).then(a.0.cmp(b.0)));
        builtin.into_iter().chain(custom.into_iter().map(|(uid, _)| uid.clone())).collect()
    }
}

/// Names of custom groups need not be unique, so the smallest uid wins, and the
/// built-in names are reserved for the built-in groups.
fn group_name_to_uid(groups: &BTreeMap<String, String>, name: &str) -> Option<String> {
    groups.iter().find(|(_, n)| n.as_str() == name).map(|(u, _)| u.clone())
}

/// Read a file named `name` in the user's home directory, if present.
async fn read_home_child(
    user: &LoggedInUser,
    name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Option<Vec<u8>>> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    match list_directory(home, store.clone(), mutable).await?.into_iter().find(|e| e.name == name) {
        Some(e) => Ok(Some(crate::read_file(&e.cap, store, mutable).await?.1)),
        None => Ok(None),
    }
}

/// The usernames of the people the user follows (`getFollowing`) — the owners of
/// the friend roots we can still retrieve, excluding anyone unfollowed or blocked.
pub async fn get_following(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    let hidden: BTreeSet<String> = get_unfollowed(user, store.clone(), mutable)
        .await?
        .into_iter()
        .chain(get_blocked(user, store.clone(), mutable).await?)
        .collect();
    let mut names: Vec<String> = Vec::new();
    for e in get_friends(user, store.clone(), mutable).await? {
        if hidden.contains(&e.owner_name) || names.contains(&e.owner_name) {
            continue;
        }
        // only a friend whose sharing dir for us can still be retrieved is followed
        if crate::retrieve_file_metadata(&e.pointer, store.clone(), mutable).await.is_ok() {
            names.push(e.owner_name);
        }
    }
    names.sort();
    Ok(names)
}

/// The usernames of the user's followers (`getFollowerNames`): the sub-directories
/// of `/<us>/shared/`, excluding hidden entries and still-pending outgoing requests.
pub async fn get_follower_names(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let shared = match list_directory(home, store.clone(), mutable).await?.into_iter().find(|e| e.name == SHARED_DIR) {
        Some(e) => e.cap,
        None => return Ok(Vec::new()),
    };
    let pending: BTreeSet<String> =
        get_pending_outgoing(user, store.clone(), mutable).await?.into_iter().collect();
    Ok(list_directory(&shared, store, mutable)
        .await?
        .into_iter()
        .map(|e| e.name)
        .filter(|n| !n.starts_with('.') && !pending.contains(n))
        .collect())
}

/// The usernames we have unfollowed (`getUnfollowed`) — the newline-separated
/// `.blocked-usernames.txt` in home. We don't see what they share with us
/// directly, though they may still follow us.
pub async fn get_unfollowed(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    match read_home_child(user, UNFOLLOWED_USERNAMES_FILE, store, mutable).await? {
        Some(bytes) => {
            let mut names: Vec<String> =
                String::from_utf8_lossy(&bytes).split('\n').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            names.sort();
            names.dedup();
            Ok(names)
        }
        None => Ok(Vec::new()),
    }
}

/// The usernames we have blocked (`getBlocked`), from whom we never see anything,
/// even via someone else — `.blocked-users.cbor` in home, `{v: 1, u: [names]}`.
pub async fn get_blocked(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    match read_home_child(user, BLOCKED_USERS_FILE, store, mutable).await? {
        Some(bytes) => Ok(CborObject::from_bytes(&bytes)?
            .get("u")
            .and_then(|c| c.as_list())
            .map(|l| l.iter().filter_map(|u| u.as_string().map(str::to_string)).collect())
            .unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

/// The usernames of follow requests the user has sent that are not yet accepted
/// (`getPendingOutgoingFollowRequests`) — from `.social-state.cbor` in home.
pub async fn get_pending_outgoing(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    match read_home_child(user, SOCIAL_STATE_FILE, store, mutable).await? {
        Some(bytes) => {
            let cbor = CborObject::from_bytes(&bytes)?;
            Ok(cbor
                .get("pendingOutgoing")
                .and_then(|c| c.as_list())
                .map(|l| l.iter().filter_map(|u| u.as_string().map(|s| s.to_string())).collect())
                .unwrap_or_default())
        }
        None => Ok(Vec::new()),
    }
}

async fn write_pending_outgoing(
    user: &LoggedInUser,
    pending: &BTreeSet<String>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let cbor = CborObject::map()
        .put("pendingOutgoing", CborObject::List(pending.iter().map(|u| CborObject::Str(u.clone())).collect()))
        .build();
    write_home_file(user, SOCIAL_STATE_FILE, &cbor.to_bytes(), store, mutable).await
}

async fn remove_from_pending_outgoing(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut pending: BTreeSet<String> = get_pending_outgoing(user, store.clone(), mutable).await?.into_iter().collect();
    if !pending.remove(username) {
        return Ok(());
    }
    write_pending_outgoing(user, &pending, store, mutable).await
}

/// The root of this user's shared-with records, `.capabilitycache/outbound/<user>`,
/// under which each directory's record sits at its home-relative path. The
/// username component is there because Java keys the records by absolute path.
async fn outbound_root(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Option<AbsoluteCapability>> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let mut cur = home.clone();
    for name in [CAP_CACHE_DIR, OUTBOUND_DIR, user.username.as_str()] {
        cur = match list_directory(&cur, store.clone(), mutable).await?.into_iter().find(|e| e.name == name) {
            Some(e) => e.cap,
            None => return Ok(None),
        };
    }
    Ok(Some(cur))
}

/// Every file shared with `username`, as `(home-relative dir path, child name,
/// access)`, by walking the outbound shared-with cache. Used by `removeFollower` to
/// revoke each one.
pub async fn collect_shares_for_user(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<(String, String, Access)>> {
    let outbound = match outbound_root(user, store.clone(), mutable).await? {
        Some(cap) => cap,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    walk_outbound(&outbound, String::new(), username, &mut out, store, mutable).await?;
    Ok(out)
}

fn walk_outbound<'a>(
    dir_cap: &'a AbsoluteCapability,
    prefix: String,
    username: &'a str,
    out: &'a mut Vec<(String, String, Access)>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let entries = list_directory(dir_cap, store.clone(), mutable).await?;
        if let Some(sw) = entries.iter().find(|e| e.name == DIR_CACHE_FILE) {
            let bytes = crate::read_file(&sw.cap, store.clone(), mutable).await?.1;
            let state = SharedWithState::from_cbor(&CborObject::from_bytes(&bytes)?);
            for (child, users) in &state.read {
                if users.contains(username) {
                    out.push((prefix.clone(), child.clone(), Access::Read));
                }
            }
            for (child, users) in &state.write {
                if users.contains(username) {
                    out.push((prefix.clone(), child.clone(), Access::Write));
                }
            }
        }
        for e in entries {
            if e.is_dir == Some(true) && e.name != DIR_CACHE_FILE {
                let sub = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
                walk_outbound(&e.cap, sub, username, out, store.clone(), mutable).await?;
            }
        }
        Ok(())
    })
}

async fn write_home_file(
    user: &LoggedInUser,
    name: &str,
    content: &[u8],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    crate::upload_file_hidden(home, name, content, None, Some(signer), user.mirror_bat_id().as_ref(), store, mutable).await?;
    Ok(())
}

async fn write_unfollowed(
    user: &LoggedInUser,
    unfollowed: &BTreeSet<String>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let content: String = unfollowed.iter().map(|u| format!("{u}\n")).collect();
    write_home_file(user, UNFOLLOWED_USERNAMES_FILE, content.as_bytes(), store, mutable).await
}

async fn set_blocked(
    user: &LoggedInUser,
    blocked: &BTreeSet<String>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let cbor = CborObject::map()
        .put("v", CborObject::Long(1))
        .put("u", CborObject::List(blocked.iter().map(|u| CborObject::Str(u.clone())).collect()))
        .build();
    write_home_file(user, BLOCKED_USERS_FILE, &cbor.to_bytes(), store, mutable).await
}

/// Stop seeing what `username` shares with us directly (`unfollow`). They may
/// still follow us. Idempotent.
pub async fn unfollow(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut unfollowed: BTreeSet<String> = get_unfollowed(user, store.clone(), mutable).await?.into_iter().collect();
    if !unfollowed.insert(username.to_string()) {
        return Ok(());
    }
    write_unfollowed(user, &unfollowed, store, mutable).await
}

async fn remove_from_unfollowed(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut unfollowed: BTreeSet<String> = get_unfollowed(user, store.clone(), mutable).await?.into_iter().collect();
    if !unfollowed.remove(username) {
        return Ok(());
    }
    write_unfollowed(user, &unfollowed, store, mutable).await
}

/// Start seeing what an unfollowed user shares with us directly again
/// (`followAgain`). A blocked user has to be unblocked first.
pub async fn follow_again(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if get_blocked(user, store.clone(), mutable).await?.iter().any(|b| b == username) {
        return Err(Error::Protocol(format!("User {username} is blocked, unblock them first")));
    }
    remove_from_unfollowed(user, username, store, mutable).await
}

/// Never see anything from `username`, even via someone else, and stop them
/// following us (`block`). They are also unfollowed, so clients which predate
/// blocking still stop showing what they share with us directly. The block is
/// recorded first, so we stop seeing them even if the rest fails, and
/// [`complete_blocks`] finishes the rest.
pub async fn block(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if username == user.username {
        return Err(Error::Protocol("You can't block yourself".into()));
    }
    let mut blocked: BTreeSet<String> = get_blocked(user, store.clone(), mutable).await?.into_iter().collect();
    if blocked.insert(username.to_string()) {
        set_blocked(user, &blocked, store.clone(), mutable).await?;
    }
    unfollow(user, username, store.clone(), mutable).await?;
    remove_from_pending_outgoing(user, username, store.clone(), mutable).await?;
    revoke_follower(user, username, store, mutable).await
}

/// Blocking takes several writes after the block itself is recorded, so finish
/// any which were interrupted (`completeBlocks`).
pub async fn complete_blocks(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let blocked = get_blocked(user, store.clone(), mutable).await?;
    if blocked.is_empty() {
        return Ok(());
    }
    let unfollowed = get_unfollowed(user, store.clone(), mutable).await?;
    let dirs = follower_dirs(user, store.clone(), mutable).await?;
    let pending = get_pending_outgoing(user, store.clone(), mutable).await?;
    for u in &blocked {
        if !unfollowed.contains(u) {
            unfollow(user, u, store.clone(), mutable).await?;
        }
        if pending.contains(u) {
            remove_from_pending_outgoing(user, u, store.clone(), mutable).await?;
        }
        if dirs.contains(u) {
            revoke_follower(user, u, store.clone(), mutable).await?;
        }
    }
    Ok(())
}

/// Unblock `username` (`unblock`). They stay unfollowed, so we see what they
/// share with us directly again only after [`follow_again`].
pub async fn unblock(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut blocked: BTreeSet<String> = get_blocked(user, store.clone(), mutable).await?.into_iter().collect();
    if !blocked.remove(username) {
        return Ok(());
    }
    set_blocked(user, &blocked, store, mutable).await
}

/// A local annotation about a friend (`FriendAnnotation`): whether we have verified
/// their identity, and which of their keys were current at verification time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendAnnotation {
    pub username: String,
    pub is_verified: bool,
    pub keys_at_verification: Vec<PublicKeyHash>,
}

impl FriendAnnotation {
    pub fn new(username: impl Into<String>, is_verified: bool, keys_at_verification: Vec<PublicKeyHash>) -> FriendAnnotation {
        FriendAnnotation { username: username.into(), is_verified, keys_at_verification }
    }

    fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("u", CborObject::Str(self.username.clone()))
            .put("v", CborObject::Boolean(self.is_verified))
            .put("k", CborObject::List(self.keys_at_verification.iter().map(|k| k.to_cbor()).collect()))
            .build()
    }

    fn from_cbor(cbor: &CborObject) -> Result<FriendAnnotation> {
        Ok(FriendAnnotation {
            username: cbor.get("u").and_then(|c| c.as_string()).ok_or_else(|| Error::Cbor("FriendAnnotation missing 'u'".into()))?.to_string(),
            is_verified: cbor.get("v").and_then(|c| c.as_bool()).unwrap_or(false),
            keys_at_verification: cbor
                .get("k")
                .and_then(|c| c.as_list())
                .map(|l| l.iter().map(PublicKeyHash::from_cbor).collect::<Result<Vec<_>>>())
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// The user's friend annotations keyed by username (`getFriendAnnotations`) — the
/// stream of [`FriendAnnotation`]s in `.annotations` in home.
pub async fn get_friend_annotations(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<BTreeMap<String, FriendAnnotation>> {
    let bytes = match read_home_child(user, FRIEND_ANNOTATIONS_FILE, store, mutable).await? {
        Some(b) => b,
        None => return Ok(BTreeMap::new()),
    };
    let mut out = BTreeMap::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
        let anno = FriendAnnotation::from_cbor(&cbor)?;
        out.insert(anno.username.clone(), anno);
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }
    Ok(out)
}

/// Add or replace a friend annotation (`addFriendAnnotation`): merges `annotation`
/// (by username) into the existing set and rewrites `.annotations` as the
/// concatenated stream of all annotations, ordered by username.
pub async fn add_friend_annotation(
    user: &LoggedInUser,
    annotation: FriendAnnotation,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut all = get_friend_annotations(user, store.clone(), mutable).await?;
    all.insert(annotation.username.clone(), annotation);
    let mut content = Vec::new();
    for anno in all.values() {
        content.extend_from_slice(&anno.to_cbor().to_bytes());
    }
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    crate::upload_file_hidden(home, FRIEND_ANNOTATIONS_FILE, &content, None, Some(signer), user.mirror_bat_id().as_ref(), store, mutable).await?;
    Ok(())
}

pub async fn get_friends(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<EntryPoint>> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let file = list_directory(home, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == FROM_FRIENDS_FILE);
    let bytes = match file {
        Some(e) => crate::read_file(&e.cap, store, mutable).await?.1,
        None => return Ok(Vec::new()),
    };
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
        entries.push(EntryPoint::from_cbor(&cbor)?);
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }
    Ok(entries)
}

fn is_null_cap(cap: &AbsoluteCapability) -> bool {
    cap.map_key.iter().all(|b| *b == 0)
}

fn null_capability() -> Result<AbsoluteCapability> {
    Ok(AbsoluteCapability {
        owner: PublicKeyHash::identity(vec![0u8; 32])?,
        writer: PublicKeyHash::identity(vec![0u8; 32])?,
        map_key: vec![0u8; 32],
        bat: None,
        r_base_key: SymmetricKey::new(vec![0u8; 32], false)?,
        w_base_key: None,
    })
}

/// `sendReplyFollowRequest` (accept branch): accept an incoming follow request.
/// Creates (or reuses) our sharing folder for them, adds them to our followers
/// group, and sends back our entry point. With `reciprocate` we also follow them:
/// they join our friends group and their entry point is persisted.
pub async fn accept_follow_request(
    user: &LoggedInUser,
    request: &ReceivedFollowRequest,
    reciprocate: bool,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    reply_to_follow_request(user, request, true, reciprocate, poster, store, mutable).await
}

/// `sendReplyFollowRequest` with `accept=false`: they don't get to follow us. Any
/// sharing dir we already have for them, e.g. from an earlier accept which failed
/// part way, is revoked first. With `reciprocate` we still follow them.
pub async fn reject_follow_request(
    user: &LoggedInUser,
    request: &ReceivedFollowRequest,
    reciprocate: bool,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let entry = request
        .entry
        .as_ref()
        .ok_or_else(|| Error::Protocol("follow request has no entry point".into()))?;
    revoke_follower(user, &entry.owner_name, store.clone(), mutable).await?;
    reply_to_follow_request(user, request, false, reciprocate, poster, store, mutable).await
}

async fn reply_to_follow_request(
    user: &LoggedInUser,
    request: &ReceivedFollowRequest,
    accept: bool,
    reciprocate: bool,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let entry = request
        .entry
        .as_ref()
        .ok_or_else(|| Error::Protocol("follow request has no entry point".into()))?;
    let their_name = entry.owner_name.clone();
    let (their_identity, their_boxer) =
        get_public_keys(poster, store.as_ref(), mutable, &their_name).await?;

    let our_cap = if accept {
        let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
        let signer = recover_signer(home, store.clone(), mutable).await?;
        let sharing = sharing_folder(user, store.clone(), mutable).await?;
        // an existing sharing dir for them keeps its keys
        let friend_root =
            get_or_mkdir(&sharing, &their_name, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
        add_member_to_group(user, FOLLOWERS_GROUP, &their_name, store.clone(), mutable).await?;
        friend_root.read_only()
    } else {
        null_capability()?
    };
    let our_entry = EntryPoint { pointer: our_cap, owner_name: user.username.clone() };
    let mut reply = CborObject::map().put("e", our_entry.to_cbor());
    if reciprocate {
        reply = reply.put("k", entry.pointer.r_base_key.to_cbor());
    }
    if accept && reciprocate {
        add_member_to_group(user, FRIENDS_GROUP, &their_name, store.clone(), mutable).await?;
    }
    blind_and_send(&their_identity, &their_boxer, &reply.build(), poster).await?;

    if reciprocate {
        // following them back undoes having unfollowed them, otherwise we still
        // wouldn't see them
        remove_from_unfollowed(user, &their_name, store.clone(), mutable).await?;
        persist_friend_entry_point(user, entry, store.clone(), mutable).await?;
    }
    remove_follow_request(user, &request.raw_cipher, poster).await?;
    Ok(())
}

/// Answer a request from an existing mutual friend (`reaffirmFollowRequest`). They
/// already have everything an accept would give them, so only send the reply,
/// which also means nothing accumulates if it has to be retried.
async fn reaffirm_follow_request(
    user: &LoggedInUser,
    request: &ReceivedFollowRequest,
    our_dir_for_them: &AbsoluteCapability,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let theirs = request.entry.as_ref().ok_or_else(|| Error::Protocol("follow request has no entry point".into()))?;
    let ours = EntryPoint { pointer: our_dir_for_them.read_only(), owner_name: user.username.clone() };
    let reply = CborObject::map().put("e", ours.to_cbor()).put("k", theirs.pointer.r_base_key.to_cbor()).build();
    let (their_identity, their_boxer) = get_public_keys(poster, store.as_ref(), mutable, &theirs.owner_name).await?;
    blind_and_send(&their_identity, &their_boxer, &reply, poster).await?;
    remove_follow_request(user, &request.raw_cipher, poster).await?;
    Ok(())
}

/// Process a reply to one of our outgoing follow requests. If they don't follow
/// us back (no key) they are fully revoked as a follower; if they follow us but
/// didn't let us follow them (null entry point) they join our followers group;
/// otherwise they join our followers and friends groups. Any entry point they
/// gave us is persisted, and the reply is removed.
pub async fn process_follow_reply(
    user: &LoggedInUser,
    request: &ReceivedFollowRequest,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let entry = match &request.entry {
        Some(e) if e.owner_name != user.username => e,
        // ignore responses claiming to be owned by us
        _ => {
            remove_follow_request(user, &request.raw_cipher, poster).await?;
            return Ok(());
        }
    };
    let their_name = entry.owner_name.clone();
    if request.key.is_none() {
        // They don't follow us. They may already have been a follower, using the same
        // dir, so revoke them fully rather than only removing the dir.
        revoke_follower(user, &their_name, store.clone(), mutable).await?;
        remove_from_pending_outgoing(user, &their_name, store.clone(), mutable).await?;
    } else if is_null_cap(&entry.pointer) {
        // they follow us, but we can't follow them
        add_member_to_group(user, FOLLOWERS_GROUP, &their_name, store.clone(), mutable).await?;
        remove_follow_request(user, &request.raw_cipher, poster).await?;
        return Ok(());
    } else {
        add_member_to_group(user, FOLLOWERS_GROUP, &their_name, store.clone(), mutable).await?;
        add_member_to_group(user, FRIENDS_GROUP, &their_name, store.clone(), mutable).await?;
    }
    if !is_null_cap(&entry.pointer) {
        persist_friend_entry_point(user, entry, store.clone(), mutable).await?;
        remove_from_pending_outgoing(user, &their_name, store.clone(), mutable).await?;
    }
    remove_follow_request(user, &request.raw_cipher, poster).await?;
    Ok(())
}

/// Fetch our follow requests and act on everything that doesn't need the user
/// (`processFollowRequests`), returning the initial requests still to be answered.
///
/// Requests are classified by message content where possible rather than by our
/// local state alone, because a failure part way through sending or replying
/// leaves that state half updated: replies to our pending requests are processed
/// (only the latest from each sender), requests from blocked users are denied,
/// requests from existing mutual friends are answered, and duplicates and replies
/// we are no longer waiting for are removed from the server.
pub async fn process_follow_requests(
    user: &LoggedInUser,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<ReceivedFollowRequest>> {
    let all = get_follow_requests(user, poster).await?;
    if all.is_empty() {
        return Ok(all);
    }
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let follower_roots: BTreeMap<String, AbsoluteCapability> = list_directory(&sharing, store.clone(), mutable)
        .await?
        .into_iter()
        .filter(|e| !e.name.starts_with('.'))
        .map(|e| (e.name, e.cap))
        .collect();
    let pending: BTreeSet<String> = get_pending_outgoing(user, store.clone(), mutable).await?.into_iter().collect();
    let blocked: BTreeSet<String> = get_blocked(user, store.clone(), mutable).await?.into_iter().collect();
    let following: BTreeSet<String> = get_following(user, store.clone(), mutable).await?.into_iter().collect();

    let mut latest_replies: Vec<(String, ReceivedFollowRequest)> = Vec::new();
    let mut initial: Vec<(String, ReceivedFollowRequest)> = Vec::new();
    let mut to_discard = Vec::new();
    let mut to_reaffirm = Vec::new();
    let mut to_reject = Vec::new();
    for p in all {
        let Some(entry) = &p.entry else {
            to_discard.push(p);
            continue;
        };
        let from = entry.owner_name.clone();
        let reply_shaped = p.key.is_none() || is_null_cap(&entry.pointer);
        if blocked.contains(&from) {
            // Deny a request, like any other, so they aren't left waiting. A reply to an
            // earlier request of ours has nothing to answer.
            if reply_shaped { to_discard.push(p) } else { to_reject.push(p) }
            continue;
        }
        if pending.contains(&from) {
            // they may have replied more than once, e.g. rejecting after an accept failed part way
            match latest_replies.iter_mut().find(|(n, _)| *n == from) {
                Some((_, earlier)) => to_discard.push(std::mem::replace(earlier, p)),
                None => latest_replies.push((from, p)),
            }
            continue;
        }
        // an initial request always has a key and an entry point, so this is an
        // unauthenticated reply to a request we are no longer waiting on
        if reply_shaped {
            to_discard.push(p);
            continue;
        }
        // They are waiting on a reply, e.g. after unfollowing and asking again.
        if follower_roots.contains_key(&from) && following.contains(&from) {
            to_reaffirm.push(p);
            continue;
        }
        // A request from someone we already have a sharing dir for is still surfaced,
        // so that a reply which failed part way can be completed.
        match initial.iter_mut().find(|(n, _)| *n == from) {
            Some((_, earlier)) => to_discard.push(std::mem::replace(earlier, p)),
            None => initial.push((from, p)),
        }
    }
    for p in to_discard {
        if let Err(e) = remove_follow_request(user, &p.raw_cipher, poster).await {
            log::warn!("Couldn't remove follow request: {e}");
        }
    }
    for p in to_reject {
        if let Err(e) = reply_to_follow_request(user, &p, false, false, poster, store.clone(), mutable).await {
            log::warn!("Couldn't deny follow request: {e}");
        }
    }
    for p in to_reaffirm {
        let from = p.sender().unwrap_or_default().to_string();
        if let Err(e) = reaffirm_follow_request(user, &p, &follower_roots[&from], poster, store.clone(), mutable).await {
            log::warn!("Couldn't answer follow request from {from}: {e}");
        }
    }
    for (from, p) in latest_replies {
        if let Err(e) = process_follow_reply(user, &p, poster, store.clone(), mutable).await {
            log::warn!("Couldn't process follow reply from {from}: {e}");
        }
    }
    Ok(initial.into_iter().map(|(_, p)| p).collect())
}

/// The capability-store file holding read shares (`CapabilityStore.READ_SHARING_FILE_NAME`).
const READ_SHARING_FILE: &str = "sharing.r";

/// Append `cap` to the given capability-store file (`sharing.r`/`sharing.w`) in
/// `/username/shared/<friend>` — the low-level share, without touching the
/// shared-with cache.
async fn append_cap_to_friend(
    user: &LoggedInUser,
    friend_username: &str,
    store_filename: &str,
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let friend_dir = get_or_mkdir(&sharing, friend_username, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    let existing = list_directory(&friend_dir, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == store_filename);
    let mut contents = match existing {
        Some(e) => crate::read_file(&e.cap, store.clone(), mutable).await?.1,
        None => Vec::new(),
    };
    contents.extend_from_slice(&cap.to_cbor().to_bytes());
    crate::upload_file(&friend_dir, store_filename, &contents, None, Some(signer), user.mirror_bat_id().as_ref(), store, mutable).await?;
    Ok(())
}

/// `shareReadAccessWith`: grant `friend_username` read access to the file/dir at
/// `file_cap` by appending its read-only capability to our capability store in
/// `/username/shared/<friend>` (`CapabilityStore.addReadOnlySharingLinkTo`), and
/// recording the share in the shared-with cache (so it can be revoked later).
///
/// The friend must already have (via an accepted follow request) a read cap to
/// that sharing folder.
pub async fn share_read_access(
    user: &LoggedInUser,
    file_path: &str,
    file_cap: &AbsoluteCapability,
    friend_username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    append_cap_to_friend(user, friend_username, READ_SHARING_FILE, &file_cap.read_only(), store.clone(), mutable)
        .await?;
    record_shared_with(user, file_path, Access::Read, &[friend_username.to_string()], store, mutable).await
}

/// The capability-store file holding write shares (`EDIT_SHARING_FILE_NAME`).
const EDIT_SHARING_FILE: &str = "sharing.w";

/// `shareWriteAccessWith`: grant `friend_username` write access to the existing
/// directory `child_name` inside `parent_cap`. If the directory shares its
/// parent's writer it is first rotated into its own writer subspace
/// ([`crate::move_dir_to_own_writer`], Peergos `rotateAllKeys`); its **writable**
/// capability is then appended to `sharing.w` in `/username/shared/<friend>`, from
/// where the friend recovers the signing key and can write.
pub async fn share_write_access(
    user: &LoggedInUser,
    parent_path: &str,
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    friend_username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    // The home writer signs writes into any of our plain subdirectories (a nested
    // parent shares it but carries no signer link of its own).
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;

    // Rotate the child into its own writer subspace (files and directories alike)
    // if it doesn't have one yet, so write access to it can be granted.
    let is_dir = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?
        .is_dir
        == Some(true);
    let dir_cap = if is_dir {
        crate::move_dir_to_own_writer(parent_cap, child_name, Some(signer.clone()), user.mirror_bat_id().as_ref(), store.clone(), mutable).await?
    } else {
        crate::move_file_to_own_writer(parent_cap, child_name, Some(signer.clone()), user.mirror_bat_id().as_ref(), store.clone(), mutable).await?
    };
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let friend_dir = get_or_mkdir(&sharing, friend_username, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;

    let existing = list_directory(&friend_dir, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == EDIT_SHARING_FILE);
    let mut contents = match existing {
        Some(e) => crate::read_file(&e.cap, store.clone(), mutable).await?.1,
        None => Vec::new(),
    };
    contents.extend_from_slice(&dir_cap.to_cbor().to_bytes());
    crate::upload_file(&friend_dir, EDIT_SHARING_FILE, &contents, None, Some(signer), user.mirror_bat_id().as_ref(), store.clone(), mutable)
        .await?;
    let file_path = join_path(parent_path, child_name);
    record_shared_with(user, &file_path, Access::Write, &[friend_username.to_string()], store, mutable).await
}

/// Read a concatenated capability store (`sharing.r` or `sharing.w`) from a
/// sharing folder.
async fn read_cap_store(
    sharing_folder_cap: &AbsoluteCapability,
    filename: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<AbsoluteCapability>> {
    let store_file = list_directory(sharing_folder_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == filename);
    let bytes = match store_file {
        Some(e) => crate::read_file(&e.cap, store, mutable).await?.1,
        None => return Ok(Vec::new()),
    };
    let mut caps = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
        caps.push(AbsoluteCapability::from_cbor(&cbor)?);
        if consumed == 0 {
            break;
        }
        offset += consumed;
    }
    Ok(caps)
}

/// Read the read-only capabilities shared with us in a sharing folder (the
/// friend's `/friend/shared/<us>`). Parses the capability store `sharing.r`.
pub async fn read_shared_capabilities(
    sharing_folder_cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<AbsoluteCapability>> {
    read_cap_store(sharing_folder_cap, READ_SHARING_FILE, store, mutable).await
}

/// Read the writable capabilities shared with us (`sharing.w`).
pub async fn read_write_shared_capabilities(
    sharing_folder_cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<AbsoluteCapability>> {
    read_cap_store(sharing_folder_cap, EDIT_SHARING_FILE, store, mutable).await
}

// ---------------------------------------------------------------------------
// CapabilityWithPath / CapabilitiesFromUser (pathed, resumable shared caps)
// ---------------------------------------------------------------------------

/// A shared capability together with its resolved absolute path, e.g.
/// `/alice/docs/secret.txt` (`CapabilityWithPath`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityWithPath {
    pub path: String,
    pub cap: AbsoluteCapability,
}

impl CapabilityWithPath {
    /// `{"c": cap, "p": path}`.
    pub fn to_cbor(&self) -> CborObject {
        CborObject::map().put("c", self.cap.to_cbor()).put("p", CborObject::Str(self.path.clone())).build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<CapabilityWithPath> {
        let path = cbor
            .get("p")
            .and_then(|c| c.as_string())
            .ok_or_else(|| Error::Cbor("CapabilityWithPath missing 'p'".into()))?
            .to_string();
        let cap = AbsoluteCapability::from_cbor(
            cbor.get("c").ok_or_else(|| Error::Cbor("CapabilityWithPath missing 'c'".into()))?,
        )?;
        Ok(CapabilityWithPath { path, cap })
    }
}

/// The capabilities read from one friend's sharing file, together with how far
/// into the file we have read (`CapabilitiesFromUser`). `bytes_read` is the
/// absolute end offset now processed — pass it back as `start_offset` next time to
/// pick up only newly-added shares.
#[derive(Debug, Clone, Default)]
pub struct CapabilitiesFromUser {
    pub bytes_read: u64,
    pub capabilities: Vec<CapabilityWithPath>,
}

impl CapabilitiesFromUser {
    /// `{"bytes": bytes_read, "caps": [CapabilityWithPath...]}`.
    pub fn to_cbor(&self) -> CborObject {
        CborObject::map()
            .put("bytes", CborObject::Long(self.bytes_read as i64))
            .put("caps", CborObject::List(self.capabilities.iter().map(|c| c.to_cbor()).collect()))
            .build()
    }

    pub fn from_cbor(cbor: &CborObject) -> Result<CapabilitiesFromUser> {
        let bytes_read = cbor.get("bytes").and_then(|c| c.as_long()).unwrap_or(0).max(0) as u64;
        let capabilities = cbor
            .get("caps")
            .and_then(|c| c.as_list())
            .ok_or_else(|| Error::Cbor("CapabilitiesFromUser missing 'caps'".into()))?
            .iter()
            .map(CapabilityWithPath::from_cbor)
            .collect::<Result<Vec<_>>>()?;
        Ok(CapabilitiesFromUser { bytes_read, capabilities })
    }
}

/// The parent capability of `cap`, or `None` at the root (`getParent`). Link nodes
/// in the chain are skipped (walked through), matching `FileWrapper.retrieveParent`.
fn retrieve_parent<'a>(
    cap: &'a AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<AbsoluteCapability>>> + 'a>> {
    Box::pin(async move {
        let (node, _props) = crate::retrieve_file_metadata(cap, store.clone(), mutable).await?;
        let rel = match node.parent_link(&cap.r_base_key)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let parent = AbsoluteCapability::new(
            cap.owner.clone(),
            rel.writer.clone().unwrap_or_else(|| cap.writer.clone()),
            rel.map_key.clone(),
            rel.bat.clone(),
            rel.r_base_key.clone(),
            None,
        )?;
        // A link node is transparent: continue up from it.
        let (_pnode, pprops) = crate::retrieve_file_metadata(&parent, store.clone(), mutable).await?;
        if pprops.is_link {
            return retrieve_parent(&parent, store, mutable).await;
        }
        Ok(Some(parent))
    })
}

/// Resolve the absolute path of `cap` by walking parent links to the root
/// (`FileWrapper.getPath`): `/home/dir/.../name`.
fn resolve_capability_path<'a>(
    cap: &'a AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + 'a>> {
    Box::pin(async move {
        let (_node, props) = crate::retrieve_file_metadata(cap, store.clone(), mutable).await?;
        match retrieve_parent(cap, store.clone(), mutable).await? {
            None => Ok(format!("/{}", props.name)),
            Some(parent) => {
                let parent_path = resolve_capability_path(&parent, store, mutable).await?;
                Ok(format!("{parent_path}/{}", props.name))
            }
        }
    })
}

/// Read a friend's sharing file (`sharing.r` / `sharing.w`) from `start_offset`,
/// resolving each shared capability to its absolute path
/// (`CapabilityStore.readSharingFile`). Caps that no longer resolve (an ancestor
/// was deleted/revoked) are skipped.
async fn read_sharing_file(
    sharing_folder_cap: &AbsoluteCapability,
    filename: &str,
    start_offset: u64,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<CapabilitiesFromUser> {
    let store_file = list_directory(sharing_folder_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == filename);
    let bytes = match store_file {
        Some(e) => crate::read_file(&e.cap, store.clone(), mutable).await?.1,
        None => return Ok(CapabilitiesFromUser::default()),
    };
    let total = bytes.len() as u64;
    let mut caps = Vec::new();
    let mut offset = start_offset.min(total) as usize;
    while offset < bytes.len() {
        let (cbor, consumed) = CborObject::from_bytes_consumed(&bytes[offset..])?;
        if consumed == 0 {
            break;
        }
        offset += consumed;
        let cap = AbsoluteCapability::from_cbor(&cbor)?;
        // A cap whose ancestry no longer resolves is silently dropped.
        if let Ok(path) = resolve_capability_path(&cap, store.clone(), mutable).await {
            caps.push(CapabilityWithPath { path, cap });
        }
    }
    Ok(CapabilitiesFromUser { bytes_read: total, capabilities: caps })
}

/// Load the read-only capabilities a friend has shared with us, each with its
/// resolved path, starting at `start_offset` (`loadReadAccessSharingLinks`).
pub async fn load_read_access_sharing_links(
    friend_shared_dir: &AbsoluteCapability,
    start_offset: u64,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<CapabilitiesFromUser> {
    read_sharing_file(friend_shared_dir, READ_SHARING_FILE, start_offset, store, mutable).await
}

/// Load the writable capabilities a friend has shared with us, each with its
/// resolved path, starting at `start_offset` (`loadWriteAccessSharingLinks`).
pub async fn load_write_access_sharing_links(
    friend_shared_dir: &AbsoluteCapability,
    start_offset: u64,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<CapabilitiesFromUser> {
    read_sharing_file(friend_shared_dir, EDIT_SHARING_FILE, start_offset, store, mutable).await
}

// ---------------------------------------------------------------------------
// Shared-with cache + revocation (unsharing)
// ---------------------------------------------------------------------------

const CAP_CACHE_DIR: &str = ".capabilitycache";
const OUTBOUND_DIR: &str = "outbound";
const DIR_CACHE_FILE: &str = "sharedWith.cbor";

/// Read (`R`) or write (`W`) access, for the shared-with cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// One item in a secret link, as the owner remembers it (`LinkMember`). Owner-private
/// and a display hint only: the path goes stale on a rename while the capability in
/// the payload does not, so membership is decided by the payload, never this list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMember {
    /// Absolute, `/owner/a/b`, as Java records it.
    pub path: String,
    pub writable: bool,
}

impl LinkMember {
    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map().put("p", CborObject::Str(self.path.clone()));
        if self.writable {
            b = b.put("w", CborObject::Boolean(true));
        }
        b.build()
    }

    fn from_cbor(cbor: &CborObject) -> Option<LinkMember> {
        Some(LinkMember {
            path: cbor.get("p")?.as_string()?.to_string(),
            writable: cbor.get("w").and_then(|c| c.as_bool()).unwrap_or(false),
        })
    }
}

/// A recorded secret link, enough to re-mint it under the same label/password when
/// the target's keys rotate (`LinkProperties`). Cbor `{l,p,u,w,o,[h],[m],[e],[ms]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkProperties {
    pub label: i64,
    pub link_password: String,
    pub user_password: String,
    /// Whether any member is writable.
    pub writable: bool,
    pub open: bool,
    pub max_retrievals: Option<i64>,
    pub expiry_epoch_secs: Option<i64>,
    /// The cid of the stored link target, as merkle link bytes.
    pub existing: Option<Vec<u8>>,
    /// What is in the link. Empty on every link written before members existed,
    /// which is a one member link of the file it is recorded under.
    pub members: Vec<LinkMember>,
}

impl LinkProperties {
    /// A new link's properties; writability is a property of the members.
    pub fn build(
        link: &crate::SecretLink,
        user_password: &str,
        max_retrievals: Option<i64>,
        expiry_epoch_secs: Option<i64>,
        members: Vec<LinkMember>,
    ) -> LinkProperties {
        LinkProperties {
            label: link.label,
            link_password: link.link_password.clone(),
            user_password: user_password.to_string(),
            writable: members.iter().any(|m| m.writable),
            open: false,
            max_retrievals,
            expiry_epoch_secs,
            existing: None,
            members,
        }
    }

    pub fn with_members(mut self, members: Vec<LinkMember>) -> LinkProperties {
        self.writable = members.iter().any(|m| m.writable);
        self.members = members;
        self
    }

    pub fn to_link(&self, owner: &PublicKeyHash) -> crate::SecretLink {
        crate::SecretLink { owner: owner.clone(), label: self.label, link_password: self.link_password.clone() }
    }

    fn to_cbor(&self) -> CborObject {
        let mut b = CborObject::map()
            .put("l", CborObject::Long(self.label))
            .put("p", CborObject::Str(self.link_password.clone()))
            .put("u", CborObject::Str(self.user_password.clone()))
            .put("w", CborObject::Boolean(self.writable))
            .put("o", CborObject::Boolean(self.open));
        if let Some(m) = self.max_retrievals {
            b = b.put("m", CborObject::Long(m));
        }
        if let Some(e) = self.expiry_epoch_secs {
            b = b.put("e", CborObject::Long(e));
        }
        if let Some(h) = &self.existing {
            b = b.put("h", CborObject::MerkleLink(h.clone()));
        }
        // absent on every link written before members existed, which is a one member link
        if !self.members.is_empty() {
            b = b.put("ms", CborObject::List(self.members.iter().map(|m| m.to_cbor()).collect()));
        }
        b.build()
    }

    fn from_cbor(cbor: &CborObject) -> Option<LinkProperties> {
        Some(LinkProperties {
            label: cbor.get("l")?.as_long()?,
            link_password: cbor.get("p")?.as_string()?.to_string(),
            user_password: cbor.get("u").and_then(|c| c.as_string()).unwrap_or("").to_string(),
            writable: cbor.get("w").and_then(|c| c.as_bool()).unwrap_or(false),
            open: cbor.get("o").and_then(|c| c.as_bool()).unwrap_or(false),
            max_retrievals: cbor.get("m").and_then(|c| c.as_long()),
            expiry_epoch_secs: cbor.get("e").and_then(|c| c.as_long()),
            existing: cbor.get("h").and_then(|c| c.as_link()).map(|l| l.to_vec()),
            members: match cbor.get("ms").and_then(|c| c.as_list()) {
                Some(ms) => ms.iter().map(LinkMember::from_cbor).collect::<Option<Vec<_>>>()?,
                None => Vec::new(),
            },
        })
    }
}

/// Who the children of a directory are shared with (`SharedWithState`). Keyed by
/// child filename → set of usernames (read/write) or list of links.
#[derive(Debug, Default, Clone)]
pub struct SharedWithState {
    read: BTreeMap<String, BTreeSet<String>>,
    write: BTreeMap<String, BTreeSet<String>>,
    links: BTreeMap<String, Vec<LinkProperties>>,
}

/// The sharing state of a single file (`FileSharedWithState`): who has read /
/// write access and any secret links to it.
#[derive(Debug, Default, Clone)]
pub struct FileSharedWithState {
    pub read: BTreeSet<String>,
    pub write: BTreeSet<String>,
    pub links: Vec<LinkProperties>,
}

impl SharedWithState {
    /// Per-child read-access usernames (`readShares`).
    pub fn read_shares(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.read
    }
    /// Per-child write-access usernames (`writeShares`).
    pub fn write_shares(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.write
    }
    /// Per-child secret links (`links`).
    pub fn links(&self) -> &BTreeMap<String, Vec<LinkProperties>> {
        &self.links
    }
    /// True if nothing in this directory is shared (`isEmpty`; links ignored, as in Java).
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }
    /// The sharing state of a single child by name (`get`).
    pub fn get(&self, filename: &str) -> FileSharedWithState {
        FileSharedWithState {
            read: self.read.get(filename).cloned().unwrap_or_default(),
            write: self.write.get(filename).cloned().unwrap_or_default(),
            links: self.links.get(filename).cloned().unwrap_or_default(),
        }
    }

    fn from_cbor(cbor: &CborObject) -> SharedWithState {
        let parse = |field: &str| -> BTreeMap<String, BTreeSet<String>> {
            let mut out = BTreeMap::new();
            if let Some(m) = cbor.get(field).and_then(|c| c.as_map()) {
                for (k, v) in m {
                    let users = v
                        .as_list()
                        .unwrap_or(&[])
                        .iter()
                        .filter_map(|u| u.as_string().map(|s| s.to_string()))
                        .collect();
                    out.insert(k.as_str().to_string(), users);
                }
            }
            out
        };
        let mut links = BTreeMap::new();
        if let Some(m) = cbor.get("l").and_then(|c| c.as_map()) {
            for (k, v) in m {
                let list: Vec<LinkProperties> = v
                    .as_list()
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(LinkProperties::from_cbor)
                    .collect();
                links.insert(k.as_str().to_string(), list);
            }
        }
        SharedWithState { read: parse("r"), write: parse("w"), links }
    }

    fn to_cbor(&self) -> CborObject {
        let map_to_cbor = |m: &BTreeMap<String, BTreeSet<String>>| {
            let mut inner = BTreeMap::new();
            for (name, users) in m {
                let list = users.iter().map(|u| CborObject::Str(u.clone())).collect();
                inner.insert(CborString::new(name.clone()), CborObject::List(list));
            }
            CborObject::Map(inner)
        };
        let mut links_inner = BTreeMap::new();
        for (name, ls) in &self.links {
            links_inner.insert(
                CborString::new(name.clone()),
                CborObject::List(ls.iter().map(|l| l.to_cbor()).collect()),
            );
        }
        let mut top = BTreeMap::new();
        top.insert(CborString::new("r"), map_to_cbor(&self.read));
        top.insert(CborString::new("w"), map_to_cbor(&self.write));
        top.insert(CborString::new("l"), CborObject::Map(links_inner));
        CborObject::Map(top)
    }

    fn map(&mut self, access: Access) -> &mut BTreeMap<String, BTreeSet<String>> {
        match access {
            Access::Read => &mut self.read,
            Access::Write => &mut self.write,
        }
    }

    fn map_ref(&self, access: Access) -> &BTreeMap<String, BTreeSet<String>> {
        match access {
            Access::Read => &self.read,
            Access::Write => &self.write,
        }
    }
}

/// Split a home-relative path into (directory components, filename). Leading
/// slashes are ignored; the caller passes paths relative to their home.
fn split_path(path: &str) -> (Vec<String>, String) {
    let parts: Vec<String> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    match parts.split_last() {
        Some((last, dirs)) => (dirs.to_vec(), last.clone()),
        None => (Vec::new(), String::new()),
    }
}

/// Join a directory path and a child name (both home-relative).
fn join_path(dir: &str, name: &str) -> String {
    let dir = dir.trim_matches('/');
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Navigate (creating if needed) `.capabilitycache/outbound/<user>/<dir_path>/` — the
/// per-directory cache tree mirroring the filesystem (`SharedWithCache`
/// `CACHE_BASE`). Returns its cap + the home writer's signer.
async fn cache_dir_for(
    user: &LoggedInUser,
    dir_path: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(AbsoluteCapability, peergos_core::keys::SigningPrivateKeyAndPublicHash)> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let cap_cache = list_directory(home, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == CAP_CACHE_DIR)
        .ok_or_else(|| Error::Protocol("no capability cache directory".into()))?
        .cap;
    let mut cur = get_or_mkdir(&cap_cache, OUTBOUND_DIR, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    cur = get_or_mkdir(&cur, &user.username, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    for comp in dir_path {
        cur = get_or_mkdir(&cur, comp, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    }
    Ok((cur, signer))
}

/// Read the `sharedWith.cbor` for the directory at `dir_path`.
async fn read_shared_with_at(
    user: &LoggedInUser,
    dir_path: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<SharedWithState> {
    let (dir, _) = cache_dir_for(user, dir_path, store.clone(), mutable).await?;
    let file = list_directory(&dir, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == DIR_CACHE_FILE);
    match file {
        Some(e) => {
            let bytes = crate::read_file(&e.cap, store, mutable).await?.1;
            Ok(SharedWithState::from_cbor(&CborObject::from_bytes(&bytes)?))
        }
        None => Ok(SharedWithState::default()),
    }
}

/// The sharing state of every child of the directory at home-relative `dir_path`
/// (`getDirectorySharingState`): who has read / write access and any links, read
/// from that directory's `sharedWith.cbor`. Read-only — never creates cache dirs;
/// returns empty if nothing under `dir_path` has been shared.
pub async fn get_directory_sharing_state(
    user: &LoggedInUser,
    dir_path: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<SharedWithState> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    // Walk .capabilitycache/outbound/<dir_path> without creating anything.
    let mut cur = match list_directory(home, store.clone(), mutable).await?.into_iter().find(|e| e.name == CAP_CACHE_DIR) {
        Some(e) => e.cap,
        None => return Ok(SharedWithState::default()),
    };
    let mut components = vec![OUTBOUND_DIR.to_string(), user.username.clone()];
    components.extend(dir_path.trim_matches('/').split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()));
    for comp in &components {
        cur = match list_directory(&cur, store.clone(), mutable).await?.into_iter().find(|e| &e.name == comp) {
            Some(e) => e.cap,
            None => return Ok(SharedWithState::default()),
        };
    }
    match list_directory(&cur, store.clone(), mutable).await?.into_iter().find(|e| e.name == DIR_CACHE_FILE) {
        Some(e) => {
            let bytes = crate::read_file(&e.cap, store, mutable).await?.1;
            Ok(SharedWithState::from_cbor(&CborObject::from_bytes(&bytes)?))
        }
        None => Ok(SharedWithState::default()),
    }
}

/// Write the `sharedWith.cbor` for the directory at `dir_path`.
async fn write_shared_with_at(
    user: &LoggedInUser,
    dir_path: &[String],
    state: &SharedWithState,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (dir, signer) = cache_dir_for(user, dir_path, store.clone(), mutable).await?;
    crate::upload_file(&dir, DIR_CACHE_FILE, &state.to_cbor().to_bytes(), None, Some(signer), user.mirror_bat_id().as_ref(), store, mutable)
        .await?;
    Ok(())
}

/// Record that the file at home-relative `path` is shared with `users` at `access`.
async fn record_shared_with(
    user: &LoggedInUser,
    path: &str,
    access: Access,
    users: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (dir_path, filename) = split_path(path);
    let mut state = read_shared_with_at(user, &dir_path, store.clone(), mutable).await?;
    state.map(access).entry(filename).or_default().extend(users.iter().cloned());
    write_shared_with_at(user, &dir_path, &state, store, mutable).await
}

/// Record a secret link minted to the file at home-relative `path` (so it can be
/// re-minted if the target's keys later rotate). Java `sharedWithCache.addSecretLink`.
pub async fn record_link(
    user: &LoggedInUser,
    path: &str,
    link: LinkProperties,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (dir_path, filename) = split_path(path);
    let mut state = read_shared_with_at(user, &dir_path, store.clone(), mutable).await?;
    let entry = state.links.entry(filename).or_default();
    // Replace an existing record for the same label (re-mint), else append.
    if let Some(existing) = entry.iter_mut().find(|l| l.label == link.label) {
        *existing = link;
    } else {
        entry.push(link);
    }
    write_shared_with_at(user, &dir_path, &state, store, mutable).await
}

/// Forget the recorded secret link with `label` for the file at home-relative
/// `path` (Java `sharedWithCache.removeSecretLink`).
pub async fn remove_link(
    user: &LoggedInUser,
    path: &str,
    label: i64,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (dir_path, filename) = split_path(path);
    let mut state = read_shared_with_at(user, &dir_path, store.clone(), mutable).await?;
    if let Some(entry) = state.links.get_mut(&filename) {
        entry.retain(|l| l.label != label);
    }
    write_shared_with_at(user, &dir_path, &state, store, mutable).await
}

/// Every directory's recorded sharing state, keyed by its home-relative path
/// (`SharedWithCache.getAllShares`). Read-only.
pub async fn get_all_shares(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<(String, SharedWithState)>> {
    let outbound = match outbound_root(user, store.clone(), mutable).await? {
        Some(cap) => cap,
        None => return Ok(Vec::new()),
    };
    let mut res = Vec::new();
    let mut todo = vec![(String::new(), outbound)];
    while let Some((path, dir)) = todo.pop() {
        for e in list_directory(&dir, store.clone(), mutable).await? {
            if e.name == DIR_CACHE_FILE {
                let bytes = crate::read_file(&e.cap, store.clone(), mutable).await?.1;
                res.push((path.clone(), SharedWithState::from_cbor(&CborObject::from_bytes(&bytes)?)));
            } else if e.is_dir != Some(false) {
                let child = if path.is_empty() { e.name.clone() } else { format!("{path}/{}", e.name) };
                todo.push((child, e.cap));
            }
        }
    }
    Ok(res)
}

/// The secret links recorded for the file at home-relative `path`.
pub async fn get_links(
    user: &LoggedInUser,
    path: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<LinkProperties>> {
    let (dir_path, filename) = split_path(path);
    let state = read_shared_with_at(user, &dir_path, store, mutable).await?;
    Ok(state.links.get(&filename).cloned().unwrap_or_default())
}

/// The usernames the file at home-relative `path` is currently shared with, at the
/// given access.
pub async fn get_shared_with(
    user: &LoggedInUser,
    path: &str,
    access: Access,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    let (dir_path, filename) = split_path(path);
    let state = read_shared_with_at(user, &dir_path, store, mutable).await?;
    Ok(state.map_ref(access).get(&filename).map(|s| s.iter().cloned().collect()).unwrap_or_default())
}

/// `unShareReadAccessWith`: revoke read access to the home child `child_name`
/// from `revoked_users`. Rotates the child's symmetric keys (invalidating the
/// revoked users' cached capabilities and deleting the old content), updates the
/// shared-with cache, and reshares the new capability to the remaining readers.
///
/// Revoking a group also revokes its members who were shared with individually.
pub async fn unshare_read_access(
    user: &LoggedInUser,
    parent_path: &str,
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    revoked_users: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let file_path = join_path(parent_path, child_name);
    let current: BTreeSet<String> =
        get_shared_with(user, &file_path, Access::Read, store.clone(), mutable).await?.into_iter().collect();
    let revoked = expand_groups_to_unshare(user, &current, revoked_users, store.clone(), mutable).await?;
    unshare_read_exactly(user, parent_path, parent_cap, child_name, &revoked, store, mutable).await
}

async fn unshare_read_exactly(
    user: &LoggedInUser,
    parent_path: &str,
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    revoked_users: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let file_path = join_path(parent_path, child_name);
    let (dir_path, filename) = split_path(&file_path);

    // Who currently has read access, minus the revoked users.
    let current: BTreeSet<String> =
        get_shared_with(user, &file_path, Access::Read, store.clone(), mutable).await?.into_iter().collect();
    let revoked: BTreeSet<String> = revoked_users.iter().cloned().collect();
    let remaining: Vec<String> = current.difference(&revoked).cloned().collect();

    // The home writer signs writes into any of our plain subdirectories (a nested
    // parent shares it but carries no signer link of its own).
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let home_signer = recover_signer(home, store.clone(), mutable).await?;

    // Rotate the child's keys: this re-encrypts and deletes the old content, so
    // any capability the revoked users cached no longer works.
    let new_cap =
        crate::rotate_child_read_keys(parent_cap, child_name, Some(home_signer), user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;

    // Update the cache: drop the revoked users.
    let mut state = read_shared_with_at(user, &dir_path, store.clone(), mutable).await?;
    if let Some(readers) = state.read.get_mut(&filename) {
        for r in revoked_users {
            readers.remove(r);
        }
        if readers.is_empty() {
            state.read.remove(&filename);
        }
    }
    write_shared_with_at(user, &dir_path, &state, store.clone(), mutable).await?;

    // Reshare the new capability to everyone who still has access.
    for friend in &remaining {
        append_cap_to_friend(user, friend, READ_SHARING_FILE, &new_cap.read_only(), store.clone(), mutable)
            .await?;
    }
    Ok(())
}

/// `unShareWriteAccessWith`: revoke write access to the home directory
/// `child_name` from `revoked_users`. Rotates the directory into a **new** writer
/// subspace (deleting the old one and deauthorising the old writer), updates the
/// shared-with cache, and reshares the new writable capability to the remaining
/// writers (and the readable capability to any remaining readers).
///
/// Revoking a group also revokes its members who were shared with individually.
pub async fn unshare_write_access(
    user: &LoggedInUser,
    parent_path: &str,
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    revoked_users: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let file_path = join_path(parent_path, child_name);
    let current: BTreeSet<String> =
        get_shared_with(user, &file_path, Access::Write, store.clone(), mutable).await?.into_iter().collect();
    let revoked = expand_groups_to_unshare(user, &current, revoked_users, store.clone(), mutable).await?;
    unshare_write_exactly(user, parent_path, parent_cap, child_name, &revoked, store, mutable).await
}

async fn unshare_write_exactly(
    user: &LoggedInUser,
    parent_path: &str,
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    revoked_users: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let file_path = join_path(parent_path, child_name);
    let (dir_path, filename) = split_path(&file_path);

    let cur_writers: BTreeSet<String> =
        get_shared_with(user, &file_path, Access::Write, store.clone(), mutable).await?.into_iter().collect();
    let cur_readers: BTreeSet<String> =
        get_shared_with(user, &file_path, Access::Read, store.clone(), mutable).await?.into_iter().collect();
    let revoked: BTreeSet<String> = revoked_users.iter().cloned().collect();
    let remaining_writers: Vec<String> = cur_writers.difference(&revoked).cloned().collect();

    // The home writer signs writes into any of our plain subdirectories.
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let home_signer = recover_signer(home, store.clone(), mutable).await?;

    // Rotate to a new writer subspace: invalidates the revoked users' cached
    // writable capabilities and deauthorises the old writer.
    let new_target =
        crate::force_rotate_child_to_new_writer(parent_cap, child_name, Some(home_signer), user.mirror_bat_id().as_ref(), store.clone(), mutable)
            .await?;

    // Update the cache: drop the revoked writers.
    let mut state = read_shared_with_at(user, &dir_path, store.clone(), mutable).await?;
    if let Some(writers) = state.write.get_mut(&filename) {
        for r in revoked_users {
            writers.remove(r);
        }
        if writers.is_empty() {
            state.write.remove(&filename);
        }
    }
    write_shared_with_at(user, &dir_path, &state, store.clone(), mutable).await?;

    // Reshare the new writable cap to remaining writers, and the new readable cap
    // to any readers (their old caps were invalidated by the rotation too).
    for w in &remaining_writers {
        append_cap_to_friend(user, w, EDIT_SHARING_FILE, &new_target, store.clone(), mutable).await?;
    }
    for r in &cur_readers {
        append_cap_to_friend(user, r, READ_SHARING_FILE, &new_target.read_only(), store.clone(), mutable).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Social groups (friends / followers), sender side
// ---------------------------------------------------------------------------

/// The two default social groups, matching Java (`SocialState.FRIENDS_GROUP_NAME`
/// / `FOLLOWERS_GROUP_NAME`).
pub const FRIENDS_GROUP: &str = "friends";
pub const FOLLOWERS_GROUP: &str = "followers";
const GROUPS_FILE: &str = ".groups.cbor";

/// The uid → group-name map stored at `/username/shared/.groups.cbor` (`Groups`).
/// A group's shared directory lives at `/username/shared/<uid>` (like a friend's,
/// but the uid is dot-prefixed so it can't clash with a username).
#[derive(Debug, Clone, Default)]
pub struct Groups {
    pub uid_to_name: BTreeMap<String, String>,
}

impl Groups {
    fn generate() -> Groups {
        let mut uid_to_name = BTreeMap::new();
        uid_to_name.insert(generate_group_uid(), FRIENDS_GROUP.to_string());
        uid_to_name.insert(generate_group_uid(), FOLLOWERS_GROUP.to_string());
        Groups { uid_to_name }
    }

    /// The uid of the group with the given name, if present.
    pub fn uid_for(&self, name: &str) -> Option<String> {
        self.uid_to_name.iter().find(|(_, n)| n.as_str() == name).map(|(u, _)| u.clone())
    }

    fn to_cbor(&self) -> CborObject {
        let mut inner = CborObject::map();
        for (uid, name) in &self.uid_to_name {
            inner = inner.put(uid, CborObject::Str(name.clone()));
        }
        CborObject::map().put("n", inner.build()).build()
    }

    fn from_cbor(cbor: &CborObject) -> Result<Groups> {
        let mut uid_to_name = BTreeMap::new();
        if let Some(m) = cbor.get("n").and_then(|c| c.as_map()) {
            for (k, v) in m {
                if let Some(name) = v.as_string() {
                    uid_to_name.insert(k.as_str().to_string(), name.to_string());
                }
            }
        }
        Ok(Groups { uid_to_name })
    }
}

/// `Groups.generateUid`: "." + hex(32 random bytes).
fn generate_group_uid() -> String {
    format!(".{}", to_hex(&peergos_crypto::random_bytes(32)))
}

/// Read the friends/followers group map (`getGroupNameMappings`), creating it — and
/// the two group sharing directories under `/username/shared/` — on first use.
pub async fn get_or_create_groups(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Groups> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;

    if let Some(e) = list_directory(&sharing, store.clone(), mutable).await?.into_iter().find(|e| e.name == GROUPS_FILE)
    {
        let bytes = crate::read_file(&e.cap, store.clone(), mutable).await?.1;
        return Groups::from_cbor(&CborObject::from_bytes(&bytes)?);
    }

    let groups = Groups::generate();
    for uid in groups.uid_to_name.keys() {
        get_or_mkdir(&sharing, uid, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    }
    crate::upload_file(&sharing, GROUPS_FILE, &groups.to_cbor().to_bytes(), None, Some(signer), user.mirror_bat_id().as_ref(), store.clone(), mutable)
        .await?;
    Ok(groups)
}

/// The uid of a named group (creating the group map on first use).
pub async fn group_uid(
    user: &LoggedInUser,
    group_name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Option<String>> {
    Ok(get_or_create_groups(user, store, mutable).await?.uid_for(group_name))
}

/// Add `member` to the named group: grant them read access to the group's sharing
/// directory, so they receive everything shared with the group (the group half of
/// accepting a follower/friend, and Java's `addToGroup`).
pub async fn add_member_to_group(
    user: &LoggedInUser,
    group_name: &str,
    member: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let uid = group_uid(user, group_name, store.clone(), mutable)
        .await?
        .ok_or_else(|| Error::Protocol(format!("no such group: {group_name}")))?;
    add_members_to_group(user, &uid, &[member.to_string()], store, mutable).await
}

/// Share read access to the item at home-relative `item_path` with everyone in the
/// named group (`shareReadAccessWith(path, group)`). Sharing with a group is
/// exactly sharing with a friend whose name is the group's uid: the cap goes into
/// `/username/shared/<uid>/sharing.r` **and** the uid is recorded in the
/// shared-with cache — matching Java, which stores the group uid there.
pub async fn share_read_with_group(
    user: &LoggedInUser,
    item_path: &str,
    item_cap: &AbsoluteCapability,
    group_name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let uid = group_uid(user, group_name, store.clone(), mutable)
        .await?
        .ok_or_else(|| Error::Protocol(format!("no such group: {group_name}")))?;
    share_read_access(user, item_path, item_cap, &uid, store, mutable).await
}

/// Share write access to the directory `child_name` in `parent_cap` with everyone
/// in the named group (`shareWriteAccessWith(path, group)`). Like
/// [`share_write_access`] but the writable cap is appended to the group's
/// `sharing.w` and the group uid is recorded in the shared-with cache.
#[allow(clippy::too_many_arguments)]
pub async fn share_write_with_group(
    user: &LoggedInUser,
    parent_path: &str,
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    group_name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let uid = group_uid(user, group_name, store.clone(), mutable)
        .await?
        .ok_or_else(|| Error::Protocol(format!("no such group: {group_name}")))?;
    share_write_access(user, parent_path, parent_cap, child_name, &uid, store, mutable).await
}

// ---------------------------------------------------------------------------
// Group membership, custom groups and follower revocation
// ---------------------------------------------------------------------------

fn group_path(uid: &str) -> String {
    format!("{SHARED_DIR}/{uid}")
}

/// Whether `name` is reserved for a built-in group (`Groups.isBuiltInName`).
pub fn is_built_in_group_name(name: &str) -> bool {
    name == FRIENDS_GROUP || name == FOLLOWERS_GROUP
}

async fn set_groups(
    user: &LoggedInUser,
    groups: &Groups,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    crate::upload_file(&sharing, GROUPS_FILE, &groups.to_cbor().to_bytes(), None, Some(signer), user.mirror_bat_id().as_ref(), store, mutable)
        .await?;
    Ok(())
}

/// The capability for the home-relative `path`, following link nodes to their
/// targets, as navigating the filesystem does.
async fn resolve_home_path(
    user: &LoggedInUser,
    path: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Option<AbsoluteCapability>> {
    let mut cur = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?.clone();
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let Some(e) = list_directory(&cur, store.clone(), mutable).await?.into_iter().find(|e| e.name == comp) else {
            return Ok(None);
        };
        let props = crate::retrieve_file_metadata(&e.cap, store.clone(), mutable).await?.1;
        cur = if props.is_link {
            list_directory(&e.cap, store.clone(), mutable)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| Error::Protocol("link node has no target".into()))?
                .cap
        } else {
            e.cap
        };
    }
    Ok(Some(cur))
}

fn parent_and_name(path: &str) -> (String, String) {
    let trimmed = path.trim_matches('/');
    match trimmed.rsplit_once('/') {
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), trimmed.to_string()),
    }
}

/// Revoke read access to the home-relative `path` from exactly `revoked`, which
/// may include group uids, without expanding groups.
async fn unshare_read_path(
    user: &LoggedInUser,
    path: &str,
    revoked: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (parent_path, name) = parent_and_name(path);
    let parent = resolve_home_path(user, &parent_path, store.clone(), mutable)
        .await?
        .ok_or_else(|| Error::Protocol(format!("Specified un-shareWith path {path} does not exist")))?;
    unshare_read_exactly(user, &parent_path, &parent, &name, revoked, store, mutable).await
}

async fn unshare_write_path(
    user: &LoggedInUser,
    path: &str,
    revoked: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (parent_path, name) = parent_and_name(path);
    let parent = resolve_home_path(user, &parent_path, store.clone(), mutable)
        .await?
        .ok_or_else(|| Error::Protocol(format!("Specified un-shareWith path {path} does not exist")))?;
    unshare_write_exactly(user, &parent_path, &parent, &name, revoked, store, mutable).await
}

/// Who is in a group: whoever its directory is shared with (`getGroupMembers`).
pub async fn get_group_members(
    user: &LoggedInUser,
    group_uid: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<BTreeSet<String>> {
    Ok(get_shared_with(user, &group_path(group_uid), Access::Read, store, mutable).await?.into_iter().collect())
}

/// Share the group's directory with each of `usernames`, so they receive
/// everything shared with the group. Each must already follow us.
pub async fn add_members_to_group(
    user: &LoggedInUser,
    group_uid: &str,
    usernames: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if usernames.is_empty() {
        return Ok(());
    }
    log::info!("Adding {usernames:?} to group {group_uid}");
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let dir = get_or_mkdir(&sharing, group_uid, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    for u in usernames {
        share_read_access(user, &group_path(group_uid), &dir, u, store.clone(), mutable).await?;
    }
    Ok(())
}

/// Remove members from a group (`removeMembersFromGroup`): rotate the group
/// directory's keys, re-sharing with the remaining members, then revoke each
/// removed member's access to everything ever shared with the group. Only actual
/// members are removed, all at once, so keys aren't rotated needlessly.
pub async fn remove_members_from_group(
    user: &LoggedInUser,
    group_uid: &str,
    usernames: &BTreeSet<String>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if usernames.is_empty() {
        return Ok(());
    }
    let members = get_group_members(user, group_uid, store.clone(), mutable).await?;
    let to_remove: Vec<String> = usernames.intersection(&members).cloned().collect();
    if to_remove.is_empty() {
        return Ok(());
    }
    log::info!("Removing {to_remove:?} from group {group_uid}");
    unshare_read_path(user, &group_path(group_uid), &to_remove, store.clone(), mutable).await?;
    for u in &to_remove {
        unshare_items_in_sharing_folder(user, group_uid, u, store.clone(), mutable).await?;
    }
    Ok(())
}

/// Revoke `username`'s access to every capability in `/username/shared/<folder>`
/// (`unshareItemsInSharingFolder`), rotating the keys of each.
pub async fn unshare_items_in_sharing_folder(
    user: &LoggedInUser,
    folder: &str,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let Some(dir) = list_directory(&sharing, store.clone(), mutable).await?.into_iter().find(|e| e.name == folder) else {
        return Ok(());
    };
    let revoked = [username.to_string()];
    let prefix = format!("/{}/", user.username);
    let reads = load_read_access_sharing_links(&dir.cap, 0, store.clone(), mutable).await?;
    for c in &reads.capabilities {
        if let Some(path) = c.path.strip_prefix(&prefix) {
            unshare_read_path(user, path, &revoked, store.clone(), mutable).await?;
        }
    }
    let writes = load_write_access_sharing_links(&dir.cap, 0, store.clone(), mutable).await?;
    for c in &writes.capabilities {
        if let Some(path) = c.path.strip_prefix(&prefix) {
            unshare_write_path(user, path, &revoked, store.clone(), mutable).await?;
        }
    }
    Ok(())
}

/// The names of our followers' sharing dirs, including any still pending.
async fn follower_dirs(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<BTreeSet<String>> {
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    Ok(list_directory(&sharing, store, mutable)
        .await?
        .into_iter()
        .map(|e| e.name)
        .filter(|n| !n.starts_with('.'))
        .collect())
}

/// Stop `username` following us (`revokeFollower`). Their sharing dir is first
/// hidden, by renaming it, so they stop being listed as a follower in one step and
/// the rest of the removal can be completed by [`reconcile_groups`] if this fails
/// part way.
pub async fn revoke_follower(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    // revoking their access re-shares with everyone else, which fails for a stale group member
    let dirs = follower_dirs(user, store.clone(), mutable).await?;
    remove_group_members_without_sharing_dirs(user, &dirs, store.clone(), mutable).await?;
    // in case an earlier removal was interrupted
    complete_follower_removal(user, username, store.clone(), mutable).await?;
    if dirs.contains(username) {
        let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
        let signer = recover_signer(home, store.clone(), mutable).await?;
        let sharing = sharing_folder(user, store.clone(), mutable).await?;
        let hidden = format!("{REMOVING_FOLLOWER_PREFIX}{username}");
        crate::rename_child(&sharing, username, &hidden, Some(signer), user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    }
    complete_follower_removal(user, username, store, mutable).await
}

async fn complete_follower_removal(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let hidden = format!("{REMOVING_FOLLOWER_PREFIX}{username}");
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    if has_child(&sharing, &hidden, store.clone(), mutable).await? {
        // revoke access to everything ever shared with this user
        unshare_items_in_sharing_folder(user, &hidden, username, store.clone(), mutable).await?;
        delete_shared_child(user, &hidden, store.clone(), mutable).await?;
    }
    // they may have become a follower again since an interrupted removal
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    if has_child(&sharing, username, store.clone(), mutable).await? {
        return Ok(());
    }
    remove_from_all_groups(user, username, store, mutable).await
}

/// Remove them from every group they are in, built in or not.
async fn remove_from_all_groups(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let to_remove: BTreeSet<String> = [username.to_string()].into_iter().collect();
    for uid in get_or_create_groups(user, store.clone(), mutable).await?.uid_to_name.keys() {
        remove_members_from_group(user, uid, &to_remove, store.clone(), mutable).await?;
    }
    Ok(())
}

/// Only followers can be in a group, and removing anyone from a group fails while
/// it has a member we no longer have a sharing dir for, e.g. left by an older client.
async fn remove_group_members_without_sharing_dirs(
    user: &LoggedInUser,
    follower_dirs: &BTreeSet<String>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    for uid in get_or_create_groups(user, store.clone(), mutable).await?.uid_to_name.keys() {
        let stale: BTreeSet<String> =
            get_group_members(user, uid, store.clone(), mutable).await?.difference(follower_dirs).cloned().collect();
        remove_members_from_group(user, uid, &stale, store.clone(), mutable).await?;
    }
    Ok(())
}

/// Keep the built-in groups in line with who our followers and friends are
/// (`reconcileGroups`): finish any interrupted follower removal, remove group
/// members we no longer have a sharing dir for, and add current followers and
/// mutual friends missing from the followers and friends groups, e.g. after
/// following someone again.
pub async fn reconcile_groups(
    user: &LoggedInUser,
    following: &BTreeSet<String>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    for e in list_directory(&sharing, store.clone(), mutable).await? {
        if let Some(name) = e.name.strip_prefix(REMOVING_FOLLOWER_PREFIX) {
            complete_follower_removal(user, name, store.clone(), mutable).await?;
        }
    }
    let dirs = follower_dirs(user, store.clone(), mutable).await?;
    let groups = get_or_create_groups(user, store.clone(), mutable).await?;
    let (Some(followers_uid), Some(friends_uid)) = (groups.uid_for(FOLLOWERS_GROUP), groups.uid_for(FRIENDS_GROUP)) else {
        return Ok(());
    };
    let followers = get_group_members(user, &followers_uid, store.clone(), mutable).await?;
    let friends = get_group_members(user, &friends_uid, store.clone(), mutable).await?;
    let stale_followers: BTreeSet<String> = followers.difference(&dirs).cloned().collect();
    let stale_friends: BTreeSet<String> = friends.difference(&dirs).cloned().collect();
    remove_members_from_group(user, &friends_uid, &stale_friends, store.clone(), mutable).await?;
    remove_members_from_group(user, &followers_uid, &stale_followers, store.clone(), mutable).await?;
    remove_group_members_without_sharing_dirs(user, &dirs, store.clone(), mutable).await?;

    let pending: BTreeSet<String> = get_pending_outgoing(user, store.clone(), mutable).await?.into_iter().collect();
    let current: BTreeSet<String> = dirs.difference(&pending).cloned().collect();
    let followers = get_group_members(user, &followers_uid, store.clone(), mutable).await?;
    let friends = get_group_members(user, &friends_uid, store.clone(), mutable).await?;
    let missing_followers: Vec<String> = current.difference(&followers).cloned().collect();
    let missing_friends: Vec<String> =
        current.intersection(following).filter(|u| !friends.contains(*u)).cloned().collect();
    add_members_to_group(user, &followers_uid, &missing_followers, store.clone(), mutable).await?;
    add_members_to_group(user, &friends_uid, &missing_friends, store, mutable).await
}

/// Unsharing a group also unshares its members who were shared with individually
/// (`gatherAllUsernamesToUnshare`). Followers contain friends, so unsharing
/// followers also unshares the friends group. Custom groups can overlap without
/// either containing the other, so no such rule applies to them.
async fn expand_groups_to_unshare(
    user: &LoggedInUser,
    current: &BTreeSet<String>,
    to_unshare: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    let mut res: BTreeSet<String> = to_unshare.iter().cloned().collect();
    if !to_unshare.iter().any(|u| u.starts_with('.')) {
        return Ok(res.into_iter().collect());
    }
    let groups = get_or_create_groups(user, store.clone(), mutable).await?;
    if let (Some(followers), Some(friends)) = (groups.uid_for(FOLLOWERS_GROUP), groups.uid_for(FRIENDS_GROUP)) {
        if res.contains(&followers) && current.contains(&friends) {
            res.insert(friends);
        }
    }
    for uid in to_unshare.iter().filter(|u| u.starts_with('.')) {
        let members = get_group_members(user, uid, store.clone(), mutable).await?;
        res.extend(current.intersection(&members).cloned());
    }
    Ok(res.into_iter().collect())
}

/// Every home-relative path shared with `name` (a username or group uid), read or write.
pub async fn get_all_paths_shared_with(
    user: &LoggedInUser,
    name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<BTreeSet<String>> {
    let mut res = BTreeSet::new();
    for (dir, state) in get_all_shares(user, store, mutable).await? {
        for (child, users) in state.read.iter().chain(state.write.iter()) {
            if users.contains(name) {
                res.insert(join_path(&dir, child));
            }
        }
    }
    Ok(res)
}

fn valid_group_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(Error::Protocol("A group needs a name".into()));
    }
    if is_built_in_group_name(trimmed) {
        return Err(Error::Protocol(format!("'{trimmed}' is reserved for a built-in group")));
    }
    Ok(trimmed.to_string())
}

async fn ensure_followers(
    user: &LoggedInUser,
    usernames: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let followers = get_follower_names(user, store, mutable).await?;
    let unknown: Vec<&String> = usernames.iter().filter(|u| !followers.contains(u)).collect();
    if !unknown.is_empty() {
        return Err(Error::Protocol(format!("Only followers can be added to a group, not: {unknown:?}")));
    }
    Ok(())
}

/// Create a sharing group (`createGroup`), returning its uid. The directory and
/// its share are the group, the name is only our label for it, so the name is
/// written last: a failure before then leaves an unnamed, invisible directory.
pub async fn create_group(
    user: &LoggedInUser,
    name: &str,
    members: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<String> {
    let name = valid_group_name(name)?;
    ensure_followers(user, members, store.clone(), mutable).await?;
    let mut groups = get_or_create_groups(user, store.clone(), mutable).await?;
    let uid = generate_group_uid();
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    get_or_mkdir(&sharing, &uid, &signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;
    add_members_to_group(user, &uid, members, store.clone(), mutable).await?;
    groups.uid_to_name.insert(uid.clone(), name);
    set_groups(user, &groups, store, mutable).await?;
    Ok(uid)
}

/// Change our label for a custom group (`renameGroup`); nothing is shared or rotated.
pub async fn rename_group(
    user: &LoggedInUser,
    group_uid: &str,
    new_name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let name = valid_group_name(new_name)?;
    let mut groups = get_or_create_groups(user, store.clone(), mutable).await?;
    match groups.uid_to_name.get(group_uid) {
        None => return Err(Error::Protocol(format!("Unknown group {group_uid}"))),
        Some(n) if is_built_in_group_name(n) => return Err(Error::Protocol("Built-in groups cannot be renamed".into())),
        _ => {}
    }
    groups.uid_to_name.insert(group_uid.to_string(), name);
    set_groups(user, &groups, store, mutable).await
}

fn ensure_custom(groups: &Groups, group_uid: &str) -> Result<()> {
    if groups.uid_to_name.get(group_uid).is_some_and(|n| is_built_in_group_name(n)) {
        return Err(Error::Protocol("Membership of built-in groups is managed automatically".into()));
    }
    Ok(())
}

/// Add followers to a custom group (`addGroupMembers`).
pub async fn add_group_members(
    user: &LoggedInUser,
    group_uid: &str,
    members: &[String],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    ensure_custom(&get_or_create_groups(user, store.clone(), mutable).await?, group_uid)?;
    ensure_followers(user, members, store.clone(), mutable).await?;
    add_members_to_group(user, group_uid, members, store, mutable).await
}

/// Remove a member from a custom group (`removeGroupMember`). This always rotates
/// the keys of the group directory, so they cannot see anything shared with the
/// group from now on. Things shared with the group before which they have already
/// retrieved stay readable to them unless `revoke_shared` is set, which also
/// rotates the keys of every one of those.
pub async fn remove_group_member(
    user: &LoggedInUser,
    group_uid: &str,
    member: &str,
    revoke_shared: bool,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    ensure_custom(&get_or_create_groups(user, store.clone(), mutable).await?, group_uid)?;
    let revoked = [member.to_string()];
    unshare_read_path(user, &group_path(group_uid), &revoked, store.clone(), mutable).await?;
    if revoke_shared {
        unshare_items_in_sharing_folder(user, group_uid, member, store, mutable).await?;
    }
    Ok(())
}

/// The number of files and folders shared with a group, which is how much work
/// revoking them all is (`countSharedWithGroup`).
pub async fn count_shared_with_group(
    user: &LoggedInUser,
    group_uid: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<usize> {
    Ok(get_all_paths_shared_with(user, group_uid, store, mutable).await?.len())
}

/// Delete a custom group (`deleteGroup`). Without `revoke_shared`, members keep
/// access to what was shared with the group before, but nothing new reaches them
/// through it. With `revoke_shared`, everything shared with the group is unshared
/// from it first, rotating the keys of each; `progress` is called once per item.
pub async fn delete_group(
    user: &LoggedInUser,
    group_uid: &str,
    revoke_shared: bool,
    mut progress: impl FnMut(),
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut groups = get_or_create_groups(user, store.clone(), mutable).await?;
    match groups.uid_to_name.get(group_uid) {
        None => return Err(Error::Protocol(format!("Unknown group {group_uid}"))),
        Some(n) if is_built_in_group_name(n) => return Err(Error::Protocol("Built-in groups cannot be deleted".into())),
        _ => {}
    }
    let group = [group_uid.to_string()];
    if revoke_shared {
        for path in get_all_paths_shared_with(user, group_uid, store.clone(), mutable).await? {
            if get_shared_with(user, &path, Access::Write, store.clone(), mutable).await?.contains(&group[0]) {
                unshare_write_path(user, &path, &group, store.clone(), mutable).await?;
            }
            if get_shared_with(user, &path, Access::Read, store.clone(), mutable).await?.contains(&group[0]) {
                unshare_read_path(user, &path, &group, store.clone(), mutable).await?;
            }
            progress();
        }
    }
    groups.uid_to_name.remove(group_uid);
    set_groups(user, &groups, store.clone(), mutable).await?;
    // Anything still recording the group would be re-sent to its directory, which is
    // about to go, whenever it is next re-keyed.
    for path in get_all_paths_shared_with(user, group_uid, store.clone(), mutable).await? {
        let (dir_path, filename) = split_path(&path);
        let mut state = read_shared_with_at(user, &dir_path, store.clone(), mutable).await?;
        for access in [Access::Read, Access::Write] {
            let map = state.map(access);
            if let Some(users) = map.get_mut(&filename) {
                users.remove(group_uid);
                if users.is_empty() {
                    map.remove(&filename);
                }
            }
        }
        write_shared_with_at(user, &dir_path, &state, store.clone(), mutable).await?;
    }
    delete_shared_child(user, group_uid, store, mutable).await
}

/// `move` with shared-with cache maintenance (`FileWrapper.moveTo` +
/// `clearSharedWith`/`addAllSharedWith`): move `name` from `source_parent` into
/// `target`, then rewrite the shared-with cache. A same-writer move with
/// `keep_access` keeps the capability (and the share record); otherwise the keys
/// rotate, breaking old shares, so the record is dropped.
#[allow(clippy::too_many_arguments)]
pub async fn move_file(
    user: &LoggedInUser,
    source_parent: &AbsoluteCapability,
    source_path: &str,
    name: &str,
    target: &AbsoluteCapability,
    target_path: &str,
    keep_access: bool,
    entry_signer: Option<peergos_core::keys::SigningPrivateKeyAndPublicHash>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let old_file_path = join_path(source_path, name);
    let new_file_path = join_path(target_path, name);
    let readers: BTreeSet<String> =
        get_shared_with(user, &old_file_path, Access::Read, store.clone(), mutable).await?.into_iter().collect();
    let writers: BTreeSet<String> =
        get_shared_with(user, &old_file_path, Access::Write, store.clone(), mutable).await?.into_iter().collect();
    // The fast (metadata-only) path preserves the capability, so shares survive.
    let preserved = keep_access && target.writer == source_parent.writer;

    let new_cap =
        crate::move_to(source_parent, name, target, keep_access, entry_signer, user.mirror_bat_id().as_ref(), store.clone(), mutable).await?;

    // Clear the shares at the old path (`clearSharedWith`).
    let (old_dir, old_name) = split_path(&old_file_path);
    let mut old_state = read_shared_with_at(user, &old_dir, store.clone(), mutable).await?;
    old_state.read.remove(&old_name);
    old_state.write.remove(&old_name);
    write_shared_with_at(user, &old_dir, &old_state, store.clone(), mutable).await?;

    // Re-add them at the new path if the capability survived (`addAllSharedWith`).
    if preserved && (!readers.is_empty() || !writers.is_empty()) {
        let (new_dir, new_name) = split_path(&new_file_path);
        let mut new_state = read_shared_with_at(user, &new_dir, store.clone(), mutable).await?;
        if !readers.is_empty() {
            new_state.read.insert(new_name.clone(), readers);
        }
        if !writers.is_empty() {
            new_state.write.insert(new_name, writers);
        }
        write_shared_with_at(user, &new_dir, &new_state, store, mutable).await?;
    }
    Ok(new_cap)
}
