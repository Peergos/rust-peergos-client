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
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let existing = list_directory(dir_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == name);
    match existing {
        Some(e) => Ok(e.cap),
        None => create_directory(dir_cap, name, Some(signer.clone()), store, mutable).await,
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
pub async fn send_follow_request(
    user: &LoggedInUser,
    target_username: &str,
    reciprocate: bool,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<bool> {
    let (target_identity, target_boxer) =
        get_public_keys(poster, store.as_ref(), mutable, target_username).await?;

    // Create /username/shared/<target> and take a read-only cap to it. The signer
    // comes from the home entry point (subdirs share its writer, holding no link
    // of their own).
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let friend_root = get_or_mkdir(&sharing, target_username, &signer, store.clone(), mutable).await?;

    let entry = EntryPoint { pointer: friend_root.read_only(), owner_name: user.username.clone() };
    let requested_key =
        if reciprocate { Some(SymmetricKey::new(peergos_crypto::random_bytes(32), false)?) } else { None };

    // FollowRequest cbor: {e: entry, k: requestedKey?}
    let mut fr = CborObject::map().put("e", entry.to_cbor());
    if let Some(k) = &requested_key {
        fr = fr.put("k", k.to_cbor());
    }
    let follow_request = fr.build();

    blind_and_send(&target_identity, &target_boxer, &follow_request, poster).await
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
    contents.extend_from_slice(&entry.to_cbor().to_bytes());
    crate::upload_file(home, FROM_FRIENDS_FILE, &contents, None, Some(signer), store, mutable).await?;
    Ok(())
}

/// The entry points shared with us by friends (`getFriendsEntryPoints`): each is
/// a read cap to a friend's `/friend/shared/<us>` folder. Persisted across logins.
const SHARED_DIR: &str = "shared";
const SOCIAL_STATE_FILE: &str = ".social-state.cbor";
const BLOCKED_USERNAMES_FILE: &str = ".blocked-usernames.txt";

/// A snapshot of the user's social state (`getSocialState`). Populated from the
/// pieces the Rust client tracks; Java additionally carries follower/following
/// FileWrapper roots, friend annotations and group-name mappings, which this does
/// not.
#[derive(Debug, Clone)]
pub struct SocialState {
    pub pending_incoming_requests: Vec<ReceivedFollowRequest>,
    pub pending_outgoing: Vec<String>,
    pub following: Vec<String>,
    pub followers: Vec<String>,
    pub blocked: Vec<String>,
    /// The friend/following entry-point roots (kept for navigation).
    pub friends: Vec<EntryPoint>,
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

/// The usernames of the people the user follows (`getFollowing`) — the owner names
/// of their friend roots.
pub async fn get_following(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    Ok(get_friends(user, store, mutable).await?.into_iter().map(|e| e.owner_name).collect())
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

/// The usernames the user has blocked (`getBlocked`) — the newline-separated
/// `.blocked-usernames.txt` in home.
pub async fn get_blocked(
    user: &LoggedInUser,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<String>> {
    match read_home_child(user, BLOCKED_USERNAMES_FILE, store, mutable).await? {
        Some(bytes) => Ok(String::from_utf8_lossy(&bytes)
            .split('\n')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()),
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

/// Every file shared with `username`, as `(home-relative dir path, child name,
/// access)`, by walking the outbound shared-with cache. Used by `removeFollower` to
/// revoke each one.
pub async fn collect_shares_for_user(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<(String, String, Access)>> {
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let cap_cache = match list_directory(home, store.clone(), mutable).await?.into_iter().find(|e| e.name == CAP_CACHE_DIR) {
        Some(e) => e.cap,
        None => return Ok(Vec::new()),
    };
    let outbound = match list_directory(&cap_cache, store.clone(), mutable).await?.into_iter().find(|e| e.name == OUTBOUND_DIR) {
        Some(e) => e.cap,
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

/// Block `username` (`unfollow`): add them to `.blocked-usernames.txt` in home. This
/// stops honouring their follow of us. (Java also removes their local entry-point
/// mirror; that cleanup is not done here.)
pub async fn unfollow(
    user: &LoggedInUser,
    username: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut blocked = get_blocked(user, store.clone(), mutable).await?;
    if !blocked.iter().any(|b| b == username) {
        blocked.push(username.to_string());
    }
    let content = format!("{}\n", blocked.join("\n"));
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    crate::upload_file(home, BLOCKED_USERNAMES_FILE, content.as_bytes(), None, Some(signer), store, mutable).await?;
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

/// `sendReplyFollowRequest` (accept branch): accept an incoming follow request.
/// Creates our sharing folder for them, sends back our entry point, persists
/// their entry point (so we can read what they share with us) and removes the
/// processed request. With `reciprocate`, the reply signals mutual friendship.
pub async fn accept_follow_request(
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
    let their_name = entry.owner_name.clone();
    let (their_identity, their_boxer) =
        get_public_keys(poster, store.as_ref(), mutable, &their_name).await?;

    // Create /username/shared/<them> and grant them read access to it.
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let friend_root = get_or_mkdir(&sharing, &their_name, &signer, store.clone(), mutable).await?;

    // Reply with our entry point; if reciprocating, echo their read key.
    let our_entry = EntryPoint { pointer: friend_root.read_only(), owner_name: user.username.clone() };
    let mut reply = CborObject::map().put("e", our_entry.to_cbor());
    if reciprocate {
        reply = reply.put("k", entry.pointer.r_base_key.to_cbor());
    }
    blind_and_send(&their_identity, &their_boxer, &reply.build(), poster).await?;

    // Persist their entry point so we retain read access after this session.
    persist_friend_entry_point(user, entry, store.clone(), mutable).await?;

    // Add them to our followers group, and — if reciprocating (mutual friends) —
    // our friends group, matching Java's accept flow. This shares each group's
    // sharing directory with them, so anything we later share with those groups
    // reaches them automatically (their cap cache auto-discovers the group dir).
    add_member_to_group(user, FOLLOWERS_GROUP, &their_name, store.clone(), mutable).await?;
    if reciprocate {
        add_member_to_group(user, FRIENDS_GROUP, &their_name, store.clone(), mutable).await?;
    }

    // Remove the processed request from our inbox.
    remove_follow_request(user, &request.raw_cipher, poster).await?;
    Ok(())
}

/// Process a reply to one of our outgoing follow requests: persist the sender's
/// entry point and remove the request. (The reply needs no further response.)
pub async fn process_follow_reply(
    user: &LoggedInUser,
    request: &ReceivedFollowRequest,
    poster: &dyn HttpPoster,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if let Some(entry) = &request.entry {
        let their_name = entry.owner_name.clone();
        let is_self = their_name == user.username;
        // A rejection sends a null capability.
        let accepted = !entry.pointer.map_key.iter().all(|b| *b == 0);
        if !is_self && accepted {
            persist_friend_entry_point(user, entry, store.clone(), mutable).await?;
        }
        // If they reciprocated (they now follow us — the reply carries a key), add
        // them to our followers group, and to our friends group too if they also
        // accepted (mutual). Matches Java's reply handling, so anything we share
        // with those groups reaches them.
        if !is_self && request.key.is_some() {
            add_member_to_group(user, FOLLOWERS_GROUP, &their_name, store.clone(), mutable).await?;
            if accepted {
                add_member_to_group(user, FRIENDS_GROUP, &their_name, store.clone(), mutable).await?;
            }
        }
    }
    remove_follow_request(user, &request.raw_cipher, poster).await?;
    Ok(())
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
    let friend_dir = get_or_mkdir(&sharing, friend_username, &signer, store.clone(), mutable).await?;
    let existing = list_directory(&friend_dir, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == store_filename);
    let mut contents = match existing {
        Some(e) => crate::read_file(&e.cap, store.clone(), mutable).await?.1,
        None => Vec::new(),
    };
    contents.extend_from_slice(&cap.to_cbor().to_bytes());
    crate::upload_file(&friend_dir, store_filename, &contents, None, Some(signer), store, mutable).await?;
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

    // Rotate the directory into its own writer if it doesn't have one yet.
    let dir_cap =
        crate::move_dir_to_own_writer(parent_cap, child_name, Some(signer.clone()), store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    let friend_dir = get_or_mkdir(&sharing, friend_username, &signer, store.clone(), mutable).await?;

    let existing = list_directory(&friend_dir, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == EDIT_SHARING_FILE);
    let mut contents = match existing {
        Some(e) => crate::read_file(&e.cap, store.clone(), mutable).await?.1,
        None => Vec::new(),
    };
    contents.extend_from_slice(&dir_cap.to_cbor().to_bytes());
    crate::upload_file(&friend_dir, EDIT_SHARING_FILE, &contents, None, Some(signer), store.clone(), mutable)
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

/// A recorded secret link, enough to re-mint it under the same label/password when
/// the target's keys rotate (`LinkProperties`). Cbor `{l,p,u,w,o,[h],[m],[e]}`.
#[derive(Debug, Clone)]
pub struct LinkProperties {
    pub label: i64,
    pub link_password: String,
    pub user_password: String,
    pub writable: bool,
    pub open: bool,
    pub max_retrievals: Option<i64>,
    pub expiry_epoch_secs: Option<i64>,
}

impl LinkProperties {
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
        })
    }
}

/// Who the children of a directory are shared with (`SharedWithState`). Keyed by
/// child filename → set of usernames (read/write) or list of links.
#[derive(Debug, Default, Clone)]
struct SharedWithState {
    read: BTreeMap<String, BTreeSet<String>>,
    write: BTreeMap<String, BTreeSet<String>>,
    links: BTreeMap<String, Vec<LinkProperties>>,
}

impl SharedWithState {
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

/// Navigate (creating if needed) `.capabilitycache/outbound/<dir_path>/` — the
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
    let mut cur = get_or_mkdir(&cap_cache, OUTBOUND_DIR, &signer, store.clone(), mutable).await?;
    for comp in dir_path {
        cur = get_or_mkdir(&cur, comp, &signer, store.clone(), mutable).await?;
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

/// Write the `sharedWith.cbor` for the directory at `dir_path`.
async fn write_shared_with_at(
    user: &LoggedInUser,
    dir_path: &[String],
    state: &SharedWithState,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (dir, signer) = cache_dir_for(user, dir_path, store.clone(), mutable).await?;
    crate::upload_file(&dir, DIR_CACHE_FILE, &state.to_cbor().to_bytes(), None, Some(signer), store, mutable)
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
        crate::rotate_child_read_keys(parent_cap, child_name, Some(home_signer), store.clone(), mutable).await?;

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
        crate::force_rotate_child_to_new_writer(parent_cap, child_name, Some(home_signer), store.clone(), mutable)
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
        get_or_mkdir(&sharing, uid, &signer, store.clone(), mutable).await?;
    }
    crate::upload_file(&sharing, GROUPS_FILE, &groups.to_cbor().to_bytes(), None, Some(signer), store.clone(), mutable)
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

/// Resolve a group's sharing-directory capability (`/username/shared/<uid>`).
async fn group_dir(
    user: &LoggedInUser,
    group_name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let groups = get_or_create_groups(user, store.clone(), mutable).await?;
    let uid = groups.uid_for(group_name).ok_or_else(|| Error::Protocol(format!("no such group: {group_name}")))?;
    let home = user.home().ok_or_else(|| Error::Protocol("no home directory".into()))?;
    let signer = recover_signer(home, store.clone(), mutable).await?;
    let sharing = sharing_folder(user, store.clone(), mutable).await?;
    get_or_mkdir(&sharing, &uid, &signer, store, mutable).await
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
    let dir = group_dir(user, group_name, store.clone(), mutable).await?;
    // The member must have an accepted follow (a sharing folder) with us already.
    append_cap_to_friend(user, member, READ_SHARING_FILE, &dir.read_only(), store, mutable).await
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
        crate::move_to(source_parent, name, target, keep_access, entry_signer, store.clone(), mutable).await?;

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
