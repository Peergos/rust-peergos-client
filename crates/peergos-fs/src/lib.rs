//! Peergos filesystem layer: capabilities, secret links, the cryptree and file
//! retrieval. Ported from `peergos.shared.user.fs`.
//!
//! Currently implemented: the secret-link → [`AbsoluteCapability`] path. The
//! cryptree node decryption and file-content retrieval are the next increments.

pub mod admin;
pub mod account;
pub mod cache;
pub mod capability;
pub mod context;
pub mod cryptree;
pub mod feed;
pub mod filewrapper;
pub mod hashtree;
pub mod incoming;
pub mod login;
pub mod mfa;
pub mod mimetype;
pub mod profile;
pub mod publish;
pub mod retrieve;
pub mod signup;
pub mod social;
pub mod thumbnail;
pub mod transaction;

pub use capability::{AbsoluteCapability, EncryptedCapability, Location, SecretLink, SecretLinkTarget};
pub use login::{change_password, login, EntryPoint, LoggedInUser, MfaResponder};
pub use mfa::{
    current_totp, generate_totp, MfaType, MultiFactorAuthMethod, MultiFactorAuthRequest,
    MultiFactorAuthResponse, TotpKey,
};
pub use signup::signup;
pub use social::{
    accept_follow_request, add_friend_annotation, add_member_to_group, block, collect_shares_for_user,
    get_blocked, get_directory_sharing_state, get_follow_requests, get_follower_names,
    get_friend_annotations, get_following, get_friends, get_links, get_or_create_groups,
    get_pending_outgoing, get_public_keys, get_shared_with, group_uid, unblock, unfollow,
    load_read_access_sharing_links, load_write_access_sharing_links, move_file,
    process_follow_reply, read_shared_capabilities, read_write_shared_capabilities, record_link,
    reject_follow_request, remove_link, send_follow_request, share_read_access, share_read_with_group, share_write_access,
    share_write_with_group, unshare_read_access, unshare_write_access, Access, CapabilitiesFromUser,
    CapabilityWithPath, FileSharedWithState, FriendAnnotation, Groups, LinkProperties,
    ReceivedFollowRequest, SharedWithState, SocialState, FOLLOWERS_GROUP, FRIENDS_GROUP,
};
pub use cryptree::{
    ChildrenLinks, CryptreeNode, FileProperties, NamedRelativeCapability, RelativeCapability,
};
pub use account::{add_totp_factor, delete_second_factor, enable_totp_factor, list_second_factors};
pub use admin::{
    accepting_signups, add_to_waitlist, approve_space_request, get_pending_space_requests, get_version_info,
    AllowedSignups, LabelledSignedSpaceRequest, VersionInfo,
};
pub use cache::CryptreeCache;
pub use context::{PaymentProperties, UserContext};
pub use feed::{Content, FileRef, Resharing, SharedItem, SocialFeed, SocialPost};
pub use filewrapper::FileWrapper;
pub use profile::Profile;
pub use incoming::{CapsInDirectory, ChildElement, IncomingCapCache, ProcessedCaps};
pub use retrieve::{FragmentedPaddedCipherText, CHUNK_MAX_SIZE};
pub use transaction::FileUploadTransaction;
// move_to, rename_child, delete_child etc. are `pub async fn` at the crate root.

use cryptree::{
    PaddedCipherText, RelativeCapability as RelCap, BASE_BLOCK_PADDING_BLOCKSIZE,
    META_DATA_PADDING_BLOCKSIZE,
};
use peergos_cbor::{CborObject, Cborable};
use peergos_core::auth::{Bat, BatId};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{
    PublicKeyHash, PublicSigningKey, SecretSigningKey, SigningPrivateKeyAndPublicHash,
};
use peergos_core::mutable::{MutablePointers, PointerUpdate};
use peergos_core::storage::{
    put_block_signed, put_raw_blocks_signed, ContentAddressedStorage, TransactionId,
};
use peergos_core::symmetric::SymmetricKey;
use peergos_core::{
    identity_key_hasher, BatWithId, BufferedNetwork, Champ, ChampWrapper, ChunkMirrorCap, FallbackStorage,
    RamStorage, MAX_CHAMP_GETS,
};
use std::future::Future;
use std::pin::Pin;
use peergos_crypto::random_bytes;
use peergos_multiformats::Cid;
use retrieve::MIN_FRAGMENT_SIZE;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Max child links per directory blob (`CryptreeNode.MAX_CHILD_LINKS_PER_BLOB`).
/// Overridable via `PEERGOS_MAX_CHILD_LINKS` (mirrors `setMaxChildLinkPerBlob`,
/// used for testing directory chunking without creating thousands of entries).
fn max_child_links_per_blob() -> usize {
    std::env::var("PEERGOS_MAX_CHILD_LINKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500)
}

/// Resolve a secret link to its [`AbsoluteCapability`] by fetching the encrypted
/// capability from the server and decrypting it with the link password (plus an
/// optional user password when the link requires one).
pub async fn retrieve_secret_link_capability(
    link_str: &str,
    store: &dyn ContentAddressedStorage,
    user_password: Option<&str>,
) -> Result<AbsoluteCapability> {
    let link = SecretLink::from_link(link_str)?;
    let label = link.label_string();
    let enc_cbor = store.get_secret_link(&link.owner, &label).await?;
    let enc = EncryptedCapability::from_cbor(&enc_cbor)?;
    let password = if enc.has_user_password {
        let extra = user_password
            .ok_or_else(|| Error::Protocol("Secret link requires a user password".into()))?;
        format!("{}{}", link.link_password, extra)
    } else {
        link.link_password.clone()
    };
    enc.decrypt_from_password(&label, &password)
}

/// Generate a shareable secret link that grants exactly `cap` and return its link
/// string (`UserContext.createSecretLink` / `updateSecretLink`). The encrypted
/// capability is stored under a fresh random label in the identity writer's
/// secret-link CHAMP (mirror-BAT gated for privacy) and committed. Pass a read-only
/// cap for a read link, or a writable cap for a write link — for a writable link the
/// caller must have already relocated the target into its own writing space (Java's
/// invariant; [`UserContext::create_secret_link`] does this via
/// [`move_dir_to_own_writer`]).
#[allow(clippy::too_many_arguments)]
pub async fn create_secret_link(
    cap: &AbsoluteCapability,
    user_password: &str,
    expiry_epoch_secs: Option<i64>,
    max_retrievals: Option<i64>,
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatWithId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<SecretLink> {
    let link = SecretLink::create(cap.owner.clone())?;
    put_secret_link(cap, &link, user_password, expiry_epoch_secs, max_retrievals, signer, mirror_bat, store, mutable).await?;
    Ok(link)
}

/// Store (or overwrite) the secret link `link` mapping `cap`, under `link`'s label —
/// used both to mint a fresh link and to RE-MINT an existing one under the same
/// label/password after the target's keys rotate (Java `updateSecretLink`).
#[allow(clippy::too_many_arguments)]
pub async fn put_secret_link(
    cap: &AbsoluteCapability,
    link: &SecretLink,
    user_password: &str,
    expiry_epoch_secs: Option<i64>,
    max_retrievals: Option<i64>,
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatWithId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let full_password = format!("{}{}", link.link_password, user_password);
    let has_user_password = !user_password.is_empty();
    let enc = EncryptedCapability::create_from_password(cap, &link.label_string(), &full_password, has_user_password)?;
    let target = SecretLinkTarget { cap: enc, expiry_epoch_secs, max_retrievals };
    add_secret_link(&cap.owner, signer, link.label, &target, mirror_bat, &store, mutable).await
}

/// The secret-link CHAMP key for a label: sha256 of its 8 little-endian bytes
/// (`SecretLinkChamp.keyToBytes`).
fn secret_link_key(label: i64) -> Vec<u8> {
    peergos_crypto::hash::sha256(&label.to_le_bytes())
}

/// Set a `MerkleLink` field on a WriterData cbor map (preserving all other fields).
fn writer_data_with_link_field(wd: &CborObject, field: &str, cid: &Cid) -> Result<CborObject> {
    let mut map = match wd {
        CborObject::Map(m) => m.clone(),
        _ => return Err(Error::Cbor("WriterData is not a map".into())),
    };
    map.insert(peergos_cbor::CborString::new(field), CborObject::MerkleLink(cid.to_bytes()));
    Ok(CborObject::Map(map))
}

/// Store `target` under `label` in the identity writer's secret-link CHAMP
/// (`WriterData.addLink`) and commit the identity pointer.
async fn add_secret_link(
    identity: &PublicKeyHash,
    signer: &SigningPrivateKeyAndPublicHash,
    label: i64,
    target: &SecretLinkTarget,
    mirror_bat: Option<&BatWithId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let pointer = mutable.get_pointer_target(identity, &signer.public_key_hash, store.as_ref()).await?;
    let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("identity has no data".into()))?;
    let wd = store.get(identity, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let tid = store.start_transaction(identity).await?;

    // Get or create the links champ; a fresh one embeds the mirror BAT so the
    // stored links stay private.
    let links_root = match wd.get("links").and_then(|c| c.as_link()) {
        Some(link) => Cid::cast(link)?,
        None => {
            let mut empty = Champ::empty();
            empty.mirror_bat = mirror_bat.map(|b| b.id());
            put_block_signed(store.as_ref(), identity, signer, empty.serialize(), &tid).await?
        }
    };
    // The champ key is already sha256(label); the champ positions by it directly
    // (identity hasher), matching Java's SecretLinkChamp.
    let mut champ =
        ChampWrapper::create(identity.clone(), links_root, mirror_bat, store.clone(), identity_key_hasher()).await?;

    // Store the target block, then map label -> MerkleLink(target).
    let value_cid = put_block_signed(store.as_ref(), identity, signer, target.to_cbor().to_bytes(), &tid).await?;
    let key = secret_link_key(label);
    let expected = champ.get(&key).await?;
    champ.put(signer, &key, &expected, Some(CborObject::MerkleLink(value_cid.to_bytes())), &tid).await?;

    // Update WriterData.links and commit the identity pointer.
    let new_wd = writer_data_with_link_field(&wd, "links", champ.root_hash())?;
    let new_wd_cid = put_block_signed(store.as_ref(), identity, signer, new_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
    if !mutable.set_pointer_update(identity, signer, &update).await? {
        return Err(Error::Protocol("secret-link pointer rejected (concurrent modification?)".into()));
    }
    store.close_transaction(identity, &tid).await?;
    Ok(())
}

/// Remove the secret link `label` from the identity writer's secret-link CHAMP and
/// commit (`WriterData.removeLink` / `UserContext.deleteSecretLink`). No-op if the
/// user has no links or the label is absent.
pub async fn delete_secret_link(
    identity: &PublicKeyHash,
    signer: &SigningPrivateKeyAndPublicHash,
    label: i64,
    mirror_bat: Option<&BatWithId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let pointer = mutable.get_pointer_target(identity, &signer.public_key_hash, store.as_ref()).await?;
    let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("identity has no data".into()))?;
    let wd = store.get(identity, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let links_root = match wd.get("links").and_then(|c| c.as_link()) {
        Some(link) => Cid::cast(link)?,
        None => return Ok(()), // no links at all
    };
    let tid = store.start_transaction(identity).await?;
    let mut champ =
        ChampWrapper::create(identity.clone(), links_root, mirror_bat, store.clone(), identity_key_hasher()).await?;
    let key = secret_link_key(label);
    let expected = champ.get(&key).await?;
    if expected.is_none() {
        return Ok(()); // label not present
    }
    champ.remove(signer, &key, &expected, &tid).await?;
    let new_wd = writer_data_with_link_field(&wd, "links", champ.root_hash())?;
    let new_wd_cid = put_block_signed(store.as_ref(), identity, signer, new_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
    if !mutable.set_pointer_update(identity, signer, &update).await? {
        return Err(Error::Protocol("secret-link delete pointer rejected".into()));
    }
    store.close_transaction(identity, &tid).await?;
    Ok(())
}

/// Open the champ tree of the capability's writer (writer pointer →
/// `WriterData.tree` → champ). All of a file's chunks live in this same tree.
async fn open_writer_champ(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<ChampWrapper> {
    let pointer = mutable
        .get_pointer_target(&cap.owner, &cap.writer, store.as_ref())
        .await?;
    let wd_cid = pointer
        .updated
        .ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let wd_cbor = store
        .get(&cap.owner, &wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("writer data block missing".into()))?;
    let tree_root = wd_cbor
        .get("tree")
        .and_then(|c| c.as_link())
        .ok_or_else(|| Error::Protocol("writer data has no champ tree".into()))?;
    ChampWrapper::create(
        cap.owner.clone(),
        Cid::cast(tree_root)?,
        None,
        store,
        identity_key_hasher(),
    )
    .await
}

/// Fetch and decode the cryptree node at `(owner, writer, map_key, bat)` by
/// looking up `map_key` in the writer's champ. `None` if absent.
async fn fetch_chunk_node(
    champ: &ChampWrapper,
    cap: &AbsoluteCapability,
    map_key: &[u8],
    bat: &Option<peergos_core::Bat>,
    store: &dyn ContentAddressedStorage,
) -> Result<Option<CryptreeNode>> {
    let value = match champ.get(map_key).await? {
        Some(v) => v,
        None => return Ok(None),
    };
    let cryptree_cid = Cid::cast(
        value
            .as_link()
            .ok_or_else(|| Error::Protocol("champ value is not a link".into()))?,
    )?;
    let bwid = match bat {
        Some(b) => Some(BatWithId::new(b.clone(), b.calculate_id()?.id)?),
        None => None,
    };
    match store.get(&cap.owner, &cryptree_cid, bwid.as_ref()).await? {
        Some(cbor) => Ok(Some(CryptreeNode::from_cbor(&cbor, &cap.r_base_key)?)),
        None => Ok(None),
    }
}

/// Resolve the writer's champ tree root (writer pointer → `WriterData.tree`),
/// without opening the tree. Used to drive server-side champ lookups.
pub(crate) async fn open_writer_root(
    cap: &AbsoluteCapability,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Cid> {
    let pointer = mutable
        .get_pointer_target(&cap.owner, &cap.writer, store.as_ref())
        .await?;
    let wd_cid = pointer
        .updated
        .ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let wd_cbor = store
        .get(&cap.owner, &wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("writer data block missing".into()))?;
    let tree_root = wd_cbor
        .get("tree")
        .and_then(|c| c.as_link())
        .ok_or_else(|| Error::Protocol("writer data has no champ tree".into()))?;
    Cid::cast(tree_root).map_err(Into::into)
}

fn bat_with_id(bat: &Option<Bat>) -> Result<Option<BatWithId>> {
    match bat {
        Some(b) => Ok(Some(BatWithId::new(b.clone(), b.calculate_id()?.id)?)),
        None => Ok(None),
    }
}

/// Fetch the cryptree node for one chunk key using the server's `champ/get`
/// API — one round-trip returns the whole champ path plus the value block — then
/// re-run the lookup LOCALLY against those blocks. Loading them into a fresh
/// [`RamStorage`] recomputes each CID, so a corrupted or omitted block simply
/// won't resolve: every hash and the lookup itself is verified client-side.
/// Data fragments the node points at are still fetched from `store` on decrypt.
async fn fetch_chunk_node_verified(
    cap: &AbsoluteCapability,
    root: &Cid,
    map_key: &[u8],
    bat: &Option<Bat>,
    store: &Arc<dyn ContentAddressedStorage>,
    cache: &CryptreeCache,
) -> Result<Option<CryptreeNode>> {
    // A hit skips both the champ/get round-trip and the decrypt. Safe because the
    // key includes the content-addressed champ `root`.
    if let Some(hit) = cache.get(root, map_key) {
        return Ok(hit);
    }
    let mirror = ChunkMirrorCap::new(map_key.to_vec(), bat_with_id(bat)?);
    let blocks = store
        .get_champ_lookup(&cap.owner, root, std::slice::from_ref(&mirror), None)
        .await?;
    if blocks.is_empty() {
        cache.put(root, map_key, None);
        return Ok(None);
    }
    let local = Arc::new(RamStorage::new());
    local.load_verified(blocks)?;
    let local_store: Arc<dyn ContentAddressedStorage> = local.clone();
    let champ = ChampWrapper::create(
        cap.owner.clone(),
        root.clone(),
        None,
        local_store,
        identity_key_hasher(),
    )
    .await?;
    let node = fetch_chunk_node(&champ, cap, map_key, bat, local.as_ref()).await?;
    cache.put(root, map_key, node.clone());
    Ok(node)
}

/// Resolve a read capability to its (first-chunk) cryptree node and decrypted
/// properties. Mirrors `NetworkAccess.getMetadata`.
pub async fn retrieve_file_metadata(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(CryptreeNode, FileProperties)> {
    retrieve_file_metadata_cached(cap, store, mutable, &CryptreeCache::new()).await
}

pub(crate) async fn retrieve_file_metadata_cached(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    cache: &CryptreeCache,
) -> Result<(CryptreeNode, FileProperties)> {
    let root = open_writer_root(cap, &store, mutable).await?;
    let node = fetch_chunk_node_verified(cap, &root, &cap.map_key, &cap.bat, &store, cache)
        .await?
        .ok_or_else(|| Error::Protocol("map key not found in tree".into()))?;
    let properties = node.get_properties(&cap.r_base_key)?;
    Ok((node, properties))
}

/// Stream a file's contents: walk all chunks (each ≤ 5 MiB), decrypt one at a
/// time and hand each plaintext slice to `sink`, never holding more than a single
/// chunk in memory. Returns the file properties. This is the RAM-safe primitive
/// for large files.
pub async fn read_file_to(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<FileProperties> {
    read_file_to_cached(cap, store, mutable, &CryptreeCache::new(), sink).await
}

pub(crate) async fn read_file_to_cached(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    cache: &CryptreeCache,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<FileProperties> {
    let root = open_writer_root(cap, &store, mutable).await?;
    let first = fetch_chunk_node_verified(cap, &root, &cap.map_key, &cap.bat, &store, cache)
        .await?
        .ok_or_else(|| Error::Protocol("map key not found in tree".into()))?;
    if first.is_directory() {
        return Err(Error::Protocol("capability points to a directory, not a file".into()));
    }
    let props = first.get_properties(&cap.r_base_key)?;

    let mut written: u64 = 0;
    let mut node = first;
    let mut map_key = cap.map_key.clone();
    let mut bat = cap.bat.clone();

    loop {
        let data_key = node.get_data_key(&cap.r_base_key)?;
        let chunk = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt_bytes(&cap.owner, &data_key, store.as_ref())
            .await?;
        // Never emit more than the declared file size (the last chunk may carry
        // padding beyond the true end).
        let remaining = props.size.saturating_sub(written) as usize;
        let take = chunk.len().min(remaining);
        if take > 0 {
            sink(&chunk[..take])?;
            written += take as u64;
        }
        if written >= props.size {
            break;
        }
        // Locate and fetch the next chunk (files use the stream secret).
        let stream_secret = props
            .stream_secret
            .as_ref()
            .ok_or_else(|| Error::Protocol("multi-chunk file without a stream secret".into()))?;
        let (next_map_key, next_bat) =
            retrieve::calculate_next_map_key(stream_secret, &map_key, &bat)?;
        map_key = next_map_key;
        bat = next_bat;
        node = match fetch_chunk_node_verified(cap, &root, &map_key, &bat, &store, cache).await? {
            Some(n) => n,
            None => break, // no further chunks written
        };
    }
    Ok(props)
}

/// Read a file's full contents into memory. Convenience wrapper over
/// [`read_file_to`] — use that directly to avoid buffering large files.
pub async fn read_file(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(FileProperties, Vec<u8>)> {
    let mut data: Vec<u8> = Vec::new();
    let props = read_file_to(cap, store, mutable, |chunk| {
        data.extend_from_slice(chunk);
        Ok(())
    })
    .await?;
    Ok((props, data))
}

/// Compute the map-key/BAT of the `n`-th subsequent chunk by iterating the stream
/// secret (`FileProperties.calculateMapKey`). Pure computation — this is how we
/// seek to a chunk without fetching the ones before it.
fn advance_map_key(
    stream_secret: &[u8],
    map_key: &[u8],
    bat: &Option<Bat>,
    n: u64,
) -> Result<(Vec<u8>, Option<Bat>)> {
    let mut mk = map_key.to_vec();
    let mut bt = bat.clone();
    for _ in 0..n {
        let (nmk, nbt) = retrieve::calculate_next_map_key(stream_secret, &mk, &bt)?;
        mk = nmk;
        bt = nbt;
    }
    Ok((mk, bt))
}

/// Read only the byte range `[offset, offset+length)` of a file, fetching just the
/// chunk(s) that overlap it (plus chunk 0 for the size + stream secret) — never the
/// whole file or all its metadata. Mirrors Java's `getInputStream(...).seek(offset)`
/// + bounded read. The returned slice is clamped to the file's end.
pub async fn read_file_section(
    cap: &AbsoluteCapability,
    offset: u64,
    length: u64,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<u8>> {
    read_file_section_cached(cap, offset, length, store, mutable, &CryptreeCache::new()).await
}

pub(crate) async fn read_file_section_cached(
    cap: &AbsoluteCapability,
    offset: u64,
    length: u64,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    cache: &CryptreeCache,
) -> Result<Vec<u8>> {
    let root = open_writer_root(cap, &store, mutable).await?;
    let first = fetch_chunk_node_verified(cap, &root, &cap.map_key, &cap.bat, &store, cache)
        .await?
        .ok_or_else(|| Error::Protocol("map key not found in tree".into()))?;
    if first.is_directory() {
        return Err(Error::Protocol("capability points to a directory, not a file".into()));
    }
    let props = first.get_properties(&cap.r_base_key)?;
    if length == 0 || offset >= props.size {
        return Ok(Vec::new());
    }
    let end = (offset + length).min(props.size);
    let chunk_size = retrieve::CHUNK_MAX_SIZE;
    let start_chunk = offset / chunk_size;
    let end_chunk = (end - 1) / chunk_size;

    // Seek to the first overlapping chunk (chunk 0 is already in hand).
    let (mut map_key, mut bat, mut node) = if start_chunk == 0 {
        (cap.map_key.clone(), cap.bat.clone(), first)
    } else {
        let ss = props
            .stream_secret
            .as_ref()
            .ok_or_else(|| Error::Protocol("multi-chunk file without a stream secret".into()))?;
        let (mk, bt) = advance_map_key(ss, &cap.map_key, &cap.bat, start_chunk)?;
        let node = fetch_chunk_node_verified(cap, &root, &mk, &bt, &store, cache)
            .await?
            .ok_or_else(|| Error::Protocol("chunk not found".into()))?;
        (mk, bt, node)
    };

    let mut out = Vec::with_capacity((end - offset) as usize);
    let mut chunk_index = start_chunk;
    loop {
        let data_key = node.get_data_key(&cap.r_base_key)?;
        let chunk_data = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt_bytes(&cap.owner, &data_key, store.as_ref())
            .await?;
        let chunk_start = chunk_index * chunk_size;
        let avail_end = chunk_start + chunk_data.len() as u64;
        let ov_start = offset.max(chunk_start);
        let ov_end = end.min(avail_end);
        if ov_end > ov_start {
            let ls = (ov_start - chunk_start) as usize;
            let le = (ov_end - chunk_start) as usize;
            out.extend_from_slice(&chunk_data[ls..le]);
        }
        if chunk_index == end_chunk {
            break;
        }
        let ss = props
            .stream_secret
            .as_ref()
            .ok_or_else(|| Error::Protocol("multi-chunk file without a stream secret".into()))?;
        let (nmk, nbt) = retrieve::calculate_next_map_key(ss, &map_key, &bat)?;
        map_key = nmk;
        bat = nbt;
        node = fetch_chunk_node_verified(cap, &root, &map_key, &bat, &store, cache)
            .await?
            .ok_or_else(|| Error::Protocol("chunk not found".into()))?;
        chunk_index += 1;
    }
    Ok(out)
}

/// A child entry within a directory listing.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    /// `Some` when the parent recorded the child's type; otherwise unknown
    /// without fetching the child's metadata.
    pub is_dir: Option<bool>,
    pub mime_type: Option<String>,
    /// The absolute read capability for this child.
    pub cap: AbsoluteCapability,
}

/// List the children of a directory capability, following subsequent directory
/// chunks. Mirrors `CryptreeNode.getDirectChildren` + `getAllChildren`.
pub async fn list_directory(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<DirEntry>> {
    list_directory_cached(cap, store, mutable, &CryptreeCache::new()).await
}

pub(crate) async fn list_directory_cached(
    cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    cache: &CryptreeCache,
) -> Result<Vec<DirEntry>> {
    let root = open_writer_root(cap, &store, mutable).await?;
    let mut node = fetch_chunk_node_verified(cap, &root, &cap.map_key, &cap.bat, &store, cache)
        .await?
        .ok_or_else(|| Error::Protocol("map key not found in tree".into()))?;
    if !node.is_directory() {
        return Err(Error::Protocol("capability points to a file, not a directory".into()));
    }

    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(cap.map_key.clone());
    loop {
        // The directory children are encrypted with the read-base key.
        let links_cbor = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt(&cap.owner, &cap.r_base_key, store.as_ref(), |c| Ok(c.clone()))
            .await?;
        match ChildrenLinks::from_cbor(&links_cbor)? {
            ChildrenLinks::Named(named) => {
                for nc in named {
                    entries.push(DirEntry {
                        name: nc.name,
                        is_dir: nc.is_dir,
                        mime_type: nc.mime_type,
                        cap: nc.cap.to_absolute(cap)?,
                    });
                }
            }
            ChildrenLinks::Legacy(legacy) => {
                for rc in legacy {
                    // Legacy links carry no name; expose the cap only.
                    entries.push(DirEntry {
                        name: String::new(),
                        is_dir: None,
                        mime_type: None,
                        cap: rc.to_absolute(cap)?,
                    });
                }
            }
        }

        // Follow this directory's next chunk (dirs don't use a stream secret).
        let (next_map_key, next_bat) = node.next_chunk_from_base(&cap.r_base_key)?;
        if !seen.insert(next_map_key.clone()) {
            break; // guard against cycles
        }
        node = match fetch_chunk_node_verified(cap, &root, &next_map_key, &next_bat, &store, cache).await? {
            Some(n) if n.is_directory() => n,
            _ => break,
        };
    }
    Ok(entries)
}

/// A capability resolved to its cryptree node + decrypted properties
/// (`RetrievedCapability`).
#[derive(Debug, Clone)]
pub struct RetrievedCapability {
    pub cap: AbsoluteCapability,
    pub node: CryptreeNode,
    pub properties: FileProperties,
}

/// Batch-retrieve the cryptree metadata for many capabilities using the server's
/// champ/get API, mirroring `NetworkAccess.retrieveAllMetadata`. Caps are grouped
/// by writer; each writer's caps are looked up in batches of [`MAX_CHAMP_GETS`]
/// (one `champ/get/bulk` call per batch), the returned blocks are hash-verified
/// locally, then each cap is resolved against them (falling back to `store` only
/// for buffered/uncommitted nodes not returned by the lookup). Returns the
/// resolved caps and the list of any that were absent.
///
/// Pair this with [`list_directory`]: it hands back the child capabilities without
/// fetching them, then this resolves them all in a handful of round-trips instead
/// of one per child.
pub async fn retrieve_all_metadata(
    caps: &[AbsoluteCapability],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(Vec<RetrievedCapability>, Vec<AbsoluteCapability>)> {
    retrieve_all_metadata_cached(caps, store, mutable, &CryptreeCache::new()).await
}

pub(crate) async fn retrieve_all_metadata_cached(
    caps: &[AbsoluteCapability],
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    cache: &CryptreeCache,
) -> Result<(Vec<RetrievedCapability>, Vec<AbsoluteCapability>)> {
    // All caps in one champ/get/bulk must share a writer (its champ tree).
    let mut by_writer: std::collections::HashMap<PublicKeyHash, Vec<AbsoluteCapability>> =
        std::collections::HashMap::new();
    for cap in caps {
        by_writer.entry(cap.writer.clone()).or_default().push(cap.clone());
    }
    let mut retrieved = Vec::new();
    let mut absent = Vec::new();
    for (_writer, group) in by_writer {
        let (r, a) = retrieve_all_metadata_single_writer(&group, &store, mutable, cache).await?;
        retrieved.extend(r);
        absent.extend(a);
    }
    Ok((retrieved, absent))
}

async fn retrieve_all_metadata_single_writer(
    links: &[AbsoluteCapability],
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    cache: &CryptreeCache,
) -> Result<(Vec<RetrievedCapability>, Vec<AbsoluteCapability>)> {
    if links.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let owner = links[0].owner.clone();
    let root = open_writer_root(&links[0], store, mutable).await?;

    let mut retrieved = Vec::new();
    let mut absent = Vec::new();

    // Serve cache hits (decrypted nodes) without any network; only miss the rest.
    let mut remaining = Vec::new();
    for l in links {
        match cache.get(&root, &l.map_key) {
            Some(Some(node)) => {
                let properties = node.get_properties(&l.r_base_key)?;
                retrieved.push(RetrievedCapability { cap: l.clone(), node, properties });
            }
            Some(None) => absent.push(l.clone()),
            None => remaining.push(l.clone()),
        }
    }
    if remaining.is_empty() {
        return Ok((retrieved, absent));
    }

    // Fetch the misses' path + value blocks in batches of MAX_CHAMP_GETS, verifying
    // each returned block by re-hashing it as it is loaded into the local store.
    let mut mirrors = Vec::with_capacity(remaining.len());
    for l in &remaining {
        mirrors.push(ChunkMirrorCap::new(l.map_key.clone(), bat_with_id(&l.bat)?));
    }
    let local = Arc::new(RamStorage::new());
    for batch in mirrors.chunks(MAX_CHAMP_GETS) {
        let blocks = store.get_champ_lookup(&owner, &root, batch, None).await?;
        local.load_verified(blocks)?;
    }

    // Resolve each miss against the verified blocks (falling back to the remote
    // store for any buffered nodes the lookup didn't return). One shared champ:
    // all links have the same writer + root.
    let local_cas: Arc<dyn ContentAddressedStorage> = local;
    let combined: Arc<dyn ContentAddressedStorage> =
        Arc::new(FallbackStorage::new(local_cas, store.clone()));
    let champ =
        ChampWrapper::create(owner, root.clone(), None, combined.clone(), identity_key_hasher()).await?;

    for l in &remaining {
        let node = fetch_chunk_node(&champ, l, &l.map_key, &l.bat, combined.as_ref()).await?;
        cache.put(&root, &l.map_key, node.clone());
        match node {
            Some(node) => {
                let properties = node.get_properties(&l.r_base_key)?;
                retrieved.push(RetrievedCapability { cap: l.clone(), node, properties });
            }
            None => absent.push(l.clone()),
        }
    }
    Ok((retrieved, absent))
}

pub(crate) fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub(crate) fn random_symmetric_key() -> Result<SymmetricKey> {
    SymmetricKey::new(random_bytes(32), false)
}

/// Replace the `tree` (champ root) link in a WriterData cbor map.
fn writer_data_with_tree(wd: &CborObject, tree: &Cid) -> Result<CborObject> {
    let mut map = match wd {
        CborObject::Map(m) => m.clone(),
        _ => return Err(Error::Cbor("WriterData is not a map".into())),
    };
    map.insert(peergos_cbor::CborString::new("tree"), CborObject::MerkleLink(tree.to_bytes()));
    Ok(CborObject::Map(map))
}

/// Recover the writer signing keypair from an entry-point directory capability
/// (a dir whose cryptree node carries a `SymmetricLinkToSigner`). Pass the result
/// as `entry_signer` when writing into descendant subdirectories, which share
/// their entry point's writer but hold no writer link of their own.
pub async fn recover_signer(
    entry_cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<SigningPrivateKeyAndPublicHash> {
    let w_base_key = entry_cap
        .w_base_key
        .as_ref()
        .ok_or_else(|| Error::Protocol("entry capability is not writable".into()))?;
    let (node, _props) = retrieve_file_metadata(entry_cap, store, mutable).await?;
    node.get_signer(&entry_cap.r_base_key, w_base_key)
}

/// State held across a directory mutation: an open champ + writer + transaction,
/// so callers can stream child chunks into it before committing.
struct DirWriteContext {
    champ: ChampWrapper,
    signer: SigningPrivateKeyAndPublicHash,
    dir_node: CryptreeNode,
    dir_link: CborObject,
    /// The directory's parent key (for building child `toParent` links).
    dir_parent_key: SymmetricKey,
    wd_cbor: CborObject,
    wd_cid: Cid,
    pointer_sequence: Option<i64>,
    tid: TransactionId,
    /// Account mirror BAT id — tags every child block written during this mutation.
    mirror_bat: Option<BatId>,
}

/// Resolve a writable directory (pointer → WriterData → champ → node + signer)
/// and open a transaction, ready for streaming writes.
async fn begin_dir_write(
    dir_cap: &AbsoluteCapability,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<DirWriteContext> {
    let pointer = mutable
        .get_pointer_target(&dir_cap.owner, &dir_cap.writer, store.as_ref())
        .await?;
    let wd_cid = pointer
        .updated
        .clone()
        .ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let wd_cbor = store
        .get(&dir_cap.owner, &wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("writer data block missing".into()))?;
    let tree_root = Cid::cast(
        wd_cbor
            .get("tree")
            .and_then(|c| c.as_link())
            .ok_or_else(|| Error::Protocol("writer data has no champ tree".into()))?,
    )?;
    let champ = ChampWrapper::create(
        dir_cap.owner.clone(),
        tree_root,
        None,
        store.clone(),
        identity_key_hasher(),
    )
    .await?;
    let dir_link = champ
        .get(&dir_cap.map_key)
        .await?
        .ok_or_else(|| Error::Protocol("directory not found in tree".into()))?;
    let dir_node = fetch_chunk_node(&champ, dir_cap, &dir_cap.map_key, &dir_cap.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol("directory node missing".into()))?;
    if !dir_node.is_directory() {
        return Err(Error::Protocol("capability is not a directory".into()));
    }
    // Use this directory's own writer link if present (entry points), otherwise
    // fall back to the entry-point signer supplied by the caller (subdirs share
    // their entry point's writer).
    let own_signer = dir_cap
        .w_base_key
        .as_ref()
        .and_then(|wb| dir_node.get_signer(&dir_cap.r_base_key, wb).ok());
    let signer = own_signer
        .or(entry_signer)
        .ok_or_else(|| Error::Protocol("no writer available; supply the entry-point signer".into()))?;
    let dir_parent_key = dir_node.base_block(&dir_cap.r_base_key)?.parent_or_data;
    let tid = store.start_transaction(&dir_cap.owner).await?;
    Ok(DirWriteContext {
        champ,
        signer,
        dir_node,
        dir_link,
        dir_parent_key,
        wd_cbor,
        wd_cid,
        pointer_sequence: pointer.sequence,
        tid,
        mirror_bat: mirror_bat.cloned(),
    })
}

/// Write one child cryptree node (fragments first, then the node) and insert it
/// into the champ. Used to stream file chunks / new directory nodes.
async fn put_child_chunk(
    ctx: &mut DirWriteContext,
    owner: &PublicKeyHash,
    store: &Arc<dyn ContentAddressedStorage>,
    map_key: &[u8],
    node_cbor: Vec<u8>,
    fragments: Vec<Vec<u8>>,
) -> Result<()> {
    put_raw_blocks_signed(store.as_ref(), owner, &ctx.signer, fragments, &ctx.tid).await?;
    let cid = put_block_signed(store.as_ref(), owner, &ctx.signer, node_cbor, &ctx.tid).await?;
    ctx.champ
        .put(&ctx.signer, map_key, &None, Some(CborObject::MerkleLink(cid.to_bytes())), &ctx.tid)
        .await?;
    Ok(())
}

/// Append one `child_link` to the directory and commit. Thin wrapper over
/// [`finish_dir_write_multi`].
async fn finish_dir_write(
    ctx: DirWriteContext,
    dir_cap: &AbsoluteCapability,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    child_link: NamedRelativeCapability,
) -> Result<()> {
    finish_dir_write_multi(ctx, dir_cap, store, mutable, vec![child_link]).await
}

/// Append `child_links` to the directory (chunking at MAX_CHILD_LINKS_PER_BLOB,
/// overflowing into fresh dir chunks as needed), then commit ONCE: champ
/// CAS-updates, new WriterData, a single mutable-pointer write, close txn. Adding
/// many links in one call is how `upload_subtree` batches child additions instead
/// of one dir rewrite per file. Mirrors `CryptreeNode.addChildrenAndCommit`.
async fn finish_dir_write_multi(
    ctx: DirWriteContext,
    dir_cap: &AbsoluteCapability,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
    child_links: Vec<NamedRelativeCapability>,
) -> Result<()> {
    let DirWriteContext {
        mut champ,
        signer,
        dir_node,
        dir_link,
        dir_parent_key: _,
        wd_cbor,
        wd_cid,
        pointer_sequence,
        tid,
        mirror_bat,
    } = ctx;
    let mirror_bat = mirror_bat.as_ref();

    struct DirChunk {
        map_key: Vec<u8>,
        node: CryptreeNode,
        children: Vec<NamedRelativeCapability>,
        // `Some` = an existing chunk (champ CAS against this value); `None` = a
        // fresh overflow chunk (champ insert).
        champ_value: Option<CborObject>,
        next_map_key: Vec<u8>,
        next_bat: Option<Bat>,
        modified: bool,
    }
    // 1. Walk the chunk chain, collecting each chunk's direct children.
    let mut dir_chunks: Vec<DirChunk> = Vec::new();
    let mut cursor = Some((dir_cap.map_key.clone(), dir_node, dir_link));
    while let Some((map_key, node, champ_value)) = cursor.take() {
        let decoded = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt(&dir_cap.owner, &dir_cap.r_base_key, store.as_ref(), |c| Ok(c.clone()))
            .await?;
        let children = match ChildrenLinks::from_cbor(&decoded)? {
            ChildrenLinks::Named(v) => v,
            ChildrenLinks::Legacy(_) => {
                return Err(Error::Protocol("legacy directory format not supported for writes".into()))
            }
        };
        let (next_map_key, next_bat) = node.next_chunk_from_base(&dir_cap.r_base_key)?;
        let next = match champ.get(&next_map_key).await? {
            Some(v) => fetch_chunk_node(&champ, dir_cap, &next_map_key, &next_bat, store.as_ref())
                .await?
                .filter(|n| n.is_directory())
                .map(|n| (next_map_key.clone(), n, v)),
            None => None,
        };
        dir_chunks.push(DirChunk {
            map_key,
            node,
            children,
            champ_value: Some(champ_value),
            next_map_key,
            next_bat,
            modified: false,
        });
        cursor = next;
    }

    // The base chunk's parent key + link, needed to build any overflow chunk.
    let parent_key = dir_chunks[0].node.base_block(&dir_cap.r_base_key)?.parent_or_data;
    let parent_link = dir_chunks[0].node.parent_link(&dir_cap.r_base_key)?;
    let max_links = max_child_links_per_blob();

    // 2. Dedup by name across ALL chunks (overwrite existing same-named children).
    let new_names: std::collections::HashSet<&str> = child_links.iter().map(|l| l.name.as_str()).collect();
    for chunk in &mut dir_chunks {
        let before = chunk.children.len();
        chunk.children.retain(|c| !new_names.contains(c.name.as_str()));
        chunk.modified |= chunk.children.len() != before;
    }

    // 3. Add each link to the first chunk with room, else overflow into a fresh
    //    chunk at the current last chunk's next-chunk location (chained onward).
    for link in child_links {
        if let Some(chunk) = dir_chunks.iter_mut().find(|c| c.children.len() < max_links) {
            chunk.children.push(link);
            chunk.modified = true;
        } else {
            let last = dir_chunks.last().unwrap();
            let new_map_key = last.next_map_key.clone();
            let new_bat = last.next_bat.clone();
            // This new chunk gets its own fresh next-chunk location for future growth.
            let next_chunk = RelCap::subsequent_chunk(
                random_bytes(32),
                Some(Bat::new(random_bytes(32))?),
                dir_cap.r_base_key.clone(),
            );
            let next_map_key = next_chunk.map_key.clone();
            let next_bat = next_chunk.bat.clone();
            let from_base = CborObject::map()
                .put("k", parent_key.to_cbor())
                .put("n", next_chunk.to_cbor())
                .build();
            let mut fp = CborObject::map();
            if let Some(p) = &parent_link {
                fp = fp.put("p", p.to_cbor());
            }
            let from_parent = fp.put("s", FileProperties::empty_subsequent_chunk().to_cbor()).build();
            let node = CryptreeNode::new(
                true,
                node_bats_opt(new_bat.as_ref(), mirror_bat)?,
                PaddedCipherText::build(&dir_cap.r_base_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
                PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
                // Placeholder; the real children are re-encrypted at commit below.
                FragmentedPaddedCipherText::build_inline(&dir_cap.r_base_key, &ChildrenLinks::Named(Vec::new()).to_cbor(), MIN_FRAGMENT_SIZE)?.to_cbor(),
            );
            dir_chunks.push(DirChunk {
                map_key: new_map_key,
                node,
                children: vec![link],
                champ_value: None,
                next_map_key,
                next_bat,
                modified: true,
            });
        }
    }

    // 4. Commit every modified/new chunk (existing → CAS, new → insert).
    for chunk in &dir_chunks {
        if !chunk.modified {
            continue;
        }
        let (children_data, fragments) = retrieve::FragmentedPaddedCipherText::build(
            &dir_cap.r_base_key,
            &ChildrenLinks::Named(chunk.children.clone()).to_cbor(),
            MIN_FRAGMENT_SIZE,
            mirror_bat,
        )?;
        put_raw_blocks_signed(store.as_ref(), &dir_cap.owner, &signer, fragments, &tid).await?;
        let new_node = chunk.node.with_children_or_data(children_data.to_cbor());
        let cid = put_block_signed(store.as_ref(), &dir_cap.owner, &signer, new_node.to_cbor().to_bytes(), &tid).await?;
        champ
            .put(&signer, &chunk.map_key, &chunk.champ_value, Some(CborObject::MerkleLink(cid.to_bytes())), &tid)
            .await?;
    }
    let new_tree_root = champ.root_hash().clone();
    let new_wd = writer_data_with_tree(&wd_cbor, &new_tree_root)?;
    let new_wd_cid =
        put_block_signed(store.as_ref(), &dir_cap.owner, &signer, new_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(
        Some(wd_cid),
        Some(new_wd_cid),
        PointerUpdate::increment(pointer_sequence),
    );
    if !mutable.set_pointer_update(&dir_cap.owner, &signer, &update).await? {
        return Err(Error::Protocol("setPointer rejected (concurrent modification?)".into()));
    }
    store.close_transaction(&dir_cap.owner, &tid).await?;
    Ok(())
}

/// Read exactly `buf.len()` bytes from `r`, mapping any error (incl. early EOF).
fn read_exact(r: &mut impl std::io::Read, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| Error::Protocol(format!("read error: {e}")))
}

/// Stream a file of `size` bytes into a writable directory, holding at most one
/// 5 MiB chunk in memory. `open` yields a fresh reader over the same content and
/// is called twice: once to compute the content hash tree, once to encrypt and
/// upload. The thumbnail (if any) goes on chunk 0.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_streaming<R, F>(
    dir_cap: &AbsoluteCapability,
    name: &str,
    size: u64,
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    open: F,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability>
where
    R: std::io::Read,
    F: Fn() -> std::io::Result<R>,
{
    upload_file_streaming_inner(dir_cap, name, size, false, thumbnail, entry_signer, mirror_bat, open, store, mutable).await
}

#[allow(clippy::too_many_arguments)]
async fn upload_file_streaming_inner<R, F>(
    dir_cap: &AbsoluteCapability,
    name: &str,
    size: u64,
    hidden: bool,
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    open: F,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability>
where
    R: std::io::Read,
    F: Fn() -> std::io::Result<R>,
{
    let epoch = now_epoch();
    let file_r_base = random_symmetric_key()?;
    // All chunks share one data key; each chunk still gets its own fresh nonce.
    let file_data_key = loop {
        let k = random_symmetric_key()?;
        if k != file_r_base {
            break k;
        }
    };
    // Files get their own write key so they are writable (deletable/editable) —
    // they share the parent's writer, so the key isn't embedded in the node, only
    // carried in the child link. Without it the file appears read-only.
    let file_w_base = random_symmetric_key()?;
    let stream_secret = random_bytes(32);
    let file_map_key = random_bytes(32);
    let file_bat = Bat::new(random_bytes(32))?;
    let file_cap = AbsoluteCapability::new(
        dir_cap.owner.clone(),
        dir_cap.writer.clone(),
        file_map_key.clone(),
        Some(file_bat.clone()),
        file_r_base.clone(),
        Some(file_w_base.clone()),
    )?;

    let chunk_size = retrieve::CHUNK_MAX_SIZE as usize;
    let n_chunks = if size == 0 { 1 } else { size.div_ceil(chunk_size as u64) as usize };
    let chunk_len = |i: usize| -> usize {
        if i + 1 == n_chunks { (size as usize) - i * chunk_size } else { chunk_size }
    };

    // Pass 1: hash each chunk (streaming) to build the content hash tree, and
    // capture the first header bytes to detect the MIME type.
    let mut reader = open().map_err(|e| Error::Protocol(format!("open error: {e}")))?;
    let mut buf = vec![0u8; chunk_size];
    let mut chunk_hashes = Vec::with_capacity(n_chunks);
    let mut header: Vec<u8> = Vec::new();
    for i in 0..n_chunks {
        let want = chunk_len(i);
        read_exact(&mut reader, &mut buf[..want])?;
        if i == 0 {
            let n = want.min(mimetype::HEADER_BYTES_TO_IDENTIFY_MIME_TYPE);
            header = buf[..n].to_vec();
        }
        chunk_hashes.push(peergos_crypto::hash::sha256(&buf[..want]));
    }
    let tree = hashtree::HashTree::build(&chunk_hashes)?;
    let mime_type = mimetype::calculate_mime_type(&header, name);

    // Pass 2: open the directory transaction, then stream-encrypt + upload chunks.
    let mut ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, &store, mutable).await?;
    let to_parent = RelCap {
        writer: None,
        map_key: dir_cap.map_key.clone(),
        bat: dir_cap.bat.clone(),
        r_base_key: ctx.dir_parent_key.clone(),
        w_base_key_link: None,
    };
    let mut reader = open().map_err(|e| Error::Protocol(format!("open error: {e}")))?;
    let mut thumbnail = thumbnail;
    let mut map_key = file_map_key.clone();
    let mut bat = Some(file_bat.clone());
    for i in 0..n_chunks {
        let want = chunk_len(i);
        read_exact(&mut reader, &mut buf[..want])?;
        let (next_map_key, next_bat) =
            retrieve::calculate_next_map_key(&stream_secret, &map_key, &bat)?;

        let (data, fragments) = retrieve::FragmentedPaddedCipherText::build(
            &file_data_key,
            &CborObject::ByteString(buf[..want].to_vec()),
            MIN_FRAGMENT_SIZE,
            mirror_bat,
        )?;
        let next_chunk =
            RelCap::subsequent_chunk(next_map_key.clone(), next_bat.clone(), file_r_base.clone());
        let from_base = CborObject::map()
            .put("k", file_data_key.to_cbor())
            .put("n", next_chunk.to_cbor())
            .build();
        // Thumbnail on chunk 0; hash-tree branch on the first chunk of each 1024.
        let mut props = FileProperties::new_file(
            name.to_string(),
            mime_type.clone(),
            size,
            epoch,
            stream_secret.clone(),
            if i == 0 { thumbnail.take() } else { None },
        );
        props.is_hidden = hidden;
        if i % 1024 == 0 {
            props.tree_hash = Some(tree.branch(i as u64));
        }
        let from_parent = CborObject::map()
            .put("p", to_parent.to_cbor())
            .put("s", props.to_cbor())
            .build();
        let node = CryptreeNode::new(
            false,
            node_bats_opt(bat.as_ref(), mirror_bat)?,
            PaddedCipherText::build(&file_r_base, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
            PaddedCipherText::build(&file_r_base, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
            data.to_cbor(),
        );
        put_child_chunk(&mut ctx, &dir_cap.owner, &store, &map_key, node.to_cbor().to_bytes(), fragments)
            .await?;
        map_key = next_map_key;
        bat = next_bat;
    }

    // `relativise`: link the parent's write-base key to the file's write key so
    // the file is writable through the directory.
    let w_link = dir_cap
        .w_base_key
        .as_ref()
        .map(|pw| -> Result<CborObject> {
            Ok(peergos_core::symmetric::CipherText::build(pw, &file_w_base)?.to_cbor())
        })
        .transpose()?;
    let child_link = NamedRelativeCapability {
        name: name.to_string(),
        cap: RelCap {
            writer: None,
            map_key: file_map_key,
            bat: Some(file_bat),
            r_base_key: file_r_base,
            w_base_key_link: w_link,
        },
        is_dir: Some(false),
        mime_type: Some(mime_type.clone()),
        created_epoch: Some(epoch),
    };
    finish_dir_write(ctx, dir_cap, &store, mutable, child_link).await?;
    Ok(file_cap)
}

/// Upload a file already in memory. Convenience wrapper over
/// [`upload_file_streaming`] — use that with a file-backed reader to avoid
/// buffering large files.
pub async fn upload_file(
    dir_cap: &AbsoluteCapability,
    name: &str,
    contents: &[u8],
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    #[cfg(feature = "thumbnails")]
    let thumbnail = match thumbnail {
        Some(t) => Some(t),
        None => {
            let mime = crate::mimetype::calculate_mime_type(contents, name);
            crate::thumbnail::generate_thumbnail(contents, &mime)
                .map(|t| t.into_tuple())
        }
    };
    #[cfg(not(feature = "thumbnails"))]
    let thumbnail = thumbnail;
    upload_file_streaming(
        dir_cap,
        name,
        contents.len() as u64,
        thumbnail,
        entry_signer,
        mirror_bat,
        || Ok(std::io::Cursor::new(contents)),
        store,
        mutable,
    )
    .await
}

/// Like [`upload_file`] but marks the file hidden (`is_hidden` / Java's
/// `isHidden`), used for internal system files (`.blocked-usernames.txt`,
/// `.social-state.cbor`, `.annotations`, `.from-friends.cbor`, feed/sharing
/// metadata) that a UI should not surface. Single-chunk only.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_hidden(
    dir_cap: &AbsoluteCapability,
    name: &str,
    contents: &[u8],
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    #[cfg(feature = "thumbnails")]
    let thumbnail = match thumbnail {
        Some(t) => Some(t),
        None => {
            let mime = crate::mimetype::calculate_mime_type(contents, name);
            crate::thumbnail::generate_thumbnail(contents, &mime)
                .map(|t| t.into_tuple())
        }
    };
    #[cfg(not(feature = "thumbnails"))]
    let thumbnail = thumbnail;
    upload_file_streaming_inner(
        dir_cap,
        name,
        contents.len() as u64,
        true,
        thumbnail,
        entry_signer,
        mirror_bat,
        || Ok(std::io::Cursor::new(contents)),
        store,
        mutable,
    )
    .await
}

/// Create an empty subdirectory inside a writable directory, returning its
/// (writable) capability.
/// Create an empty subdirectory `name` under `dir_cap` and return its capability.
pub async fn create_directory(
    dir_cap: &AbsoluteCapability,
    name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    create_directory_inner(dir_cap, name, false, entry_signer, mirror_bat, store, mutable).await
}

/// Like [`create_directory`] but marks the new directory hidden (`is_hidden` /
/// Java's `isSystemFolder`), used for the special signup folders (`shared`,
/// `.transactions`, `.capabilitycache`) that a UI should not surface.
pub async fn mkdir_hidden(
    dir_cap: &AbsoluteCapability,
    name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    create_directory_inner(dir_cap, name, true, entry_signer, mirror_bat, store, mutable).await
}

async fn create_directory_inner(
    dir_cap: &AbsoluteCapability,
    name: &str,
    hidden: bool,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let epoch = now_epoch();
    let sub_r_base = random_symmetric_key()?;
    let sub_parent_key = loop {
        let k = random_symmetric_key()?;
        if k != sub_r_base {
            break k;
        }
    };
    let sub_w_base = random_symmetric_key()?;
    let sub_map_key = random_bytes(32);
    let sub_bat = Bat::new(random_bytes(32))?;
    let sub_cap = AbsoluteCapability::new(
        dir_cap.owner.clone(),
        dir_cap.writer.clone(),
        sub_map_key.clone(),
        Some(sub_bat.clone()),
        sub_r_base.clone(),
        Some(sub_w_base.clone()),
    )?;

    let mut ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, &store, mutable).await?;

    // Build the (empty) subdirectory node: base block encrypted with its rBaseKey,
    // parent block with its parentKey.
    let mut props = FileProperties::new_directory(name.to_string(), epoch);
    props.is_hidden = hidden;
    let parent_cap = RelCap {
        writer: None,
        map_key: dir_cap.map_key.clone(),
        bat: dir_cap.bat.clone(),
        r_base_key: ctx.dir_parent_key.clone(),
        w_base_key_link: None,
    };
    let next_chunk =
        RelCap::subsequent_chunk(random_bytes(32), Some(Bat::new(random_bytes(32))?), sub_r_base.clone());
    let from_base = CborObject::map()
        .put("k", sub_parent_key.to_cbor())
        .put("n", next_chunk.to_cbor())
        .build();
    let from_parent = CborObject::map()
        .put("p", parent_cap.to_cbor())
        .put("s", props.to_cbor())
        .build();
    let empty_children = retrieve::FragmentedPaddedCipherText::build_inline(
        &sub_r_base,
        &ChildrenLinks::Named(Vec::new()).to_cbor(),
        MIN_FRAGMENT_SIZE,
    )?;
    let node = CryptreeNode::new(
        true,
        node_bats(&sub_bat, mirror_bat)?,
        PaddedCipherText::build(&sub_r_base, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
        PaddedCipherText::build(&sub_parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        empty_children.to_cbor(),
    );
    put_child_chunk(&mut ctx, &dir_cap.owner, &store, &sub_map_key, node.to_cbor().to_bytes(), Vec::new())
        .await?;

    // The child link carries a write-key link so the subdir stays writable.
    let w_link = dir_cap
        .w_base_key
        .as_ref()
        .map(|pw| -> Result<CborObject> {
            Ok(peergos_core::symmetric::CipherText::build(pw, &sub_w_base)?.to_cbor())
        })
        .transpose()?;
    let child_link = NamedRelativeCapability {
        name: name.to_string(),
        cap: RelCap {
            writer: None,
            map_key: sub_map_key,
            bat: Some(sub_bat),
            r_base_key: sub_r_base,
            w_base_key_link: w_link,
        },
        is_dir: Some(true),
        mime_type: None,
        created_epoch: Some(epoch),
    };
    finish_dir_write(ctx, dir_cap, &store, mutable, child_link).await?;
    Ok(sub_cap)
}

/// Replace the `owned` (owned-key champ root) link in a WriterData cbor map.
fn writer_data_with_owned(wd: &CborObject, owned: &Cid) -> Result<CborObject> {
    let mut map = match wd {
        CborObject::Map(m) => m.clone(),
        _ => return Err(Error::Cbor("WriterData is not a map".into())),
    };
    map.insert(peergos_cbor::CborString::new("owned"), CborObject::MerkleLink(owned.to_bytes()));
    Ok(CborObject::Map(map))
}

/// Create a subdirectory that lives in its **own writer subspace** (not the
/// parent's), so write access to it can be granted to another user. The new
/// writer is registered as owned by the **parent's writer** (ownership is
/// hierarchical: identity → home writer → this writer), gets its own `WriterData`
/// + pointer, and its cryptree node carries a `SymmetricLinkToSigner` so a holder
/// of the writable capability can recover the signing key. A child link with an
/// explicit `writer` is added to `parent_cap`.
///
/// `parent_cap` must be a writable entry point (e.g. the home directory) whose
/// node carries the parent writer's signing link. Returns the writable capability
/// to the new directory. Internal: the public path is [`move_dir_to_own_writer`].
/// Recover the writer signing key that authorises writes into `parent_cap`. A
/// plain subdirectory shares its parent's writer but carries no signer link on its
/// own node, so fall back to the caller-supplied entry-point signer (mirrors
/// [`begin_dir_write`] / `upload_signer`, and Java's `FileWrapper.signingPair`).
async fn parent_writer_signer(
    parent_cap: &AbsoluteCapability,
    entry_signer: &Option<SigningPrivateKeyAndPublicHash>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<SigningPrivateKeyAndPublicHash> {
    if let Ok(s) = recover_signer(parent_cap, store.clone(), mutable).await {
        return Ok(s);
    }
    entry_signer
        .clone()
        .ok_or_else(|| Error::Protocol("no writer available; supply the entry-point signer".into()))
}

async fn create_writable_shared_dir(
    parent_cap: &AbsoluteCapability,
    name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let epoch = now_epoch();
    let owner = &parent_cap.owner;
    // The parent writer owns the new writer; recover its signing key.
    let parent_writer = parent_writer_signer(parent_cap, &entry_signer, store.clone(), mutable).await?;
    let parent_writer_hash = parent_writer.public_key_hash.clone();

    // A fresh writer keypair with an inline (identity-multihash) key hash.
    let (wpub, wsec64) = peergos_crypto::sign::keypair_from_seed(&random_bytes(32))
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let writer_pub = PublicSigningKey::new(wpub.to_vec());
    let writer_hash = writer_pub.hash()?;
    let writer = SigningPrivateKeyAndPublicHash::new(writer_hash.clone(), SecretSigningKey::new(wsec64.to_vec()));

    // Directory keys/location.
    let dir_r = random_symmetric_key()?;
    let dir_w = loop {
        let k = random_symmetric_key()?;
        if k != dir_r {
            break k;
        }
    };
    let parent_key = loop {
        let k = random_symmetric_key()?;
        if k != dir_r {
            break k;
        }
    };
    let dir_map_key = random_bytes(32);
    let dir_bat = Bat::new(random_bytes(32))?;

    let tid = store.start_transaction(owner).await?;

    // --- 1. Register the new writer as owned by the PARENT WRITER first. The
    // server checks ownership on every block write and pointer set, so this must
    // happen before any block signed by the new writer is uploaded. The proof
    // signs the PARENT WRITER's hash (its owner).
    let pw_pointer = mutable.get_pointer_target(owner, &parent_writer_hash, store.as_ref()).await?;
    let pw_wd_cid = pw_pointer.updated.clone().ok_or_else(|| Error::Protocol("parent writer has no data".into()))?;
    let pw_wd = store
        .get(owner, &pw_wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("parent writer data missing".into()))?;
    let owned_root = Cid::cast(
        pw_wd.get("owned").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("parent writer has no owned champ".into()))?,
    )?;
    let signed_owner = writer.secret.sign_message(&parent_writer_hash.to_cbor().to_bytes())?;
    let owner_proof = CborObject::map()
        .put("o", writer_hash.to_cbor())
        .put("p", CborObject::ByteString(signed_owner))
        .build();
    let proof_cid = put_block_signed(store.as_ref(), owner, &parent_writer, owner_proof.to_bytes(), &tid).await?;
    let mut owned_champ =
        ChampWrapper::create(owner.clone(), owned_root, None, store.clone(), identity_key_hasher()).await?;
    let mut owned_key = writer_hash.to_cbor().to_bytes();
    owned_key.reverse();
    owned_champ
        .put(&parent_writer, &owned_key, &None, Some(CborObject::MerkleLink(proof_cid.to_bytes())), &tid)
        .await?;
    let new_pw_wd = writer_data_with_owned(&pw_wd, owned_champ.root_hash())?;
    let new_pw_wd_cid = put_block_signed(store.as_ref(), owner, &parent_writer, new_pw_wd.to_bytes(), &tid).await?;
    let pw_update = PointerUpdate::new(
        Some(pw_wd_cid),
        Some(new_pw_wd_cid),
        PointerUpdate::increment(pw_pointer.sequence),
    );
    if !mutable.set_pointer_update(owner, &parent_writer, &pw_update).await? {
        return Err(Error::Protocol("parent writer pointer rejected".into()));
    }

    // --- 2. Build the directory node (with a writer link) + the new writer's
    // subspace, now that the writer is authorised to write.
    let writer_link = peergos_core::symmetric::CipherText::build(&dir_w, &writer)?.to_cbor();
    let next_chunk =
        RelCap::subsequent_chunk(random_bytes(32), Some(Bat::new(random_bytes(32))?), dir_r.clone());
    let from_base = CborObject::map()
        .put("k", parent_key.to_cbor())
        .put("w", writer_link)
        .put("n", next_chunk.to_cbor())
        .build();
    let props = FileProperties::new_directory(name.to_string(), epoch);
    // Parent link back to `parent_cap` so the new dir can resolve its path
    // (`getPath` walks up). The new dir has its own writer, so the link names the
    // parent's writer explicitly; its read key is the parent's parent-key.
    let parent_node = retrieve_file_metadata(parent_cap, store.clone(), mutable).await?.0;
    let to_parent = RelCap {
        writer: Some(parent_cap.writer.clone()),
        map_key: parent_cap.map_key.clone(),
        bat: parent_cap.bat.clone(),
        r_base_key: parent_node.get_parent_key(&parent_cap.r_base_key),
        w_base_key_link: None,
    };
    let from_parent = CborObject::map().put("p", to_parent.to_cbor()).put("s", props.to_cbor()).build();
    let empty_children = retrieve::FragmentedPaddedCipherText::build_inline(
        &dir_r,
        &ChildrenLinks::Named(Vec::new()).to_cbor(),
        MIN_FRAGMENT_SIZE,
    )?;
    let node = CryptreeNode::new(
        true,
        node_bats(&dir_bat, mirror_bat)?,
        PaddedCipherText::build(&dir_r, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
        PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        empty_children.to_cbor(),
    );
    let node_cid = put_block_signed(store.as_ref(), owner, &writer, node.to_cbor().to_bytes(), &tid).await?;
    let writer_owned =
        put_block_signed(store.as_ref(), owner, &writer, peergos_core::Champ::empty().serialize(), &tid).await?;
    let fs_empty =
        put_block_signed(store.as_ref(), owner, &writer, peergos_core::Champ::empty().serialize(), &tid).await?;
    let mut fs_champ =
        ChampWrapper::create(owner.clone(), fs_empty, None, store.clone(), identity_key_hasher()).await?;
    fs_champ
        .put(&writer, &dir_map_key, &None, Some(CborObject::MerkleLink(node_cid.to_bytes())), &tid)
        .await?;
    let writer_wd = CborObject::map()
        .put("controller", writer_hash.to_cbor())
        .put("owned", CborObject::MerkleLink(writer_owned.to_bytes()))
        .put("tree", CborObject::MerkleLink(fs_champ.root_hash().to_bytes()))
        .build();
    let writer_wd_cid = put_block_signed(store.as_ref(), owner, &writer, writer_wd.to_bytes(), &tid).await?;
    let writer_update = PointerUpdate::new(None, Some(writer_wd_cid), PointerUpdate::increment(None));
    if !mutable.set_pointer_update(owner, &writer, &writer_update).await? {
        return Err(Error::Protocol("new writer pointer rejected".into()));
    }
    store.close_transaction(owner, &tid).await?;

    // --- 3. Add a child link (with explicit writer) to the parent ------------
    // The rotated directory lives entirely in the new writer subspace. The caller
    // links it into the parent via a link node (see `create_link_node`), so the
    // name is kept in the parent's writer space.
    AbsoluteCapability::new(
        owner.clone(),
        writer_hash,
        dir_map_key,
        Some(dir_bat),
        dir_r,
        Some(dir_w),
    )
}

/// Create a **link node** in `parent_cap`'s writer subspace that points to
/// `target` (which lives in a different writer subspace), and add a child link to
/// the parent naming it. This keeps the name/rename authority in the parent's
/// writer space (`CryptreeNode.createAndCommitLink`): a holder of write access to
/// the target can edit its contents but cannot rename it. Overwrites any existing
/// child with `name`.
#[allow(clippy::too_many_arguments)]
async fn create_link_node(
    parent_cap: &AbsoluteCapability,
    name: &str,
    target: &AbsoluteCapability,
    is_dir: bool,
    mime_type: Option<String>,
    created_epoch: i64,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let link_r = random_symmetric_key()?;
    let link_parent_key = loop {
        let k = random_symmetric_key()?;
        if k != link_r {
            break k;
        }
    };
    let link_w = random_symmetric_key()?;
    let link_map_key = random_bytes(32);
    let link_bat = Bat::new(random_bytes(32))?;

    let mut ctx = begin_dir_write(parent_cap, entry_signer.clone(), mirror_bat, &store, mutable).await?;

    // The link node's single child: a relative cap from the link node to the
    // target (its writer differs, so the writer field is carried), with the
    // target's write key linked through the link node's write-base key.
    let to_target_w = peergos_core::symmetric::CipherText::build(
        &link_w,
        target.w_base_key.as_ref().ok_or_else(|| Error::Protocol("target not writable".into()))?,
    )?
    .to_cbor();
    let to_target = NamedRelativeCapability {
        name: name.to_string(),
        cap: RelCap {
            writer: Some(target.writer.clone()),
            map_key: target.map_key.clone(),
            bat: target.bat.clone(),
            r_base_key: target.r_base_key.clone(),
            w_base_key_link: Some(to_target_w),
        },
        is_dir: Some(is_dir),
        mime_type: mime_type.clone(),
        created_epoch: Some(created_epoch),
    };
    // The link node is a directory node with `is_link` properties whose single
    // child is the target. It has no writer link (it lives in the parent writer).
    let to_parent = RelCap {
        writer: None,
        map_key: parent_cap.map_key.clone(),
        bat: parent_cap.bat.clone(),
        r_base_key: ctx.dir_parent_key.clone(),
        w_base_key_link: None,
    };
    let next_chunk =
        RelCap::subsequent_chunk(random_bytes(32), Some(Bat::new(random_bytes(32))?), link_r.clone());
    let from_base = CborObject::map()
        .put("k", link_parent_key.to_cbor())
        .put("n", next_chunk.to_cbor())
        .build();
    let mut props = FileProperties::new_directory(name.to_string(), created_epoch);
    props.is_link = true;
    let from_parent = CborObject::map()
        .put("p", to_parent.to_cbor())
        .put("s", props.to_cbor())
        .build();
    let (children_data, fragments) = retrieve::FragmentedPaddedCipherText::build(
        &link_r,
        &ChildrenLinks::Named(vec![to_target]).to_cbor(),
        MIN_FRAGMENT_SIZE,
        mirror_bat,
    )?;
    let link_node = CryptreeNode::new(
        true,
        node_bats(&link_bat, mirror_bat)?,
        PaddedCipherText::build(&link_r, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
        PaddedCipherText::build(&link_parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        children_data.to_cbor(),
    );
    put_child_chunk(&mut ctx, &parent_cap.owner, &store, &link_map_key, link_node.to_cbor().to_bytes(), fragments)
        .await?;

    // The parent's child link points at the link node (same writer as parent), so
    // the write cap propagates to whoever can write the parent (for renames).
    let w_link = parent_cap
        .w_base_key
        .as_ref()
        .map(|pw| -> Result<CborObject> { Ok(peergos_core::symmetric::CipherText::build(pw, &link_w)?.to_cbor()) })
        .transpose()?;
    let child_link = NamedRelativeCapability {
        name: name.to_string(),
        cap: RelCap {
            writer: None,
            map_key: link_map_key,
            bat: Some(link_bat),
            r_base_key: link_r,
            w_base_key_link: w_link,
        },
        is_dir: Some(is_dir),
        mime_type,
        created_epoch: Some(created_epoch),
    };
    finish_dir_write(ctx, parent_cap, &store, mutable, child_link).await
}

/// Recursively copy every child of `old_cap` into `new_cap` (which lives in a
/// different writer subspace), re-encrypting under the new keys. Files are read
/// and re-uploaded; subdirectories are recreated (sharing the new writer).
fn copy_dir_contents<'a>(
    old_cap: &'a AbsoluteCapability,
    new_cap: &'a AbsoluteCapability,
    new_signer: &'a SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&'a BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        for e in list_directory(old_cap, store.clone(), mutable).await? {
            if e.is_dir == Some(true) {
                let sub_new =
                    create_directory(new_cap, &e.name, Some(new_signer.clone()), mirror_bat, store.clone(), mutable).await?;
                copy_dir_contents(&e.cap, &sub_new, new_signer, mirror_bat, store.clone(), mutable).await?;
            } else {
                let (props, bytes) = read_file(&e.cap, store.clone(), mutable).await?;
                upload_file(
                    new_cap,
                    &e.name,
                    &bytes,
                    props.thumbnail.clone(),
                    Some(new_signer.clone()),
                    mirror_bat,
                    store.clone(),
                    mutable,
                )
                .await?;
            }
        }
        Ok(())
    })
}

/// Remove an orphaned subtree (whose parent link has already been replaced) from
/// the parent writer's champ, committing the parent directory.
async fn remove_orphaned_subtree(
    parent_cap: &AbsoluteCapability,
    old: &AbsoluteCapability,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut ctx = begin_dir_write(parent_cap, entry_signer, mirror_bat, store, mutable).await?;
    let signer = ctx.signer.clone();
    let loc = ChunkLoc {
        map_key: old.map_key.clone(),
        bat: old.bat.clone(),
        r_base_key: old.r_base_key.clone(),
    };
    remove_all_chunks(&mut ctx.champ, &signer, parent_cap, loc, store, &ctx.tid).await?;
    commit_dir_write(&ctx, parent_cap, store, mutable).await
}

/// Move the directory `child_name` in `parent_cap` into its **own writer
/// subspace** (Peergos `rotateAllKeys`), so write access to it can be granted to
/// another user. If it already has its own writer this is a no-op that returns
/// its writable capability. Otherwise a new writer is created (owned by the
/// parent writer), the subtree is copied under fresh keys, the parent's child
/// link is repointed, and the old subtree is deleted.
///
/// Returns the writable capability to the (possibly rotated) directory.
pub async fn move_dir_to_own_writer(
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let old = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?;
    if !old.cap.is_writable() {
        return Err(Error::Protocol("cannot grant write access without a writable capability".into()));
    }
    if old.is_dir != Some(true) {
        return Err(Error::Protocol(
            "write-sharing currently supports directories; wrap a file in a directory first".into(),
        ));
    }
    let (_n, old_props) = retrieve_file_metadata(&old.cap, store.clone(), mutable).await?;
    // Already write-shared: the child is a link node whose target is in its own
    // writer subspace. Follow it and share the existing keys (no rotation).
    if old_props.is_link {
        let target = list_directory(&old.cap, store.clone(), mutable)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("link node has no target".into()))?
            .cap;
        return Ok(target);
    }
    // Already in its own writer subspace without a link node — share existing keys.
    if old.cap.writer != parent_cap.writer {
        return Ok(old.cap);
    }
    let created = old_props.created_epoch;

    // Create the replacement directory in a fresh writer subspace, copy the old
    // contents across, then link it into the parent via a link node (which repoints
    // the parent's child by name and keeps rename authority in the parent writer),
    // and finally delete the now-orphaned old subtree.
    let new_dir =
        create_writable_shared_dir(parent_cap, child_name, entry_signer.clone(), mirror_bat, store.clone(), mutable).await?;
    let new_signer = recover_signer(&new_dir, store.clone(), mutable).await?;
    copy_dir_contents(&old.cap, &new_dir, &new_signer, mirror_bat, store.clone(), mutable).await?;
    create_link_node(parent_cap, child_name, &new_dir, true, None, created, entry_signer.clone(), mirror_bat, store.clone(), mutable)
        .await?;
    remove_orphaned_subtree(parent_cap, &old.cap, entry_signer, mirror_bat, &store, mutable).await?;
    Ok(new_dir)
}

/// Create a **single-chunk file** in a fresh writer subspace owned by the parent
/// writer, holding `content` under new keys with a writer link (so it is writable),
/// and return its writable capability. The file is NOT yet linked into the parent —
/// the caller adds a link node (see [`move_file_to_own_writer`]). Mirrors the file
/// arm of Java `rotateAllKeys`.
#[allow(clippy::too_many_arguments)]
async fn create_writable_shared_file(
    parent_cap: &AbsoluteCapability,
    name: &str,
    content: &[u8],
    old_props: &FileProperties,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let owner = &parent_cap.owner;
    let parent_writer = parent_writer_signer(parent_cap, &entry_signer, store.clone(), mutable).await?;
    let parent_writer_hash = parent_writer.public_key_hash.clone();

    // A fresh writer keypair (inline identity-multihash hash).
    let (wpub, wsec64) =
        peergos_crypto::sign::keypair_from_seed(&random_bytes(32)).map_err(|e| Error::Crypto(e.to_string()))?;
    let writer_hash = PublicSigningKey::new(wpub.to_vec()).hash()?;
    let writer = SigningPrivateKeyAndPublicHash::new(writer_hash.clone(), SecretSigningKey::new(wsec64.to_vec()));

    // Fresh file keys/location.
    let file_r = random_symmetric_key()?;
    let file_w = loop {
        let k = random_symmetric_key()?;
        if k != file_r {
            break k;
        }
    };
    let file_data_key = loop {
        let k = random_symmetric_key()?;
        if k != file_r {
            break k;
        }
    };
    let file_map_key = random_bytes(32);
    let file_bat = Bat::new(random_bytes(32))?;
    let stream_secret = random_bytes(32);

    let tid = store.start_transaction(owner).await?;

    // --- 1. Register the new writer as owned by the parent writer (must precede
    // any block signed by the new writer).
    let pw_pointer = mutable.get_pointer_target(owner, &parent_writer_hash, store.as_ref()).await?;
    let pw_wd_cid = pw_pointer.updated.clone().ok_or_else(|| Error::Protocol("parent writer has no data".into()))?;
    let pw_wd = store.get(owner, &pw_wd_cid, None).await?.ok_or_else(|| Error::Protocol("parent writer data missing".into()))?;
    let owned_root = Cid::cast(
        pw_wd.get("owned").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("parent writer has no owned champ".into()))?,
    )?;
    let signed_owner = writer.secret.sign_message(&parent_writer_hash.to_cbor().to_bytes())?;
    let owner_proof = CborObject::map()
        .put("o", writer_hash.to_cbor())
        .put("p", CborObject::ByteString(signed_owner))
        .build();
    let proof_cid = put_block_signed(store.as_ref(), owner, &parent_writer, owner_proof.to_bytes(), &tid).await?;
    let mut owned_champ = ChampWrapper::create(owner.clone(), owned_root, None, store.clone(), identity_key_hasher()).await?;
    let mut owned_key = writer_hash.to_cbor().to_bytes();
    owned_key.reverse();
    owned_champ.put(&parent_writer, &owned_key, &None, Some(CborObject::MerkleLink(proof_cid.to_bytes())), &tid).await?;
    let new_pw_wd = writer_data_with_owned(&pw_wd, owned_champ.root_hash())?;
    let new_pw_wd_cid = put_block_signed(store.as_ref(), owner, &parent_writer, new_pw_wd.to_bytes(), &tid).await?;
    let pw_update = PointerUpdate::new(Some(pw_wd_cid), Some(new_pw_wd_cid), PointerUpdate::increment(pw_pointer.sequence));
    if !mutable.set_pointer_update(owner, &parent_writer, &pw_update).await? {
        return Err(Error::Protocol("parent writer pointer rejected".into()));
    }

    // --- 2. Write the file's chunk nodes (writer link on chunk 0) in the new writer.
    let writer_link = peergos_core::symmetric::CipherText::build(&file_w, &writer)?.to_cbor();
    let mime = mimetype::calculate_mime_type(content, name);
    let parent_node = retrieve_file_metadata(parent_cap, store.clone(), mutable).await?.0;
    let to_parent = RelCap {
        writer: Some(parent_cap.writer.clone()),
        map_key: parent_cap.map_key.clone(),
        bat: parent_cap.bat.clone(),
        r_base_key: parent_node.get_parent_key(&parent_cap.r_base_key),
        w_base_key_link: None,
    };
    let chunks = write_file_chunks(
        owner,
        &writer,
        &file_map_key,
        &Some(file_bat.clone()),
        &file_r,
        &file_data_key,
        &stream_secret,
        &to_parent,
        Some(&writer_link),
        name,
        &mime,
        old_props.created_epoch,
        &old_props.thumbnail,
        mirror_bat,
        content,
        &store,
        &tid,
    )
    .await?;

    // --- 3. The new writer's subspace: a champ holding all the file's chunk nodes.
    let writer_owned = put_block_signed(store.as_ref(), owner, &writer, peergos_core::Champ::empty().serialize(), &tid).await?;
    let fs_empty = put_block_signed(store.as_ref(), owner, &writer, peergos_core::Champ::empty().serialize(), &tid).await?;
    let mut fs_champ = ChampWrapper::create(owner.clone(), fs_empty, None, store.clone(), identity_key_hasher()).await?;
    for (mk, cid) in &chunks {
        fs_champ.put(&writer, mk, &None, Some(CborObject::MerkleLink(cid.to_bytes())), &tid).await?;
    }
    let writer_wd = CborObject::map()
        .put("controller", writer_hash.to_cbor())
        .put("owned", CborObject::MerkleLink(writer_owned.to_bytes()))
        .put("tree", CborObject::MerkleLink(fs_champ.root_hash().to_bytes()))
        .build();
    let writer_wd_cid = put_block_signed(store.as_ref(), owner, &writer, writer_wd.to_bytes(), &tid).await?;
    let writer_update = PointerUpdate::new(None, Some(writer_wd_cid), PointerUpdate::increment(None));
    if !mutable.set_pointer_update(owner, &writer, &writer_update).await? {
        return Err(Error::Protocol("new writer pointer rejected".into()));
    }
    store.close_transaction(owner, &tid).await?;

    AbsoluteCapability::new(owner.clone(), writer_hash, file_map_key, Some(file_bat), file_r, Some(file_w))
}

/// Move the file `child_name` in `parent_cap` into its **own writer subspace** so
/// write access to it can be granted (Java `shareWriteAccessWith`/`rotateAllKeys`
/// for a file). No-op returning the writable cap if it already has its own writer;
/// otherwise the file is re-encrypted into a fresh writer, linked into the parent
/// via a link node, and the old chunk removed. Returns the writable capability.
pub async fn move_file_to_own_writer(
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let old = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?;
    if old.is_dir == Some(true) {
        return Err(Error::Protocol("move_file_to_own_writer is for files; use move_dir_to_own_writer".into()));
    }
    if !old.cap.is_writable() {
        return Err(Error::Protocol("cannot grant write access without a writable capability".into()));
    }
    // Already in its own writer subspace — just hand back its writable cap.
    if old.cap.writer != parent_cap.writer {
        return Ok(old.cap);
    }
    let (_node, old_props) = retrieve_file_metadata(&old.cap, store.clone(), mutable).await?;
    // Already write-shared: the child is a link node whose target is in its own
    // writer subspace. Follow it and share the existing keys (no rotation).
    if old_props.is_link {
        let target = list_directory(&old.cap, store.clone(), mutable)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Protocol("link node has no target".into()))?
            .cap;
        return Ok(target);
    }
    let (_props, content) = read_file(&old.cap, store.clone(), mutable).await?;

    let new_cap =
        create_writable_shared_file(parent_cap, child_name, &content, &old_props, entry_signer.clone(), mirror_bat, store.clone(), mutable)
            .await?;
    create_link_node(
        parent_cap,
        child_name,
        &new_cap,
        false,
        Some(old_props.mime_type.clone()),
        old_props.created_epoch,
        entry_signer.clone(),
        mirror_bat,
        store.clone(),
        mutable,
    )
    .await?;
    remove_orphaned_subtree(parent_cap, &old.cap, entry_signer, mirror_bat, &store, mutable).await?;
    Ok(new_cap)
}

/// Remove `writer_to_remove` from `parent_cap`'s writer's owned-key champ
/// (`CryptreeNode.deAuthoriseSigner`): the server will then reject any further
/// writes signed by that key.
async fn deauthorize_writer(
    parent_cap: &AbsoluteCapability,
    writer_to_remove: &PublicKeyHash,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let owner = &parent_cap.owner;
    let parent_writer = parent_writer_signer(parent_cap, &entry_signer, store.clone(), mutable).await?;
    let pw_pointer = mutable.get_pointer_target(owner, &parent_writer.public_key_hash, store.as_ref()).await?;
    let pw_wd_cid = pw_pointer.updated.clone().ok_or_else(|| Error::Protocol("parent writer has no data".into()))?;
    let pw_wd = store
        .get(owner, &pw_wd_cid, None)
        .await?
        .ok_or_else(|| Error::Protocol("parent writer data missing".into()))?;
    let owned_root = Cid::cast(
        pw_wd.get("owned").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("parent writer has no owned champ".into()))?,
    )?;
    let mut owned_champ =
        ChampWrapper::create(owner.clone(), owned_root, None, store.clone(), identity_key_hasher()).await?;
    let mut owned_key = writer_to_remove.to_cbor().to_bytes();
    owned_key.reverse();
    let tid = store.start_transaction(owner).await?;
    let current = owned_champ.get(&owned_key).await?;
    if current.is_none() {
        return Ok(()); // not owned; nothing to do
    }
    owned_champ.remove(&parent_writer, &owned_key, &current, &tid).await?;
    let new_pw_wd = writer_data_with_owned(&pw_wd, owned_champ.root_hash())?;
    let new_pw_wd_cid = put_block_signed(store.as_ref(), owner, &parent_writer, new_pw_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(
        Some(pw_wd_cid),
        Some(new_pw_wd_cid),
        PointerUpdate::increment(pw_pointer.sequence),
    );
    if !mutable.set_pointer_update(owner, &parent_writer, &update).await? {
        return Err(Error::Protocol("deauthorise pointer rejected".into()));
    }
    store.close_transaction(owner, &tid).await?;
    Ok(())
}

/// Delete the account's filesystem (`UserContext.deleteAccount`): null the home
/// writer's mutable pointer and then the identity pointer (CAS to empty, each signed
/// by its own key). Irreversible; leaves the account with no readable data.
pub async fn delete_account(
    identity: &PublicKeyHash,
    identity_signer: &SigningPrivateKeyAndPublicHash,
    home_cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    // Null the home writer FIRST, while the identity's owned-key set still
    // authorises it; then null the identity pointer.
    let home_signer = recover_signer(home_cap, store.clone(), mutable).await?;
    delete_writer_subspace(identity, &home_signer, &store, mutable).await?;
    delete_writer_subspace(identity, identity_signer, &store, mutable).await?;
    Ok(())
}

/// Delete a writer's whole subspace by setting its mutable pointer to empty
/// (`WriterData.commitDeletion`). Must be done while the writer is still
/// authorised. Signed by `writer` (the subspace owner).
async fn delete_writer_subspace(
    owner: &PublicKeyHash,
    writer: &SigningPrivateKeyAndPublicHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let pointer = mutable.get_pointer_target(owner, &writer.public_key_hash, store.as_ref()).await?;
    if pointer.updated.is_none() {
        return Ok(());
    }
    let update = PointerUpdate::new(pointer.updated.clone(), None, PointerUpdate::increment(pointer.sequence));
    mutable.set_pointer_update(owner, writer, &update).await?;
    Ok(())
}

/// Force a write-shared directory (`child_name` in `parent_cap`, already in its
/// own writer subspace behind a link node) into a **fresh** writer subspace,
/// deleting the old one and deauthorising the old writer. This is Peergos
/// `rotateAllKeys` with `rotateSigner=true`, used to revoke write access.
///
/// Returns the new writable capability to the rotated directory.
pub async fn force_rotate_child_to_new_writer(
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    // The parent's child is a link node; follow it to the real (own-writer) target.
    let link = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?;
    let (_n, link_props) = retrieve_file_metadata(&link.cap, store.clone(), mutable).await?;
    if !link_props.is_link {
        return Err(Error::Protocol(
            "child is not write-shared (no link node / own writer)".into(),
        ));
    }
    let old_target = list_directory(&link.cap, store.clone(), mutable)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| Error::Protocol("link node has no target".into()))?
        .cap;
    let old_writer = recover_signer(&old_target, store.clone(), mutable).await?;
    let (_old_meta, old_props) = retrieve_file_metadata(&old_target, store.clone(), mutable).await?;
    let is_dir = old_props.is_directory;
    let created = old_props.created_epoch;

    // Create a fresh writer subspace, copy the old contents across, and relink.
    let new_target = if is_dir {
        let new_dir = create_writable_shared_dir(parent_cap, child_name, entry_signer.clone(), mirror_bat, store.clone(), mutable).await?;
        let new_signer = recover_signer(&new_dir, store.clone(), mutable).await?;
        copy_dir_contents(&old_target, &new_dir, &new_signer, mirror_bat, store.clone(), mutable).await?;
        create_link_node(parent_cap, child_name, &new_dir, true, None, created, entry_signer.clone(), mirror_bat, store.clone(), mutable)
            .await?;
        new_dir
    } else {
        let (props, content) = read_file(&old_target, store.clone(), mutable).await?;
        let mime = props.mime_type.clone();
        let new_file = create_writable_shared_file(
            parent_cap, child_name, &content, &props, entry_signer.clone(), mirror_bat, store.clone(), mutable,
        ).await?;
        create_link_node(parent_cap, child_name, &new_file, false, Some(mime), created, entry_signer.clone(), mirror_bat, store.clone(), mutable)
            .await?;
        new_file
    };

    // Delete the old target subspace (while its writer is still authorised), then
    // remove the orphaned old link node, then deauthorise the old writer.
    delete_writer_subspace(&parent_cap.owner, &old_writer, &store, mutable).await?;
    remove_orphaned_subtree(parent_cap, &link.cap, entry_signer.clone(), mirror_bat, &store, mutable).await?;
    deauthorize_writer(parent_cap, &old_target.writer, entry_signer, store.clone(), mutable).await?;
    Ok(new_target)
}

/// Rotate the symmetric keys of `child_name` in `parent_cap` **in place** (same
/// writer, fresh read/write/map keys), re-encrypting its content and deleting the
/// old copy. This is the read-access rotation of Peergos `rotateAllKeys`
/// (`rotateSigner=false`): any cached capability to the old keys is invalidated.
///
/// Returns the new capability. The child (file or directory) must share the
/// parent's writer (i.e. not already write-shared into its own writer).
pub async fn rotate_child_read_keys(
    parent_cap: &AbsoluteCapability,
    child_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let old = list_directory(parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == child_name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {child_name}")))?;
    if old.cap.writer != parent_cap.writer {
        return Err(Error::Protocol(
            "child has its own writer; use write-access rotation instead".into(),
        ));
    }
    let signer = parent_writer_signer(parent_cap, &entry_signer, store.clone(), mutable).await?;

    let new_cap = if old.is_dir == Some(true) {
        // Re-create the directory under fresh keys (replaces the parent's child
        // link by name), then copy the old subtree across.
        let new_dir = create_directory(parent_cap, child_name, Some(signer.clone()), mirror_bat, store.clone(), mutable).await?;
        copy_dir_contents(&old.cap, &new_dir, &signer, mirror_bat, store.clone(), mutable).await?;
        new_dir
    } else {
        // Re-upload the file's content under fresh keys (replaces the link).
        let (props, bytes) = read_file(&old.cap, store.clone(), mutable).await?;
        upload_file(parent_cap, child_name, &bytes, props.thumbnail, Some(signer.clone()), mirror_bat, store.clone(), mutable)
            .await?
    };
    // Delete the old (now-orphaned) subtree so its old keys grant no access.
    remove_orphaned_subtree(parent_cap, &old.cap, entry_signer, mirror_bat, &store, mutable).await?;
    Ok(new_cap)
}

/// Remove a child link from `dir_cap` **without deleting the child's data**
/// (`CryptreeNode.removeChildren`), returning the removed child's relative cap.
/// Used by move's fast path (the data moves with the child, it isn't deleted).
async fn remove_child_link(
    dir_cap: &AbsoluteCapability,
    name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, &store, mutable).await?;
    let mut chunks = collect_dir_chunks(dir_cap, &ctx, &store).await?;
    let mut modified: Option<usize> = None;
    for (i, (.., children)) in chunks.iter_mut().enumerate() {
        if let Some(pos) = children.iter().position(|c| c.name == name) {
            children.remove(pos);
            modified = Some(i);
            break;
        }
    }
    if let Some(i) = modified {
        let (map_key, node, champ_value, children) = &chunks[i];
        recommit_dir_chunk(&mut ctx, dir_cap, &store, map_key, node, champ_value, children.clone()).await?;
    }
    commit_dir_write(&ctx, dir_cap, &store, mutable).await
}

/// Overwrite the cryptree node at `cap`'s map key with `new_node` (same map key,
/// same writer) and commit. Used by move's fast path to rewrite a moved file's
/// chunk-0 parent link in place.
async fn reupload_node(
    cap: &AbsoluteCapability,
    new_node: &CryptreeNode,
    signer: &SigningPrivateKeyAndPublicHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let owner = &cap.owner;
    let pointer = mutable.get_pointer_target(owner, &cap.writer, store.as_ref()).await?;
    let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let base_wd = store.get(owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let tree_root = Cid::cast(base_wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("no champ tree".into()))?)?;
    let mut champ = ChampWrapper::create(owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?;
    let tid = store.start_transaction(owner).await?;
    let expected = champ.get(&cap.map_key).await?;
    let new_cid = put_block_signed(store.as_ref(), owner, signer, new_node.to_cbor().to_bytes(), &tid).await?;
    champ.put(signer, &cap.map_key, &expected, Some(CborObject::MerkleLink(new_cid.to_bytes())), &tid).await?;
    let new_wd = writer_data_with_tree(&base_wd, champ.root_hash())?;
    let new_wd_cid = put_block_signed(store.as_ref(), owner, signer, new_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
    if !mutable.set_pointer_update(owner, signer, &update).await? {
        return Err(Error::Protocol("node reupload pointer rejected".into()));
    }
    store.close_transaction(owner, &tid).await?;
    Ok(())
}

/// The `bats` list for a cryptree node: the block's own inline BAT (secret embedded)
/// plus — by id, NOT inlined — the account mirror BAT, matching Java (2 BATs per
/// cryptree node / fragment; internal champ + WriterData blocks carry none).
fn node_bats(bat: &Bat, mirror_bat: Option<&BatId>) -> Result<Vec<CborObject>> {
    let mut v = vec![BatId::inline(bat)?.to_cbor()];
    if let Some(m) = mirror_bat {
        v.push(m.to_cbor());
    }
    Ok(v)
}

/// As [`node_bats`] but for an optional block BAT (continuation chunks / children).
fn node_bats_opt(bat: Option<&Bat>, mirror_bat: Option<&BatId>) -> Result<Vec<CborObject>> {
    let mut v: Vec<CborObject> =
        bat.map(|b| BatId::inline(b).map(|id| id.to_cbor())).transpose()?.into_iter().collect();
    if let Some(m) = mirror_bat {
        v.push(m.to_cbor());
    }
    Ok(v)
}

/// Write every chunk node for a file holding `content`, encrypting fragments and
/// nodes into `store` under `signer`, and return `(map_key, node_cid)` per chunk.
/// Chunk map-keys/BATs derive from `first_map_key`/`first_bat` via `stream_secret`;
/// `writer_link` (if any) is embedded in chunk 0's base block for own-writer files.
/// Shared by full-file rewrite ([`rewrite_file_content`]) and own-writer relocation.
#[allow(clippy::too_many_arguments)]
async fn write_file_chunks(
    owner: &PublicKeyHash,
    signer: &SigningPrivateKeyAndPublicHash,
    first_map_key: &[u8],
    first_bat: &Option<Bat>,
    r_base_key: &SymmetricKey,
    data_key: &SymmetricKey,
    stream_secret: &[u8],
    to_parent: &RelCap,
    writer_link: Option<&CborObject>,
    name: &str,
    mime: &str,
    created: i64,
    thumbnail: &Option<(String, Vec<u8>)>,
    mirror_bat: Option<&BatId>,
    content: &[u8],
    store: &Arc<dyn ContentAddressedStorage>,
    tid: &TransactionId,
) -> Result<Vec<(Vec<u8>, Cid)>> {
    let chunk_size = retrieve::CHUNK_MAX_SIZE as usize;
    let n_chunks = if content.is_empty() { 1 } else { content.len().div_ceil(chunk_size) };
    let hashes: Vec<Vec<u8>> = (0..n_chunks)
        .map(|i| peergos_crypto::hash::sha256(&content[i * chunk_size..((i + 1) * chunk_size).min(content.len())]))
        .collect();
    let tree = hashtree::HashTree::build(&hashes)?;

    let mut out = Vec::with_capacity(n_chunks);
    let mut map_key = first_map_key.to_vec();
    let mut bat = first_bat.clone();
    for i in 0..n_chunks {
        let slice = &content[i * chunk_size..((i + 1) * chunk_size).min(content.len())];
        let (next_map_key, next_bat) = retrieve::calculate_next_map_key(stream_secret, &map_key, &bat)?;
        let (data, fragments) = retrieve::FragmentedPaddedCipherText::build(
            data_key,
            &CborObject::ByteString(slice.to_vec()),
            MIN_FRAGMENT_SIZE,
            mirror_bat,
        )?;
        put_raw_blocks_signed(store.as_ref(), owner, signer, fragments, tid).await?;
        let next_chunk = RelCap::subsequent_chunk(next_map_key.clone(), next_bat.clone(), r_base_key.clone());
        let mut fb = CborObject::map().put("k", data_key.to_cbor());
        if i == 0 {
            if let Some(w) = writer_link {
                fb = fb.put("w", w.clone());
            }
        }
        let from_base = fb.put("n", next_chunk.to_cbor()).build();
        let mut props = FileProperties::new_file(
            name.to_string(),
            mime.to_string(),
            content.len() as u64,
            created,
            stream_secret.to_vec(),
            if i == 0 { thumbnail.clone() } else { None },
        );
        if i % 1024 == 0 {
            props.tree_hash = Some(tree.branch(i as u64));
        }
        let from_parent = CborObject::map().put("p", to_parent.to_cbor()).put("s", props.to_cbor()).build();
        let node = CryptreeNode::new(
            false,
            node_bats_opt(bat.as_ref(), mirror_bat)?,
            PaddedCipherText::build(r_base_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
            PaddedCipherText::build(r_base_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
            data.to_cbor(),
        );
        let cid = put_block_signed(store.as_ref(), owner, signer, node.to_cbor().to_bytes(), tid).await?;
        out.push((map_key.clone(), cid));
        map_key = next_map_key;
        bat = next_bat;
    }
    Ok(out)
}

/// Rewrite a file's entire content in place, keeping its capability (any size).
/// Re-encrypts all chunks under the file's existing keys at their existing map-keys
/// (preserved via the stream secret), removes any now-surplus trailing chunks, and
/// commits in one pointer update. The content hash-tree is recomputed for the new
/// content. Backs multi-chunk `truncate`/`append`.
pub async fn rewrite_file_content(
    cap: &AbsoluteCapability,
    new_content: &[u8],
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (node, old_props) = retrieve_file_metadata(cap, store.clone(), mutable).await?;
    if node.is_directory() {
        return Err(Error::Protocol("cannot rewrite a directory".into()));
    }
    let r_base = &cap.r_base_key;
    let base = node.base_block(r_base)?;
    let data_key = node.get_data_key(r_base)?;
    let writer_link = base.signer.clone();
    let to_parent = node.parent_link(r_base)?.ok_or_else(|| Error::Protocol("file has no parent link".into()))?;
    let stream_secret = old_props
        .stream_secret
        .clone()
        .ok_or_else(|| Error::Protocol("file without a stream secret".into()))?;
    let old_n = chunk_count(old_props.size);

    let owner = &cap.owner;
    let pointer = mutable.get_pointer_target(owner, &cap.writer, store.as_ref()).await?;
    let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let wd = store.get(owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let tree_root = Cid::cast(wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("no champ tree".into()))?)?;
    let mut champ = ChampWrapper::create(owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?;
    let tid = store.start_transaction(owner).await?;

    let new_chunks = write_file_chunks(
        owner,
        signer,
        &cap.map_key,
        &cap.bat,
        r_base,
        &data_key,
        &stream_secret,
        &to_parent,
        writer_link.as_ref(),
        &old_props.name,
        &old_props.mime_type,
        old_props.created_epoch,
        &old_props.thumbnail,
        mirror_bat,
        new_content,
        &store,
        &tid,
    )
    .await?;
    let new_n = new_chunks.len() as u64;
    for (mk, cid) in &new_chunks {
        let expected = champ.get(mk).await?;
        champ.put(signer, mk, &expected, Some(CborObject::MerkleLink(cid.to_bytes())), &tid).await?;
    }
    // Drop trailing chunks that the shorter new content no longer needs.
    let mut mk = cap.map_key.clone();
    let mut bat = cap.bat.clone();
    for i in 0..old_n {
        if i >= new_n {
            let expected = champ.get(&mk).await?;
            if expected.is_some() {
                champ.remove(signer, &mk, &expected, &tid).await?;
            }
        }
        let (nmk, nbat) = retrieve::calculate_next_map_key(&stream_secret, &mk, &bat)?;
        mk = nmk;
        bat = nbat;
    }

    let new_wd = writer_data_with_tree(&wd, champ.root_hash())?;
    let new_wd_cid = put_block_signed(store.as_ref(), owner, signer, new_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
    if !mutable.set_pointer_update(owner, signer, &update).await? {
        return Err(Error::Protocol("file rewrite pointer rejected (concurrent modification?)".into()));
    }
    store.close_transaction(owner, &tid).await?;
    Ok(())
}

/// Overwrite a **single-chunk** file's content in place, keeping its capability
/// (Java `FileWrapper.overwriteFile`): same owner/writer/map-key/keys, only the
/// data + size change. Used by comment merging so a post's cap stays stable.
pub async fn overwrite_file(
    cap: &AbsoluteCapability,
    new_content: &[u8],
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    // Now a thin wrapper over the any-size in-place rewrite.
    rewrite_file_content(cap, new_content, signer, mirror_bat, store, mutable).await
}

/// Overwrite the bytes `[offset, offset+data.len())` of a file **in place**, fetching
/// and re-encrypting only the chunk(s) that overlap the range — not the whole file.
/// The write must stay within the current file size (it does not grow the file); the
/// capability, keys, size and per-chunk links are all preserved, only the affected
/// chunks' data blocks change. Mirrors Java's `overwriteSection` for a partial range
/// (which, like this, leaves the content hash-tree untouched — `updateTreeHash` is
/// false unless the whole file is rewritten).
/// Returns the map-keys of the chunks that were rewritten (so a caller can update a
/// cryptree-node cache — those specific nodes changed, everything else is unchanged).
pub async fn overwrite_file_section(
    cap: &AbsoluteCapability,
    offset: u64,
    data: &[u8],
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<Vec<u8>>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let root = open_writer_root(cap, &store, mutable).await?;
    let cache = CryptreeCache::new();
    let first = fetch_chunk_node_verified(cap, &root, &cap.map_key, &cap.bat, &store, &cache)
        .await?
        .ok_or_else(|| Error::Protocol("map key not found in tree".into()))?;
    if first.is_directory() {
        return Err(Error::Protocol("cannot overwrite a directory".into()));
    }
    let props = first.get_properties(&cap.r_base_key)?;
    let end = offset + data.len() as u64;
    if end > props.size {
        return Err(Error::Protocol(
            "overwrite_file_section cannot grow the file; the range must lie within the current size".into(),
        ));
    }
    let chunk_size = retrieve::CHUNK_MAX_SIZE;
    let start_chunk = offset / chunk_size;
    let end_chunk = (end - 1) / chunk_size;

    let (mut map_key, mut bat, mut node) = if start_chunk == 0 {
        (cap.map_key.clone(), cap.bat.clone(), first)
    } else {
        let ss = props
            .stream_secret
            .as_ref()
            .ok_or_else(|| Error::Protocol("multi-chunk file without a stream secret".into()))?;
        let (mk, bt) = advance_map_key(ss, &cap.map_key, &cap.bat, start_chunk)?;
        let node = fetch_chunk_node_verified(cap, &root, &mk, &bt, &store, &cache)
            .await?
            .ok_or_else(|| Error::Protocol("chunk not found".into()))?;
        (mk, bt, node)
    };

    // Splice the new bytes into each overlapping chunk, re-encrypting with that
    // chunk's own (unchanged) data key and keeping its base/parent blocks.
    let mut updates: Vec<(Vec<u8>, CryptreeNode, Vec<Vec<u8>>)> = Vec::new();
    let mut chunk_index = start_chunk;
    loop {
        let data_key = node.get_data_key(&cap.r_base_key)?;
        let mut chunk_data = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt_bytes(&cap.owner, &data_key, store.as_ref())
            .await?;
        let chunk_start = chunk_index * chunk_size;
        let avail_end = chunk_start + chunk_data.len() as u64;
        let ov_start = offset.max(chunk_start);
        let ov_end = end.min(avail_end);
        if ov_end > ov_start {
            let ls = (ov_start - chunk_start) as usize;
            let src = (ov_start - offset) as usize;
            let n = (ov_end - ov_start) as usize;
            chunk_data[ls..ls + n].copy_from_slice(&data[src..src + n]);
        }
        let (fpct, fragments) = FragmentedPaddedCipherText::build(
            &data_key,
            &CborObject::ByteString(chunk_data),
            MIN_FRAGMENT_SIZE,
            mirror_bat,
        )?;
        // Rebuild the chunk clearing the content hash-tree branch (Java removes the
        // hash on a partial write) and bumping the modified time; the base block
        // (data key + writer link + next-chunk) is preserved.
        let new_node = node.overwrite_chunk_data(&cap.r_base_key, fpct.to_cbor(), now_epoch())?;
        updates.push((map_key.clone(), new_node, fragments));
        if chunk_index == end_chunk {
            break;
        }
        let ss = props
            .stream_secret
            .as_ref()
            .ok_or_else(|| Error::Protocol("multi-chunk file without a stream secret".into()))?;
        let (nmk, nbt) = retrieve::calculate_next_map_key(ss, &map_key, &bat)?;
        map_key = nmk;
        bat = nbt;
        node = fetch_chunk_node_verified(cap, &root, &map_key, &bat, &store, &cache)
            .await?
            .ok_or_else(|| Error::Protocol("chunk not found".into()))?;
        chunk_index += 1;
    }

    let changed: Vec<Vec<u8>> = updates.iter().map(|(k, _, _)| k.clone()).collect();
    reupload_nodes(cap, updates, signer, &store, mutable).await?;
    Ok(changed)
}

/// Re-put several `(map_key, node)` pairs into the writer's champ in a single
/// pointer update (a multi-node [`reupload_node`]), uploading each node's fragments.
async fn reupload_nodes(
    cap: &AbsoluteCapability,
    updates: Vec<(Vec<u8>, CryptreeNode, Vec<Vec<u8>>)>,
    signer: &SigningPrivateKeyAndPublicHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let owner = &cap.owner;
    let pointer = mutable.get_pointer_target(owner, &cap.writer, store.as_ref()).await?;
    let wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let base_wd = store.get(owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let tree_root = Cid::cast(base_wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("no champ tree".into()))?)?;
    let mut champ = ChampWrapper::create(owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?;
    let tid = store.start_transaction(owner).await?;
    for (map_key, node, fragments) in updates {
        if !fragments.is_empty() {
            put_raw_blocks_signed(store.as_ref(), owner, signer, fragments, &tid).await?;
        }
        let expected = champ.get(&map_key).await?;
        let new_cid = put_block_signed(store.as_ref(), owner, signer, node.to_cbor().to_bytes(), &tid).await?;
        champ.put(signer, &map_key, &expected, Some(CborObject::MerkleLink(new_cid.to_bytes())), &tid).await?;
    }
    let new_wd = writer_data_with_tree(&base_wd, champ.root_hash())?;
    let new_wd_cid = put_block_signed(store.as_ref(), owner, signer, new_wd.to_bytes(), &tid).await?;
    let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
    if !mutable.set_pointer_update(owner, signer, &update).await? {
        return Err(Error::Protocol("section overwrite pointer rejected (concurrent modification?)".into()));
    }
    store.close_transaction(owner, &tid).await?;
    Ok(())
}

/// The metadata-only fast path of [`move_to`] (target & source share a writer):
/// rewrite the child's chunk-0 parent link to point at the target, add the child
/// link to the target, and remove it from the source. No data is re-encrypted, so
/// the child's capability is unchanged and existing shares keep working.
async fn move_fast_path(
    source_parent: &AbsoluteCapability,
    target_dir: &AbsoluteCapability,
    target_node: &CryptreeNode,
    child: &DirEntry,
    name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let different_writer = child.cap.writer != target_dir.writer;

    // 1. Rewrite the child's chunk-0 node with a parent link to the target.
    let child_champ = open_writer_champ(&child.cap, store.clone(), mutable).await?;
    let child_node = fetch_chunk_node(&child_champ, &child.cap, &child.cap.map_key, &child.cap.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol("child node missing".into()))?;
    let parent_key = child_node.get_parent_key(&child.cap.r_base_key);
    let props = child_node.get_properties(&child.cap.r_base_key)?;
    let target_parent_key = target_node.get_parent_key(&target_dir.r_base_key);
    let new_parent_link = RelCap {
        writer: if different_writer { Some(target_dir.writer.clone()) } else { None },
        map_key: target_dir.map_key.clone(),
        bat: target_dir.bat.clone(),
        r_base_key: target_parent_key,
        w_base_key_link: None,
    };
    let from_parent = CborObject::map().put("p", new_parent_link.to_cbor()).put("s", props.to_cbor()).build();
    let new_node = CryptreeNode::new(
        child_node.is_directory(),
        child_node.bats.clone(),
        child_node.from_base_key.clone(),
        PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        child_node.children_or_data.clone(),
    );
    let child_signer = recover_signer(&child.cap, store.clone(), mutable)
        .await
        .ok()
        .or_else(|| entry_signer.clone())
        .ok_or_else(|| Error::Protocol("no signer for child writer".into()))?;
    reupload_node(&child.cap, &new_node, &child_signer, &store, mutable).await?;

    // 2. Add the child link to the target directory (`relativise`).
    let w_link = match (&target_dir.w_base_key, &child.cap.w_base_key) {
        (Some(pw), Some(cw)) => Some(peergos_core::symmetric::CipherText::build(pw, cw)?.to_cbor()),
        _ => None,
    };
    let child_link = NamedRelativeCapability {
        name: name.to_string(),
        cap: RelCap {
            writer: if different_writer { Some(child.cap.writer.clone()) } else { None },
            map_key: child.cap.map_key.clone(),
            bat: child.cap.bat.clone(),
            r_base_key: child.cap.r_base_key.clone(),
            w_base_key_link: w_link,
        },
        is_dir: child.is_dir,
        mime_type: child.mime_type.clone(),
        created_epoch: Some(props.created_epoch),
    };
    let ctx = begin_dir_write(target_dir, entry_signer.clone(), mirror_bat, &store, mutable).await?;
    finish_dir_write(ctx, target_dir, &store, mutable, child_link).await?;

    // 3. Remove the child link from the source (data stays in place).
    remove_child_link(source_parent, name, entry_signer, mirror_bat, store, mutable).await
}

/// Copy `child` into `target_dir` under `target_name`, re-encrypting under fresh
/// keys (`copyTo`). For a directory this recurses; for a file it re-uploads.
async fn copy_into(
    target_dir: &AbsoluteCapability,
    child: &DirEntry,
    target_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let signer = recover_signer(target_dir, store.clone(), mutable)
        .await
        .ok()
        .or(entry_signer)
        .ok_or_else(|| Error::Protocol("no writer signer for target".into()))?;
    if child.is_dir == Some(true) {
        let new_dir = create_directory(target_dir, target_name, Some(signer.clone()), mirror_bat, store.clone(), mutable).await?;
        copy_dir_contents(&child.cap, &new_dir, &signer, mirror_bat, store.clone(), mutable).await?;
        Ok(new_dir)
    } else {
        let (props, bytes) = read_file(&child.cap, store.clone(), mutable).await?;
        upload_file(target_dir, target_name, &bytes, props.thumbnail, Some(signer), mirror_bat, store, mutable).await
    }
}

/// Pick a copy name that doesn't clash in `target_dir` (`pickUniqueCopyName`):
/// `name`, then `base (copy).ext`, then `base (copy 2).ext`, …
async fn pick_unique_copy_name(
    target_dir: &AbsoluteCapability,
    original: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<String> {
    let existing: std::collections::HashSet<String> =
        list_directory(target_dir, store, mutable).await?.into_iter().map(|e| e.name).collect();
    let (base, ext) = match original.rfind('.') {
        Some(dot) if dot > 0 && dot < original.len() - 1 => (&original[..dot], &original[dot..]),
        _ => (original, ""),
    };
    let mut n = 0;
    loop {
        let candidate = match n {
            0 => format!("{base}{ext}"),
            1 => format!("{base} (copy){ext}"),
            _ => format!("{base} (copy {n}){ext}"),
        };
        if !existing.contains(&candidate) {
            return Ok(candidate);
        }
        n += 1;
    }
}

/// Copy `name` from `source_parent_cap` into `target_dir_cap` (`FileWrapper.copyTo`):
/// the file/dir is re-encrypted under fresh keys in the target, keeping the
/// original in place. A clashing name gets a unique "(copy)" suffix. Returns the
/// new capability.
pub async fn copy_to(
    source_parent_cap: &AbsoluteCapability,
    name: &str,
    target_dir_cap: &AbsoluteCapability,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    if !target_dir_cap.is_writable() {
        return Err(Error::Protocol("copy requires write access to the target".into()));
    }
    let (_n, target_props) = retrieve_file_metadata(target_dir_cap, store.clone(), mutable).await?;
    if !target_props.is_directory {
        return Err(Error::Protocol("copy target must be a directory".into()));
    }
    let child = list_directory(source_parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {name}")))?;
    let unique = pick_unique_copy_name(target_dir_cap, name, store.clone(), mutable).await?;
    copy_into(target_dir_cap, &child, &unique, entry_signer, mirror_bat, store, mutable).await
}

/// Is `candidate` the same as, or a descendant of, the subtree rooted at `root`?
/// (Match by writer + map key.) Used to prevent moving a folder into itself.
fn is_within_subtree<'a>(
    root: &'a AbsoluteCapability,
    candidate: &'a AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + 'a>> {
    Box::pin(async move {
        if root.writer == candidate.writer && root.map_key == candidate.map_key {
            return Ok(true);
        }
        let (_n, props) = retrieve_file_metadata(root, store.clone(), mutable).await?;
        if !props.is_directory {
            return Ok(false);
        }
        for e in list_directory(root, store.clone(), mutable).await? {
            if is_within_subtree(&e.cap, candidate, store.clone(), mutable).await? {
                return Ok(true);
            }
        }
        Ok(false)
    })
}

/// Move `name` from `source_parent_cap` into `target_dir_cap`. Faithful port of
/// `FileWrapper.moveTo`, with the same optimisation:
///
/// - **Fast path** (target and source share a writer): only metadata moves — the
///   child's chunk-0 parent link is rewritten, the child link is added to the
///   target and removed from the source. The file data stays in place with the
///   same keys, so the child's capability is unchanged and existing shares to it
///   keep working. Returns the (unchanged) capability.
/// - **Slow path** (different writers, **or `keep_access == false`**): the subtree
///   is copied into the target under fresh keys (`copyTo`) and the old one
///   deleted. Returns the new cap. Shares to the old cap do not follow — pass
///   `keep_access = false` to deliberately drop shares on a same-writer move.
pub async fn move_to(
    source_parent_cap: &AbsoluteCapability,
    name: &str,
    target_dir_cap: &AbsoluteCapability,
    keep_access: bool,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    if !target_dir_cap.is_writable() || !source_parent_cap.is_writable() {
        return Err(Error::Protocol("move requires write access to both directories".into()));
    }
    let (target_node, target_props) = retrieve_file_metadata(target_dir_cap, store.clone(), mutable).await?;
    if !target_props.is_directory {
        return Err(Error::Protocol("move target must be a directory".into()));
    }
    if list_directory(target_dir_cap, store.clone(), mutable).await?.iter().any(|e| e.name == name) {
        return Err(Error::Protocol(format!("target already has a child named '{name}'")));
    }
    let child = list_directory(source_parent_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == name)
        .ok_or_else(|| Error::Protocol(format!("no such child: {name}")))?;
    // Guard against moving a folder into itself or one of its descendants
    // (`targetPath.startsWith(ourPath)` in Java) — that would orphan the subtree.
    if child.is_dir == Some(true)
        && is_within_subtree(&child.cap, target_dir_cap, store.clone(), mutable).await?
    {
        return Err(Error::Protocol("cannot move a folder into itself or a descendant".into()));
    }

    // Fast path only when keeping access AND the target shares the source's writer.
    if keep_access && target_dir_cap.writer == source_parent_cap.writer {
        move_fast_path(source_parent_cap, target_dir_cap, &target_node, &child, name, entry_signer, mirror_bat, store, mutable)
            .await?;
        Ok(child.cap)
    } else {
        let new_cap = copy_into(target_dir_cap, &child, name, entry_signer.clone(), mirror_bat, store.clone(), mutable).await?;
        delete_child(source_parent_cap, name, entry_signer, mirror_bat, store, mutable).await?;
        Ok(new_cap)
    }
}

/// The location of a chunk within the writer's champ (map-key + BAT + read key).
struct ChunkLoc {
    map_key: Vec<u8>,
    bat: Option<Bat>,
    r_base_key: SymmetricKey,
}

/// `ceil(size / CHUNK_MAX_SIZE)`, at least one (`FileProperties.chunkCount`).
fn chunk_count(size: u64) -> u64 {
    size.div_ceil(retrieve::CHUNK_MAX_SIZE).max(1)
}

/// Remove a champ entry for `map_key` (CAS on its current value), if present.
async fn champ_remove_entry(
    champ: &mut ChampWrapper,
    signer: &SigningPrivateKeyAndPublicHash,
    map_key: &[u8],
    tid: &TransactionId,
) -> Result<()> {
    if let Some(current) = champ.get(map_key).await? {
        champ.remove(signer, map_key, &Some(current), tid).await?;
    }
    Ok(())
}

/// Recursively delete every cryptree chunk reachable from `loc` (a file's chunk
/// chain, or a directory and all its descendants), removing each from the champ.
/// Mirrors `FileWrapper.deleteAllChunks` (bottom-up for directories).
#[allow(clippy::too_many_arguments)]
fn remove_all_chunks<'a>(
    champ: &'a mut ChampWrapper,
    signer: &'a SigningPrivateKeyAndPublicHash,
    dir_cap: &'a AbsoluteCapability,
    loc: ChunkLoc,
    store: &'a Arc<dyn ContentAddressedStorage>,
    tid: &'a TransactionId,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        // A minimal capability used only to fetch the node (owner + BAT + key).
        let cap = AbsoluteCapability::new(
            dir_cap.owner.clone(),
            dir_cap.writer.clone(),
            loc.map_key.clone(),
            loc.bat.clone(),
            loc.r_base_key.clone(),
            None,
        )?;
        let node = match fetch_chunk_node(champ, &cap, &loc.map_key, &loc.bat, store.as_ref()).await? {
            Some(n) => n,
            None => return Ok(()),
        };
        let props = node.get_properties(&loc.r_base_key)?;

        if !node.is_directory() {
            // A file: walk its chunk chain and remove every chunk.
            if let Some(stream_secret) = &props.stream_secret {
                let n = chunk_count(props.size);
                let mut map_key = loc.map_key.clone();
                let mut bat = loc.bat.clone();
                for i in 0..n {
                    champ_remove_entry(champ, signer, &map_key, tid).await?;
                    if i + 1 < n {
                        let (nmk, nbat) =
                            retrieve::calculate_next_map_key(stream_secret, &map_key, &bat)?;
                        map_key = nmk;
                        bat = nbat;
                    }
                }
            } else {
                champ_remove_entry(champ, signer, &loc.map_key, tid).await?;
            }
            return Ok(());
        }

        // A directory: for each chunk, delete its children (recursively) first,
        // then remove the chunk itself.
        let mut cursor = Some((loc.map_key.clone(), node));
        while let Some((map_key, node)) = cursor.take() {
            let decoded = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
                .get_and_decrypt(&dir_cap.owner, &loc.r_base_key, store.as_ref(), |c| Ok(c.clone()))
                .await?;
            if let ChildrenLinks::Named(children) = ChildrenLinks::from_cbor(&decoded)? {
                for child in children {
                    remove_all_chunks(
                        champ,
                        signer,
                        dir_cap,
                        ChunkLoc {
                            map_key: child.cap.map_key.clone(),
                            bat: child.cap.bat.clone(),
                            r_base_key: child.cap.r_base_key.clone(),
                        },
                        store,
                        tid,
                    )
                    .await?;
                }
            }
            // The next directory chunk (dir chunks share the base read key).
            let (next_map_key, next_bat) = node.next_chunk_from_base(&loc.r_base_key)?;
            let next = if champ.get(&next_map_key).await?.is_some() {
                fetch_chunk_node(champ, &cap, &next_map_key, &next_bat, store.as_ref())
                    .await?
                    .filter(|n| n.is_directory())
                    .map(|n| (next_map_key.clone(), n))
            } else {
                None
            };
            champ_remove_entry(champ, signer, &map_key, tid).await?;
            cursor = next;
        }
        Ok(())
    })
}

/// Recursively collect every own-writer subspace reachable under `cap` (crossing
/// link nodes at every level), in pre-order (a parent writer before its children).
/// `owned_by_parent` is true while still within the original parent writer's space:
/// such own-writers are pushed to `first_level` (they must be deauthorised from
/// that writer), whereas deeper ones are owned by an own-writer that is itself
/// being nulled. Every own-writer target is pushed to `to_null`.
fn collect_own_writer_targets<'a>(
    cap: &'a AbsoluteCapability,
    owned_by_parent: bool,
    to_null: &'a mut Vec<AbsoluteCapability>,
    first_level: &'a mut Vec<PublicKeyHash>,
    store: &'a Arc<dyn ContentAddressedStorage>,
    mutable: &'a dyn MutablePointers,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let (_n, props) = retrieve_file_metadata(cap, store.clone(), mutable).await?;
        if props.is_link {
            // A link node: its single child is the target in its own writer subspace.
            let target = list_directory(cap, store.clone(), mutable)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| Error::Protocol("link node has no target".into()))?
                .cap;
            if owned_by_parent {
                first_level.push(target.writer.clone());
            }
            to_null.push(target.clone());
            // The target's own children are owned by the target writer, not the parent.
            collect_own_writer_targets(&target, false, to_null, first_level, store, mutable).await?;
        } else if props.is_directory {
            // A same-writer directory: its children share this writer's ownership.
            for e in list_directory(cap, store.clone(), mutable).await? {
                collect_own_writer_targets(&e.cap, owned_by_parent, to_null, first_level, store, mutable).await?;
            }
        }
        Ok(())
    })
}

/// Delete a child (file or directory) by name from a writable directory. The
/// child link is removed from the parent and all of the child's cryptree chunks
/// are removed from the writer's champ. Mirrors `FileWrapper.remove`.
pub async fn delete_child(
    dir_cap: &AbsoluteCapability,
    name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    // A write-shared file/dir is a link node here pointing to a target in its OWN
    // writer subspace; deleting only the link node would leak that whole subspace.
    // Reclaim every own-writer subspace in the subtree being deleted, regardless of
    // nesting: collect them, null their pointers deepest-FIRST (a writer must be
    // nulled while its owner still authorises it — like Java's leaf-to-root delete),
    // and deauthorise the first-level ones from this directory's writer afterwards.
    let child_cap = list_directory(dir_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == name)
        .map(|e| e.cap);
    let (mut to_null, first_level) = match &child_cap {
        Some(cc) => {
            let mut to_null = Vec::new();
            let mut first_level = Vec::new();
            collect_own_writer_targets(cc, true, &mut to_null, &mut first_level, &store, mutable).await?;
            (to_null, first_level)
        }
        None => (Vec::new(), Vec::new()),
    };
    let deauth_signer = entry_signer.clone();
    // Discovery is parent-before-child (pre-order); reverse so descendants are
    // nulled before their owning writer.
    to_null.reverse();
    for target in &to_null {
        let target_signer = recover_signer(target, store.clone(), mutable).await?;
        delete_writer_subspace(&dir_cap.owner, &target_signer, &store, mutable).await?;
    }

    let mut ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, &store, mutable).await?;

    // Walk the directory chunk chain, collecting each chunk's children.
    struct DirChunk {
        map_key: Vec<u8>,
        node: CryptreeNode,
        champ_value: CborObject,
        children: Vec<NamedRelativeCapability>,
        modified: bool,
    }
    let mut dir_chunks: Vec<DirChunk> = Vec::new();
    let mut cursor = Some((dir_cap.map_key.clone(), ctx.dir_node.clone(), ctx.dir_link.clone()));
    while let Some((map_key, node, champ_value)) = cursor.take() {
        let decoded = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt(&dir_cap.owner, &dir_cap.r_base_key, store.as_ref(), |c| Ok(c.clone()))
            .await?;
        let children = match ChildrenLinks::from_cbor(&decoded)? {
            ChildrenLinks::Named(v) => v,
            ChildrenLinks::Legacy(_) => {
                return Err(Error::Protocol("legacy directory format not supported for deletes".into()))
            }
        };
        let (next_map_key, next_bat) = node.next_chunk_from_base(&dir_cap.r_base_key)?;
        let next = match ctx.champ.get(&next_map_key).await? {
            Some(v) => fetch_chunk_node(&ctx.champ, dir_cap, &next_map_key, &next_bat, store.as_ref())
                .await?
                .filter(|n| n.is_directory())
                .map(|n| (next_map_key.clone(), n, v)),
            None => None,
        };
        dir_chunks.push(DirChunk { map_key, node, champ_value, children, modified: false });
        cursor = next;
    }

    // Find the named child and its location, removing its link from its chunk.
    let mut removed: Option<ChunkLoc> = None;
    for chunk in &mut dir_chunks {
        if let Some(pos) = chunk.children.iter().position(|c| c.name == name) {
            let child = chunk.children.remove(pos);
            removed = Some(ChunkLoc {
                map_key: child.cap.map_key.clone(),
                bat: child.cap.bat.clone(),
                r_base_key: child.cap.r_base_key.clone(),
            });
            chunk.modified = true;
            break;
        }
    }
    let removed = removed.ok_or_else(|| Error::Protocol(format!("no such child: {name}")))?;

    // Re-commit each modified directory chunk (champ CAS-update).
    for chunk in &dir_chunks {
        if !chunk.modified {
            continue;
        }
        let (children_data, fragments) = retrieve::FragmentedPaddedCipherText::build(
            &dir_cap.r_base_key,
            &ChildrenLinks::Named(chunk.children.clone()).to_cbor(),
            MIN_FRAGMENT_SIZE,
            ctx.mirror_bat.as_ref(),
        )?;
        put_raw_blocks_signed(store.as_ref(), &dir_cap.owner, &ctx.signer, fragments, &ctx.tid).await?;
        let new_node = chunk.node.with_children_or_data(children_data.to_cbor());
        let cid = put_block_signed(
            store.as_ref(),
            &dir_cap.owner,
            &ctx.signer,
            new_node.to_cbor().to_bytes(),
            &ctx.tid,
        )
        .await?;
        ctx.champ
            .put(
                &ctx.signer,
                &chunk.map_key,
                &Some(chunk.champ_value.clone()),
                Some(CborObject::MerkleLink(cid.to_bytes())),
                &ctx.tid,
            )
            .await?;
    }

    // Remove the child's own chunks (recursively for directories) from the champ.
    let signer = ctx.signer.clone();
    remove_all_chunks(&mut ctx.champ, &signer, dir_cap, removed, &store, &ctx.tid).await?;

    // Commit: new WriterData with the updated champ root, then the pointer.
    let new_tree_root = ctx.champ.root_hash().clone();
    let new_wd = writer_data_with_tree(&ctx.wd_cbor, &new_tree_root)?;
    let new_wd_cid =
        put_block_signed(store.as_ref(), &dir_cap.owner, &ctx.signer, new_wd.to_bytes(), &ctx.tid).await?;
    let update = PointerUpdate::new(
        Some(ctx.wd_cid.clone()),
        Some(new_wd_cid),
        PointerUpdate::increment(ctx.pointer_sequence),
    );
    if !mutable.set_pointer_update(&dir_cap.owner, &ctx.signer, &update).await? {
        return Err(Error::Protocol("setPointer rejected (concurrent modification?)".into()));
    }
    store.close_transaction(&dir_cap.owner, &ctx.tid).await?;

    // The link node(s) are gone: deauthorise the first-level orphaned writers from
    // this directory's writer's owned champ. Deeper writers were owned by an
    // own-writer we already nulled, so they need no deauthorisation.
    for w in &first_level {
        deauthorize_writer(dir_cap, w, deauth_signer.clone(), store.clone(), mutable).await?;
    }
    Ok(())
}

/// Walk a directory's chunk chain, returning each chunk's (map-key, node, champ
/// value, decrypted children). Shared by delete/rename.
async fn collect_dir_chunks(
    dir_cap: &AbsoluteCapability,
    ctx: &DirWriteContext,
    store: &Arc<dyn ContentAddressedStorage>,
) -> Result<Vec<(Vec<u8>, CryptreeNode, CborObject, Vec<NamedRelativeCapability>)>> {
    let mut out = Vec::new();
    let mut cursor = Some((dir_cap.map_key.clone(), ctx.dir_node.clone(), ctx.dir_link.clone()));
    while let Some((map_key, node, champ_value)) = cursor.take() {
        let decoded = FragmentedPaddedCipherText::from_cbor(&node.children_or_data)?
            .get_and_decrypt(&dir_cap.owner, &dir_cap.r_base_key, store.as_ref(), |c| Ok(c.clone()))
            .await?;
        let children = match ChildrenLinks::from_cbor(&decoded)? {
            ChildrenLinks::Named(v) => v,
            ChildrenLinks::Legacy(_) => {
                return Err(Error::Protocol("legacy directory format not supported".into()))
            }
        };
        let (next_map_key, next_bat) = node.next_chunk_from_base(&dir_cap.r_base_key)?;
        let next = match ctx.champ.get(&next_map_key).await? {
            Some(v) => fetch_chunk_node(&ctx.champ, dir_cap, &next_map_key, &next_bat, store.as_ref())
                .await?
                .filter(|n| n.is_directory())
                .map(|n| (next_map_key.clone(), n, v)),
            None => None,
        };
        out.push((map_key, node, champ_value, children));
        cursor = next;
    }
    Ok(out)
}

/// Re-serialize a directory chunk with an updated children list and CAS-update it
/// in the champ (fragments first, then the node).
async fn recommit_dir_chunk(
    ctx: &mut DirWriteContext,
    dir_cap: &AbsoluteCapability,
    store: &Arc<dyn ContentAddressedStorage>,
    map_key: &[u8],
    node: &CryptreeNode,
    champ_value: &CborObject,
    children: Vec<NamedRelativeCapability>,
) -> Result<()> {
    let (children_data, fragments) = retrieve::FragmentedPaddedCipherText::build(
        &dir_cap.r_base_key,
        &ChildrenLinks::Named(children).to_cbor(),
        MIN_FRAGMENT_SIZE,
        ctx.mirror_bat.as_ref(),
    )?;
    put_raw_blocks_signed(store.as_ref(), &dir_cap.owner, &ctx.signer, fragments, &ctx.tid).await?;
    let new_node = node.with_children_or_data(children_data.to_cbor());
    let cid =
        put_block_signed(store.as_ref(), &dir_cap.owner, &ctx.signer, new_node.to_cbor().to_bytes(), &ctx.tid)
            .await?;
    ctx.champ
        .put(
            &ctx.signer,
            map_key,
            &Some(champ_value.clone()),
            Some(CborObject::MerkleLink(cid.to_bytes())),
            &ctx.tid,
        )
        .await?;
    Ok(())
}

/// Commit the directory's transaction: a new WriterData with the current champ
/// root, then the signed CAS pointer update, then close the transaction.
async fn commit_dir_write(
    ctx: &DirWriteContext,
    dir_cap: &AbsoluteCapability,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let new_tree_root = ctx.champ.root_hash().clone();
    let new_wd = writer_data_with_tree(&ctx.wd_cbor, &new_tree_root)?;
    let new_wd_cid =
        put_block_signed(store.as_ref(), &dir_cap.owner, &ctx.signer, new_wd.to_bytes(), &ctx.tid).await?;
    let update = PointerUpdate::new(
        Some(ctx.wd_cid.clone()),
        Some(new_wd_cid),
        PointerUpdate::increment(ctx.pointer_sequence),
    );
    if !mutable.set_pointer_update(&dir_cap.owner, &ctx.signer, &update).await? {
        return Err(Error::Protocol("setPointer rejected (concurrent modification?)".into()));
    }
    store.close_transaction(&dir_cap.owner, &ctx.tid).await?;
    Ok(())
}

/// Update the properties of a child (file or directory) in place without touching
/// its content. Only the parent block is re-encrypted; the base block and data are
/// preserved. Mirrors Java's `FileWrapper.setProperties`.
pub async fn update_file_properties(
    dir_cap: &AbsoluteCapability,
    child_cap: &AbsoluteCapability,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    new_props: FileProperties,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let mut ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, &store, mutable).await?;
    let node = fetch_chunk_node(
        &ctx.champ,
        child_cap,
        &child_cap.map_key,
        &child_cap.bat,
        store.as_ref(),
    )
    .await?
    .ok_or_else(|| Error::Protocol("child node missing".into()))?;
    let new_node = node.update_properties(&child_cap.r_base_key, new_props)?;
    let cid = put_block_signed(
        store.as_ref(),
        &dir_cap.owner,
        &ctx.signer,
        new_node.to_cbor().to_bytes(),
        &ctx.tid,
    )
    .await?;
    let old_val = ctx.champ.get(&child_cap.map_key).await?;
    ctx.champ
        .put(
            &ctx.signer,
            &child_cap.map_key,
            &old_val,
            Some(CborObject::MerkleLink(cid.to_bytes())),
            &ctx.tid,
        )
        .await?;
    commit_dir_write(&ctx, dir_cap, &store, mutable).await
}

/// Rename a child (file or directory) within a writable directory. Updates the
/// child's own chunk-0 properties (the authoritative name) and the parent's child
/// link. Mirrors `FileWrapper.rename`.
///
/// **Atomic**: both updates (the renamed child node and the renamed parent link)
/// are written as fresh content-addressed blocks — orphaned and invisible while
/// the mutable pointer still references the old `WriterData` — and are made live
/// together by the single compare-and-swap pointer write in [`commit_dir_write`].
/// If any step fails first, the function returns before that write and the old
/// state is fully intact; the pointer CAS itself is all-or-nothing.
pub async fn rename_child(
    dir_cap: &AbsoluteCapability,
    old_name: &str,
    new_name: &str,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if new_name.is_empty() || new_name.contains('/') {
        return Err(Error::Protocol(format!("illegal file name: {new_name}")));
    }
    let mut ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, &store, mutable).await?;
    let mut chunks = collect_dir_chunks(dir_cap, &ctx, &store).await?;

    // The target name must be free, and the source must exist.
    if chunks.iter().any(|(.., children)| children.iter().any(|c| c.name == new_name)) {
        return Err(Error::Protocol(format!("cannot rename: '{new_name}' already exists")));
    }
    let mut renamed: Option<(usize, RelCap)> = None;
    for (i, (.., children)) in chunks.iter_mut().enumerate() {
        if let Some(pos) = children.iter().position(|c| c.name == old_name) {
            children[pos].name = new_name.to_string();
            renamed = Some((i, children[pos].cap.clone()));
            break;
        }
    }
    let (chunk_index, child) =
        renamed.ok_or_else(|| Error::Protocol(format!("no such child: {old_name}")))?;

    // 1. Update the child's own chunk-0 properties (the authoritative name).
    let child_abs = AbsoluteCapability::new(
        dir_cap.owner.clone(),
        dir_cap.writer.clone(),
        child.map_key.clone(),
        child.bat.clone(),
        child.r_base_key.clone(),
        None,
    )?;
    let node = fetch_chunk_node(&ctx.champ, &child_abs, &child.map_key, &child.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol("child node missing".into()))?;
    let parent_key = node.get_parent_key(&child.r_base_key);
    let mut props = node.get_properties(&child.r_base_key)?;
    props.name = new_name.to_string();
    let parent_link = node.parent_link(&child.r_base_key)?;
    let mut fp = CborObject::map();
    if let Some(pl) = &parent_link {
        fp = fp.put("p", pl.to_cbor());
    }
    let from_parent = fp.put("s", props.to_cbor()).build();
    let new_child_node = CryptreeNode::new(
        node.is_directory(),
        node.bats.clone(),
        node.from_base_key.clone(),
        PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        node.children_or_data.clone(),
    );
    let old_val = ctx.champ.get(&child.map_key).await?;
    let cid = put_block_signed(
        store.as_ref(),
        &dir_cap.owner,
        &ctx.signer,
        new_child_node.to_cbor().to_bytes(),
        &ctx.tid,
    )
    .await?;
    ctx.champ
        .put(&ctx.signer, &child.map_key, &old_val, Some(CborObject::MerkleLink(cid.to_bytes())), &ctx.tid)
        .await?;

    // 2. Update the parent's child link (the renamed chunk).
    let (map_key, node, champ_value, children) = &chunks[chunk_index];
    recommit_dir_chunk(&mut ctx, dir_cap, &store, map_key, node, champ_value, children.clone()).await?;

    commit_dir_write(&ctx, dir_cap, &store, mutable).await
}

// ---------------------------------------------------------------------------
// File upload transactions
// ---------------------------------------------------------------------------

const TRANSACTIONS_DIR: &str = ".transactions";

/// The `.transactions` directory under home + the home writer's signer.
async fn transactions_dir(
    home_cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<(AbsoluteCapability, SigningPrivateKeyAndPublicHash)> {
    let signer = recover_signer(home_cap, store.clone(), mutable).await?;
    let dir = list_directory(home_cap, store.clone(), mutable)
        .await?
        .into_iter()
        .find(|e| e.name == TRANSACTIONS_DIR)
        .ok_or_else(|| Error::Protocol("no .transactions directory".into()))?
        .cap;
    Ok((dir, signer))
}

/// `TransactionService.open`: write the transaction record into `.transactions`
/// (`Ok(true)` if a record with that name already existed — a resume/conflict).
async fn open_transaction(
    home_cap: &AbsoluteCapability,
    txn: &FileUploadTransaction,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<bool> {
    let (tdir, signer) = transactions_dir(home_cap, store.clone(), mutable).await?;
    let existed = list_directory(&tdir, store.clone(), mutable).await?.iter().any(|e| e.name == txn.name);
    upload_file(&tdir, &txn.name, &txn.to_cbor().to_bytes(), None, Some(signer), None, store, mutable).await?;
    Ok(existed)
}

/// `TransactionService.close`: remove a transaction record from `.transactions`.
async fn close_transaction_record(
    home_cap: &AbsoluteCapability,
    name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let (tdir, signer) = transactions_dir(home_cap, store.clone(), mutable).await?;
    if list_directory(&tdir, store.clone(), mutable).await?.iter().any(|e| e.name == name) {
        delete_child(&tdir, name, Some(signer), None, store, mutable).await?;
    }
    Ok(())
}

/// `TransactionService.getOpenTransactions`: the in-progress / failed uploads
/// recorded in `.transactions`.
pub async fn list_open_transactions(
    home_cap: &AbsoluteCapability,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Vec<FileUploadTransaction>> {
    let (tdir, _) = transactions_dir(home_cap, store.clone(), mutable).await?;
    let mut out = Vec::new();
    for e in list_directory(&tdir, store.clone(), mutable).await? {
        let bytes = read_file(&e.cap, store.clone(), mutable).await?.1;
        if let Ok(cbor) = CborObject::from_bytes(&bytes) {
            if let Ok(txn) = FileUploadTransaction::from_cbor(&cbor, &e.name) {
                out.push(txn);
            }
        }
    }
    Ok(out)
}

/// Read a single open transaction record by name (`hash(path)`), if present.
async fn get_open_transaction(
    home_cap: &AbsoluteCapability,
    name: &str,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Option<FileUploadTransaction>> {
    let (tdir, _) = transactions_dir(home_cap, store.clone(), mutable).await?;
    let entry = list_directory(&tdir, store.clone(), mutable).await?.into_iter().find(|e| e.name == name);
    match entry {
        Some(e) => {
            let bytes = read_file(&e.cap, store.clone(), mutable).await?.1;
            let cbor = CborObject::from_bytes(&bytes)?;
            Ok(Some(FileUploadTransaction::from_cbor(&cbor, name)?))
        }
        None => Ok(None),
    }
}

/// Resolve the writer signer for uploading into `dir_cap`, like Java's
/// `parent.signingPair()`: the directory's own writer link if it has one (a
/// write-shared / entry-point dir), else the explicit `entry_signer`, else the
/// home/entry-point writer (a plain subdirectory shares it).
async fn upload_signer(
    dir_cap: &AbsoluteCapability,
    home_cap: &AbsoluteCapability,
    entry_signer: &Option<SigningPrivateKeyAndPublicHash>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<SigningPrivateKeyAndPublicHash> {
    if let Ok(s) = recover_signer(dir_cap, store.clone(), mutable).await {
        return Ok(s);
    }
    if let Some(s) = entry_signer {
        return Ok(s.clone());
    }
    recover_signer(home_cap, store, mutable).await
}

/// Upload chunks `[start_chunk, n)` into the writer subspace, **committing after
/// each chunk** (so a failure leaves a resumable/cleanable partial upload). Keys,
/// stream secret and properties all come from `txn`; `tree` is the content hash
/// tree for a fresh upload (a resume reuses `txn.props.tree_hash` for chunk 0).
#[allow(clippy::too_many_arguments)]
async fn upload_txn_chunks<R, F>(
    dir_cap: &AbsoluteCapability,
    txn: &FileUploadTransaction,
    tree: Option<&hashtree::HashTree>,
    start_chunk: usize,
    mirror_bat: Option<&BatId>,
    open: F,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()>
where
    R: std::io::Read,
    F: Fn() -> std::io::Result<R>,
{
    let owner = &txn.owner;
    let signer = &txn.writer;
    let chunk_size = retrieve::CHUNK_MAX_SIZE as usize;
    let n_chunks = txn.chunk_count() as usize;
    let size = txn.size as usize;
    let chunk_len = |i: usize| if i + 1 == n_chunks { size - i * chunk_size } else { chunk_size };

    // The link back to the parent directory (its parent key + location).
    let dir_champ = open_writer_champ(dir_cap, store.clone(), mutable).await?;
    let dir_node = fetch_chunk_node(&dir_champ, dir_cap, &dir_cap.map_key, &dir_cap.bat, store.as_ref())
        .await?
        .ok_or_else(|| Error::Protocol("target directory missing".into()))?;
    let dir_parent_key = dir_node.base_block(&dir_cap.r_base_key)?.parent_or_data;
    let to_parent = RelCap {
        writer: None,
        map_key: dir_cap.map_key.clone(),
        bat: dir_cap.bat.clone(),
        r_base_key: dir_parent_key,
        w_base_key_link: None,
    };

    // Open the writer subspace; the base WriterData's `tree` is swapped each commit.
    let pointer = mutable.get_pointer_target(owner, &signer.public_key_hash, store.as_ref()).await?;
    let mut wd_cid = pointer.updated.clone().ok_or_else(|| Error::Protocol("writer has no data".into()))?;
    let base_wd = store.get(owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let tree_root = Cid::cast(
        base_wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("no champ tree".into()))?,
    )?;
    let mut champ = ChampWrapper::create(owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?;
    let mut seq = pointer.sequence;
    let tid = store.start_transaction(owner).await?;

    // Map key / BAT of start_chunk (chained from the first chunk), and a reader
    // positioned there (already-uploaded chunks skipped).
    let mut map_key = txn.first_map_key.clone();
    let mut bat = txn.first_bat.clone();
    let mut reader = open().map_err(|e| Error::Protocol(format!("open error: {e}")))?;
    let mut buf = vec![0u8; chunk_size];
    for _ in 0..start_chunk {
        let (nmk, nbat) = retrieve::calculate_next_map_key(&txn.stream_secret, &map_key, &bat)?;
        read_exact(&mut reader, &mut buf)?;
        map_key = nmk;
        bat = nbat;
    }

    for i in start_chunk..n_chunks {
        let want = chunk_len(i);
        read_exact(&mut reader, &mut buf[..want])?;
        let (next_map_key, next_bat) = retrieve::calculate_next_map_key(&txn.stream_secret, &map_key, &bat)?;
        let (data, fragments) = retrieve::FragmentedPaddedCipherText::build(
            &txn.data_key,
            &CborObject::ByteString(buf[..want].to_vec()),
            MIN_FRAGMENT_SIZE,
            mirror_bat,
        )?;
        let next_chunk = RelCap::subsequent_chunk(next_map_key.clone(), next_bat.clone(), txn.base_key.clone());
        let from_base = CborObject::map().put("k", txn.data_key.to_cbor()).put("n", next_chunk.to_cbor()).build();
        let mut props = FileProperties::new_file(
            txn.props.name.clone(),
            txn.props.mime_type.clone(),
            txn.size,
            txn.props.created_epoch,
            txn.stream_secret.clone(),
            if i == 0 { txn.props.thumbnail.clone() } else { None },
        );
        if i % 1024 == 0 {
            props.tree_hash = match tree {
                Some(t) => Some(t.branch(i as u64)),
                None if i == 0 => txn.props.tree_hash.clone(),
                None => None,
            };
        }
        let from_parent = CborObject::map().put("p", to_parent.to_cbor()).put("s", props.to_cbor()).build();
        let node = CryptreeNode::new(
            false,
            node_bats_opt(bat.as_ref(), mirror_bat)?,
            PaddedCipherText::build(&txn.base_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
            PaddedCipherText::build(&txn.base_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
            data.to_cbor(),
        );
        put_raw_blocks_signed(store.as_ref(), owner, signer, fragments, &tid).await?;
        let node_cid = put_block_signed(store.as_ref(), owner, signer, node.to_cbor().to_bytes(), &tid).await?;
        let expected = champ.get(&map_key).await?;
        champ.put(signer, &map_key, &expected, Some(CborObject::MerkleLink(node_cid.to_bytes())), &tid).await?;

        // Commit this chunk so it survives a later failure (resumable/cleanable).
        let new_wd = writer_data_with_tree(&base_wd, champ.root_hash())?;
        let new_wd_cid = put_block_signed(store.as_ref(), owner, signer, new_wd.to_bytes(), &tid).await?;
        let update = PointerUpdate::new(Some(wd_cid.clone()), Some(new_wd_cid.clone()), PointerUpdate::increment(seq));
        if !mutable.set_pointer_update(owner, signer, &update).await? {
            return Err(Error::Protocol("chunk pointer commit rejected".into()));
        }
        wd_cid = new_wd_cid;
        seq = update.sequence;
        map_key = next_map_key;
        bat = next_bat;
    }
    store.close_transaction(owner, &tid).await?;
    Ok(())
}

/// Add the completed file's child link to `dir_cap` (`relativise` + a writable
/// SymmetricLink), returning its capability.
async fn add_file_child_link(
    dir_cap: &AbsoluteCapability,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    txn: &FileUploadTransaction,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let file_cap = AbsoluteCapability::new(
        txn.owner.clone(),
        txn.writer.public_key_hash.clone(),
        txn.first_map_key.clone(),
        txn.first_bat.clone(),
        txn.base_key.clone(),
        Some(txn.write_key.clone()),
    )?;
    let ctx = begin_dir_write(dir_cap, entry_signer, mirror_bat, store, mutable).await?;
    let w_link = dir_cap
        .w_base_key
        .as_ref()
        .map(|pw| -> Result<CborObject> {
            Ok(peergos_core::symmetric::CipherText::build(pw, &txn.write_key)?.to_cbor())
        })
        .transpose()?;
    let child_link = NamedRelativeCapability {
        name: txn.props.name.clone(),
        cap: RelCap {
            writer: None,
            map_key: txn.first_map_key.clone(),
            bat: txn.first_bat.clone(),
            r_base_key: txn.base_key.clone(),
            w_base_key_link: w_link,
        },
        is_dir: Some(false),
        mime_type: Some(txn.props.mime_type.clone()),
        created_epoch: Some(txn.props.created_epoch),
    };
    finish_dir_write(ctx, dir_cap, store, mutable, child_link).await?;
    Ok(file_cap)
}

/// Upload a file into `dir_cap` **under a transaction**: a record is written to
/// `.transactions` (under `home_cap`) first, chunks are committed incrementally,
/// and the record is removed on success. If interrupted, the record + partial
/// chunks remain for [`list_open_transactions`] / [`clear_transaction`] /
/// [`resume_transaction`]. `path` identifies the upload (its transaction name).
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_with_transaction<R, F>(
    home_cap: &AbsoluteCapability,
    dir_cap: &AbsoluteCapability,
    path: &str,
    name: &str,
    size: u64,
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    open: F,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability>
where
    R: std::io::Read,
    F: Fn() -> std::io::Result<R>,
{
    let signer = upload_signer(dir_cap, home_cap, &entry_signer, store.clone(), mutable).await?;
    let base_key = random_symmetric_key()?;
    let data_key = loop {
        let k = random_symmetric_key()?;
        if k != base_key {
            break k;
        }
    };
    let write_key = random_symmetric_key()?;
    let stream_secret = random_bytes(32);
    let first_map_key = random_bytes(32);
    let first_bat = Bat::new(random_bytes(32))?;

    // Pass 1: content hash tree + MIME (bounded RAM).
    let chunk_size = retrieve::CHUNK_MAX_SIZE as usize;
    let n_chunks = if size == 0 { 1 } else { size.div_ceil(chunk_size as u64) as usize };
    let mut reader = open().map_err(|e| Error::Protocol(format!("open error: {e}")))?;
    let mut buf = vec![0u8; chunk_size];
    let mut chunk_hashes = Vec::with_capacity(n_chunks);
    let mut header: Vec<u8> = Vec::new();
    for i in 0..n_chunks {
        let want = if i + 1 == n_chunks { (size as usize) - i * chunk_size } else { chunk_size };
        read_exact(&mut reader, &mut buf[..want])?;
        if i == 0 {
            header = buf[..want.min(mimetype::HEADER_BYTES_TO_IDENTIFY_MIME_TYPE)].to_vec();
        }
        chunk_hashes.push(peergos_crypto::hash::sha256(&buf[..want]));
    }
    let tree = hashtree::HashTree::build(&chunk_hashes)?;
    let mime_type = mimetype::calculate_mime_type(&header, name);

    let epoch = now_epoch();
    let mut props = FileProperties::new_file(name.to_string(), mime_type, size, epoch, stream_secret.clone(), thumbnail);
    props.tree_hash = Some(tree.branch(0));

    // Auto-resume: if an interrupted upload of the same path is recorded and it has
    // the SAME content hash tree (same bytes), continue it from the first missing
    // chunk instead of restarting. A record with a different hash is a stale upload
    // of different content at this path — clear it and start fresh.
    let txn_name = FileUploadTransaction::name_for_path(path)?;
    if let Some(existing) = get_open_transaction(home_cap, &txn_name, store.clone(), mutable).await? {
        if existing.size == size && existing.props.tree_hash == props.tree_hash {
            let start = find_first_absent_chunk(&existing, &store, mutable).await? as usize;
            // Pass the (already-computed) tree so a resumed multi-chunk upload still
            // sets every content hash-tree branch, not just chunk 0's.
            upload_txn_chunks(dir_cap, &existing, Some(&tree), start, mirror_bat, &open, &store, mutable).await?;
            let file_cap = add_file_child_link(dir_cap, Some(existing.writer.clone()), mirror_bat, &existing, &store, mutable).await?;
            close_transaction_record(home_cap, &existing.name, store, mutable).await?;
            return Ok(file_cap);
        }
        clear_transaction(home_cap, &existing, store.clone(), mutable).await?;
    }

    let txn = FileUploadTransaction {
        start_time_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0),
        path: path.to_string(),
        name: FileUploadTransaction::name_for_path(path)?,
        owner: dir_cap.owner.clone(),
        writer: signer,
        first_map_key,
        first_bat: Some(first_bat),
        props,
        base_key,
        data_key,
        write_key,
        stream_secret,
        size,
    };

    open_transaction(home_cap, &txn, store.clone(), mutable).await?;
    upload_txn_chunks(dir_cap, &txn, Some(&tree), 0, mirror_bat, &open, &store, mutable).await?;
    // The transaction's writer is the parent's writer, so it links the child too.
    let file_cap = add_file_child_link(dir_cap, Some(txn.writer.clone()), mirror_bat, &txn, &store, mutable).await?;
    close_transaction_record(home_cap, &txn.name, store, mutable).await?;
    Ok(file_cap)
}

/// The standard user-facing upload. Routes exactly like Java's `uploadFilePart`
/// (`FileWrapper.java`): a single-chunk file (`size <= CHUNK_MAX_SIZE`) is written
/// with one atomic [`upload_file_streaming`], while a multi-chunk file goes
/// through a crash-safe [`upload_file_with_transaction`] (record in
/// `.transactions` + incremental per-chunk commits, so it can be listed, cleaned
/// up or resumed). `home_cap` locates `.transactions`; `path` is the upload's
/// home-relative path (its transaction name).
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_streaming_auto<R, F>(
    home_cap: &AbsoluteCapability,
    dir_cap: &AbsoluteCapability,
    path: &str,
    name: &str,
    size: u64,
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    open: F,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability>
where
    R: std::io::Read,
    F: Fn() -> std::io::Result<R>,
{
    if size <= retrieve::CHUNK_MAX_SIZE {
        upload_file_streaming(dir_cap, name, size, thumbnail, entry_signer, mirror_bat, open, store, mutable).await
    } else {
        upload_file_with_transaction(
            home_cap, dir_cap, path, name, size, thumbnail, entry_signer, mirror_bat, open, store, mutable,
        )
        .await
    }
}

/// In-memory convenience over [`upload_file_streaming_auto`]: transactional for
/// multi-chunk files, atomic for single-chunk ones.
#[allow(clippy::too_many_arguments)]
pub async fn upload_file_auto(
    home_cap: &AbsoluteCapability,
    dir_cap: &AbsoluteCapability,
    path: &str,
    name: &str,
    contents: &[u8],
    thumbnail: Option<(String, Vec<u8>)>,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    upload_file_streaming_auto(
        home_cap,
        dir_cap,
        path,
        name,
        contents.len() as u64,
        thumbnail,
        entry_signer,
        mirror_bat,
        || Ok(std::io::Cursor::new(contents)),
        store,
        mutable,
    )
    .await
}

/// A file to place in a subtree upload.
/// A lazily-opened byte source: called once per read pass, never holding the whole
/// file in memory (like Java's `AsyncReader` supplier).
type ReaderFactory = Arc<dyn Fn() -> std::io::Result<Box<dyn std::io::Read + Send>> + Send + Sync>;

/// A file to place in a subtree upload. Content is provided LAZILY via `open`, so
/// huge files stream chunk-by-chunk and are never held whole in RAM. `hash`, if
/// present, lets an unchanged file be skipped without reading it.
pub struct FileUpload {
    pub name: String,
    pub size: u64,
    open: ReaderFactory,
    hash: Option<hashtree::RootHash>,
}

impl FileUpload {
    /// A file whose bytes come from a reader factory (`open` is called once per
    /// pass — the hash pass and the upload pass — so it must re-yield the same bytes).
    pub fn from_reader<F, R>(name: impl Into<String>, size: u64, open: F) -> FileUpload
    where
        F: Fn() -> std::io::Result<R> + Send + Sync + 'static,
        R: std::io::Read + Send + 'static,
    {
        FileUpload {
            name: name.into(),
            size,
            open: Arc::new(move || open().map(|r| Box::new(r) as Box<dyn std::io::Read + Send>)),
            hash: None,
        }
    }

    /// Stream a file from disk (size read from the filesystem, content re-opened
    /// lazily each pass — never fully buffered).
    pub fn from_path(name: impl Into<String>, path: impl AsRef<std::path::Path>) -> std::io::Result<FileUpload> {
        let path = path.as_ref().to_path_buf();
        let size = std::fs::metadata(&path)?.len();
        Ok(FileUpload {
            name: name.into(),
            size,
            open: Arc::new(move || std::fs::File::open(&path).map(|f| Box::new(f) as Box<dyn std::io::Read + Send>)),
            hash: None,
        })
    }

    /// A small in-memory file. Its content hash is precomputed so re-uploading an
    /// unchanged copy is skipped.
    pub fn from_bytes(name: impl Into<String>, data: Vec<u8>) -> FileUpload {
        let size = data.len() as u64;
        let hash = content_root_hash(&data).ok();
        let data = Arc::new(data);
        FileUpload {
            name: name.into(),
            size,
            open: Arc::new(move || Ok(Box::new(std::io::Cursor::new((*data).clone())) as Box<dyn std::io::Read + Send>)),
            hash,
        }
    }

    /// Attach a precomputed content hash-tree root (from a prior scan) so this file
    /// can be deduped against an unchanged remote copy without reading it.
    pub fn with_hash(mut self, hash: hashtree::RootHash) -> FileUpload {
        self.hash = Some(hash);
        self
    }
}

/// A directory relative to the upload base and the files to place directly in it.
/// `rel_path` is the `/`-free component list under the base (empty = the base dir).
pub struct FolderUpload {
    pub rel_path: Vec<String>,
    pub files: Vec<FileUpload>,
}

/// The content hash-tree root a file's bytes would produce on upload (the same
/// `HashTree` upload builds), for content-based dedup against a remote file's
/// stored `tree_hash`.
pub fn content_root_hash(data: &[u8]) -> Result<hashtree::RootHash> {
    let chunk = retrieve::CHUNK_MAX_SIZE as usize;
    let n = if data.is_empty() { 1 } else { data.len().div_ceil(chunk) };
    let mut hashes = Vec::with_capacity(n);
    for i in 0..n {
        let end = ((i + 1) * chunk).min(data.len());
        hashes.push(peergos_crypto::hash::sha256(&data[i * chunk..end]));
    }
    Ok(hashtree::HashTree::build(&hashes)?.root_hash)
}

/// Compute the Merkle tree root hash of a file at `path` by reading it in 5 MiB
/// chunks, SHA-256 hashing each chunk, and building the hash tree.
/// Uses [`std::thread::available_parallelism`] threads automatically.
pub fn hash_file_parallel(path: &std::path::Path, size: u64) -> Result<hashtree::RootHash> {
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    hash_file_with_threads(path, size, n_threads)
}

/// Like [`hash_file_parallel`] but with an explicit thread count.
pub fn hash_file_with_threads(path: &std::path::Path, size: u64, n_threads: usize) -> Result<hashtree::RootHash> {
    let chunk_size = retrieve::CHUNK_MAX_SIZE;
    if size == 0 {
        return hashtree::HashTree::build(&[peergos_crypto::hash::sha256(&[])])
            .map(|t| t.root_hash);
    }
    let n_chunks = size.div_ceil(chunk_size) as usize;
    let chunk_hashes = if n_chunks <= n_threads || n_threads <= 1 {
        let mut file = std::fs::File::open(path)
            .map_err(|e| Error::Protocol(format!("open for hash: {e}")))?;
        read_chunk_hashes_serial(&mut file, size, n_chunks, chunk_size as usize)?
    } else {
        read_chunk_hashes_parallel(path, size, n_chunks, n_threads, chunk_size as usize)?
    };
    hashtree::HashTree::build(&chunk_hashes).map(|t| t.root_hash)
}

/// Read a file and SHA-256 hash each 5 MiB chunk serially.
fn read_chunk_hashes_serial(
    file: &mut impl Read,
    size: u64,
    n_chunks: usize,
    chunk_size: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut hashes = Vec::with_capacity(n_chunks);
    let mut buf = vec![0u8; chunk_size];
    let mut remaining = size;
    loop {
        let to_read = chunk_size.min(remaining as usize);
        if to_read == 0 {
            break;
        }
        let mut total = 0;
        while total < to_read {
            let n = file.read(&mut buf[total..to_read])
                .map_err(|e| Error::Protocol(e.to_string()))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        if total == 0 {
            break;
        }
        hashes.push(peergos_crypto::hash::sha256(&buf[..total]));
        remaining -= total as u64;
        if total < to_read {
            break;
        }
    }
    debug_assert_eq!(hashes.len(), n_chunks, "wrong chunk count for size={size}");
    Ok(hashes)
}

/// Read a file and SHA-256 hash each 5 MiB chunk in parallel across `n_threads`.
fn read_chunk_hashes_parallel(
    path: &std::path::Path,
    size: u64,
    n_chunks: usize,
    n_threads: usize,
    chunk_size: usize,
) -> Result<Vec<Vec<u8>>> {
    let chunks_per_thread = (n_chunks + n_threads - 1) / n_threads;
    let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::with_capacity(n_threads)));
    std::thread::scope(|s| {
        for i in 0..n_threads {
            let start_chunk = i * chunks_per_thread;
            let end_chunk = n_chunks.min((i + 1) * chunks_per_thread);
            if start_chunk >= end_chunk {
                continue;
            }
            let results = std::sync::Arc::clone(&results);
            s.spawn(move || {
                let start_offset = start_chunk as u64 * retrieve::CHUNK_MAX_SIZE;
                let end_offset = size.min(end_chunk as u64 * retrieve::CHUNK_MAX_SIZE);
                let range_len = end_offset - start_offset;
                let result = (|| -> Result<Vec<Vec<u8>>> {
                    let mut file = std::fs::File::open(path)
                        .map_err(|e| Error::Protocol(format!("parallel hash open: {e}")))?;
                    file.seek(SeekFrom::Start(start_offset))
                        .map_err(|e| Error::Protocol(format!("parallel hash seek: {e}")))?;
                    let mut hashes = Vec::with_capacity(end_chunk - start_chunk);
                    let mut buf = vec![0u8; chunk_size];
                    let mut remaining = range_len;
                    while remaining > 0 {
                        let to_read = chunk_size.min(remaining as usize);
                        let mut total = 0;
                        while total < to_read {
                            let n = file.read(&mut buf[total..to_read])
                                .map_err(|e| Error::Protocol(e.to_string()))?;
                            if n == 0 {
                                break;
                            }
                            total += n;
                        }
                        if total == 0 {
                            break;
                        }
                        hashes.push(peergos_crypto::hash::sha256(&buf[..total]));
                        remaining -= total as u64;
                        if total < to_read {
                            break;
                        }
                    }
                    Ok(hashes)
                })();
                results.lock().unwrap().push((i, result));
            });
        }
    });
    let mut all = std::sync::Arc::into_inner(results).unwrap().into_inner().unwrap();
    all.sort_by_key(|(i, _)| *i);
    let mut chunk_hashes = Vec::with_capacity(n_chunks);
    for (_, result) in all {
        chunk_hashes.extend(result?);
    }
    Ok(chunk_hashes)
}

/// Navigate `components` under `base`, creating any missing directories, through
/// the given store/mutable. Returns the leaf directory's capability.
async fn get_or_mkdirs_cap(
    base: &AbsoluteCapability,
    components: &[String],
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability> {
    let mut cur = base.clone();
    for comp in components {
        let existing = list_directory(&cur, store.clone(), mutable)
            .await?
            .into_iter()
            .find(|e| &e.name == comp);
        cur = match existing {
            Some(e) => e.cap,
            None => create_directory(&cur, comp, Some(signer.clone()), mirror_bat, store.clone(), mutable).await?,
        };
    }
    Ok(cur)
}

/// Efficiently upload a whole directory tree in as few server commits as possible
/// (ports `FileWrapper.uploadSubtree`). Every write goes through a [`BufferedNetwork`]
/// over `store`/`mutable`: blocks and pointer updates are buffered and flushed in
/// bulk once the buffer reaches ~20 MiB (and at the end), GC'd to the reachable set
/// before each flush so superseded intermediate champ nodes are never sent.
///
/// Files STREAM — their bytes are read chunk-by-chunk from [`FileUpload::open`],
/// never held whole in RAM. Small (single-chunk) files are written atomically;
/// large (multi-chunk) files go through the crash-safe transaction path, which
/// commits each chunk, so the auto-commit flushes mid-file and memory stays bounded
/// to ~one 5 MiB chunk plus the ~20 MiB buffer regardless of file size. Within each
/// folder files are uploaded sorted by ascending size, and any file whose content
/// hash matches the stored one is skipped. `base_signer` signs writes into `base`
/// and its plain subdirectories (they share its writer); `home_cap`/`base_path`
/// anchor the `.transactions` records for large files.
pub async fn upload_subtree(
    home_cap: &AbsoluteCapability,
    base: &AbsoluteCapability,
    base_path: &str,
    base_signer: SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    folders: Vec<FolderUpload>,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: Arc<dyn MutablePointers>,
) -> Result<()> {
    let owner = base.owner.clone();
    let net = BufferedNetwork::with_defaults(store, mutable);
    let bstore: Arc<dyn ContentAddressedStorage> = net.storage();
    let bmutable: Arc<dyn MutablePointers> = net.pointers();

    for folder in folders {
        let dir_cap =
            get_or_mkdirs_cap(base, &folder.rel_path, &base_signer, mirror_bat, bstore.clone(), bmutable.as_ref()).await?;

        // Pre-load the directory's existing children ONCE, so we can skip files
        // whose content is unchanged without a per-file lookup (Java's fast path).
        let existing = list_directory(&dir_cap, bstore.clone(), bmutable.as_ref()).await?;
        let existing_hash: std::collections::HashMap<String, hashtree::RootHash> = if existing.is_empty() {
            std::collections::HashMap::new()
        } else {
            let caps: Vec<_> = existing.iter().map(|e| e.cap.clone()).collect();
            let (retrieved, _) = retrieve_all_metadata(&caps, bstore.clone(), bmutable.as_ref()).await?;
            retrieved
                .into_iter()
                .filter_map(|rc| rc.properties.tree_hash.map(|h| (rc.properties.name, h.root_hash)))
                .collect()
        };

        // Home-relative path of this folder (for transaction records of large files).
        let mut dir_path = base_path.trim_matches('/').to_string();
        for comp in &folder.rel_path {
            dir_path = if dir_path.is_empty() { comp.clone() } else { format!("{dir_path}/{comp}") };
        }

        // Files in a plain subdirectory share the base writer's signer.
        let mut files = folder.files;
        files.sort_by_key(|f| f.size);

        // Small (single-chunk) files are staged and their parent links added in one
        // dir write per ~10 MiB group (Java's uploadFolder batching); large files go
        // through the crash-safe transaction path individually, after flushing any
        // pending small-file batch so the directory stays consistent.
        let mut batch: Vec<FileUpload> = Vec::new();
        let mut batch_bytes = 0u64;
        for f in files {
            // Skip unchanged files (identical content already present) when we can
            // tell without reading — the caller supplied a content hash.
            if let (Some(remote), Some(local)) = (existing_hash.get(&f.name), &f.hash) {
                if local == remote {
                    continue;
                }
            }
            if f.size > retrieve::CHUNK_MAX_SIZE {
                if !batch.is_empty() {
                    commit_small_batch(&dir_cap, &base_signer, mirror_bat, std::mem::take(&mut batch), &bstore, bmutable.as_ref()).await?;
                    batch_bytes = 0;
                }
                let file_path = if dir_path.is_empty() { f.name.clone() } else { format!("{dir_path}/{}", f.name) };
                let open = f.open.clone();
                upload_file_streaming_auto(
                    home_cap,
                    &dir_cap,
                    &file_path,
                    &f.name,
                    f.size,
                    None,
                    Some(base_signer.clone()),
                    mirror_bat,
                    move || open(),
                    bstore.clone(),
                    bmutable.as_ref(),
                )
                .await?;
            } else {
                batch_bytes += f.size;
                batch.push(f);
                if batch_bytes >= SUBTREE_PROGRESS_BATCH {
                    commit_small_batch(&dir_cap, &base_signer, mirror_bat, std::mem::take(&mut batch), &bstore, bmutable.as_ref()).await?;
                    batch_bytes = 0;
                }
            }
        }
        if !batch.is_empty() {
            commit_small_batch(&dir_cap, &base_signer, mirror_bat, batch, &bstore, bmutable.as_ref()).await?;
        }
    }
    net.commit(&owner).await
}

/// The progress/commit batch size within a folder (Java `uploadFolder` batchSize).
const SUBTREE_PROGRESS_BATCH: u64 = 10 * 1024 * 1024;

/// Stage a batch of small (single-chunk) files into `dir_cap` and add all their
/// child links in ONE dir write: write each file's chunk blocks + champ entries,
/// then `finish_dir_write_multi` adds every link and commits once. Each file's data
/// (≤ one 5 MiB chunk) is read from its lazy reader only while it is being staged.
async fn commit_small_batch(
    dir_cap: &AbsoluteCapability,
    signer: &SigningPrivateKeyAndPublicHash,
    mirror_bat: Option<&BatId>,
    files: Vec<FileUpload>,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let owner = &dir_cap.owner;
    let mut ctx = begin_dir_write(dir_cap, Some(signer.clone()), mirror_bat, store, mutable).await?;
    let epoch = now_epoch();
    let mut links = Vec::with_capacity(files.len());
    for f in files {
        let mut data = Vec::new();
        (f.open)()
            .map_err(|e| Error::Protocol(format!("open error: {e}")))?
            .read_to_end(&mut data)
            .map_err(|e| Error::Protocol(format!("read error: {e}")))?;

        let file_r_base = random_symmetric_key()?;
        let file_data_key = loop {
            let k = random_symmetric_key()?;
            if k != file_r_base {
                break k;
            }
        };
        let file_write_key = random_symmetric_key()?;
        let stream_secret = random_bytes(32);
        let first_map_key = random_bytes(32);
        let first_bat = Bat::new(random_bytes(32))?;
        let to_parent = RelCap {
            writer: None,
            map_key: dir_cap.map_key.clone(),
            bat: dir_cap.bat.clone(),
            r_base_key: ctx.dir_parent_key.clone(),
            w_base_key_link: None,
        };
        let mime = mimetype::calculate_mime_type(
            &data[..data.len().min(mimetype::HEADER_BYTES_TO_IDENTIFY_MIME_TYPE)],
            &f.name,
        );
        // Writes the file's chunk nodes (content hash tree computed inside) and
        // returns their (map-key, cid); we champ-put each into this dir write.
        let chunks = write_file_chunks(
            owner,
            signer,
            &first_map_key,
            &Some(first_bat.clone()),
            &file_r_base,
            &file_data_key,
            &stream_secret,
            &to_parent,
            None,
            &f.name,
            &mime,
            epoch,
            &None,
            mirror_bat,
            &data,
            store,
            &ctx.tid,
        )
        .await?;
        for (mk, cid) in &chunks {
            let expected = ctx.champ.get(mk).await?;
            ctx.champ
                .put(signer, mk, &expected, Some(CborObject::MerkleLink(cid.to_bytes())), &ctx.tid)
                .await?;
        }
        // The write key lives only in the child link (the file shares the parent writer).
        let w_link = dir_cap
            .w_base_key
            .as_ref()
            .map(|pw| peergos_core::symmetric::CipherText::build(pw, &file_write_key).map(|c| c.to_cbor()))
            .transpose()?;
        links.push(NamedRelativeCapability {
            name: f.name.clone(),
            cap: RelCap {
                writer: None,
                map_key: first_map_key,
                bat: Some(first_bat),
                r_base_key: file_r_base,
                w_base_key_link: w_link,
            },
            is_dir: Some(false),
            mime_type: Some(mime),
            created_epoch: Some(epoch),
        });
    }
    finish_dir_write_multi(ctx, dir_cap, store, mutable, links).await
}

/// How many probes per round in the 8-ary search for the first absent chunk.
const PROBE_COUNT: u64 = 8;

/// Derive map-key/BAT pairs for each probe index, walking forward cumulatively
/// from `prev_key`/`prev_bat` at index `prev_index`. Equivalent to Java's
/// `deriveProbesForIndices`.
async fn derive_probes_for_indices(
    stream_secret: &[u8],
    prev_key: &[u8],
    prev_bat: &Option<Bat>,
    prev_index: u64,
    probe_indices: &[u64],
    pos: usize,
    probes: &mut [(Vec<u8>, Option<Bat>)],
) -> Result<()> {
    if pos >= probes.len() {
        return Ok(());
    }
    let steps = probe_indices[pos] - prev_index;
    let (next_key, next_bat) = advance_map_key(stream_secret, prev_key, prev_bat, steps)?;
    probes[pos] = (next_key.clone(), next_bat.clone());
    Box::pin(derive_probes_for_indices(
        stream_secret,
        &next_key,
        &next_bat,
        probe_indices[pos],
        probe_indices,
        pos + 1,
        probes,
    ))
    .await
}

/// 8-ary search for the first absent chunk index.  Invariant: the answer is in
/// `[lo, hi)`, chunk[hi] is absent.
///
/// `lookup` receives an owned batch of (map_key, bat) pairs and returns a
/// boolean for each indicating whether the chunk is present.
///
/// Each round issues at most `PROBE_COUNT` (8) probes, narrowing the range by
/// ~8×, so the total number of CHAMP round-trips is O(log₈ N) rather than O(N).
pub async fn binary_search_absent_chunk(
    stream_secret: &[u8],
    lo: u64,
    hi: u64,
    lo_map_key: &[u8],
    lo_bat: &Option<Bat>,
    lookup: &dyn Fn(Vec<(Vec<u8>, Option<Bat>)>) -> Pin<Box<dyn Future<Output = Result<Vec<bool>>>>>,
) -> Result<u64> {
    if lo >= hi {
        return Ok(lo);
    }

    let range_size = hi - lo;
    let batch_size = std::cmp::min(range_size, PROBE_COUNT) as usize;

    // probe_indices[0] = lo, probe_indices[batchSize-1] < hi
    let probe_indices: Vec<u64> = (0..batch_size)
        .map(|i| lo + (i as u64) * range_size / (batch_size as u64))
        .collect();

    // Derive map-key/BAT for each probe (cumulatively from lo)
    let mut probes = vec![(lo_map_key.to_vec(), lo_bat.clone()); batch_size];
    derive_probes_for_indices(stream_secret, lo_map_key, lo_bat, lo, &probe_indices, 1, &mut probes).await?;

    let present_flags = lookup(probes.clone()).await?;

    for i in 0..batch_size {
        if !present_flags[i] {
            if i == 0 {
                return Ok(lo);
            }
            // probe[i-1] present, probe[i] absent → answer in (probe[i-1], probe[i]]
            return Box::pin(binary_search_absent_chunk(
                stream_secret,
                probe_indices[i - 1],
                probe_indices[i],
                &probes[i - 1].0,
                &probes[i - 1].1,
                lookup,
            ))
            .await;
        }
    }

    // All probes present → advance lo to last probe
    let new_lo = probe_indices[batch_size - 1];
    if new_lo + 1 >= hi {
        return Ok(hi);
    }
    Box::pin(binary_search_absent_chunk(
        stream_secret,
        new_lo,
        hi,
        &probes[batch_size - 1].0,
        &probes[batch_size - 1].1,
        lookup,
    ))
    .await
}

/// The index of the first chunk not yet present in the writer's champ (the
/// uploaded chunks form a contiguous prefix). `chunk_count` if all are present.
///
/// Uses 8-ary search (`binary_search_absent_chunk`) for O(log₈ N) CHAMP
/// round-trips instead of O(N).
async fn find_first_absent_chunk(
    txn: &FileUploadTransaction,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<u64> {
    let pointer = mutable.get_pointer_target(&txn.owner, &txn.writer.public_key_hash, store.as_ref()).await?;
    let wd_cid = match pointer.updated {
        Some(c) => c,
        None => return Ok(0),
    };
    let wd = store.get(&txn.owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
    let tree_root = Cid::cast(wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("no champ tree".into()))?)?;
    let champ = std::sync::Arc::new(ChampWrapper::create(txn.owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?);
    let n = txn.chunk_count();
    if n == 0 {
        return Ok(0);
    }
    let lookup = |probes: Vec<(Vec<u8>, Option<Bat>)>| {
        let champ = champ.clone();
        Box::pin(async move {
            let mut results = Vec::with_capacity(probes.len());
            for (key, _bat) in &probes {
                results.push(champ.get(key).await.map(|v| v.is_some())?);
            }
            Ok(results)
        }) as Pin<Box<dyn Future<Output = Result<Vec<bool>>>>>
    };
    binary_search_absent_chunk(
        &txn.stream_secret,
        0,
        n,
        &txn.first_map_key,
        &txn.first_bat,
        &lookup,
    )
    .await
}

/// Resume an interrupted upload from its transaction record: upload the missing
/// chunks (from the first absent one), add the file to its parent, and close the
/// transaction. `open` re-yields a reader over the same content.
#[allow(clippy::too_many_arguments)]
pub async fn resume_transaction<R, F>(
    home_cap: &AbsoluteCapability,
    dir_cap: &AbsoluteCapability,
    entry_signer: Option<SigningPrivateKeyAndPublicHash>,
    txn: &FileUploadTransaction,
    mirror_bat: Option<&BatId>,
    open: F,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<AbsoluteCapability>
where
    R: std::io::Read,
    F: Fn() -> std::io::Result<R>,
{
    let _ = &entry_signer; // the transaction records the parent's writer directly
    let start = find_first_absent_chunk(txn, &store, mutable).await? as usize;
    // The record only stored chunk 0's hash-tree branch, which is the whole tree for
    // files up to 1024 chunks. For larger files, recompute the tree from the source
    // so every branch (one per 1024 chunks) is set on the resumed chunks.
    let n_chunks = txn.chunk_count() as usize;
    let tree = if n_chunks > 1024 {
        let chunk_size = retrieve::CHUNK_MAX_SIZE as usize;
        let mut reader = open().map_err(|e| Error::Protocol(format!("open error: {e}")))?;
        let mut buf = vec![0u8; chunk_size];
        let mut chunk_hashes = Vec::with_capacity(n_chunks);
        for i in 0..n_chunks {
            let want = if i + 1 == n_chunks { (txn.size as usize) - i * chunk_size } else { chunk_size };
            read_exact(&mut reader, &mut buf[..want])?;
            chunk_hashes.push(peergos_crypto::hash::sha256(&buf[..want]));
        }
        Some(hashtree::HashTree::build(&chunk_hashes)?)
    } else {
        None
    };
    upload_txn_chunks(dir_cap, txn, tree.as_ref(), start, mirror_bat, &open, &store, mutable).await?;
    let file_cap = add_file_child_link(dir_cap, Some(txn.writer.clone()), mirror_bat, txn, &store, mutable).await?;
    close_transaction_record(home_cap, &txn.name, store, mutable).await?;
    Ok(file_cap)
}

/// Clean up a failed upload (`Transaction.clear`): delete its partial chunks from
/// the writer's champ and remove the transaction record.
pub async fn clear_transaction(
    home_cap: &AbsoluteCapability,
    txn: &FileUploadTransaction,
    store: Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<()> {
    let owner = &txn.owner;
    let signer = &txn.writer;
    let pointer = mutable.get_pointer_target(owner, &signer.public_key_hash, store.as_ref()).await?;
    if let Some(wd_cid) = pointer.updated.clone() {
        let base_wd = store.get(owner, &wd_cid, None).await?.ok_or_else(|| Error::Protocol("writer data missing".into()))?;
        let tree_root = Cid::cast(base_wd.get("tree").and_then(|c| c.as_link()).ok_or_else(|| Error::Protocol("no champ tree".into()))?)?;
        let mut champ = ChampWrapper::create(owner.clone(), tree_root, None, store.clone(), identity_key_hasher()).await?;
        let tid = store.start_transaction(owner).await?;
        let mut map_key = txn.first_map_key.clone();
        let mut bat = txn.first_bat.clone();
        let mut modified = false;
        for _ in 0..txn.chunk_count() {
            if let Some(cur) = champ.get(&map_key).await? {
                champ.remove(signer, &map_key, &Some(cur), &tid).await?;
                modified = true;
            }
            let (nmk, nbat) = retrieve::calculate_next_map_key(&txn.stream_secret, &map_key, &bat)?;
            map_key = nmk;
            bat = nbat;
        }
        if modified {
            let new_wd = writer_data_with_tree(&base_wd, champ.root_hash())?;
            let new_wd_cid = put_block_signed(store.as_ref(), owner, signer, new_wd.to_bytes(), &tid).await?;
            let update = PointerUpdate::new(Some(wd_cid), Some(new_wd_cid), PointerUpdate::increment(pointer.sequence));
            mutable.set_pointer_update(owner, signer, &update).await?;
        }
        store.close_transaction(owner, &tid).await?;
    }
    close_transaction_record(home_cap, &txn.name, store, mutable).await
}

#[cfg(test)]
mod tests;
