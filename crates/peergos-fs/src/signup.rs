//! User signup (`UserContext.signUp`), ported from `peergos.shared.user`.
//!
//! Signup atomically registers a new user by building **all** the initial blocks,
//! champ nodes, WriterData and mutable pointers locally into an [`OpLog`], then
//! POSTing that single log — together with the username claim chain and a
//! proof-of-work — to the PKI's `core/signup` endpoint, which applies it as one
//! transaction.
//!
//! All new accounts are **post-quantum** (`SecretGenerationAlgorithm.getDefault`,
//! scrypt `outputBytes = 64`): the password derives only the login signing key
//! and the root key. The identity signing key is a fresh random keypair, and the
//! boxing key is a fresh **hybrid Curve25519 + ML-KEM-1024** keypair. The
//! (encrypted) entry points — carrying the identity and boxing keypairs — are
//! served via the login server, not stored inline in `WriterData`. Legacy
//! (Curve25519-only) signups are intentionally not supported. [`crate::login`]
//! reads the entry points back over the modern login path.
//!
//! Structure built (owner throughout is the identity key hash):
//!  - a random **writer** subspace holding the user's home directory cryptree
//!    (an entry point, so its node carries a `SymmetricLinkToSigner`);
//!  - the **identity** `WriterData`: scrypt algorithm, hybrid boxing-key hash and
//!    an owned-key champ authorising the writer (no inline entry points);
//!  - the encrypted entry points as `OpLog` login data;
//!  - the special directories `shared`, `.transactions`, `.capabilitycache`;
//!  - a mirror BAT.

use crate::capability::AbsoluteCapability;
use crate::cryptree::{
    CryptreeNode, FileProperties, PaddedCipherText, RelativeCapability as RelCap,
    BASE_BLOCK_PADDING_BLOCKSIZE, META_DATA_PADDING_BLOCKSIZE,
};
use crate::{now_epoch, random_symmetric_key, ChildrenLinks};
use async_trait::async_trait;
use peergos_cbor::{CborObject, Cborable};
use peergos_core::auth::{Bat, BatId, BatWithId};
use peergos_core::error::{Error, Result};
use peergos_core::keys::{PublicKeyHash, PublicSigningKey, SigningKeyPair, SigningPrivateKeyAndPublicHash};
use peergos_core::mutable::{MutablePointers, PointerUpdate, SignedPointerUpdate};
use peergos_core::poster::HttpPoster;
use peergos_core::storage::{
    hash_to_cid, put_block_signed, ContentAddressedStorage, TransactionId,
};
use peergos_core::symmetric::{CipherText, SymmetricKey};
use peergos_core::{identity_key_hasher, Champ, ChampWrapper};
use peergos_crypto::sign::keypair_from_seed;
use peergos_crypto::{boxing, random_bytes};
use peergos_multiformats::Cid;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CORE_URL: &str = "peergos/v0/core/";
const BATS_ADD_PATH: &str = "peergos/v0/bats/addBat";
const CURVE25519: i64 = 0x1;
const HYBRID_CURVE25519_MLKEM: i64 = 0x2;
const USER_STATIC_DATA_PADDING: usize = 4096;
const ENTRY_POINTS_VERSION: i64 = 2;

// ---------------------------------------------------------------------------
// In-memory OpLog storage
// ---------------------------------------------------------------------------

#[derive(Default)]
struct OpLogInner {
    blocks: HashMap<Vec<u8>, Vec<u8>>,
    /// Recorded operations, in order, as `BlockWrite`/`PointerWrite` cbor maps.
    ops: Vec<CborObject>,
    /// Latest signed CAS per writer (keyed by writer key-hash string).
    pointers: HashMap<String, Vec<u8>>,
    /// The mirror BAT: `(BatWithId cbor, signed auth)`.
    mirror_bat: Option<(CborObject, Vec<u8>)>,
    /// The login data: `(LoginData cbor, signed auth)` — modern accounts only.
    login_data: Option<(CborObject, Vec<u8>)>,
}

/// An in-memory [`ContentAddressedStorage`] + [`MutablePointers`] that records
/// every write into an [`OpLog`] for atomic signup (`corenode.OpLog`).
pub struct OpLogStore {
    inner: Mutex<OpLogInner>,
}

impl OpLogStore {
    fn new() -> OpLogStore {
        OpLogStore { inner: Mutex::new(OpLogInner::default()) }
    }

    fn record_block(&self, writer: &PublicKeyHash, signature: &[u8], block: Vec<u8>, is_raw: bool) -> Cid {
        let cid = hash_to_cid(&block, is_raw).expect("cid");
        let key = cid.to_bytes();
        let mut g = self.inner.lock().unwrap();
        if !g.blocks.contains_key(&key) {
            let op = CborObject::map()
                .put("w", writer.to_cbor())
                .put("s", CborObject::ByteString(signature.to_vec()))
                .put("b", CborObject::ByteString(block.clone()))
                .put("r", CborObject::Boolean(is_raw))
                .build();
            g.ops.push(op);
            g.blocks.insert(key, block);
        }
        cid
    }

    fn set_mirror_bat(&self, bat_with_id: CborObject, auth: Vec<u8>) {
        self.inner.lock().unwrap().mirror_bat = Some((bat_with_id, auth));
    }

    fn set_login_data(&self, login: CborObject, auth: Vec<u8>) {
        self.inner.lock().unwrap().login_data = Some((login, auth));
    }

    /// Serialize the accumulated operations as an `OpLog` cbor map.
    fn to_oplog_cbor(&self) -> CborObject {
        let g = self.inner.lock().unwrap();
        let mut b = CborObject::map().put("ops", CborObject::List(g.ops.clone()));
        if let Some((login, auth)) = &g.login_data {
            b = b.put("login", login.clone()).put("loginAuth", CborObject::ByteString(auth.clone()));
        }
        if let Some((bat, auth)) = &g.mirror_bat {
            b = b.put("b", bat.clone()).put("a", CborObject::ByteString(auth.clone()));
        }
        b.build()
    }
}

#[async_trait]
impl ContentAddressedStorage for OpLogStore {
    async fn id(&self) -> Result<Cid> {
        Err(Error::Protocol("OpLogStore has no id".into()))
    }
    async fn ids(&self) -> Result<Vec<Cid>> {
        Ok(Vec::new())
    }
    async fn start_transaction(&self, _owner: &PublicKeyHash) -> Result<TransactionId> {
        Ok(TransactionId("1".into()))
    }
    async fn close_transaction(&self, _owner: &PublicKeyHash, _tid: &TransactionId) -> Result<bool> {
        Ok(true)
    }
    async fn get(&self, _owner: &PublicKeyHash, hash: &Cid, _bat: Option<&BatWithId>) -> Result<Option<CborObject>> {
        let raw = self.inner.lock().unwrap().blocks.get(&hash.to_bytes()).cloned();
        match raw {
            Some(bytes) => Ok(Some(CborObject::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }
    async fn get_raw(&self, _owner: &PublicKeyHash, hash: &Cid, _bat: Option<&BatWithId>) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().unwrap().blocks.get(&hash.to_bytes()).cloned())
    }
    async fn put(
        &self,
        _owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        _tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        Ok(blocks
            .into_iter()
            .zip(signed_hashes)
            .map(|(block, sig)| self.record_block(writer, &sig, block, false))
            .collect())
    }
    async fn put_raw(
        &self,
        _owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        signed_hashes: Vec<Vec<u8>>,
        blocks: Vec<Vec<u8>>,
        _tid: &TransactionId,
    ) -> Result<Vec<Cid>> {
        Ok(blocks
            .into_iter()
            .zip(signed_hashes)
            .map(|(block, sig)| self.record_block(writer, &sig, block, true))
            .collect())
    }
    async fn get_size(&self, _owner: &PublicKeyHash, _block: &peergos_multiformats::Multihash) -> Result<Option<u64>> {
        Ok(None)
    }
    async fn get_secret_link(&self, _owner: &PublicKeyHash, _label: &str) -> Result<CborObject> {
        Err(Error::Protocol("OpLogStore has no secret links".into()))
    }
}

#[async_trait]
impl MutablePointers for OpLogStore {
    async fn set_pointer(
        &self,
        _owner: &PublicKeyHash,
        writer: &PublicKeyHash,
        writer_signed_payload: Vec<u8>,
    ) -> Result<bool> {
        let op = CborObject::map()
            .put("w", writer.to_cbor())
            .put("s", CborObject::ByteString(writer_signed_payload.clone()))
            .build();
        let mut g = self.inner.lock().unwrap();
        g.ops.push(op);
        g.pointers.insert(writer.to_string(), writer_signed_payload);
        Ok(true)
    }
    async fn set_pointers(&self, owner: &PublicKeyHash, updates: Vec<SignedPointerUpdate>) -> Result<bool> {
        for u in updates {
            self.set_pointer(owner, &u.writer, u.signed).await?;
        }
        Ok(true)
    }
    async fn get_pointer(&self, _owner: &PublicKeyHash, writer: &PublicKeyHash) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().unwrap().pointers.get(&writer.to_string()).cloned())
    }
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

/// `Serialize.serialize(byte[])`: 4-byte big-endian length prefix, then bytes.
fn serialize_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// `Serialize.serialize(String)`: 4-byte big-endian char count, then UTF-8 bytes.
fn serialize_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.chars().count() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// A random ed25519 signing keypair with an inline (identity-multihash) key hash.
fn random_signer() -> Result<(SigningKeyPair, SigningPrivateKeyAndPublicHash)> {
    let (public, secret64) = keypair_from_seed(&random_bytes(32))?;
    let pair = SigningKeyPair {
        public: PublicSigningKey::new(public.to_vec()),
        secret: peergos_core::keys::SecretSigningKey::new(secret64.to_vec()),
    };
    let hash = PublicKeyHash::identity(pair.public.serialize())?;
    let priv_hash = SigningPrivateKeyAndPublicHash::new(hash, pair.secret.clone());
    Ok((pair, priv_hash))
}

/// Build the default `ScryptGenerator` cbor (memory 17, output 64 → post-quantum
/// account: separate identity key + hybrid boxer + root key from the password).
fn default_algorithm_cbor(extra_salt: &str) -> CborObject {
    CborObject::map()
        .put("type", CborObject::Long(0x1)) // Scrypt
        .put("c", CborObject::Long(8))
        .put("m", CborObject::Long(17))
        .put("o", CborObject::Long(64))
        .put("p", CborObject::Long(1))
        .put("s", CborObject::Str(extra_salt.to_string()))
        .build()
}

/// A fresh hybrid Curve25519+ML-KEM-1024 boxing keypair
/// (`BoxingKeyPair.randomHybrid`), returning its `(public, keypair)` cbor.
fn random_hybrid_boxer() -> (CborObject, CborObject) {
    let (curve_pub, curve_sec) = boxing::random_keypair();
    let (mlkem_pub, mlkem_sec) = boxing::mlkem_keypair();
    let curve_pub_cbor = CborObject::List(vec![
        CborObject::Long(CURVE25519),
        CborObject::ByteString(curve_pub.to_vec()),
    ]);
    let curve_sec_cbor = CborObject::List(vec![
        CborObject::Long(CURVE25519),
        CborObject::ByteString(curve_sec.to_vec()),
    ]);
    let mlkem_pub_cbor = CborObject::map().put("p", CborObject::ByteString(mlkem_pub)).build();
    let mlkem_sec_cbor = CborObject::map().put("s", CborObject::ByteString(mlkem_sec)).build();
    // Hybrid keys: List[type=2, {c: curve, m: mlkem}]
    let public = CborObject::List(vec![
        CborObject::Long(HYBRID_CURVE25519_MLKEM),
        CborObject::map().put("c", curve_pub_cbor).put("m", mlkem_pub_cbor).build(),
    ]);
    let secret = CborObject::List(vec![
        CborObject::Long(HYBRID_CURVE25519_MLKEM),
        CborObject::map().put("c", curve_sec_cbor).put("m", mlkem_sec_cbor).build(),
    ]);
    let keypair = CborObject::List(vec![public.clone(), secret]);
    (public, keypair)
}

/// Assemble a `WriterData` cbor map (only the fields we populate).
fn writer_data_cbor(
    controller: &PublicKeyHash,
    algorithm: Option<CborObject>,
    follow_receiver: Option<&PublicKeyHash>,
    owned: Option<&Cid>,
    static_data: Option<CborObject>,
    tree: Option<&Cid>,
) -> CborObject {
    let mut b = CborObject::map().put("controller", controller.to_cbor());
    if let Some(a) = algorithm {
        b = b.put("algorithm", a);
    }
    if let Some(f) = follow_receiver {
        b = b.put("inbound", f.to_cbor());
    }
    if let Some(o) = owned {
        b = b.put("owned", CborObject::MerkleLink(o.to_bytes()));
    }
    if let Some(sd) = static_data {
        b = b.put("static", sd);
    }
    if let Some(t) = tree {
        b = b.put("tree", CborObject::MerkleLink(t.to_bytes()));
    }
    b.build()
}

/// Create an empty champ, returning its root CID (written into `store`).
async fn create_empty_champ(
    store: &Arc<dyn ContentAddressedStorage>,
    owner: &PublicKeyHash,
    writer: &SigningPrivateKeyAndPublicHash,
    tid: &TransactionId,
) -> Result<Cid> {
    put_block_signed(store.as_ref(), owner, writer, Champ::empty().serialize(), tid).await
}

/// The civil date `days` after the unix epoch, formatted `YYYY-MM-DD`
/// (Howard Hinnant's days→civil algorithm).
fn epoch_days_to_date(days: i64) -> String {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Build the single-link username claim chain (`UserPublicKeyLink.createInitial`).
fn build_claim_chain(
    identity: &SigningPrivateKeyAndPublicHash,
    username: &str,
    expiry: &str,
    storage_provider: &Cid,
) -> Result<CborObject> {
    // Claim.build payload: serialize(username) + serialize(expiry) + writeInt(n) + serialize(provider)
    let mut payload = Vec::new();
    serialize_string(&mut payload, username);
    serialize_string(&mut payload, expiry);
    payload.extend_from_slice(&1u32.to_be_bytes());
    serialize_bytes(&mut payload, &storage_provider.to_bytes());
    let signed = identity.secret.sign_message(&payload)?;

    let claim = CborObject::List(vec![
        CborObject::Str(username.to_string()),
        CborObject::Str(expiry.to_string()),
        CborObject::List(vec![CborObject::ByteString(storage_provider.to_bytes())]),
        CborObject::ByteString(signed),
    ]);
    Ok(CborObject::map()
        .put("owner", identity.public_key_hash.to_cbor())
        .put("claim", claim)
        .build())
}

/// Sign up `username` with `password` against the Peergos server behind `poster`.
///
/// Creates a **post-quantum** account: scrypt derives the login signing key and
/// the root key from the password; the identity signing key and the hybrid
/// Curve25519+ML-KEM-1024 boxing key are fresh random keypairs stored (encrypted
/// with the root key) in the login data served by the account endpoint.
///
/// `token` is the optional signup token (invite/registration token) some servers
/// require. `real_store` is the live server storage (used only for its node id).
/// On success the account exists and can be logged in.
pub async fn signup(
    username: &str,
    password: &str,
    token: Option<&str>,
    poster: &dyn HttpPoster,
    real_store: &dyn ContentAddressedStorage,
) -> Result<()> {
    if password == username {
        return Err(Error::Protocol("Your password cannot be the same as your username!".into()));
    }
    // Default scrypt: 64 output bytes → login signing key(32) ‖ root key(32).
    let extra_salt = hex(&random_bytes(32)); // SecretGenerationAlgorithm.getDefault salt
    let key_bytes = peergos_crypto::hash::hash_to_key_bytes(
        &format!("{username}{extra_salt}"),
        password,
        17,
        8,
        1,
        64,
    )?;
    // The login key is only needed as the authorised reader (public); its secret
    // is re-derived from the password at login time, never stored.
    let (login_public, _) = keypair_from_seed(&key_bytes[0..32])?;
    let login_pub = PublicSigningKey::new(login_public.to_vec());
    let root_key = SymmetricKey::new(key_bytes[32..64].to_vec(), false)?;

    // The identity is a fresh random signing keypair (inline hash).
    let (identity_pair, identity) = random_signer()?;
    let identity_hash = identity.public_key_hash.clone();

    // A fresh hybrid Curve25519+ML-KEM-1024 boxing keypair; its (large) public
    // key is stored as a block, referenced by hash from the identity WriterData.
    let (boxer_public_cbor, boxer_keypair_cbor) = random_hybrid_boxer();

    // The mirror BAT.
    let mirror = Bat::new(random_bytes(32))?;
    let mirror_id = mirror.calculate_id()?;

    let oplog = Arc::new(OpLogStore::new());
    let store: Arc<dyn ContentAddressedStorage> = oplog.clone();
    let tid = TransactionId("1".into());

    // The hybrid boxing public key is too large to inline: store it as a block
    // signed by the identity, and reference it from the identity WriterData.
    let boxer_hash = PublicKeyHash::new(
        put_block_signed(store.as_ref(), &identity_hash, &identity, boxer_public_cbor.to_bytes(), &tid).await?,
    )?;

    // --- 1. The home directory's writer subspace ------------------------------
    let (_writer_kp, writer) = random_signer()?;
    let root_map_key = random_bytes(32);
    let root_bat = Bat::new(random_bytes(32))?;
    let root_r_key = random_symmetric_key()?;
    let root_w_key = loop {
        let k = random_symmetric_key()?;
        if k != root_r_key {
            break k;
        }
    };
    let epoch = now_epoch();

    // Home dir cryptree node (an entry point: carries a SymmetricLinkToSigner).
    let parent_key = loop {
        let k = random_symmetric_key()?;
        if k != root_r_key {
            break k;
        }
    };
    let writer_link = CipherText::build(&root_w_key, &writer)?.to_cbor();
    let next_chunk =
        RelCap::subsequent_chunk(random_bytes(32), Some(Bat::new(random_bytes(32))?), root_r_key.clone());
    let from_base = CborObject::map()
        .put("k", parent_key.to_cbor())
        .put("w", writer_link)
        .put("n", next_chunk.to_cbor())
        .build();
    let props = FileProperties::new_directory(username.to_string(), epoch);
    let from_parent = CborObject::map().put("s", props.to_cbor()).build();
    let empty_children = crate::retrieve::FragmentedPaddedCipherText::build_inline(
        &root_r_key,
        &ChildrenLinks::Named(Vec::new()).to_cbor(),
        crate::retrieve::MIN_FRAGMENT_SIZE,
    )?;
    let home_node = CryptreeNode::new(
        true,
        vec![BatId::inline(&root_bat)?.to_cbor(), mirror_id.to_cbor()],
        PaddedCipherText::build(&root_r_key, &from_base, BASE_BLOCK_PADDING_BLOCKSIZE)?,
        PaddedCipherText::build(&parent_key, &from_parent, META_DATA_PADDING_BLOCKSIZE)?,
        empty_children.to_cbor(),
    );
    let home_node_cid =
        put_block_signed(store.as_ref(), &identity_hash, &writer, home_node.to_cbor().to_bytes(), &tid).await?;

    // Writer's owned-key champ (empty) and filesystem champ (home dir under rootMapKey).
    let writer_owned_root = create_empty_champ(&store, &identity_hash, &writer, &tid).await?;
    let fs_empty_root = create_empty_champ(&store, &identity_hash, &writer, &tid).await?;
    let mut fs_champ =
        ChampWrapper::create(identity_hash.clone(), fs_empty_root, None, store.clone(), identity_key_hasher())
            .await?;
    fs_champ
        .put(&writer, &root_map_key, &None, Some(CborObject::MerkleLink(home_node_cid.to_bytes())), &tid)
        .await?;
    let fs_tree_root = fs_champ.root_hash().clone();

    let writer_wd = writer_data_cbor(
        &writer.public_key_hash,
        None,
        None,
        Some(&writer_owned_root),
        None,
        Some(&fs_tree_root),
    );
    let writer_wd_cid =
        put_block_signed(store.as_ref(), &identity_hash, &writer, writer_wd.to_bytes(), &tid).await?;
    let writer_update = PointerUpdate::new(None, Some(writer_wd_cid), PointerUpdate::increment(None));
    oplog.set_pointer_update(&identity_hash, &writer, &writer_update).await?;

    // --- 2. Authorise the writer as an owned key of the identity --------------
    let signed_owner = writer.secret.sign_message(&identity_hash.to_cbor().to_bytes())?;
    let owner_proof = CborObject::map()
        .put("o", writer.public_key_hash.to_cbor())
        .put("p", CborObject::ByteString(signed_owner))
        .build();
    let proof_cid = put_block_signed(store.as_ref(), &identity_hash, &identity, owner_proof.to_bytes(), &tid).await?;
    let id_owned_empty = create_empty_champ(&store, &identity_hash, &identity, &tid).await?;
    let mut owned_champ =
        ChampWrapper::create(identity_hash.clone(), id_owned_empty, None, store.clone(), identity_key_hasher())
            .await?;
    // OwnedKeyChamp keys are the reversed serialized key hash.
    let mut owned_key = writer.public_key_hash.to_cbor().to_bytes();
    owned_key.reverse();
    owned_champ
        .put(&identity, &owned_key, &None, Some(CborObject::MerkleLink(proof_cid.to_bytes())), &tid)
        .await?;
    let id_owned_root = owned_champ.root_hash().clone();

    // --- 3. The identity WriterData + login data ------------------------------
    let root_cap = AbsoluteCapability::new(
        identity_hash.clone(),
        writer.public_key_hash.clone(),
        root_map_key.clone(),
        Some(root_bat.clone()),
        root_r_key.clone(),
        Some(root_w_key.clone()),
    )?;
    let entry_point = CborObject::map()
        .put("c", root_cap.to_cbor())
        .put("n", CborObject::Str(username.to_string()))
        .build();
    // Modern entry points carry the identity signing keypair and the boxing
    // keypair, so a fresh login can recover them (`EntryPoints` v2, i + b).
    let entry_points = CborObject::map()
        .put("v", CborObject::Long(ENTRY_POINTS_VERSION))
        .put("e", CborObject::List(vec![entry_point]))
        .put("b", boxer_keypair_cbor)
        .put("i", identity_pair.to_cbor())
        .build();
    let static_data = PaddedCipherText::build(&root_key, &entry_points, USER_STATIC_DATA_PADDING)?.to_cbor();

    // The identity WriterData has NO inline static data (post-quantum accounts
    // store the entry points via the login server instead).
    let identity_wd = writer_data_cbor(
        &identity_hash,
        Some(default_algorithm_cbor(&extra_salt)),
        Some(&boxer_hash),
        Some(&id_owned_root),
        None,
        None,
    );
    let identity_wd_cid =
        put_block_signed(store.as_ref(), &identity_hash, &identity, identity_wd.to_bytes(), &tid).await?;
    let identity_update = PointerUpdate::new(None, Some(identity_wd_cid), PointerUpdate::increment(None));
    oplog.set_pointer_update(&identity_hash, &identity, &identity_update).await?;

    // Login data: the encrypted entry points, authorised by the login key,
    // signed by the identity. Served by the account endpoint on login.
    let login_data = CborObject::map()
        .put("u", CborObject::Str(username.to_string()))
        .put("e", static_data)
        .put("r", login_pub.to_cbor())
        .build();
    let login_auth = identity.secret.signature_only(&login_data.to_bytes())?;
    oplog.set_login_data(login_data, login_auth);

    // --- 4. The mirror BAT ----------------------------------------------------
    let bat_with_id = BatWithId::new(mirror.clone(), mirror_id.id.clone())?;
    let bat_auth = sign_time_limited(&identity, BATS_ADD_PATH)?;
    oplog.set_mirror_bat(bat_with_id.to_cbor(), bat_auth);

    // --- 5. The special directories -------------------------------------------
    for dir in ["shared", ".transactions", ".capabilitycache"] {
        crate::create_directory(&root_cap, dir, Some(writer.clone()), Some(&mirror_id), store.clone(), oplog.as_ref()).await?;
    }

    // --- 6. Username claim chain + proof of work, then POST signup -------------
    let server_id = real_store.id().await?;
    let expiry = epoch_days_to_date(now_epoch() / 86400 + 60);
    let chain_link = build_claim_chain(&identity, username, &expiry, &server_id)?;
    let chain_bytes = chain_link.to_bytes();

    let pow_data = CborObject::List(vec![chain_link.clone()]).to_bytes();
    let oplog_bytes = oplog.to_oplog_cbor().to_bytes();
    let token = token.unwrap_or("");

    // Proof-of-work with retry: the server rejects a too-easy proof and replies
    // with the required difficulty (`signupWithRetry`); recompute and resend.
    let mut difficulty = 0i32;
    for _ in 0..3 {
        let prefix = peergos_crypto::hash::generate_proof_of_work(difficulty, &pow_data);
        let proof = CborObject::map()
            .put("prefix", CborObject::ByteString(prefix))
            .put("type", CborObject::Long(0x12)) // sha2-256
            .build();
        match post_signup(poster, username, &chain_bytes, &oplog_bytes, &proof.to_bytes(), token).await? {
            None => return Ok(()),
            Some(required) => difficulty = required,
        }
    }
    Err(Error::Protocol("Signup rejected: server is under load, please try again later".into()))
}

/// Lowercase hex encoding (`ArrayOps.bytesToHex`).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Sign a `TimeLimitedClient.SignedRequest{path, now}` with `identity` (attached).
fn sign_time_limited(identity: &SigningPrivateKeyAndPublicHash, path: &str) -> Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let req = CborObject::map()
        .put("p", CborObject::Str(path.to_string()))
        .put("t", CborObject::Long(now))
        .build();
    identity.secret.sign_message(&req.to_bytes())
}

/// POST the signup log to `core/signup`. Returns `Ok(None)` on success, or
/// `Ok(Some(difficulty))` if the server wants a stronger proof of work (retry).
async fn post_signup(
    poster: &dyn HttpPoster,
    username: &str,
    chain: &[u8],
    oplog: &[u8],
    proof: &[u8],
    token: &str,
) -> Result<Option<i32>> {
    let mut body = Vec::new();
    serialize_string(&mut body, username);
    serialize_bytes(&mut body, chain);
    serialize_bytes(&mut body, oplog);
    serialize_bytes(&mut body, proof);
    serialize_string(&mut body, token);
    let res = match poster.post_unzip(&format!("{CORE_URL}signup"), body, 60_000).await {
        Ok(res) => res,
        // A 4xx carries the server's reason in the `Trailer` header (surfaced by
        // the poster). An empty reason on a taken username means "already exists".
        Err(Error::Http(msg)) if msg.starts_with("status 4") => {
            let reason = msg.splitn(2, ':').nth(1).map(str::trim).unwrap_or("");
            if reason.is_empty() {
                return Err(Error::Protocol(format!("Signup failed: username '{username}' already exists")));
            }
            return Err(Error::Protocol(format!("Signup failed for '{username}': {reason}")));
        }
        Err(e) => return Err(e),
    };
    // Response: readBoolean success; if false, readInt = required difficulty.
    if res.first().is_some_and(|b| *b != 0) {
        Ok(None)
    } else if res.len() >= 5 {
        Ok(Some(i32::from_be_bytes([res[1], res[2], res[3], res[4]])))
    } else {
        Err(Error::Protocol("signup rejected by server".into()))
    }
}
