//! In-process mock Peergos server: a [`MockPoster`] implementing [`HttpPoster`],
//! backed by in-memory state, enough to run the client's tests without a live Java
//! server. Every server call the client makes goes through `HttpPoster::{get,post}`,
//! so we parse the URL + body and service it from memory. See `server.md`.
//!
//! This module currently covers the **storage** endpoints (blocks, champ lookup,
//! transactions, id). Mutable pointers, signup/login, social, etc. are layered on
//! in later milestones.

use async_trait::async_trait;
use peergos_cbor::{Cborable, CborObject};
use peergos_core::error::{Error, Result};
use peergos_core::keys::PublicKeyHash;
use peergos_core::mutable::{PointerUpdate, SignedPointerUpdate, MUTABLE_POINTERS_URL};
use peergos_core::poster::HttpPoster;
use peergos_core::storage::{
    champ_lookup_local, BlockWriteGroup, ChunkMirrorCap, ContentAddressedStorage, TransactionId,
    API_PREFIX,
};
use peergos_core::{build_cid, hash_to_cid, RamStorage};
use peergos_multiformats::Cid;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The in-memory state behind a mock server. Cheap to clone (`Arc`-shared), so a
/// single server can back a client's store, mutable pointers, and poster at once.
#[derive(Clone)]
pub struct MockServer {
    /// Content-addressed blocks (its own interior `Mutex`, so no lock is held
    /// across an await).
    blocks: Arc<RamStorage>,
    /// Mutable pointers: (owner, writer) → the last signed CAS payload.
    pointers: Arc<Mutex<HashMap<(Vec<u8>, Vec<u8>), Vec<u8>>>>,
    /// Registered accounts, keyed by username.
    accounts: Arc<Mutex<HashMap<String, Account>>>,
    /// A stable fake node identity.
    server_id: Cid,
}

/// A registered user: their identity key hash, login data (encrypted entry
/// points, served by `getLogin`), and mirror BATs.
#[derive(Clone)]
struct Account {
    identity: PublicKeyHash,
    login: CborObject,
    bats: Vec<CborObject>,
}

impl Default for MockServer {
    fn default() -> Self {
        MockServer::new()
    }
}

impl MockServer {
    pub fn new() -> MockServer {
        MockServer {
            blocks: Arc::new(RamStorage::new()),
            pointers: Arc::new(Mutex::new(HashMap::new())),
            accounts: Arc::new(Mutex::new(HashMap::new())),
            // A deterministic non-identity CID; its Display round-trips through the
            // client's `Cid::decode_peer_id`.
            server_id: build_cid(vec![7u8; 32], false).expect("server id"),
        }
    }

    /// A [`HttpPoster`] backed by this server, to hand to the client in place of a
    /// real HTTP poster.
    pub fn poster(&self) -> Arc<dyn HttpPoster> {
        Arc::new(MockPoster { server: self.clone() })
    }

    /// The `(poster, store, mutable)` a client needs, all backed by this server —
    /// drop-in for the `ReqwestPoster` + `HttpStorage` + `HttpMutablePointers` trio
    /// the examples build against a live server.
    pub fn connect(
        &self,
    ) -> (Arc<dyn HttpPoster>, Arc<dyn ContentAddressedStorage>, Arc<dyn peergos_core::mutable::MutablePointers>) {
        let poster = self.poster();
        let store: Arc<dyn ContentAddressedStorage> =
            Arc::new(peergos_core::HttpStorage::new(poster.clone(), true));
        let mutable: Arc<dyn peergos_core::mutable::MutablePointers> =
            Arc::new(peergos_core::mutable::HttpMutablePointers::new(poster.clone()));
        (poster, store, mutable)
    }

    // ---- request dispatch -------------------------------------------------

    async fn handle(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let (path, query) = split_url(url);
        let path = path.strip_prefix('/').unwrap_or(path);

        // Storage endpoints (api/v0/…).
        if let Some(rest) = path.strip_prefix(API_PREFIX) {
            return self.handle_storage(rest, &query, body).await;
        }
        // Mutable pointers (peergos/v0/mutable/…).
        if let Some(rest) = path.strip_prefix(MUTABLE_POINTERS_URL) {
            return self.handle_mutable(rest, &query, body);
        }
        // Core / PKI (peergos/v0/core/…).
        if let Some(rest) = path.strip_prefix("peergos/v0/core/") {
            return self.handle_core(rest, body).await;
        }
        // Login (peergos/v0/login/…).
        if let Some(rest) = path.strip_prefix("peergos/v0/login/") {
            return self.handle_login(rest, &query, body);
        }
        // Space usage (peergos/v0/storage/…).
        if let Some(rest) = path.strip_prefix("peergos/v0/storage/") {
            return self.handle_usage(rest, &query).await;
        }
        Err(Error::Http(format!("status 404: mock has no route for {path}")))
    }

    async fn handle_usage(&self, rest: &str, q: &Query) -> Result<Vec<u8>> {
        match rest {
            // A generous fixed quota.
            "quota" => Ok(CborObject::Long(10 * 1024 * 1024 * 1024).to_bytes()),
            "usage" => {
                let owner = q.pkh("owner")?;
                let bytes = self.reachable_usage(&owner).await? as i64;
                Ok(CborObject::Long(bytes).to_bytes())
            }
            other => Err(Error::Http(format!("status 404: mock storage has no route for {other}"))),
        }
    }

    /// Total bytes of the blocks reachable from all of `owner`'s pointers (walking
    /// each WriterData → champ → nodes → fragments, unique blocks only). Because the
    /// client's delete path repoints away from removed blocks, this reproduces the
    /// "delete returns usage to exactly the prior value" property without a real GC.
    async fn reachable_usage(&self, owner: &PublicKeyHash) -> Result<u64> {
        let owner_key = pkh_key(owner);
        let mut stack: Vec<Cid> = Vec::new();
        {
            let map = self.pointers.lock().unwrap();
            for ((o, _w), payload) in map.iter() {
                if *o == owner_key {
                    if let Ok(upd) = parse_pointer_update(payload) {
                        if let Some(cid) = upd.updated {
                            stack.push(cid);
                        }
                    }
                }
            }
        }
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut total = 0u64;
        while let Some(cid) = stack.pop() {
            if !seen.insert(cid.to_bytes()) {
                continue;
            }
            let block = match self.blocks.get_raw(owner, &cid, None).await? {
                Some(b) => b,
                None => continue,
            };
            total += block.len() as u64;
            if !cid.is_raw() {
                if let Ok(cbor) = CborObject::from_bytes(&block) {
                    for link in cbor.links() {
                        if let Ok(c) = Cid::cast(&link) {
                            stack.push(c);
                        }
                    }
                }
            }
        }
        Ok(total)
    }

    async fn handle_core(&self, rest: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        match rest {
            "signup" => {
                // body = serialize(username) bytes(chain) bytes(oplog) bytes(proof) serialize(token)
                let mut r = Reader::new(&body);
                let username = r.string()?;
                let chain = r.bytes()?;
                let oplog = r.bytes()?;
                let _proof = r.bytes()?; // PoW accepted at difficulty 0 for the mock
                let _token = r.string()?;

                if self.accounts.lock().unwrap().contains_key(&username) {
                    // Taken: a 4xx with an empty reason means "already exists" to the client.
                    return Err(Error::Http("status 409: ".into()));
                }
                let identity = PublicKeyHash::from_cbor(
                    CborObject::from_bytes(&chain)?
                        .get("owner")
                        .ok_or_else(|| Error::Protocol("claim chain missing owner".into()))?,
                )?;
                self.apply_oplog(&identity, &username, &oplog).await?;
                Ok(vec![1]) // readBoolean = success
            }
            "getPublicKey" => {
                // body = serialize_string(username); response [bool][len BE][cbor].
                let username = Reader::new(&body).string()?;
                match self.accounts.lock().unwrap().get(&username) {
                    Some(a) => {
                        let cbor = a.identity.to_cbor().to_bytes();
                        let mut out = vec![1u8];
                        out.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
                        out.extend_from_slice(&cbor);
                        Ok(out)
                    }
                    None => Ok(vec![0]),
                }
            }
            other => Err(Error::Http(format!("status 404: mock core has no route for {other}"))),
        }
    }

    /// Apply a signup OpLog: store its block writes, apply its pointer writes (owned
    /// by `identity`), record the login data + mirror BATs, and register the account.
    async fn apply_oplog(&self, identity: &PublicKeyHash, username: &str, oplog: &[u8]) -> Result<()> {
        let log = CborObject::from_bytes(oplog)?;
        let tid = TransactionId("1".into());
        if let Some(CborObject::List(ops)) = log.get("ops").cloned() {
            for op in ops {
                if let Some(block) = op.get("b").and_then(|c| c.as_bytes()) {
                    // Block write: {w, s, b, r}.
                    let is_raw = op.get("r").and_then(|c| c.as_bool()).unwrap_or(false);
                    let (block, writer) = (block.to_vec(), identity.clone());
                    if is_raw {
                        self.blocks.put_raw(identity, &writer, vec![vec![0]], vec![block], &tid).await?;
                    } else {
                        self.blocks.put(identity, &writer, vec![vec![0]], vec![block], &tid).await?;
                    }
                } else if let (Some(w), Some(s)) = (op.get("w"), op.get("s").and_then(|c| c.as_bytes())) {
                    // Pointer write: {w, s}, owned by the identity.
                    let writer = PublicKeyHash::from_cbor(w)?;
                    self.apply_cas(identity, &writer, s.to_vec())?;
                }
            }
        }
        // The oplog `login` is LoginData `{u, e, r}`; getLogin serves its `e`
        // (the UserStaticData / encrypted entry points).
        let login = log.get("login").and_then(|ld| ld.get("e").cloned()).unwrap_or(CborObject::Null);
        let bats = log.get("b").cloned().into_iter().collect();
        self.accounts
            .lock()
            .unwrap()
            .insert(username.to_string(), Account { identity: identity.clone(), login, bats });
        Ok(())
    }

    fn handle_login(&self, rest: &str, q: &Query, body: Vec<u8>) -> Result<Vec<u8>> {
        match rest {
            "getLogin" => {
                let username = q.get("username").unwrap_or_default();
                let accounts = self.accounts.lock().unwrap();
                let login = accounts
                    .get(username)
                    .map(|a| a.login.clone())
                    .ok_or_else(|| Error::Http("status 404: no such user".into()))?;
                // LoginResponse: {a: authorized (no MFA needed), r: UserStaticData}.
                Ok(CborObject::map().put("a", CborObject::Boolean(true)).put("r", login).build().to_bytes())
            }
            "setLogin" => {
                // body = LoginData `{u: username, e: UserStaticData, r: login_pub}`.
                let data = CborObject::from_bytes(&body)?;
                let username = data.get("u").and_then(|c| c.as_string()).unwrap_or_default().to_string();
                let new_static = data.get("e").cloned().unwrap_or(CborObject::Null);
                let mut accounts = self.accounts.lock().unwrap();
                match accounts.get_mut(&username) {
                    Some(a) => {
                        a.login = new_static;
                        Ok(vec![1])
                    }
                    None => Err(Error::Http("status 404: no such user".into())),
                }
            }
            other => Err(Error::Http(format!("status 404: mock login has no route for {other}"))),
        }
    }

    fn handle_mutable(&self, rest: &str, q: &Query, body: Vec<u8>) -> Result<Vec<u8>> {
        match rest {
            "getPointer" => {
                let key = (pkh_key(&q.pkh("owner")?), pkh_key(&q.pkh("writer")?));
                Ok(self.pointers.lock().unwrap().get(&key).cloned().unwrap_or_default())
            }
            "setPointer" => {
                let owner = q.pkh("owner")?;
                let writer = q.pkh("writer")?;
                Ok(vec![self.apply_cas(&owner, &writer, body)? as u8])
            }
            "setPointers" => {
                // body = MultiWriterCommit `{p:[SignedPointerUpdate]}`; all-or-nothing.
                let owner = q.pkh("owner")?;
                let updates = match CborObject::from_bytes(&body)?.get("p").and_then(|c| c.as_list().map(|l| l.to_vec())) {
                    Some(list) => list.iter().map(SignedPointerUpdate::from_cbor).collect::<Result<Vec<_>>>()?,
                    None => Vec::new(),
                };
                let mut ok = true;
                for u in updates {
                    ok &= self.apply_cas(&owner, &u.writer, u.signed)?;
                }
                Ok(vec![ok as u8])
            }
            other => Err(Error::Http(format!("status 404: mock mutable has no route for {other}"))),
        }
    }

    /// Apply a signed CAS pointer update: accept iff its `original` matches the
    /// writer's current target, then store the new signed payload. Returns whether
    /// it was accepted (a rejected CAS drives the client's 3-way merge path).
    fn apply_cas(&self, owner: &PublicKeyHash, writer: &PublicKeyHash, signed: Vec<u8>) -> Result<bool> {
        let new = parse_pointer_update(&signed)?;
        let key = (pkh_key(owner), pkh_key(writer));
        let mut map = self.pointers.lock().unwrap();
        let current_target = match map.get(&key) {
            Some(p) => parse_pointer_update(p)?.updated,
            None => None,
        };
        if new.original != current_target {
            return Ok(false);
        }
        map.insert(key, signed);
        Ok(true)
    }

    async fn handle_storage(&self, rest: &str, q: &Query, body: Vec<u8>) -> Result<Vec<u8>> {
        match rest {
            "id" => Ok(format!("{{\"ID\":\"{}\"}}", self.server_id).into_bytes()),
            "ids" => Ok(format!("[\"{}\"]", self.server_id).into_bytes()),
            "transaction/start" => Ok(b"1".to_vec()),
            "transaction/close" => Ok(b"true".to_vec()),

            "block/put/bulk" => {
                let owner = q.pkh("owner")?;
                let writer = q.pkh("writer")?;
                let is_raw = q.get("format") == Some("raw");
                let group = BlockWriteGroup::from_cbor(&CborObject::from_bytes(&body)?)?;
                let tid = TransactionId("1".into());
                let cids = if is_raw {
                    self.blocks.put_raw(&owner, &writer, group.signatures, group.blocks, &tid).await?
                } else {
                    self.blocks.put(&owner, &writer, group.signatures, group.blocks, &tid).await?
                };
                // Response is a whitespace-separated stream of `{"Hash":"<cid>"}`.
                let mut out = String::new();
                for cid in cids {
                    out.push_str(&format!("{{\"Hash\":\"{cid}\"}}\n"));
                }
                Ok(out.into_bytes())
            }

            "block/get" => {
                let owner = q.pkh("owner")?;
                let cid = q.cid("arg")?;
                // Empty response = "not found" (the client's convention).
                Ok(self.blocks.get_raw(&owner, &cid, None).await?.unwrap_or_default())
            }

            "block/stat" => {
                let owner = q.pkh("owner")?;
                let cid = q.cid("arg")?;
                let size = self.blocks.get_raw(&owner, &cid, None).await?.map(|b| b.len()).unwrap_or(0);
                Ok(format!("{{\"Size\":{size}}}").into_bytes())
            }

            "champ/get/bulk" => {
                let owner = q.pkh("owner")?;
                let root = q.cid("arg")?;
                let caps = match q.get("caps") {
                    Some(enc) => {
                        let raw = peergos_multiformats::bases::multibase_decode(enc)
                            .map_err(|e| Error::Protocol(format!("bad caps: {e}")))?;
                        match CborObject::from_bytes(&raw)? {
                            CborObject::List(items) => {
                                items.iter().map(ChunkMirrorCap::from_cbor).collect::<Result<Vec<_>>>()?
                            }
                            _ => Vec::new(),
                        }
                    }
                    None => Vec::new(),
                };
                let committed = q.get("committed").and_then(|s| Cid::decode(s).ok());
                let blocks =
                    champ_lookup_local(self.blocks.as_ref(), &owner, &root, &caps, committed.as_ref()).await?;
                Ok(CborObject::List(blocks.into_iter().map(CborObject::ByteString).collect()).to_bytes())
            }

            other => Err(Error::Http(format!("status 404: mock storage has no route for {other}"))),
        }
    }

    /// Direct block insertion (for test setup / assertions).
    pub async fn put_block(&self, block: Vec<u8>, is_raw: bool) -> Result<Cid> {
        let dummy = PublicKeyHash::identity(vec![0u8; 4])?;
        let cids = if is_raw {
            self.blocks.put_raw(&dummy, &dummy, vec![], vec![block], &TransactionId("1".into())).await?
        } else {
            self.blocks.put(&dummy, &dummy, vec![], vec![block], &TransactionId("1".into())).await?
        };
        Ok(cids.into_iter().next().unwrap())
    }

    /// The CID a block's bytes hash to (matching what the mock stores it under).
    pub fn cid_of(block: &[u8], is_raw: bool) -> Result<Cid> {
        hash_to_cid(block, is_raw)
    }
}

struct MockPoster {
    server: MockServer,
}

#[async_trait]
impl HttpPoster for MockPoster {
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.server.handle(url, Vec::new()).await
    }
    async fn post(&self, url: &str, payload: Vec<u8>, _unzip: bool, _timeout_ms: i32) -> Result<Vec<u8>> {
        self.server.handle(url, payload).await
    }
    async fn put(&self, url: &str, body: Vec<u8>, _headers: Vec<(String, String)>) -> Result<Vec<u8>> {
        self.server.handle(url, body).await
    }
}

// ---------------------------------------------------------------------------
// URL / query parsing
// ---------------------------------------------------------------------------

struct Query(HashMap<String, String>);

impl Query {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|s| s.as_str())
    }
    fn cid(&self, key: &str) -> Result<Cid> {
        let s = self.get(key).ok_or_else(|| Error::Protocol(format!("missing '{key}'")))?;
        Cid::decode(s).map_err(|e| Error::Protocol(format!("bad {key} cid: {e}")))
    }
    fn pkh(&self, key: &str) -> Result<PublicKeyHash> {
        let s = self.get(key).ok_or_else(|| Error::Protocol(format!("missing '{key}'")))?;
        let cid = Cid::decode(s).map_err(|e| Error::Protocol(format!("bad {key} pkh: {e}")))?;
        PublicKeyHash::new(cid)
    }
}

/// Split `path?query` and parse the (form-encoded) query. CID/pkh/multibase values
/// the client sends are already URL-safe, so we only decode `+` and `%XX`.
fn split_url(url: &str) -> (&str, Query) {
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url, ""),
    };
    let mut map = HashMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(k.to_string(), url_decode(v));
    }
    (path, Query(map))
}

/// Reads Java `DataInputStream`-style length-prefixed fields (4-byte big-endian
/// length, then bytes; strings are UTF-8) — the signup request body encoding.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        if self.pos + 4 > self.buf.len() {
            return Err(Error::Protocol("truncated request".into()));
        }
        let len = u32::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1], self.buf[self.pos + 2], self.buf[self.pos + 3]]) as usize;
        self.pos += 4;
        if self.pos + len > self.buf.len() {
            return Err(Error::Protocol("truncated request field".into()));
        }
        let out = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
    fn string(&mut self) -> Result<String> {
        // char count == byte count for the ASCII usernames/tokens tests use.
        Ok(String::from_utf8_lossy(&self.bytes()?).into_owned())
    }
}

/// A stable map key for a public-key hash (its multibase string).
fn pkh_key(pkh: &PublicKeyHash) -> Vec<u8> {
    pkh.to_string().into_bytes()
}

/// Extract the `PointerUpdate` from a writer's signed CAS payload
/// (`sign_message` = 64-byte signature || cbor). The mock trusts the signature
/// for now (verification is a later milestone); it only needs the fields to CAS.
fn parse_pointer_update(signed: &[u8]) -> Result<PointerUpdate> {
    if signed.len() < 64 {
        return Err(Error::Protocol("signed pointer payload too short".into()));
    }
    PointerUpdate::from_cbor(&CborObject::from_bytes(&signed[64..])?)
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use peergos_core::HttpStorage;

    #[tokio::test]
    async fn put_get_roundtrip_through_httpstorage() {
        let server = MockServer::new();
        let store = HttpStorage::new(server.poster(), true);
        let owner = PublicKeyHash::identity(vec![1u8; 4]).unwrap();

        // id round-trips.
        assert!(store.id().await.is_ok());

        // Put a raw block via the client, get it back.
        let tid = store.start_transaction(&owner).await.unwrap();
        let block = b"hello mock world".to_vec();
        let cids = store
            .put_raw(&owner, &owner, vec![vec![9u8; 64]], vec![block.clone()], &tid)
            .await
            .unwrap();
        assert_eq!(cids.len(), 1);
        let got = store.get_raw(&owner, &cids[0], None).await.unwrap();
        assert_eq!(got.as_deref(), Some(block.as_slice()));

        // A missing block reads back as None.
        let absent = MockServer::cid_of(b"nope", true).unwrap();
        assert!(store.get_raw(&owner, &absent, None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn pointer_cas_accept_and_reject() {
        use peergos_core::keys::SigningKeyPair;
        use peergos_core::mutable::{HttpMutablePointers, MutablePointers, PointerUpdate};

        let server = MockServer::new();
        let mp = HttpMutablePointers::new(server.poster());
        let owner = PublicKeyHash::identity(vec![2u8; 4]).unwrap();
        let (_p, sk) = peergos_crypto::sign::random_keypair();
        let writer = SigningKeyPair::from_secret(sk.to_vec()).unwrap().to_private_and_hash().unwrap();

        let t1 = MockServer::cid_of(b"wd1", false).unwrap();
        let u1 = PointerUpdate::new(None, Some(t1.clone()), Some(1));
        assert!(mp.set_pointer_update(&owner, &writer, &u1).await.unwrap(), "first write accepted");

        let raw = mp.get_pointer(&owner, &writer.public_key_hash).await.unwrap().expect("pointer present");
        assert_eq!(parse_pointer_update(&raw).unwrap().updated, Some(t1.clone()));

        // A stale CAS (original still None, not the current target) is rejected.
        let t2 = MockServer::cid_of(b"wd2", false).unwrap();
        let stale = PointerUpdate::new(None, Some(t2.clone()), Some(2));
        assert!(!mp.set_pointer_update(&owner, &writer, &stale).await.unwrap(), "stale CAS rejected");

        // A valid CAS (original == current target) is accepted.
        let valid = PointerUpdate::new(Some(t1), Some(t2.clone()), Some(2));
        assert!(mp.set_pointer_update(&owner, &writer, &valid).await.unwrap(), "valid CAS accepted");
        let raw2 = mp.get_pointer(&owner, &writer.public_key_hash).await.unwrap().unwrap();
        assert_eq!(parse_pointer_update(&raw2).unwrap().updated, Some(t2));
    }
}
