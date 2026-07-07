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
use peergos_core::poster::HttpPoster;
use peergos_core::storage::{
    champ_lookup_local, BlockWriteGroup, ChunkMirrorCap, ContentAddressedStorage, TransactionId,
    API_PREFIX,
};
use peergos_core::{build_cid, hash_to_cid, RamStorage};
use peergos_multiformats::Cid;
use std::collections::HashMap;
use std::sync::Arc;

/// The in-memory state behind a mock server. Cheap to clone (`Arc`-shared), so a
/// single server can back a client's store, mutable pointers, and poster at once.
#[derive(Clone)]
pub struct MockServer {
    /// Content-addressed blocks (its own interior `Mutex`, so no lock is held
    /// across an await).
    blocks: Arc<RamStorage>,
    /// A stable fake node identity.
    server_id: Cid,
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

    // ---- request dispatch -------------------------------------------------

    async fn handle(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let (path, query) = split_url(url);
        let path = path.strip_prefix('/').unwrap_or(path);

        // Storage endpoints (api/v0/…).
        if let Some(rest) = path.strip_prefix(API_PREFIX) {
            return self.handle_storage(rest, &query, body).await;
        }
        Err(Error::Http(format!("status 404: mock has no route for {path}")))
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
}
