use crate::auth::*;
use crate::champ::*;
use crate::error::Result;
use crate::keys::*;
use crate::mutable::*;
use crate::poster::HttpPoster;
use crate::storage::*;
use async_trait::async_trait;
use peergos_cbor::{CborObject, Cborable};
use peergos_multiformats::{Cid, Codec, CID_V1};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Records requests and replays a queue of canned responses.
#[derive(Default)]
struct MockPoster {
    responses: Mutex<VecDeque<Vec<u8>>>,
    calls: Mutex<Vec<(String, String, Vec<u8>)>>, // (method, url, body)
}

impl MockPoster {
    fn with(responses: Vec<Vec<u8>>) -> Arc<MockPoster> {
        Arc::new(MockPoster {
            responses: Mutex::new(responses.into()),
            calls: Mutex::new(Vec::new()),
        })
    }
    fn next(&self) -> Vec<u8> {
        self.responses.lock().unwrap().pop_front().unwrap_or_default()
    }
    fn last_url(&self) -> String {
        self.calls.lock().unwrap().last().unwrap().1.clone()
    }
    fn last_body(&self) -> Vec<u8> {
        self.calls.lock().unwrap().last().unwrap().2.clone()
    }
}

#[async_trait]
impl HttpPoster for MockPoster {
    async fn post(&self, url: &str, payload: Vec<u8>, _unzip: bool, _timeout_ms: i32) -> Result<Vec<u8>> {
        self.calls.lock().unwrap().push(("POST".into(), url.into(), payload));
        Ok(self.next())
    }
    async fn put(&self, url: &str, body: Vec<u8>, _headers: Vec<(String, String)>) -> Result<Vec<u8>> {
        self.calls.lock().unwrap().push(("PUT".into(), url.into(), body));
        Ok(self.next())
    }
    async fn get(&self, url: &str) -> Result<Vec<u8>> {
        self.calls.lock().unwrap().push(("GET".into(), url.into(), Vec::new()));
        Ok(self.next())
    }
}

fn owner() -> PublicKeyHash {
    PublicKeyHash::new(hash_to_cid(b"owner-key", false).unwrap()).unwrap()
}

// ---- pure helpers ----------------------------------------------------------

#[test]
fn build_cid_is_v1_dag_cbor() {
    let cid = hash_to_cid(b"hello", false).unwrap();
    assert_eq!(cid.version, CID_V1);
    assert_eq!(cid.codec, Codec::DagCbor);
    let bytes = cid.to_bytes();
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x71);
    assert_eq!(Cid::cast(&bytes).unwrap(), cid);

    let raw = hash_to_cid(b"hello", true).unwrap();
    assert_eq!(raw.codec, Codec::Raw);
}

#[test]
fn block_write_group_cbor_roundtrips() {
    let g = BlockWriteGroup {
        blocks: vec![vec![1, 2, 3], vec![4, 5]],
        signatures: vec![vec![9], vec![8, 7]],
    };
    let bytes = g.serialize();
    let decoded = CborObject::from_bytes(&bytes).unwrap();
    // canonical: map {b:[...], s:[...]}, keys "b" < "s"
    assert_eq!(decoded.to_bytes(), bytes);
    let b = decoded.get("b").and_then(|v| v.as_list()).unwrap();
    assert_eq!(b[0].as_bytes(), Some(&[1u8, 2, 3][..]));
    let s = decoded.get("s").and_then(|v| v.as_list()).unwrap();
    assert_eq!(s[1].as_bytes(), Some(&[8u8, 7][..]));
}

#[test]
fn url_encode_matches_urlencoder() {
    assert_eq!(url_encode("abcXYZ123-_.*"), "abcXYZ123-_.*");
    assert_eq!(url_encode("a b"), "a+b");
    assert_eq!(url_encode("a/b=c&d"), "a%2Fb%3Dc%26d");
    // A base58btc CID passes through unchanged.
    let cid = hash_to_cid(b"x", false).unwrap().to_string();
    assert_eq!(url_encode(&cid), cid);
}

#[test]
fn public_key_hash_cbor_roundtrip() {
    let pkh = PublicKeyHash::new(hash_to_cid(b"key", false).unwrap()).unwrap();
    let cbor = pkh.to_cbor();
    assert_eq!(PublicKeyHash::from_cbor(&cbor).unwrap(), pkh);
}

#[test]
fn signing_key_hash_is_identity() {
    let (_pub, secret) = peergos_crypto::sign::keypair_from_seed(&[7u8; 32]).unwrap();
    let kp = SigningKeyPair::from_secret(secret.to_vec()).unwrap();
    let hash = kp.public.hash().unwrap();
    assert!(hash.is_identity());
    // the identity hash embeds the key's cbor bytes
    assert_eq!(hash.target.get_hash(), &kp.public.serialize()[..]);
}

// ---- storage client protocol (mocked transport) ----------------------------

#[tokio::test]
async fn id_parses_peer_id() {
    let mock = MockPoster::with(vec![
        br#"{"ID":"QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn"}"#.to_vec(),
    ]);
    let store = HttpStorage::new(mock.clone(), true);
    let id = store.id().await.unwrap();
    assert_eq!(id.to_string(), "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn");
    assert_eq!(mock.last_url(), "api/v0/id");
}

#[tokio::test]
async fn get_identity_block_skips_network() {
    let mock = MockPoster::with(vec![]);
    let store = HttpStorage::new(mock.clone(), true);
    // an identity CID embedding cbor Long(42)
    let cbor = CborObject::Long(42).to_bytes();
    let identity = PublicKeyHash::identity(cbor.clone()).unwrap().target;
    let got = store.get(&owner(), &identity, None).await.unwrap();
    assert_eq!(got, Some(CborObject::Long(42)));
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn get_block_over_network() {
    let payload = CborObject::map().put("k", CborObject::Long(1)).build().to_bytes();
    let mock = MockPoster::with(vec![payload.clone()]);
    let store = HttpStorage::new(mock.clone(), true);
    let hash = hash_to_cid(&payload, false).unwrap();
    let got = store.get(&owner(), &hash, None).await.unwrap();
    assert_eq!(got, Some(CborObject::from_bytes(&payload).unwrap()));
    let url = mock.last_url();
    assert!(url.starts_with("api/v0/block/get?arg="), "url={url}");
    assert!(url.contains(&format!("arg={hash}")));
    assert!(url.contains("owner="));
}

#[tokio::test]
async fn put_block_signs_and_parses_hash() {
    let block = CborObject::Str("payload".into()).to_bytes();
    let expected = hash_to_cid(&block, false).unwrap();
    let resp = format!("{{\"Hash\":\"{expected}\"}}").into_bytes();
    let mock = MockPoster::with(vec![resp]);
    let store = HttpStorage::new(mock.clone(), true);

    let (_pub, secret) = peergos_crypto::sign::keypair_from_seed(&[3u8; 32]).unwrap();
    let writer = SigningKeyPair::from_secret(secret.to_vec())
        .unwrap()
        .to_private_and_hash()
        .unwrap();
    let sig = sign_block(&writer, &block).unwrap();
    let tid = TransactionId("42".into());
    let hashes = store
        .put(&owner(), &writer.public_key_hash, vec![sig], vec![block.clone()], &tid)
        .await
        .unwrap();
    assert_eq!(hashes, vec![expected]);

    let url = mock.last_url();
    assert!(url.contains("block/put/bulk?format=dag-cbor"), "url={url}");
    assert!(url.contains("transaction=42"));
    assert!(url.contains("writer="));
    // body is a BlockWriteGroup carrying our block + signature
    let body = CborObject::from_bytes(&mock.last_body()).unwrap();
    let b = body.get("b").and_then(|v| v.as_list()).unwrap();
    assert_eq!(b[0].as_bytes(), Some(&block[..]));
}

// ---- BATs ------------------------------------------------------------------

fn sample_bat() -> Bat {
    Bat::new((0u8..32).collect()).unwrap()
}

#[test]
fn bat_secret_encoding_roundtrip() {
    let bat = sample_bat();
    let encoded = bat.encode_secret();
    assert!(encoded.starts_with('z')); // multibase base58btc
    assert_eq!(Bat::from_string(&encoded).unwrap(), bat);
}

#[test]
fn bat_cbor_roundtrip() {
    let bat = sample_bat();
    let decoded = Bat::from_cbor(&bat.to_cbor()).unwrap();
    assert_eq!(decoded, bat);
}

#[test]
fn bat_id_variants() {
    let bat = sample_bat();
    let inline = BatId::inline(&bat).unwrap();
    assert!(inline.is_inline());
    assert_eq!(inline.get_inline().unwrap(), bat);
    assert_eq!(inline.id.codec, Codec::Raw);

    let sha = BatId::sha256(&bat).unwrap();
    assert!(!sha.is_inline());
    assert_eq!(sha.id.codec, Codec::Raw);
    // cbor roundtrip
    assert_eq!(BatId::from_cbor(&sha.to_cbor()).unwrap(), sha);
}

#[test]
fn bat_with_id_encode_roundtrip() {
    let bat = sample_bat();
    let id = BatId::sha256(&bat).unwrap().id; // raw, non-identity
    let bwi = BatWithId::new(bat, id).unwrap();
    let encoded = bwi.encode();
    assert!(encoded.starts_with('z'));
    assert_eq!(BatWithId::decode(&encoded).unwrap(), bwi);
    // an identity id is rejected
    let bad = Cid::new(CID_V1, Codec::Raw, peergos_multiformats::MultihashType::Id, vec![1, 2, 3]).unwrap();
    assert!(BatWithId::new(sample_bat(), bad).is_err());
}

#[test]
fn block_auth_cbor_and_time_packing() {
    let bat = sample_bat();
    let block = hash_to_cid(b"block", true).unwrap();
    let node = hash_to_cid(b"node", true).unwrap();
    let bat_id = BatId::sha256(&bat).unwrap().id;
    let datetime = "20240115T093000Z";
    let auth = bat
        .generate_auth(&block, &node, 300, datetime, &bat_id)
        .unwrap();
    assert_eq!(auth.expiry_seconds, 300);
    assert_eq!(auth.aws_datetime, datetime);
    assert_eq!(auth.signature.len(), 32); // hmac-sha256 output
    // cbor roundtrip preserves the datetime through the packed-long form
    let decoded = BlockAuth::from_cbor(&auth.to_cbor()).unwrap();
    assert_eq!(decoded, auth);
    // and the hex encode/decode roundtrip
    assert_eq!(BlockAuth::from_string(&auth.encode()).unwrap(), auth);
}

#[test]
fn s3_signature_is_deterministic_and_sensitive() {
    let bat = sample_bat();
    let node = hash_to_cid(b"node", true).unwrap();
    let bat_id = BatId::sha256(&bat).unwrap().id;
    let dt = "20240115T093000Z";
    let a = bat.generate_auth(&hash_to_cid(b"b1", true).unwrap(), &node, 300, dt, &bat_id).unwrap();
    let b = bat.generate_auth(&hash_to_cid(b"b1", true).unwrap(), &node, 300, dt, &bat_id).unwrap();
    assert_eq!(a.signature, b.signature); // deterministic
    let c = bat.generate_auth(&hash_to_cid(b"b2", true).unwrap(), &node, 300, dt, &bat_id).unwrap();
    assert_ne!(a.signature, c.signature); // depends on the block
}

#[tokio::test]
async fn get_block_with_bat_param() {
    let payload = CborObject::Long(5).to_bytes();
    let mock = MockPoster::with(vec![payload.clone()]);
    let store = HttpStorage::new(mock.clone(), true);
    let bat = sample_bat();
    let bwi = BatWithId::new(bat.clone(), BatId::sha256(&bat).unwrap().id).unwrap();
    let hash = hash_to_cid(&payload, false).unwrap();
    let got = store.get(&owner(), &hash, Some(&bwi)).await.unwrap();
    assert_eq!(got, Some(CborObject::Long(5)));
    let url = mock.last_url();
    assert!(url.contains(&format!("&bat={}", bwi.encode())), "url={url}");
}

// ---- mutable pointers ------------------------------------------------------

fn writer_keypair(seed: u8) -> SigningPrivateKeyAndPublicHash {
    let (_pub, secret) = peergos_crypto::sign::keypair_from_seed(&[seed; 32]).unwrap();
    SigningKeyPair::from_secret(secret.to_vec())
        .unwrap()
        .to_private_and_hash()
        .unwrap()
}

#[test]
fn pointer_update_cbor_roundtrip() {
    let updated = hash_to_cid(b"root", false).unwrap();
    // with a sequence
    let pu = PointerUpdate::new(None, Some(updated.clone()), Some(3));
    let decoded = PointerUpdate::from_cbor(&CborObject::from_bytes(&pu.serialize()).unwrap()).unwrap();
    assert_eq!(decoded, pu);
    // without a sequence, and with a non-null original
    let original = hash_to_cid(b"old", false).unwrap();
    let pu2 = PointerUpdate::new(Some(original), Some(updated), None);
    let decoded2 = PointerUpdate::from_cbor(&pu2.to_cbor()).unwrap();
    assert_eq!(decoded2, pu2);
}

#[test]
fn pointer_update_increment() {
    assert_eq!(PointerUpdate::increment(None), Some(1));
    assert_eq!(PointerUpdate::increment(Some(4)), Some(5));
}

#[test]
fn signed_pointer_update_cbor_roundtrip() {
    let w = writer_keypair(2);
    let spu = SignedPointerUpdate::new(w.public_key_hash.clone(), vec![1, 2, 3, 4]);
    let decoded = SignedPointerUpdate::from_cbor(&spu.to_cbor()).unwrap();
    assert_eq!(decoded, spu);
}

#[tokio::test]
async fn set_and_get_pointer_http() {
    let mock = MockPoster::with(vec![vec![1u8], b"signed-cas-bytes".to_vec()]);
    let mp = HttpMutablePointers::new(mock.clone());
    let w = writer_keypair(5);

    let ok = mp
        .set_pointer(&owner(), &w.public_key_hash, vec![9, 9, 9])
        .await
        .unwrap();
    assert!(ok);
    assert!(mock.last_url().contains("peergos/v0/mutable/setPointer?owner="));
    assert!(mock.last_url().contains("&writer="));

    let got = mp.get_pointer(&owner(), &w.public_key_hash).await.unwrap();
    assert_eq!(got, Some(b"signed-cas-bytes".to_vec()));
    assert!(mock.last_url().contains("peergos/v0/mutable/getPointer?owner="));
}

#[tokio::test]
async fn get_pointer_target_unwraps_signature() {
    // Writer with an identity key hash, so get_signing_key needs no network.
    let w = writer_keypair(7);
    assert!(w.public_key_hash.is_identity());
    let update = PointerUpdate::new(None, Some(hash_to_cid(b"newroot", false).unwrap()), Some(1));
    let signed = w.secret.sign_message(&update.serialize()).unwrap();

    let mp_mock = MockPoster::with(vec![signed]); // getPointer returns the signed CAS
    let mp = HttpMutablePointers::new(mp_mock);
    let store = HttpStorage::new(MockPoster::with(vec![]), true);

    let target = mp
        .get_pointer_target(&owner(), &w.public_key_hash, &store)
        .await
        .unwrap();
    assert_eq!(target, update);
}

#[tokio::test]
async fn get_pointer_target_empty_when_unset() {
    let mp = HttpMutablePointers::new(MockPoster::with(vec![])); // empty getPointer response
    let store = HttpStorage::new(MockPoster::with(vec![]), true);
    let w = writer_keypair(8);
    let target = mp
        .get_pointer_target(&owner(), &w.public_key_hash, &store)
        .await
        .unwrap();
    assert_eq!(target, PointerUpdate::empty());
}

// ---- champ (HAMT) ----------------------------------------------------------

#[test]
fn champ_mask_extracts_index() {
    // bit_width 3, depth 0 => low 3 bits of byte 0.
    assert_eq!(Champ::mask(&[0x00], 0, 3), 0);
    assert_eq!(Champ::mask(&[0x05], 0, 3), 5);
    assert_eq!(Champ::mask(&[0xff], 0, 3), 7);
    // depth 1 => bits [3..6) of byte 0.
    assert_eq!(Champ::mask(&[0x11], 1, 3), 2); // 0x11 >> 3 == 2
    assert_eq!(Champ::mask(&[0xff], 1, 3), 7);
}

/// A single-level champ mapping key bytes (via identity hashing) to Long values.
fn flat_champ(entries: &[(Vec<u8>, i64)]) -> Champ {
    // group by bitpos at depth 0
    let mut by_pos: std::collections::BTreeMap<usize, Vec<KeyElement>> = Default::default();
    for (k, v) in entries {
        let pos = Champ::mask(k, 0, BIT_WIDTH);
        by_pos.entry(pos).or_default().push(KeyElement {
            key: k.clone(),
            value: Some(CborObject::Long(*v)),
        });
    }
    let mut data_map = vec![0u8; 1];
    let mut contents = Vec::new();
    for (pos, mappings) in &by_pos {
        data_map[pos / 8] |= 1 << (pos % 8);
        contents.push(Payload::Mappings(mappings.clone()));
    }
    Champ { data_map, node_map: Vec::new(), contents, mirror_bat: None }
}

#[test]
fn champ_cbor_roundtrip() {
    let champ = flat_champ(&[(vec![0x00], 10), (vec![0x02], 20), (vec![0x05], 30)]);
    let bytes = champ.serialize();
    let decoded = Champ::from_cbor(&CborObject::from_bytes(&bytes).unwrap()).unwrap();
    assert_eq!(decoded, champ);
    assert_eq!(decoded.serialize(), bytes); // canonical
}

#[tokio::test]
async fn champ_flat_get() {
    let champ = flat_champ(&[(vec![0x00], 10), (vec![0x02], 20), (vec![0x05], 30)]);
    let root_bytes = champ.serialize();
    let root_hash = hash_to_cid(&root_bytes, false).unwrap();
    // storage returns the root when asked for root_hash
    let store = Arc::new(HttpStorage::new(MockPoster::with(vec![root_bytes]), true));
    let wrapper = ChampWrapper::create(owner(), root_hash, None, store, identity_key_hasher())
        .await
        .unwrap();
    assert_eq!(wrapper.get(&[0x00]).await.unwrap(), Some(CborObject::Long(10)));
    assert_eq!(wrapper.get(&[0x02]).await.unwrap(), Some(CborObject::Long(20)));
    assert_eq!(wrapper.get(&[0x05]).await.unwrap(), Some(CborObject::Long(30)));
    assert_eq!(wrapper.get(&[0x04]).await.unwrap(), None); // bitpos unset
}

#[tokio::test]
async fn champ_sharded_get_follows_link() {
    // Child champ holds K=[0x11] at depth 1 (bitpos 2), value Long(99).
    let key = vec![0x11u8];
    let child = {
        let mut data_map = vec![0u8; 1];
        let pos = Champ::mask(&key, 1, BIT_WIDTH); // == 2
        data_map[pos / 8] |= 1 << (pos % 8);
        Champ {
            data_map,
            node_map: Vec::new(),
            contents: vec![Payload::Mappings(vec![KeyElement {
                key: key.clone(),
                value: Some(CborObject::Long(99)),
            }])],
            mirror_bat: None,
        }
    };
    let child_bytes = child.serialize();
    let child_hash = hash_to_cid(&child_bytes, false).unwrap();

    // Parent has a shard link at depth-0 bitpos 1 (0x11 & 7 == 1).
    let parent = Champ {
        data_map: Vec::new(),
        node_map: vec![0b0000_0010], // bit 1 set
        contents: vec![Payload::Link(child_hash.clone())],
        mirror_bat: None,
    };
    let parent_bytes = parent.serialize();
    let parent_hash = hash_to_cid(&parent_bytes, false).unwrap();

    // Mock storage: root fetch, then a child fetch per lookup that descends.
    let store = Arc::new(HttpStorage::new(
        MockPoster::with(vec![parent_bytes, child_bytes.clone(), child_bytes]),
        true,
    ));
    let wrapper = ChampWrapper::create(owner(), parent_hash, None, store, identity_key_hasher())
        .await
        .unwrap();
    assert_eq!(wrapper.get(&key).await.unwrap(), Some(CborObject::Long(99)));
    // [0x09] routes to the same shard (bitpos 1) but is absent there => None
    assert_eq!(wrapper.get(&[0x09]).await.unwrap(), None);
}

#[tokio::test]
async fn champ_put_get_roundtrip_in_ram() {
    use crate::ram::RamStorage;
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
    let writer = writer_keypair(11);
    let tid = TransactionId("0".into());

    // Start from an empty champ persisted to the store.
    let empty = Champ::empty();
    let root_hash = crate::put_block_signed(store.as_ref(), &owner(), &writer, empty.serialize(), &tid)
        .await
        .unwrap();
    let mut champ =
        ChampWrapper::create(owner(), root_hash, None, store.clone(), identity_key_hasher())
            .await
            .unwrap();

    // Insert enough keys to force sharding (max 4 collisions per bitpos, so keys
    // colliding on the low 3 bits push down a level).
    let val = |n: i64| Some(CborObject::Long(n));
    let keys: Vec<Vec<u8>> = (0u8..20).map(|i| vec![i, 0xAA, i.wrapping_mul(7)]).collect();
    for (i, k) in keys.iter().enumerate() {
        champ.put(&writer, k, &None, val(i as i64), &tid).await.unwrap();
    }
    // All keys read back with their values.
    for (i, k) in keys.iter().enumerate() {
        assert_eq!(champ.get(k).await.unwrap(), val(i as i64), "key {i}");
    }
    // Update an existing key (CAS on the old value).
    champ.put(&writer, &keys[3], &val(3), val(999), &tid).await.unwrap();
    assert_eq!(champ.get(&keys[3]).await.unwrap(), val(999));
    // Wrong CAS expectation fails.
    assert!(champ.put(&writer, &keys[3], &val(3), val(1), &tid).await.is_err());
    // Absent key is None.
    assert_eq!(champ.get(&[0xFF, 0xFF]).await.unwrap(), None);

    // Re-open the champ at its committed root and confirm persistence.
    let reopened =
        ChampWrapper::create(owner(), champ.root_hash().clone(), None, store, identity_key_hasher())
            .await
            .unwrap();
    assert_eq!(reopened.get(&keys[7]).await.unwrap(), val(7));
    assert_eq!(reopened.get(&keys[3]).await.unwrap(), val(999));
}

#[test]
fn boxing_curve25519_roundtrip() {
    use crate::boxing::BoxingKeyPair;
    let recipient = BoxingKeyPair::random_curve25519();
    let ephemeral = BoxingKeyPair::random_curve25519();
    let msg = b"a classical follow request";
    // Sender encrypts to the recipient's public key using its own secret.
    let cipher = recipient.public.encrypt(msg, &ephemeral.secret).unwrap();
    // Recipient decrypts with its secret + the sender's public key.
    let plain = recipient.secret.decrypt(&cipher, &ephemeral.public).unwrap();
    assert_eq!(plain, msg);
    // cbor round-trips.
    assert_eq!(BoxingKeyPair::from_cbor(&recipient.to_cbor()).unwrap(), recipient);
}

#[test]
fn boxing_hybrid_roundtrip() {
    use crate::boxing::BoxingKeyPair;
    let recipient = BoxingKeyPair::random_hybrid();
    let ephemeral = BoxingKeyPair::random_hybrid();
    let msg = b"a post-quantum follow request payload";
    let cipher = recipient.public.encrypt(msg, &ephemeral.secret).unwrap();
    let plain = recipient.secret.decrypt(&cipher, &ephemeral.public).unwrap();
    assert_eq!(plain, msg);
    // cbor round-trips (public 1568-byte ML-KEM key + secret 3168-byte key).
    assert_eq!(BoxingKeyPair::from_cbor(&recipient.to_cbor()).unwrap(), recipient);
    // A different recipient cannot decrypt.
    let other = BoxingKeyPair::random_hybrid();
    assert!(other.secret.decrypt(&cipher, &ephemeral.public).is_err());
}

#[tokio::test]
async fn champ_remove_collapses_to_empty() {
    use crate::ram::RamStorage;
    let store: Arc<dyn ContentAddressedStorage> = Arc::new(RamStorage::new());
    let writer = writer_keypair(11);
    let tid = TransactionId("0".into());

    let empty = Champ::empty();
    let empty_hash = crate::put_block_signed(store.as_ref(), &owner(), &writer, empty.serialize(), &tid)
        .await
        .unwrap();
    let mut champ =
        ChampWrapper::create(owner(), empty_hash.clone(), None, store.clone(), identity_key_hasher())
            .await
            .unwrap();

    // Insert enough colliding keys to force sharding, then remove all of them.
    let val = |n: i64| Some(CborObject::Long(n));
    let keys: Vec<Vec<u8>> = (0u8..20).map(|i| vec![i, 0xAA, i.wrapping_mul(7)]).collect();
    for (i, k) in keys.iter().enumerate() {
        champ.put(&writer, k, &None, val(i as i64), &tid).await.unwrap();
    }

    // Removing with a wrong CAS expectation fails.
    assert!(champ.remove(&writer, &keys[0], &val(999), &tid).await.is_err());

    // Remove every key; each should then read back as absent.
    for (i, k) in keys.iter().enumerate() {
        champ.remove(&writer, k, &val(i as i64), &tid).await.unwrap();
        assert_eq!(champ.get(k).await.unwrap(), None, "key {i} still present after remove");
    }
    // The tree has collapsed all the way back to the empty champ.
    assert_eq!(champ.root_hash(), &empty_hash);

    // Reinserting still works after the collapse.
    champ.put(&writer, &keys[5], &None, val(5), &tid).await.unwrap();
    assert_eq!(champ.get(&keys[5]).await.unwrap(), val(5));
}

#[tokio::test]
async fn transactions() {
    let mock = MockPoster::with(vec![b"txn-7".to_vec(), b"1".to_vec()]);
    let store = HttpStorage::new(mock.clone(), true);
    let tid = store.start_transaction(&owner()).await.unwrap();
    assert_eq!(tid, TransactionId("txn-7".into()));
    assert!(store.close_transaction(&owner(), &tid).await.unwrap());
    assert!(mock.last_url().contains("transaction/close?arg=txn-7"));
}
