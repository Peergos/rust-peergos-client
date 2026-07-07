//! Verifies the block-BAT invariant against a live server: every raw fragment and
//! every cryptree node carries exactly TWO BatIds — an INLINE block-BAT (identity
//! multihash, embedding the secret) followed by the user's MIRROR BAT referenced
//! BY HASH (a sha256 raw CID, never inlined) — while internal champ HAMT nodes and
//! WriterData blocks carry ZERO.
//!
//!   cargo run -p peergos-fs --example bat_invariant -- http://localhost:7777/

use peergos_cbor::CborObject;
use peergos_core::auth::{BatId, BatWithId};
use peergos_core::mutable::{HttpMutablePointers, MutablePointers};
use peergos_core::{
    identity_key_hasher, ChampWrapper, ContentAddressedStorage, HttpPoster, HttpStorage, ReqwestPoster,
};
use peergos_fs::UserContext;
use peergos_multiformats::Cid;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// `Bat.RAW_BLOCK_MAGIC_PREFIX` — marks a raw block carrying a BAT header.
const RAW_BLOCK_MAGIC_PREFIX: [u8; 8] = [0x71, 0x1d, 0x10, 0xcf, 0x3d, 0x32, 0x2f, 0x2b];

/// Decode a cbor list of BatId byte-strings and classify each as inline vs hash.
fn classify_bats(list: &[CborObject]) -> Vec<(bool, Cid)> {
    list.iter()
        .filter_map(|c| BatId::from_cbor(c).ok())
        .map(|b| (b.is_inline(), b.id))
        .collect()
}

/// Assert a bats list is exactly [inline block-bat, hash mirror-bat].
fn assert_two_bats(what: &str, list: &[CborObject]) {
    let bats = classify_bats(list);
    assert_eq!(bats.len(), 2, "{what}: expected 2 BATs, found {}", bats.len());
    assert!(bats[0].0, "{what}: first BAT must be INLINE (identity multihash)");
    assert!(!bats[1].0, "{what}: mirror BAT must be BY HASH (sha256), not inlined");
    println!("  {what}: 2 BATs — [inline block-bat, hash mirror-bat] ✓");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).unwrap_or_else(|| "http://localhost:7777/".to_string());
    let poster: Arc<dyn HttpPoster> = Arc::new(ReqwestPoster::new(&base, false)?);
    let store: Arc<dyn ContentAddressedStorage> =
        Arc::new(HttpStorage::new(Arc::new(ReqwestPoster::new(&base, false)?), true));
    let mutable: Arc<dyn MutablePointers> = Arc::new(HttpMutablePointers::new(poster.clone()));

    // A fresh user so the mirror BAT is minted and threaded from signup onward.
    let n = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let username = format!("bat{n}");
    let ctx = UserContext::sign_up(&username, "batpass99", None, poster.clone(), store.clone(), mutable.clone()).await?;
    println!("signed up {username}");

    let mirror = ctx.get_mirror_bat().await?.expect("a fresh user must have a mirror BAT");
    let mirror_id = mirror.id();
    assert!(!mirror_id.is_inline(), "mirror BAT id must be a hash, not inline");
    println!("mirror BAT id (hash form): {}", mirror_id.id);

    // Upload a single-chunk file big enough to be stored as external raw
    // fragments (a tiny payload would be inlined into the cryptree node).
    let dir = ctx.get_home().await?.mkdir(&format!("d{n}")).await?;
    let payload: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let file = dir.upload("hello.bin", &payload).await?;
    let cap = file.capability().clone();
    println!("uploaded hello.bin ({} bytes)", file.size());

    // --- 1. the file's cryptree node carries 2 BATs --------------------------
    let root = open_root(&cap.owner, &cap.writer, &store, mutable.as_ref()).await?;
    let champ = ChampWrapper::create(cap.owner.clone(), root, None, store.clone(), identity_key_hasher()).await?;
    let node_cid = Cid::cast(
        champ.get(&cap.map_key).await?.expect("file node in champ").as_link().expect("champ value is a link"),
    )?;
    let bwid = cap.bat.as_ref().map(|b| BatWithId::new(b.clone(), b.calculate_id().unwrap().id).unwrap());
    let node = store.get(&cap.owner, &node_cid, bwid.as_ref()).await?.expect("cryptree node block");
    let node_bats = node.get("bats").and_then(|c| c.as_list()).expect("cryptree node must have a 'bats' field");
    assert_two_bats("file cryptree node", node_bats);
    // The mirror BAT in the node must be exactly the user's mirror id (by hash).
    let node_mirror = classify_bats(node_bats)[1].1.clone();
    assert_eq!(node_mirror, mirror_id.id, "cryptree node's mirror BAT must equal the user's mirror id");
    println!("  file cryptree node mirror BAT == user mirror id ✓");

    // --- 2. a raw fragment the node points at carries 2 BATs -----------------
    let frag_cid = find_fragment_link(&node).expect("file node should reference a raw fragment");
    // The fragment is gated by its own block-BAT; the user's mirror BAT (present on
    // every one of their blocks) authorises the read.
    let frag = store
        .get_raw(&cap.owner, &frag_cid, Some(&mirror))
        .await?
        .expect("raw fragment block");
    assert!(frag.starts_with(&RAW_BLOCK_MAGIC_PREFIX), "raw fragment must carry the magic prefix");
    let frag_bats = parse_raw_block_bats(&frag).expect("raw fragment BAT header");
    assert_two_bats("raw fragment", &frag_bats);
    assert_eq!(classify_bats(&frag_bats)[1].1, mirror_id.id, "fragment mirror BAT must equal the user's mirror id");
    println!("  raw fragment mirror BAT == user mirror id ✓");

    // --- 3. the WriterData block itself carries 0 BATs -----------------------
    let wd_cid = mutable
        .get_pointer_target(&cap.owner, &cap.writer, store.as_ref())
        .await?
        .updated
        .expect("writer data");
    let wd = store.get(&cap.owner, &wd_cid, None).await?.expect("writer data block");
    assert!(wd.get("bats").is_none(), "WriterData must carry NO bats field");
    println!("  WriterData block: 0 BATs ✓");

    println!("\nBAT invariant OK: fragments + cryptree nodes = 2 BATs (inline + mirror-by-hash); WriterData = 0.");
    Ok(())
}

/// The writer's champ tree root (replicates the crate-private `open_writer_root`).
async fn open_root(
    owner: &peergos_core::keys::PublicKeyHash,
    writer: &peergos_core::keys::PublicKeyHash,
    store: &Arc<dyn ContentAddressedStorage>,
    mutable: &dyn MutablePointers,
) -> Result<Cid, Box<dyn std::error::Error>> {
    let wd_cid = mutable.get_pointer_target(owner, writer, store.as_ref()).await?.updated.expect("writer data");
    let wd = store.get(owner, &wd_cid, None).await?.expect("writer data block");
    Ok(Cid::cast(wd.get("tree").and_then(|c| c.as_link()).expect("champ tree link"))?)
}

/// The first raw-fragment link reachable from a cryptree node's cipher-text.
fn find_fragment_link(node: &CborObject) -> Option<Cid> {
    fn walk(c: &CborObject, out: &mut Vec<Cid>) {
        match c {
            CborObject::List(l) => l.iter().for_each(|x| walk(x, out)),
            CborObject::Map(m) => m.iter().for_each(|(_, v)| walk(v, out)),
            other => {
                if let Some(bytes) = other.as_link() {
                    if let Ok(cid) = Cid::cast(bytes) {
                        out.push(cid);
                    }
                }
            }
        }
    }
    let mut links = Vec::new();
    walk(node, &mut links);
    // Raw fragments are Codec::Raw; cryptree/champ links are DagCbor.
    links.into_iter().find(|c| c.is_raw())
}

/// Parse the `[inline-bat, mirror-bat-id]` cbor header of a raw block that follows
/// the magic prefix.
fn parse_raw_block_bats(block: &[u8]) -> Option<Vec<CborObject>> {
    let rest = &block[RAW_BLOCK_MAGIC_PREFIX.len()..];
    // The BAT header is a cbor list prefixing the fragment bytes.
    let cbor = CborObject::from_bytes_prefix(rest).ok()?;
    cbor.as_list().map(|l| l.to_vec())
}
