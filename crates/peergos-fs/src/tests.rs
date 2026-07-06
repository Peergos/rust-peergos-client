use crate::capability::*;
use crate::hashtree::{HashBranch, HashTree};
use peergos_cbor::{CborObject, Cborable};
use peergos_core::keys::PublicKeyHash;
use peergos_core::symmetric::SymmetricKey;
use peergos_core::{hash_to_cid, Bat};
use peergos_crypto::hash::sha256;

#[test]
fn mimetype_detection() {
    use crate::mimetype::calculate_mime_type as m;
    // magic bytes
    assert_eq!(m(&[0x89, b'P', b'N', b'G', 13, 10, 26, 10], "x.png"), "image/png");
    assert_eq!(m(&[0xff, 0xd8, 0xff], "x.jpg"), "image/jpg");
    assert_eq!(m(b"GIF89a", "x.gif"), "image/gif");
    assert_eq!(m(b"%PDF-1.7", "x.pdf"), "application/pdf");
    assert_eq!(m(&[b'P', b'K', 3, 4], "x.zip"), "application/zip");
    assert_eq!(m(&[b'P', b'K', 3, 4], "x.docx"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    // RIFF...WEBP at offset 8
    assert_eq!(m(b"RIFF\0\0\0\0WEBP", "x.webp"), "image/webp");
    // mp4: byte0==0, 'ftyp' at 4, brand at 8
    assert_eq!(m(&[0, 0, 0, 0x18, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm'], "x.mp4"), "video/mp4");
    // text + extension tie-breakers (needs valid utf8 content)
    assert_eq!(m(b"# hello\n", "notes.md"), "text/md");
    assert_eq!(m(b"{\"a\":1}", "x.json"), "application/json");
    assert_eq!(m(b"plain words", "x.txt"), "text/plain");
    assert_eq!(m(b"<html><body>", "x.htm"), "text/html");
    // binary / unknown
    assert_eq!(m(&[0x00, 0x01, 0x99, 0xfe], "x.bin"), "application/octet-stream");
    // truncated utf-8 prefix is tolerated (still text)
    assert_eq!(m(&[b'h', b'i', 0xf0, 0x9f], "x.txt"), "text/plain");
}

#[test]
fn hash_tree_single_chunk_matches_formula() {
    // One chunk: level1 = [ChunkHashList(sha256(data))],
    // root = sha256(CborList([ChunkHashList]).serialize()).
    let data = b"the quick brown fox";
    let chunk_hash = sha256(data);
    let branch = HashTree::build(&[chunk_hash.clone()]).unwrap().branch(0);

    let l1 = branch.level1.clone().unwrap();
    assert_eq!(l1.chunk_hashes, chunk_hash); // 32 bytes, one hash
    assert!(branch.level2.is_none() && branch.level3.is_none());

    let list = CborObject::List(vec![l1.to_cbor()]);
    assert_eq!(branch.root_hash.hash, sha256(&list.to_bytes()));

    // cbor roundtrip
    assert_eq!(HashBranch::from_cbor(&branch.to_cbor()).unwrap(), branch);
}

#[test]
fn hash_tree_multi_chunk_groups_hashes() {
    // 24 chunk hashes → one level-1 list of 24*32 bytes.
    let hashes: Vec<Vec<u8>> = (0u8..24).map(|i| sha256(&[i; 8])).collect();
    let branch = HashTree::build(&hashes).unwrap().branch(0);
    let l1 = branch.level1.unwrap();
    assert_eq!(l1.chunk_hashes.len(), 24 * 32);
    // the concatenation is the chunk hashes in order
    assert_eq!(&l1.chunk_hashes[0..32], &hashes[0][..]);
    assert_eq!(&l1.chunk_hashes[23 * 32..], &hashes[23][..]);
}

const LINK: &str = "http://localhost:7777/secret/z59vuwzfFDotcy4BSS7EPNyKWQcjwn7L2Hg3dLBrqyCyfSbvS5WJLj5/1126520708#uAjtTdWVWURJ";

#[test]
fn secret_link_parses_full_url() {
    let link = SecretLink::from_link(LINK).unwrap();
    assert_eq!(link.label, 1126520708);
    assert_eq!(link.label_string(), "1126520708");
    assert_eq!(link.link_password, "uAjtTdWVWURJ");
    assert_eq!(
        link.owner.to_string(),
        "z59vuwzfFDotcy4BSS7EPNyKWQcjwn7L2Hg3dLBrqyCyfSbvS5WJLj5"
    );
}

#[test]
fn secret_link_parses_bare_path() {
    let link = SecretLink::from_link(
        "secret/z59vuwzfFDotcy4BSS7EPNyKWQcjwn7L2Hg3dLBrqyCyfSbvS5WJLj5/42#pw",
    )
    .unwrap();
    assert_eq!(link.label, 42);
    assert_eq!(link.link_password, "pw");
}

#[test]
fn secret_link_rejects_bad() {
    assert!(SecretLink::from_link("not a link").is_err());
    assert!(SecretLink::from_link("secret/a/b/c#x").is_err());
}

fn pkh(seed: &[u8]) -> PublicKeyHash {
    PublicKeyHash::new(hash_to_cid(seed, false).unwrap()).unwrap()
}

#[test]
fn absolute_capability_cbor_roundtrip_read_only() {
    let cap = AbsoluteCapability::new(
        pkh(b"owner"),
        pkh(b"writer"),
        vec![7u8; MAP_KEY_LENGTH],
        None,
        SymmetricKey::new(vec![3u8; 32], false).unwrap(),
        None,
    )
    .unwrap();
    let decoded = AbsoluteCapability::from_cbor(&cap.to_cbor()).unwrap();
    assert_eq!(decoded, cap);
    assert!(!decoded.is_writable());
}

#[test]
fn absolute_capability_cbor_roundtrip_writable_with_bat() {
    let cap = AbsoluteCapability::new(
        pkh(b"owner"),
        pkh(b"writer"),
        vec![1u8; MAP_KEY_LENGTH],
        Some(Bat::new((0u8..32).collect()).unwrap()),
        SymmetricKey::new(vec![9u8; 32], false).unwrap(),
        Some(SymmetricKey::new(vec![5u8; 32], true).unwrap()),
    )
    .unwrap();
    let decoded = AbsoluteCapability::from_cbor(&cap.to_cbor()).unwrap();
    assert_eq!(decoded, cap);
    assert!(decoded.is_writable());
    assert!(decoded.bat.is_some());
}
