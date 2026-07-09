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

#[test]
fn hash_tree_1k_chunks_single_level() {
    let hashes: Vec<Vec<u8>> = (0..1024).map(|_| [0u8; 32].to_vec()).collect();
    let tree = HashTree::build(&hashes).unwrap();
    assert_eq!(tree.level1.len(), 1);
    assert_eq!(tree.level1[0].chunk_hashes.len(), 1024 * 32);
    assert!(tree.level2.is_empty());
    assert!(tree.level3.is_empty());
}

#[test]
fn hash_tree_2k_chunks_two_levels() {
    let hashes: Vec<Vec<u8>> = (0..2048).map(|_| [0u8; 32].to_vec()).collect();
    let tree = HashTree::build(&hashes).unwrap();
    assert_eq!(tree.level1.len(), 2);
    assert_eq!(tree.level1[0].chunk_hashes.len(), 1024 * 32);
    assert_eq!(tree.level2.len(), 1);
    assert!(tree.level3.is_empty());
}

#[test]
fn hash_tree_1m_chunks_three_level_structure() {
    let hashes: Vec<Vec<u8>> = (0..1024 * 1024).map(|_| [0u8; 32].to_vec()).collect();
    let tree = HashTree::build(&hashes).unwrap();
    assert_eq!(tree.level1.len(), 1024);
    assert_eq!(tree.level2.len(), 1);
    assert!(tree.level3.is_empty());
}

#[test]
fn hash_tree_rejects_empty() {
    assert!(HashTree::build(&[]).is_err());
}

#[test]
fn hash_tree_cbor_roundtrip() {
    let hashes: Vec<Vec<u8>> = (0..2048).map(|i| sha256(&[i as u8; 8])).collect();
    let tree = HashTree::build(&hashes).unwrap();
    for i in 0..2048 {
        let branch = tree.branch(i);
        let decoded = HashBranch::from_cbor(&branch.to_cbor()).unwrap();
        assert_eq!(decoded, branch);
    }
}

use crate::retrieve::{FragmentedPaddedCipherText, CHUNK_MAX_SIZE, FRAGMENT_MAX_LENGTH, INLINE_LIMIT, remove_raw_block_bat_prefix};
use crate::cryptree::ChildrenLinks;
use peergos_core::auth::BatId;
use peergos_crypto::random_bytes;

#[test]
fn fragmented_ciphertext_inlines_small_data() {
    let key = SymmetricKey::new(vec![0u8; 32], false).unwrap();
    // data up to ~4 KB is inlined; the exact threshold depends on CBOR overhead + padding
    for (len, expect_inline) in [(0usize, true), (1000, true), (4000, true), (5000, false), (10000, false)] {
        let data = vec![0u8; len];
        let (fpct, raw) = FragmentedPaddedCipherText::build(&key, &CborObject::ByteString(data), 4096, None).unwrap();
        if expect_inline {
            assert!(fpct.inlined.is_some(), "len={len} should be inlined");
            assert!(fpct.fragments.is_empty(), "len={len} should have no fragments");
            assert!(raw.is_empty(), "len={len} should have no raw blocks");
        } else {
            assert!(fpct.inlined.is_none(), "len={len} should NOT be inlined");
            assert!(!fpct.fragments.is_empty(), "len={len} should have fragments");
        }
    }
}

#[test]
fn fragmented_ciphertext_fragment_count_and_alignment() {
    let key = SymmetricKey::new(vec![0u8; 32], false).unwrap();
    let bat = Bat::new(random_bytes(32)).unwrap();
    let mirror_bat = BatId::sha256(&bat).unwrap();

    let test_lens: Vec<usize> = vec![
        0, 4000, 4093, 4096, 4099,
        FRAGMENT_MAX_LENGTH - 3, FRAGMENT_MAX_LENGTH, FRAGMENT_MAX_LENGTH + 3,
        CHUNK_MAX_SIZE as usize - 4, CHUNK_MAX_SIZE as usize,
    ];

    for len in test_lens {
        let data = vec![0u8; len];
        let (fpct, raw) = FragmentedPaddedCipherText::build(
            &key, &CborObject::ByteString(data), 4096, Some(&mirror_bat),
        ).unwrap();

        // All raw blocks should be block-aligned (after stripping bat prefix)
        for block in &raw {
            let stripped = remove_raw_block_bat_prefix(block).unwrap();
            assert_eq!(stripped.len() % 4096, 0, "misaligned block for len={len}");
        }
        assert!(raw.len() as u64 <= CHUNK_MAX_SIZE / FRAGMENT_MAX_LENGTH as u64,
            "too many fragments for len={len}: {} (max {})", raw.len(), CHUNK_MAX_SIZE / FRAGMENT_MAX_LENGTH as u64);

        if len > INLINE_LIMIT {
            let expected_frags = (len + FRAGMENT_MAX_LENGTH - 1) / FRAGMENT_MAX_LENGTH;
            assert_eq!(fpct.fragments.len(), expected_frags,
                "wrong fragment count for len={len}: expected {expected_frags}, got {}", fpct.fragments.len());
            assert_eq!(raw.len(), expected_frags,
                "wrong raw block count for len={len}: expected {expected_frags}, got {}", raw.len());
        } else {
            assert!(fpct.fragments.is_empty(), "len={len} should have no fragments");
            assert!(raw.is_empty(), "len={len} should have no raw blocks");
        }
    }
}

#[test]
fn fragmented_ciphertext_directory_small_file_equality() {
    let key = SymmetricKey::new(vec![1u8; 32], false).unwrap();
    let bat = Bat::new(random_bytes(32)).unwrap();
    let mirror_bat = BatId::sha256(&bat).unwrap();

    // Empty file
    let empty_file = CborObject::ByteString(Vec::new());
    let (fpct_file, _) = FragmentedPaddedCipherText::build(
        &key, &empty_file, 4096, Some(&mirror_bat),
    ).unwrap();

    // Empty directory
    let empty_dir = ChildrenLinks::Named(Vec::new()).to_cbor();
    let (fpct_dir, _) = FragmentedPaddedCipherText::build(
        &key, &empty_dir, 4096, Some(&mirror_bat),
    ).unwrap();

    // Same cbor length
    assert_eq!(fpct_file.to_cbor().to_bytes().len(), fpct_dir.to_cbor().to_bytes().len());
    // Same inline content length
    assert_eq!(fpct_file.inlined.as_ref().map(|b| b.len()), fpct_dir.inlined.as_ref().map(|b| b.len()));
}
