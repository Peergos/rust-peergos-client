use crate::bases::*;
use crate::*;

#[test]
fn base58_vectors() {
    assert_eq!(base58_encode(&[]), "");
    assert_eq!(base58_encode(&[0]), "1");
    assert_eq!(base58_encode(&[0, 0]), "11");
    assert_eq!(base58_encode(&[1]), "2");
    assert_eq!(base58_encode(&[255]), "5Q");
    // leading-zero preservation
    let data = [0u8, 0, 1, 2, 3];
    assert_eq!(base58_decode(&base58_encode(&data)).unwrap(), data);
}

#[test]
fn base32_vectors() {
    // RFC 4648 test vector (padding stripped).
    assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
    // lowercase decodes too (multibase 'b' is lowercase)
    assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar");
}

#[test]
fn base16_roundtrip() {
    let data = [0x00u8, 0x12, 0xab, 0xff];
    assert_eq!(base16_encode(&data), "0012abff");
    assert_eq!(base16_decode("0012abff").unwrap(), data);
}

#[test]
fn multihash_roundtrip() {
    let hash = vec![0x11u8; 32];
    let mh = Multihash::new(MultihashType::Sha2_256, hash.clone()).unwrap();
    let bytes = mh.to_bytes();
    assert_eq!(&bytes[..2], &[0x12, 0x20]); // sha2-256, len 32
    assert_eq!(Multihash::decode(&bytes).unwrap(), mh);
    assert_eq!(mh.get_hash(), &hash[..]);
    // base58 roundtrip
    assert_eq!(Multihash::from_base58(&mh.to_base58()).unwrap(), mh);
}

#[test]
fn multihash_rejects_bad_length() {
    assert!(Multihash::new(MultihashType::Sha2_256, vec![0; 31]).is_err());
}

#[test]
fn cid_v0_known_vector() {
    // Canonical IPFS empty-directory CIDv0.
    let s = "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn";
    let cid = Cid::decode(s).unwrap();
    assert_eq!(cid.version, CID_V0);
    assert_eq!(cid.codec, Codec::DagProtobuf);
    assert_eq!(cid.hash_type(), MultihashType::Sha2_256);
    assert_eq!(cid.to_string(), s);
    let bytes = cid.to_bytes();
    assert_eq!(&bytes[..2], &[0x12, 0x20]);
    assert_eq!(Cid::cast(&bytes).unwrap(), cid);
}

#[test]
fn cid_v1_roundtrip() {
    let hash = vec![0xabu8; 32];
    let cid = Cid::build_v1(Codec::DagCbor, MultihashType::Sha2_256, hash).unwrap();
    let bytes = cid.to_bytes();
    // v1: version(1), codec(0x71 dag-cbor), then multihash
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x71);
    assert_eq!(Cid::cast(&bytes).unwrap(), cid);
    // string form is multibase base58btc (prefix 'z') and roundtrips
    let s = cid.to_string();
    assert!(s.starts_with('z'));
    assert_eq!(Cid::decode(&s).unwrap(), cid);
}

#[test]
fn cid_v1_base32_decode() {
    // A base32 ('b') multibase CIDv1 must decode; re-encoding uses base58btc.
    let hash = vec![0x07u8; 32];
    let cid = Cid::build_v1(Codec::Raw, MultihashType::Sha2_256, hash).unwrap();
    let b32 = {
        let mut s = String::from("b");
        s.push_str(&base32_encode(&cid.to_bytes()).to_lowercase());
        s
    };
    assert_eq!(Cid::decode(&b32).unwrap(), cid);
}
