use crate::*;

fn enc(o: &CborObject) -> Vec<u8> {
    o.to_bytes()
}

fn roundtrip(o: &CborObject) {
    let bytes = o.to_bytes();
    let decoded = CborObject::from_bytes(&bytes).expect("decode");
    assert_eq!(&decoded, o, "roundtrip mismatch for {o:?}");
    // Re-encoding the decoded value must be byte-identical (canonical).
    assert_eq!(decoded.to_bytes(), bytes, "re-encode not canonical for {o:?}");
}

#[test]
fn unsigned_integers() {
    // RFC 8949 appendix A vectors.
    assert_eq!(enc(&CborObject::Long(0)), [0x00]);
    assert_eq!(enc(&CborObject::Long(1)), [0x01]);
    assert_eq!(enc(&CborObject::Long(10)), [0x0a]);
    assert_eq!(enc(&CborObject::Long(23)), [0x17]);
    assert_eq!(enc(&CborObject::Long(24)), [0x18, 0x18]);
    assert_eq!(enc(&CborObject::Long(25)), [0x18, 0x19]);
    assert_eq!(enc(&CborObject::Long(100)), [0x18, 0x64]);
    assert_eq!(enc(&CborObject::Long(1000)), [0x19, 0x03, 0xe8]);
    assert_eq!(enc(&CborObject::Long(1_000_000)), [0x1a, 0x00, 0x0f, 0x42, 0x40]);
    assert_eq!(
        enc(&CborObject::Long(1_000_000_000_000)),
        [0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]
    );
}

#[test]
fn negative_integers() {
    assert_eq!(enc(&CborObject::Long(-1)), [0x20]);
    assert_eq!(enc(&CborObject::Long(-10)), [0x29]);
    assert_eq!(enc(&CborObject::Long(-100)), [0x38, 0x63]);
    assert_eq!(enc(&CborObject::Long(-1000)), [0x39, 0x03, 0xe7]);
}

#[test]
fn simple_values() {
    assert_eq!(enc(&CborObject::Boolean(false)), [0xf4]);
    assert_eq!(enc(&CborObject::Boolean(true)), [0xf5]);
    assert_eq!(enc(&CborObject::Null), [0xf6]);
}

#[test]
fn strings_and_bytes() {
    assert_eq!(enc(&CborObject::Str(String::new())), [0x60]);
    assert_eq!(enc(&CborObject::Str("a".into())), [0x61, 0x61]);
    assert_eq!(enc(&CborObject::Str("IETF".into())), [0x64, 0x49, 0x45, 0x54, 0x46]);
    assert_eq!(
        enc(&CborObject::ByteString(vec![0x01, 0x02, 0x03, 0x04])),
        [0x44, 0x01, 0x02, 0x03, 0x04]
    );
}

#[test]
fn arrays_and_maps() {
    assert_eq!(enc(&CborObject::List(vec![])), [0x80]);
    assert_eq!(
        enc(&CborObject::List(vec![
            CborObject::Long(1),
            CborObject::Long(2),
            CborObject::Long(3)
        ])),
        [0x83, 0x01, 0x02, 0x03]
    );

    let m = CborObject::map()
        .put("a", CborObject::Long(1))
        .put("b", CborObject::List(vec![CborObject::Long(2), CborObject::Long(3)]))
        .build();
    assert_eq!(
        enc(&m),
        [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03]
    );
}

#[test]
fn canonical_map_ordering() {
    // Insert out of order; keys must serialize by (utf16 length, then lexico).
    let m = CborObject::map()
        .put("aa", CborObject::Long(3))
        .put("b", CborObject::Long(2))
        .put("a", CborObject::Long(1))
        .build();
    // Expected order: "a", "b" (len 1), then "aa" (len 2).
    assert_eq!(
        enc(&m),
        [
            0xa3, // map(3)
            0x61, 0x61, 0x01, // "a": 1
            0x61, 0x62, 0x02, // "b": 2
            0x62, 0x61, 0x61, 0x03 // "aa": 3
        ]
    );
}

#[test]
fn merkle_link_roundtrip() {
    let cid = vec![0x01, 0x55, 0x12, 0x20, 0xde, 0xad, 0xbe, 0xef];
    let link = CborObject::MerkleLink(cid.clone());
    let bytes = link.to_bytes();
    // tag 42 = 0xd8 0x2a, then byte string of (0x00 || cid).
    let mut expected = vec![0xd8, 0x2a];
    let mut payload = vec![0x00];
    payload.extend_from_slice(&cid);
    expected.push(0x40 | payload.len() as u8); // len 9 fits in the low bits
    expected.extend_from_slice(&payload);
    assert_eq!(bytes, expected);

    let decoded = CborObject::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, link);
    assert_eq!(decoded.links(), vec![cid]);
}

#[test]
fn roundtrips() {
    roundtrip(&CborObject::Long(0));
    roundtrip(&CborObject::Long(-1));
    roundtrip(&CborObject::Long(i64::MAX));
    roundtrip(&CborObject::Long(i64::MIN));
    roundtrip(&CborObject::Boolean(true));
    roundtrip(&CborObject::Null);
    roundtrip(&CborObject::Str("héllo wörld".into()));
    roundtrip(&CborObject::ByteString(vec![0, 1, 2, 255]));
    roundtrip(
        &CborObject::map()
            .put("name", CborObject::Str("peergos".into()))
            .put("n", CborObject::Long(42))
            .put("flag", CborObject::Boolean(false))
            .put("link", CborObject::MerkleLink(vec![0x12, 0x20, 9, 9, 9]))
            .build(),
    );
}

#[test]
fn extreme_integers() {
    // i64::MIN: sign extends, magnitude = !MIN = MAX, negative major type.
    assert_eq!(
        enc(&CborObject::Long(i64::MIN)),
        [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(
        enc(&CborObject::Long(i64::MAX)),
        [0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

#[test]
fn rejects_trailing_and_empty() {
    assert!(CborObject::from_bytes(&[]).is_err());
    assert!(CborObject::from_bytes(&[0x00, 0x00]).is_err()); // trailing byte
}

#[test]
fn typed_accessors() {
    let m = CborObject::map()
        .put("count", CborObject::Long(7))
        .put("name", CborObject::Str("x".into()))
        .build();
    assert_eq!(m.get("count").and_then(|v| v.as_long()), Some(7));
    assert_eq!(m.get("name").and_then(|v| v.as_string()), Some("x"));
    assert!(m.get("missing").is_none());
}
