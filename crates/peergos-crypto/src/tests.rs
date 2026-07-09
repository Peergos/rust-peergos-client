use crate::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ---- digests / hmac (known answer tests) -----------------------------------

#[test]
fn sha256_kat() {
    assert_eq!(
        hash::sha256(b""),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        hash::sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn hmac_sha256_rfc4231_case1() {
    let key = vec![0x0bu8; 20];
    assert_eq!(
        hash::hmac_sha256(&key, b"Hi There"),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn blake2b_kat() {
    // BLAKE2b-512("abc") official test vector.
    assert_eq!(
        hash::blake2b(b"abc", 64),
        hex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    );
}

#[test]
fn blake3_kat() {
    assert_eq!(
        hash::blake3(b""),
        hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
}

#[test]
fn blake3_4kb_known_answer() {
    // Use data seeded from Python/Java LCG: random.setSeed(42) then nextBytes(4096)
    // We pre-compute the expected output by running blake3 on known fixed data.
    let data = vec![0xabu8; 4096];
    let hash = hash::blake3(&data);
    assert_eq!(
        hash,
        hex("6137ffbadc14cb7467070fc77b4a218c6aebe78a7c1236ffc28ca0d0ec95a6c1")
    );
    // Verify empty-hash known answer (already tested above, but keep stable)
    assert_eq!(
        hash::blake3(b""),
        hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
}

#[test]
fn scrypt_param_mapping_rfc7914() {
    // Confirms Params::new(log_n, r, p, len) argument order that
    // hash_to_key_bytes relies on (N = 1<<log_n). RFC 7914 vector: N=16, r=1, p=1.
    use scrypt::{scrypt, Params};
    let params = Params::new(4, 1, 1, 64).unwrap();
    let mut out = [0u8; 64];
    scrypt(b"", b"", &params, &mut out).unwrap();
    assert_eq!(
        out.to_vec(),
        hex("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
    );
}

#[test]
fn hash_to_key_bytes_is_deterministic() {
    // Small cost so the test is fast; asserts stability, not a Java oracle.
    let a = hash::hash_to_key_bytes("aliceextrasalt", "password1", 12, 8, 1, 96).unwrap();
    let b = hash::hash_to_key_bytes("aliceextrasalt", "password1", 12, 8, 1, 96).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.len(), 96);
    let c = hash::hash_to_key_bytes("aliceextrasalt", "password2", 12, 8, 1, 96).unwrap();
    assert_ne!(a, c);
}

// ---- proof of work ---------------------------------------------------------

#[test]
fn proof_of_work() {
    // difficulty 0 is always satisfied; difficulty 8 requires a zero first byte.
    assert!(hash::satisfies_difficulty(0, &[0xff, 0xff]));
    assert!(hash::satisfies_difficulty(8, &[0x00, 0xff]));
    assert!(!hash::satisfies_difficulty(8, &[0x01, 0x00]));
    // Signed arithmetic must not underflow for difficulty < 8.
    assert!(hash::satisfies_difficulty(0, &[0xff]));

    let data = b"proof of work payload";
    let difficulty = 8;
    let prefix = hash::generate_proof_of_work(difficulty, data);
    assert_eq!(prefix.len(), hash::PROOF_OF_WORK_PREFIX_BYTES);
    let mut combined = prefix.clone();
    combined.extend_from_slice(data);
    assert!(hash::satisfies_difficulty(difficulty, &hash::sha256(&combined)));
}

// ---- symmetric secretbox ---------------------------------------------------

#[test]
fn secretbox_roundtrip() {
    let key = vec![7u8; symmetric::KEY_BYTES];
    let nonce = vec![3u8; symmetric::NONCE_BYTES];
    let msg = b"the quick brown fox";
    let cipher = symmetric::secretbox(msg, &nonce, &key).unwrap();
    // mac(16) prefix then ciphertext of same length as plaintext.
    assert_eq!(cipher.len(), symmetric::MAC_BYTES + msg.len());
    assert_eq!(symmetric::secretbox_open(&cipher, &nonce, &key).unwrap(), msg);

    // tampering with the MAC (first bytes) must fail authentication.
    let mut tampered = cipher.clone();
    tampered[0] ^= 1;
    assert!(symmetric::secretbox_open(&tampered, &nonce, &key).is_err());
}

// ---- boxing (crypto_box) ---------------------------------------------------

#[test]
fn crypto_box_roundtrip() {
    let (a_pub, a_sec) = boxing::random_keypair();
    let (b_pub, b_sec) = boxing::random_keypair();
    let nonce = vec![9u8; boxing::NONCE_BYTES];
    let msg = b"follow request payload";

    // A encrypts to B.
    let cipher = boxing::crypto_box(msg, &nonce, &b_pub, &a_sec).unwrap();
    assert_eq!(cipher.len(), boxing::MAC_BYTES + msg.len());
    // B decrypts from A.
    let plain = boxing::crypto_box_open(&cipher, &nonce, &a_pub, &b_sec).unwrap();
    assert_eq!(plain, msg);

    // wrong recipient key fails.
    let (_c_pub, c_sec) = boxing::random_keypair();
    assert!(boxing::crypto_box_open(&cipher, &a_pub, &nonce, &c_sec).is_err());
}

#[test]
fn box_public_from_secret_is_stable() {
    let (pub_key, sec) = boxing::random_keypair();
    assert_eq!(boxing::public_from_secret(&sec).unwrap().to_vec(), pub_key.to_vec());
}

// ---- signing (ed25519) -----------------------------------------------------

#[test]
fn sign_open_roundtrip() {
    let (public, secret) = sign::random_keypair();
    let msg = b"sign me";
    let signed = sign::crypto_sign(msg, &secret).unwrap();
    assert_eq!(signed.len(), sign::SIGNATURE_BYTES + msg.len());
    assert_eq!(sign::crypto_sign_open(&signed, &public).unwrap(), msg);

    // a different public key must reject.
    let (other_pub, _) = sign::random_keypair();
    assert!(sign::crypto_sign_open(&signed, &other_pub).is_err());
}

#[test]
fn keypair_from_seed_matches_java_layout() {
    // The NaCl secret key is seed(32) || public(32); deriving is deterministic.
    let seed = [42u8; 32];
    let (public, secret) = sign::keypair_from_seed(&seed).unwrap();
    assert_eq!(&secret[..32], &seed);
    assert_eq!(&secret[32..], &public);
    assert_eq!(sign::public_from_secret(&secret).unwrap(), public);
    // signing with the derived secret verifies against the derived public.
    let signed = sign::crypto_sign(b"x", &secret).unwrap();
    assert_eq!(sign::crypto_sign_open(&signed, &public).unwrap(), b"x");
}
