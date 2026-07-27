#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

//! Checked-in wire-format vectors for v0.3.0 (ciborium + ML-DSA-65).
//!
//! Parameters:
//! - recipient ML-KEM key from `StdRng::seed_from_u64(0x7A01_0005)`
//! - sender ML-DSA-65 from seed `0x7A01_0007` (32 bytes, little-endian repeated)
//! - encrypt RNG `StdRng::seed_from_u64(0x7A01_0006)`
//! - msg_id `00000000-0000-4000-8000-000000000001`
//! - timestamp `1700000000`

use rand::rngs::StdRng;
use rand::SeedableRng;
use tholos_pq::*;

const PLAINTEXT: &[u8] = b"tholos-pq wire format vector v0.3.0";
const MSG_ID: &str = "00000000-0000-4000-8000-000000000001";
const TIMESTAMP: u64 = 1_700_000_000;
const KEY_SEED: u64 = 0x7A01_0005;
const ENC_SEED: u64 = 0x7A01_0006;
const SENDER_SEED: [u8; 32] = [
    0x07, 0x00, 0x01, 0x7a, 0x07, 0x00, 0x01, 0x7a, 0x07, 0x00, 0x01, 0x7a, 0x07, 0x00, 0x01, 0x7a,
    0x07, 0x00, 0x01, 0x7a, 0x07, 0x00, 0x01, 0x7a, 0x07, 0x00, 0x01, 0x7a, 0x07, 0x00, 0x01, 0x7a,
];

fn load_hex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn vector_keys() -> (RecipientPub, RecipientPriv, SenderKeypair) {
    let mut key_rng = StdRng::seed_from_u64(KEY_SEED);
    let (pub_r, priv_r) = gen_recipient_keypair_with("vector-recipient", &mut key_rng);
    let sender = gen_sender_keypair_deterministic("vector-sender", &SENDER_SEED);
    (pub_r, priv_r, sender)
}

fn make_wire(pub_r: &RecipientPub, sender: &SenderKeypair) -> Vec<u8> {
    let mut enc_rng = StdRng::seed_from_u64(ENC_SEED);
    encrypt_with(
        PLAINTEXT,
        sender,
        std::slice::from_ref(pub_r),
        EncryptOptions {
            rng: &mut enc_rng,
            msg_id: MSG_ID.into(),
            timestamp_unix: TIMESTAMP,
        },
    )
    .unwrap()
}

#[test]
fn decrypt_stored_wire_vector() {
    let (pub_r, priv_r, sender) = vector_keys();
    assert_eq!(pub_r.pk_kyber.len(), MLKEM1024_PK_LEN);
    assert_eq!(sender.public_key_bytes().len(), DILITHIUM3_PK_LEN);

    let wire = load_hex(include_str!("data/v0.3.0/wire.hex"));
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let header = verify_header(&wire, &allowed).unwrap();
    assert_eq!(header.v, 1);
    assert_eq!(header.suite, SUITE_V1);
    assert_eq!(header.msg_id, MSG_ID);
    assert_eq!(header.timestamp_unix, TIMESTAMP);

    let pt = decrypt(&wire, "vector-recipient", &priv_r.sk_kyber, &allowed).unwrap();
    assert_eq!(pt, PLAINTEXT);
}

#[test]
fn encrypt_with_seed_matches_stored_wire() {
    let (pub_r, _, sender) = vector_keys();
    let expected = load_hex(include_str!("data/v0.3.0/wire.hex"));
    let wire = make_wire(&pub_r, &sender);
    assert_eq!(
        wire, expected,
        "encoder drift: regenerating with the same seeds must match tests/data/v0.3.0/wire.hex"
    );
}

/// Regenerates `tests/data/v0.3.0/*.hex` when run with `--ignored --nocapture`.
#[test]
#[ignore]
fn regenerate_vector_files() {
    use std::fs;
    use std::path::PathBuf;

    let (pub_r, _, sender) = vector_keys();
    let wire = make_wire(&pub_r, &sender);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/v0.3.0");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("sender_pk.hex"),
        hex::encode(sender.public_key_bytes()),
    )
    .unwrap();
    fs::write(
        dir.join("sender_sk.hex"),
        hex::encode(sender.private_key_bytes()),
    )
    .unwrap();
    fs::write(dir.join("wire.hex"), hex::encode(&wire)).unwrap();
    println!("wrote vectors to {}", dir.display());
    println!("wire_len={}", wire.len());
}
