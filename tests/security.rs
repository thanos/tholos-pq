#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use tholos_pq::__private::*;
use tholos_pq::*;

#[test]
fn tag_stripped_wire_is_rejected() {
    let (pub_a, priv_a) = gen_recipient_keypair("A");
    let sender = gen_sender_keypair("S1");
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let wire = encrypt(b"secret", &sender, std::slice::from_ref(&pub_a)).unwrap();
    assert_eq!(&wire[..3], &[0xd9, 0xd9, 0xf7]);

    let stripped = wire[3..].to_vec();
    let result = decrypt(&stripped, "A", &priv_a.sk_kyber, &allowed);
    assert!(matches!(
        result,
        Err(TholosError::Malformed("wire self-describe tag"))
    ));
}

#[test]
fn injected_unknown_field_in_inner_is_rejected() {
    let (pub_a, priv_a) = gen_recipient_keypair("A");
    let sender = gen_sender_keypair("S1");
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let wire = encrypt(b"secret", &sender, std::slice::from_ref(&pub_a)).unwrap();
    let bundle = decode_bundle(&wire).unwrap();

    let mut inner: ciborium::Value = decode_cbor(&bundle.inner).unwrap();
    match &mut inner {
        ciborium::Value::Map(map) => {
            map.push((
                ciborium::Value::Text("attacker_field".into()),
                ciborium::Value::Text("injected".into()),
            ));
        }
        _ => panic!("inner not a map"),
    }

    let tampered_inner = encode_cbor(&inner).unwrap();
    let tampered = encode_bundle(&BundleSigned {
        inner: tampered_inner,
        sig_dilithium: bundle.sig_dilithium,
    })
    .unwrap();

    let result = decrypt(&tampered, "A", &priv_a.sk_kyber, &allowed);
    assert!(matches!(
        result,
        Err(TholosError::Ser(_)) | Err(TholosError::BadSignature)
    ));
}

#[test]
fn verify_header_rejects_tampered_wire() {
    let (pub_a, _) = gen_recipient_keypair("A");
    let sender = gen_sender_keypair("S1");
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let wire = encrypt(b"secret", &sender, std::slice::from_ref(&pub_a)).unwrap();
    let mut tampered = wire.clone();
    tampered[20] ^= 0xFF;

    assert!(matches!(
        verify_header(&tampered, &allowed),
        Err(TholosError::BadSignature)
            | Err(TholosError::Aead)
            | Err(TholosError::Malformed(_))
            | Err(TholosError::Ser(_))
    ));
}
