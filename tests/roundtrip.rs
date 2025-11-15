use tholos_pq::*;

#[test]
fn three_recipients_roundtrip() {
    let (pub_a, priv_a) = gen_recipient_keypair("A");
    let (pub_b, priv_b) = gen_recipient_keypair("B");
    let (pub_c, priv_c) = gen_recipient_keypair("C");
    let s1 = gen_sender_keypair("S1");
    let s2 = gen_sender_keypair("S2");

    let allowed = vec![
        (s1.sid.clone(), sender_pub(&s1).pk_dilithium),
        (s2.sid.clone(), sender_pub(&s2).pk_dilithium),
    ];

    let msg = b"post-quantum hello to A, B, and C!";
    let wire = encrypt(msg, &s1, &[pub_a.clone(), pub_b.clone(), pub_c.clone()]).unwrap();

    // A, B, C can all decrypt
    for (kid, sk) in [("A", &priv_a.sk_kyber), ("B", &priv_b.sk_kyber), ("C", &priv_c.sk_kyber)] {
        let pt = decrypt(&wire, kid, sk, &allowed).unwrap();
        assert_eq!(pt, msg);
    }
}

#[test]
fn signature_rejection() {
    let (pub_a, priv_a) = gen_recipient_keypair("A");
    let s1 = gen_sender_keypair("S1");
    let s2 = gen_sender_keypair("S2");

    // Only S2 allowed → S1's bundle must be rejected
    let allowed = vec![(s2.sid.clone(), sender_pub(&s2).pk_dilithium)];

    let wire = encrypt(b"nope", &s1, std::slice::from_ref(&pub_a)).unwrap();
    let err = decrypt(&wire, "A", &priv_a.sk_kyber, &allowed).unwrap_err();
    matches!(err, TholosError::BadSignature);
}
