#![allow(clippy::unwrap_used)] // unwrap() is idiomatic in property tests

use proptest::prelude::*;
use tholos_pq::__private::*;
use tholos_pq::*;

// ============================================================================
// Property: Round-trip encryption/decryption
// ============================================================================

proptest! {
    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        message in prop::collection::vec(any::<u8>(), 0..10000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
    ) {
        let (pub_key, priv_key) = gen_recipient_keypair(&recipient_id);
        let sender = gen_sender_keypair(&sender_id);
        let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

        let wire = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;
        let decrypted = decrypt(&wire, &recipient_id, &priv_key.sk_kyber, &allowed)?;

        prop_assert_eq!(decrypted, message);
    }
}

proptest! {
    #[test]
    fn prop_encrypt_decrypt_empty_message(
        recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
    ) {
        let message = b"";
        let (pub_key, priv_key) = gen_recipient_keypair(&recipient_id);
        let sender = gen_sender_keypair(&sender_id);
        let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

        let wire = encrypt(message, &sender, std::slice::from_ref(&pub_key))?;
        let decrypted = decrypt(&wire, &recipient_id, &priv_key.sk_kyber, &allowed)?;

        prop_assert_eq!(decrypted, message);
    }
}

// ============================================================================
// Property: Multiple recipients can all decrypt
// ============================================================================

proptest! {
    #[test]
    fn prop_all_recipients_can_decrypt(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        num_recipients in 1usize..10,
    ) {
        let sender = gen_sender_keypair("SENDER");
        let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

        // Generate N recipients
        let mut recipients = Vec::new();
        let mut pub_keys = Vec::new();
        for i in 0..num_recipients {
            let id = format!("R{}", i);
            let (pub_key, priv_key) = gen_recipient_keypair(&id);
            recipients.push((id, priv_key));
            pub_keys.push(pub_key);
        }

        // Encrypt once for all recipients
        let wire = encrypt(&message, &sender, &pub_keys)?;

        // All recipients should be able to decrypt
        for (id, priv_key) in &recipients {
            let decrypted = decrypt(&wire, id, &priv_key.sk_kyber, &allowed)?;
            prop_assert_eq!(&decrypted, &message);
        }
    }
}

// ============================================================================
// Property: Wrong recipient key cannot decrypt
// ============================================================================

proptest! {
    #[test]
    fn prop_wrong_key_cannot_decrypt(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
        wrong_recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
    ) {
        // Ensure different IDs
        prop_assume!(recipient_id != wrong_recipient_id);

        let (pub_key, _) = gen_recipient_keypair(&recipient_id);
        let (_, wrong_priv_key) = gen_recipient_keypair(&wrong_recipient_id);
        let sender = gen_sender_keypair(&sender_id);
        let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

        // Encrypt for recipient_id
        let wire = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;

        // Wrong recipient should not be able to decrypt
        let result = decrypt(&wire, &recipient_id, &wrong_priv_key.sk_kyber, &allowed);
        prop_assert!(matches!(result, Err(TholosError::Aead)));
    }
}

// ============================================================================
// Property: Invalid sender is rejected
// ============================================================================

proptest! {
    #[test]
    fn prop_invalid_sender_rejected(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
        other_sender_id in "[A-Za-z0-9_]{1,20}",
    ) {
        // Ensure different sender IDs
        prop_assume!(sender_id != other_sender_id);

        let (pub_key, priv_key) = gen_recipient_keypair(&recipient_id);
        let sender = gen_sender_keypair(&sender_id);
        let other_sender = gen_sender_keypair(&other_sender_id);

        // Only other_sender is allowed
        let allowed = vec![(other_sender.sid.clone(), sender_pub(&other_sender).pk_dilithium)];

        // Encrypt with sender (not allowed)
        let wire = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;

        // Should be rejected
        let result = decrypt(&wire, &recipient_id, &priv_key.sk_kyber, &allowed);
        prop_assert!(matches!(result, Err(TholosError::BadSignature)));
    }
}

// ============================================================================
// Property: Wire format is valid CBOR
// ============================================================================

proptest! {
    #[test]
    fn prop_wire_format_valid_cbor(
        message in prop::collection::vec(any::<u8>(), 0..1000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
    ) {
        let (pub_key, _) = gen_recipient_keypair(&recipient_id);
        let sender = gen_sender_keypair(&sender_id);

        let wire = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;

        // Should be valid CBOR
        let bundle = decode_bundle(&wire)?;
        let inner = decode_inner(&bundle.inner)?;

        prop_assert_eq!(inner.header.v, 1);
        prop_assert_eq!(inner.header.suite, SUITE_V1);
        prop_assert_eq!(inner.header.sender, sender_id);
        prop_assert_eq!(inner.header.recipients.len(), 1);
        prop_assert_eq!(&inner.header.recipients[0], &recipient_id);
        prop_assert_eq!(inner.recipients.len(), 1);
        prop_assert_eq!(&inner.recipients[0].kid, &recipient_id);
        prop_assert_eq!(inner.pay_nonce.len(), 24);
        prop_assert_eq!(bundle.sig_dilithium.len(), DILITHIUM3_SIG_LEN);
    }
}

// ============================================================================
// Property: Different encryptions produce different wire formats
// ============================================================================

proptest! {
    #[test]
    fn prop_different_encryptions_different_wire(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
    ) {
        let (pub_key, _) = gen_recipient_keypair(&recipient_id);
        let sender = gen_sender_keypair(&sender_id);

        // Encrypt same message twice
        let wire1 = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;
        let wire2 = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;

        // Wire formats should be different due to randomness (nonces, UUIDs, timestamps)
        prop_assert_ne!(&wire1, &wire2);

        // But both should decode to valid bundles
        let bundle1 = decode_bundle(&wire1)?;
        let bundle2 = decode_bundle(&wire2)?;
        prop_assert_eq!(bundle1.inner.len(), bundle2.inner.len());
    }
}

// ============================================================================
// Property: Key generation produces unique keys
// ============================================================================

proptest! {
    #[test]
    fn prop_key_generation_unique(
        id1 in "[A-Za-z0-9_]{1,20}",
        id2 in "[A-Za-z0-9_]{1,20}",
    ) {
        let (pub1, _) = gen_recipient_keypair(&id1);
        let (pub2, _) = gen_recipient_keypair(&id2);

        // Even with same or different IDs, keys should be different (random generation)
        prop_assert_ne!(&pub1.pk_kyber, &pub2.pk_kyber);

        // Public keys should have correct size (ML-KEM-1024 = 1568 bytes)
        prop_assert_eq!(pub1.pk_kyber.len(), 1568);
        prop_assert_eq!(pub2.pk_kyber.len(), 1568);
    }
}

proptest! {
    #[test]
    fn prop_sender_key_generation_unique(
        id1 in "[A-Za-z0-9_]{1,20}",
        id2 in "[A-Za-z0-9_]{1,20}",
    ) {
        let s1 = gen_sender_keypair(&id1);
        let s2 = gen_sender_keypair(&id2);

        // Keys should be different (random generation)
        prop_assert_ne!(s1.public_key_bytes(), s2.public_key_bytes());

        // Public keys should have correct size (Dilithium-3 = 1952 bytes)
        prop_assert_eq!(s1.public_key_bytes().len(), 1952);
        prop_assert_eq!(s2.public_key_bytes().len(), 1952);
    }
}

// ============================================================================
// Property: Wire format size properties
// ============================================================================

proptest! {
    #[test]
    fn prop_wire_format_size_properties(
        message in prop::collection::vec(any::<u8>(), 0..10000),
        num_recipients in 1usize..5,
    ) {
        let sender = gen_sender_keypair("SENDER");
        let mut pub_keys = Vec::new();
        for i in 0..num_recipients {
            let (pub_key, _) = gen_recipient_keypair(&format!("R{}", i));
            pub_keys.push(pub_key);
        }

        let wire = encrypt(&message, &sender, &pub_keys)?;

        let bundle = decode_bundle(&wire)?;
        let inner = decode_inner(&bundle.inner)?;
        prop_assert_eq!(bundle.sig_dilithium.len(), DILITHIUM3_SIG_LEN);
        prop_assert!(!inner.ciphertext.is_empty() || message.is_empty());
        prop_assert_eq!(inner.recipients.len(), num_recipients);
    }
}

// ============================================================================
// Property: Multiple senders with same recipient
// ============================================================================

proptest! {
    #[test]
    fn prop_multiple_senders_same_recipient(
        message1 in prop::collection::vec(any::<u8>(), 1..1000),
        message2 in prop::collection::vec(any::<u8>(), 1..1000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
    ) {
        let (pub_key, priv_key) = gen_recipient_keypair(&recipient_id);
        let s1 = gen_sender_keypair("S1");
        let s2 = gen_sender_keypair("S2");

        let allowed = vec![
            (s1.sid.clone(), sender_pub(&s1).pk_dilithium),
            (s2.sid.clone(), sender_pub(&s2).pk_dilithium),
        ];

        // Encrypt with both senders
        let wire1 = encrypt(&message1, &s1, std::slice::from_ref(&pub_key))?;
        let wire2 = encrypt(&message2, &s2, std::slice::from_ref(&pub_key))?;

        // Recipient should be able to decrypt both
        let dec1 = decrypt(&wire1, &recipient_id, &priv_key.sk_kyber, &allowed)?;
        let dec2 = decrypt(&wire2, &recipient_id, &priv_key.sk_kyber, &allowed)?;

        prop_assert_eq!(dec1, message1);
        prop_assert_eq!(dec2, message2);
    }
}

// ============================================================================
// Property: Corrupted wire format fails appropriately
// ============================================================================

proptest! {
    #[test]
    fn prop_corrupted_wire_fails(
        message in prop::collection::vec(any::<u8>(), 1..1000),
        recipient_id in "[A-Za-z0-9_]{1,20}",
        sender_id in "[A-Za-z0-9_]{1,20}",
        corruption_idx in any::<prop::sample::Index>(),
    ) {
        let (pub_key, priv_key) = gen_recipient_keypair(&recipient_id);
        let sender = gen_sender_keypair(&sender_id);
        let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

        let wire = encrypt(&message, &sender, std::slice::from_ref(&pub_key))?;

        let mut corrupted = wire.clone();
        let pos = corruption_idx.index(wire.len());
        corrupted[pos] ^= 0xFF;

        let result = decrypt(&corrupted, &recipient_id, &priv_key.sk_kyber, &allowed);
        assert!(matches!(
            result,
            Err(TholosError::BadSignature)
                | Err(TholosError::Aead)
                | Err(TholosError::Malformed(_))
                | Err(TholosError::Ser(_))
                | Err(TholosError::UnsupportedSuite { .. })
        ));
    }
}

// ============================================================================
// Property: CBOR round-trip preserves data
// ============================================================================

proptest! {
    #[test]
    fn prop_cbor_roundtrip_header(
        version in 1u32..10,
        suite in "[A-Za-z0-9+]{1,100}",
        sender_id in "[A-Za-z0-9_]{1,20}",
        recipient_ids in prop::collection::vec("[A-Za-z0-9_]{1,20}", 0..10),
        msg_id in "[0-9a-f-]{36}",
        timestamp in 0u64..2000000000u64,
    ) {
        let header = Header {
            v: version,
            suite: suite.clone(),
            sender: sender_id.clone(),
            recipients: recipient_ids.clone(),
            msg_id: msg_id.clone(),
            timestamp_unix: timestamp,
        };

        let encoded = encode_cbor(&header)?;
        let decoded: Header = decode_cbor(&encoded)?;

        prop_assert_eq!(header.v, decoded.v);
        prop_assert_eq!(header.suite, decoded.suite);
        prop_assert_eq!(header.sender, decoded.sender);
        prop_assert_eq!(header.recipients, decoded.recipients);
        prop_assert_eq!(header.msg_id, decoded.msg_id);
        prop_assert_eq!(header.timestamp_unix, decoded.timestamp_unix);
    }
}
