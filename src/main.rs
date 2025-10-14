//! tholos-pq demo main.rs
//! Demonstrates multi-recipient encryption using:
//! - ML-KEM (Kyber) for key encapsulation
//! - XChaCha20-Poly1305 for payload encryption
//! - Dilithium-3 for sender signatures

use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- 1️⃣ Generate recipient keypairs (A, B, C) ---
    let (pub_a, priv_a) = gen_recipient_keypair("A");
    let (pub_b, priv_b) = gen_recipient_keypair("B");
    let (pub_c, priv_c) = gen_recipient_keypair("C");

    println!("Recipients:");
    println!("  A: {} bytes public key", pub_a.pk_kyber.len());
    println!("  B: {} bytes public key", pub_b.pk_kyber.len());
    println!("  C: {} bytes public key\n", pub_c.pk_kyber.len());

    // --- 2️⃣ Generate sender keypairs (S1, S2) ---
    let s1 = gen_sender_keypair("S1");
    let s2 = gen_sender_keypair("S2");

    println!("Senders:");
    println!("  S1 + S2 generated (Dilithium-3)\n");

    // Build the allowed sender list: (sid, pk_bytes)
    let allowed = vec![
        (s1.sid.clone(), sender_pub(&s1).pk_dilithium),
        (s2.sid.clone(), sender_pub(&s2).pk_dilithium),
    ];

    // --- 3️⃣ Encrypt a message once for A, B, and C ---
    let message = b"Hello post-quantum world — one ciphertext, three recipients!";
    let recipients = vec![pub_a.clone(), pub_b.clone(), pub_c.clone()];

    let wire = encrypt(message, &s1, &recipients)?;
    println!("Encrypted bundle size: {} bytes", wire.len());

    // --- 4️⃣ Each recipient decrypts using their private key ---
    for (name, privkey) in [
        ("A", &priv_a.sk_kyber),
        ("B", &priv_b.sk_kyber),
        ("C", &priv_c.sk_kyber),
    ] {
        let pt = decrypt(&wire, name, privkey, &allowed)?;
        println!("Recipient {name} decrypted: {}", String::from_utf8_lossy(&pt));
        assert_eq!(pt, message);
    }

    // --- 5️⃣ Try with an invalid sender (signature rejection) ---
    println!("\nTesting invalid sender signature rejection...");
    let wire_bad = encrypt(b"forbidden", &s1, &[pub_a.clone()])?;
    let disallowed = vec![(s2.sid.clone(), sender_pub(&s2).pk_dilithium)];
    let res = decrypt(&wire_bad, "A", &priv_a.sk_kyber, &disallowed);
    assert!(res.is_err());
    println!("Invalid sender rejected as expected: {:?}", res.err().unwrap());

    println!("\n✅ All tests passed.");
    Ok(())
}
