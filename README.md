# tholos-pq

Pure post-quantum multi-recipient encryption library.

- **KEM:** Kyber-1024 (per-recipient CEK wrapping)
- **AEAD:** XChaCha20-Poly1305 (payload + CEK wrap)
- **Signature:** Dilithium-3 (allowed-sender policy)
- **Wire:** Canonical CBOR, versioned (`suite = Kyber1024+XChaCha20P1305+Dilithium3`)

## Quick start

```rust
```rust
use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // recipients
    let (pub_a, priv_a) = gen_recipient_keypair("A");
    let (pub_b, priv_b) = gen_recipient_keypair("B");
    let (pub_c, _priv_c) = gen_recipient_keypair("C");

    // senders
    let s1 = gen_sender_keypair("S1");
    let s2 = gen_sender_keypair("S2");

    let allowed = vec![
        (s1.sid.clone(), sender_pub(&s1).pk_dilithium),
        (s2.sid.clone(), sender_pub(&s2).pk_dilithium),
    ];

    // encrypt once for A,B,C
    let wire = encrypt(b"hello PQ world", &s1, &[pub_a.clone(), pub_b.clone(), pub_c.clone()])?;

    // decrypt as B
    let pt = decrypt(&wire, "B", &priv_b.sk_kyber, &allowed)?;
    assert_eq!(&pt, b"hello PQ world");
    Ok(())
}
```

```
```

`
---

### `tests/roundtrip.rs`

```rust
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

    let wire = encrypt(b"nope", &s1, &[pub_a.clone()]).unwrap();
    let err = decrypt(&wire, "A", &priv_a.sk_kyber, &allowed).unwrap_err();
    matches!(err, TholosError::BadSignature);
}
```
```

```

```


```
```


```

