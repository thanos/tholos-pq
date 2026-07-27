# tholos-pq

Post-quantum multi-recipient encryption with a versioned CBOR wire format.

## Overview

`tholos-pq` encrypts messages to multiple recipients using ML-KEM-1024 (Kyber-1024) for key encapsulation, XChaCha20-Poly1305 for symmetric encryption, and Dilithium-3 for sender authentication.


[![CI](https://github.com/thanos/tholos-pq/actions/workflows/ci.yml/badge.svg)](https://github.com/thanos/tholos-pq/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/thanos/tholos-pq/badge.svg?branch=main)](https://coveralls.io/github/thanos/tholos-pq?branch=main)
[![crates.io](https://img.shields.io/crates/v/tholos-pq.svg)](https://crates.io/crates/tholos-pq)
[![docs.rs](https://docs.rs/tholos-pq/badge.svg)](https://docs.rs/tholos-pq)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue)](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/)

## Features

- Multi-recipient encryption: encrypt once for N recipients
- Post-quantum algorithms: ML-KEM-1024 and Dilithium-3
- Sender authentication via Dilithium-3 signatures over the signed inner payload
- Versioned CBOR wire format for interoperability
- ML-KEM-1024 and ML-DSA-65 via pure-Rust crates (`ml-kem`, `dilithium-rs`); XChaCha20-Poly1305 via `chacha20poly1305`

## Algorithm Suite

- **Key Encapsulation**: ML-KEM-1024 (Kyber-1024) for per-recipient key wrapping
- **Symmetric Encryption**: XChaCha20-Poly1305 for payload and CEK encryption
- **Digital Signatures**: ML-DSA-65 (Dilithium3) for sender authentication
- **Wire Format**: Versioned CBOR (`suite = Kyber1024+XChaCha20P1305+MlDsa65`)

## Installation

```toml
[dependencies]
tholos-pq = "0.3"
```

## Usage

### Basic Example

```rust
use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (pub_a, priv_a) = gen_recipient_keypair("alice");
    let (pub_b, priv_b) = gen_recipient_keypair("bob");
    let sender = gen_sender_keypair("server1");
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let message = b"Hello, post-quantum world!";
    let wire = encrypt(message, &sender, &[pub_a.clone(), pub_b.clone()])?;

    let decrypted_a = decrypt(&wire, "alice", &priv_a.sk_kyber, &allowed)?;
    let decrypted_b = decrypt(&wire, "bob", &priv_b.sk_kyber, &allowed)?;
    assert_eq!(decrypted_a, message);
    assert_eq!(decrypted_b, message);
    Ok(())
}
```

### Multi-Recipient Encryption

```rust
use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sender = gen_sender_keypair("server1");
    let (pub_a, priv_a) = gen_recipient_keypair("alice");
    let (pub_b, priv_b) = gen_recipient_keypair("bob");
    let (pub_c, priv_c) = gen_recipient_keypair("charlie");
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let wire = encrypt(
        b"Message for A, B, and C",
        &sender,
        &[pub_a.clone(), pub_b.clone(), pub_c.clone()],
    )?;

    let pt_a = decrypt(&wire, "alice", &priv_a.sk_kyber, &allowed)?;
    let pt_b = decrypt(&wire, "bob", &priv_b.sk_kyber, &allowed)?;
    let pt_c = decrypt(&wire, "charlie", &priv_c.sk_kyber, &allowed)?;
    assert_eq!(pt_a, b"Message for A, B, and C");
    assert_eq!(pt_b, b"Message for A, B, and C");
    assert_eq!(pt_c, b"Message for A, B, and C");
    Ok(())
}
```

### Sender Authentication

```rust
use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sender1 = gen_sender_keypair("server1");
    let sender2 = gen_sender_keypair("server2");
    let (pub_key, priv_key) = gen_recipient_keypair("recipient");
    let allowed = vec![(sender1.sid.clone(), sender_pub(&sender1).pk_dilithium)];

    let wire1 = encrypt(b"Hello", &sender1, &[pub_key.clone()])?;
    let pt1 = decrypt(&wire1, "recipient", &priv_key.sk_kyber, &allowed)?;
    assert_eq!(pt1, b"Hello");

    let wire2 = encrypt(b"Hello", &sender2, &[pub_key])?;
    let result = decrypt(&wire2, "recipient", &priv_key.sk_kyber, &allowed);
    assert!(matches!(result, Err(TholosError::BadSignature)));
    Ok(())
}
```

### Inspecting Headers (Replay Protection)

```rust
use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (pub_key, priv_key) = gen_recipient_keypair("recipient");
    let sender = gen_sender_keypair("server1");
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    let wire = encrypt(b"Hello", &sender, &[pub_key])?;
    let header = verify_header(&wire, &allowed)?;
    // Applications can track header.msg_id and header.timestamp_unix for replay protection.
    let _ = header.msg_id;

    let pt = decrypt(&wire, "recipient", &priv_key.sk_kyber, &allowed)?;
    assert_eq!(pt, b"Hello");
    Ok(())
}
```

## API Reference

### Key Generation

- `gen_recipient_keypair(kid) -> (RecipientPub, RecipientPriv)`
- `gen_sender_keypair(sid) -> SenderKeypair`
- `sender_pub(sender) -> SenderPub`

### Encryption and Decryption

- `encrypt(plaintext, sender, recipients) -> Result<Vec<u8>, TholosError>`
- `decrypt(wire, my_kid, my_sk, allowed_senders) -> Result<Vec<u8>, TholosError>`
- `verify_header(wire, allowed_senders) -> Result<Header, TholosError>`

### Error Types

- `BadSignature`: signature invalid or sender not allowed
- `MissingEnvelope`: no envelope for the recipient
- `Malformed`: invalid wire field
- `Aead`: AEAD failure
- `Ser`: CBOR serialization/deserialization failure
- `NoRecipients`: encrypt called with an empty recipient list
- `UnsupportedSuite`: unsupported version or algorithm suite

## Known Limitations

- No forward secrecy: recipient ML-KEM keys are long-lived; compromise exposes past messages to that recipient
- No replay protection: `msg_id` and `timestamp_unix` are authenticated but not checked; use `verify_header` and track `msg_id` in your application if needed
- CBOR encoding uses maintained `ciborium`; signatures cover encoded `inner` bytes verbatim

## Security Considerations

- Cryptographic operations use `OsRng` for randomness
- Private keys are the caller's responsibility to protect; CEK/KEK material, ML-KEM decapsulation keys, and ML-DSA secret keys are zeroized on drop
- The allowed sender list must be managed carefully
- No forward secrecy: recipient ML-KEM keys are long-lived; compromise exposes past messages to that recipient
- No replay protection: `msg_id` and `timestamp_unix` are authenticated but not checked; use `verify_header` and track `msg_id` in your application if needed

## Testing

The crate includes integration tests, property-based tests (`proptest`), security regression tests, and doctests (this README is included in crate documentation).

```bash
cargo test
cargo test --test property
make check
```

Run the demo:

```bash
cargo run --example demo
```

## Wire Format

The wire format is a versioned CBOR `BundleSigned` structure:

- **`inner`**: opaque signed CBOR bytes encoding the unsigned bundle
- **`sig_dilithium`**: ML-DSA-65 signature over `inner` verbatim

The unsigned bundle contains:

- **Header**: version, suite, sender, recipient IDs, message ID, timestamp
- **Payload**: XChaCha20-Poly1305 ciphertext
- **Recipient Envelopes**: per-recipient ML-KEM ciphertexts and wrapped CEKs

## Dependencies

- `ml-kem`: pure-Rust ML-KEM-1024
- `dilithium-rs`: ML-DSA-65 (Dilithium3)
- `ciborium`: CBOR serialization
- `chacha20poly1305`: XChaCha20-Poly1305
- `hkdf`: key derivation

## License

Licensed under the Apache License, Version 2.0.

## Contributing

Contributions are welcome. Please run `make check` before submitting a pull request.
