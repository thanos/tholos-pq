# tholos-pq

A pure Rust implementation of post-quantum multi-recipient encryption with a stable, versioned wire format.

## Overview

`tholos-pq` provides a complete solution for encrypting messages to multiple recipients using post-quantum cryptographic algorithms. The library uses ML-KEM-1024 (Kyber-1024) for key encapsulation, XChaCha20-Poly1305 for symmetric encryption, and Dilithium-3 for sender authentication.

## Features

- **Multi-recipient encryption**: Encrypt once for N recipients efficiently
- **Post-quantum security**: All cryptographic primitives are quantum-resistant
- **Sender authentication**: Verify sender identity using Dilithium-3 signatures
- **Stable wire format**: Versioned CBOR format for interoperability
- **Pure Rust**: No C dependencies, safe Rust throughout
- **Comprehensive testing**: Unit tests, integration tests, and property-based tests

## Algorithm Suite

- **Key Encapsulation**: ML-KEM-1024 (Kyber-1024) for per-recipient key wrapping
- **Symmetric Encryption**: XChaCha20-Poly1305 for payload and CEK encryption
- **Digital Signatures**: Dilithium-3 for sender authentication
- **Wire Format**: Canonical CBOR with versioning (`suite = Kyber1024+XChaCha20P1305+Dilithium3`)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tholos-pq = "0.1.0"
```

## Usage

### Basic Example

```rust
use tholos_pq::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate recipient keypairs
    let (pub_a, priv_a) = gen_recipient_keypair("alice");
    let (pub_b, priv_b) = gen_recipient_keypair("bob");

    // Generate sender keypair
    let sender = gen_sender_keypair("server1");

    // Build allowed sender list
    let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

    // Encrypt message for multiple recipients
    let message = b"Hello, post-quantum world!";
    let wire = encrypt(message, &sender, &[pub_a.clone(), pub_b.clone()])?;

    // Each recipient can decrypt
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

let sender = gen_sender_keypair("server1");
let (pub_a, priv_a) = gen_recipient_keypair("alice");
let (pub_b, priv_b) = gen_recipient_keypair("bob");
let (pub_c, priv_c) = gen_recipient_keypair("charlie");

let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];

// Encrypt once for all three recipients
let wire = encrypt(
    b"Message for A, B, and C",
    &sender,
    &[pub_a.clone(), pub_b.clone(), pub_c.clone()]
)?;

// Each recipient can decrypt independently
let pt_a = decrypt(&wire, "alice", &priv_a.sk_kyber, &allowed)?;
let pt_b = decrypt(&wire, "bob", &priv_b.sk_kyber, &allowed)?;
let pt_c = decrypt(&wire, "charlie", &priv_c.sk_kyber, &allowed)?;
```

### Sender Authentication

```rust
use tholos_pq::*;

let sender1 = gen_sender_keypair("server1");
let sender2 = gen_sender_keypair("server2");
let (pub_key, priv_key) = gen_recipient_keypair("recipient");

// Only allow sender1
let allowed = vec![(sender1.sid.clone(), sender_pub(&sender1).pk_dilithium)];

// Message from sender1 succeeds
let wire1 = encrypt(b"Hello", &sender1, &[pub_key.clone()])?;
let pt1 = decrypt(&wire1, "recipient", &priv_key.sk_kyber, &allowed)?;

// Message from sender2 is rejected
let wire2 = encrypt(b"Hello", &sender2, &[pub_key.clone()])?;
let result = decrypt(&wire2, "recipient", &priv_key.sk_kyber, &allowed);
assert!(matches!(result, Err(TholosError::BadSignature)));
```

## API Reference

### Key Generation

- `gen_recipient_keypair(kid: &str) -> (RecipientPub, RecipientPriv)`: Generate a new ML-KEM-1024 keypair for a recipient
- `gen_sender_keypair(sid: &str) -> SenderKeypair`: Generate a new Dilithium-3 keypair for a sender
- `sender_pub(sender: &SenderKeypair) -> SenderPub`: Extract public key information from a sender keypair

### Encryption and Decryption

- `encrypt(plaintext: &[u8], sender: &SenderKeypair, recipients: &[RecipientPub]) -> Result<Vec<u8>, TholosError>`: Encrypt a message for multiple recipients
- `decrypt(wire_cbor: &[u8], my_kid: &str, my_sk: &<MlKem1024 as KemCore>::DecapsulationKey, allowed_senders: &[(String, Vec<u8>)]) -> Result<Vec<u8>, TholosError>`: Decrypt a message as a recipient

### Error Types

The `TholosError` enum includes:
- `BadSignature`: Signature verification failed or sender not allowed
- `MissingEnvelope`: No recipient envelope found for the specified recipient ID
- `Malformed`: A field in the wire format is malformed
- `Aead`: AEAD encryption or decryption operation failed
- `Ser`: CBOR serialization or deserialization error

## Security Considerations

- All cryptographic operations use secure random number generation via `OsRng`
- Private keys should be stored securely and never exposed
- The allowed sender list must be managed carefully to prevent unauthorized access
- Wire formats should be validated before decryption
- This library provides cryptographic primitives; key management and distribution are the application's responsibility

## Testing

The library includes comprehensive test coverage:

- Unit tests for individual functions
- Integration tests for round-trip encryption/decryption
- Property-based tests using `proptest` for correctness validation
- Error path testing for malformed inputs

Run tests with:

```bash
cargo test
```

Run property tests with:

```bash
cargo test --test property
```

## Wire Format

The wire format is a versioned CBOR structure (`BundleSigned`) containing:

- **Header**: Version, suite identifier, sender ID, recipient IDs, message ID, timestamp
- **Payload**: Encrypted plaintext using XChaCha20-Poly1305
- **Recipient Envelopes**: Per-recipient ML-KEM ciphertexts and wrapped CEKs
- **Signature**: Dilithium-3 signature over the unsigned bundle

The format is designed for interoperability and includes versioning to support future algorithm updates.

## Dependencies

- `ml-kem`: Pure Rust ML-KEM-1024 implementation
- `pqcrypto-dilithium`: Dilithium-3 signature implementation
- `chacha20poly1305`: XChaCha20-Poly1305 AEAD encryption
- `serde_cbor`: CBOR serialization
- `hkdf`: Key derivation

## License

Licensed under the Apache License, Version 2.0.

## Contributing

Contributions are welcome. Please ensure all tests pass and code follows Rust conventions.
