# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-15

### Added

- Initial release of tholos-pq
- Multi-recipient encryption using ML-KEM-1024 for key encapsulation
- XChaCha20-Poly1305 for symmetric encryption of payload and content encryption keys
- Dilithium-3 for sender authentication and message signing
- Canonical CBOR wire format with versioning (`suite = Kyber1024+XChaCha20P1305+Dilithium3`)
- Key generation functions: `gen_recipient_keypair()` and `gen_sender_keypair()`
- Encryption function: `encrypt()` for multi-recipient message encryption
- Decryption function: `decrypt()` with sender signature verification
- Comprehensive error handling with `TholosError` enum
- Support for empty message encryption
- Sender allow-list policy enforcement
- Full test suite including unit tests, integration tests, and property-based tests
- Complete Rust documentation for all public APIs with examples

### Security

- All cryptographic operations use secure random number generation (`OsRng`)
- Post-quantum algorithms throughout (ML-KEM-1024, Dilithium-3)
- Proper key derivation using HKDF-SHA256 with domain separation
- Authenticated encryption for all ciphertexts (XChaCha20-Poly1305)
- Signature verification before decryption
- Per-recipient key encapsulation for forward secrecy properties

### Documentation

- Complete API documentation with examples
- README with usage examples and security considerations
- Inline code documentation following Rust standards
- CHANGELOG following Keep a Changelog format

### Testing

- Unit tests for all cryptographic operations
- Integration tests for round-trip encryption/decryption
- Property-based tests using proptest (13 property tests)
- Error path testing for malformed inputs
- Test coverage for edge cases including empty messages and multiple recipients
- Comprehensive test coverage with cargo-tarpaulin

### Technical Details

- Pure Rust implementation with no C dependencies
- ML-KEM-1024 public keys: 1568 bytes
- ML-KEM-1024 ciphertexts: 1568 bytes
- Dilithium-3 public keys: 1952 bytes
- Dilithium-3 signatures: 3293 bytes
- Wire format: Versioned CBOR with self-describe tag

