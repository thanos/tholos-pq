# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-XX-XX

### Added

- Initial release of tholos-pq
- Multi-recipient encryption using ML-KEM-1024 for key encapsulation
- XChaCha20-Poly1305 for symmetric encryption of payload and content encryption keys
- Dilithium-3 for sender authentication and message signing
- Canonical CBOR wire format with versioning
- Key generation functions for recipients and senders
- Comprehensive error handling with `TholosError` enum
- Full test suite including unit tests, integration tests, and property-based tests
- Complete Rust documentation for all public APIs
- Support for empty message encryption
- Sender allow-list policy enforcement

### Security

- All cryptographic operations use secure random number generation
- Post-quantum algorithms throughout (ML-KEM-1024, Dilithium-3)
- Proper key derivation using HKDF-SHA256
- Authenticated encryption for all ciphertexts
- Signature verification before decryption

### Documentation

- Complete API documentation with examples
- README with usage examples
- Inline code documentation following Rust standards
- Security considerations documented

### Testing

- Unit tests for all cryptographic operations
- Integration tests for round-trip encryption/decryption
- Property-based tests using proptest
- Error path testing for malformed inputs
- Test coverage for edge cases including empty messages and multiple recipients

