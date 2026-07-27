# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-27

### Changed

- **Breaking:** `BundleSigned.inner` is now opaque signed CBOR bytes; signatures cover the transmitted bytes verbatim (fixes malleability where tag-stripped or re-encoded bundles verified incorrectly).
- **Breaking:** wire structs reject unknown CBOR fields (`deny_unknown_fields`).
- **Breaking:** `encrypt` returns `NoRecipients` when the recipient list is empty.
- **Breaking:** `decrypt` returns `UnsupportedSuite` for unsupported `header.v` / `header.suite` values.
- **Breaking:** CBOR codec migrated from unmaintained `serde_cbor` to `ciborium`.
- **Breaking:** signing backend migrated from `pqcrypto-dilithium` (PQClean C) to pure-Rust `dilithium-rs` (ML-DSA-65); suite id is now `Kyber1024+XChaCha20P1305+MlDsa65`.
- Renamed internal CBOR helper from `to_cbor_canonical` to `to_cbor`; documentation no longer claims RFC canonical CBOR.
- Explicit public API re-exports; test helpers moved to `tholos_pq::__private` (not semver-stable).
- Demo moved from `src/main.rs` to `examples/demo.rs` (no longer published as a binary crate root).
- Replaced `time` dependency with `std::time::SystemTime`.
- Enabled `ml-kem` `zeroize` feature for decapsulation-key wipe-on-drop.
- CI actions pinned to commit SHAs.

### Added

- `encrypt_with` / `EncryptOptions` for deterministic encryption (test vectors).
- `gen_recipient_keypair_with`, `gen_sender_keypair_deterministic`, and `sender_keypair_from_bytes`.
- `verify_header(wire, allowed_senders)` for authenticated header inspection (replay tracking).
- `NoRecipients` and `UnsupportedSuite` error variants.
- Recipient list consistency validation (header vs envelopes, no duplicate `kid`s).
- Zeroization of content encryption keys, derived key material, and ML-DSA secret keys on drop.
- Checked-in wire-format vectors under `tests/data/v0.3.0/`.
- Security regression tests (tag stripping, unknown field injection).
- CI: doctests, `cargo doc`, MSRV job (1.85), dependency audit, `--locked` builds.
- MSRV raised to 1.85 (`dilithium-rs`, `uuid`, `zeroize`, lockfile v4).
- Publish workflow runs tests before release.
- `package.metadata.docs.rs` configuration.

### Fixed

- Test suite integrity issues (no-op assertions, misnamed tests, duplicate tests removed).
- Documentation accuracy (removed false forward-secrecy claims; pure-Rust crypto stack is now accurate).

### Security

- Signatures now authenticate exact on-wire bytes.
- Unknown fields in signed structures are rejected at deserialization.
- Removed unmaintained `serde_cbor` (RUSTSEC-2021-0127) in favor of `ciborium`.
- Removed C/PQClean Dilithium dependency; ML-DSA-65 secrets zeroize via `dilithium-rs`.

## [0.1.1] - 2025-11-15

### Added

- GitHub Actions CI, coverage (Coveralls), and crates.io publish workflows.
- Clippy warning fixes.

## [0.1.0] - 2025-11-15

### Added

- Initial release: multi-recipient ML-KEM-1024 + XChaCha20-Poly1305 + Dilithium-3 encryption.
- Property-based and integration tests.
