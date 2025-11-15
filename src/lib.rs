//! # tholos-pq
//!
//! A pure Rust implementation of post-quantum multi-recipient encryption with a stable,
//! versioned wire format.
//!
//! ## Algorithm Suite
//!
//! - **Key Encapsulation:** ML-KEM-1024 (Kyber-1024) for per-recipient key wrapping
//! - **Symmetric Encryption:** XChaCha20-Poly1305 for payload and CEK encryption
//! - **Digital Signatures:** Dilithium-3 for sender authentication
//! - **Wire Format:** Canonical CBOR with versioning
//!
//! ## Features
//!
//! - Multi-recipient encryption: encrypt once for N recipients
//! - Sender authentication: verify sender identity and signature
//! - Post-quantum security: all primitives are quantum-resistant
//! - Stable wire format: versioned format for interoperability
//! - Pure Rust: no C dependencies
//!
//! ## Example
//!
//! ```rust
//! use tholos_pq::*;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate recipient keypairs
//! let (pub_a, priv_a) = gen_recipient_keypair("A");
//! let (pub_b, priv_b) = gen_recipient_keypair("B");
//!
//! // Generate sender keypair
//! let sender = gen_sender_keypair("S1");
//!
//! // Build allowed sender list
//! let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];
//!
//! // Encrypt message for multiple recipients
//! let message = b"Hello, post-quantum world!";
//! let wire = encrypt(message, &sender, &[pub_a.clone(), pub_b.clone()])?;
//!
//! // Each recipient can decrypt
//! let decrypted_a = decrypt(&wire, "A", &priv_a.sk_kyber, &allowed)?;
//! let decrypted_b = decrypt(&wire, "B", &priv_b.sk_kyber, &allowed)?;
//!
//! assert_eq!(decrypted_a, message);
//! assert_eq!(decrypted_b, message);
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! - All cryptographic operations use secure random number generation
//! - Keys should be stored securely and never exposed
//! - The allowed sender list must be managed carefully to prevent unauthorized access
//! - Wire formats should be validated before decryption
//!
//! ## License
//!
//! Licensed under the Apache License, Version 2.0.

mod errors;
mod types;
mod crypto;

pub use errors::TholosError;
pub use types::*;
pub use crypto::*;

