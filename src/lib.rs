#![doc = include_str!("../README.md")]

//! Post-quantum multi-recipient encryption with a versioned wire format.

mod crypto;
mod errors;
mod types;

pub use crypto::{
    decrypt, encrypt, encrypt_with, gen_recipient_keypair, gen_recipient_keypair_with,
    gen_sender_keypair, gen_sender_keypair_deterministic, sender_keypair_from_bytes, sender_pub,
    verify_header, EncryptOptions, RecipientPriv, SenderKeypair,
};
pub use errors::TholosError;
pub use types::{
    BundleSigned, BundleUnsigned, Header, RecipientEnvelope, RecipientPub, SenderPub,
    DILITHIUM3_PK_LEN, DILITHIUM3_SIG_LEN, MLKEM1024_PK_LEN, SUITE_V1,
};

/// Unstable helpers for integration tests. Not covered by semver.
#[doc(hidden)]
pub mod __private {
    pub use crate::crypto::test_support::*;
}
