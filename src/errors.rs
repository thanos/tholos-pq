//! Error types for tholos-pq operations.

use thiserror::Error;

/// Errors that can occur during encryption, decryption, or serialization operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TholosError {
    /// Signature verification failed or sender is not in the allowed list.
    ///
    /// Deliberately indistinguishable from an invalid signature so callers cannot
    /// be used as an oracle for allow-list membership.
    #[error("signature invalid or sender not allowed")]
    BadSignature,

    /// No recipient envelope found for the specified recipient ID.
    #[error("missing envelope for recipient {0}")]
    MissingEnvelope(String),

    /// A field in the wire format is malformed or has an invalid value.
    #[error("malformed field: {0}")]
    Malformed(&'static str),

    /// AEAD encryption or decryption operation failed.
    #[error("aead failure")]
    Aead,

    /// CBOR serialization or deserialization error.
    #[error("serialization error: {0}")]
    Ser(String),

    /// Encryption was requested with no recipients.
    #[error("at least one recipient is required")]
    NoRecipients,

    /// Wire format version or algorithm suite is not supported.
    #[error("unsupported wire format version {v} / suite {suite}")]
    UnsupportedSuite { v: u32, suite: String },
}
