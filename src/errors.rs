//! Error types for tholos-pq operations.

use thiserror::Error;

/// Errors that can occur during encryption, decryption, or serialization operations.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum TholosError {
    /// Signature verification failed or sender is not in the allowed list.
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
}

