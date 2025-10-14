use thiserror::Error;

#[derive(Debug, Error)]
pub enum TholosError {
    #[error("signature invalid or sender not allowed")]
    BadSignature,
    #[error("missing envelope for recipient {0}")]
    MissingEnvelope(String),
    #[error("malformed field: {0}")]
    Malformed(&'static str),
    #[error("aead failure")]
    Aead,
    #[error("serialization error: {0}")]
    Ser(String),
}

