//! Wire format types and serialization utilities.

use serde::{Deserialize, Serialize};

/// Versioned algorithm suite identifier for the current wire format.
///
/// - ML-KEM-1024 for key encapsulation
/// - XChaCha20-Poly1305 for symmetric encryption
/// - ML-DSA-65 (Dilithium3) for digital signatures
pub const SUITE_V1: &str = "Kyber1024+XChaCha20P1305+MlDsa65";

/// ML-DSA-65 / Dilithium3 detached signature length in bytes.
pub const DILITHIUM3_SIG_LEN: usize = 3309;

/// ML-DSA-65 / Dilithium3 public key length in bytes.
pub const DILITHIUM3_PK_LEN: usize = 1952;

/// ML-KEM-1024 public key and ciphertext length in bytes.
pub const MLKEM1024_PK_LEN: usize = 1568;

/// CBOR self-describe tag (RFC 8949 tag 55799): `d9 d9 f7`.
const CBOR_SELF_DESCRIBE_TAG: [u8; 3] = [0xd9, 0xd9, 0xf7];

/// Sender public key information.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SenderPub {
    /// Sender identifier (e.g., "S1", "alice@example.com").
    pub sid: String,
    /// ML-DSA-65 public key bytes (1952 bytes).
    #[serde(with = "serde_bytes")]
    pub pk_dilithium: Vec<u8>,
}

/// Recipient public key information.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecipientPub {
    /// Recipient identifier (e.g., "A", "bob@example.com").
    pub kid: String,
    /// ML-KEM-1024 public key bytes (1568 bytes).
    #[serde(with = "serde_bytes")]
    pub pk_kyber: Vec<u8>,
}

/// Message header containing metadata.
///
/// The `recipients` list must match the `kid` values in the envelope list exactly
/// (same order and contents) for a valid bundle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Format version number.
    pub v: u32,
    /// Algorithm suite identifier (e.g., `SUITE_V1`).
    pub suite: String,
    /// Sender identifier.
    pub sender: String,
    /// List of recipient identifiers; must match envelope `kid` values in order.
    pub recipients: Vec<String>,
    /// Unique message identifier (UUID v4).
    pub msg_id: String,
    /// Unix timestamp in seconds since epoch.
    pub timestamp_unix: u64,
}

/// Per-recipient encryption envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecipientEnvelope {
    /// Recipient identifier.
    pub kid: String,
    /// ML-KEM ciphertext from key encapsulation (1568 bytes for ML-KEM-1024).
    #[serde(with = "serde_bytes")]
    pub kem_ct: Vec<u8>,
    /// 24-byte nonce used for wrapping the CEK.
    #[serde(with = "serde_bytes")]
    pub wrap_nonce: Vec<u8>,
    /// Wrapped CEK: `AEAD(kek, wrap_nonce, header_cbor, cek)`.
    #[serde(with = "serde_bytes")]
    pub wrapped_cek: Vec<u8>,
}

/// Unsigned bundle containing the encrypted message and recipient envelopes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleUnsigned {
    /// Message header.
    pub header: Header,
    /// 24-byte nonce used for payload encryption.
    #[serde(with = "serde_bytes")]
    pub pay_nonce: Vec<u8>,
    /// Encrypted payload: `AEAD(cek, pay_nonce, header_cbor, plaintext)`.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// Recipient envelopes, one per recipient.
    pub recipients: Vec<RecipientEnvelope>,
}

/// Final signed bundle ready for transmission.
///
/// The ML-DSA-65 signature covers `inner` verbatim. Only deserialize `inner`
/// after signature verification succeeds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleSigned {
    /// CBOR encoding of [`BundleUnsigned`], signed verbatim.
    #[serde(with = "serde_bytes")]
    pub inner: Vec<u8>,
    /// ML-DSA-65 detached signature over `inner`.
    #[serde(with = "serde_bytes")]
    pub sig_dilithium: Vec<u8>,
}

/// Serialize a value to CBOR with a self-describe tag, using `ciborium`.
///
/// Output is deterministic for a fixed `ciborium` version but is not full
/// RFC 8949 canonical CBOR. Signatures cover the encoded `inner` bytes exactly
/// as produced here.
pub(crate) fn to_cbor<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, crate::TholosError> {
    let mut buf = CBOR_SELF_DESCRIBE_TAG.to_vec();
    ciborium::ser::into_writer(v, &mut buf).map_err(|e| crate::TholosError::Ser(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a value from CBOR (optional leading self-describe tag is stripped
/// only by callers that already validated the outer wire tag).
pub(crate) fn from_cbor<T: serde::de::DeserializeOwned>(
    data: &[u8],
) -> Result<T, crate::TholosError> {
    let payload = strip_self_describe_prefix(data);
    ciborium::de::from_reader(payload).map_err(|e| crate::TholosError::Ser(e.to_string()))
}

pub(crate) fn strip_self_describe_prefix(data: &[u8]) -> &[u8] {
    if data.len() >= CBOR_SELF_DESCRIBE_TAG.len()
        && data[..CBOR_SELF_DESCRIBE_TAG.len()] == CBOR_SELF_DESCRIBE_TAG
    {
        &data[CBOR_SELF_DESCRIBE_TAG.len()..]
    } else {
        data
    }
}

pub(crate) fn has_self_describe_tag(data: &[u8]) -> bool {
    data.len() >= CBOR_SELF_DESCRIBE_TAG.len()
        && data[..CBOR_SELF_DESCRIBE_TAG.len()] == CBOR_SELF_DESCRIBE_TAG
}
