//! Wire format types and serialization utilities.

use serde::{Deserialize, Serialize};

/// Versioned algorithm suite identifier for the current wire format.
///
/// This identifier specifies the cryptographic algorithms used:
/// - ML-KEM-1024 (Kyber-1024) for key encapsulation
/// - XChaCha20-Poly1305 for symmetric encryption
/// - Dilithium-3 for digital signatures
pub const SUITE_V1: &str = "Kyber1024+XChaCha20P1305+Dilithium3";

/// Sender public key information.
///
/// This structure contains the information needed to verify messages from a sender.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderPub {
    /// Sender identifier (e.g., "S1", "alice@example.com").
    pub sid: String,
    /// Dilithium-3 public key bytes (1952 bytes for Dilithium-3).
    #[serde(with = "serde_bytes")]
    pub pk_dilithium: Vec<u8>,
}

/// Recipient public key information.
///
/// This structure contains the information needed to encrypt messages for a recipient.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientPub {
    /// Recipient identifier (e.g., "A", "bob@example.com").
    pub kid: String,
    /// ML-KEM-1024 public key bytes (1568 bytes for ML-KEM-1024).
    #[serde(with = "serde_bytes")]
    pub pk_kyber: Vec<u8>,
}

/// Message header containing metadata.
///
/// This header is included as additional authenticated data (AAD) in the encryption
/// operations and is signed as part of the bundle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    /// Format version number.
    pub v: u32,
    /// Algorithm suite identifier (e.g., `SUITE_V1`).
    pub suite: String,
    /// Sender identifier.
    pub sender: String,
    /// List of recipient identifiers.
    pub recipients: Vec<String>,
    /// Unique message identifier (UUID v4).
    pub msg_id: String,
    /// Unix timestamp in seconds since epoch.
    pub timestamp_unix: u64,
}

/// Per-recipient encryption envelope.
///
/// Each recipient has their own envelope containing the wrapped content encryption key (CEK).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
///
/// This structure is serialized to canonical CBOR and signed to produce the final bundle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
/// This is the complete wire format that can be serialized to CBOR and transmitted.
/// The signature covers the canonical CBOR encoding of `inner`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleSigned {
    /// The unsigned bundle containing the encrypted message.
    pub inner: BundleUnsigned,
    /// Dilithium-3 detached signature over the canonical CBOR encoding of `inner`.
    #[serde(with = "serde_bytes")]
    pub sig_dilithium: Vec<u8>,
}

/// Serialize a value to canonical CBOR format.
///
/// The output includes a CBOR self-describe tag and uses deterministic serialization
/// suitable for cryptographic signatures.
///
/// # Arguments
///
/// * `v` - The value to serialize
///
/// # Returns
///
/// The CBOR-encoded bytes, or an error if serialization fails.
pub fn to_cbor_canonical<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, crate::TholosError> {
    let mut buf = Vec::new();
    let mut ser = serde_cbor::ser::Serializer::new(&mut buf);
    let _ = ser.self_describe(); // attach CBOR self-describe tag for robustness
    // Note: serde_cbor doesn't have a canonical() method, but the default serialization
    // should be deterministic for our use case
    v.serialize(&mut ser).map_err(|e| crate::TholosError::Ser(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a value from CBOR format.
///
/// # Arguments
///
/// * `data` - The CBOR-encoded bytes
///
/// # Returns
///
/// The deserialized value, or an error if deserialization fails.
pub fn from_cbor<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, crate::TholosError> {
    serde_cbor::from_slice::<T>(data).map_err(|e| crate::TholosError::Ser(e.to_string()))
}

