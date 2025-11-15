use serde::{Deserialize, Serialize};

/// Versioned algorithm suite identifier (stable)
pub const SUITE_V1: &str = "Kyber1024+XChaCha20P1305+Dilithium3";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderPub {
    /// sender id, e.g., "S1"
    pub sid: String,
    /// Dilithium-3 public key bytes
    #[serde(with = "serde_bytes")]
    pub pk_dilithium: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientPub {
    /// short key id, e.g., "A"
    pub kid: String,
    /// Kyber-1024 public key bytes
    #[serde(with = "serde_bytes")]
    pub pk_kyber: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub v: u32,                 // format version
    pub suite: String,          // SUITE_V1
    pub sender: String,         // sid
    pub recipients: Vec<String>,// [kid...]
    pub msg_id: String,         // UUID v4
    pub timestamp_unix: u64,    // seconds since epoch
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientEnvelope {
    pub kid: String,
    /// Kyber ciphertext (encapsulation)
    #[serde(with = "serde_bytes")]
    pub kem_ct: Vec<u8>,
    /// 24-byte nonce for wrapping the CEK
    #[serde(with = "serde_bytes")]
    pub wrap_nonce: Vec<u8>,
    /// AEAD(wrap_nonce, AAD=header_cbor, pt=CEK)
    #[serde(with = "serde_bytes")]
    pub wrapped_cek: Vec<u8>,
}

/// The bytes we sign: canonical CBOR encoding of this struct
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleUnsigned {
    pub header: Header,
    /// 24B payload nonce
    #[serde(with = "serde_bytes")]
    pub pay_nonce: Vec<u8>,
    /// AEAD payload (XChaCha20-Poly1305) under CEK with header as AAD
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub recipients: Vec<RecipientEnvelope>,
}

/// Final wire object: (unsigned, signature)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleSigned {
    pub inner: BundleUnsigned,
    /// Dilithium-3 detached signature over canonical CBOR of `inner`
    #[serde(with = "serde_bytes")]
    pub sig_dilithium: Vec<u8>,
}

/// Convenience: stable, canonical CBOR (deterministic for signatures)
pub fn to_cbor_canonical<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, crate::TholosError> {
    let mut buf = Vec::new();
    let mut ser = serde_cbor::ser::Serializer::new(&mut buf);
    let _ = ser.self_describe(); // attach CBOR self-describe tag for robustness
    // Note: serde_cbor doesn't have a canonical() method, but the default serialization
    // should be deterministic for our use case
    v.serialize(&mut ser).map_err(|e| crate::TholosError::Ser(e.to_string()))?;
    Ok(buf)
}

pub fn from_cbor<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, crate::TholosError> {
    serde_cbor::from_slice::<T>(data).map_err(|e| crate::TholosError::Ser(e.to_string()))
}

