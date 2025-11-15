//! Cryptographic operations for encryption, decryption, and key generation.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use ml_kem::{MlKem1024, Ciphertext, EncodedSizeUser, KemCore};
use ml_kem::kem::{Decapsulate, Encapsulate};
use pqcrypto_dilithium::dilithium3 as dilithium;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as SigPublicKey,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use time::OffsetDateTime;

use crate::errors::TholosError;
use crate::types::*;

/// Recipient private key material.
///
/// This structure holds the ML-KEM-1024 decapsulation key needed to decrypt
/// messages addressed to the recipient.
pub struct RecipientPriv {
    /// Recipient identifier.
    pub kid: String,
    /// ML-KEM-1024 decapsulation (secret) key.
    pub sk_kyber: <MlKem1024 as KemCore>::DecapsulationKey,
}

/// Sender keypair for signing messages.
///
/// This structure holds both the public and private Dilithium-3 keys needed
/// to sign and verify messages.
pub struct SenderKeypair {
    /// Sender identifier.
    pub sid: String,
    /// Dilithium-3 public key.
    pub pk_dilithium: dilithium::PublicKey,
    /// Dilithium-3 secret key.
    pub sk_dilithium: dilithium::SecretKey,
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a new recipient keypair.
///
/// This function generates a fresh ML-KEM-1024 keypair for a recipient.
/// The keypair consists of a public key (for encryption) and a private key
/// (for decryption).
///
/// # Arguments
///
/// * `kid` - Recipient identifier (e.g., "alice", "bob@example.com")
///
/// # Returns
///
/// A tuple containing the public key (`RecipientPub`) and private key (`RecipientPriv`).
///
/// # Example
///
/// ```rust
/// use tholos_pq::gen_recipient_keypair;
///
/// let (pub_key, priv_key) = gen_recipient_keypair("alice");
/// ```
pub fn gen_recipient_keypair(kid: &str) -> (RecipientPub, RecipientPriv) {
    let mut rng = OsRng;
    let (sk, pk) = MlKem1024::generate(&mut rng); // ML-KEM (Kyber) pure-Rust
    let pub_bytes = pk.as_bytes().to_vec();
    (
        RecipientPub {
            kid: kid.to_string(),
            pk_kyber: pub_bytes,
        },
        RecipientPriv {
            kid: kid.to_string(),
            sk_kyber: sk,
        },
    )
}

/// Generate a new sender keypair.
///
/// This function generates a fresh Dilithium-3 keypair for a sender.
/// The keypair consists of a public key (for signature verification) and a
/// private key (for signing).
///
/// # Arguments
///
/// * `sid` - Sender identifier (e.g., "server1", "alice@example.com")
///
/// # Returns
///
/// A `SenderKeypair` containing both public and private keys.
///
/// # Example
///
/// ```rust
/// use tholos_pq::gen_sender_keypair;
///
/// let sender = gen_sender_keypair("server1");
/// ```
pub fn gen_sender_keypair(sid: &str) -> SenderKeypair {
    let (pk, sk) = dilithium::keypair();
    SenderKeypair {
        sid: sid.to_string(),
        pk_dilithium: pk,
        sk_dilithium: sk,
    }
}

/// Extract the public key information from a sender keypair.
///
/// This function converts a `SenderKeypair` into a `SenderPub` structure
/// that can be shared with recipients for signature verification.
///
/// # Arguments
///
/// * `sender` - The sender keypair
///
/// # Returns
///
/// A `SenderPub` structure containing the sender ID and public key bytes.
///
/// # Example
///
/// ```rust
/// use tholos_pq::{gen_sender_keypair, sender_pub};
///
/// let sender = gen_sender_keypair("server1");
/// let pub_info = sender_pub(&sender);
/// // Share pub_info.pk_dilithium with recipients
/// ```
pub fn sender_pub(sender: &SenderKeypair) -> SenderPub {
    SenderPub {
        sid: sender.sid.clone(),
        pk_dilithium: sender.pk_dilithium.as_bytes().to_vec(),
    }
}

/* ---------------- Symmetric helpers ---------------- */

fn hkdf32(shared: &[u8], kid: &str, header_cbor: &[u8]) -> [u8; 32] {
    // Domain separation with recipient kid + canonical header CBOR as info
    let hk = Hkdf::<Sha256>::new(Some(kid.as_bytes()), shared);
    let mut okm = [0u8; 32];
    // HKDF expand with a 32-byte output buffer cannot fail (max output is 255 * hash_len = 8160 bytes for SHA-256)
    #[allow(clippy::expect_used)]
    hk.expand(header_cbor, &mut okm)
        .expect("HKDF expand failed - this should never happen with 32-byte output");
    okm
}

fn aead_enc(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, TholosError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from(*nonce24);
    cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload { msg: pt, aad },
        )
        .map_err(|_| TholosError::Aead)
}

fn aead_dec(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, TholosError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from(*nonce24);
    cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| TholosError::Aead)
}

// ============================================================================
// Encryption
// ============================================================================

/// Encrypt a message for multiple recipients and sign it with the sender's key.
///
/// This function performs the following operations:
/// 1. Generates a random content encryption key (CEK)
/// 2. Encrypts the plaintext using XChaCha20-Poly1305 with the CEK
/// 3. For each recipient, performs ML-KEM key encapsulation and wraps the CEK
/// 4. Signs the bundle with Dilithium-3
/// 5. Serializes the result to canonical CBOR
///
/// # Arguments
///
/// * `plaintext` - The message to encrypt
/// * `sender` - The sender's keypair for signing
/// * `recipients` - Slice of recipient public keys
///
/// # Returns
///
/// The canonical CBOR-encoded wire format bytes, or an error if encryption fails.
///
/// # Errors
///
/// Returns `TholosError` if:
/// - Key encapsulation fails
/// - AEAD encryption fails
/// - CBOR serialization fails
///
/// # Example
///
/// ```rust
/// use tholos_pq::*;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let sender = gen_sender_keypair("alice");
/// let (pub_key, _) = gen_recipient_keypair("bob");
///
/// let message = b"Hello, world!";
/// let wire = encrypt(message, &sender, &[pub_key])?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt(
    plaintext: &[u8],
    sender: &SenderKeypair,
    recipients: &[RecipientPub],
) -> Result<Vec<u8>, TholosError> {
    // Header (AAD)
    let header = Header {
        v: 1,
        suite: SUITE_V1.to_string(),
        sender: sender.sid.clone(),
        recipients: recipients.iter().map(|r| r.kid.clone()).collect(),
        msg_id: uuid::Uuid::new_v4().to_string(),
        timestamp_unix: OffsetDateTime::now_utc().unix_timestamp() as u64,
    };
    let header_cbor = to_cbor_canonical(&header)?;

    // CEK
    let mut rng = OsRng;
    let mut cek = [0u8; 32];
    rng.fill_bytes(&mut cek);

    // Payload AEAD
    let mut pay_nonce = [0u8; 24];
    rng.fill_bytes(&mut pay_nonce);
    let ciphertext = aead_enc(&cek, &pay_nonce, &header_cbor, plaintext)?;

    // Envelopes (one per recipient)
    let mut envs = Vec::with_capacity(recipients.len());
    for r in recipients {
        let pk_bytes: &[u8] = &r.pk_kyber;
        let pk = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&pk_bytes.try_into().map_err(|_| TholosError::Malformed("ml-kem pk"))?);
        let (kem_ct, shared) = pk.encapsulate(&mut rng).map_err(|_| TholosError::Malformed("encapsulation"))?;

        let kek = hkdf32(shared.as_slice(), &r.kid, &header_cbor);

        let mut wrap_nonce = [0u8; 24];
        rng.fill_bytes(&mut wrap_nonce);
        let wrapped_cek = aead_enc(&kek, &wrap_nonce, &header_cbor, &cek)?;

        envs.push(RecipientEnvelope {
            kid: r.kid.clone(),
            kem_ct: kem_ct.as_slice().to_vec(),
            wrap_nonce: wrap_nonce.to_vec(),
            wrapped_cek,
        });
    }

    let inner = BundleUnsigned {
        header,
        pay_nonce: pay_nonce.to_vec(),
        ciphertext,
        recipients: envs,
    };

    // Sign canonical CBOR of inner
    let inner_cbor = to_cbor_canonical(&inner)?;
    let sig = dilithium::detached_sign(&inner_cbor, &sender.sk_dilithium);

    let bundle = BundleSigned {
        inner,
        sig_dilithium: sig.as_bytes().to_vec(),
    };

    // Final canonical CBOR wire
    to_cbor_canonical(&bundle)
}

// ============================================================================
// Decryption
// ============================================================================

/// Decrypt a message as a recipient and verify the sender's signature.
///
/// This function performs the following operations:
/// 1. Deserializes the wire format from CBOR
/// 2. Verifies the sender is in the allowed list
/// 3. Verifies the Dilithium-3 signature
/// 4. Finds the recipient's envelope
/// 5. Decapsulates the ML-KEM ciphertext to recover the KEK
/// 6. Unwraps the CEK using the KEK
/// 7. Decrypts the payload using the CEK
///
/// # Arguments
///
/// * `wire_cbor` - The CBOR-encoded wire format bytes
/// * `my_kid` - The recipient's identifier (must match one in the message)
/// * `my_sk` - The recipient's ML-KEM decapsulation key
/// * `allowed_senders` - List of (sender_id, public_key_bytes) pairs for signature verification
///
/// # Returns
///
/// The decrypted plaintext, or an error if decryption or verification fails.
///
/// # Errors
///
/// Returns `TholosError` if:
/// - The sender is not in the allowed list (`BadSignature`)
/// - Signature verification fails (`BadSignature`)
/// - No envelope is found for the recipient (`MissingEnvelope`)
/// - ML-KEM decapsulation fails (`Malformed`)
/// - AEAD decryption fails (`Aead`)
/// - CBOR deserialization fails (`Ser`)
///
/// # Example
///
/// ```rust
/// use tholos_pq::*;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let sender = gen_sender_keypair("alice");
/// let (pub_key, priv_key) = gen_recipient_keypair("bob");
/// let allowed = vec![(sender.sid.clone(), sender_pub(&sender).pk_dilithium)];
///
/// let wire = encrypt(b"Hello", &sender, &[pub_key.clone()])?;
/// let plaintext = decrypt(&wire, "bob", &priv_key.sk_kyber, &allowed)?;
/// assert_eq!(plaintext, b"Hello");
/// # Ok(())
/// # }
/// ```
pub fn decrypt(
    wire_cbor: &[u8],
    my_kid: &str,
    my_sk: &<MlKem1024 as KemCore>::DecapsulationKey,
    allowed_senders: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, TholosError> {
    let bundle: BundleSigned = crate::types::from_cbor(wire_cbor)?;

    // Verify sender + signature
    let sender_sid = &bundle.inner.header.sender;
    let Some((_, pk_bytes)) = allowed_senders.iter().find(|(sid, _)| sid == sender_sid) else {
        return Err(TholosError::BadSignature);
    };
    let pk = dilithium::PublicKey::from_bytes(pk_bytes)
        .map_err(|_| TholosError::Malformed("dilithium pk"))?;
    let inner_cbor = crate::types::to_cbor_canonical(&bundle.inner)?;
    let sig = dilithium::DetachedSignature::from_bytes(&bundle.sig_dilithium)
        .map_err(|_| TholosError::Malformed("signature"))?;
    dilithium::verify_detached_signature(&sig, &inner_cbor, &pk)
        .map_err(|_| TholosError::BadSignature)?;

    // Find my envelope
    let env = bundle
        .inner
        .recipients
        .iter()
        .find(|e| e.kid == my_kid)
        .ok_or_else(|| TholosError::MissingEnvelope(my_kid.to_string()))?;

    // ML-KEM decapsulate → KEK
    if env.wrap_nonce.len() != 24 {
        return Err(TholosError::Malformed("wrap nonce"));
    }
    let kem_ct_bytes: &[u8] = &env.kem_ct;
    let kem_ct: Ciphertext<MlKem1024> = kem_ct_bytes.try_into().map_err(|_| TholosError::Malformed("kem_ct"))?;
    let shared = my_sk.decapsulate(&kem_ct).map_err(|_| TholosError::Malformed("decapsulation"))?;

    let header_cbor = crate::types::to_cbor_canonical(&bundle.inner.header)?;
    let kek = hkdf32(shared.as_slice(), my_kid, &header_cbor);

    // Unwrap CEK
    let mut wrap_nonce = [0u8; 24];
    wrap_nonce.copy_from_slice(&env.wrap_nonce);
    let cek = aead_dec(&kek, &wrap_nonce, &header_cbor, &env.wrapped_cek)?;

    if cek.len() != 32 {
        return Err(TholosError::Malformed("cek length"));
    }
    let mut cek_arr = [0u8; 32];
    cek_arr.copy_from_slice(&cek);

    // Decrypt payload
    if bundle.inner.pay_nonce.len() != 24 {
        return Err(TholosError::Malformed("pay nonce"));
    }
    let mut pay_nonce = [0u8; 24];
    pay_nonce.copy_from_slice(&bundle.inner.pay_nonce);

    let pt = aead_dec(&cek_arr, &pay_nonce, &header_cbor, &bundle.inner.ciphertext)?;
    Ok(pt)
}
