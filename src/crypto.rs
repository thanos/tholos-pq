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

/// Recipient private (ML-KEM) holder
pub struct RecipientPriv {
    pub kid: String,
    pub sk_kyber: <MlKem1024 as KemCore>::DecapsulationKey, // ML-KEM secret key
}

/// Sender keypair (Dilithium-3)
pub struct SenderKeypair {
    pub sid: String,
    pub pk_dilithium: dilithium::PublicKey,
    pub sk_dilithium: dilithium::SecretKey,
}

/* ---------------- Keygen ---------------- */

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

pub fn gen_sender_keypair(sid: &str) -> SenderKeypair {
    let (pk, sk) = dilithium::keypair();
    SenderKeypair {
        sid: sid.to_string(),
        pk_dilithium: pk,
        sk_dilithium: sk,
    }
}

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
    hk.expand(header_cbor, &mut okm).expect("HKDF expand");
    okm
}

fn aead_enc(
    key: &[u8; 32],
    nonce24: &[u8; 24],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, TholosError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce24),
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
    cipher
        .decrypt(
            XNonce::from_slice(nonce24),
            chacha20poly1305::aead::Payload { msg: ct, aad },
        )
        .map_err(|_| TholosError::Aead)
}

/* ---------------- Encrypt ---------------- */

/// Encrypt once for N recipients (ML-KEM per recipient CEK wrap) and sign with Dilithium-3.
/// Returns **canonical CBOR** wire bytes of `BundleSigned`.
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

/* ---------------- Decrypt ---------------- */

/// Decrypt as recipient using your ML-KEM secret key, verifying Dilithium-3 signature
/// against the provided allowed sender list.
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
