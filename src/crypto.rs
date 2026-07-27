//! Cryptographic operations for encryption, decryption, and key generation.

use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_65};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::errors::TholosError;
use crate::types::*;

/// Recipient private key material.
///
/// The ML-KEM decapsulation key is zeroized on drop (`ml-kem` `zeroize` feature).
pub struct RecipientPriv {
    /// Recipient identifier.
    pub kid: String,
    /// ML-KEM-1024 decapsulation (secret) key.
    pub sk_kyber: <MlKem1024 as KemCore>::DecapsulationKey,
}

/// Sender keypair for signing messages.
///
/// Private key material is held inside [`DilithiumKeyPair`], which zeroizes on drop.
pub struct SenderKeypair {
    /// Sender identifier.
    pub sid: String,
    keypair: DilithiumKeyPair,
}

impl Drop for SenderKeypair {
    fn drop(&mut self) {
        self.sid.zeroize();
    }
}

impl SenderKeypair {
    /// ML-DSA-65 public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.keypair.public_key()
    }

    /// ML-DSA-65 private key bytes (for tests / vectors).
    pub fn private_key_bytes(&self) -> &[u8] {
        self.keypair.private_key()
    }
}

/// Options for deterministic / injectable encryption parameters.
pub struct EncryptOptions<'a, R: RngCore + CryptoRng> {
    /// RNG used for CEK, nonces, ML-KEM encapsulation, and signing randomness.
    pub rng: &'a mut R,
    /// Message ID written into the header (normally a UUID).
    pub msg_id: String,
    /// Unix timestamp written into the header.
    pub timestamp_unix: u64,
}

/// Generate a new recipient keypair.
pub fn gen_recipient_keypair(kid: &str) -> (RecipientPub, RecipientPriv) {
    let mut rng = OsRng;
    gen_recipient_keypair_with(kid, &mut rng)
}

/// Generate a recipient keypair using the provided RNG (for tests / vectors).
pub fn gen_recipient_keypair_with<R: RngCore + CryptoRng>(
    kid: &str,
    rng: &mut R,
) -> (RecipientPub, RecipientPriv) {
    let (sk, pk) = MlKem1024::generate(rng);
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

/// Generate a new sender keypair (ML-DSA-65).
pub fn gen_sender_keypair(sid: &str) -> SenderKeypair {
    #[allow(clippy::expect_used)]
    let keypair = DilithiumKeyPair::generate(ML_DSA_65).expect("ML-DSA-65 key generation failed");
    SenderKeypair {
        sid: sid.to_string(),
        keypair,
    }
}

/// Generate a sender keypair deterministically from a 32-byte seed (tests / vectors).
pub fn gen_sender_keypair_deterministic(sid: &str, seed: &[u8; 32]) -> SenderKeypair {
    SenderKeypair {
        sid: sid.to_string(),
        keypair: DilithiumKeyPair::generate_deterministic(ML_DSA_65, seed),
    }
}

/// Reconstruct a sender keypair from raw ML-DSA-65 key bytes (for tests / vectors).
pub fn sender_keypair_from_bytes(
    sid: &str,
    pk_bytes: &[u8],
    sk_bytes: &[u8],
) -> Result<SenderKeypair, TholosError> {
    let keypair = DilithiumKeyPair::from_keys(sk_bytes, pk_bytes, ML_DSA_65)
        .map_err(|_| TholosError::Malformed("ml-dsa keys"))?;
    Ok(SenderKeypair {
        sid: sid.to_string(),
        keypair,
    })
}

/// Extract the public key information from a sender keypair.
pub fn sender_pub(sender: &SenderKeypair) -> SenderPub {
    SenderPub {
        sid: sender.sid.clone(),
        pk_dilithium: sender.public_key_bytes().to_vec(),
    }
}

fn unix_timestamp_secs() -> Result<u64, TholosError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TholosError::Malformed("system clock before unix epoch"))
        .map(|d| d.as_secs())
}

fn hkdf32(shared: &[u8], kid: &str, header_cbor: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(kid.as_bytes()), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    #[allow(clippy::expect_used)]
    hk.expand(header_cbor, okm.as_mut())
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
        .encrypt(&nonce, chacha20poly1305::aead::Payload { msg: pt, aad })
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
        .decrypt(&nonce, chacha20poly1305::aead::Payload { msg: ct, aad })
        .map_err(|_| TholosError::Aead)
}

fn expect_self_describe_tag(wire_cbor: &[u8]) -> Result<(), TholosError> {
    if !has_self_describe_tag(wire_cbor) {
        return Err(TholosError::Malformed("wire self-describe tag"));
    }
    Ok(())
}

fn sign_inner<R: RngCore>(
    inner_cbor: &[u8],
    sender: &SenderKeypair,
    rng: &mut R,
) -> Result<Vec<u8>, TholosError> {
    let mut rnd = [0u8; 32];
    rng.fill_bytes(&mut rnd);
    let sig = sender
        .keypair
        .sign_deterministic(inner_cbor, b"", &rnd)
        .map_err(|_| TholosError::Malformed("ml-dsa sign"))?;
    rnd.zeroize();
    Ok(sig.as_bytes().to_vec())
}

fn validate_inner(inner: &BundleUnsigned) -> Result<(), TholosError> {
    if inner.header.v != 1 || inner.header.suite != SUITE_V1 {
        return Err(TholosError::UnsupportedSuite {
            v: inner.header.v,
            suite: inner.header.suite.clone(),
        });
    }

    if inner.header.recipients.len() != inner.recipients.len() {
        return Err(TholosError::Malformed("recipient list mismatch"));
    }

    let mut seen = std::collections::HashSet::new();
    for (header_kid, env) in inner.header.recipients.iter().zip(&inner.recipients) {
        if header_kid != &env.kid {
            return Err(TholosError::Malformed("recipient order mismatch"));
        }
        if !seen.insert(env.kid.clone()) {
            return Err(TholosError::Malformed("duplicate recipient kid"));
        }
    }

    Ok(())
}

fn verify_signed_bundle(
    bundle: &BundleSigned,
    allowed_senders: &[(String, Vec<u8>)],
) -> Result<BundleUnsigned, TholosError> {
    if bundle.inner.is_empty() {
        return Err(TholosError::Malformed("empty inner bundle"));
    }

    let inner: BundleUnsigned = from_cbor(&bundle.inner)?;
    validate_inner(&inner)?;

    let sender_sid = &inner.header.sender;
    let Some((_, pk_bytes)) = allowed_senders.iter().find(|(sid, _)| sid == sender_sid) else {
        return Err(TholosError::BadSignature);
    };

    if pk_bytes.len() != DILITHIUM3_PK_LEN {
        return Err(TholosError::Malformed("dilithium pk"));
    }
    if bundle.sig_dilithium.len() != DILITHIUM3_SIG_LEN {
        return Err(TholosError::Malformed("signature"));
    }

    let sig = DilithiumSignature::from_slice(&bundle.sig_dilithium);
    if !DilithiumKeyPair::verify(pk_bytes, &sig, &bundle.inner, b"", ML_DSA_65) {
        return Err(TholosError::BadSignature);
    }

    Ok(inner)
}

/// Verify a wire bundle and return its authenticated header without decrypting.
pub fn verify_header(
    wire_cbor: &[u8],
    allowed_senders: &[(String, Vec<u8>)],
) -> Result<Header, TholosError> {
    expect_self_describe_tag(wire_cbor)?;
    let bundle: BundleSigned = from_cbor(wire_cbor)?;
    let inner = verify_signed_bundle(&bundle, allowed_senders)?;
    Ok(inner.header)
}

/// Encrypt a message for multiple recipients and sign it with the sender's key.
pub fn encrypt(
    plaintext: &[u8],
    sender: &SenderKeypair,
    recipients: &[RecipientPub],
) -> Result<Vec<u8>, TholosError> {
    let mut rng = OsRng;
    encrypt_with(
        plaintext,
        sender,
        recipients,
        EncryptOptions {
            rng: &mut rng,
            msg_id: uuid::Uuid::new_v4().to_string(),
            timestamp_unix: unix_timestamp_secs()?,
        },
    )
}

/// Encrypt with caller-supplied RNG, message ID, and timestamp.
pub fn encrypt_with<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    sender: &SenderKeypair,
    recipients: &[RecipientPub],
    opts: EncryptOptions<'_, R>,
) -> Result<Vec<u8>, TholosError> {
    if recipients.is_empty() {
        return Err(TholosError::NoRecipients);
    }

    let header = Header {
        v: 1,
        suite: SUITE_V1.to_string(),
        sender: sender.sid.clone(),
        recipients: recipients.iter().map(|r| r.kid.clone()).collect(),
        msg_id: opts.msg_id,
        timestamp_unix: opts.timestamp_unix,
    };
    let header_cbor = to_cbor(&header)?;

    let rng = opts.rng;
    let mut cek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(cek.as_mut());

    let mut pay_nonce = [0u8; 24];
    rng.fill_bytes(&mut pay_nonce);
    let ciphertext = aead_enc(&cek, &pay_nonce, &header_cbor, plaintext)?;

    let mut envs = Vec::with_capacity(recipients.len());
    for r in recipients {
        let pk_bytes: &[u8] = &r.pk_kyber;
        let pk = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(
            &pk_bytes
                .try_into()
                .map_err(|_| TholosError::Malformed("ml-kem pk"))?,
        );
        let (kem_ct, shared) = pk
            .encapsulate(rng)
            .map_err(|_| TholosError::Malformed("encapsulation"))?;

        let kek = hkdf32(shared.as_slice(), &r.kid, &header_cbor);

        let mut wrap_nonce = [0u8; 24];
        rng.fill_bytes(&mut wrap_nonce);
        let wrapped_cek = aead_enc(&kek, &wrap_nonce, &header_cbor, cek.as_ref())?;

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

    let inner_cbor = to_cbor(&inner)?;
    let sig_dilithium = sign_inner(&inner_cbor, sender, rng)?;

    let bundle = BundleSigned {
        inner: inner_cbor,
        sig_dilithium,
    };

    to_cbor(&bundle)
}

/// Decrypt a message as a recipient and verify the sender's signature.
pub fn decrypt(
    wire_cbor: &[u8],
    my_kid: &str,
    my_sk: &<MlKem1024 as KemCore>::DecapsulationKey,
    allowed_senders: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, TholosError> {
    expect_self_describe_tag(wire_cbor)?;
    let bundle: BundleSigned = from_cbor(wire_cbor)?;
    let inner = verify_signed_bundle(&bundle, allowed_senders)?;

    let env = inner
        .recipients
        .iter()
        .find(|e| e.kid == my_kid)
        .ok_or_else(|| TholosError::MissingEnvelope(my_kid.to_string()))?;

    if env.wrap_nonce.len() != 24 {
        return Err(TholosError::Malformed("wrap nonce"));
    }
    let kem_ct_bytes: &[u8] = &env.kem_ct;
    let kem_ct: Ciphertext<MlKem1024> = kem_ct_bytes
        .try_into()
        .map_err(|_| TholosError::Malformed("kem_ct"))?;
    let shared = my_sk
        .decapsulate(&kem_ct)
        .map_err(|_| TholosError::Malformed("decapsulation"))?;

    let header_cbor = to_cbor(&inner.header)?;
    let kek = hkdf32(shared.as_slice(), my_kid, &header_cbor);

    let mut wrap_nonce = [0u8; 24];
    wrap_nonce.copy_from_slice(&env.wrap_nonce);
    let cek = aead_dec(&kek, &wrap_nonce, &header_cbor, &env.wrapped_cek)?;

    if cek.len() != 32 {
        return Err(TholosError::Malformed("cek length"));
    }
    let mut cek_arr = Zeroizing::new([0u8; 32]);
    cek_arr.copy_from_slice(&cek);

    if inner.pay_nonce.len() != 24 {
        return Err(TholosError::Malformed("pay nonce"));
    }
    let mut pay_nonce = [0u8; 24];
    pay_nonce.copy_from_slice(&inner.pay_nonce);

    aead_dec(&cek_arr, &pay_nonce, &header_cbor, &inner.ciphertext)
}

pub(crate) mod test_support {
    use super::*;

    pub fn resign_bundle(
        inner: &BundleUnsigned,
        sender: &SenderKeypair,
    ) -> Result<BundleSigned, TholosError> {
        let inner_cbor = to_cbor(inner)?;
        let mut rng = OsRng;
        let sig_dilithium = sign_inner(&inner_cbor, sender, &mut rng)?;
        Ok(BundleSigned {
            inner: inner_cbor,
            sig_dilithium,
        })
    }

    pub fn encode_bundle(bundle: &BundleSigned) -> Result<Vec<u8>, TholosError> {
        to_cbor(bundle)
    }

    pub fn decode_bundle(wire: &[u8]) -> Result<BundleSigned, TholosError> {
        from_cbor(wire)
    }

    pub fn decode_inner(bytes: &[u8]) -> Result<BundleUnsigned, TholosError> {
        from_cbor(bytes)
    }

    pub fn encode_cbor<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, TholosError> {
        to_cbor(v)
    }

    pub fn decode_cbor<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, TholosError> {
        from_cbor(data)
    }
}
