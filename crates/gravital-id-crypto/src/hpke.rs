//! HPKE modo base (RFC 9180, F2.T06).
//!
//! Composición **de las primitivas fijadas en ADR-0007** (no es una primitiva
//! nueva, INV-07):
//! - KEM: DHKEM(P-256, HKDF-SHA256) (ID: 0x0010).
//! - KDF: HKDF-SHA256 (ID: 0x0001).
//! - AEAD: ChaCha20Poly1305 (ID: 0x0003).
//!
//! Suite coherente con el perfil:
//! `DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305`.
//!
//! La aleatoriedad efímera del emisor se **inyecta** (INV-11): el llamador pasa
//! la clave efímera; nunca se genera aquí.

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};

use crate::ecdh::{agree, agree_ephemeral};
use gravital_id_types::{ErrorCode, GidError};

/// Longitud de la clave encapsulada (clave pública SEC1 sin comprimir).
pub const ENC_LEN: usize = 65;

/// Identificador de KEM del suite (RFC 9180 §7.1): DHKEM(P-256, HKDF-SHA256).
pub const SUITE_KEM_ID: u16 = 0x0010;
/// Identificador de KDF del suite (RFC 9180 §7.2): HKDF-SHA256.
pub const SUITE_KDF_ID: u16 = 0x0001;
/// Identificador de AEAD del suite (RFC 9180 §7.3): ChaCha20Poly1305.
pub const SUITE_AEAD_ID: u16 = 0x0003;

/// Modo base (sin autenticación del emisor).
const MODE_BASE: u8 = 0x00;

/// Etiqueta HPKE para el *key schedule* (RFC 9180 §4).
const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// Suite ID para KEM (RFC 9180 §4.1): "KEM" || I2OSP(kem_id, 2).
const KEM_SUITE_ID: &[u8; 5] = b"KEM\x00\x10";

/// Suite ID para HPKE (RFC 9180 §5.1): "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
const HPKE_SUITE_ID: &[u8; 10] = b"HPKE\x00\x10\x00\x01\x00\x03";

/// Longitud de la clave AEAD derivada (Nk = 32 para ChaCha20Poly1305).
pub const NK: usize = 32;

/// Longitud del nonce base derivado (Nn = 12 para ChaCha20Poly1305).
pub const NN: usize = 12;

fn invalid(reason: &str) -> GidError {
    GidError::new(ErrorCode::MalformedMessage, reason)
}

/// Etiquetado criptográfico `LabeledExtract` según RFC 9180 §4.
/// `LabeledExtract(suite_id, salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)`
fn labeled_extract(
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<[u8; 32], GidError> {
    let mut full_ikm = Vec::with_capacity(
        HPKE_VERSION
            .len()
            .saturating_add(suite_id.len())
            .saturating_add(label.len())
            .saturating_add(ikm.len()),
    );
    full_ikm.extend_from_slice(HPKE_VERSION);
    full_ikm.extend_from_slice(suite_id);
    full_ikm.extend_from_slice(label);
    full_ikm.extend_from_slice(ikm);

    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(salt_opt, &full_ikm);
    Ok(prk_into_array(&prk))
}

/// Etiquetado criptográfico `LabeledExpand` según RFC 9180 §4.
/// `LabeledExpand(suite_id, prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)`
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, GidError> {
    let mut full_info = Vec::with_capacity(
        2usize
            .saturating_add(HPKE_VERSION.len())
            .saturating_add(suite_id.len())
            .saturating_add(label.len())
            .saturating_add(info.len()),
    );
    full_info.extend_from_slice(&(len as u16).to_be_bytes());
    full_info.extend_from_slice(HPKE_VERSION);
    full_info.extend_from_slice(suite_id);
    full_info.extend_from_slice(label);
    full_info.extend_from_slice(info);

    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
        .map_err(|_| invalid("invalid PRK for LabeledExpand"))?;
    let mut okm = alloc::vec![0u8; len];
    hkdf.expand(&full_info, &mut okm)
        .map_err(|_| invalid("LabeledExpand failed"))?;
    Ok(okm)
}

/// Convierte un PRK en array fijo de 32 bytes.
fn prk_into_array(
    prk: &hkdf::hmac::digest::generic_array::GenericArray<u8, hkdf::hmac::digest::typenum::U32>,
) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(slice) = out.get_mut(..prk.len()) {
        slice.copy_from_slice(prk);
    }
    out
}

/// Serializa una clave pública en SEC1 sin comprimir (65 bytes).
fn sec1_bytes(key: PublicKey) -> Result<[u8; ENC_LEN], GidError> {
    let bytes = key.to_encoded_point(false);
    let mut out = [0u8; ENC_LEN];
    let raw = bytes.as_bytes();
    if raw.len() != ENC_LEN {
        return Err(invalid("unexpected public key encoding length"));
    }
    if let Some(slice) = out.get_mut(..raw.len()) {
        slice.copy_from_slice(raw);
    }
    Ok(out)
}

/// DHKEM Decap (RFC 9180 §4.1): deriva `shared_secret` a partir de `enc` y `skR`.
fn decap(recipient_secret: &SecretKey, enc_key: &PublicKey) -> Result<[u8; 32], GidError> {
    let dh = agree(recipient_secret, enc_key).map_err(|_| invalid("key agreement failed"))?;
    let enc = sec1_bytes(*enc_key)?;
    let pk_r = sec1_bytes(recipient_secret.public_key())?;
    let mut kem_context = Vec::with_capacity(ENC_LEN.saturating_mul(2));
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&pk_r);

    let eae_prk = labeled_extract(KEM_SUITE_ID, &[], b"eae_prk", &dh)?;
    let shared_secret_vec =
        labeled_expand(KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context, 32)?;
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_vec);
    Ok(shared_secret)
}

/// DHKEM Encap (RFC 9180 §4.1): deriva `enc` y `shared_secret` a partir de `skE` y `pkR`.
fn encap(
    recipient_public: &PublicKey,
    ephemeral_secret: &SecretKey,
) -> Result<([u8; ENC_LEN], [u8; 32]), GidError> {
    let dh =
        agree(ephemeral_secret, recipient_public).map_err(|_| invalid("key agreement failed"))?;
    let enc = sec1_bytes(ephemeral_secret.public_key())?;
    let pk_r = sec1_bytes(*recipient_public)?;
    let mut kem_context = Vec::with_capacity(ENC_LEN.saturating_mul(2));
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&pk_r);

    let eae_prk = labeled_extract(KEM_SUITE_ID, &[], b"eae_prk", &dh)?;
    let shared_secret_vec =
        labeled_expand(KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context, 32)?;
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_vec);
    Ok((enc, shared_secret))
}

/// Deriva el material de clave del *key schedule* RFC 9180 §5.1 en modo base.
fn key_schedule(shared_secret: &[u8; 32], info: &[u8]) -> Result<([u8; NK], [u8; NN]), GidError> {
    let psk_id_hash = labeled_extract(HPKE_SUITE_ID, &[], b"psk_id_hash", &[])?;
    let info_hash = labeled_extract(HPKE_SUITE_ID, &[], b"info_hash", info)?;

    let mut context = Vec::with_capacity(
        1usize
            .saturating_add(psk_id_hash.len())
            .saturating_add(info_hash.len()),
    );
    context.push(MODE_BASE);
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);

    let secret = labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", &[])?;
    let key_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"key", &context, NK)?;
    let nonce_vec = labeled_expand(HPKE_SUITE_ID, &secret, b"base_nonce", &context, NN)?;

    let mut key = [0u8; NK];
    key.copy_from_slice(&key_vec);
    let mut base_nonce = [0u8; NN];
    base_nonce.copy_from_slice(&nonce_vec);
    Ok((key, base_nonce))
}

/// Cifra con ChaCha20Poly1305 (RFC 9180 AEAD ID 0x0003).
fn aead_seal_chacha(
    key: &[u8; NK],
    nonce: &[u8; NN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| GidError::new(ErrorCode::AeadAuthenticationFailed, "AEAD seal failed"))
}

/// Descifra con ChaCha20Poly1305 (RFC 9180 AEAD ID 0x0003).
fn aead_open_chacha(
    key: &[u8; NK],
    nonce: &[u8; NN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            GidError::new(
                ErrorCode::AeadAuthenticationFailed,
                "AEAD authentication failed",
            )
        })
}

/// Configura el contexto del receptor HPKE derivando la clave simétrica y el nonce base (RFC 9180 §5.1).
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si la clave encapsulada no es válida.
pub fn hpke_setup_recipient(
    recipient_secret: &SecretKey,
    enc: &[u8],
    info: &[u8],
) -> Result<([u8; NK], [u8; NN]), GidError> {
    let enc_key =
        PublicKey::from_sec1_bytes(enc).map_err(|_| invalid("invalid encapsulated key"))?;
    let shared_secret = decap(recipient_secret, &enc_key)?;
    key_schedule(&shared_secret, info)
}

/// Encapsula hacia una clave pública y sella `plaintext` en modo base (RFC 9180).
///
/// Devuelve la clave encapsulada `enc` (65 bytes) y el sobre `ciphertext || tag`.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si las claves no son válidas;
/// [`ErrorCode::AeadAuthenticationFailed`] si el sellado falla.
pub fn hpke_seal_base_p256_hkdf_sha256_chacha20poly1305(
    recipient_public: &[u8; ENC_LEN],
    ephemeral_secret: &[u8; 32],
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; ENC_LEN], Vec<u8>), GidError> {
    let pk = PublicKey::from_sec1_bytes(recipient_public)
        .map_err(|_| invalid("invalid recipient public key"))?;
    let sk = SecretKey::from_bytes(ephemeral_secret.into())
        .map_err(|_| invalid("invalid ephemeral secret key"))?;
    let (enc, shared_secret) = encap(&pk, &sk)?;
    let (key, base_nonce) = key_schedule(&shared_secret, info)?;
    let sealed = aead_seal_chacha(&key, &base_nonce, plaintext, aad)?;
    Ok((enc, sealed))
}

/// Desencapsula y abre un sobre en modo base (RFC 9180).
///
/// # Errores
/// [`ErrorCode::AeadAuthenticationFailed`] si la etiqueta no verifica;
/// [`ErrorCode::MalformedMessage`] si las claves no son válidas.
pub fn hpke_open_base_p256_hkdf_sha256_chacha20poly1305(
    recipient_secret: &[u8; 32],
    enc: &[u8],
    ciphertext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let sk = SecretKey::from_bytes(recipient_secret.into())
        .map_err(|_| invalid("invalid recipient secret key"))?;
    let (key, base_nonce) = hpke_setup_recipient(&sk, enc, info)?;
    aead_open_chacha(&key, &base_nonce, ciphertext, aad)
}

/// Encapsula hacia una clave pública tipada y sella `plaintext` (modo base).
///
/// Devuelve la clave encapsulada y el sobre `ciphertext || tag`.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si la clave pública receptora no es P-256.
pub fn seal_base(
    recipient_public: &PublicKey,
    ephemeral_secret: &SecretKey,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; ENC_LEN], Vec<u8>), GidError> {
    let (enc, shared_secret) = encap(recipient_public, ephemeral_secret)?;
    let (key, base_nonce) = key_schedule(&shared_secret, info)?;
    let sealed = aead_seal_chacha(&key, &base_nonce, plaintext, aad)?;
    Ok((enc, sealed))
}

/// Desencapsula y abre un sobre con clave tipada (modo base).
///
/// # Errores
/// [`ErrorCode::AeadAuthenticationFailed`] si la etiqueta no verifica;
/// [`ErrorCode::MalformedMessage`] si la clave encapsulada no es P-256.
pub fn open_base(
    recipient_secret: &SecretKey,
    enc: &[u8],
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let (key, base_nonce) = hpke_setup_recipient(recipient_secret, enc, info)?;
    aead_open_chacha(&key, &base_nonce, ciphertext, aad)
}

/// Variante efímera del emisor para flujos de un solo uso.
///
/// # Errores
/// Igual que [`seal_base`].
pub fn seal_base_ephemeral(
    recipient_public: &PublicKey,
    ephemeral_secret: EphemeralSecret,
    info: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; ENC_LEN], Vec<u8>), GidError> {
    let enc_key = ephemeral_secret.public_key();
    let enc = sec1_bytes(enc_key)?;
    let pk_r = sec1_bytes(*recipient_public)?;
    let mut kem_context = Vec::with_capacity(ENC_LEN.saturating_mul(2));
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&pk_r);

    let dh = agree_ephemeral(ephemeral_secret, recipient_public)
        .map_err(|_| invalid("invalid recipient public key"))?;

    let eae_prk = labeled_extract(KEM_SUITE_ID, &[], b"eae_prk", &dh)?;
    let shared_secret_vec =
        labeled_expand(KEM_SUITE_ID, &eae_prk, b"shared_secret", &kem_context, 32)?;
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_secret_vec);

    let (key, base_nonce) = key_schedule(&shared_secret, info)?;
    let sealed = aead_seal_chacha(&key, &base_nonce, plaintext, aad)?;
    Ok((enc, sealed))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use p256::SecretKey;

    fn recipient() -> SecretKey {
        let mut secret = [0u8; 32];
        for (i, slot) in secret.iter_mut().enumerate() {
            *slot = 11u8.wrapping_add(i as u8);
        }
        SecretKey::from_bytes(&secret.into()).expect("valid key")
    }

    fn sender() -> SecretKey {
        let mut secret = [0u8; 32];
        for (i, slot) in secret.iter_mut().enumerate() {
            *slot = 200u8.wrapping_sub(i as u8);
        }
        SecretKey::from_bytes(&secret.into()).expect("valid key")
    }

    // // Verifies: REQ-SEC-002 (round-trip HPKE modo base)
    #[test]
    fn seal_and_open_round_trip() {
        let recipient = recipient();
        let sender = sender();
        let (enc, sealed) = seal_base(
            &recipient.public_key(),
            &sender,
            b"gravital-relay-v1",
            b"sobre de operacion",
            b"aad",
        )
        .expect("seal");

        let opened =
            open_base(&recipient, &enc, b"gravital-relay-v1", &sealed, b"aad").expect("open");
        assert_eq!(opened, b"sobre de operacion");
    }

    // // Verifies: REQ-SEC-002 (info distinto => no abre)
    #[test]
    fn wrong_info_is_rejected() {
        let recipient = recipient();
        let sender = sender();
        let (enc, sealed) =
            seal_base(&recipient.public_key(), &sender, b"info-a", b"mensaje", b"").expect("seal");
        assert!(open_base(&recipient, &enc, b"info-b", &sealed, b"").is_err());
    }

    // // Verifies: REQ-SEC-002 (AAD distinto => no abre)
    #[test]
    fn wrong_aad_is_rejected() {
        let recipient = recipient();
        let sender = sender();
        let (enc, sealed) = seal_base(
            &recipient.public_key(),
            &sender,
            b"info",
            b"mensaje",
            b"aad-1",
        )
        .expect("seal");
        assert!(open_base(&recipient, &enc, b"info", &sealed, b"aad-2").is_err());
    }

    // // Verifies: REQ-SEC-002 (receptor distinto => no abre)
    #[test]
    fn wrong_recipient_is_rejected() {
        let recipient = recipient();
        let sender = sender();
        let (enc, sealed) =
            seal_base(&recipient.public_key(), &sender, b"info", b"mensaje", b"").expect("seal");
        let mut other = [0u8; 32];
        for (i, slot) in other.iter_mut().enumerate() {
            *slot = 77u8.wrapping_add(i as u8);
        }
        let intruder = SecretKey::from_bytes(&other.into()).expect("valid key");
        assert!(open_base(&intruder, &enc, b"info", &sealed, b"").is_err());
    }

    // // Verifies: REQ-SEC-002 (clave encapsulada inválida)
    #[test]
    fn invalid_encapsulated_key_is_rejected() {
        let recipient = recipient();
        assert!(open_base(&recipient, &[0xFF; 65], b"info", b"sobre", b"").is_err());
        assert!(open_base(&recipient, &[], b"info", b"sobre", b"").is_err());
    }

    // // Verifies: REQ-SEC-002 (el cifrado no es determinista entre emisores)
    #[test]
    fn different_senders_give_different_ciphertexts() {
        let recipient = recipient();
        let sender_a = sender();
        let mut other = [0u8; 32];
        for (i, slot) in other.iter_mut().enumerate() {
            *slot = 3u8.wrapping_mul(i as u8);
        }
        let sender_b = SecretKey::from_bytes(&other.into()).expect("valid key");

        let (enc_a, sealed_a) =
            seal_base(&recipient.public_key(), &sender_a, b"info", b"mismo", b"").expect("seal a");
        let (enc_b, sealed_b) =
            seal_base(&recipient.public_key(), &sender_b, b"info", b"mismo", b"").expect("seal b");
        assert_ne!(enc_a, enc_b);
        assert_ne!(sealed_a, sealed_b);

        // Ambos se abren con el mismo receptor.
        assert_eq!(
            open_base(&recipient, &enc_a, b"info", &sealed_a, b"").expect("open a"),
            b"mismo"
        );
        assert_eq!(
            open_base(&recipient, &enc_b, b"info", &sealed_b, b"").expect("open b"),
            b"mismo"
        );
    }
}
