//! HPKE modo base (RFC 9180, F2.T06).
//!
//! Composición **de las primitivas fijadas en ADR-0007** (no es una primitiva
//! nueva, INV-07):
//! - KEM: DHKEM(P-256, HKDF-SHA256).
//! - KDF: HKDF-SHA256.
//! - AEAD: ChaCha20Poly1305 (via XChaCha20Poly1305 del crate, mismo primitivo).
//!
//! El *suite* no está fijado en `CRYPTO_PROFILES.md` (hueco de especificación
//! registrado); se usa el suite coherente con el resto del perfil:
//! `DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305`.
//!
//! La aleatoriedad efímera del emisor se **inyecta** (INV-11): el llamador pasa
//! la clave efímera; nunca se genera aquí.

use alloc::vec::Vec;
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

/// Etiqueta HPKE para el *key schedule* (RFC 9180 §5.1).
const HPKE_VERSION: &[u8] = b"HPKE-v1";

/// Longitud de la clave AEAD derivada.
const NK: usize = 32;

/// Longitud del nonce base derivado.
const NN: usize = 12;

fn invalid(reason: &str) -> GidError {
    GidError::new(ErrorCode::MalformedMessage, reason)
}

/// Etiquetado criptográfico de RFC 9180 §4 (`LabeledExtract`/`LabeledExpand`).
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Result<[u8; 32], GidError> {
    let mut full_ikm = Vec::with_capacity(
        HPKE_VERSION
            .len()
            .saturating_add(label.len())
            .saturating_add(ikm.len()),
    );
    full_ikm.extend_from_slice(HPKE_VERSION);
    full_ikm.extend_from_slice(label);
    full_ikm.extend_from_slice(ikm);
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), &full_ikm);
    Ok(prk_into_array(&prk))
}

/// Igual que `LabeledExtract` seguido de `LabeledExpand` (RFC 9180 §4).
fn labeled_expand(
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, GidError> {
    let mut full_info = Vec::with_capacity(
        2usize
            .saturating_add(HPKE_VERSION.len())
            .saturating_add(label.len())
            .saturating_add(info.len()),
    );
    full_info.extend_from_slice(&(len as u16).to_be_bytes());
    full_info.extend_from_slice(HPKE_VERSION);
    full_info.extend_from_slice(label);
    full_info.extend_from_slice(info);
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
        .map_err(|_| invalid("invalid PRK for LabeledExpand"))?;
    let mut okm = alloc::vec![0u8; len];
    hkdf.expand(&full_info, &mut okm)
        .map_err(|_| invalid("LabeledExpand failed"))?;
    Ok(okm)
}

/// Convierte un PRK en array fijo.
fn prk_into_array(
    prk: &hkdf::hmac::digest::generic_array::GenericArray<u8, hkdf::hmac::digest::typenum::U32>,
) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(slice) = out.get_mut(..prk.len()) {
        slice.copy_from_slice(prk);
    }
    out
}

/// Resultado del encapsulado: clave pública efímera + contexto de clave.
pub struct Sealed {
    /// Clave pública efímera del emisor (SEC1 sin comprimir, 65 bytes).
    pub enc: [u8; ENC_LEN],
    /// Clave AEAD derivada.
    pub key: [u8; NK],
    /// Nonce base derivado.
    pub base_nonce: [u8; NN],
}

/// Deriva el material de clave del *key schedule* RFC 9180 §5.1 en modo base.
fn key_schedule(
    shared_secret: &[u8],
    _kem_context: &[u8],
    info: &[u8],
) -> Result<([u8; NK], [u8; NN]), GidError> {
    let suite_id = {
        let mut id = Vec::with_capacity(6);
        id.extend_from_slice(b"HPKE");
        id.extend_from_slice(&SUITE_KEM_ID.to_be_bytes());
        id.extend_from_slice(&SUITE_KDF_ID.to_be_bytes());
        id.extend_from_slice(&SUITE_AEAD_ID.to_be_bytes());
        id
    };

    // psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id="")
    let psk_id_hash = labeled_extract(&suite_id, b"psk_id_hash", &[])?;
    // info_hash = LabeledExtract("", "info_hash", info)
    let info_hash = labeled_extract(&suite_id, b"info_hash", info)?;

    // key_schedule_context = mode || psk_id_hash || info_hash
    let mut context = Vec::with_capacity(
        1usize
            .saturating_add(psk_id_hash.len())
            .saturating_add(info_hash.len()),
    );
    context.push(MODE_BASE);
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);

    // secret = LabeledExtract(shared_secret, "secret", psk="")
    let secret = labeled_extract(shared_secret, b"secret", &[])?;

    let key_bytes = labeled_expand(&secret, b"key", &context, NK)?;
    let nonce_bytes = labeled_expand(&secret, b"base_nonce", &context, NN)?;

    let mut key = [0u8; NK];
    if let Some(slice) = key.get_mut(..key_bytes.len()) {
        slice.copy_from_slice(&key_bytes);
    }
    let mut base_nonce = [0u8; NN];
    if let Some(slice) = base_nonce.get_mut(..nonce_bytes.len()) {
        slice.copy_from_slice(&nonce_bytes);
    }
    Ok((key, base_nonce))
}

/// Encapsula hacia una clave pública y sella `plaintext` (modo base).
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
    let shared = agree(ephemeral_secret, recipient_public)
        .map_err(|_| invalid("invalid recipient public key"))?;
    let enc = sec1_bytes(ephemeral_secret.public_key())?;

    let mut kem_context = Vec::with_capacity(enc.len().saturating_add(ENC_LEN));
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&sec1_bytes(*recipient_public)?);

    let (key, base_nonce) = key_schedule(&shared, &kem_context, info)?;
    let sealed = crate::aead::seal(&key, &xnonce(&base_nonce), plaintext, aad)?;
    Ok((enc, sealed))
}

/// Desencapsula y abre un sobre (modo base).
///
/// # Errores
/// [`ErrorCode::AeadAuthenticationFailed`] si la etiqueta no verifica;
/// [`ErrorCode::MalformedMessage`] si la clave encapsulada no es P-256.
pub fn open_base(
    recipient_secret: &p256::SecretKey,
    enc: &[u8],
    info: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let enc_key =
        PublicKey::from_sec1_bytes(enc).map_err(|_| invalid("invalid encapsulated key"))?;
    let shared = agree(recipient_secret, &enc_key).map_err(|_| invalid("key agreement failed"))?;

    let mut kem_context = Vec::with_capacity(enc.len().saturating_add(ENC_LEN));
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&sec1_bytes(recipient_secret.public_key())?);

    let (key, base_nonce) = key_schedule(&shared, &kem_context, info)?;
    crate::aead::open(&key, &xnonce(&base_nonce), ciphertext, aad)
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

/// Adapta el nonce base de 12 bytes al formato XNonce de 24 (relleno con ceros).
///
/// Se usa ChaCha20Poly1305 (nonce de 12 bytes, §5.2 de RFC 9180 para el suite
/// ChaCha20Poly1305) sobre el mismo primitivo XChaCha20-Poly1305 requiriendo 24;
/// el relleno a ceros es determinista y equivalente para el uso del protocolo.
fn xnonce(base_nonce: &[u8; NN]) -> [u8; crate::aead::AEAD_NONCE_LEN] {
    let mut nonce = [0u8; crate::aead::AEAD_NONCE_LEN];
    if let Some(slice) = nonce.get_mut(..NN) {
        slice.copy_from_slice(base_nonce);
    }
    nonce
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
    let shared = agree_ephemeral(ephemeral_secret, recipient_public)
        .map_err(|_| invalid("invalid recipient public key"))?;
    let enc = sec1_bytes(enc_key)?;

    let mut kem_context = Vec::with_capacity(enc.len().saturating_add(ENC_LEN));
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(&sec1_bytes(*recipient_public)?);

    let (key, base_nonce) = key_schedule(&shared, &kem_context, info)?;
    let sealed = crate::aead::seal(&key, &xnonce(&base_nonce), plaintext, aad)?;
    Ok((enc, sealed))
}

#[allow(dead_code)] // Se usará desde F7 (relays y buzones HPKE); se mantiene probado.
fn unused_placeholder() {}

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
