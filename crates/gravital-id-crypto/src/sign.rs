//! Firmas ES256 (ECDSA P-256 + SHA-256) y conversiones P1363 ↔ DER (F2.T06).
//!
//! Backend RustCrypto (`p256` + `ecdsa`, ADR-0007).
//!
//! Decisiones del perfil (`CRYPTO_PROFILES.md §3.1`, `ROADMAP.md` F2.T06):
//! - La firma en el protocolo es IEEE P1363 (`r‖s`, exactamente 64 bytes).
//! - Se admite conversión desde/hacia ASN.1 DER porque los almacenes de
//!   hardware (Secure Enclave, StrongBox) devuelven DER: la conversión ocurre
//!   **en Rust** (REQ-KEY-010, P-11).
//! - **No se exige *low-S*** (REQ-KEY-010, `ARCHITECTURE.md §10`): una firma
//!   con `s > n/2` sigue siendo válida y se verifica como tal. La normalización
//!   solo se aplica si la verificación directa falla, para aceptar ambas formas.
//!   Ver issue #23 (contradicción con `CRYPTO_PROFILES.md §3.1`).
//! - Ninguna firma se usa como identificador (maleabilidad, REQ-KEY-010).

use alloc::vec::Vec;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ecdsa::{Signature, SignatureBytes, SigningKey, VerifyingKey};
use p256::NistP256;

use gravital_id_types::{ErrorCode, GidError};

/// Longitud de la firma P1363 (`r‖s`) en bytes.
pub const ES256_SIGNATURE_LEN: usize = 64;

/// Longitud de la clave privada P-256 en bytes.
pub const ES256_SECRET_KEY_LEN: usize = 32;

/// Longitud de la clave pública SEC1 sin comprimir en bytes.
pub const ES256_PUBLIC_KEY_LEN: usize = 65;

/// Firma determinista RFC 6979 sobre el prehash SHA-256: sin aleatoriedad
/// implícita (INV-11).
fn sign_deterministic_rfc6979(
    key: &SigningKey<NistP256>,
    message: &[u8],
) -> Result<Signature<NistP256>, GidError> {
    let digest = crate::sha::sha256(message);
    key.sign_prehash(&digest)
        .map_err(|_| GidError::new(ErrorCode::InvalidSignature, "deterministic signing failed"))
}

/// Firma `message` con `key` y devuelve la firma P1363 (`r‖s`, 64 bytes).
///
/// Usa el nonce determinista RFC 6979: la firma depende solo del mensaje y de
/// la clave, sin aleatoriedad implícita (INV-11).
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`] si la clave es inválida.
pub fn sign_es256(
    key: &SigningKey<NistP256>,
    message: &[u8],
) -> Result<[u8; ES256_SIGNATURE_LEN], GidError> {
    let signature = sign_deterministic_rfc6979(key, message)?;
    to_p1363(&signature)
}

/// Verifica una firma P1363 (`r‖s`) de `message` contra `key`.
///
/// # Errores
/// [`ErrorCode::InvalidSignature`] si la firma no verifica o su codificación es
/// inválida.
pub fn verify_es256(
    key: &VerifyingKey<NistP256>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), GidError> {
    let signature = parse_flexible_signature(signature)?;
    verify_signature(key, message, &signature)
}

/// Verifica una firma en ASN.1 DER (la forma que devuelven los almacenes de
/// hardware).
///
/// # Errores
/// [`ErrorCode::InvalidSignature`] si la firma no verifica o su codificación es
/// inválida.
pub fn verify_es256_der(
    key: &VerifyingKey<NistP256>,
    message: &[u8],
    der: &[u8],
) -> Result<(), GidError> {
    let p1363 = der_to_p1363(der)?;
    verify_es256(key, message, &p1363)
}

/// Convierte una firma DER a P1363 (`r‖s`).
///
/// # Errores
/// [`ErrorCode::InvalidSignature`] si el DER no es una firma ECDSA P-256 válida.
pub fn der_to_p1363(der: &[u8]) -> Result<[u8; ES256_SIGNATURE_LEN], GidError> {
    let signature = Signature::<NistP256>::from_der(der)
        .map_err(|_| GidError::new(ErrorCode::InvalidSignature, "invalid DER ECDSA signature"))?;
    to_p1363(&signature)
}

/// Convierte una firma P1363 a DER (ASN.1 SEQUENCE de dos INTEGER).
///
/// # Errores
/// [`ErrorCode::InvalidSignature`] si los componentes no son escalares válidos.
pub fn p1363_to_der(signature: &[u8]) -> Result<Vec<u8>, GidError> {
    let signature = parse_p1363(signature)?;
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Convierte una firma tipada a sus 64 bytes P1363.
fn to_p1363(signature: &Signature<NistP256>) -> Result<[u8; ES256_SIGNATURE_LEN], GidError> {
    let bytes: SignatureBytes<NistP256> = signature.to_bytes();
    let mut out = [0u8; ES256_SIGNATURE_LEN];
    if let Some(slice) = out.get_mut(..bytes.len()) {
        slice.copy_from_slice(&bytes);
    }
    Ok(out)
}

/// Parsea exactamente 64 bytes P1363.
fn parse_p1363(signature: &[u8]) -> Result<Signature<NistP256>, GidError> {
    if signature.len() != ES256_SIGNATURE_LEN {
        return Err(GidError::new(
            ErrorCode::InvalidSignature,
            "signature must be exactly 64 bytes (P1363 r||s)",
        ));
    }
    let mut bytes = [0u8; ES256_SIGNATURE_LEN];
    if let Some(slice) = bytes.get_mut(..signature.len()) {
        slice.copy_from_slice(signature);
    }
    Signature::from_slice(&bytes)
        .map_err(|_| GidError::new(ErrorCode::InvalidSignature, "invalid P1363 signature"))
}

/// Acepta indistintamente P1363 (64 bytes) o DER.
fn parse_flexible_signature(signature: &[u8]) -> Result<Signature<NistP256>, GidError> {
    if signature.len() == ES256_SIGNATURE_LEN {
        parse_p1363(signature)
    } else {
        der_to_p1363(signature).and_then(|p1363| parse_p1363(&p1363))
    }
}

/// Verifica una firma tipada, aceptando `s` alto (REQ-KEY-010).
///
/// La verificación directa normalmente acepta ambas formas; el reintento con
/// `s` normalizado existe por defensa en profundidad para backends que
/// rechacen `s > n/2`.
fn verify_signature(
    key: &VerifyingKey<NistP256>,
    message: &[u8],
    signature: &Signature<NistP256>,
) -> Result<(), GidError> {
    let digest = crate::sha::sha256(message);
    if key.verify_prehash(&digest, signature).is_ok() {
        return Ok(());
    }

    if let Some(normalized) = signature.normalize_s() {
        if key.verify_prehash(&digest, &normalized).is_ok() {
            return Ok(());
        }
    }

    Err(GidError::new(
        ErrorCode::InvalidSignature,
        "signature verification failed",
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    fn test_key() -> SigningKey {
        // Clave determinista de prueba: 32 bytes de un patrón fijo.
        let mut secret = [0u8; ES256_SECRET_KEY_LEN];
        for (i, slot) in secret.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        SigningKey::from_bytes(&secret.into()).expect("valid test key")
    }

    // // Verifies: REQ-KEY-010 (round-trip de firma/verificación P1363)
    #[test]
    fn sign_and_verify_round_trip() {
        let key = test_key();
        let verifying = key.verifying_key();
        let signature = sign_es256(&key, b"mensaje de prueba").expect("sign");
        assert_eq!(signature.len(), ES256_SIGNATURE_LEN);
        verify_es256(verifying, b"mensaje de prueba", &signature).expect("verify");
    }

    // // Verifies: REQ-KEY-010 (mensaje distinto no verifica)
    #[test]
    fn wrong_message_is_rejected() {
        let key = test_key();
        let verifying = key.verifying_key();
        let signature = sign_es256(&key, b"mensaje").expect("sign");
        assert_eq!(
            verify_es256(verifying, b"otro mensaje", &signature)
                .expect_err("tamper")
                .code,
            ErrorCode::InvalidSignature
        );
    }

    // // Verifies: REQ-KEY-010 (firma alterada no verifica)
    #[test]
    fn tampered_signature_is_rejected() {
        let key = test_key();
        let verifying = key.verifying_key();
        let mut signature = sign_es256(&key, b"mensaje").expect("sign");
        if let Some(byte) = signature.get_mut(0) {
            *byte ^= 0xFF;
        }
        assert!(verify_es256(verifying, b"mensaje", &signature).is_err());
    }

    // // Verifies: REQ-KEY-010 (longitudes inválidas)
    #[test]
    fn invalid_signature_lengths_are_rejected() {
        let key = test_key();
        let verifying = key.verifying_key();
        let signature = sign_es256(&key, b"mensaje").expect("sign");
        assert!(verify_es256(verifying, b"mensaje", &signature[..63]).is_err());
        assert!(verify_es256(verifying, b"mensaje", &signature[..0]).is_err());
    }

    // // Verifies: REQ-KEY-010 (conversión DER ↔ P1363)
    #[test]
    fn der_and_p1363_conversions_round_trip() {
        let key = test_key();
        let verifying = key.verifying_key();
        let signature = sign_es256(&key, b"conversion").expect("sign");

        // P1363 → DER → P1363.
        let der = p1363_to_der(&signature).expect("to der");
        let back = der_to_p1363(&der).expect("from der");
        assert_eq!(signature, back);

        // La verificación acepta ambas formas.
        verify_es256_der(verifying, b"conversion", &der).expect("verify der");
        verify_es256(verifying, b"conversion", &der).expect("verify flexible");
    }

    // // Verifies: REQ-KEY-010 (caso negativo: DER inválido)
    #[test]
    fn invalid_der_is_rejected() {
        assert!(der_to_p1363(&[0x30, 0x00]).is_err());
        assert!(p1363_to_der(&[0u8; 63]).is_err());
    }

    // // Verifies: REQ-KEY-010 (clave pública desde/hacia SEC1)
    #[test]
    fn public_key_sec1_round_trip() {
        let key = test_key();
        let verifying = key.verifying_key();
        let encoded = verifying.to_encoded_point(false);
        let sec1 = encoded.as_bytes();
        assert_eq!(sec1.len(), ES256_PUBLIC_KEY_LEN);
        let restored = VerifyingKey::from_sec1_bytes(sec1).expect("valid sec1 public key");
        let signature = sign_es256(&key, b"clave").expect("sign");
        verify_es256(&restored, b"clave", &signature).expect("verify");
    }

    // // Verifies: REQ-KEY-010 (el nonce es determinista: RFC 6979)
    #[test]
    fn signing_is_deterministic() {
        let key = test_key();
        let first = sign_es256(&key, b"mismo mensaje").expect("sign");
        let second = sign_es256(&key, b"mismo mensaje").expect("sign");
        assert_eq!(first, second, "RFC 6979: mismas entradas => misma firma");
    }
}
