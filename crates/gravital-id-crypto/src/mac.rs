//! HMAC-SHA-256 y comparación en tiempo constante (F2.T06, REQ-SEC-004).
//!
//! Backend RustCrypto (`hmac`, `subtle`, ADR-0007). HMAC se usa en los índices
//! ciegos de almacenamiento (ADR-0008) y en los patrones de similaridad.

use gravital_id_types::{ErrorCode, GidError};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Etiqueta de tipo para HMAC-SHA-256.
type HmacSha256 = Hmac<Sha256>;

/// Longitud de la etiqueta HMAC-SHA-256 en bytes.
pub const HMAC_OUTPUT_LEN: usize = 32;

/// Calcula HMAC-SHA-256(`key`, `data`).
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`] si la clave está vacía (HMAC la admite, pero
/// el perfil exige material de clave real).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_OUTPUT_LEN], GidError> {
    if key.is_empty() {
        return Err(GidError::new(
            ErrorCode::InvalidKeyFormat,
            "HMAC key must not be empty",
        ));
    }
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| GidError::new(ErrorCode::InvalidKeyFormat, "invalid HMAC key"))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_OUTPUT_LEN];
    if let Some(slice) = out.get_mut(..tag.len()) {
        slice.copy_from_slice(&tag);
    }
    Ok(out)
}

/// Verifica una etiqueta HMAC-SHA-256 en **tiempo constante** (REQ-SEC-004).
///
/// # Errores
/// [`ErrorCode::AeadAuthenticationFailed`] si la etiqueta no coincide o tiene
/// longitud inválida.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), GidError> {
    let expected = hmac_sha256(key, data)?;
    if tag.len() != expected.len() {
        return Err(GidError::new(
            ErrorCode::AeadAuthenticationFailed,
            "HMAC tag has invalid length",
        ));
    }
    match expected.ct_eq(tag).into() {
        true => Ok(()),
        false => Err(GidError::new(
            ErrorCode::AeadAuthenticationFailed,
            "HMAC tag mismatch",
        )),
    }
}

/// Comparación de secretos en tiempo constante (REQ-SEC-004).
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::vec;

    // // Verifies: REQ-SEC-004 (vectores RFC 4231 para HMAC-SHA-256)
    #[test]
    fn hmac_matches_rfc4231_vectors() {
        // Caso 1: clave de 20 bytes 0x0b.
        let key = vec![0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There").expect("valid key");
        assert_eq!(
            tag,
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7
            ]
        );

        // Caso 2: clave "Jefe", mensaje "what do ya want for nothing?".
        let tag2 = hmac_sha256(b"Jefe", b"what do ya want for nothing?").expect("valid key");
        assert_eq!(
            tag2,
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43
            ]
        );
    }

    // // Verifies: REQ-SEC-004 (caso negativo: clave vacía)
    #[test]
    fn rejects_empty_key() {
        assert!(hmac_sha256(b"", b"data").is_err());
    }

    // // Verifies: REQ-SEC-004 (verificación)
    #[test]
    fn verify_accepts_correct_tag_and_rejects_wrong_one() {
        let tag = hmac_sha256(b"key", b"message").expect("valid");
        assert!(hmac_sha256_verify(b"key", b"message", &tag).is_ok());
        assert!(hmac_sha256_verify(b"key", b"other", &tag).is_err());
        assert!(hmac_sha256_verify(b"other key", b"message", &tag).is_err());
        // Longitud inválida.
        assert!(hmac_sha256_verify(b"key", b"message", &tag[..16]).is_err());
    }

    // // Verifies: REQ-SEC-004 (comparación en tiempo constante)
    #[test]
    fn constant_time_comparison() {
        let a = [1u8, 2, 3];
        assert!(constant_time_eq(&a, &a));
        assert!(!constant_time_eq(&a, &[1u8, 2, 4]));
        assert!(!constant_time_eq(&a, &[1u8, 2]));
    }
}
