//! Derivación de claves HKDF-SHA256 (F2.T06).
//!
//! Backend RustCrypto (`hkdf`, ADR-0007; RFC 5869). Se usa para segmentar el
//! almacén cifrado (ADR-0008) y como KDF de HPKE (RFC 9180).

use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::Sha256;

/// Longitud máxima razonable de salida HKDF (RFC 5869: 255 × 32 bytes).
pub const MAX_HKDF_OUTPUT_LEN: usize = 255 * 32;

/// HKDF-Extract + Expand en un paso (RFC 5869 §2.2, §2.3).
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`] si `salt` o `ikm` están vacíos, o si
/// `okm_len` excede [`MAX_HKDF_OUTPUT_LEN`].
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, GidError> {
    if ikm.is_empty() {
        return Err(GidError::new(
            ErrorCode::InvalidKeyFormat,
            "HKDF input key material must not be empty",
        ));
    }
    if okm_len == 0 || okm_len > MAX_HKDF_OUTPUT_LEN {
        return Err(GidError::new(
            ErrorCode::InvalidKeyFormat,
            "HKDF output length out of range",
        ));
    }

    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; okm_len];
    hkdf.expand(info, &mut okm)
        .map_err(|_| GidError::new(ErrorCode::InvalidKeyFormat, "HKDF expand failed"))?;
    Ok(okm)
}

/// HKDF-Extract aislado (RFC 5869 §2.2): devuelve el PRK.
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`] si `ikm` está vacío.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Result<[u8; 32], GidError> {
    if ikm.is_empty() {
        return Err(GidError::new(
            ErrorCode::InvalidKeyFormat,
            "HKDF input key material must not be empty",
        ));
    }
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    if let Some(slice) = out.get_mut(..prk.len()) {
        slice.copy_from_slice(&prk);
    }
    Ok(out)
}

/// HKDF-Expand aislado (RFC 5869 §2.3) a partir de una pseudorandom key (PRK).
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`] si `okm_len` es 0 o excede [`MAX_HKDF_OUTPUT_LEN`].
pub fn hkdf_expand_sha256(
    prk: &[u8; 32],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, GidError> {
    if okm_len == 0 || okm_len > MAX_HKDF_OUTPUT_LEN {
        return Err(GidError::new(
            ErrorCode::InvalidKeyFormat,
            "HKDF output length out of range",
        ));
    }

    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| GidError::new(ErrorCode::InvalidKeyFormat, "HKDF from_prk failed"))?;
    let mut okm = vec![0u8; okm_len];
    hkdf.expand(info, &mut okm)
        .map_err(|_| GidError::new(ErrorCode::InvalidKeyFormat, "HKDF expand failed"))?;
    Ok(okm)
}

use alloc::vec;
use gravital_id_types::{ErrorCode, GidError};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;

    // // Verifies: REQ-SEC-002 (vector RFC 5869 A.1, SHA-256)
    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = {
            let mut s = [0u8; 13];
            for (i, slot) in s.iter_mut().enumerate() {
                *slot = i as u8;
            }
            s
        };
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let okm = hkdf_sha256(&salt, &ikm, &info, 42).expect("valid");
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected);

        // PRK del caso 1 (RFC 5869 A.1).
        let prk = hkdf_extract_sha256(&salt, &ikm).expect("valid");
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected_prk);
    }

    // // Verifies: REQ-SEC-002 (caso negativo: argumentos inválidos)
    #[test]
    fn rejects_invalid_arguments() {
        assert!(hkdf_sha256(b"salt", b"", b"info", 32).is_err());
        assert!(hkdf_sha256(b"salt", b"ikm", b"info", 0).is_err());
        assert!(hkdf_sha256(b"salt", b"ikm", b"info", MAX_HKDF_OUTPUT_LEN + 1).is_err());
        assert!(hkdf_extract_sha256(b"salt", b"").is_err());
    }

    // // Verifies: REQ-SEC-002 (salt vacío = ceros, permitido por RFC 5869)
    #[test]
    fn empty_salt_is_treated_as_zeros() {
        let okm = hkdf_sha256(b"", b"ikm", b"info", 32).expect("valid with empty salt");
        let zero_salt = [0u8; 32];
        let okm_zeros = hkdf_sha256(&zero_salt, b"ikm", b"info", 32).expect("valid");
        assert_eq!(okm, okm_zeros);
    }

    // // Verifies: REQ-SEC-002 (hkdf_expand_sha256 con PRK)
    #[test]
    fn hkdf_expand_matches_rfc5869_case_1() {
        let salt = {
            let mut s = [0u8; 13];
            for (i, slot) in s.iter_mut().enumerate() {
                *slot = i as u8;
            }
            s
        };
        let ikm = [0x0bu8; 22];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let prk = hkdf_extract_sha256(&salt, &ikm).expect("valid");
        let okm = hkdf_expand_sha256(&prk, &info, 42).expect("valid expand");
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected);

        assert!(hkdf_expand_sha256(&prk, &info, 0).is_err());
        assert!(hkdf_expand_sha256(&prk, &info, MAX_HKDF_OUTPUT_LEN + 1).is_err());
    }
}
