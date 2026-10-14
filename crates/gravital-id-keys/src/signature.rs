//! Normalización de firmas ECDSA P-256 (P1363 ↔ DER).
//!
//! Trazabilidad:
//! - **REQ-KEY-010:** Conversión de firmas ECDSA entre DER y P1363 en el núcleo Rust;
//!   la verificación no exige *low-S* y ninguna firma se usa como identificador.
//! - **PROJECT_STRUCTURE.md §7:** Normalización de firmas de hardware hacia IEEE P1363.

use alloc::vec::Vec;
use gravital_id_crypto::{der_to_p1363, p1363_to_der, ES256_SIGNATURE_LEN};
use gravital_id_types::{ErrorCode, GidError};

/// Normaliza una firma ECDSA P-256 hacia el formato estándar IEEE P1363 (`r‖s`, 64 bytes).
///
/// Acepta tanto firmas P1363 nativas de 64 bytes como firmas codificadas en ASN.1 DER
/// producidas por módulos de seguridad de plataforma (Secure Enclave, StrongBox, TPM, PKCS#11).
///
/// # Errores
/// [`ErrorCode::InvalidSignature`] si los bytes no corresponden a una firma válida ni en P1363 ni en DER.
pub fn normalize_signature_to_p1363(
    raw_signature: &[u8],
) -> Result<[u8; ES256_SIGNATURE_LEN], GidError> {
    if raw_signature.len() == ES256_SIGNATURE_LEN {
        // Valida que (r, s) sean escalares válidos en P-256 (no nulos y dentro del orden de la curva).
        let _ = p1363_to_der(raw_signature)?;
        let mut out = [0u8; ES256_SIGNATURE_LEN];
        out.copy_from_slice(raw_signature);
        Ok(out)
    } else if raw_signature.starts_with(&[0x30]) {
        der_to_p1363(raw_signature)
    } else {
        Err(GidError::new(
            ErrorCode::InvalidSignature,
            "signature must be 64 bytes P1363 (r||s) or ASN.1 DER sequence",
        ))
    }
}

/// Convierte una firma en formato IEEE P1363 (64 bytes) a formato ASN.1 DER.
///
/// # Errores
/// [`ErrorCode::InvalidSignature`] si los componentes `(r, s)` no son escalares P-256 válidos.
pub fn signature_to_der(p1363_signature: &[u8]) -> Result<Vec<u8>, GidError> {
    p1363_to_der(p1363_signature)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_valid_p1363() {
        let sig = [0x42u8; 64];
        let normalized = normalize_signature_to_p1363(&sig).expect("normalize p1363");
        assert_eq!(normalized, sig);
    }

    #[test]
    fn normalize_rejects_invalid_length() {
        let err = normalize_signature_to_p1363(&[0x42u8; 63]).expect_err("should reject");
        assert_eq!(err.code, ErrorCode::InvalidSignature);
    }
}
