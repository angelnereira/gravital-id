//! Cifrado autenticado XChaCha20-Poly1305 (F2.T06, ADR-0008).
//!
//! Backend RustCrypto (`chacha20poly1305` con XChaCha20, ADR-0007; nonce
//! extendido de 192 bits / 24 bytes, `CRYPTO_PROFILES.md §3.1`).
//!
//! El nonce **nunca** se genera aquí: lo aporta el llamador desde el CSPRNG
//! inyectado (INV-11) y debe ser único por clave (REQ-SEC-003).

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use gravital_id_types::{ErrorCode, GidError};

/// Longitud de la clave XChaCha20-Poly1305 en bytes.
pub const AEAD_KEY_LEN: usize = 32;

/// Longitud del nonce extendido XChaCha20 en bytes.
pub const AEAD_NONCE_LEN: usize = 24;

/// Longitud de la etiqueta de autenticación Poly1305 en bytes.
pub const AEAD_TAG_LEN: usize = 16;

/// Sella (cifra + autentica) `plaintext` con `aad` como datos asociados.
///
/// La salida es `ciphertext || tag` (convención del crate).
///
/// # Errores
/// [`ErrorCode::InvalidKeyFormat`] si la clave o el nonce no tienen la longitud
/// del perfil.
pub fn seal(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| GidError::new(ErrorCode::InvalidKeyFormat, "AEAD seal failed"))
}

/// Abre (descifra + verifica) un sobre `ciphertext || tag` con `aad`.
///
/// # Errores
/// [`ErrorCode::AeadAuthenticationFailed`] si la etiqueta no verifica (datos
/// corruptos, clave incorrecta o AAD distinto). Fail-closed: nunca devuelve
/// datos parciales.
pub fn open(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, GidError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;

    fn key() -> [u8; AEAD_KEY_LEN] {
        [0x42u8; AEAD_KEY_LEN]
    }

    fn nonce() -> [u8; AEAD_NONCE_LEN] {
        [0x07u8; AEAD_NONCE_LEN]
    }

    // // Verifies: REQ-SEC-002 (round-trip con AAD)
    #[test]
    fn round_trips_with_authenticated_data() {
        let plaintext = b"presentacion offline de prueba";
        let aad = b"kid=te-iss-2026-ecdsa-01";
        let sealed = seal(&key(), &nonce(), plaintext, aad).expect("seal");
        assert_eq!(sealed.len(), plaintext.len() + AEAD_TAG_LEN);
        let opened = open(&key(), &nonce(), &sealed, aad).expect("open");
        assert_eq!(opened, plaintext);
    }

    // // Verifies: REQ-SEC-003 (el cifrado no es determinista en el sentido de
    // que alterar cualquier byte del sobre invalida la etiqueta)
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let plaintext = b"datos sensibles";
        let mut sealed = seal(&key(), &nonce(), plaintext, b"").expect("seal");
        let len = sealed.len();
        if let Some(byte) = sealed.get_mut(len.saturating_sub(1)) {
            *byte ^= 0xFF;
        }
        assert_eq!(
            open(&key(), &nonce(), &sealed, b"")
                .expect_err("tamper")
                .code,
            ErrorCode::AeadAuthenticationFailed
        );
    }

    // // Verifies: REQ-SEC-003 (AAD incorrecto rechaza)
    #[test]
    fn wrong_aad_is_rejected() {
        let sealed = seal(&key(), &nonce(), b"mensaje", b"aad-correcto").expect("seal");
        assert!(open(&key(), &nonce(), &sealed, b"aad-incorrecto").is_err());
        assert!(open(&key(), &nonce(), &sealed, b"").is_err());
    }

    // // Verifies: REQ-SEC-003 (clave incorrecta rechaza)
    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&key(), &nonce(), b"mensaje", b"").expect("seal");
        let mut other = key();
        if let Some(byte) = other.get_mut(0) {
            *byte ^= 0xFF;
        }
        assert!(open(&other, &nonce(), &sealed, b"").is_err());
    }

    // // Verifies: REQ-SEC-003 (nonce distinto rechaza)
    #[test]
    fn wrong_nonce_is_rejected() {
        let sealed = seal(&key(), &nonce(), b"mensaje", b"").expect("seal");
        let mut other_nonce = nonce();
        if let Some(byte) = other_nonce.get_mut(0) {
            *byte ^= 0xFF;
        }
        assert!(open(&key(), &other_nonce, &sealed, b"").is_err());
    }

    // // Verifies: REQ-SEC-003 (sobre vacío y mensaje vacío)
    #[test]
    fn handles_empty_payloads() {
        let sealed = seal(&key(), &nonce(), b"", b"").expect("seal empty");
        assert_eq!(sealed.len(), AEAD_TAG_LEN);
        let opened = open(&key(), &nonce(), &sealed, b"").expect("open empty");
        assert!(opened.is_empty());
        // Un sobre sin etiqueta completa se rechaza.
        let short = sealed.get(..AEAD_TAG_LEN.saturating_sub(1)).unwrap_or(&[]);
        assert!(open(&key(), &nonce(), short, b"").is_err());
    }
}
