//! Cifrado y descifrado de sobres de operación con HPKE RFC 9180 (REQ-SYNC-006).
//!
//! Trazabilidad:
//! - **REQ-SYNC-006:** Los sobres de operación DEBEN cifrarse al destinatario con HPKE (RFC 9180).
//! - **INV-01:** Sans-I/O en capa L4.
//! - **INV-07:** Uso exclusivo de las primitivas de `gravital-id-crypto`.
//! - **INV-11:** Aleatoriedad efímera inyectada en el sellado.

use gravital_id_crypto::hpke::{
    hpke_open_base_p256_hkdf_sha256_chacha20poly1305,
    hpke_seal_base_p256_hkdf_sha256_chacha20poly1305, ENC_LEN,
};

use crate::error::SyncError;

/// Contexto normativo por defecto para el key schedule de sobres de sincronización.
pub const SYNC_HPKE_INFO: &[u8] = b"gid-sync-envelope-v1";

/// Utilidad para sellar y abrir sobres de operación cifrados con HPKE (REQ-SYNC-006).
pub struct HpkeEnvelope;

impl HpkeEnvelope {
    /// Sella un payload en texto claro hacia la clave pública del destinatario.
    ///
    /// Formato del sobre serializado: `enc (65 bytes)` || `ciphertext || auth_tag`.
    ///
    /// # Errores
    /// [`SyncError::EncryptionFailed`] si la clave pública o efímera es inválida o el sellado falla.
    pub fn seal(
        recipient_public_sec1: &[u8; ENC_LEN],
        ephemeral_secret: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SyncError> {
        let (enc, ciphertext) = hpke_seal_base_p256_hkdf_sha256_chacha20poly1305(
            recipient_public_sec1,
            ephemeral_secret,
            SYNC_HPKE_INFO,
            plaintext,
            aad,
        )
        .map_err(|e| SyncError::EncryptionFailed(e.to_string()))?;

        let mut out = Vec::with_capacity(ENC_LEN.saturating_add(ciphertext.len()));
        out.extend_from_slice(&enc);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Abre un sobre cifrado con la clave privada del receptor.
    ///
    /// # Errores
    /// - [`SyncError::DecryptionFailed`] si el sobre tiene menos de 65 bytes o la etiqueta AEAD no verifica.
    pub fn open(
        recipient_secret: &[u8; 32],
        envelope_bytes: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SyncError> {
        if envelope_bytes.len() < ENC_LEN {
            return Err(SyncError::DecryptionFailed(format!(
                "envelope too short: expected at least {} bytes (got {})",
                ENC_LEN,
                envelope_bytes.len()
            )));
        }

        let (enc, ciphertext) = envelope_bytes.split_at(ENC_LEN);

        hpke_open_base_p256_hkdf_sha256_chacha20poly1305(
            recipient_secret,
            enc,
            ciphertext,
            SYNC_HPKE_INFO,
            aad,
        )
        .map_err(|e| SyncError::DecryptionFailed(e.to_string()))
    }
}
