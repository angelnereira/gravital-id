//! Verificación de integridad de contenido y descarga anónima (REQ-SYNC-004, REQ-SYNC-005).
//!
//! Trazabilidad:
//! - **REQ-SYNC-004:** Todo contenido recibido de relays DEBE verificarse por firma o hash antes de usarse.
//! - **REQ-SYNC-005:** Las descargas de datos públicos NO DEBEN incluir identificadores del titular.
//! - **INV-01:** Sans-I/O en capa L4.
//! - **INV-02:** Cero datos personales o identificadores en rutas de descarga pública.
//! - **INV-05:** Fail-closed ante cualquier discrepancia criptográfica.

use gravital_id_crypto::sha256;

use crate::error::SyncError;

/// Parámetros prohibidos en consultas de datos públicos para garantizar anonimato (REQ-SYNC-005).
const FORBIDDEN_ANONYMOUS_QUERY_KEYS: &[&str] = &[
    "sub",
    "subject",
    "holder",
    "user",
    "userid",
    "id",
    "identifier",
    "cedula",
    "document",
    "name",
    "imei",
    "cplc",
    "token",
    "bearer",
    "auth",
    "authorization",
    "jwt",
    "session",
];

/// Verificador de integridad y privacidad para sincronización (REQ-SYNC-004, REQ-SYNC-005).
pub struct ContentVerifier;

impl ContentVerifier {
    /// Verifica que el digest SHA-256 de `data` coincida exactamente con `expected_sha256_hex` (REQ-SYNC-004).
    ///
    /// # Errores
    /// [`SyncError::ContentIntegrityFailed`] si los hashes no coinciden (fail-closed, INV-05).
    pub fn verify_object_sha256(data: &[u8], expected_sha256_hex: &str) -> Result<(), SyncError> {
        let digest = sha256(data);
        let actual_hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let expected_clean = expected_sha256_hex.trim().to_ascii_lowercase();

        if actual_hex != expected_clean {
            return Err(SyncError::ContentIntegrityFailed {
                expected_hash: expected_clean,
                actual_hash: actual_hex,
            });
        }

        Ok(())
    }

    /// Valida que la ruta de descarga pública no contenga identificadores del titular ni credenciales (REQ-SYNC-005).
    ///
    /// # Errores
    /// [`SyncError::AnonymousDownloadViolation`] si detecta parámetros o cabeceras prohibidas.
    pub fn assert_anonymous_public_request(url_or_path: &str) -> Result<(), SyncError> {
        let lower = url_or_path.to_ascii_lowercase();

        if let Some((_, query)) = lower.split_once('?') {
            for param in query.split('&') {
                let key = param.split('=').next().unwrap_or("").trim();
                for forbidden in FORBIDDEN_ANONYMOUS_QUERY_KEYS {
                    if key == *forbidden {
                        return Err(SyncError::AnonymousDownloadViolation(format!(
                            "forbidden identity query parameter '{key}' found in public request"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}
