//! Errores de sincronización de operaciones (`gravital-id-sync`, F7.T07).
//!
//! Trazabilidad:
//! - **INV-02:** Cero datos personales ni secretos en mensajes de error.
//! - **INV-05:** Fail-closed ante discrepancias de integridad o autenticación.

use thiserror::Error;

/// Errores producidos durante el ciclo de vida de sincronización.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SyncError {
    /// La cola de salida está vacía.
    #[error("la cola de sincronización está vacía")]
    QueueEmpty,

    /// No se encontró la operación solicitada.
    #[error("operación con id '{0}' no encontrada")]
    OperationNotFound(String),

    /// Intento de transición de estado inválido para una operación.
    #[error("estado inválido para la operación '{id}': se esperaba '{expected}', se encontró '{actual}'")]
    InvalidOperationState {
        /// Identificador de la operación afectada.
        id: String,
        /// Estado esperado para permitir la transición.
        expected: &'static str,
        /// Estado real actual de la operación.
        actual: &'static str,
    },

    /// Clave de idempotencia duplicada en la cola de salida.
    #[error("clave de idempotencia duplicada: la operación '{0}' ya existe en cola")]
    DuplicateOperationId(String),

    /// Fallo de integridad de contenido (REQ-SYNC-004, INV-05).
    #[error("fallo de integridad de contenido: el hash real '{actual_hash}' no coincide con el esperado '{expected_hash}'")]
    ContentIntegrityFailed {
        /// Hash SHA-256 esperado según la dirección de contenido.
        expected_hash: String,
        /// Hash SHA-256 real computado sobre los bytes recibidos.
        actual_hash: String,
    },

    /// Fallo en la verificación de firma digital de un objeto recibido (REQ-SYNC-004).
    #[error("fallo en la verificación de firma digital: {0}")]
    SignatureVerificationFailed(String),

    /// Violación de descarga anónima de datos públicos (REQ-SYNC-005, INV-02).
    #[error("violación de privacidad (REQ-SYNC-005): la solicitud pública '{0}' contiene parámetros de identidad prohibidos")]
    AnonymousDownloadViolation(String),

    /// Fallo al descifrar o autenticar el sobre HPKE (REQ-SYNC-006).
    #[error("fallo al descifrar el sobre HPKE: {0}")]
    DecryptionFailed(String),

    /// Fallo al sellar el sobre HPKE hacia el destinatario (REQ-SYNC-006).
    #[error("fallo al cifrar el sobre HPKE: {0}")]
    EncryptionFailed(String),

    /// Fallo de transporte de red al comunicarse con el relay (REQ-SYNC-007).
    #[error("error de transporte de red con el relay '{relay_url}': {detail}")]
    TransportError {
        /// URL del relay que originó el fallo.
        relay_url: String,
        /// Detalle del error de red subyacente.
        detail: String,
    },

    /// No hay relays disponibles o saludables en el pool (REQ-SYNC-007).
    #[error("todos los relays del pool están agotados o en periodo de penalización")]
    RelayPoolExhausted,

    /// Error de serialización o deserialización de datos.
    #[error("error de serialización de mensaje: {0}")]
    SerializationError(String),

    /// Error de acceso al almacenamiento persistente.
    #[error("error de almacenamiento: {0}")]
    StorageError(String),
}
