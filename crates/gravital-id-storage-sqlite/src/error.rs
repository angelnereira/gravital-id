//! Mapeo de errores SQLite a errores canónicos de Gravital ID (INV-02, INV-05).
//!
//! Trazabilidad:
//! - `INV-02`: Ausencia estricta de datos personales o secretos en mensajes de error.
//! - `INV-05`: Fail-closed.

use gravital_id_types::{ErrorCode, GidError};

/// Convierte un error de lectura de SQLite en [`GidError`] con [`ErrorCode::StorageReadFailed`].
#[must_use]
pub fn sqlite_read_err(e: rusqlite::Error) -> GidError {
    GidError::new(
        ErrorCode::StorageReadFailed,
        format!("SQLite read failure: {e}"),
    )
}

/// Convierte un error de escritura o transacción de SQLite en [`GidError`] con [`ErrorCode::StorageWriteFailed`].
#[must_use]
pub fn sqlite_write_err(e: rusqlite::Error) -> GidError {
    GidError::new(
        ErrorCode::StorageWriteFailed,
        format!("SQLite write failure: {e}"),
    )
}

/// Convierte un error de migración en [`GidError`] con [`ErrorCode::SchemaMigrationFailed`].
#[must_use]
pub fn migration_err(e: rusqlite::Error) -> GidError {
    GidError::new(
        ErrorCode::SchemaMigrationFailed,
        format!("SQLite schema migration failure: {e}"),
    )
}

/// Error de estado del verificador corrupto o inválido.
#[must_use]
pub fn verifier_state_corrupted(reason: &str) -> GidError {
    GidError::new(
        ErrorCode::VerifierStateCorrupted,
        format!("Verifier state corrupted: {reason}"),
    )
}
