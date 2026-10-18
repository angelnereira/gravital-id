//! Errores tipados para pip-indexer (F7.T03, REQ-LEDG-005).

use thiserror::Error;

/// Errores derivados de la ejecución del indexador.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IndexerError {
    /// Error en la configuración.
    #[error("Error de configuración del indexador: {0}")]
    Config(String),

    /// Error de persistencia en base de datos.
    #[error("Error de almacenamiento en base de datos: {0}")]
    Database(String),

    /// Error reportado por el adaptador de ledger.
    #[error("Error de acceso al ledger: {0}")]
    Ledger(String),

    /// Divergencia detectada entre proveedores RPC (REQ-LEDG-006, REQ-LEDG-005).
    #[error("Divergencia RPC detectada: altura {block_number}, detalles: {reason}")]
    RpcDivergence {
        /// Número de bloque donde ocurrió la discrepancia.
        block_number: u64,
        /// Causa de la discrepancia.
        reason: String,
    },

    /// Detección de bloque no finalizado o retroceso de cabeza.
    #[error("Inconsistencia en altura finalizada: solicitada {requested}, pero finalizada es {finalized}")]
    BlockNotFinalized {
        /// Altura solicitada.
        requested: u64,
        /// Altura finalizada máxima disponible.
        finalized: u64,
    },

    /// Error de serialización/deserialización JSON.
    #[error("Error de serialización JSON: {0}")]
    Serialization(String),
}
