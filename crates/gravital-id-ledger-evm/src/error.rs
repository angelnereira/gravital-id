//! Catálogo de errores para el adaptador EVM de Gravital ID (F6.T09, F6.T10).
//!
//! Trazabilidad:
//! - **REQ-LEDG-005:** Consumo acotado a bloques finalizados y tolerancia a fallos.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC con failover y verificación de consistencia.

use core::fmt;
use gravital_id_ledger::LedgerError;

/// Resultado de operaciones en `gravital-id-ledger-evm`.
pub type EvmLedgerResult<T> = Result<T, EvmLedgerError>;

/// Errores tipados del adaptador EVM.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvmLedgerError {
    /// Lista de endpoints RPC vacía o no configurada.
    NoRpcEndpointsConfigured,
    /// Todos los endpoints RPC fallaron tras agotar los reintentos permitidos.
    AllEndpointsFailed {
        /// Número de endpoints intentados.
        endpoints_count: usize,
        /// Mensaje del último error observado.
        last_error: String,
    },
    /// Error devuelto por la llamada JSON-RPC del nodo EVM.
    RpcError {
        /// Código de error devuelto por el nodo JSON-RPC (ej. -32600).
        code: i64,
        /// Mensaje descriptivo retornado por el nodo.
        message: String,
    },
    /// Inconsistencia detectada entre proveedores RPC (split-view o discrepancia de cadena).
    ProviderInconsistency {
        /// Descripción de la discrepancia.
        reason: String,
    },
    /// El bloque solicitado no se encuentra finalizado en el ledger (REQ-LEDG-005).
    BlockNotFinalized {
        /// Bloque solicitado.
        requested: u64,
        /// Altura del bloque finalizado más reciente.
        finalized_head: u64,
    },
    /// Rango de bloques inválido (`from_block > to_block`).
    InvalidBlockRange {
        /// Bloque inicial.
        from_block: u64,
        /// Bloque final.
        to_block: u64,
    },
    /// Error de serialización o deserialización de datos JSON-RPC.
    JsonSerialization(String),
    /// Error de decodificación ABI de eventos o retornos de contrato.
    AbiDecoding(String),
    /// Error de transporte de red HTTP / IO.
    Transport(String),
}

impl fmt::Display for EvmLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRpcEndpointsConfigured => write!(f, "no RPC endpoints configured"),
            Self::AllEndpointsFailed {
                endpoints_count,
                last_error,
            } => write!(
                f,
                "all {endpoints_count} RPC endpoints failed; last error: {last_error}"
            ),
            Self::RpcError { code, message } => {
                write!(f, "JSON-RPC error [{code}]: {message}")
            }
            Self::ProviderInconsistency { reason } => {
                write!(f, "provider inconsistency detected: {reason}")
            }
            Self::BlockNotFinalized {
                requested,
                finalized_head,
            } => write!(
                f,
                "block {requested} is not finalized; latest finalized block is {finalized_head}"
            ),
            Self::InvalidBlockRange {
                from_block,
                to_block,
            } => write!(
                f,
                "invalid block range: from_block ({from_block}) > to_block ({to_block})"
            ),
            Self::JsonSerialization(msg) => write!(f, "JSON serialization error: {msg}"),
            Self::AbiDecoding(msg) => write!(f, "ABI decoding error: {msg}"),
            Self::Transport(msg) => write!(f, "RPC transport error: {msg}"),
        }
    }
}

impl std::error::Error for EvmLedgerError {}

impl From<EvmLedgerError> for LedgerError {
    fn from(err: EvmLedgerError) -> Self {
        LedgerError::Adapter(err.to_string())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_and_conversion() {
        let errors = vec![
            EvmLedgerError::NoRpcEndpointsConfigured,
            EvmLedgerError::AllEndpointsFailed {
                endpoints_count: 2,
                last_error: "timeout".to_string(),
            },
            EvmLedgerError::RpcError {
                code: -32600,
                message: "invalid request".to_string(),
            },
            EvmLedgerError::ProviderInconsistency {
                reason: "hash mismatch".to_string(),
            },
            EvmLedgerError::BlockNotFinalized {
                requested: 105,
                finalized_head: 100,
            },
            EvmLedgerError::InvalidBlockRange {
                from_block: 200,
                to_block: 100,
            },
            EvmLedgerError::JsonSerialization("bad json".to_string()),
            EvmLedgerError::AbiDecoding("truncated".to_string()),
            EvmLedgerError::Transport("connection reset".to_string()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
            let ledger_err: LedgerError = err.into();
            match ledger_err {
                LedgerError::Adapter(m) => assert_eq!(m, msg),
                _ => panic!("expected Adapter"),
            }
        }
    }
}
