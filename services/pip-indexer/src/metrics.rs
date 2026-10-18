//! Métricas de retraso y sincronización para el indexador (F7.T03, REQ-LEDG-005).

use serde::{Deserialize, Serialize};

/// Métricas de retraso entre la cabeza finalizada de la red y el cursor indexado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LagMetrics {
    /// Último bloque finalizado conocido en la red blockchain.
    pub finalized_head: u64,
    /// Último bloque indexado exitosamente por el servicio.
    pub indexed_head: u64,
    /// Diferencia en bloques (finalized_head - indexed_head).
    pub lag_blocks: u64,
    /// Indica si el indexador está completamente al día (lag == 0).
    pub is_caught_up: bool,
    /// Timestamp Unix en el que se calcularon estas métricas.
    pub calculated_at: u64,
}

impl LagMetrics {
    /// Calcula las métricas a partir de la cabeza finalizada y el cursor actual.
    #[must_use]
    pub fn compute(finalized_head: u64, indexed_head: u64, timestamp: u64) -> Self {
        let lag_blocks = finalized_head.saturating_sub(indexed_head);
        let is_caught_up = lag_blocks == 0;
        Self {
            finalized_head,
            indexed_head,
            lag_blocks,
            is_caught_up,
            calculated_at: timestamp,
        }
    }
}
