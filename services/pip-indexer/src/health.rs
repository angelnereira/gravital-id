//! Verificación de salud y preparación para pip-indexer (F7.T03, REQ-REL-001, REQ-OBS-001).

use crate::metrics::LagMetrics;
use crate::storage::IndexerStorage;
use pip_service_common::health::{ComponentHealth, HealthCheck};
use std::sync::{Arc, Mutex};

/// Comprobador de salud del servicio indexador.
#[derive(Clone)]
pub struct IndexerHealthCheck {
    storage: Arc<dyn IndexerStorage>,
    chain_id: u64,
    max_allowed_lag: u64,
    last_metrics: Arc<Mutex<Option<LagMetrics>>>,
}

impl IndexerHealthCheck {
    /// Crea un nuevo comprobador de salud.
    #[must_use]
    pub fn new(
        storage: Arc<dyn IndexerStorage>,
        chain_id: u64,
        max_allowed_lag: u64,
        last_metrics: Arc<Mutex<Option<LagMetrics>>>,
    ) -> Self {
        Self {
            storage,
            chain_id,
            max_allowed_lag,
            last_metrics,
        }
    }
}

impl HealthCheck for IndexerHealthCheck {
    fn name(&self) -> &str {
        "pip-indexer"
    }

    fn check(&self) -> ComponentHealth {
        // 1. Validar accesibilidad del almacenamiento
        if let Err(e) = self.storage.get_checkpoint(self.chain_id) {
            let msg = format!("Almacenamiento del indexador no disponible: {e}");
            return ComponentHealth::unhealthy(self.name(), &msg);
        }

        // 2. Evaluar métricas de retraso si están disponibles
        if let Ok(guard) = self.last_metrics.lock() {
            if let Some(metrics) = *guard {
                if metrics.lag_blocks > self.max_allowed_lag {
                    let msg = format!(
                        "Retraso de sincronización elevado: {} bloques (límite: {}, finalizado: {}, indexado: {})",
                        metrics.lag_blocks, self.max_allowed_lag, metrics.finalized_head, metrics.indexed_head
                    );
                    return ComponentHealth::degraded(self.name(), &msg);
                }
            }
        }

        ComponentHealth::healthy(self.name())
    }
}
