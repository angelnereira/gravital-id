//! Comprobaciones de salud para pip-relay (F7.T06, REQ-REL-001, REQ-OBS-001).

use gravital_id_types::Clock;
use pip_service_common::health::{ComponentHealth, HealthCheck};
use std::sync::Arc;

use crate::store::InMemoryRelayStore;

/// Comprobador de salud para `pip-relay`.
pub struct RelayHealthCheck<C: Clock + Send + Sync + 'static> {
    store: Arc<InMemoryRelayStore<C>>,
}

impl<C: Clock + Send + Sync + 'static> RelayHealthCheck<C> {
    /// Construye una nueva comprobación de salud para el relay.
    pub fn new(store: Arc<InMemoryRelayStore<C>>) -> Self {
        Self { store }
    }
}

impl<C: Clock + Send + Sync + 'static> HealthCheck for RelayHealthCheck<C> {
    fn name(&self) -> &str {
        "pip-relay-storage"
    }

    fn check(&self) -> ComponentHealth {
        let object_count = self.store.object_count();
        let max_objects = self.store.config().max_objects_capacity;

        if max_objects > 0 && object_count >= max_objects.saturating_mul(9).div_ceil(10) {
            let msg = format!(
                "Almacenamiento de objetos cercano al límite de capacidad: {object_count}/{max_objects}"
            );
            return ComponentHealth::degraded(self.name(), &msg);
        }

        ComponentHealth::healthy(self.name())
    }
}
