//! Comprobaciones de salud para pip-trust-service (F7.T04, REQ-REL-001, REQ-OBS-001).

use crate::aggregator::AggregatedSignedBundle;
use crate::publisher::BundlePublisher;
use pip_service_common::health::{ComponentHealth, HealthCheck};
use std::sync::{Arc, Mutex};

/// Estado de la última ejecución del proceso de derivación y agregación.
#[derive(Debug, Clone)]
pub struct LastAggregationStatus {
    /// Timestamp Unix de la última agregación.
    pub timestamp: u64,
    /// Indica si la última agregación fue exitosa.
    pub success: bool,
    /// Detalles del último bundle generado si fue exitoso.
    pub last_bundle: Option<AggregatedSignedBundle>,
    /// Mensaje de error si la última agregación falló.
    pub error_message: Option<String>,
}

/// Comprobador de salud del servicio de confianza.
#[derive(Clone)]
pub struct TrustServiceHealthCheck {
    publisher: Arc<dyn BundlePublisher>,
    status: Arc<Mutex<Option<LastAggregationStatus>>>,
}

impl TrustServiceHealthCheck {
    /// Crea una nueva comprobación de salud para pip-trust-service.
    #[must_use]
    pub fn new(
        publisher: Arc<dyn BundlePublisher>,
        status: Arc<Mutex<Option<LastAggregationStatus>>>,
    ) -> Self {
        Self { publisher, status }
    }
}

impl HealthCheck for TrustServiceHealthCheck {
    fn name(&self) -> &str {
        "pip-trust-service"
    }

    fn check(&self) -> ComponentHealth {
        // 1. Validar accesibilidad del almacenamiento del publicador
        if let Err(e) = self.publisher.get_object("bundles/current.json") {
            let msg = format!("Almacenamiento de bundles no disponible: {e}");
            return ComponentHealth::unhealthy(self.name(), &msg);
        }

        // 2. Evaluar el estado de la última agregación
        if let Ok(guard) = self.status.lock() {
            if let Some(st) = guard.as_ref() {
                if !st.success {
                    let err = st
                        .error_message
                        .as_deref()
                        .unwrap_or("Fallo indeterminado en última agregación");
                    let msg = format!("Última generación de trust bundle falló: {err}");
                    return ComponentHealth::degraded(self.name(), &msg);
                }

                if let Some(bundle) = &st.last_bundle {
                    if !bundle.divergent_operators.is_empty() {
                        let msg = format!(
                            "Bundle publicado con operadores divergentes detectados: {:?}",
                            bundle.divergent_operators
                        );
                        return ComponentHealth::degraded(self.name(), &msg);
                    }
                }
            } else {
                return ComponentHealth::degraded(
                    self.name(),
                    "Servicio iniciando: aún no se ha ejecutado ninguna agregación de confianza",
                );
            }
        }

        ComponentHealth::healthy(self.name())
    }
}
