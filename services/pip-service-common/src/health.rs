//! Comprobaciones de salud y disponibilidad para servicios de Gravital ID (F7.T02, REQ-REL-001).
//!
//! Implementa los endpoints estándar de monitoreo de microservicios:
//! - `/healthz`: Comprobación de vida (*liveness probe*).
//! - `/readyz`: Comprobación de disponibilidad y dependencias (*readiness probe*).

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Estado de salud de un componente o servicio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthStatus {
    /// Totalmente operativo y listo para recibir tráfico.
    Up,
    /// Degradado (funcionando parcialmente con advertencias).
    Degraded,
    /// No operativo o desconectado de dependencias esenciales.
    Down,
}

impl HealthStatus {
    /// Determina si el estado general permite aceptar tráfico.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Up | Self::Degraded)
    }
}

/// Estado de salud individual de una dependencia o subsistema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Nombre del componente (ej. "database", "evm_rpc", "s3_storage").
    pub name: String,
    /// Estado del componente.
    pub status: HealthStatus,
    /// Mensaje descriptivo o métricas opcionales.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ComponentHealth {
    /// Crea un nuevo reporte de componente saludable.
    #[must_use]
    pub fn healthy(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Up,
            message: None,
        }
    }

    /// Crea un nuevo reporte de componente con error o desconexión.
    #[must_use]
    pub fn unhealthy(name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Down,
            message: Some(message.to_string()),
        }
    }

    /// Crea un nuevo reporte de componente degradado.
    #[must_use]
    pub fn degraded(name: &str, message: &str) -> Self {
        Self {
            name: name.to_string(),
            status: HealthStatus::Degraded,
            message: Some(message.to_string()),
        }
    }
}

/// Respuesta HTTP estructurada para los endpoints de salud.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Estado global agregado.
    pub status: HealthStatus,
    /// Nombre del microservicio.
    pub service: String,
    /// Versión del microservicio.
    pub version: String,
    /// Lista de componentes evaluados.
    pub components: Vec<ComponentHealth>,
}

/// Trait para componentes que implementan comprobaciones dinámicas de disponibilidad.
pub trait HealthCheck: Send + Sync {
    /// Nombre del componente comprobado.
    fn name(&self) -> &str;
    /// Ejecuta la comprobación y devuelve el estado actual.
    fn check(&self) -> ComponentHealth;
}

/// Registro central de comprobaciones de salud del servicio.
#[derive(Clone)]
pub struct HealthRegistry {
    service_name: String,
    version: String,
    readiness_checks: Vec<Arc<dyn HealthCheck>>,
}

impl HealthRegistry {
    /// Crea un nuevo registro de salud para un servicio.
    #[must_use]
    pub fn new(service_name: &str, version: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            version: version.to_string(),
            readiness_checks: Vec::new(),
        }
    }

    /// Registra una comprobación de disponibilidad dinámica (ej. base de datos, RPC, S3).
    pub fn register_check<C: HealthCheck + 'static>(&mut self, check: C) {
        self.readiness_checks.push(Arc::new(check));
    }

    /// Evalúa el endpoint `/healthz` (liveness probe).
    /// Siempre responde UP si el proceso está activo y respondiendo.
    #[must_use]
    pub fn check_liveness(&self) -> HealthResponse {
        HealthResponse {
            status: HealthStatus::Up,
            service: self.service_name.clone(),
            version: self.version.clone(),
            components: vec![ComponentHealth::healthy("process")],
        }
    }

    /// Evalúa el endpoint `/readyz` (readiness probe).
    /// Ejecuta todas las comprobaciones de dependencias registradas.
    #[must_use]
    pub fn check_readiness(&self) -> HealthResponse {
        let mut components = Vec::with_capacity(self.readiness_checks.len());
        let mut overall_status = HealthStatus::Up;

        for check in &self.readiness_checks {
            let res = check.check();
            if res.status == HealthStatus::Down {
                overall_status = HealthStatus::Down;
            } else if res.status == HealthStatus::Degraded && overall_status != HealthStatus::Down {
                overall_status = HealthStatus::Degraded;
            }
            components.push(res);
        }

        HealthResponse {
            status: overall_status,
            service: self.service_name.clone(),
            version: self.version.clone(),
            components,
        }
    }
}
