//! Errores para el módulo común de servicios (`pip-service-common`).

use thiserror::Error;

/// Errores producidos por la infraestructura común de servicios.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum CommonError {
    /// Error en la configuración del servicio.
    #[error("Error de configuración: {0}")]
    Config(String),

    /// Error en la inicialización o ejecución de telemetría.
    #[error("Error de telemetría: {0}")]
    Telemetry(String),

    /// Error en la verificación de salud.
    #[error("Error en comprobación de salud: {0}")]
    Health(String),

    /// Error en el servidor HTTP o de red.
    #[error("Error de red/servidor: {0}")]
    Server(String),

    /// Error de serialización o deserialización JSON.
    #[error("Error de serialización JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Error de I/O del sistema.
    #[error("Error de I/O: {0}")]
    Io(#[from] std::io::Error),
}
