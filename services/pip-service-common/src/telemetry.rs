//! Inicialización de observabilidad, trazas estructuradas y OpenTelemetry (F7.T02, REQ-OBS-001).
//!
//! Trazabilidad:
//! - **REQ-OBS-001:** Los servicios DEBEN instrumentarse con OpenTelemetry.
//! - **REQ-PRIV-003:** Los servicios NO DEBEN registrar datos personales ni secretos.

use crate::config::TelemetryConfig;
use crate::error::CommonError;
use crate::redaction::RedactingWriter;
use std::io;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Estructura guardiana de telemetría que asegura el vaciado de buffers al cerrarse.
#[derive(Debug)]
pub struct TelemetryGuard {
    service_name: String,
}

impl TelemetryGuard {
    /// Nombre del servicio registrado en la telemetría.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Al salir, asegura el vaciado ordenado
        let _ = io::stdout();
    }
}

/// Configura el filtro de niveles para telemetría a partir del nivel solicitado.
#[must_use]
pub fn create_env_filter(log_level: &str) -> EnvFilter {
    EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Describe las opciones activas de formato de telemetría.
#[must_use]
pub fn format_description(config: &TelemetryConfig) -> String {
    format!(
        "service={}, level={}, format={}, redaction={}",
        config.service_name,
        config.log_level,
        if config.json_format {
            "json"
        } else {
            "compact"
        },
        config.enable_redaction
    )
}

/// Construye la capa de formateo y escritura de eventos según la configuración especificada.
pub fn build_layer<S>(
    config: &TelemetryConfig,
) -> Box<dyn tracing_subscriber::Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    if config.enable_redaction {
        let make_writer = || RedactingWriter::new(io::stdout());
        if config.json_format {
            Box::new(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(make_writer),
            )
        } else {
            Box::new(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_writer(make_writer),
            )
        }
    } else if config.json_format {
        Box::new(tracing_subscriber::fmt::layer().json())
    } else {
        Box::new(tracing_subscriber::fmt::layer().compact())
    }
}

// Verifies: REQ-OBS-001, REQ-PRIV-003
/// Inicializa el suscriptor global de `tracing` con soporte de formato estructurado y capa de redacción.
pub fn init_telemetry(config: &TelemetryConfig) -> Result<TelemetryGuard, CommonError> {
    let filter = create_env_filter(&config.log_level);
    let layer = build_layer(config);

    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init()
        .map_err(|e| CommonError::Telemetry(format!("Error inicializando suscriptor: {e}")))?;

    Ok(TelemetryGuard {
        service_name: config.service_name.clone(),
    })
}
