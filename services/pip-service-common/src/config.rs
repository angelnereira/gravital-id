//! Configuración tipada y validación para servicios de Gravital ID (ADR-0013, REQ-REL-001).

use crate::error::CommonError;
use serde::{Deserialize, Serialize};
use std::env;

/// Entorno de ejecución del servicio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Entorno local de desarrollo (Anvil, MinIO, Postgres local).
    Local,
    /// Entorno de desarrollo en nube.
    Dev,
    /// Entorno oficial de pruebas en Arbitrum Sepolia.
    Testnet,
    /// Entorno de piloto institucional controlado.
    Pilot,
    /// Red principal en producción.
    Production,
}

impl Environment {
    /// Determina si el entorno actual es de producción o piloto.
    #[must_use]
    pub const fn is_production(&self) -> bool {
        matches!(self, Self::Pilot | Self::Production)
    }

    /// Parsea un entorno desde cadena de texto de forma tolerante a mayúsculas.
    pub fn parse_str(s: &str) -> Result<Self, CommonError> {
        match s.trim().to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "dev" | "development" => Ok(Self::Dev),
            "testnet" => Ok(Self::Testnet),
            "pilot" => Ok(Self::Pilot),
            "prod" | "production" => Ok(Self::Production),
            other => Err(CommonError::Config(format!(
                "Entorno no reconocido: '{other}'. Valores permitidos: local, dev, testnet, pilot, production"
            ))),
        }
    }
}

/// Configuración de red y servidor HTTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Dirección IP o host donde escuchar (por defecto "0.0.0.0").
    pub host: String,
    /// Puerto TCP donde exponer el servicio.
    pub port: u16,
    /// Tiempo máximo en segundos para completar peticiones durante el apagado ordenado.
    pub shutdown_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            shutdown_timeout_secs: 15,
        }
    }
}

/// Configuración de observabilidad y telemetría.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Nombre del servicio para spans de OpenTelemetry y logs.
    pub service_name: String,
    /// Nivel de log mínimo (ej. "info", "debug", "warn", "error").
    pub log_level: String,
    /// Indica si emitir logs estructurados en formato JSON (recomendado en producción).
    pub json_format: bool,
    /// Indica si la capa de redacción no-PII está activada (obligatorio por INV-02).
    pub enable_redaction: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "gravital-id-service".to_string(),
            log_level: "info".to_string(),
            json_format: false,
            enable_redaction: true,
        }
    }
}

/// Configuración integral base de un microservicio de Gravital ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Entorno de ejecución.
    pub environment: Environment,
    /// Configuración del servidor HTTP.
    pub server: ServerConfig,
    /// Configuración de telemetría y observabilidad.
    pub telemetry: TelemetryConfig,
}

impl ServiceConfig {
    /// Carga y valida la configuración desde las variables de entorno del sistema.
    pub fn from_env(default_service_name: &str, default_port: u16) -> Result<Self, CommonError> {
        let env_str = env::var("ENVIRONMENT").unwrap_or_else(|_| "local".to_string());
        let environment = Environment::parse_str(&env_str)?;

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = match env::var("PORT") {
            Ok(p) => p
                .parse::<u16>()
                .map_err(|e| CommonError::Config(format!("Variable PORT inválida '{p}': {e}")))?,
            Err(_) => default_port,
        };

        if port == 0 {
            return Err(CommonError::Config("El puerto no puede ser 0".to_string()));
        }

        let shutdown_timeout_secs = match env::var("SHUTDOWN_TIMEOUT_SECS") {
            Ok(s) => s.parse::<u64>().map_err(|e| {
                CommonError::Config(format!(
                    "Variable SHUTDOWN_TIMEOUT_SECS inválida '{s}': {e}"
                ))
            })?,
            Err(_) => 15,
        };

        let log_level = env::var("RUST_LOG")
            .or_else(|_| env::var("LOG_LEVEL"))
            .unwrap_or_else(|_| "info".to_string());

        let json_format = match env::var("LOG_FORMAT") {
            Ok(f) => f.trim().eq_ignore_ascii_case("json"),
            Err(_) => environment.is_production(),
        };

        // En entornos de producción y testnet, la redacción no se puede desactivar (INV-02)
        let enable_redaction = match env::var("ENABLE_LOG_REDACTION") {
            Ok(val) => {
                let parsed = val.trim().eq_ignore_ascii_case("true") || val.trim() == "1";
                if environment.is_production() && !parsed {
                    return Err(CommonError::Config(
                        "No se puede desactivar la redacción de logs en producción (INV-02 / REQ-PRIV-003)".to_string(),
                    ));
                }
                parsed
            }
            Err(_) => true,
        };

        Ok(Self {
            environment,
            server: ServerConfig {
                host,
                port,
                shutdown_timeout_secs,
            },
            telemetry: TelemetryConfig {
                service_name: default_service_name.to_string(),
                log_level,
                json_format,
                enable_redaction,
            },
        })
    }
}
