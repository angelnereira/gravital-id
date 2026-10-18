//! Configuración tipada y validación para pip-relay (F7.T06, REQ-SYNC-004, REQ-SYNC-006, REQ-REL-001).

use crate::error::RelayError;
use pip_service_common::config::{ServerConfig, TelemetryConfig};
use std::env;

/// Configuración operativa completa de `pip-relay`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// Configuración del servidor HTTP (host, puerto, timeout de apagado).
    pub server: ServerConfig,
    /// Configuración de telemetría y redacción de logs.
    pub telemetry: TelemetryConfig,
    /// Tamaño máximo permitido para cualquier payload individual en bytes (por defecto 128 KiB).
    pub max_payload_bytes: usize,
    /// TTL por defecto para objetos direccionados por hash en segundos (por defecto 7 días).
    pub default_object_ttl_secs: u64,
    /// TTL máximo admisible para objetos en segundos (por defecto 30 días).
    pub max_object_ttl_secs: u64,
    /// TTL por defecto para sobres de buzón en segundos (por defecto 24 horas).
    pub default_envelope_ttl_secs: u64,
    /// TTL máximo admisible para sobres en segundos (por defecto 7 días).
    pub max_envelope_ttl_secs: u64,
    /// TTL estricto para sesiones de punto de encuentro numérico (`SessionCode`) en segundos (norma: 180 s).
    pub session_code_ttl_secs: u64,
    /// Capacidad máxima de objetos en memoria.
    pub max_objects_capacity: usize,
    /// Capacidad máxima de buzones concurrentes en memoria.
    pub max_mailboxes_capacity: usize,
    /// Número máximo de sobres pendientes por buzón.
    pub max_envelopes_per_mailbox: usize,
    /// Capacidad máxima de sesiones de punto de encuentro en memoria.
    pub max_rendezvous_capacity: usize,
    /// Límite de peticiones por minuto por cliente/IP.
    pub rate_limit_requests_per_minute: u32,
    /// Ráfaga máxima permitida para el limitador de tasa.
    pub rate_limit_burst: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8083,
                shutdown_timeout_secs: 5,
            },
            telemetry: TelemetryConfig {
                service_name: "pip-relay".to_string(),
                log_level: "info".to_string(),
                json_format: true,
                enable_redaction: true,
            },
            max_payload_bytes: 128 * 1024,       // 128 KiB
            default_object_ttl_secs: 7 * 86_400, // 7 días
            max_object_ttl_secs: 30 * 86_400,    // 30 días
            default_envelope_ttl_secs: 86_400,   // 24 horas
            max_envelope_ttl_secs: 7 * 86_400,   // 7 días
            session_code_ttl_secs: 180,          // 180 segundos (PROTOCOL.md §7.7)
            max_objects_capacity: 10_000,
            max_mailboxes_capacity: 5_000,
            max_envelopes_per_mailbox: 100,
            max_rendezvous_capacity: 2_000,
            rate_limit_requests_per_minute: 120,
            rate_limit_burst: 30,
        }
    }
}

impl RelayConfig {
    /// Carga la configuración desde las variables de entorno con prefijo `PIP_RELAY_`
    /// aplicando valores por defecto y validación fail-closed.
    ///
    /// # Errores
    /// Retorna [`RelayError::Config`] si algún valor numérico o rango es inválido.
    pub fn from_env() -> Result<Self, RelayError> {
        Self::from_env_with_prefix("PIP_RELAY_")
    }

    /// Carga la configuración desde variables de entorno con el prefijo indicado.
    pub fn from_env_with_prefix(prefix: &str) -> Result<Self, RelayError> {
        let mut config = Self::default();

        let host_key = format!("{prefix}HOST");
        if let Ok(val) = env::var(&host_key) {
            if !val.trim().is_empty() {
                config.server.host = val.trim().to_string();
            }
        }

        let port_key = format!("{prefix}PORT");
        if let Ok(val) = env::var(&port_key) {
            config.server.port = val
                .parse::<u16>()
                .map_err(|e| RelayError::Config(format!("Invalid {port_key}: '{val}' ({e})")))?;
        }

        let max_payload_key = format!("{prefix}MAX_PAYLOAD_BYTES");
        if let Ok(val) = env::var(&max_payload_key) {
            config.max_payload_bytes = val.parse::<usize>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_payload_key}: '{val}' ({e})"))
            })?;
        }

        let def_obj_ttl_key = format!("{prefix}DEFAULT_OBJECT_TTL_SECS");
        if let Ok(val) = env::var(&def_obj_ttl_key) {
            config.default_object_ttl_secs = val.parse::<u64>().map_err(|e| {
                RelayError::Config(format!("Invalid {def_obj_ttl_key}: '{val}' ({e})"))
            })?;
        }

        let max_obj_ttl_key = format!("{prefix}MAX_OBJECT_TTL_SECS");
        if let Ok(val) = env::var(&max_obj_ttl_key) {
            config.max_object_ttl_secs = val.parse::<u64>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_obj_ttl_key}: '{val}' ({e})"))
            })?;
        }

        let def_env_ttl_key = format!("{prefix}DEFAULT_ENVELOPE_TTL_SECS");
        if let Ok(val) = env::var(&def_env_ttl_key) {
            config.default_envelope_ttl_secs = val.parse::<u64>().map_err(|e| {
                RelayError::Config(format!("Invalid {def_env_ttl_key}: '{val}' ({e})"))
            })?;
        }

        let max_env_ttl_key = format!("{prefix}MAX_ENVELOPE_TTL_SECS");
        if let Ok(val) = env::var(&max_env_ttl_key) {
            config.max_envelope_ttl_secs = val.parse::<u64>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_env_ttl_key}: '{val}' ({e})"))
            })?;
        }

        let session_ttl_key = format!("{prefix}SESSION_CODE_TTL_SECS");
        if let Ok(val) = env::var(&session_ttl_key) {
            config.session_code_ttl_secs = val.parse::<u64>().map_err(|e| {
                RelayError::Config(format!("Invalid {session_ttl_key}: '{val}' ({e})"))
            })?;
        }

        let max_objs_key = format!("{prefix}MAX_OBJECTS_CAPACITY");
        if let Ok(val) = env::var(&max_objs_key) {
            config.max_objects_capacity = val.parse::<usize>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_objs_key}: '{val}' ({e})"))
            })?;
        }

        let max_boxes_key = format!("{prefix}MAX_MAILBOXES_CAPACITY");
        if let Ok(val) = env::var(&max_boxes_key) {
            config.max_mailboxes_capacity = val.parse::<usize>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_boxes_key}: '{val}' ({e})"))
            })?;
        }

        let max_envs_per_box_key = format!("{prefix}MAX_ENVELOPES_PER_MAILBOX");
        if let Ok(val) = env::var(&max_envs_per_box_key) {
            config.max_envelopes_per_mailbox = val.parse::<usize>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_envs_per_box_key}: '{val}' ({e})"))
            })?;
        }

        let max_rendezvous_key = format!("{prefix}MAX_RENDEZVOUS_CAPACITY");
        if let Ok(val) = env::var(&max_rendezvous_key) {
            config.max_rendezvous_capacity = val.parse::<usize>().map_err(|e| {
                RelayError::Config(format!("Invalid {max_rendezvous_key}: '{val}' ({e})"))
            })?;
        }

        let rate_limit_key = format!("{prefix}RATE_LIMIT_REQUESTS_PER_MINUTE");
        if let Ok(val) = env::var(&rate_limit_key) {
            config.rate_limit_requests_per_minute = val.parse::<u32>().map_err(|e| {
                RelayError::Config(format!("Invalid {rate_limit_key}: '{val}' ({e})"))
            })?;
        }

        let rate_burst_key = format!("{prefix}RATE_LIMIT_BURST");
        if let Ok(val) = env::var(&rate_burst_key) {
            config.rate_limit_burst = val.parse::<u32>().map_err(|e| {
                RelayError::Config(format!("Invalid {rate_burst_key}: '{val}' ({e})"))
            })?;
        }

        let log_level_key = format!("{prefix}LOG_LEVEL");
        if let Ok(val) = env::var(&log_level_key) {
            config.telemetry.log_level = val.trim().to_lowercase();
        }

        config.validate()?;
        Ok(config)
    }

    /// Valida las invariantes de configuración.
    ///
    /// # Errores
    /// Retorna [`RelayError::Config`] si algún parámetro excede límites o es inconsistente.
    pub fn validate(&self) -> Result<(), RelayError> {
        if self.server.port == 0 {
            return Err(RelayError::Config("server.port must not be 0".to_string()));
        }

        if self.max_payload_bytes == 0 || self.max_payload_bytes > 10 * 1024 * 1024 {
            return Err(RelayError::Config(
                "max_payload_bytes must be between 1 and 10 MiB".to_string(),
            ));
        }

        if self.default_object_ttl_secs == 0
            || self.default_object_ttl_secs > self.max_object_ttl_secs
        {
            return Err(RelayError::Config(
                "default_object_ttl_secs must be > 0 and <= max_object_ttl_secs".to_string(),
            ));
        }

        if self.default_envelope_ttl_secs == 0
            || self.default_envelope_ttl_secs > self.max_envelope_ttl_secs
        {
            return Err(RelayError::Config(
                "default_envelope_ttl_secs must be > 0 and <= max_envelope_ttl_secs".to_string(),
            ));
        }

        if self.session_code_ttl_secs == 0 || self.session_code_ttl_secs > 180 {
            return Err(RelayError::Config(
                "session_code_ttl_secs must be > 0 and <= 180 seconds (PROTOCOL.md §7.7)"
                    .to_string(),
            ));
        }

        if self.max_objects_capacity == 0 || self.max_mailboxes_capacity == 0 {
            return Err(RelayError::Config(
                "capacities must be greater than zero".to_string(),
            ));
        }

        if self.max_envelopes_per_mailbox == 0 {
            return Err(RelayError::Config(
                "max_envelopes_per_mailbox must be greater than zero".to_string(),
            ));
        }

        if self.rate_limit_requests_per_minute == 0 {
            return Err(RelayError::Config(
                "rate_limit_requests_per_minute must be greater than zero".to_string(),
            ));
        }

        Ok(())
    }
}
