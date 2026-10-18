//! Configuración tipada y validación para pip-trust-service (F7.T04, REQ-TRUST-003, REQ-REL-001).

use crate::error::TrustServiceError;
use pip_service_common::config::{ServerConfig, TelemetryConfig};
use std::env;

/// Configuración operativa completa de `pip-trust-service`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustServiceConfig {
    /// Configuración del servidor HTTP de observabilidad (/healthz, /readyz).
    pub server: ServerConfig,
    /// Configuración de telemetría y redacción de logs.
    pub telemetry: TelemetryConfig,
    /// Identificador normativo del marco de confianza (ej. "pip-global-mainnet").
    pub framework_id: String,
    /// Identificador de la cadena EVM (Chain ID).
    pub chain_id: u64,
    /// Época activa de la raíz de confianza.
    pub bundle_epoch: u64,
    /// Versión monotónica incremental del trust bundle.
    pub bundle_version: u64,
    /// Vigencia en segundos asignada al bundle (ej. 7 días = 604.800 s).
    pub validity_duration_seconds: u64,
    /// Umbral mínimo de operadores distintos requeridos (k).
    pub threshold: u32,
    /// Identificador de la organización u operador local.
    pub operator_id: String,
    /// Identificador de la clave pública del operador local en el trust bundle.
    pub operator_kid: String,
    /// Clave privada P-256 en hexadecimal (para dev/test).
    pub operator_private_key_hex: Option<String>,
    /// Backend de almacenamiento para publicación ("memory", "filesystem", "s3").
    pub storage_backend: String,
    /// Directorio local en disco si se usa backend "filesystem".
    pub storage_local_dir: String,
    /// Nombre del bucket S3 si se usa backend "s3".
    pub s3_bucket: String,
    /// Endpoint compatible con S3 (ej. MinIO http://127.0.0.1:9000).
    pub s3_endpoint: String,
    /// Intervalo de sondeo en milisegundos para comprobaciones continuas.
    pub poll_interval_millis: u64,
}

impl Default for TrustServiceConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8082,
                shutdown_timeout_secs: 5,
            },
            telemetry: TelemetryConfig {
                service_name: "pip-trust-service".to_string(),
                log_level: "info".to_string(),
                json_format: true,
                enable_redaction: true,
            },
            framework_id: "pip-global-mainnet".to_string(),
            chain_id: 31337,
            bundle_epoch: 1,
            bundle_version: 1,
            validity_duration_seconds: 604_800, // 7 días
            threshold: 2,
            operator_id: "operator-primary".to_string(),
            operator_kid: "urn:pip:signer:operator-primary".to_string(),
            operator_private_key_hex: None,
            storage_backend: "memory".to_string(),
            storage_local_dir: "/var/data/pip/bundles".to_string(),
            s3_bucket: "pip-trust-bundles".to_string(),
            s3_endpoint: "http://127.0.0.1:9000".to_string(),
            poll_interval_millis: 5000,
        }
    }
}

impl TrustServiceConfig {
    /// Carga la configuración desde el entorno con el prefijo por defecto `PIP_TRUST_`.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Config`] si alguna variable es inválida o no supera la validación.
    pub fn from_env() -> Result<Self, TrustServiceError> {
        Self::from_env_with_prefix("PIP_TRUST_")
    }

    /// Carga la configuración con un prefijo personalizado para variables de entorno.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Config`] ante variables malformadas o inconsistentes.
    pub fn from_env_with_prefix(prefix: &str) -> Result<Self, TrustServiceError> {
        let mut cfg = Self::default();

        if let Ok(port_str) = env::var("PIP_SERVER_PORT") {
            let port = port_str
                .parse::<u16>()
                .map_err(|e| TrustServiceError::Config(format!("PIP_SERVER_PORT inválido: {e}")))?;
            cfg.server.port = port;
        }

        if let Ok(level) = env::var("PIP_LOG_LEVEL") {
            cfg.telemetry.log_level = level;
        }

        let fw_var = format!("{prefix}FRAMEWORK_ID");
        if let Ok(val) = env::var(&fw_var) {
            cfg.framework_id = val;
        }

        let chain_var = format!("{prefix}CHAIN_ID");
        if let Ok(val) = env::var(&chain_var) {
            cfg.chain_id = val
                .parse::<u64>()
                .map_err(|e| TrustServiceError::Config(format!("{chain_var} inválido: {e}")))?;
        }

        let epoch_var = format!("{prefix}BUNDLE_EPOCH");
        if let Ok(val) = env::var(&epoch_var) {
            cfg.bundle_epoch = val
                .parse::<u64>()
                .map_err(|e| TrustServiceError::Config(format!("{epoch_var} inválido: {e}")))?;
        }

        let ver_var = format!("{prefix}BUNDLE_VERSION");
        if let Ok(val) = env::var(&ver_var) {
            cfg.bundle_version = val
                .parse::<u64>()
                .map_err(|e| TrustServiceError::Config(format!("{ver_var} inválido: {e}")))?;
        }

        let val_var = format!("{prefix}VALIDITY_SECONDS");
        if let Ok(val) = env::var(&val_var) {
            cfg.validity_duration_seconds = val
                .parse::<u64>()
                .map_err(|e| TrustServiceError::Config(format!("{val_var} inválido: {e}")))?;
        }

        let th_var = format!("{prefix}THRESHOLD");
        if let Ok(val) = env::var(&th_var) {
            cfg.threshold = val
                .parse::<u32>()
                .map_err(|e| TrustServiceError::Config(format!("{th_var} inválido: {e}")))?;
        }

        let op_var = format!("{prefix}OPERATOR_ID");
        if let Ok(val) = env::var(&op_var) {
            cfg.operator_id = val;
        }

        let kid_var = format!("{prefix}OPERATOR_KID");
        if let Ok(val) = env::var(&kid_var) {
            cfg.operator_kid = val;
        }

        let key_var = format!("{prefix}OPERATOR_PRIVATE_KEY_HEX");
        if let Ok(val) = env::var(&key_var) {
            if !val.trim().is_empty() {
                cfg.operator_private_key_hex = Some(val.trim().to_string());
            }
        }

        let st_var = format!("{prefix}STORAGE_BACKEND");
        if let Ok(val) = env::var(&st_var) {
            cfg.storage_backend = val;
        }

        let dir_var = format!("{prefix}STORAGE_LOCAL_DIR");
        if let Ok(val) = env::var(&dir_var) {
            cfg.storage_local_dir = val;
        }

        let bkt_var = format!("{prefix}S3_BUCKET");
        if let Ok(val) = env::var(&bkt_var) {
            cfg.s3_bucket = val;
        }

        let ep_var = format!("{prefix}S3_ENDPOINT");
        if let Ok(val) = env::var(&ep_var) {
            cfg.s3_endpoint = val;
        }

        let poll_var = format!("{prefix}POLL_INTERVAL_MS");
        if let Ok(val) = env::var(&poll_var) {
            cfg.poll_interval_millis = val
                .parse::<u64>()
                .map_err(|e| TrustServiceError::Config(format!("{poll_var} inválido: {e}")))?;
        }

        cfg.validate()?;
        Ok(cfg)
    }

    /// Valida que la configuración respete los límites y requerimientos de seguridad.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Config`] ante valores fuera de rango o contradictorios.
    pub fn validate(&self) -> Result<(), TrustServiceError> {
        if self.framework_id.trim().is_empty() || self.framework_id.len() > 64 {
            return Err(TrustServiceError::Config(
                "framework_id debe tener entre 1 y 64 caracteres".to_string(),
            ));
        }

        if self.chain_id == 0 {
            return Err(TrustServiceError::Config(
                "chain_id debe ser estrictamente positivo (> 0)".to_string(),
            ));
        }

        if self.bundle_epoch == 0 {
            return Err(TrustServiceError::Config(
                "bundle_epoch debe ser estrictamente positivo (> 0)".to_string(),
            ));
        }

        if self.bundle_version == 0 {
            return Err(TrustServiceError::Config(
                "bundle_version debe ser estrictamente positivo (> 0)".to_string(),
            ));
        }

        if self.validity_duration_seconds < 3600 || self.validity_duration_seconds > 31_536_000 {
            return Err(TrustServiceError::Config(format!(
                "validity_duration_seconds ({}) debe estar en el rango [3600, 31536000]",
                self.validity_duration_seconds
            )));
        }

        if self.threshold == 0 {
            return Err(TrustServiceError::Config(
                "threshold debe ser al menos 1".to_string(),
            ));
        }

        if self.operator_id.trim().is_empty() {
            return Err(TrustServiceError::Config(
                "operator_id no puede ser vacío".to_string(),
            ));
        }

        if self.operator_kid.trim().is_empty() {
            return Err(TrustServiceError::Config(
                "operator_kid no puede ser vacío".to_string(),
            ));
        }

        match self.storage_backend.as_str() {
            "memory" => {}
            "filesystem" => {
                if self.storage_local_dir.trim().is_empty() {
                    return Err(TrustServiceError::Config(
                        "storage_local_dir no puede estar vacío cuando storage_backend es filesystem".to_string(),
                    ));
                }
            }
            "s3" => {
                if self.s3_bucket.trim().is_empty() {
                    return Err(TrustServiceError::Config(
                        "s3_bucket no puede estar vacío cuando storage_backend es s3".to_string(),
                    ));
                }
                if self.s3_endpoint.trim().is_empty() {
                    return Err(TrustServiceError::Config(
                        "s3_endpoint no puede estar vacío cuando storage_backend es s3".to_string(),
                    ));
                }
            }
            other => {
                return Err(TrustServiceError::Config(format!(
                    "storage_backend '{other}' desconocido; valores válidos: memory, filesystem, s3"
                )));
            }
        }

        if self.poll_interval_millis < 50 || self.poll_interval_millis > 600_000 {
            return Err(TrustServiceError::Config(format!(
                "poll_interval_millis ({}) debe estar en el rango [50, 600000]",
                self.poll_interval_millis
            )));
        }

        Ok(())
    }
}
