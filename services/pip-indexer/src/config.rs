//! Configuración tipada y validación para pip-indexer (F7.T03, REQ-LEDG-005).

use crate::error::IndexerError;
use pip_service_common::config::{ServerConfig, TelemetryConfig};
use std::env;

/// Configuración operativa completa de `pip-indexer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexerConfig {
    /// Configuración del servidor HTTP de observabilidad (/healthz, /readyz).
    pub server: ServerConfig,
    /// Configuración de telemetría y redacción de logs.
    pub telemetry: TelemetryConfig,
    /// Lista de endpoints RPC EVM para tolerancia a fallos y verificación de consistencia.
    pub rpc_endpoints: Vec<String>,
    /// Identificador numérico de la cadena EVM (Chain ID).
    pub chain_id: u64,
    /// Dirección Ethereum del contrato `TrustRegistry.sol` (ej. `0x123...`).
    pub trust_registry_address: String,
    /// Dirección Ethereum del contrato `StatusAnchor.sol` (ej. `0x456...`).
    pub status_anchor_address: String,
    /// Cadena de conexión a la base de datos (PostgreSQL o SQLite para test).
    pub database_url: String,
    /// Tamaño máximo de bloques por consulta de logs (`chunk_size`).
    pub chunk_size_blocks: u64,
    /// Intervalo de sondeo en milisegundos entre verificaciones de nuevos bloques.
    pub poll_interval_millis: u64,
    /// Altura de bloque inicial a escanear si la base de datos no tiene cursor guardado.
    pub start_block: u64,
    /// Umbral de retraso en bloques para reportar degradación de salud.
    pub max_allowed_lag: u64,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8081,
                shutdown_timeout_secs: 5,
            },
            telemetry: TelemetryConfig {
                service_name: "pip-indexer".to_string(),
                log_level: "info".to_string(),
                json_format: true,
                enable_redaction: true,
            },
            rpc_endpoints: vec!["http://127.0.0.1:8545".to_string()],
            chain_id: 31337,
            trust_registry_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3".to_string(),
            status_anchor_address: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512".to_string(),
            database_url: "postgres://pip:pip@localhost:5432/pip_indexer".to_string(),
            chunk_size_blocks: 500,
            poll_interval_millis: 2000,
            start_block: 0,
            max_allowed_lag: 100,
        }
    }
}

impl IndexerConfig {
    /// Carga y valida la configuración desde el entorno con el prefijo por defecto `PIP_INDEXER_`.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::Config`] si alguna variable es inválida o no supera la validación.
    pub fn from_env() -> Result<Self, IndexerError> {
        Self::from_env_with_prefix("PIP_INDEXER_")
    }

    /// Carga y valida la configuración con un prefijo personalizado para variables de entorno.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::Config`] si alguna variable requerida es inválida o viola invariantes.
    pub fn from_env_with_prefix(prefix: &str) -> Result<Self, IndexerError> {
        let mut cfg = Self::default();

        // Servidor y telemetría compartidos
        if let Ok(port_str) = env::var("PIP_SERVER_PORT") {
            let port = port_str
                .parse::<u16>()
                .map_err(|e| IndexerError::Config(format!("PIP_SERVER_PORT inválido: {e}")))?;
            cfg.server.port = port;
        }

        if let Ok(level) = env::var("PIP_LOG_LEVEL") {
            cfg.telemetry.log_level = level;
        }

        // Endpoints RPC
        let rpc_var = format!("{prefix}RPC_ENDPOINTS");
        if let Ok(endpoints_str) = env::var(&rpc_var) {
            let list: Vec<String> = endpoints_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if list.is_empty() {
                return Err(IndexerError::Config(format!(
                    "{rpc_var} no contiene ningún endpoint RPC válido"
                )));
            }
            cfg.rpc_endpoints = list;
        }

        // Chain ID
        let chain_var = format!("{prefix}CHAIN_ID");
        if let Ok(val) = env::var(&chain_var) {
            cfg.chain_id = val
                .parse::<u64>()
                .map_err(|e| IndexerError::Config(format!("{chain_var} inválido: {e}")))?;
        }

        // Direcciones de contratos
        let tr_var = format!("{prefix}TRUST_REGISTRY");
        if let Ok(val) = env::var(&tr_var) {
            cfg.trust_registry_address = val;
        }

        let sa_var = format!("{prefix}STATUS_ANCHOR");
        if let Ok(val) = env::var(&sa_var) {
            cfg.status_anchor_address = val;
        }

        // Base de datos
        let db_var = format!("{prefix}DATABASE_URL");
        if let Ok(val) = env::var(&db_var) {
            cfg.database_url = val;
        }

        // Chunk size
        let chunk_var = format!("{prefix}CHUNK_SIZE");
        if let Ok(val) = env::var(&chunk_var) {
            cfg.chunk_size_blocks = val
                .parse::<u64>()
                .map_err(|e| IndexerError::Config(format!("{chunk_var} inválido: {e}")))?;
        }

        // Intervalo de sondeo
        let poll_var = format!("{prefix}POLL_INTERVAL_MS");
        if let Ok(val) = env::var(&poll_var) {
            cfg.poll_interval_millis = val
                .parse::<u64>()
                .map_err(|e| IndexerError::Config(format!("{poll_var} inválido: {e}")))?;
        }

        // Bloque inicial
        let start_var = format!("{prefix}START_BLOCK");
        if let Ok(val) = env::var(&start_var) {
            cfg.start_block = val
                .parse::<u64>()
                .map_err(|e| IndexerError::Config(format!("{start_var} inválido: {e}")))?;
        }

        // Lag máximo permitido
        let lag_var = format!("{prefix}MAX_ALLOWED_LAG");
        if let Ok(val) = env::var(&lag_var) {
            cfg.max_allowed_lag = val
                .parse::<u64>()
                .map_err(|e| IndexerError::Config(format!("{lag_var} inválido: {e}")))?;
        }

        cfg.validate()?;
        Ok(cfg)
    }

    /// Valida que la configuración cumpla los límites fail-closed operativos.
    ///
    /// # Errores
    /// Devuelve [`IndexerError::Config`] ante cualquier violación de reglas de seguridad o coherencia.
    pub fn validate(&self) -> Result<(), IndexerError> {
        if self.rpc_endpoints.is_empty() {
            return Err(IndexerError::Config(
                "Debe configurarse al menos un endpoint RPC".to_string(),
            ));
        }

        for ep in &self.rpc_endpoints {
            if !ep.starts_with("http://") && !ep.starts_with("https://") && !ep.starts_with("ws://")
            {
                return Err(IndexerError::Config(format!(
                    "Endpoint RPC '{ep}' inválido: debe iniciar con http://, https:// o ws://"
                )));
            }
        }

        if self.chain_id == 0 {
            return Err(IndexerError::Config(
                "chain_id debe ser un entero estrictamente positivo (> 0)".to_string(),
            ));
        }

        if !is_valid_eth_address(&self.trust_registry_address) {
            return Err(IndexerError::Config(format!(
                "Dirección de TrustRegistry inválida: '{}'",
                self.trust_registry_address
            )));
        }

        if !is_valid_eth_address(&self.status_anchor_address) {
            return Err(IndexerError::Config(format!(
                "Dirección de StatusAnchor inválida: '{}'",
                self.status_anchor_address
            )));
        }

        if self.chunk_size_blocks == 0 || self.chunk_size_blocks > 10_000 {
            return Err(IndexerError::Config(format!(
                "chunk_size_blocks ({}) debe estar en el rango [1, 10000]",
                self.chunk_size_blocks
            )));
        }

        if self.poll_interval_millis < 50 || self.poll_interval_millis > 600_000 {
            return Err(IndexerError::Config(format!(
                "poll_interval_millis ({}) debe estar en el rango [50, 600000]",
                self.poll_interval_millis
            )));
        }

        if self.database_url.trim().is_empty() {
            return Err(IndexerError::Config(
                "database_url no puede ser vacía".to_string(),
            ));
        }

        Ok(())
    }
}

fn is_valid_eth_address(addr: &str) -> bool {
    addr.starts_with("0x")
        && addr.len() == 42
        && addr
            .get(2..)
            .is_some_and(|hex| hex.chars().all(|c| c.is_ascii_hexdigit()))
}
