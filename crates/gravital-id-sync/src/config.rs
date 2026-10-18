//! Configuración operativa para el subsistema de sincronización (F7.T07).

use crate::error::SyncError;

/// Configuración de la máquina de estados de sincronización.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    /// Lista ordenada de URLs base de endpoints de relay con soporte de failover (`REQ-SYNC-007`).
    pub relay_endpoints: Vec<String>,
    /// Número máximo de reintentos antes de marcar una operación como `Failed`.
    pub max_retries: u32,
    /// Intervalo base de espera inicial en segundos para el backoff exponencial.
    pub initial_backoff_secs: u64,
    /// Intervalo máximo de espera en segundos para el backoff exponencial.
    pub max_backoff_secs: u64,
    /// Factor multiplicador del backoff exponencial (típicamente 2).
    pub backoff_multiplier: u32,
    /// Capacidad máxima de operaciones pendientes en la cola local.
    pub max_queue_size: usize,
    /// TTL en segundos para sobres de operación en los buzones de los relays.
    pub envelope_ttl_secs: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            relay_endpoints: vec!["https://relay.gravital.id".to_string()],
            max_retries: 5,
            initial_backoff_secs: 1,
            max_backoff_secs: 60,
            backoff_multiplier: 2,
            max_queue_size: 1_000,
            envelope_ttl_secs: 86_400,
        }
    }
}

impl SyncConfig {
    /// Valida que la configuración cumpla todas las restricciones operativas.
    ///
    /// # Errores
    /// Retorna [`SyncError::Config`] si alguna invariante no se satisface.
    pub fn validate(&self) -> Result<(), SyncError> {
        if self.relay_endpoints.is_empty() {
            return Err(SyncError::Config(
                "at least one relay endpoint must be configured (REQ-SYNC-007)".to_string(),
            ));
        }

        for endpoint in &self.relay_endpoints {
            if endpoint.trim().is_empty() {
                return Err(SyncError::Config(
                    "relay endpoint URL cannot be empty".to_string(),
                ));
            }
        }

        if self.max_retries == 0 {
            return Err(SyncError::Config("max_retries must be greater than 0".into()));
        }

        if self.initial_backoff_secs == 0 || self.initial_backoff_secs > self.max_backoff_secs {
            return Err(SyncError::Config(
                "initial_backoff_secs must be > 0 and <= max_backoff_secs".into(),
            ));
        }

        if self.backoff_multiplier == 0 {
            return Err(SyncError::Config(
                "backoff_multiplier must be greater than 0".into(),
            ));
        }

        if self.max_queue_size == 0 {
            return Err(SyncError::Config(
                "max_queue_size must be greater than 0".into(),
            ));
        }

        if self.envelope_ttl_secs == 0 {
            return Err(SyncError::Config(
                "envelope_ttl_secs must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}
