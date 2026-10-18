//! Gestión de múltiples relays con conmutación por error (failover) (REQ-SYNC-007).
//!
//! Trazabilidad:
//! - **REQ-SYNC-007:** El cliente DEBE soportar múltiples endpoints de relay con failover.
//! - **INV-01:** Sans-I/O: la selección y seguimiento de salud es determinista en memoria.

use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};

use crate::error::SyncError;

/// Estado y métricas de salud de un relay individual en el pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpoint {
    /// URL base del relay (ej. `https://relay1.gravital.id`).
    pub url: String,
    /// Fallos consecutivos registrados.
    pub consecutive_failures: u32,
    /// Instante hasta el cual el relay está penalizado por fallos.
    #[serde(with = "crate::model::unix_time_serde")]
    pub healthy_after: UnixTime,
    /// Total histórico de operaciones exitosas.
    pub total_successes: u64,
}

impl RelayEndpoint {
    /// Crea un nuevo endpoint de relay con métricas en cero.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            consecutive_failures: 0,
            healthy_after: UnixTime::from_seconds(0),
            total_successes: 0,
        }
    }

    /// Retorna `true` si el relay no está actualmente bajo penalización temporal.
    #[must_use]
    pub fn is_healthy(&self, now: UnixTime) -> bool {
        now.as_seconds() >= self.healthy_after.as_seconds()
    }
}

/// Pool de endpoints de relay con failover automático y penalización temporal (REQ-SYNC-007).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPool {
    endpoints: Vec<RelayEndpoint>,
    active_index: usize,
    default_penalty_secs: u64,
}

impl RelayPool {
    /// Construye un nuevo pool de relays con los endpoints iniciales.
    ///
    /// # Errores
    /// [`SyncError::RelayPoolExhausted`] si la lista de URLs está vacía.
    pub fn new(urls: Vec<String>, default_penalty_secs: u64) -> Result<Self, SyncError> {
        if urls.is_empty() {
            return Err(SyncError::RelayPoolExhausted);
        }

        let endpoints = urls.into_iter().map(RelayEndpoint::new).collect();

        Ok(Self {
            endpoints,
            active_index: 0,
            default_penalty_secs: if default_penalty_secs == 0 {
                60
            } else {
                default_penalty_secs
            },
        })
    }

    /// Selecciona el endpoint activo saludable actual (REQ-SYNC-007).
    ///
    /// Si el activo actual está penalizado, busca el siguiente relay saludable en el pool (failover).
    ///
    /// # Errores
    /// [`SyncError::RelayPoolExhausted`] si todos los relays están penalizados o caídos.
    pub fn select_active_relay(&mut self, now: UnixTime) -> Result<&str, SyncError> {
        if self.endpoints.is_empty() {
            return Err(SyncError::RelayPoolExhausted);
        }

        // 1. Probar el activo actual
        if let Some(current) = self.endpoints.get(self.active_index) {
            if current.is_healthy(now) {
                return Ok(&current.url);
            }
        }

        // 2. Failover: buscar el primer endpoint saludable en orden circular
        let total = self.endpoints.len();
        if total == 0 {
            return Err(SyncError::RelayPoolExhausted);
        }
        for offset in 1..total {
            let candidate_idx = self
                .active_index
                .saturating_add(offset)
                .checked_rem(total)
                .unwrap_or(0);
            if let Some(candidate) = self.endpoints.get(candidate_idx) {
                if candidate.is_healthy(now) {
                    self.active_index = candidate_idx;
                    return Ok(&candidate.url);
                }
            }
        }

        // 3. Si todos están penalizados, seleccionar el que tenga el tiempo de penalización más bajo
        if let Some((min_idx, ep)) = self
            .endpoints
            .iter()
            .enumerate()
            .min_by_key(|(_, ep)| ep.healthy_after.as_seconds())
        {
            self.active_index = min_idx;
            return Ok(&ep.url);
        }

        Err(SyncError::RelayPoolExhausted)
    }

    /// Registra una operación exitosa en un relay, restableciendo su contador de fallos.
    pub fn record_success(&mut self, url: &str) {
        if let Some(ep) = self.endpoints.iter_mut().find(|ep| ep.url == url) {
            ep.consecutive_failures = 0;
            ep.healthy_after = UnixTime::from_seconds(0);
            ep.total_successes = ep.total_successes.saturating_add(1);
        }
    }

    /// Registra un fallo de transporte en un relay y aplica penalización para failover.
    pub fn record_failure(&mut self, url: &str, now: UnixTime) {
        let penalty = self.default_penalty_secs;
        let total = self.endpoints.len();

        if let Some((idx, ep)) = self
            .endpoints
            .iter_mut()
            .enumerate()
            .find(|(_, ep)| ep.url == url)
        {
            ep.consecutive_failures = ep.consecutive_failures.saturating_add(1);
            let multiplier = 1u64
                .checked_shl(ep.consecutive_failures.min(5))
                .unwrap_or(32);
            let total_penalty = penalty.saturating_mul(multiplier);
            ep.healthy_after =
                UnixTime::from_seconds(now.as_seconds().saturating_add(total_penalty));

            // Rotar inmediatamente al siguiente si falló el activo
            if idx == self.active_index && total > 1 {
                self.active_index = self
                    .active_index
                    .saturating_add(1)
                    .checked_rem(total)
                    .unwrap_or(0);
            }
        }
    }

    /// Retorna una lista de todos los endpoints configurados.
    #[must_use]
    pub fn endpoints(&self) -> &[RelayEndpoint] {
        &self.endpoints
    }
}
