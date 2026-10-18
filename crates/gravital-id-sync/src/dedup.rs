//! Filtro de deduplicación de sobres entrantes (REQ-SYNC-002).
//!
//! Trazabilidad:
//! - **REQ-SYNC-002:** La entrega DEBE ser al-menos-una-vez con deduplicación en el destinatario.
//! - **INV-01:** Sans-I/O en capa L4.
//! - **INV-02:** Los identificadores de sobre no contienen datos personales.

use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Límite por defecto de identificadores retenidos en el filtro de deduplicación.
pub const DEFAULT_MAX_DEDUP_CAPACITY: usize = 10_000;
/// Ventana temporal por defecto de retención de deduplicación (24 horas).
pub const DEFAULT_DEDUP_WINDOW_SECS: u64 = 86_400;

/// Filtro de deduplicación con ventana deslizante y límite de capacidad (REQ-SYNC-002).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundDeduplicationFilter {
    max_capacity: usize,
    default_ttl_secs: u64,
    /// Mapa de `envelope_id` -> timestamp de caducidad en segundos Unix.
    seen_envelopes: HashMap<String, u64>,
}

impl Default for InboundDeduplicationFilter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DEDUP_CAPACITY, DEFAULT_DEDUP_WINDOW_SECS)
    }
}

impl InboundDeduplicationFilter {
    /// Crea un nuevo filtro de deduplicación con la capacidad y ventana configuradas.
    #[must_use]
    pub fn new(max_capacity: usize, default_ttl_secs: u64) -> Self {
        Self {
            max_capacity: if max_capacity == 0 { 1 } else { max_capacity },
            default_ttl_secs: if default_ttl_secs == 0 {
                60
            } else {
                default_ttl_secs
            },
            seen_envelopes: HashMap::new(),
        }
    }

    /// Comprueba si el sobre ya fue procesado; si es nuevo, lo registra y retorna `true`.
    ///
    /// Si el sobre ya existe dentro de la ventana de vigencia, retorna `false` (es duplicado).
    pub fn check_and_record(&mut self, envelope_id: &str, now: UnixTime) -> bool {
        self.purge_expired(now);

        let now_sec = now.as_seconds();
        if let Some(&expires_at_sec) = self.seen_envelopes.get(envelope_id) {
            if expires_at_sec > now_sec {
                return false; // Ya visto dentro de la ventana: duplicado
            }
        }

        // Si se supera la capacidad máxima, purgar los más próximos a expirar
        if self.seen_envelopes.len() >= self.max_capacity {
            if let Some(oldest_key) = self
                .seen_envelopes
                .iter()
                .min_by_key(|(_, &exp)| exp)
                .map(|(k, _)| k.clone())
            {
                self.seen_envelopes.remove(&oldest_key);
            }
        }

        let expiration_sec = now_sec.saturating_add(self.default_ttl_secs);
        self.seen_envelopes
            .insert(envelope_id.to_string(), expiration_sec);
        true
    }

    /// Consulta si un sobre ya fue visto sin alterar el estado.
    #[must_use]
    pub fn is_duplicate(&self, envelope_id: &str, now: UnixTime) -> bool {
        if let Some(&expires_at_sec) = self.seen_envelopes.get(envelope_id) {
            expires_at_sec > now.as_seconds()
        } else {
            false
        }
    }

    /// Elimina las entradas cuya ventana de retención haya expirado.
    pub fn purge_expired(&mut self, now: UnixTime) {
        let now_sec = now.as_seconds();
        self.seen_envelopes
            .retain(|_, &mut expires_at_sec| expires_at_sec > now_sec);
    }

    /// Retorna el número de identificadores actualmente rastreados.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen_envelopes.len()
    }

    /// Indica si el filtro está vacío.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen_envelopes.is_empty()
    }
}
