//! Trait de abstracción de transporte de red para sincronización (L4 sans-I/O).
//!
//! Trazabilidad:
//! - **INV-01:** Sin I/O de red en capa L4: el trait desacopla la máquina de estados de los sockets.
//! - **INV-11:** Soporte de transporte simulado determinista en memoria para pruebas.

use gravital_id_types::UnixTime;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::SyncError;
use crate::model::SyncEnvelope;

/// Abstracción de operaciones de red contra un relay o almacenamiento de objetos.
pub trait Transport: Send + Sync {
    /// Publica un objeto direccionado por contenido en el relay y retorna su digest SHA-256.
    fn put_object(&self, relay_url: &str, data: &[u8]) -> Result<String, SyncError>;

    /// Descarga un objeto inmutable por su digest SHA-256 (REQ-SYNC-004, REQ-SYNC-005).
    fn get_object(&self, relay_url: &str, sha256_hex: &str) -> Result<Vec<u8>, SyncError>;

    /// Publica un sobre cifrado en el buzón de destino (REQ-SYNC-001, REQ-SYNC-006).
    fn post_envelope(
        &self,
        relay_url: &str,
        inbox_id: &str,
        envelope_id: &str,
        payload: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<(), SyncError>;

    /// Consulta los sobres pendientes en un buzón desde el timestamp `since` (REQ-SYNC-002).
    fn fetch_envelopes(
        &self,
        relay_url: &str,
        inbox_id: &str,
        since: Option<UnixTime>,
    ) -> Result<Vec<SyncEnvelope>, SyncError>;

    /// Confirma la recepción y elimina un sobre del buzón tras su entrega.
    fn ack_envelope(
        &self,
        relay_url: &str,
        inbox_id: &str,
        envelope_id: &str,
    ) -> Result<(), SyncError>;
}

/// Implementación en memoria de `Transport` para pruebas deterministas sin red (INV-01, INV-11).
#[derive(Default)]
pub struct MockTransport {
    objects: RwLock<HashMap<String, Vec<u8>>>,
    mailboxes: RwLock<HashMap<String, Vec<SyncEnvelope>>>,
    fail_urls: RwLock<HashMap<String, u32>>,
}

impl MockTransport {
    /// Crea una nueva instancia de transporte simulado en memoria.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configura un número de fallos simulados para una URL de relay específica.
    pub fn set_simulate_failures(&self, relay_url: &str, failures_count: u32) {
        if let Ok(mut map) = self.fail_urls.write() {
            map.insert(relay_url.to_string(), failures_count);
        }
    }

    fn check_simulated_failure(&self, relay_url: &str) -> Result<(), SyncError> {
        if let Ok(mut map) = self.fail_urls.write() {
            if let Some(count) = map.get_mut(relay_url) {
                if *count > 0 {
                    *count = count.saturating_sub(1);
                    return Err(SyncError::TransportError {
                        relay_url: relay_url.to_string(),
                        detail: "simulated network transport failure".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl Transport for MockTransport {
    fn put_object(&self, relay_url: &str, data: &[u8]) -> Result<String, SyncError> {
        self.check_simulated_failure(relay_url)?;
        let digest = gravital_id_crypto::sha256(data);
        let hex = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if let Ok(mut map) = self.objects.write() {
            map.insert(hex.clone(), data.to_vec());
        }
        Ok(hex)
    }

    fn get_object(&self, relay_url: &str, sha256_hex: &str) -> Result<Vec<u8>, SyncError> {
        self.check_simulated_failure(relay_url)?;
        let map = self.objects.read().map_err(|_| SyncError::TransportError {
            relay_url: relay_url.to_string(),
            detail: "lock poisoned".to_string(),
        })?;

        map.get(sha256_hex)
            .cloned()
            .ok_or_else(|| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("object with hash '{sha256_hex}' not found"),
            })
    }

    fn post_envelope(
        &self,
        relay_url: &str,
        inbox_id: &str,
        envelope_id: &str,
        payload: &[u8],
        _ttl_secs: Option<u64>,
    ) -> Result<(), SyncError> {
        self.check_simulated_failure(relay_url)?;
        let mut map = self
            .mailboxes
            .write()
            .map_err(|_| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: "lock poisoned".to_string(),
            })?;

        let entry = map.entry(inbox_id.to_string()).or_default();
        if !entry.iter().any(|e| e.envelope_id == envelope_id) {
            entry.push(SyncEnvelope {
                envelope_id: envelope_id.to_string(),
                payload: payload.to_vec(),
                created_at: UnixTime::from_seconds(100),
                expires_at: UnixTime::from_seconds(3600),
            });
        }
        Ok(())
    }

    fn fetch_envelopes(
        &self,
        relay_url: &str,
        inbox_id: &str,
        since: Option<UnixTime>,
    ) -> Result<Vec<SyncEnvelope>, SyncError> {
        self.check_simulated_failure(relay_url)?;
        let map = self
            .mailboxes
            .read()
            .map_err(|_| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: "lock poisoned".to_string(),
            })?;

        let envelopes = map.get(inbox_id).cloned().unwrap_or_default();
        if let Some(s) = since {
            Ok(envelopes
                .into_iter()
                .filter(|e| e.created_at.as_seconds() >= s.as_seconds())
                .collect())
        } else {
            Ok(envelopes)
        }
    }

    fn ack_envelope(
        &self,
        relay_url: &str,
        inbox_id: &str,
        envelope_id: &str,
    ) -> Result<(), SyncError> {
        self.check_simulated_failure(relay_url)?;
        let mut map = self
            .mailboxes
            .write()
            .map_err(|_| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: "lock poisoned".to_string(),
            })?;

        if let Some(list) = map.get_mut(inbox_id) {
            list.retain(|e| e.envelope_id != envelope_id);
        }
        Ok(())
    }
}
