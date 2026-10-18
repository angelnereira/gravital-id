//! Modelos de datos para la sincronización de operaciones (`gravital-id-sync`, F7.T07).
//!
//! Trazabilidad:
//! - **REQ-SYNC-001:** Claves de idempotencia y almacenamiento de operaciones pendientes.
//! - **REQ-SYNC-006:** Sobres cifrados con HPKE.

use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Clave única de idempotencia para una operación de sincronización (REQ-SYNC-001).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OperationId(String);

impl OperationId {
    /// Crea un nuevo identificador de operación validado.
    ///
    /// # Errores
    /// Retorna `None` si la cadena está vacía o excede 128 caracteres.
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let s = id.into();
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            None
        } else {
            Some(Self(trimmed.to_string()))
        }
    }

    /// Retorna el valor en formato `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identificador de buzón de destino en un relay (REQ-SYNC-006).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MailboxId(String);

impl MailboxId {
    /// Crea un nuevo identificador de buzón validado.
    ///
    /// # Errores
    /// Retorna `None` si la cadena está vacía o excede 128 caracteres.
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let s = id.into();
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            None
        } else {
            Some(Self(trimmed.to_string()))
        }
    }

    /// Retorna el valor en formato `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Estado del ciclo de vida de una operación en la cola de sincronización.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationStatus {
    /// En espera de ser despachada al relay.
    Pending,
    /// En tránsito: enviada al relay pero pendiente de acuse de recibo.
    InFlight,
    /// Entregada satisfactoriamente y confirmada.
    Delivered,
    /// Fallo definitivo tras agotar los reintentos permitidos.
    FailedPermanent,
}

/// Módulo de serialización y deserialización para `UnixTime`.
pub mod unix_time_serde {
    use gravital_id_types::UnixTime;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializa un `UnixTime` como entero `u64` en segundos Unix.
    pub fn serialize<S>(time: &UnixTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(time.as_seconds())
    }

    /// Deserializa un `UnixTime` a partir de un entero `u64` en segundos Unix.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<UnixTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(UnixTime::from_seconds(secs))
    }
}

/// Operación de sincronización saliente pendiente o en curso (REQ-SYNC-001, REQ-SYNC-006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOperation {
    /// Clave de idempotencia única.
    pub id: OperationId,
    /// Buzón de destino en el relay.
    pub target_mailbox: MailboxId,
    /// Carga cifrada opaca (HPKE ciphertext `enc || ciphertext`).
    pub payload_ciphertext: Vec<u8>,
    /// Instante de creación.
    #[serde(with = "unix_time_serde")]
    pub created_at: UnixTime,
    /// Número de reintentos ejecutados.
    pub retry_count: u32,
    /// Instante del próximo intento permitido según la política de backoff.
    #[serde(with = "unix_time_serde")]
    pub next_attempt: UnixTime,
    /// Estado actual de la operación.
    pub status: OperationStatus,
    /// TTL opcional en segundos para el relay.
    pub ttl_secs: Option<u64>,
}

impl SyncOperation {
    /// Crea una nueva operación en estado `Pending`.
    #[must_use]
    pub fn new(
        id: OperationId,
        target_mailbox: MailboxId,
        payload_ciphertext: Vec<u8>,
        now: UnixTime,
        ttl_secs: Option<u64>,
    ) -> Self {
        Self {
            id,
            target_mailbox,
            payload_ciphertext,
            created_at: now,
            retry_count: 0,
            next_attempt: now,
            status: OperationStatus::Pending,
            ttl_secs,
        }
    }
}

/// Sobre de operación entrante recibido desde un buzón de relay (REQ-SYNC-006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEnvelope {
    /// Identificador único del sobre (clave de idempotencia en origen).
    pub envelope_id: String,
    /// Carga cifrada (HPKE ciphertext).
    pub payload: Vec<u8>,
    /// Timestamp Unix de creación en el relay.
    #[serde(with = "unix_time_serde")]
    pub created_at: UnixTime,
    /// Timestamp Unix de caducidad en el relay.
    #[serde(with = "unix_time_serde")]
    pub expires_at: UnixTime,
}

/// Mensaje entrante procesado y descifrado entregado a la aplicación titular.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredMessage {
    /// Identificador del sobre de origen.
    pub envelope_id: String,
    /// Buzón desde el cual se recibió.
    pub mailbox_id: MailboxId,
    /// Carga en texto claro tras verificar HPKE y autenticación.
    pub plaintext_payload: Vec<u8>,
    /// Instante de recepción y entrega.
    pub received_at: UnixTime,
}
