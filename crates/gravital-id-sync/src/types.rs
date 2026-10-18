//! Tipos de datos para operaciones, sobres cifrados y estado de sincronización (F7.T07).

use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};

/// Estado del ciclo de vida de una operación en la cola de sincronización.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationStatus {
    /// Pendiente de primer intento o en espera del próximo backoff.
    Pending,
    /// En proceso de transmisión activa hacia el relay.
    InFlight,
    /// Entregada satisfactoriamente y confirmada por el relay o destinatario.
    Delivered,
    /// Ha agotado el número máximo de reintentos permitidos sin éxito.
    Failed,
}

/// Operación pendiente almacenada en la cola de sincronización (REQ-SYNC-001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOperation {
    /// Identificador único y clave de idempotencia (`REQ-SYNC-001`).
    pub id: String,
    /// Identificador opaco del buzón de destino en el relay.
    pub destination_inbox: String,
    /// Clave pública P-256 SEC1 (65 bytes) del destinatario para cifrado HPKE (`REQ-SYNC-006`).
    pub recipient_public_key: Vec<u8>,
    /// Carga útil en claro de la operación a transmitir.
    pub plaintext_payload: Vec<u8>,
    /// Instante Unix de creación de la operación.
    pub created_at: UnixTime,
    /// Número de intentos de transmisión realizados.
    pub retry_count: u32,
    /// Próximo instante Unix programado para reintento (computado con backoff exponencial).
    pub next_retry_at: UnixTime,
    /// Estado actual de la operación.
    pub status: OperationStatus,
}

impl SyncOperation {
    /// Construye una nueva operación lista para ser encolada.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        destination_inbox: impl Into<String>,
        recipient_public_key: Vec<u8>,
        plaintext_payload: Vec<u8>,
        created_at: UnixTime,
    ) -> Self {
        Self {
            id: id.into(),
            destination_inbox: destination_inbox.into(),
            recipient_public_key,
            plaintext_payload,
            created_at,
            retry_count: 0,
            next_retry_at: created_at,
            status: OperationStatus::Pending,
        }
    }
}

/// Sobre de operación cifrado para transmisión por el relay (REQ-SYNC-006).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Clave de idempotencia única del sobre (`REQ-SYNC-001`).
    pub envelope_id: String,
    /// Carga cifrada opaca con HPKE RFC 9180 (`REQ-SYNC-006`).
    pub payload: Vec<u8>,
    /// Instante de creación del sobre.
    pub created_at: UnixTime,
}

/// Acuse de entrega emitido tras el envío de una operación.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// Identificador de la operación entregada.
    pub operation_id: String,
    /// Instante de confirmación de entrega.
    pub delivered_at: UnixTime,
    /// URL del relay que procesó la entrega.
    pub relay_url: String,
    /// Indica si el sobre ya existía en el relay (acuse de duplicado idempotente).
    pub duplicate: bool,
}

/// Operación entrante descifrada y deduplicada recibida desde un buzón de relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundOperation {
    /// Identificador único del sobre recibido.
    pub envelope_id: String,
    /// Carga útil descifrada y autenticada con HPKE.
    pub decrypted_payload: Vec<u8>,
    /// Instante en que se procesó el sobre.
    pub received_at: UnixTime,
}
