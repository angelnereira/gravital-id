//! # `gravital-id-sync`
//!
//! Máquina de sincronización de operaciones sans-I/O para Gravital ID (F7.T07).
//!
//! Implementa:
//! - **REQ-SYNC-001:** Cola de salida cifrada con claves de idempotencia.
//! - **REQ-SYNC-002:** Entrega al-menos-una-vez con deduplicación en el destinatario.
//! - **REQ-SYNC-003:** Backoff exponencial con jitter.
//! - **REQ-SYNC-004:** Verificación estricta de hash de todo contenido recibido.
//! - **REQ-SYNC-005:** Descargas públicas anónimas sin identificadores.
//! - **REQ-SYNC-006:** Sobres cifrados con HPKE (RFC 9180).
//! - **REQ-SYNC-007:** Pool de relays con failover automático.
//!
//! Reglas arquitectónicas:
//! - **Capa arquitectónica:** L4 (sans-I/O estricto)
//! - **Invariantes:** INV-01, INV-02, INV-05, INV-07, INV-11.

#![forbid(unsafe_code)]

pub mod backoff;
pub mod dedup;
pub mod engine;
pub mod error;
pub mod hpke_envelope;
pub mod model;
pub mod queue;
pub mod relay_pool;
pub mod transport;
pub mod verifier;

// Re-exportaciones ergonómicas
pub use backoff::RetryPolicy;
pub use dedup::InboundDeduplicationFilter;
pub use engine::{OutboxStepResult, SyncEngine};
pub use error::SyncError;
pub use hpke_envelope::HpkeEnvelope;
pub use model::{
    DeliveredMessage, MailboxId, OperationId, OperationStatus, SyncEnvelope, SyncOperation,
};
pub use queue::EncryptedOutboxQueue;
pub use relay_pool::{RelayEndpoint, RelayPool};
pub use transport::{MockTransport, Transport};
pub use verifier::ContentVerifier;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
