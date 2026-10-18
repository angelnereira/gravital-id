//! Biblioteca del microservicio `pip-relay` para Gravital ID (F7.T06).
//!
//! Trazabilidad:
//! - **REQ-SYNC-004:** Retransmisión y descarga de objetos por digest SHA-256.
//! - **REQ-SYNC-006:** Buzón de sobres de operación cifrados con HPKE.
//! - **REQ-CODE-001..004:** Punto de encuentro para código numérico de sesión (`SessionCode`).
//! - **REQ-REL-001 / REQ-OBS-001:** Telemetría estructurada, observabilidad y apagado limpio.
//! - **INV-01:** Lógica de almacenamiento y enrutamiento sans-I/O en la biblioteca.
//! - **INV-02:** Cero datos personales o payloads registrados en logs.
//! - **INV-11:** Inyección de reloj [`Clock`] para determinismo estricto.

pub mod clock;
pub mod config;
pub mod error;
pub mod health;
pub mod limiter;
pub mod server;
pub mod store;

pub use clock::SystemClock;
pub use config::RelayConfig;
pub use error::RelayError;
pub use health::RelayHealthCheck;
pub use limiter::RateLimiter;
pub use server::{start_relay_server, RelayHttpService};
pub use store::{
    compute_damm_check_digit, compute_session_hash_hex, validate_session_code, EnvelopeRecord,
    InMemoryRelayStore, ObjectRecord, RendezvousSession,
};
