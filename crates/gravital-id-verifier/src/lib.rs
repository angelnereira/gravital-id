//! # `gravital-id-verifier`
//!
//! Pipeline de verificación offline con typestate para Gravital ID.
//!
//! - **Capa arquitectónica:** L3
//! - **Garantía no_std:** Sí
//!
//! Trazabilidad:
//! - **REQ-VER-006:** piso de tiempo confiable y detección de retroceso de reloj.
//! - **REQ-VER-011:** estado del verificador tras `VerifierStateStore`; si falta o no es
//!   íntegro, el resultado es `Unverifiable`.
//! - **REQ-PRES-004:** caché de nonces con expiración.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod state;

pub use state::{
    InMemoryStateStore, RememberedNonce, StateIntegrityKey, TimeFloorCheck, TimeFloorGuard,
    VerifierStateStore, DEFAULT_MAX_NONCES,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
