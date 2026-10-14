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
//! - **REQ-VER-005 / REQ-VER-007:** política de verificación configurable por el
//!   integrador; el núcleo no decide la aceptación.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod policy;
pub mod state;

pub use policy::{
    IssuerSelection, OperationClass, StatusFreshness, VctSelection, VerificationPolicy,
    MAX_CLOCK_SKEW_SECONDS,
};
pub use state::{
    InMemoryStateStore, RememberedNonce, StateIntegrityKey, TimeFloorCheck, TimeFloorGuard,
    VerifierStateStore, DEFAULT_MAX_NONCES,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
