//! # `gravital-id-protocol`
//!
//! Máquinas de estado de protocolo (OID4VCI, OID4VP, QR offline) sans-I/O para Gravital ID.
//!
//! - **Capa arquitectónica:** L4
//! - **Garantía no_std:** No

#![forbid(unsafe_code)]

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
