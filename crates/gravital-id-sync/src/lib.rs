//! # `gravital-id-sync`
//!
//! Máquina de sincronización de operaciones sans-I/O para Gravital ID.
//!
//! - **Capa arquitectónica:** L4
//! - **Garantía no_std:** No

#![forbid(unsafe_code)]

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
