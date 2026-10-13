//! # `gravital-id-status`
//!
//! Verificación e interpretación de Token Status List para Gravital ID.
//!
//! - **Capa arquitectónica:** L2
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
