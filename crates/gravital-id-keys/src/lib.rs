//! # `gravital-id-keys`
//!
//! Gestión y traits de claves, propósitos de clave y normalización de firmas para Gravital ID.
//!
//! - **Capa arquitectónica:** L1
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
