//! # `gravital-id-holder`
//!
//! Gestión de credenciales del titular y preparación de presentaciones para Gravital ID.
//!
//! - **Capa arquitectónica:** L3
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
