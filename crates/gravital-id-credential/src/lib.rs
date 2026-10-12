//! # `gravital-id-credential`
//!
//! Emisión, validación y verificación de credenciales SD-JWT y SD-JWT VC para Gravital ID.
//!
//! - **Capa arquitectónica:** L2
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
