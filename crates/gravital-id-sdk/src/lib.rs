//! # `gravital-id-sdk`
//!
//! Fachada y API pública del SDK de Gravital ID.
//!
//! - **Capa arquitectónica:** L6
//! - **Garantía no_std:** No

#![forbid(unsafe_code)]

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
