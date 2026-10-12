//! # `gravital-id-testkit`
//!
//! Utilidades de prueba, relojes fijos y datos deterministas para Gravital ID.
//!
//! - **Capa arquitectónica:** Dev
//! - **Garantía no_std:** No

#![forbid(unsafe_code)]

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
