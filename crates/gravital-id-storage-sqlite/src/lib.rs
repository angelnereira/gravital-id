//! # `gravital-id-storage-sqlite`
//!
//! Adaptador de almacenamiento persistente SQLite para Gravital ID.
//!
//! - **Capa arquitectónica:** L5
//! - **Garantía no_std:** No

#![forbid(unsafe_code)]

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
