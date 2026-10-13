//! # `gravital-id-types`
//!
//! Identificadores validados, marcas de tiempo y tipos fundamentales del protocolo Gravital ID.
//!
//! - **Capa arquitectónica:** L1
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod clock;
pub mod error;

pub use clock::Clock;
pub use error::{ErrorCode, GidError, PipError};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
