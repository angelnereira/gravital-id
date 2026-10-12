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
pub mod ids;

pub use clock::Clock;
pub use error::{ErrorCode, GidError, PipError};
pub use ids::{BundleVersion, IssuerId, Kid, ProfileId, UnixTime, Vct, MAX_ID_LEN, MAX_VCT_LEN};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
