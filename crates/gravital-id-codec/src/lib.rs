//! # `gravital-id-codec`
//!
//! Codificación y serialización acotada (base64url, JSON, CBOR, Base45) para Gravital ID.
//!
//! - **Capa arquitectónica:** L1
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod base64url;

pub use base64url::{decode, decode_bounded, encode, MAX_INPUT_LEN};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
