//! # `gravital-id-crypto`
//!
//! Abstracciones y backend criptográfico (ES256, SHA-256, HMAC, XChaCha20-Poly1305, HPKE) para Gravital ID.
//!
//! - **Capa arquitectónica:** L1
//! - **Garantía no_std:** Sí

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
