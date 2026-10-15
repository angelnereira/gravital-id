//! # `gravital-id-status`
//!
//! Verificación e interpretación de Token Status List para Gravital ID.
//!
//! - **Capa arquitectónica:** L2
//! - **Garantía no_std:** Sí
//!
//! Trazabilidad:
//! - **REQ-STAT-001:** Token Status List en formato JWT (versión fijada en
//!   `CRYPTO_PROFILES.md`).
//! - **REQ-STAT-003:** Descompresión acotada (2 MiB de salida, ratio 10:1).
//! - **REQ-STAT-007:** Estados válido, revocado y suspendido (1 y 2 bits por entrada).
//! - **REQ-STAT-008:** Manifiesto de estado por emisor con versión monotónica (ADR-0017).
//! - **REQ-STAT-004:** Frescura por perfil y clase de operación, calculada con el `Clock`
//!   inyectado.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod cache;
pub mod manifest;
pub mod status_list;

pub use cache::{FreshnessPolicy, StatusCache, StatusSnapshot, DEFAULT_MAX_CACHED_LISTS};
pub use manifest::{
    IssuerStatusManifest, ManifestListEntry, StatusManifestVerifier, DEFAULT_MANIFEST_MAX_BYTES,
};
pub use status_list::{
    StatusListVerifier, TokenStatus, TokenStatusList, MAX_DECOMPRESSED_BYTES, MAX_EXPANSION_RATIO,
    STATUS_LIST_ALG, STATUS_LIST_TYP, SUPPORTED_BITS_PER_ENTRY,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
