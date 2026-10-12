//! # `gravital-id-sdk`
//!
//! Fachada y API pública del SDK de Gravital ID.
//!
//! - **Capa arquitectónica:** L6
//! - **Garantía no_std:** No
//!
//! ## Estado en F1 (F1.T13)
//!
//! Fachada mínima: expone los contratos de host (`Clock`, `Rng`) y el catálogo
//! canónico de errores (`GidError`/`PipError`), de modo que la forma de la API
//! se valida contra FFI desde la primera fase. Las features `verifier`,
//! `holder`, `issuer`, `sync` y `full-verification` se añaden en F9.T01
//! (`ROADMAP.md §14`, `SDK_API.md`).

#![forbid(unsafe_code)]

pub use gravital_id_crypto::Rng;
pub use gravital_id_types::{Clock, ErrorCode, GidError, PipError};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;

    // // Verifies: REQ-SDK-001 (la fachada re-exporta el catálogo canónico)
    #[test]
    fn facade_reexports_canonical_error_catalog() {
        let err = GidError::new(ErrorCode::NonceReused, "Session nonce was reused");
        assert_eq!(err.code_str(), "GID-E1003");
        assert_eq!(err.code.legacy_code_str(), "PIP-E1003");
    }

    // // Verifies: REQ-SDK-001 (el trait Clock está disponible para el host)
    #[test]
    fn facade_exposes_clock_trait_for_hosts() {
        struct HostClock;
        impl Clock for HostClock {
            fn now_seconds(&self) -> u64 {
                1_700_000_000
            }
            fn monotonic_elapsed_millis(&self) -> Option<u64> {
                None
            }
        }
        let clock: &dyn Clock = &HostClock;
        assert_eq!(clock.now_seconds(), 1_700_000_000);
    }
}
