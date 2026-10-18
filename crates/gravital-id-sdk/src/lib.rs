//! # `gravital-id-sdk`
//!
//! Fachada y API pública del SDK de Gravital ID (`SPEC-PIP-SDK-001`).
//!
//! - **Capa arquitectónica:** L6 (no `no_std`).
//! - **Garantía:** cero I/O en L1–L4; el I/O vive en adaptadores L5 y en el host.
//!
//! Esta fachada expone los objetos normativos del SDK (`TrustStore`, `Verifier`,
//! `Wallet`, `Issuer`) junto con los contratos del host (`KeyStore`, `Clock`,
//! `StorageBackend`, `VerifierStateStore`, `Transport`, `Rng`) y el catálogo
//! canónico de errores. Las features `verifier`, `holder`, `issuer` y `sync`
//! permiten compilar subconjuntos para plataformas con presupuesto reducido
//! (F9.T01, `ROADMAP.md §14`).

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;

use gravital_id_codec::base64url;
use gravital_id_verifier::policy::OperationClass;
use gravital_id_verifier::policy::VerificationPolicy;

// --- Re-exportaciones del catálogo canónico y de los contratos del host ---

pub use gravital_id_crypto::Rng;
pub use gravital_id_keys::KeyStore;
pub use gravital_id_storage::StorageBackend;
pub use gravital_id_sync::Transport;
pub use gravital_id_types::{Clock, ErrorCode, GidError, PipError};
pub use gravital_id_verifier::VerifierStateStore;

// --- Resultado de verificación (INV-04) ---

pub use gravital_id_verifier::VerificationResult;
pub use gravital_id_verifier::VerificationStatus;

// --- Objetos del SDK (F9.T01) ---

use gravital_id_trust::bundle::TrustBundle;
use gravital_id_trust::root::TrustRoot;
use gravital_id_verifier::pipeline::VerifierPipeline;
pub use gravital_id_verifier::result::CheckEvidence;

/// Almacén de confianza del host: gestiona la raíz activa y el bundle multi-firma.
///
/// Equivalente normativo a `TrustStore` de `SDK_API.md §2.1`.
#[derive(Debug, Default)]
pub struct TrustStore {
    root: Option<TrustRoot>,
    bundle: Option<TrustBundle>,
}

impl TrustStore {
    /// Crea un almacén de confianza vacío.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Importa y valida (parseo) una raíz de confianza multi-firma.
    pub fn import_root(&mut self, root_jws: &str) -> Result<TrustRoot, PipError> {
        let (root, _jws) = TrustRoot::parse(root_jws)?;
        self.root = Some(root.clone());
        Ok(root)
    }

    /// Importa y valida (parseo) un bundle multi-firma.
    pub fn import_bundle(&mut self, bundle_jws: &str) -> Result<TrustBundle, PipError> {
        let (bundle, _jws) = TrustBundle::parse(bundle_jws)?;
        self.bundle = Some(bundle.clone());
        Ok(bundle)
    }

    /// Raíz de confianza activa, si la hay.
    #[must_use]
    pub fn active_root(&self) -> Option<&TrustRoot> {
        self.root.as_ref()
    }

    /// Bundle multi-firma activo, si lo hay.
    #[must_use]
    pub fn active_bundle(&self) -> Option<&TrustBundle> {
        self.bundle.as_ref()
    }
}

/// Motor de verificación desconectada (*sans-I/O*) del integrador.
///
/// Equivalente normativo a `Verifier` de `SDK_API.md §2.2`. Requiere la feature
/// `verifier` (activa por defecto).
#[cfg(feature = "verifier")]
pub struct Verifier {
    audience: String,
    policy: VerificationPolicy,
}

#[cfg(feature = "verifier")]
impl Verifier {
    /// Crea un verificador para la audiencia y la política indicadas.
    #[must_use]
    pub fn new(audience: impl Into<String>, policy: VerificationPolicy) -> Self {
        Self {
            audience: audience.into(),
            policy,
        }
    }

    /// Genera una solicitud de verificación con un nonce fresco de 128 bits.
    pub fn create_request<R: gravital_id_crypto::Rng>(
        &self,
        rng: &R,
        operation_class: OperationClass,
        expires_at: gravital_id_types::UnixTime,
    ) -> Result<gravital_id_verifier::VerificationRequest, PipError> {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf)?;
        // Codificación URL-safe sin relleno (base64url RFC 4648 §5).
        let nonce = base64url::encode(&buf);
        Ok(gravital_id_verifier::VerificationRequest::new(
            nonce,
            self.audience.clone(),
            expires_at,
            operation_class,
        ))
    }

    /// Verifica una presentación compacta contra el estado local sin red.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_presentation(
        &self,
        presentation_compact: &str,
        expected_request: Option<&gravital_id_verifier::VerificationRequest>,
        trust_bundle: &TrustBundle,
        status_snapshot: Option<&gravital_id_status::cache::StatusSnapshot>,
        state_store: &mut impl VerifierStateStore,
        now: gravital_id_types::UnixTime,
        monotonic_elapsed_millis: Option<u64>,
    ) -> gravital_id_verifier::VerificationResult {
        VerifierPipeline::verify(
            presentation_compact,
            expected_request,
            trust_bundle,
            status_snapshot,
            state_store,
            &self.policy,
            now,
            monotonic_elapsed_millis,
        )
    }

    /// Audiencia configurada para este verificador.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// Alias ergonómico a la wallet del titular (`gravital-id-holder`).
///
/// Equivalente normativo a `Wallet` de `SDK_API.md §2.3`. Requiere la feature
/// `holder` (activa por defecto). Expone todos los métodos de `HolderWallet`.
#[cfg(feature = "holder")]
pub type Wallet<B, R> = gravital_id_holder::HolderWallet<B, R>;

/// Emisor de credenciales SD-JWT VC (sin estado).
///
/// Equivalente normativo a `Issuer` de `SDK_API.md §2`. Requiere la feature
/// `issuer` (activa por defecto). Delega en `gravital-id-issuer::Issuer`.
#[cfg(feature = "issuer")]
pub use gravital_id_issuer::Issuer;

/// Versión semántica del SDK en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    // Verifies: REQ-SDK-001 (la fachada expone el catálogo canónico)
    #[test]
    fn facade_reexports_canonical_error_catalog() {
        let err = gravital_id_types::GidError::new(
            gravital_id_types::ErrorCode::NonceReused,
            "Session nonce was reused",
        );
        assert_eq!(err.code_str(), "GID-E1003");
        assert_eq!(err.code.legacy_code_str(), "PIP-E1003");
    }

    // Verifies: REQ-SDK-001 (el trait Clock está disponible para el host)
    #[test]
    fn facade_exposes_clock_trait_for_hosts() {
        struct HostClock;
        impl gravital_id_types::Clock for HostClock {
            fn now_seconds(&self) -> u64 {
                1_700_000_000
            }
            fn monotonic_elapsed_millis(&self) -> Option<u64> {
                None
            }
        }
        let clock: &dyn gravital_id_types::Clock = &HostClock;
        assert_eq!(clock.now_seconds(), 1_700_000_000);
    }

    // Verifies: REQ-SDK-001 (TrustStore se puede instanciar y está vacío)
    #[test]
    fn trust_store_starts_empty() {
        let ts = TrustStore::new();
        assert!(ts.active_root().is_none());
        assert!(ts.active_bundle().is_none());
    }

    // Verifies: REQ-SDK-003 (PipError cruza como tipo público)
    #[test]
    fn pip_error_is_public() {
        let e =
            gravital_id_types::PipError::new(gravital_id_types::ErrorCode::MalformedMessage, "bad");
        assert_eq!(e.code, gravital_id_types::ErrorCode::MalformedMessage);
    }

    #[cfg(feature = "verifier")]
    mod verifier_tests {
        use super::*;
        struct TestRng;
        impl gravital_id_crypto::Rng for TestRng {
            fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), gravital_id_types::GidError> {
                for (i, b) in dest.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_add(1);
                }
                Ok(())
            }
        }

        // Verifies: REQ-VER-001 (el verificador se construye y genera nonce de 128 bits)
        #[test]
        fn verifier_creates_request_with_nonce() {
            let rng = TestRng;
            let policy = VerificationPolicy::default();
            let v = Verifier::new("https://verifier.example", policy);
            let req = v
                .create_request(
                    &rng,
                    OperationClass::Default,
                    gravital_id_types::UnixTime::from_seconds(1_700_000_100),
                )
                .expect("create_request");
            // 16 bytes => 22 chars en base64url sin relleno
            assert_eq!(req.nonce.len(), 22);
            assert_eq!(req.audience, "https://verifier.example");
        }
    }
}

// Silencia imports no usados cuando las features desactivan módulos.
#[allow(unused_imports)]
use gravital_id_status::cache::StatusSnapshot as _SS;
