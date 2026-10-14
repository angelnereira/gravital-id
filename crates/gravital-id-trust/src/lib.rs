//! # `gravital-id-trust`
//!
//! Raíz de confianza, trust bundle multi-firma y políticas de verificación para Gravital ID.
//!
//! - **Capa arquitectónica:** L2
//! - **Garantía no_std:** Sí
//!
//! Trazabilidad:
//! - **REQ-TRUST-001:** bundle cofirmado por umbral k-de-n de firmantes distintos, con
//!   versión monotónica y ventana de validez.
//! - **REQ-TRUST-002:** rechazo de `(bundle_epoch, bundle_version)` inferior al aceptado.
//! - **REQ-TRUST-009:** cadena de raíces con doble umbral y `bundle_epoch` incremental
//!   para recuperarse de un avance forzado.
//! - **REQ-TRUST-010:** el bundle no contiene punteros ni hashes de listas de estado.
//! - **REQ-KEY-005 / REQ-KEY-006:** estados de clave de emisor y vigencia de credenciales
//!   emitidas antes del retiro.
//! - **INV-16:** ninguna clave única decide la confianza offline.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use gravital_id_codec::json::Value;
use gravital_id_crypto::JwkEcP256;

pub mod bundle;
pub mod jws_json;
pub mod root;

pub use bundle::{
    AcceptedBundleState, IssuerEntry, IssuerKey, IssuerState, KeyState, PolicyEntry, StatusKey,
    TrustBundle, TrustBundleVerifier, VerifierEntry, MAX_BUNDLE_BYTES, MAX_ISSUERS_PER_BUNDLE,
    MAX_KEYS_PER_ISSUER,
};
pub use jws_json::{JwsJsonParser, JwsSignature, MultiSignedJws, JWS_ALG};
pub use root::{
    BundleSigner, RootKey, TrustRoot, TrustRootVerifier, MAX_FRAMEWORK_ID_BYTES,
    MAX_REGISTRY_ADDRESS_BYTES, MAX_ROOT_KEYS,
};

/// Serializa un valor JSON de forma canónica (RFC 8785).
pub use gravital_id_credential::to_canonical_json;

/// Convierte una clave pública en su valor JSON (uso interno de pruebas y fixtures).
#[doc(hidden)]
pub fn json_value_of(jwk: &JwkEcP256) -> Value {
    let json = jwk.to_canonical_json();
    gravital_id_codec::json::parse(json.as_str()).unwrap_or(Value::Null)
}

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
