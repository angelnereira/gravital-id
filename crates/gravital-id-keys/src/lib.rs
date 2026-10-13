//! # `gravital-id-keys`
//!
//! Gestión y traits de claves, propósitos de clave y normalización de firmas para Gravital ID.
//!
//! - **Capa arquitectónica:** L1
//! - **Garantía no_std:** Sí (`#![no_std]` + `alloc`)
//!
//! Trazabilidad:
//! - **REQ-KEY-001:** Separación por `KeyPurpose` y tipado estricto con `KeyHandle<P>`.
//! - **REQ-KEY-004:** Trait `KeyStore` e implementación `SoftwareKeyStore`.
//! - **REQ-KEY-007:** Thumbprints RFC 7638 como identificadores de clave.
//! - **REQ-KEY-009:** Claves HPKE con propósito propio separado de firma.
//! - **REQ-KEY-010:** Normalización de firmas DER ↔ IEEE P1363.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod keystore;
pub mod purpose;
pub mod signature;

#[cfg(feature = "software-keystore")]
pub mod software;

pub use keystore::KeyStore;
pub use purpose::{
    HolderBinding, HolderRecovery, HpkeKeyAgreement, IssuerSigning, KeyAgreementPurpose, KeyHandle,
    KeyPurpose, KeyPurposeMarker, SigningPurpose, StatusListSigning, TrustBundle, TrustRoot,
    VerifierRequest,
};
pub use signature::{normalize_signature_to_p1363, signature_to_der};

#[cfg(feature = "software-keystore")]
pub use software::SoftwareKeyStore;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
