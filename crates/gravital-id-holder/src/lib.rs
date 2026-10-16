//! # `gravital-id-holder`
//!
//! Gestión de credenciales del titular y preparación de presentaciones offline para Gravital ID.
//!
//! - **Capa arquitectónica:** L3
//! - **Garantía no_std:** Sí (`#![no_std]` + `alloc`)
//!
//! Trazabilidad:
//! - **REQ-STOR-006:** Auditoría local apendible sin PII y con retención configurable.
//! - **REQ-KEY-008:** Asociación segura de credenciales con la clave del titular (`KeyHandle`).
//! - **REQ-PRIV-005:** Cero persistencia del contenido de presentaciones enviadas ni nonces del verificador.
//! - **REQ-PRES-001:** Selección y consentimiento explícito de atributos por el titular antes de presentar.
//! - **REQ-PRES-003:** Solicitudes de presentación basadas en un subconjunto de DCQL.
//! - **REQ-PRIV-001:** Divulgación selectiva compartiendo únicamente los atributos necesarios.
//! - **INV-01:** Cero llamadas de red en L1–L4 (L3 es estrictamente no_std).
//! - **INV-02:** Ningún dato personal en logs ni almacenamiento en claro.
//! - **INV-03:** Claves privadas del titular permanecen en el hardware/KeyStore seguro.
//! - **INV-05:** Fail-closed ante cualquier inconsistencia o error.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod audit;
pub mod credential;
pub mod plan;
pub mod presentation;
pub mod query;
pub mod wallet;

pub use audit::{AuditEventType, WalletAuditEvent};
pub use credential::{
    CredentialId, WalletCredential, WalletCredentialSummary, MAX_CREDENTIAL_ID_LEN,
};
pub use plan::{DisclosurePlan, PlannedClaim};
pub use presentation::PresentationBuilder;
pub use query::{
    CredentialQuery, DcqlQuery, RequestedClaim, MAX_CLAIMS_PER_QUERY, MAX_CREDENTIAL_QUERIES,
    MAX_QUERY_ID_LEN, MAX_VCT_VALUES_PER_QUERY,
};
pub use wallet::HolderWallet;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
