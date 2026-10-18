//! Microservicio de confianza, derivación determinista de bundles y cofirma multi-operador (F7.T04).
//!
//! Trazabilidad:
//! - **REQ-TRUST-001:** Cofirma multi-operador con umbral k-de-n.
//! - **REQ-TRUST-003:** Derivación acotada exclusivamente a bloques finalizados.
//! - **REQ-TRUST-005:** Raíz de confianza fija y firmantes registrados.
//! - **REQ-TRUST-008:** Derivación determinista idéntica byte a byte.
//! - **INV-01:** Verificación posterior sans-I/O sin red.
//! - **INV-02:** Cero datos personales.
//! - **INV-05:** Fail-closed si no se alcanza el quórum.
//! - **INV-16:** Sin firmante único; umbral k-de-n inviolable.

#![forbid(unsafe_code)]

pub mod aggregator;
pub mod config;
pub mod engine;
pub mod error;
pub mod health;
pub mod operator;
pub mod publisher;
pub mod signer;
