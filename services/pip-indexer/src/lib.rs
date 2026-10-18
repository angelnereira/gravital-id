//! `pip-indexer` — Servicio indexador de eventos del ledger y mantenimiento de proyecciones (F7.T03, REQ-LEDG-005).
//!
//! Trazabilidad:
//! - **REQ-LEDG-005:** El indexador DEBE consumir solo bloques finalizados y tolerar reorganizaciones.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC con failover y verificación de consistencia.
//! - **REQ-OBS-001:** Instrumentación con OpenTelemetry.
//! - **REQ-PRIV-003 / INV-02:** Cero datos personales ni secretos en base de datos o logs.
//! - **INV-09:** Prohibido código inseguro (`unsafe`).
//! - **INV-10:** Sin panics, unwraps ni indexación que pueda fallar.

#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod divergence;
pub mod engine;
pub mod error;
pub mod health;
pub mod metrics;
pub mod postgres;
pub mod storage;
