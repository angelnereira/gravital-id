//! # `gravital-id-ledger-evm`
//!
//! Adaptador de ledger para redes EVM para Gravital ID (F6.T09, F6.T10).
//!
//! Este crate implementa la integración concreta de capa L5 con redes compatibles
//! con Ethereum Virtual Machine (EVM, EIP-155), abstrayendo la conexión RPC y el
//! procesamiento de eventos emitidos por `TrustRegistry.sol` y `StatusAnchor.sol`.
//!
//! - **Capa arquitectónica:** L5 (Adaptadores de plataforma y red)
//! - **Garantía no_std:** No (requiere `std` para transporte, mutex y atomicidad)
//!
//! ## Trazabilidad
//! - **REQ-LEDG-002:** Abstracción del ledger con `LedgerAdapter`.
//! - **REQ-LEDG-005:** Consumo acotado a bloques finalizados y tolerancia a reorganizaciones.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC con failover y verificación de consistencia.
//! - **INV-01:** Pruebas deterministas sans-I/O mediante `MockRpcTransport`.
//! - **INV-02 / REQ-LEDG-001:** Cero datos personales en parámetros y eventos del ledger.

#![forbid(unsafe_code)]

pub mod abi;
pub mod adapter;
pub mod client;
pub mod error;
pub mod transport;

pub use adapter::{EvmContractAddresses, EvmLedgerAdapter};
pub use client::{hex_encode, MultiRpcClient, MultiRpcConfig, RawEvmLog};
pub use error::{EvmLedgerError, EvmLedgerResult};
pub use transport::{FnRpcTransport, MockRpcTransport, RecordedRpcCall, RpcTransport};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
