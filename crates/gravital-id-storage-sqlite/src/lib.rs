//! # `gravital-id-storage-sqlite`
//!
//! Adaptador de almacenamiento persistente SQLite para Gravital ID.
//!
//! - **Capa arquitectónica:** L5
//! - **Garantía no_std:** No
//!
//! Trazabilidad:
//! - `REQ-STOR-004`: Atomicidad transaccional y WAL mode.
//! - `REQ-STOR-005`: Versionado y migraciones de esquema probadas con fixtures.
//! - `REQ-STOR-008`: Backend intercambiable (`StorageBackend`).
//! - `REQ-VER-006`, `REQ-VER-011`: `VerifierStateStore` persistente.
//! - `STORAGE_FORMAT.md §4, §5, §6`: Estructura de tablas, índices ciegos y ciclo de migración.
//! - `INV-01`: Cero llamadas a red durante la verificación.
//! - `INV-02`: Ausencia absoluta de datos personales o secretos en disco o logs.

#![forbid(unsafe_code)]

pub mod error;
pub mod migration;
pub mod storage;
pub mod verifier_state;

pub use migration::{
    apply_migrations, get_current_version, Migration, LATEST_SCHEMA_VERSION, MIGRATIONS,
};
pub use storage::{SqliteStorage, SqliteStorageConfig};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
