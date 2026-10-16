//! # `gravital-id-storage`
//!
//! Traits de almacenamiento, cifrado de sobre e índices ciegos para Gravital ID.
//!
//! - **Capa arquitectónica:** L3
//! - **Garantía no_std:** Sí
//!
//! Trazabilidad:
//! - `REQ-STOR-001`: Cifrado de sobre (DEK/KEK) con AEAD y datos asociados (AAD).
//! - `REQ-STOR-002`: Clave KEK provista por el almacén seguro de hardware.
//! - `REQ-STOR-003`: Consultas mediante índices ciegos sin metadatos en claro (`P-09`).
//! - `REQ-STOR-004`: Atomicidad y consistencia ante fallos en transacciones.
//! - `REQ-STOR-008`: Backend intercambiable (`StorageBackend`).
//! - `STORAGE_FORMAT.md`: Formato binario de registros cifrados y jerarquía de claves.
//! - `INV-01`: Cero llamadas a red o dependencias de I/O bloqueante.
//! - `INV-02`: Ausencia absoluta de datos personales o metadatos en claro en disco.
//! - `INV-03`: Claves del titular y secretos protegidos en memoria con `SecretBytes`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod backend;
pub mod blind_index;
pub mod envelope;
pub mod record;

pub use backend::{InMemoryStorageBackend, StorageBackend, StorageBatch, StorageOp, StoredRecord};
pub use blind_index::{BlindIndex, BlindIndexer};
pub use envelope::{
    compute_record_id_hash, derive_bik, derive_dek, EnvelopeEncryption, KekProvider,
    StaticKekProvider, KDF_INFO_BIK, KDF_INFO_DEK_PREFIX,
};
pub use record::{
    compute_aad, CipherSuite, CollectionName, EncryptedRecord, RecordId, AAD_PREFIX,
    RECORD_HEADER_LEN, RECORD_MIN_LEN, SCHEMA_VERSION_V1, STORAGE_MAGIC,
};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
