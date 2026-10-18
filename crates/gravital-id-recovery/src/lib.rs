//! # `gravital-id-recovery`
//!
//! Protocolos de respaldo, código de recuperación y migración para Gravital ID.
//!
//! - **Capa arquitectónica:** L3
//! - **Garantía no_std:** Sí (`#![no_std]` + `alloc`)
//!
//! Trazabilidad:
//! - **REQ-REC-002:** El respaldo cifrado DEBE protegerse con un código de recuperación generado de ≥ 128 bits.
//! - **REQ-REC-004:** La clave de recuperación DEBE tener propósito exclusivo (`HolderRecovery`).
//! - **REQ-REC-007:** Las claves de recuperación DEBEN derivarse por emisor; la misma huella NO DEBE registrarse ante dos emisores.
//! - **REQ-STOR-001:** Cifrado de sobre con AEAD y AAD ligado.
//! - **INV-01:** Cero llamadas de red en L1–L4 (L3 es estrictamente no_std).
//! - **INV-02:** Cero datos personales ni secretos expuestos en logs o errores.
//! - **INV-03:** Claves privadas del titular protegidas en el dispositivo.
//! - **INV-05:** Fail-closed ante cualquier alteración de bytes o tag inválido.
//! - **INV-11:** Relojes y generadores de números aleatorios inyectados deterministamente.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod code;
pub mod error;
pub mod gf256;
pub mod kdf;
pub mod manager;
pub mod package;
pub mod payload;
pub mod shamir;
pub mod wordlist;

pub use code::{RecoveryCode, BIP39_WORD_COUNT, RECOVERY_ENTROPY_LEN};
pub use error::RecoveryError;
pub use gf256::{gf256_add, gf256_div, gf256_eval_poly, gf256_inv, gf256_mul, gf256_sub};
pub use kdf::{
    derive_backup_keys, derive_issuer_recovery_jwk, derive_issuer_recovery_secret, BACKUP_SALT_LEN,
};
pub use manager::RecoveryManager;
pub use package::{
    EncryptedBackupPackage, BACKUP_HEADER_LEN, BACKUP_MAGIC_GIDB, BACKUP_MAGIC_PIPB,
    BACKUP_PACKAGE_FORMAT_VERSION, CIPHER_SUITE_XCHACHA20_POLY1305,
};
pub use payload::{
    BackupCredential, BackupDeviceSlot, BackupPayload, BackupTenantRole, BACKUP_SCHEMA_VERSION,
    MAX_BACKUP_PAYLOAD_BYTES,
};
pub use shamir::{
    ShamirSecretSharing, ShamirShare, MAX_SHAMIR_SECRET_LEN, SHAMIR_CHECKSUM_LEN,
    SHAMIR_FORMAT_VERSION, SHAMIR_HEADER_LEN, SHAMIR_MAGIC_GIDS, SHAMIR_MIN_THRESHOLD,
};
pub use wordlist::{find_word_index, get_word, BIP39_WORDLIST_SIZE};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
