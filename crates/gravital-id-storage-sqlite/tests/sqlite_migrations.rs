//! Pruebas de migraciones de esquema versionadas para SQLite (F5.T05, REQ-STOR-005).
//!
//! Trazabilidad:
//! - `REQ-STOR-005`: Versión de esquema y compatibilidad verificada con datos de versiones anteriores.
//! - `STORAGE_FORMAT.md §6`: Procedimiento paso a paso $N \to N+1$.
//! - `INV-04`, `INV-05`: Rechazo fail-closed ante downgrade.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_storage::{
    CollectionName, EncryptedRecord, EnvelopeEncryption, RecordId, StorageBackend,
};
use gravital_id_storage_sqlite::{get_current_version, SqliteStorage, SqliteStorageConfig};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime};

fn make_sample_record(id: &str) -> EncryptedRecord {
    let kek = SecretBytes::new([0x55u8; 32]);
    let rng = SeededRng::new(5555);
    let record_id = RecordId::new(id).expect("id");
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    EnvelopeEncryption::encrypt(&kek, &record_id, &collection, b"v1 payload", &rng)
        .expect("encrypt")
}

// // Verifies: REQ-STOR-005 (Migración progresiva V1 -> V2 preservando integridad de registros)
#[test]
fn schema_migration_from_v1_to_v2_preserves_records() {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let dir = std::env::temp_dir();
    let counter_val = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_path = dir.join(format!(
        "pip_migration_test_{}_{}.sqlite",
        std::process::id(),
        counter_val
    ));

    let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    let id1 = RecordId::new("rec:v1-001").expect("id");
    let id2 = RecordId::new("rec:v1-002").expect("id");
    let time = UnixTime::from_seconds(1700000000);

    // 1. Inicializar base de datos en versión de esquema 1
    {
        let config = SqliteStorageConfig {
            path: db_path.to_string_lossy().to_string(),
            target_schema_version: 1,
        };
        let mut storage = SqliteStorage::open_with_config(config).expect("open v1");
        assert_eq!(
            get_current_version(storage.connection()).expect("version"),
            1
        );

        storage
            .put(&col, &id1, make_sample_record("rec:v1-001"), &[], time)
            .expect("put v1");
        storage
            .put(&col, &id2, make_sample_record("rec:v1-002"), &[], time)
            .expect("put v1");
        assert_eq!(storage.count(&col).expect("count"), 2);
    }

    // 2. Abrir con target_schema_version = 2 (ejecuta migración 1 -> 2)
    {
        let config = SqliteStorageConfig {
            path: db_path.to_string_lossy().to_string(),
            target_schema_version: 2,
        };
        let storage = SqliteStorage::open_with_config(config).expect("open v2");
        assert_eq!(
            get_current_version(storage.connection()).expect("version"),
            2
        );

        // Verificar que todos los registros de V1 siguen presentes e intactos
        assert_eq!(storage.count(&col).expect("count"), 2);
        let r1 = storage.get(&col, &id1).expect("get").expect("found");
        assert_eq!(r1.record_id, id1);
        let r2 = storage.get(&col, &id2).expect("get").expect("found");
        assert_eq!(r2.record_id, id2);
    }

    // 3. Intento de anti-downgrade (abrir base de datos V2 con binario configurado para V1)
    {
        let config_downgrade = SqliteStorageConfig {
            path: db_path.to_string_lossy().to_string(),
            target_schema_version: 1,
        };
        let err =
            SqliteStorage::open_with_config(config_downgrade).expect_err("downgrade must fail");
        assert_eq!(err.code, ErrorCode::SchemaMigrationFailed);
    }

    // Limpieza
    let _ = std::fs::remove_file(db_path);
}
