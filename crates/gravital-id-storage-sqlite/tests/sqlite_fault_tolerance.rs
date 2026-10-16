//! Pruebas de consistencia ante fallos, atomicidad y tolerancia a interrupciones (F5.T06, REQ-STOR-004).
//!
//! Trazabilidad:
//! - `REQ-STOR-004`: Escrituras atómicas y consistentes ante interrupciones.
//! - `STORAGE_FORMAT.md §5`: Modo WAL, synchronous=NORMAL, foreign_keys=ON.
//! - `INV-04`, `INV-05`: Integridad estricta y fail-closed ante fallos en transacciones.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_storage::{
    BlindIndex, CollectionName, EncryptedRecord, EnvelopeEncryption, RecordId, StorageBackend,
};
use gravital_id_storage_sqlite::SqliteStorage;
use gravital_id_testkit::SeededRng;
use gravital_id_types::UnixTime;
use rusqlite::TransactionBehavior;

fn make_record(id: &str, payload: &[u8]) -> EncryptedRecord {
    let kek = SecretBytes::new([0x99u8; 32]);
    let rng = SeededRng::new(9999);
    let record_id = RecordId::new(id).expect("id");
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    EnvelopeEncryption::encrypt(&kek, &record_id, &collection, payload, &rng).expect("encrypt")
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// // Verifies: REQ-STOR-004, STORAGE_FORMAT.md §5 (PRAGMAs normativos de seguridad en disco)
#[test]
fn sqlite_pragmas_match_specification() {
    let dir = std::env::temp_dir();
    let counter_val = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_path = dir.join(format!(
        "pip_pragma_test_{}_{}.sqlite",
        std::process::id(),
        counter_val
    ));

    let storage = SqliteStorage::open(&db_path).expect("open file");
    let conn = storage.connection();

    // 1. WAL mode
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .expect("journal_mode");
    assert_eq!(journal_mode.to_lowercase(), "wal");

    // 2. Synchronous = NORMAL (1)
    let sync_mode: i64 = conn
        .query_row("PRAGMA synchronous;", [], |row| row.get(0))
        .expect("synchronous");
    assert_eq!(sync_mode, 1);

    // 3. Foreign keys = ON (1)
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .expect("foreign_keys");
    assert_eq!(foreign_keys, 1);

    drop(storage);
    let _ = std::fs::remove_file(db_path);
}

// // Verifies: REQ-STOR-004 (Limpieza atómica en cascada por foreign keys)
#[test]
fn sqlite_foreign_key_cascade_atomicity() {
    let mut storage = SqliteStorage::open_in_memory().expect("open");
    let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    let id = RecordId::new("cred:cascade-test").expect("id");
    let rec = make_record("cred:cascade-test", b"cascade payload");
    let idx = BlindIndex::new([0x12; 32]);
    let time = UnixTime::from_seconds(1700000000);

    storage.put(&col, &id, rec, &[idx], time).expect("put");

    // Verificar que el índice existe en la tabla subyacente
    let count_indices: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pip_blind_indices WHERE record_id = ?1",
            rusqlite::params![id.as_str()],
            |row| row.get(0),
        )
        .expect("query indices");
    assert_eq!(count_indices, 1);

    // Eliminar el registro padre
    assert!(storage.delete(&col, &id).expect("delete"));

    // El índice asociado DEBE haber desaparecido automáticamente por ON DELETE CASCADE
    let count_indices_after: i64 = storage
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pip_blind_indices WHERE record_id = ?1",
            rusqlite::params![id.as_str()],
            |row| row.get(0),
        )
        .expect("query indices after");
    assert_eq!(count_indices_after, 0);
}

// // Verifies: REQ-STOR-004 (Inyección de fallo en transacción: reversión atómica total sin corrupción)
#[test]
fn sqlite_transaction_rollback_on_fault_injection() {
    let mut storage = SqliteStorage::open_in_memory().expect("open");
    let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    let id_initial = RecordId::new("rec:committed-001").expect("id");
    let time = UnixTime::from_seconds(1700000000);

    // Estado inicial confirmado
    storage
        .put(
            &col,
            &id_initial,
            make_record("rec:committed-001", b"stable data"),
            &[],
            time,
        )
        .expect("put initial");
    assert_eq!(storage.count(&col).expect("count"), 1);

    // Inyección de fallo: Transacción que inserta un registro nuevo pero aborta antes de commit
    {
        let conn = storage.connection_mut();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("tx");

        let rec_fail = make_record("rec:fault-002", b"transient data");
        let blob = rec_fail.to_bytes();
        tx.execute(
            r#"
            INSERT INTO pip_records (record_id, collection, record_data, created_at, updated_at)
            VALUES ('rec:fault-002', 'credentials', ?1, 1700000000, 1700000000)
            "#,
            rusqlite::params![blob],
        )
        .expect("insert in tx");

        // Simulación de fallo / caída de proceso: tx se descarta sin llamar a tx.commit()
        drop(tx);
    }

    // Verificar que la base de datos se mantiene exactamente en el estado previo consistente (REQ-STOR-004)
    assert_eq!(storage.count(&col).expect("count"), 1);
    let id_fault = RecordId::new("rec:fault-002").expect("id");
    assert!(storage.get(&col, &id_fault).expect("get").is_none());
    assert!(storage.get(&col, &id_initial).expect("get").is_some());
}
