//! Pruebas de integración de SqliteStorage y VerifierStateStore (F5.T04).
//!
//! Trazabilidad:
//! - `REQ-STOR-008`: Backend intercambiable SQLite en L5.
//! - `REQ-STOR-003`: Búsqueda mediante índices ciegos en SQLite.
//! - `REQ-STOR-004`: Atomicidad transaccional.
//! - `REQ-VER-006`: Piso de tiempo monotónico.
//! - `REQ-PRES-004`: Consumo atómico de nonces anti-replay.
//! - `REQ-TRUST-009`: Persistencia del estado de bundle aceptado.
//! - `INV-01`: Operación sans-I/O sin red.
//! - `INV-02`: Ausencia de PII en claro.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_storage::{
    BlindIndexer, CollectionName, EncryptedRecord, EnvelopeEncryption, RecordId, StorageBackend,
    StorageBatch,
};
use gravital_id_storage_sqlite::SqliteStorage;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::AcceptedBundleState;
use gravital_id_types::UnixTime;
use gravital_id_verifier::state::VerifierStateStore;

fn sample_record(payload: &[u8]) -> EncryptedRecord {
    let kek = SecretBytes::new([0x33u8; 32]);
    let rng = SeededRng::new(1234);
    let record_id = RecordId::new("cred:panama:001").expect("id");
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    EnvelopeEncryption::encrypt(&kek, &record_id, &collection, payload, &rng).expect("encrypt")
}

// // Verifies: REQ-STOR-008, REQ-STOR-003 (CRUD y búsqueda por índice ciego en SQLite)
#[test]
fn sqlite_crud_and_blind_index_queries() {
    let mut storage = SqliteStorage::open_in_memory().expect("open sqlite in memory");
    let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    let id = RecordId::new("cred:panama:001").expect("id");
    let rec = sample_record(b"sample credentials payload");

    let kek = SecretBytes::new([0x33u8; 32]);
    let indexer = BlindIndexer::from_kek(&kek).expect("indexer");
    let idx_issuer = indexer.compute_issuer_index("iss-te").expect("idx");
    let idx_vct = indexer.compute_vct_index("id-v1").expect("idx");

    let time = UnixTime::from_seconds(1700000000);

    // Get inexistente
    assert!(storage.get(&col, &id).expect("get").is_none());
    assert_eq!(storage.count(&col).expect("count"), 0);

    // Put
    storage
        .put(&col, &id, rec.clone(), &[idx_issuer, idx_vct], time)
        .expect("put");
    assert_eq!(storage.count(&col).expect("count"), 1);

    // Get existente
    let stored = storage.get(&col, &id).expect("get").expect("found");
    assert_eq!(stored.record_id, id);
    assert_eq!(stored.collection, col);
    assert_eq!(stored.record, rec);
    assert_eq!(stored.created_at, time);

    // Consulta por índice ciego de emisor
    let results = storage
        .query_by_blind_index(&col, &idx_issuer)
        .expect("query");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].record_id, id);

    // Consulta por índice ciego de vct
    let results_vct = storage.query_by_blind_index(&col, &idx_vct).expect("query");
    assert_eq!(results_vct.len(), 1);

    // List
    let list = storage.list(&col).expect("list");
    assert_eq!(list.len(), 1);

    // Delete
    assert!(storage.delete(&col, &id).expect("delete"));
    assert_eq!(storage.count(&col).expect("count"), 0);
    assert!(storage.get(&col, &id).expect("get").is_none());

    // Índices ciegos eliminados en cascada
    let after_del = storage
        .query_by_blind_index(&col, &idx_issuer)
        .expect("query");
    assert!(after_del.is_empty());
}

// // Verifies: REQ-STOR-004 (Transacciones atómicas por lotes en SQLite)
#[test]
fn sqlite_transaction_batch_execution() {
    let mut storage = SqliteStorage::open_in_memory().expect("open");
    let col = CollectionName::new(CollectionName::SESSIONS).expect("col");
    let id1 = RecordId::new("sess:001").expect("id");
    let id2 = RecordId::new("sess:002").expect("id");
    let rec1 = sample_record(b"sess1");
    let rec2 = sample_record(b"sess2");
    let time = UnixTime::from_seconds(1700000000);

    let mut batch = StorageBatch::new();
    batch.put(col.clone(), id1.clone(), rec1, vec![], time);
    batch.put(col.clone(), id2.clone(), rec2, vec![], time);

    storage
        .execute_transaction(batch.ops())
        .expect("execute tx");
    assert_eq!(storage.count(&col).expect("count"), 2);
}

// // Verifies: REQ-VER-006, REQ-TRUST-009, REQ-PRES-004 (VerifierStateStore en SQLite)
#[test]
fn sqlite_verifier_state_store_contract() {
    let mut storage = SqliteStorage::open_in_memory().expect("open");

    // 1. Piso de tiempo (Time Floor)
    assert!(storage.time_floor().expect("time_floor").is_none());
    let t1 = UnixTime::from_seconds(1700000000);
    storage.raise_time_floor(t1).expect("raise floor");
    assert_eq!(storage.time_floor().expect("time_floor"), Some(t1));

    // Elevar a un instante anterior no disminuye el piso (monotónico)
    let t_past = UnixTime::from_seconds(1600000000);
    storage.raise_time_floor(t_past).expect("raise past");
    assert_eq!(storage.time_floor().expect("time_floor"), Some(t1));

    // Elevar a un instante futuro actualiza el piso
    let t_future = UnixTime::from_seconds(1800000000);
    storage.raise_time_floor(t_future).expect("raise future");
    assert_eq!(storage.time_floor().expect("time_floor"), Some(t_future));

    // 2. Estado de bundle aceptado (AcceptedBundleState)
    assert!(storage.accepted_bundle().expect("bundle").is_none());
    let bundle_state = AcceptedBundleState {
        bundle_epoch: 1,
        bundle_version: 42,
    };
    storage
        .record_accepted_bundle(bundle_state)
        .expect("record bundle");
    assert_eq!(
        storage.accepted_bundle().expect("bundle"),
        Some(bundle_state)
    );

    // 3. Caché de Nonces y consumo atómico
    let nonce = "nonce-xyz-789";
    let now = UnixTime::from_seconds(1700000000);
    let expires = UnixTime::from_seconds(1700000600);

    // No visto inicialmente
    assert!(!storage.nonce_seen(nonce, now).expect("seen"));

    // Consumo atómico por primera vez: devuelve true
    assert!(storage
        .check_and_consume_nonce(nonce, expires, now)
        .expect("consume fresh"));

    // Consumo repetido mientras sigue vigente: detecta replay y devuelve false
    assert!(!storage
        .check_and_consume_nonce(nonce, expires, now)
        .expect("consume replay"));
    assert!(storage.nonce_seen(nonce, now).expect("seen"));

    // Tras expiración: ya no se considera vigente
    let future_after_exp = UnixTime::from_seconds(1700000700);
    assert!(!storage.nonce_seen(nonce, future_after_exp).expect("seen"));

    // 4. Verificación de integridad y reset
    assert!(storage.integrity_check().is_ok());
    storage.reset();
    assert!(storage.time_floor().expect("time_floor").is_none());
    assert!(storage.accepted_bundle().expect("bundle").is_none());
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// // Verifies: REQ-STOR-008 (Persistencia en archivo real en disco)
#[test]
fn sqlite_file_based_persistence() {
    let dir = std::env::temp_dir();
    let counter_val = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_path = dir.join(format!(
        "pip_test_db_{}_{}.sqlite",
        std::process::id(),
        counter_val
    ));

    // 1. Abrir, escribir registro y estado, cerrar
    {
        let mut storage = SqliteStorage::open(&db_path).expect("open file");
        let col = CollectionName::new(CollectionName::KEYS).expect("col");
        let id = RecordId::new("key:device-main").expect("id");
        let rec = sample_record(b"private key metadata");
        let time = UnixTime::from_seconds(1700000000);

        storage.put(&col, &id, rec, &[], time).expect("put");
        storage.raise_time_floor(time).expect("time floor");
    }

    // 2. Reabrir desde disco y verificar persistencia íntegra
    {
        let storage = SqliteStorage::open(&db_path).expect("reopen file");
        let col = CollectionName::new(CollectionName::KEYS).expect("col");
        let id = RecordId::new("key:device-main").expect("id");

        let stored = storage.get(&col, &id).expect("get").expect("found");
        assert_eq!(stored.record_id, id);
        assert_eq!(
            storage.time_floor().expect("floor"),
            Some(UnixTime::from_seconds(1700000000))
        );
    }

    // Limpieza
    let _ = std::fs::remove_file(db_path);
}

#[test]
fn sqlite_error_and_edge_cases_coverage() {
    use gravital_id_storage_sqlite::error::{
        migration_err, sqlite_read_err, sqlite_write_err, verifier_state_corrupted,
    };
    use rusqlite::Error as RusqliteError;

    let e1 = sqlite_read_err(RusqliteError::QueryReturnedNoRows);
    assert_eq!(e1.code, gravital_id_types::ErrorCode::StorageReadFailed);

    let e2 = sqlite_write_err(RusqliteError::QueryReturnedNoRows);
    assert_eq!(e2.code, gravital_id_types::ErrorCode::StorageWriteFailed);

    let e3 = migration_err(RusqliteError::QueryReturnedNoRows);
    assert_eq!(e3.code, gravital_id_types::ErrorCode::SchemaMigrationFailed);

    let e4 = verifier_state_corrupted("test reason");
    assert_eq!(
        e4.code,
        gravital_id_types::ErrorCode::VerifierStateCorrupted
    );

    // Corrupted verifier state records
    let mut storage = SqliteStorage::open_in_memory().expect("open");
    // Insert corrupted time_floor with negative value
    storage
        .connection_mut()
        .execute(
            "INSERT INTO pip_verifier_state (key, value_int, updated_at) VALUES ('time_floor', -5, 100)",
            [],
        )
        .expect("insert corrupted");
    assert_eq!(
        storage.time_floor().expect_err("time floor must fail").code,
        gravital_id_types::ErrorCode::VerifierStateCorrupted
    );

    // Insert corrupted accepted_bundle with non-numeric version
    storage
        .connection_mut()
        .execute(
            "INSERT OR REPLACE INTO pip_verifier_state (key, value_int, value_text, updated_at) VALUES ('accepted_bundle', 1, 'bad_ver', 100)",
            [],
        )
        .expect("insert corrupted bundle");
    assert_eq!(
        storage
            .accepted_bundle()
            .expect_err("bundle must fail")
            .code,
        gravital_id_types::ErrorCode::VerifierStateCorrupted
    );
}
