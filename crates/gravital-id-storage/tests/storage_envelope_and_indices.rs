//! Pruebas de integración para cifrado de sobre, índices ciegos y StorageBackend (F5.T01–F5.T03).
//!
//! Trazabilidad:
//! - `REQ-STOR-001`: Cifrado de sobre (DEK/KEK) con AEAD y datos asociados (AAD).
//! - `REQ-STOR-002`: Clave maestra KEK provista por el host vía `KekProvider`.
//! - `REQ-STOR-003`: Índices ciegos con HMAC-SHA-256 e inspección automática de ausencia de PII en claro.
//! - `REQ-STOR-004`: Atomicidad y consistencia ante fallos en transacciones.
//! - `REQ-STOR-008`: Backend intercambiable mediante el trait `StorageBackend`.
//! - `INV-01`: Cero I/O de red.
//! - `INV-02`: Cero PII en logs, almacenamiento ni índices.
//! - `INV-05`: Fail-closed ante cualquier manipulación.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_storage::{
    BlindIndex, BlindIndexer, CipherSuite, CollectionName, EncryptedRecord, EnvelopeEncryption,
    InMemoryStorageBackend, KekProvider, RecordId, StaticKekProvider, StorageBackend, StorageBatch,
    SCHEMA_VERSION_V1, STORAGE_MAGIC,
};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime};

fn make_test_kek(seed: u8) -> SecretBytes<32> {
    SecretBytes::new([seed; 32])
}

// // Verifies: REQ-STOR-001 (Ciclo de vida completo: cifrar -> serializar -> deserializar -> descifrar)
#[test]
fn e2e_envelope_lifecycle_round_trip() {
    let kek = make_test_kek(0x42);
    let rng = SeededRng::new(9999);
    let record_id = RecordId::new("cred:panama-national-id:001").expect("id");
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("collection");
    let plaintext_payload = b"{\n  \"sub\": \"did:gid:holder-42\",\n  \"document\": \"8-123-456\",\n  \"exp\": 1800000000\n}";

    // 1. Cifrado de sobre
    let encrypted =
        EnvelopeEncryption::encrypt(&kek, &record_id, &collection, plaintext_payload, &rng)
            .expect("encrypt must succeed");

    assert_eq!(encrypted.magic(), &STORAGE_MAGIC);
    assert_eq!(encrypted.schema_version(), SCHEMA_VERSION_V1);
    assert_eq!(encrypted.cipher_suite(), CipherSuite::XChaCha20Poly1305);
    assert_ne!(encrypted.ciphertext(), plaintext_payload);

    // 2. Serialización binaria canónica
    let serialized_bytes = encrypted.to_bytes();

    // 3. Deserialización binaria
    let recovered_encrypted =
        EncryptedRecord::from_bytes(&serialized_bytes).expect("deserialization must succeed");
    assert_eq!(encrypted, recovered_encrypted);

    // 4. Descifrado de sobre y verificación de AAD
    let decrypted =
        EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &recovered_encrypted)
            .expect("decrypt must succeed");

    assert_eq!(decrypted, plaintext_payload);
}

// // Verifies: REQ-STOR-001 (Matriz negativa: todas las alteraciones fallan fail-closed)
#[test]
fn e2e_envelope_negative_matrix_fails_closed() {
    let kek = make_test_kek(0x42);
    let wrong_kek = make_test_kek(0x99);
    let rng = SeededRng::new(9999);
    let record_id = RecordId::new("cred:001").expect("id");
    let other_id = RecordId::new("cred:002").expect("id");
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("collection");
    let other_col = CollectionName::new(CollectionName::KEYS).expect("collection");
    let plaintext = b"critical secret data";

    let encrypted = EnvelopeEncryption::encrypt(&kek, &record_id, &collection, plaintext, &rng)
        .expect("encrypt");

    // 1. KEK incorrecta rechaza
    let err = EnvelopeEncryption::decrypt(&wrong_kek, &record_id, &collection, &encrypted)
        .expect_err("wrong KEK must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);

    // 2. RecordId intercambiado rechaza
    let err = EnvelopeEncryption::decrypt(&kek, &other_id, &collection, &encrypted)
        .expect_err("swapped record id must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);

    // 3. Colección intercambiada rechaza
    let err = EnvelopeEncryption::decrypt(&kek, &record_id, &other_col, &encrypted)
        .expect_err("swapped collection must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);

    // 4. Modificación de un solo bit en ciphertext rechaza
    let mut tampered_ct = encrypted.ciphertext().to_vec();
    if let Some(b) = tampered_ct.first_mut() {
        *b ^= 0x01;
    }
    let record_tampered_ct = EncryptedRecord::new(
        encrypted.schema_version(),
        encrypted.cipher_suite(),
        *encrypted.nonce(),
        *encrypted.record_id_hash(),
        tampered_ct,
        *encrypted.auth_tag(),
    );
    let err = EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &record_tampered_ct)
        .expect_err("tampered ciphertext must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);

    // 5. Modificación de un solo bit en auth_tag rechaza
    let mut tampered_tag = *encrypted.auth_tag();
    tampered_tag[0] ^= 0x01;
    let record_tampered_tag = EncryptedRecord::new(
        encrypted.schema_version(),
        encrypted.cipher_suite(),
        *encrypted.nonce(),
        *encrypted.record_id_hash(),
        encrypted.ciphertext().to_vec(),
        tampered_tag,
    );
    let err = EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &record_tampered_tag)
        .expect_err("tampered tag must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);

    // 6. Modificación de un solo bit en nonce rechaza
    let mut tampered_nonce = *encrypted.nonce();
    tampered_nonce[0] ^= 0x01;
    let record_tampered_nonce = EncryptedRecord::new(
        encrypted.schema_version(),
        encrypted.cipher_suite(),
        tampered_nonce,
        *encrypted.record_id_hash(),
        encrypted.ciphertext().to_vec(),
        *encrypted.auth_tag(),
    );
    let err = EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &record_tampered_nonce)
        .expect_err("tampered nonce must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);

    // 7. Modificación de versión de esquema rechaza AAD
    let record_tampered_version = EncryptedRecord::new(
        encrypted.schema_version() + 1,
        encrypted.cipher_suite(),
        *encrypted.nonce(),
        *encrypted.record_id_hash(),
        encrypted.ciphertext().to_vec(),
        *encrypted.auth_tag(),
    );
    let err = EnvelopeEncryption::decrypt(&kek, &record_id, &collection, &record_tampered_version)
        .expect_err("tampered schema version must fail");
    assert_eq!(err.code, ErrorCode::AeadAuthenticationFailed);
}

// // Verifies: REQ-STOR-003, INV-02 (Inspección exhaustiva: cero metadatos o PII en claro en el almacenamiento)
#[test]
fn e2e_blind_indexing_and_forensic_database_inspection() {
    let kek = make_test_kek(0x77);
    let indexer = BlindIndexer::from_kek(&kek).expect("indexer from kek");
    let rng = SeededRng::new(5555);
    let mut backend = InMemoryStorageBackend::new();

    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("collection");

    // Datos sensibles con PII y metadatos
    let sensitive_issuer = "iss-tribunal-electoral-panama";
    let sensitive_vct = "https://credentials.gravital.io/vct/personal/id-v1";
    let sensitive_document = "8-765-4321";
    let sensitive_name = "Juan Perez";

    let payload = format!(
        "{{\"issuer\":\"{sensitive_issuer}\",\"vct\":\"{sensitive_vct}\",\"doc\":\"{sensitive_document}\",\"name\":\"{sensitive_name}\"}}"
    );

    let rec_id = RecordId::new("cred:user-juan-01").expect("rec_id");

    // Índices ciegos calculados con la BIK derivada
    let idx_issuer = indexer
        .compute_issuer_index(sensitive_issuer)
        .expect("idx_issuer");
    let idx_vct = indexer.compute_vct_index(sensitive_vct).expect("idx_vct");
    let idx_doc = indexer
        .compute_index("doc", sensitive_document)
        .expect("idx_doc");

    let encrypted =
        EnvelopeEncryption::encrypt(&kek, &rec_id, &collection, payload.as_bytes(), &rng)
            .expect("encrypt");

    let timestamp = UnixTime::from_seconds(1700000000);
    backend
        .put(
            &collection,
            &rec_id,
            encrypted,
            &[idx_issuer, idx_vct, idx_doc],
            timestamp,
        )
        .expect("storage put");

    // 1. Verificación de búsqueda funcional por índice ciego
    let results_by_issuer = backend
        .query_by_blind_index(&collection, &idx_issuer)
        .expect("query issuer");
    assert_eq!(results_by_issuer.len(), 1);
    assert_eq!(results_by_issuer[0].record_id, rec_id);

    let results_by_vct = backend
        .query_by_blind_index(&collection, &idx_vct)
        .expect("query vct");
    assert_eq!(results_by_vct.len(), 1);

    let results_by_doc = backend
        .query_by_blind_index(&collection, &idx_doc)
        .expect("query doc");
    assert_eq!(results_by_doc.len(), 1);

    // Consulta con índice no coincidente
    let wrong_idx = indexer
        .compute_issuer_index("iss-other-bank")
        .expect("wrong");
    let no_results = backend
        .query_by_blind_index(&collection, &wrong_idx)
        .expect("query empty");
    assert!(no_results.is_empty());

    // 2. INSPECCIÓN FORENSE (INV-02, REQ-STOR-003):
    // Ningún string en claro sensible puede aparecer en el volcado de almacenamiento.
    let records = backend.list(&collection).expect("list");
    assert_eq!(records.len(), 1);

    let stored = &records[0];
    let serialized_blob = stored.record.to_bytes();

    let forbidden_strings = [
        sensitive_issuer,
        sensitive_vct,
        sensitive_document,
        sensitive_name,
        "Juan",
        "Perez",
        "panama",
        "tribunal",
        "electoral",
        "credentials.gravital.io",
    ];

    for forbidden in forbidden_strings {
        let pattern = forbidden.as_bytes();
        // Búsqueda en el payload binario serializado
        let found_in_blob = serialized_blob.windows(pattern.len()).any(|w| w == pattern);
        assert!(
            !found_in_blob,
            "INVARIANTE INV-02 VIOLADO: cadena sensible '{}' encontrada en claro en el blob serializado",
            forbidden
        );

        // Búsqueda en los índices ciegos hexadecimales
        let hex_issuer = idx_issuer.to_hex();
        let hex_vct = idx_vct.to_hex();
        let hex_doc = idx_doc.to_hex();
        assert!(!hex_issuer
            .to_lowercase()
            .contains(&forbidden.to_lowercase()));
        assert!(!hex_vct.to_lowercase().contains(&forbidden.to_lowercase()));
        assert!(!hex_doc.to_lowercase().contains(&forbidden.to_lowercase()));
    }
}

// // Verifies: REQ-STOR-004, REQ-STOR-008 (Contrato genérico de StorageBackend y atomicidad)
fn exercise_generic_storage_contract<B: StorageBackend>(backend: &mut B) {
    let col = CollectionName::new(CollectionName::SESSIONS).expect("col");
    let id1 = RecordId::new("sess:001").expect("id1");
    let id2 = RecordId::new("sess:002").expect("id2");
    let time = UnixTime::from_seconds(1700000000);

    let rec1 = EncryptedRecord::new(
        1,
        CipherSuite::XChaCha20Poly1305,
        [1u8; 24],
        [2u8; 16],
        b"data1".to_vec(),
        [3u8; 16],
    );
    let rec2 = EncryptedRecord::new(
        1,
        CipherSuite::XChaCha20Poly1305,
        [4u8; 24],
        [5u8; 16],
        b"data2".to_vec(),
        [6u8; 16],
    );

    let idx1 = BlindIndex::new([0x11; 32]);
    let idx2 = BlindIndex::new([0x22; 32]);

    let mut batch = StorageBatch::new();
    batch.put(col.clone(), id1.clone(), rec1.clone(), vec![idx1], time);
    batch.put(col.clone(), id2.clone(), rec2.clone(), vec![idx2], time);

    backend
        .execute_transaction(batch.ops())
        .expect("batch commit");
    assert_eq!(backend.count(&col).expect("count"), 2);

    let r1 = backend.get(&col, &id1).expect("get").expect("found");
    assert_eq!(r1.record, rec1);

    let q = backend.query_by_blind_index(&col, &idx1).expect("query");
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].record_id, id1);

    // Borrado
    let deleted = backend.delete(&col, &id1).expect("delete");
    assert!(deleted);
    assert_eq!(backend.count(&col).expect("count"), 1);
    assert!(backend.get(&col, &id1).expect("get").is_none());
}

#[test]
fn generic_storage_contract_on_in_memory_backend() {
    let mut backend = InMemoryStorageBackend::new();
    exercise_generic_storage_contract(&mut backend);
}

// // Verifies: REQ-STOR-002 (KekProvider con StaticKekProvider)
#[test]
fn host_kek_provider_integration() {
    let kek = make_test_kek(0x88);
    let provider = StaticKekProvider::new(kek.clone());
    let fetched = provider.get_kek().expect("get_kek");
    assert_eq!(fetched.expose_secret(), kek.expose_secret());
}

#[test]
fn storage_types_methods_and_debug_coverage() {
    // RecordId
    let id = RecordId::new("rec:test-01").expect("id");
    assert_eq!(id.as_str(), "rec:test-01");
    assert_eq!(format!("{id}"), "rec:test-01");
    assert_eq!(format!("{id:?}"), "RecordId(\"rec:test-01\")");

    // CollectionName
    let col = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    assert_eq!(col.as_str(), "credentials");
    assert_eq!(format!("{col}"), "credentials");
    assert_eq!(format!("{col:?}"), "CollectionName(\"credentials\")");
    assert_eq!(CollectionName::KEYS, "keys");
    assert_eq!(CollectionName::SESSIONS, "sessions");
    assert_eq!(CollectionName::STATE, "state");

    // CipherSuite
    let suite1 = CipherSuite::XChaCha20Poly1305;
    assert_eq!(suite1.as_u8(), 0x01);
    let suite2 = CipherSuite::from_u8(0x02).expect("aes256gcm");
    assert_eq!(suite2, CipherSuite::Aes256Gcm);
    assert_eq!(suite2.as_u8(), 0x02);

    // BlindIndex
    let raw = [0x5au8; 32];
    let idx = BlindIndex::new(raw);
    assert_eq!(idx.as_bytes(), &raw);
    assert_eq!(idx.truncated_16(), [0x5au8; 16]);
    assert_eq!(
        format!("{idx:?}"),
        format!("BlindIndex(\"{}\")", idx.to_hex())
    );
    // Hex decode con mayúsculas
    let hex_upper = idx.to_hex().to_uppercase();
    let decoded_upper = BlindIndex::from_hex(&hex_upper).expect("from_hex uppercase");
    assert_eq!(idx, decoded_upper);

    // BlindIndexer
    let kek = make_test_kek(0x11);
    let indexer = BlindIndexer::from_kek(&kek).expect("indexer");
    assert!(format!("{indexer:?}").contains("[REDACTED]"));
    let id_idx = indexer.compute_id_index("rec:test-01").expect("id_idx");
    assert_eq!(id_idx.truncated_16().len(), 16);

    // Error por nombre de atributo demasiado largo
    let too_long_attr = "a".repeat(BlindIndexer::MAX_ATTR_NAME_LEN + 1);
    assert!(indexer.compute_index(&too_long_attr, "val").is_err());

    // StorageBatch
    let mut batch = StorageBatch::new();
    batch.delete(col.clone(), id.clone());
    assert_eq!(batch.ops().len(), 1);
    let ops = batch.into_ops();
    assert_eq!(ops.len(), 1);

    // EncryptedRecord getters & Debug
    let rec = EncryptedRecord::new(
        SCHEMA_VERSION_V1,
        CipherSuite::XChaCha20Poly1305,
        [0x11; 24],
        [0x22; 16],
        b"data".to_vec(),
        [0x33; 16],
    );
    assert_eq!(rec.magic(), &STORAGE_MAGIC);
    assert_eq!(rec.schema_version(), 1);
    assert_eq!(rec.cipher_suite(), CipherSuite::XChaCha20Poly1305);
    assert_eq!(rec.nonce(), &[0x11; 24]);
    assert_eq!(rec.record_id_hash(), &[0x22; 16]);
    assert_eq!(rec.ciphertext(), b"data");
    assert_eq!(rec.auth_tag(), &[0x33; 16]);
    assert!(format!("{rec:?}").contains("[REDACTED]"));

    // InMemoryStorageBackend: actualización preserva created_at, delete no existente devuelve false
    let mut backend = InMemoryStorageBackend::new();
    assert!(!backend.delete(&col, &id).expect("delete nonexistent"));

    let t1 = UnixTime::from_seconds(1000);
    backend.put(&col, &id, rec.clone(), &[], t1).expect("put");
    let stored1 = backend.get(&col, &id).expect("get").expect("found");
    assert_eq!(stored1.created_at, t1);
    assert_eq!(stored1.updated_at, t1);

    let t2 = UnixTime::from_seconds(2000);
    backend
        .put(&col, &id, rec.clone(), &[], t2)
        .expect("update");
    let stored2 = backend.get(&col, &id).expect("get").expect("found");
    assert_eq!(stored2.created_at, t1);
    assert_eq!(stored2.updated_at, t2);
}
