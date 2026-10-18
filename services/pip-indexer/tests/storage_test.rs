//! Pruebas de almacenamiento, idempotencia y reconstrucción de estado (F7.T03, REQ-LEDG-005, INV-02).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_ledger::{
    BundleSignerUpdatedEvent, EventCoordinate, IssuerDeregisteredEvent, IssuerRegisteredEvent,
    IssuerReinstatedEvent, IssuerSuspendedEvent, KeyAddedEvent, KeyCompromisedEvent,
    KeyRetiredEvent, KeySuspendedEvent, LedgerEvent, SequencedLedgerEvent,
    StatusManifestAnchoredEvent, TrustRootUpdatedEvent, VerifierDeregisteredEvent,
    VerifierRegisteredEvent,
};
use gravital_id_testkit::SeededRng;
use pip_indexer::storage::{
    deserialize_ledger_event, hex_decode, hex_encode, InMemoryIndexerStorage, IndexerStorage,
    SqliteIndexerStorage,
};

fn sample_valid_key() -> (Vec<u8>, [u8; 32]) {
    let rng = SeededRng::new(42);
    let sk = generate_p256_secret_key(&rng).expect("valid sk");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(jwk.x());
    uncompressed.extend_from_slice(jwk.y());
    let mut kid = [0u8; 32];
    kid.copy_from_slice(jwk.thumbprint_sha256().as_slice());
    (uncompressed, kid)
}

fn sample_issuer_registered_event(
    block: u64,
    tx: u32,
    log: u32,
    issuer_id: [u8; 32],
) -> SequencedLedgerEvent {
    let coord = EventCoordinate::new(block, tx, log, 1_700_000_000u64.saturating_add(block));
    let event = LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
        issuer_id,
        uri: "https://issuer.example.com".to_string(),
        profiles: vec!["pip-personal-v1".to_string()],
        vcts: vec!["https://schema.example.com/id".to_string()],
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
    });
    SequencedLedgerEvent::new(coord, event)
}

fn sample_key_added_event(block: u64, tx: u32, log: u32) -> SequencedLedgerEvent {
    let (key_bytes, kid) = sample_valid_key();
    let coord = EventCoordinate::new(block, tx, log, 1_700_000_000u64.saturating_add(block));
    let event = LedgerEvent::KeyAdded(KeyAddedEvent {
        issuer_id: [1u8; 32],
        kid,
        public_key: key_bytes,
    });
    SequencedLedgerEvent::new(coord, event)
}

fn test_storage_lifecycle(storage: &dyn IndexerStorage) {
    let chain_id = 421614;

    // 1. Inicialmente no hay checkpoint
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), None);

    // 2. Guardar y leer checkpoint
    storage
        .save_checkpoint(chain_id, 100, Some("0xabc123"), 1_700_000_100)
        .unwrap();
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(100));

    // 3. Inserción de eventos e idempotencia (ON CONFLICT DO NOTHING)
    let ev1 = sample_issuer_registered_event(101, 0, 0, [1u8; 32]);
    let ev2 = sample_key_added_event(101, 0, 1);
    let ev3 = sample_issuer_registered_event(102, 0, 0, [2u8; 32]);

    let inserted = storage
        .store_events(chain_id, &[ev1.clone(), ev2.clone(), ev3.clone()])
        .unwrap();
    assert_eq!(inserted, 3);
    assert_eq!(storage.count_events(chain_id).unwrap(), 3);

    // Inserción duplicada de ev1 y ev2 -> debe insertar 0 y preservar total
    let duplicate_inserted = storage
        .store_events(chain_id, &[ev1.clone(), ev2.clone()])
        .unwrap();
    assert_eq!(duplicate_inserted, 0);
    assert_eq!(storage.count_events(chain_id).unwrap(), 3);

    // 4. Consulta de rango
    let range = storage.get_events(chain_id, 101, 101).unwrap();
    assert_eq!(range.len(), 2);
    assert_eq!(range.first().unwrap().coordinate, ev1.coordinate);
    assert_eq!(range.get(1).unwrap().coordinate, ev2.coordinate);

    let range_all = storage.get_events(chain_id, 100, 200).unwrap();
    assert_eq!(range_all.len(), 3);

    // 5. Construcción y proyección del estado del ledger
    let state = storage.build_ledger_state(chain_id).unwrap();
    let issuer_record = state.issuers().get(&[1u8; 32]).unwrap();
    assert_eq!(issuer_record.uri, "https://issuer.example.com");
    let (_, kid) = sample_valid_key();
    assert!(issuer_record.keys.contains_key(&kid));

    // 6. Rebobinado tras reorganización (rewind_to_block)
    storage
        .rewind_to_block(chain_id, 101, 1_700_000_200)
        .unwrap();
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(101));
    assert_eq!(storage.count_events(chain_id).unwrap(), 2);
    // ev3 (bloque 102) fue eliminado
    let events_after = storage.get_events(chain_id, 100, 200).unwrap();
    assert_eq!(events_after.len(), 2);
    assert_eq!(events_after.first().unwrap().coordinate.block_number, 101);
    assert_eq!(events_after.get(1).unwrap().coordinate.block_number, 101);
}

#[test]
fn in_memory_storage_passes_lifecycle() {
    let storage = InMemoryIndexerStorage::new();
    test_storage_lifecycle(&storage);
}

#[test]
fn sqlite_storage_passes_lifecycle_and_persists_to_file() {
    let storage = SqliteIndexerStorage::new_in_memory().unwrap();
    test_storage_lifecycle(&storage);

    // Archivo temporal SQLite
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("pip_indexer_test_{}.db", std::process::id()));
    let file_storage = SqliteIndexerStorage::new_from_path(db_path.to_str().unwrap()).unwrap();
    test_storage_lifecycle(&file_storage);
    let _ = std::fs::remove_file(db_path);
}

#[test]
fn all_13_ledger_events_round_trip_serialization() {
    let events = vec![
        LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id: [1u8; 32],
            uri: "https://iss.com".to_string(),
            profiles: vec!["p1".to_string()],
            vcts: vec!["v1".to_string()],
            valid_from: 100,
            valid_until: 200,
        }),
        LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
            issuer_id: [1u8; 32],
            expires_at: 300,
            initiated_by: [9u8; 20],
        }),
        LedgerEvent::IssuerReinstated(IssuerReinstatedEvent {
            issuer_id: [1u8; 32],
        }),
        LedgerEvent::IssuerDeregistered(IssuerDeregisteredEvent {
            issuer_id: [1u8; 32],
        }),
        LedgerEvent::KeyAdded(KeyAddedEvent {
            issuer_id: [1u8; 32],
            kid: [2u8; 32],
            public_key: vec![1, 2, 3, 4],
        }),
        LedgerEvent::KeyRetired(KeyRetiredEvent {
            issuer_id: [1u8; 32],
            kid: [2u8; 32],
            state_since: 500,
        }),
        LedgerEvent::KeySuspended(KeySuspendedEvent {
            issuer_id: [1u8; 32],
            kid: [2u8; 32],
            expires_at: 600,
            initiated_by: [8u8; 20],
        }),
        LedgerEvent::KeyCompromised(KeyCompromisedEvent {
            issuer_id: [1u8; 32],
            kid: [2u8; 32],
            state_since: 700,
        }),
        LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
            verifier_id: [3u8; 32],
            uri: "https://ver.com".to_string(),
            profiles: vec!["p2".to_string()],
            public_key: vec![5, 6, 7],
            valid_from: 1000,
            valid_until: 2000,
        }),
        LedgerEvent::VerifierDeregistered(VerifierDeregisteredEvent {
            verifier_id: [3u8; 32],
        }),
        LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
            root_hash: [4u8; 32],
            root_version: 1,
            updated_at: 5000,
        }),
        LedgerEvent::BundleSignerUpdated(BundleSignerUpdatedEvent {
            signer_address: [7u8; 20],
            kid: [5u8; 32],
            public_key: vec![8, 9, 10],
            authorized: true,
        }),
        LedgerEvent::StatusManifestAnchored(StatusManifestAnchoredEvent {
            issuer_id: [1u8; 32],
            manifest_version: 42,
            manifest_hash: [6u8; 32],
            uri_hint: "https://status.hint".to_string(),
        }),
    ];

    for original in &events {
        let (name, json) = pip_indexer::storage::serialize_ledger_event(original).unwrap();
        assert!(!name.is_empty());
        let recovered = deserialize_ledger_event(&json).unwrap();
        assert_eq!(*original, recovered);
    }
}

#[test]
fn hex_helpers_and_error_handling() {
    let bytes = b"hello gravital id indexer";
    let encoded = hex_encode(bytes);
    let decoded = hex_decode(&encoded).unwrap();
    assert_eq!(bytes.as_slice(), decoded.as_slice());

    // Con prefijo 0x
    let with_0x = format!("0x{encoded}");
    assert_eq!(hex_decode(&with_0x).unwrap(), bytes.as_slice());

    // Longitud impar
    assert!(hex_decode("abc").is_err());

    // Caracteres no hexadecimales
    assert!(hex_decode("zz").is_err());

    // Deserialización de JSON malformado
    assert!(deserialize_ledger_event("not a json").is_err());

    // Deserialización de tipo desconocido
    assert!(deserialize_ledger_event(r#"{"type":"UnknownType","payload":{}}"#).is_err());
}
