//! Pruebas forenses de privacidad, no-persistencia y registro de auditoría local (F5.T07, REQ-PRIV-005, REQ-STOR-006, INV-02).
//!
//! Trazabilidad:
//! - `REQ-PRIV-005`: La wallet NUNCA DEBE persistir el contenido de presentaciones enviadas
//!   ni nonces del verificador más allá de la sesión de presentación (P-02).
//! - `INV-02`: Cero datos personales, nombres, fechas o identificadores de titular en logs
//!   o en almacenamiento en claro.
//! - `REQ-STOR-006`: Auditoría apendible local con retención y purga configurable.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_codec::json::Value;
use gravital_id_credential::SdJwtVcBuilder;
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_holder::{AuditEventType, CredentialQuery, HolderWallet, RequestedClaim};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_storage::{CollectionName, InMemoryStorageBackend, StorageBackend};
use gravital_id_storage_sqlite::SqliteStorage;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{UnixTime, Vct};

const TEST_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";

static FORENSIC_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// // Verifies: REQ-PRIV-005, INV-02 (Prueba de inspección forense automatizada: presentaciones y nonces nunca se persisten)
#[test]
fn forensic_inspection_presentations_and_nonces_never_persisted() {
    let rng_holder = SeededRng::new(1111);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);

    let rng_issuer = SeededRng::new(2222);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let sensitive_first_name = "SuperSecretGivenNameAngel";
    let sensitive_last_name = "UltraPrivateFamilyNameNereira";
    let sensitive_doc_number = "PA-SECRET-ID-99998888";
    let ephemeral_verifier_nonce = "TOP_SECRET_VERIFIER_NONCE_VERY_UNIQUE_9876543210123456";
    let target_audience = "https://verifier.org/secret-entrance-gate";

    let rng_emit = SeededRng::new(3333);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(TEST_VCT).expect("vct"), now)
        .expect("builder")
        .exp(UnixTime::from_seconds(now.as_seconds().saturating_add(3600)))
        .cnf_jwk(holder_pub)
        .status_list(1, STATUS_LIST_URI)
        .expect("status")
        .add_sd_claim("given_name", Value::String(sensitive_first_name.into()))
        .add_sd_claim("family_name", Value::String(sensitive_last_name.into()))
        .add_sd_claim(
            "document_number",
            Value::String(sensitive_doc_number.into()),
        )
        .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x88u8; 32]);
    let rng_wallet = SeededRng::new(4444);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    // 1. Importar la credencial en la wallet
    wallet
        .import_credential(
            issued.to_compact_serialization(),
            holder_handle.id(),
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("import");

    // 2. Preparar consulta y confirmar presentación
    let query = CredentialQuery::new(
        "gate_query",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![RequestedClaim::required("given_name")],
    )
    .expect("query");
    let plan = wallet.prepare_disclosure_plan(&query, None).expect("plan");

    let presentation = wallet
        .confirm_presentation(
            &plan,
            target_audience,
            ephemeral_verifier_nonce,
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("confirm presentation");

    // 3. Inspección forense exhaustiva de TODAS las colecciones en el backend de almacenamiento
    let col_credentials = CollectionName::new(CollectionName::CREDENTIALS).expect("col");
    let col_audit = CollectionName::new("audit_log").expect("col");

    let all_records = wallet.storage().list(&col_credentials).expect("list creds");
    let all_audit_records = wallet.storage().list(&col_audit).expect("list audit");

    // Inspección en bytes crudos de cada registro en disco/memoria
    for stored in all_records.iter().chain(all_audit_records.iter()) {
        let serialized_raw = stored.record.to_bytes();

        // REQ-PRIV-005: El nonce efímero del verificador NUNCA debe estar persistido
        assert!(
            !serialized_raw
                .windows(ephemeral_verifier_nonce.len())
                .any(|window| window == ephemeral_verifier_nonce.as_bytes()),
            "SECURITY VIOLATION (REQ-PRIV-005): Verifier nonce found in storage record!"
        );

        // REQ-PRIV-005: La presentación final completa generada NUNCA debe estar persistida
        assert!(
            !serialized_raw
                .windows(presentation.len())
                .any(|window| window == presentation.as_bytes()),
            "SECURITY VIOLATION (REQ-PRIV-005): Presentation string found in storage record!"
        );

        // INV-02: Ningún claim o dato personal sensible en claro
        assert!(
            !serialized_raw
                .windows(sensitive_first_name.len())
                .any(|window| window == sensitive_first_name.as_bytes()),
            "SECURITY VIOLATION (INV-02): Plaintext sensitive attribute found in storage record!"
        );
        assert!(
            !serialized_raw
                .windows(sensitive_last_name.len())
                .any(|window| window == sensitive_last_name.as_bytes()),
            "SECURITY VIOLATION (INV-02): Plaintext sensitive attribute found in storage record!"
        );
        assert!(
            !serialized_raw
                .windows(sensitive_doc_number.len())
                .any(|window| window == sensitive_doc_number.as_bytes()),
            "SECURITY VIOLATION (INV-02): Plaintext sensitive attribute found in storage record!"
        );
    }
}

// // Verifies: REQ-STOR-006, INV-02 (Eventos de auditoría apendibles y depuración por retención)
#[test]
fn wallet_audit_log_events_and_retention_purge() {
    let rng_holder = SeededRng::new(5555);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let t1 = UnixTime::from_seconds(1700000100);
    let t2 = UnixTime::from_seconds(1700000200);
    let t3 = UnixTime::from_seconds(1700000300);
    let t4 = UnixTime::from_seconds(1700000400);

    let rng_issuer = SeededRng::new(6666);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let rng_emit = SeededRng::new(7777);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(TEST_VCT).expect("vct"), t1)
        .expect("builder")
        .exp(UnixTime::from_seconds(t1.as_seconds().saturating_add(3600)))
        .cnf_jwk(holder_pub)
        .status_list(1, STATUS_LIST_URI)
        .expect("status")
        .add_sd_claim("given_name", Value::String("Angel".into()))
        .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x99u8; 32]);
    let rng_wallet = SeededRng::new(8888);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    // 1. T1: Importar
    let cred_id = wallet
        .import_credential(
            issued.to_compact_serialization(),
            holder_handle.id(),
            t1,
            &holder_keystore,
            &holder_handle,
        )
        .expect("import");

    // 2. T2: Presentar
    let query = CredentialQuery::new(
        "q1",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![RequestedClaim::required("given_name")],
    )
    .expect("query");
    let plan = wallet.prepare_disclosure_plan(&query, None).expect("plan");
    let _ = wallet
        .confirm_presentation(
            &plan,
            "https://verifier.org",
            "challenge1234567890123456",
            t2,
            &holder_keystore,
            &holder_handle,
        )
        .expect("pres");

    // 3. T3: Eliminar
    wallet.delete_credential(&cred_id, t3).expect("delete");

    // Verificar historial de auditoría
    let events = wallet.list_audit_events().expect("list audit");
    assert_eq!(events.len(), 3);

    assert_eq!(events[0].timestamp, t1);
    match &events[0].event_type {
        AuditEventType::CredentialImported { vct } => assert_eq!(vct.as_str(), TEST_VCT),
        _ => panic!("expected CredentialImported"),
    }

    assert_eq!(events[1].timestamp, t2);
    match &events[1].event_type {
        AuditEventType::PresentationCreated { vct, query_id } => {
            assert_eq!(vct.as_str(), TEST_VCT);
            assert_eq!(query_id, "q1");
        }
        _ => panic!("expected PresentationCreated"),
    }

    assert_eq!(events[2].timestamp, t3);
    match &events[2].event_type {
        AuditEventType::CredentialDeleted { credential_id } => {
            assert_eq!(credential_id, cred_id.as_str());
        }
        _ => panic!("expected CredentialDeleted"),
    }

    // 4. T4: Purgar eventos anteriores a t3 (debe borrar eventos de t1 y t2)
    let purged_count = wallet.purge_audit_events(t3, t4).expect("purge");
    assert_eq!(purged_count, 2);

    let events_after = wallet.list_audit_events().expect("list after");
    // Quedan: el evento de t3 (eliminación) + el evento de t4 (AuditLogPurged)
    assert_eq!(events_after.len(), 2);
    assert_eq!(events_after[0].timestamp, t3);
    assert_eq!(events_after[1].timestamp, t4);
    match &events_after[1].event_type {
        AuditEventType::AuditLogPurged { records_removed } => {
            assert_eq!(*records_removed, 2);
        }
        _ => panic!("expected AuditLogPurged"),
    }
}

// // Verifies: REQ-STOR-006, REQ-STOR-008 (Auditoría con SQLite en disco)
#[test]
fn wallet_audit_log_sqlite_persistence() {
    let dir = std::env::temp_dir();
    let cnt = FORENSIC_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_path = dir.join(format!(
        "pip_audit_test_{}_{}.sqlite",
        std::process::id(),
        cnt
    ));

    let rng_holder = SeededRng::new(9001);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);

    let rng_issuer = SeededRng::new(9002);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let rng_emit = SeededRng::new(9003);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(TEST_VCT).expect("vct"), now)
        .expect("builder")
        .exp(UnixTime::from_seconds(now.as_seconds().saturating_add(3600)))
        .cnf_jwk(holder_pub)
        .status_list(1, STATUS_LIST_URI)
        .expect("status")
        .add_sd_claim("given_name", Value::String("Angel".into()))
        .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let kek = SecretBytes::new([0xAAu8; 32]);

    {
        let storage = SqliteStorage::open(&db_path).expect("open sqlite");
        let rng_wallet = SeededRng::new(9004);
        let mut wallet = HolderWallet::new(storage, kek.clone(), rng_wallet).expect("wallet");

        wallet
            .import_credential(
                issued.to_compact_serialization(),
                holder_handle.id(),
                now,
                &holder_keystore,
                &holder_handle,
            )
            .expect("import");
    }

    {
        let storage2 = SqliteStorage::open(&db_path).expect("reopen sqlite");
        let rng_wallet2 = SeededRng::new(9005);
        let wallet2 = HolderWallet::new(storage2, kek, rng_wallet2).expect("wallet 2");

        let events = wallet2.list_audit_events().expect("list audit");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp, now);
        match &events[0].event_type {
            AuditEventType::CredentialImported { vct } => assert_eq!(vct.as_str(), TEST_VCT),
            _ => panic!("expected CredentialImported"),
        }
    }

    let _ = std::fs::remove_file(db_path);
}
