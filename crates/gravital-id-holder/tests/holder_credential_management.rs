//! Pruebas de integración de gestión de credenciales en la wallet (F5.T07, REQ-KEY-008, REQ-STOR-006).
//!
//! Trazabilidad:
//! - `REQ-KEY-008`: Asociación segura de cada credencial con la clave del titular sin
//!   almacenar la clave privada en la estructura ni permitir sustitución no autenticada.
//! - `REQ-STOR-001`, `REQ-STOR-003`: Cifrado de sobre DEK/KEK y consultas por índices ciegos.
//! - `REQ-STOR-008`: Almacenamiento desacoplado verificable en InMemory y SQLite.
//! - `INV-02`: Ausencia de datos en claro en almacenamiento.
//! - `INV-03`: Claves privadas del titular fuera de FFI / delegadas al KeyStore.
//! - `INV-05`: Fail-closed ante cualquier inconsistencia o manipulación.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_codec::json::Value;
use gravital_id_credential::SdJwtVcBuilder;
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_crypto::JwkEcP256;
use gravital_id_holder::{CredentialId, HolderWallet};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_storage::InMemoryStorageBackend;
use gravital_id_storage_sqlite::SqliteStorage;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime, Vct};

const TEST_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";

static DB_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Helper: genera una credencial SD-JWT VC nominal vinculada a la clave del titular.
fn create_test_credential(now: UnixTime, holder_jwk: JwkEcP256) -> String {
    let rng_key = SeededRng::new(1111);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_key);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let rng_emit = SeededRng::new(2222);
    let builder = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(TEST_VCT).expect("vct"), now)
        .expect("builder")
        .exp(UnixTime::from_seconds(
            now.as_seconds().saturating_add(3600),
        ))
        .cnf_jwk(holder_jwk)
        .status_list(1, STATUS_LIST_URI)
        .expect("status")
        .add_sd_claim("given_name", Value::String("Angel".into()))
        .add_sd_claim("family_name", Value::String("Nereira".into()))
        .add_sd_claim("document_number", Value::String("8-123-456".into()));

    let issued = builder
        .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
        .expect("issue");

    issued.to_compact_serialization().to_string()
}

// // Verifies: REQ-KEY-008, REQ-STOR-001, REQ-STOR-003, REQ-STOR-008 (InMemory)
#[test]
fn wallet_import_and_lookup_in_memory_nominal() {
    let rng_holder = SeededRng::new(3333);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);
    let raw_sd_jwt = create_test_credential(now, holder_pub);

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x42u8; 32]);
    let rng_wallet = SeededRng::new(4444);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    // 1. Importar credencial
    let cred_id = wallet
        .import_credential(
            &raw_sd_jwt,
            holder_handle.id(),
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("import");

    // 2. Obtener por ID
    let cred = wallet
        .get_credential(&cred_id)
        .expect("get")
        .expect("found");
    assert_eq!(cred.id, cred_id);
    assert_eq!(cred.vct.as_str(), TEST_VCT);
    assert_eq!(cred.issuer.as_str(), ISSUER_URI);
    assert_eq!(cred.holder_binding_key_id, holder_handle.id());
    assert!(cred.available_claims.contains(&"given_name".to_string()));
    assert!(cred.available_claims.contains(&"family_name".to_string()));
    assert!(cred
        .available_claims
        .contains(&"document_number".to_string()));

    // 3. Listar credenciales (resúmenes)
    let list = wallet.list_credentials().expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, cred_id);
    assert_eq!(list[0].vct.as_str(), TEST_VCT);

    // 4. Buscar por VCT mediante índices ciegos (REQ-STOR-003)
    let vct = Vct::parse(TEST_VCT).expect("vct");
    let found_ids = wallet.find_credentials_by_vct(&vct).expect("find");
    assert_eq!(found_ids.len(), 1);
    assert_eq!(found_ids[0], cred_id);

    // 5. Borrar credencial
    let deleted = wallet.delete_credential(&cred_id, now).expect("delete");
    assert!(deleted);
    assert!(wallet.get_credential(&cred_id).expect("get").is_none());
    assert_eq!(wallet.list_credentials().expect("list").len(), 0);
}

// // Verifies: REQ-KEY-008 (Rechazo fail-closed de sustitución no autenticada de claves)
#[test]
fn wallet_rejects_unauthenticated_key_substitution() {
    let rng_holder = SeededRng::new(5555);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle_1 = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("key1");
    let holder_handle_2 = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("key2");
    let holder_pub_1 = holder_keystore.public_key(&holder_handle_1).expect("pub1");

    let now = UnixTime::from_seconds(1700000000);
    let raw_sd_jwt = create_test_credential(now, holder_pub_1);

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x42u8; 32]);
    let rng_wallet = SeededRng::new(6666);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    // Caso A: El atacante pasa un handle que no coincide con el requested key_id
    let err = wallet
        .import_credential(
            &raw_sd_jwt,
            "another_key_id",
            now,
            &holder_keystore,
            &holder_handle_1,
        )
        .expect_err("should reject mismatched key handle id");
    assert_eq!(err.code, ErrorCode::KeyBindingFailed);

    // Caso B: El atacante intenta importar una credencial ligada a key1 pasando key2
    let err2 = wallet
        .import_credential(
            &raw_sd_jwt,
            holder_handle_2.id(),
            now,
            &holder_keystore,
            &holder_handle_2,
        )
        .expect_err("should reject mismatched cnf.jwk");
    assert_eq!(err2.code, ErrorCode::KeyBindingFailed);
}

// // Verifies: INV-05, REQ-VER-003 (Rechazo de credenciales corruptas o malformadas)
#[test]
fn wallet_rejects_corrupted_credential_import() {
    let rng_holder = SeededRng::new(7777);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);
    let raw_sd_jwt = create_test_credential(now, holder_pub);

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x42u8; 32]);
    let rng_wallet = SeededRng::new(8888);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    // Corromper el SD-JWT
    let corrupted_jwt = format!("{raw_sd_jwt}tampered_data");
    let err = wallet
        .import_credential(
            &corrupted_jwt,
            holder_handle.id(),
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect_err("should reject corrupted SD-JWT");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// // Verifies: REQ-STOR-004, REQ-STOR-006 (Borrado individual y en lote)
#[test]
fn wallet_batch_delete_atomic() {
    let rng_holder = SeededRng::new(9999);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);
    let raw_sd_jwt = create_test_credential(now, holder_pub);

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x42u8; 32]);
    let rng_wallet = SeededRng::new(1010);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    let cred_id1 = wallet
        .import_credential(
            &raw_sd_jwt,
            holder_handle.id(),
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("import 1");

    assert_eq!(wallet.list_credentials().expect("list").len(), 1);

    // Borrado en lote con cred_id1
    let deleted_count = wallet
        .delete_credentials_batch(&[cred_id1.clone()], now)
        .expect("batch delete");
    assert_eq!(deleted_count, 1);
    assert_eq!(wallet.list_credentials().expect("list").len(), 0);

    // Borrado de lote vacío
    let empty_deleted = wallet
        .delete_credentials_batch(&[], now)
        .expect("empty batch");
    assert_eq!(empty_deleted, 0);

    // Borrado de credencial inexistente retorna false
    let not_found_del = wallet
        .delete_credential(&cred_id1, now)
        .expect("delete not found");
    assert!(!not_found_del);
}

// // Verifies: REQ-STOR-008 (Persistencia en SQLite real en disco)
#[test]
fn wallet_sqlite_file_based_persistence() {
    let dir = std::env::temp_dir();
    let cnt = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_path = dir.join(format!(
        "pip_wallet_test_{}_{}.sqlite",
        std::process::id(),
        cnt
    ));

    let rng_holder = SeededRng::new(1212);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);
    let raw_sd_jwt = create_test_credential(now, holder_pub);

    let kek = SecretBytes::new([0x77u8; 32]);
    let cred_id: CredentialId;

    // 1. Abrir SQLite, importar credencial, cerrar
    {
        let storage = SqliteStorage::open(&db_path).expect("open sqlite");
        let rng_wallet = SeededRng::new(1313);
        let mut wallet = HolderWallet::new(storage, kek.clone(), rng_wallet).expect("wallet");

        cred_id = wallet
            .import_credential(
                &raw_sd_jwt,
                holder_handle.id(),
                now,
                &holder_keystore,
                &holder_handle,
            )
            .expect("import");
        assert_eq!(wallet.list_credentials().expect("list").len(), 1);
    }

    // 2. Reabrir SQLite con nuevo proceso/conexión, verificar que los datos persisten
    {
        let storage2 = SqliteStorage::open(&db_path).expect("reopen sqlite");
        let rng_wallet2 = SeededRng::new(1414);
        let wallet2 = HolderWallet::new(storage2, kek, rng_wallet2).expect("wallet 2");

        let list = wallet2.list_credentials().expect("list");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, cred_id);

        let cred = wallet2
            .get_credential(&cred_id)
            .expect("get")
            .expect("found");
        assert_eq!(cred.vct.as_str(), TEST_VCT);
        assert_eq!(cred.holder_binding_key_id, holder_handle.id());
    }

    let _ = std::fs::remove_file(db_path);
}
