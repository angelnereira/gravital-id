#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas integrales de robustez, tolerancia a fallos y consistencia transaccional
//! en persistencia, migración entre dispositivos y recuperación criptográfica (F8.T10).
//!
//! Trazabilidad:
//! - **REQ-STOR-004:** El sistema DEBE garantizar la consistencia transaccional ante fallos
//!   o cortes de energía sin corromper el estado.
//! - **REQ-REC-001:** Migración de dispositivos con compromiso previo, SAS y canal efímero.
//! - **REQ-REC-002:** Respaldo cifrado protegido con código de recuperación de $\ge 128$ bits.
//! - **REQ-REC-003:** Partición secreta de Shamir ($k$-de-$n$) sobre $GF(2^8)$.
//! - **REQ-REC-004:** Clave de recuperación exclusiva y protocolo de re-vinculación.
//! - **REQ-DEVSLOT-003:** Revocación atómica por clase de dispositivo (`ADR-0029`).
//! - **INV-01:** Sans-I/O en capas L1–L4.
//! - **INV-02:** Cero datos personales o secretos en errores, diagnósticos o registros.
//! - **INV-05:** Fail-closed determinista ante cualquier alteración de bytes o fallo.
//! - **INV-10:** Cero pánicos ni estados indefinidos en bibliotecas.

use std::fs;

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_recovery::code::RecoveryCode;
use gravital_id_recovery::manager::RecoveryManager;
use gravital_id_recovery::migration::{SourceMigrationMachine, TargetMigrationMachine};
use gravital_id_recovery::payload::{
    BackupCredential, BackupDeviceSlot, BackupPayload, BackupTenantRole,
};
use gravital_id_recovery::shamir::{ShamirSecretSharing, ShamirShare};
use gravital_id_status::{TokenStatus, TokenStatusListBuilder};
use gravital_id_storage::{
    CollectionName, EncryptedRecord, EnvelopeEncryption, RecordId, StorageBackend,
};
use gravital_id_storage_sqlite::{rusqlite, SqliteStorage};
use gravital_id_testkit::{FixedClock, SeededRng};
use gravital_id_types::UnixTime;

static DB_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);

fn create_test_record(id: &str, payload: &[u8], kek: &SecretBytes<32>) -> EncryptedRecord {
    let rng = SeededRng::new(0x1234);
    let record_id = RecordId::new(id).expect("valid record id");
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("valid collection");
    EnvelopeEncryption::encrypt(kek, &record_id, &collection, payload, &rng)
        .expect("encrypt record")
}

fn create_sample_backup_payload() -> BackupPayload {
    let secret = SecretBytes::new([0xAA; 32]);
    let cred1 = BackupCredential {
        id: "cred-identity-official".to_string(),
        vct: "urn:gravital-id:vct:pip-identity-official-v1".to_string(),
        issuer: "https://tribunal-electoral.gob.pa/issuer".to_string(),
        serialized_sd_jwt:
            "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJURVBBIiwiZXhwIjoxODAwMDAwMDAwfQ.sig~discl1~discl2~"
                .to_string(),
    };
    let cred2 = BackupCredential {
        id: "cred-bank-kyc".to_string(),
        vct: "pip-financial-v1".to_string(),
        issuer: "https://banco-nacional.pa/issuer".to_string(),
        serialized_sd_jwt: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJCTlAiLCJreWMiOiJ0aWVyMyJ9.sig~disclA~"
            .to_string(),
    };
    let slot = BackupDeviceSlot {
        device_factor_class: "mobile".to_string(),
        status_index: 42,
    };
    let role = BackupTenantRole {
        tenant_id: "tenant-banca-movil".to_string(),
        role_vct: "pip-tenant-role-v1".to_string(),
        tenant_subject_id: "tenant-sub-12345".to_string(),
    };

    BackupPayload::new(
        secret,
        vec![cred1, cred2],
        vec![slot],
        vec![role],
        UnixTime::from_seconds(1_700_000_000),
    )
}

// ============================================================================
// 1. Persistencia SQLite y Recuperación ante Caídas / Rollback (REQ-STOR-004)
// ============================================================================

/// Verifies: REQ-STOR-004, INV-05
///
/// Inyecta una interrupción / rollback abrupto a mitad de una transacción de escritura
/// en `SqliteStorage`, comprobando que:
/// 1. La base de datos mantiene integridad perfecta (`PRAGMA integrity_check` -> `"ok"`).
/// 2. Los registros no consolidados se descartan sin dejar huellas corruptas.
/// 3. Los registros comprometidos previamente permanecen 100% íntegros y descifrables.
/// 4. Tras la falla y reconexión, las transacciones subsecuentes operan sin anomalías.
#[test]
fn test_storage_persistence_fault_tolerance_and_rollback_recovery() {
    let dir = std::env::temp_dir();
    let counter_val = DB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_path = dir.join(format!(
        "pip_robustness_test_{}_{}.sqlite",
        std::process::id(),
        counter_val
    ));

    // Limpieza preventiva si el archivo ya existiese
    let _ = fs::remove_file(&db_path);

    let kek = SecretBytes::new([0x77u8; 32]);
    let collection = CollectionName::new(CollectionName::CREDENTIALS).expect("collection name");
    let ts = UnixTime::from_seconds(1_700_000_000);

    // 1. Estado Inicial S_0: Abrir base de datos y comprometer 3 registros
    {
        let mut storage = SqliteStorage::open(&db_path).expect("open sqlite storage");

        let rec1 = create_test_record("record-01", b"payload-committed-1", &kek);
        let rec2 = create_test_record("record-02", b"payload-committed-2", &kek);
        let rec3 = create_test_record("record-03", b"payload-committed-3", &kek);

        storage
            .put(
                &collection,
                &RecordId::new("record-01").unwrap(),
                rec1,
                &[],
                ts,
            )
            .expect("put rec1");
        storage
            .put(
                &collection,
                &RecordId::new("record-02").unwrap(),
                rec2,
                &[],
                ts,
            )
            .expect("put rec2");
        storage
            .put(
                &collection,
                &RecordId::new("record-03").unwrap(),
                rec3,
                &[],
                ts,
            )
            .expect("put rec3");

        assert!(storage
            .get(&collection, &RecordId::new("record-01").unwrap())
            .unwrap()
            .is_some());
        assert!(storage
            .get(&collection, &RecordId::new("record-02").unwrap())
            .unwrap()
            .is_some());
        assert!(storage
            .get(&collection, &RecordId::new("record-03").unwrap())
            .unwrap()
            .is_some());
    }

    // 2. Inyección de Fallo: Simular transacción interrumpida / caída de proceso
    {
        let storage = SqliteStorage::open(&db_path).expect("reopen storage");
        let conn = storage.connection();

        // Iniciar transacción exclusiva
        conn.execute("BEGIN IMMEDIATE;", [])
            .expect("begin immediate transaction");

        // Insertar registros provisionales directamente en pip_records dentro de la transacción activa
        let rec_fail_1 = create_test_record("record-fail-1", b"payload-uncommitted-1", &kek);
        let rec_fail_2 = create_test_record("record-fail-2", b"payload-uncommitted-2", &kek);

        conn.execute(
            "INSERT INTO pip_records (collection, record_id, record_data, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            rusqlite::params![
                collection.as_str(),
                "record-fail-1",
                rec_fail_1.to_bytes(),
                ts.as_seconds() as i64,
                ts.as_seconds() as i64,
            ],
        )
        .expect("insert uncommitted record 1");

        conn.execute(
            "INSERT INTO pip_records (collection, record_id, record_data, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            rusqlite::params![
                collection.as_str(),
                "record-fail-2",
                rec_fail_2.to_bytes(),
                ts.as_seconds() as i64,
                ts.as_seconds() as i64,
            ],
        )
        .expect("insert uncommitted record 2");

        // Inyectar el fallo: Abortar abruptamente mediante ROLLBACK (equivalente a caída de proceso)
        conn.execute("ROLLBACK;", [])
            .expect("rollback on injected failure");
    }

    // 3. Verificación Post-Caída: Reabrir almacenamiento desde el disco
    {
        let mut storage = SqliteStorage::open(&db_path).expect("reopen storage after crash");
        let conn = storage.connection();

        // Verificación de integridad de bajo nivel en SQLite (PRAGMA integrity_check)
        let integrity: String = conn
            .query_row("PRAGMA integrity_check;", [], |row| row.get(0))
            .expect("integrity_check");
        assert_eq!(
            integrity, "ok",
            "La base de datos debe reportar integridad 'ok' tras la falla"
        );

        // Los registros provisionales no deben existir
        assert!(
            storage
                .get(&collection, &RecordId::new("record-fail-1").unwrap())
                .unwrap()
                .is_none(),
            "El registro provisional 1 no debe existir tras el rollback"
        );
        assert!(
            storage
                .get(&collection, &RecordId::new("record-fail-2").unwrap())
                .unwrap()
                .is_none(),
            "El registro provisional 2 no debe existir tras el rollback"
        );

        // Los registros de S_0 deben estar completamente preservados
        let id1 = RecordId::new("record-01").unwrap();
        let stored_1 = storage
            .get(&collection, &id1)
            .expect("get rec1")
            .expect("rec1 must exist");
        let decrypted_payload =
            EnvelopeEncryption::decrypt(&kek, &id1, &collection, &stored_1.record)
                .expect("decrypt payload");
        assert_eq!(decrypted_payload.as_slice(), b"payload-committed-1");

        // 4. Comprobación de recuperabilidad operativa: Insertar nuevo registro con éxito
        let rec_new = create_test_record("record-04-after-recovery", b"payload-committed-4", &kek);
        storage
            .put(
                &collection,
                &RecordId::new("record-04-after-recovery").unwrap(),
                rec_new,
                &[],
                ts,
            )
            .expect("put new record after crash");
        assert!(storage
            .get(
                &collection,
                &RecordId::new("record-04-after-recovery").unwrap()
            )
            .unwrap()
            .is_some());
    }

    // Limpieza de archivo temporal
    let _ = fs::remove_file(&db_path);
}

// ============================================================================
// 2. Respaldo Cifrado: Inyección de Corrupción y Truncamiento (REQ-REC-002, INV-05)
// ============================================================================

/// Verifies: REQ-REC-002, REQ-STOR-004, INV-05
///
/// Inyecta una matriz exhaustiva de fallos en paquetes de respaldo cifrados `GIDB`:
/// - Truncamiento progresivo en cada frontera de cabecera, AAD y datos.
/// - Mutación del número mágico (`b"GIDB"` alterado).
/// - Alteración de versión de formato y suite criptográfica.
/// - Manipulación de AAD (marca temporal, sal) -> fallo de autenticación AEAD.
/// - Manipulación de ciphertext y tag Poly1305 -> fallo de autenticación AEAD.
/// - Código de recuperación erróneo -> fallo de autenticación AEAD sin fuga de datos.
#[test]
fn test_backup_package_fault_injection_matrix() {
    let rng = SeededRng::new(0xCAFE);
    let code = RecoveryCode::generate(&rng).expect("generate recovery code");
    let payload = create_sample_backup_payload();
    let created_at = UnixTime::from_seconds(1_700_000_200);

    let package_bytes =
        RecoveryManager::export_backup(&payload, &code, created_at, &rng).expect("export backup");
    assert!(package_bytes.len() > 60);

    // Verificación nominal positiva inicial
    let restored = RecoveryManager::restore_backup(&package_bytes, &code).expect("restore valid");
    assert_eq!(restored.credentials.len(), 2);
    assert_eq!(restored.device_slots.len(), 1);
    assert_eq!(restored.tenant_roles.len(), 1);

    // Fallo 1: Truncamiento en múltiples longitudes críticas
    let critical_truncation_lengths = [
        0,
        1,
        3,
        4,
        10,
        20,
        58,
        59,
        package_bytes.len().saturating_sub(1),
    ];
    for &trunc_len in &critical_truncation_lengths {
        let truncated = &package_bytes[..trunc_len];
        let result = RecoveryManager::restore_backup(truncated, &code);
        assert!(
            result.is_err(),
            "El paquete truncado a {} bytes debe ser rechazado fail-closed",
            trunc_len
        );
    }

    // Fallo 2: Mutación del número mágico (bytes 0..4)
    {
        let mut corrupted_magic = package_bytes.clone();
        corrupted_magic[0] = b'B';
        corrupted_magic[1] = b'A';
        corrupted_magic[2] = b'D';
        corrupted_magic[3] = b'!';
        let result = RecoveryManager::restore_backup(&corrupted_magic, &code);
        assert!(
            result.is_err(),
            "Un paquete con magic inválido debe ser rechazado fail-closed"
        );
    }

    // Fallo 3: Mutación de la versión de formato (byte 4)
    {
        let mut corrupted_version = package_bytes.clone();
        corrupted_version[4] = 99; // Versión inexistente
        let result = RecoveryManager::restore_backup(&corrupted_version, &code);
        assert!(
            result.is_err(),
            "Una versión de formato no soportada debe ser rechazada fail-closed"
        );
    }

    // Fallo 4: Mutación de la suite criptográfica (byte 5)
    {
        let mut corrupted_suite = package_bytes.clone();
        corrupted_suite[5] = 0xFF; // Suite desconocida
        let result = RecoveryManager::restore_backup(&corrupted_suite, &code);
        assert!(
            result.is_err(),
            "Una suite criptográfica inválida debe ser rechazada fail-closed"
        );
    }

    // Fallo 5: Mutación de la sal AAD (bytes 14..30)
    {
        let mut corrupted_salt = package_bytes.clone();
        corrupted_salt[20] ^= 0x55;
        let result = RecoveryManager::restore_backup(&corrupted_salt, &code);
        assert!(
            result.is_err(),
            "La alteración de la sal en el AAD debe provocar fallo de autenticación AEAD"
        );
    }

    // Fallo 6: Mutación de un byte del ciphertext
    {
        let mut corrupted_ciphertext = package_bytes.clone();
        let payload_offset = 59 + 24; // Cabecera + Nonce
        corrupted_ciphertext[payload_offset] ^= 0x01;
        let result = RecoveryManager::restore_backup(&corrupted_ciphertext, &code);
        assert!(
            result.is_err(),
            "La alteración de bits en el ciphertext debe provocar fallo de autenticación AEAD"
        );
    }

    // Fallo 7: Mutación de un byte del tag Poly1305 (últimos 16 bytes)
    {
        let mut corrupted_tag = package_bytes.clone();
        let last_idx = corrupted_tag.len().saturating_sub(1);
        corrupted_tag[last_idx] ^= 0xFF;
        let result = RecoveryManager::restore_backup(&corrupted_tag, &code);
        assert!(
            result.is_err(),
            "La alteración del tag Poly1305 debe provocar fallo de autenticación AEAD"
        );
    }

    // Fallo 8: Código de recuperación incorrecto
    {
        let wrong_rng = SeededRng::new(0x9999);
        let wrong_code = RecoveryCode::generate(&wrong_rng).expect("generate wrong code");
        let result = RecoveryManager::restore_backup(&package_bytes, &wrong_code);
        assert!(
            result.is_err(),
            "Un código de recuperación erróneo debe fallar la autenticación AEAD sin descifrar nada"
        );
    }
}

// ============================================================================
// 3. Shamir Secret Recovery: Inyección de Fallos y Quórum (REQ-REC-003, INV-16)
// ============================================================================

/// Verifies: REQ-REC-003, INV-05, INV-16
///
/// Inyecta fallos en el esquema de fragmentos de Shamir $k$-de-$n$:
/// - Intento de reconstrucción con quórum insuficiente ($k-1$ fragmentos).
/// - Presentación de fragmentos con índices duplicados.
/// - Alteración de valores $y$ de los fragmentos -> detección fail-closed de suma de verificación.
/// - Truncamiento y corrupción de cabecera binaria `GIDS`.
#[test]
fn test_shamir_secret_recovery_fault_injection_matrix() {
    let rng = SeededRng::new(0xBEEF_1234);
    let secret = b"super-secret-recovery-master-key-32b!";

    // Dividir en 5 fragmentos con umbral k=3
    let shares =
        ShamirSecretSharing::split(secret, 3, 5, &rng).expect("split secret into 5 shares");
    assert_eq!(shares.len(), 5);

    // Verificación nominal positiva con 3 fragmentos cualesquiera
    let recovered_nominal =
        ShamirSecretSharing::combine(&shares[0..3]).expect("combine valid quorum");
    assert_eq!(recovered_nominal.as_slice(), secret);

    // Fallo 1: Quórum insuficiente (k - 1 = 2 fragmentos) -> Falla cerrada
    let result_insufficient = ShamirSecretSharing::combine(&shares[0..2]);
    assert!(
        result_insufficient.is_err(),
        "El quórum insuficiente (2 de 3) debe ser rechazado fail-closed"
    );

    // Fallo 2: Fragmentos duplicados con mismo índice (share 0 repetido dos veces + share 1)
    let duplicate_shares = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
    let result_duplicate = ShamirSecretSharing::combine(&duplicate_shares);
    assert!(
        result_duplicate.is_err(),
        "Fragmentos con índices duplicados deben ser rechazados fail-closed"
    );

    // Fallo 3: Corrupción de un fragmento individual en su serialización binaria
    {
        let share_bytes = shares[0].to_bytes();

        // 3.1 Truncamiento de bytes del fragmento
        let result_trunc = ShamirShare::from_bytes(&share_bytes[..10]);
        assert!(
            result_trunc.is_err(),
            "Un fragmento binario truncado debe ser rechazado"
        );

        // 3.2 Mutación de la cabecera mágica "GIDS"
        let mut corrupted_magic = share_bytes.clone();
        corrupted_magic[0] = b'X';
        let result_magic = ShamirShare::from_bytes(&corrupted_magic);
        assert!(
            result_magic.is_err(),
            "Un fragmento con magic corrupto debe ser rechazado"
        );

        // 3.3 Alteración de la suma de comprobación del fragmento
        let mut corrupted_checksum = share_bytes.clone();
        let last_idx = corrupted_checksum.len().saturating_sub(1);
        corrupted_checksum[last_idx] ^= 0xAA;
        let result_chk = ShamirShare::from_bytes(&corrupted_checksum);
        assert!(
            result_chk.is_err(),
            "Un fragmento con checksum alterado debe fallar al deserializarse"
        );
    }
}

// ============================================================================
// 4. Protocolo de Migración: Inyección de Fallos e Interrupciones (REQ-REC-001)
// ============================================================================

/// Verifies: REQ-REC-001, REQ-STOR-004, INV-05
///
/// Inyecta fallos y ataques en cada fase de la máquina de estados de migración dispositivo a dispositivo:
/// - Desconexión tras Engagement QR.
/// - Ataque de intermediario (MitM) manipulando el resumen de compromiso previo ($C_A$).
/// - Rechazo interactivo de SAS por discrepancia visual o intento prematuro de enviar datos.
/// - Corrupción de paquete de bóveda cifrada en tránsito -> fallo AEAD y aborto en Target sin tocar almacenamiento.
#[test]
fn test_migration_protocol_fault_injection_and_state_isolation() {
    let target_rng = SeededRng::new(0x1111);
    let source_rng = SeededRng::new(0x2222);
    let clock = FixedClock::new(1_700_000_500);

    // Fallo 1: Ataque MitM alterando el compromiso previo (Fase 2)
    {
        let (mut target_machine, engagement) =
            TargetMigrationMachine::new(&target_rng, &clock).expect("target init");
        let (mut source_machine, commitment) =
            SourceMigrationMachine::from_engagement(engagement, &source_rng).expect("source init");

        // El atacante altera el compromiso en tránsito
        let mut tampered_commitment = commitment;
        tampered_commitment.commitment[0] ^= 0xFF;

        let ack = target_machine
            .process_commitment(tampered_commitment)
            .expect("target accepts tampered commitment without knowing real secret yet");

        let (revelation, _source_sas) = source_machine
            .process_ack(ack)
            .expect("source reveals ephemeral key");

        // Cuando el Target valida la revelación contra el compromiso alterado -> Falla cerrada
        let result_revelation = target_machine.process_revelation(revelation);
        assert!(
            result_revelation.is_err(),
            "Target debe detectar discrepancia de compromiso previo y abortar fail-closed (MitM detectado)"
        );
    }

    // Fallo 2: Intento de transferir datos antes de confirmar el SAS (violación de seguridad)
    {
        let (mut target_machine, engagement) =
            TargetMigrationMachine::new(&target_rng, &clock).expect("target init");
        let (mut source_machine, commitment) =
            SourceMigrationMachine::from_engagement(engagement, &source_rng).expect("source init");

        let ack = target_machine
            .process_commitment(commitment)
            .expect("target ack");
        let (revelation, _source_sas) = source_machine.process_ack(ack).expect("source reveal");
        let _target_sas = target_machine
            .process_revelation(revelation)
            .expect("target reveal");

        // Source intenta exportar la carga útil antes de confirmar interactivamente el SAS
        let dummy_payload = create_sample_backup_payload();
        let export_result = source_machine.encrypt_payload(&dummy_payload);
        assert!(
            export_result.is_err(),
            "Source no debe permitir cifrar payload si el titular no ha confirmado el código SAS"
        );
    }

    // Fallo 3: Corrupción del paquete de datos cifrados en tránsito (Fase 4)
    {
        let (mut target_machine, engagement) =
            TargetMigrationMachine::new(&target_rng, &clock).expect("target init");
        let (mut source_machine, commitment) =
            SourceMigrationMachine::from_engagement(engagement, &source_rng).expect("source init");

        let ack = target_machine
            .process_commitment(commitment)
            .expect("target ack");
        let (revelation, source_sas) = source_machine.process_ack(ack).expect("source reveal");
        let target_sas = target_machine
            .process_revelation(revelation)
            .expect("target reveal");

        // SAS coincide
        assert_eq!(source_sas, target_sas);
        source_machine.confirm_sas().expect("source confirm sas");
        target_machine.confirm_sas().expect("target confirm sas");

        let payload = create_sample_backup_payload();
        let mut package = source_machine
            .encrypt_payload(&payload)
            .expect("export package");

        // Corromper el ciphertext en tránsito
        let last_idx = package.encrypted_data.len().saturating_sub(1);
        package.encrypted_data[last_idx] ^= 0x7E;

        let result_process = target_machine.receive_and_decrypt(package);
        assert!(
            result_process.is_err(),
            "Target debe rechazar el paquete con ciphertext corrupto por fallo de autenticación AEAD"
        );
    }
}

// ============================================================================
// 5. Reemplazo Atómico de Ranura: Falla Transaccional y Rollback (REQ-DEVSLOT-003)
// ============================================================================

/// Verifies: REQ-DEVSLOT-003, ADR-0029, REQ-STOR-004
///
/// Simula la consistencia transaccional durante el reemplazo atómico de una ranura de dispositivo:
/// - El titular posee la ranura `mobile` (índice 42) y `card` (índice 108) activas.
/// - Un fallo simulado a mitad de la re-emisión aborta la operación antes del commit.
/// - Se comprueba que ambas ranuras originales continúan activas (`Valid`) sin corrupción.
/// - La reanudación y commit exitoso revoca únicamente la ranura `mobile` anterior (índice 42 -> `Revoked`),
///   activa la nueva ranura `mobile` (índice 150 -> `Valid`) y mantiene la ranura `card` (índice 108 -> `Valid`).
#[test]
fn test_device_slot_replacement_fault_tolerance_and_rollback() {
    let mut status_builder =
        TokenStatusListBuilder::new(2, 131_072).expect("crear lista de 2 bits");

    let slot_mobile_old = 42u64;
    let slot_card = 108u64;
    let slot_mobile_new = 150u64;

    // Estado inicial: ambas ranuras activas
    assert_eq!(
        status_builder.get_status(slot_mobile_old).unwrap(),
        TokenStatus::Valid
    );
    assert_eq!(
        status_builder.get_status(slot_card).unwrap(),
        TokenStatus::Valid
    );
    assert_eq!(
        status_builder.get_status(slot_mobile_new).unwrap(),
        TokenStatus::Valid
    );

    // Intento 1: Inyección de fallo a mitad de la re-vinculación con rollback
    {
        // Se altera provisionalmente el índice anterior
        status_builder
            .set_status(slot_mobile_old, TokenStatus::Revoked)
            .unwrap();

        // Ocurre un fallo inyectado (p. ej. error de red con el relay o fallo de firma)
        let simulated_failure = true;
        if simulated_failure {
            // Revertir atómicamente al estado nominal anterior
            status_builder
                .set_status(slot_mobile_old, TokenStatus::Valid)
                .unwrap();
        }
    }

    // Verificar que el estado original fue preservado tras el rollback
    assert_eq!(
        status_builder.get_status(slot_mobile_old).unwrap(),
        TokenStatus::Valid,
        "La ranura móvil anterior debe permanecer válida tras el rollback"
    );
    assert_eq!(
        status_builder.get_status(slot_card).unwrap(),
        TokenStatus::Valid,
        "La ranura tarjeta debe permanecer válida tras el rollback"
    );

    // Intento 2: Transacción reanudada con commit exitoso
    status_builder
        .set_status(slot_mobile_old, TokenStatus::Revoked)
        .expect("commit revoke old mobile");
    status_builder
        .set_status(slot_mobile_new, TokenStatus::Valid)
        .expect("commit activate new mobile");

    // Verificaciones finales
    assert_eq!(
        status_builder.get_status(slot_mobile_old).unwrap(),
        TokenStatus::Revoked,
        "El móvil viejo debe estar revocado tras el reemplazo atómico exitoso"
    );
    assert_eq!(
        status_builder.get_status(slot_mobile_new).unwrap(),
        TokenStatus::Valid,
        "El móvil nuevo debe estar activo"
    );
    assert_eq!(
        status_builder.get_status(slot_card).unwrap(),
        TokenStatus::Valid,
        "La tarjeta física debe permanecer activa e intacta"
    );
}

// ============================================================================
// 6. Auditoría Forense de Ausencia de Datos Personales en Fallos (INV-02)
// ============================================================================

/// Verifies: INV-02
///
/// Audita forensemente que los mensajes de error generados durante fallos de persistencia,
/// respaldos corruptos, desincronización de Shamir y abortos de migración carezcan por completo
/// de datos personales (PII), números de cédula, nombres o claves en texto plano.
#[test]
fn test_recovery_fault_injection_zero_pii_audit() {
    let rng = SeededRng::new(0x9999);
    let code = RecoveryCode::generate(&rng).unwrap();

    // Colectar strings de errores producidos en escenarios de fallo
    let mut collected_error_strings = Vec::new();

    // Error por paquete truncado
    if let Err(e) = RecoveryManager::restore_backup(&[0x01, 0x02], &code) {
        collected_error_strings.push(format!("{:?} - {}", e, e));
    }

    // Error por magic corrupto
    let bad_magic = b"XXXX\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    if let Err(e) = RecoveryManager::restore_backup(bad_magic, &code) {
        collected_error_strings.push(format!("{:?} - {}", e, e));
    }

    // Error por Shamir insuficiente
    if let Err(e) = ShamirSecretSharing::combine(&[]) {
        collected_error_strings.push(format!("{:?} - {}", e, e));
    }

    // Error por Shamir corrupto
    if let Err(e) = ShamirShare::from_bytes(&[0xFF; 20]) {
        collected_error_strings.push(format!("{:?} - {}", e, e));
    }

    // Patrones prohibidos según INV-02
    let forbidden_patterns = [
        "cédula",
        "cedula",
        "passport",
        "given_name",
        "family_name",
        "national_id",
        "secret_key_material",
        "private_key",
        "plaintext",
    ];

    for err_msg in &collected_error_strings {
        let lower = err_msg.to_lowercase();
        for pattern in &forbidden_patterns {
            assert!(
                !lower.contains(pattern),
                "Fuga de PII detectada en mensaje de error: {} contiene '{}'",
                err_msg,
                pattern
            );
        }
    }
}
