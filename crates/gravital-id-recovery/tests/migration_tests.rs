//! Pruebas de integración de migración entre dispositivos con compromiso previo y SAS (`F8.T05`).
//!
//! Trazabilidad:
//! - **REQ-REC-001:** La migración entre dispositivos DEBE usar canal efímero ECDH con compromiso previo de claves y verificación SAS.
//! - **REQ-REC-002:** El respaldo cifrado DEBE protegerse con un código de recuperación generado de ≥ 128 bits.
//! - **REQ-REC-004:** La clave de recuperación DEBE tener propósito exclusivo (`HolderRecovery`) y habilitar la re-vinculación.
//! - **REQ-STOR-001:** Cifrado de sobre con AEAD y AAD ligado.
//! - **ADR-0009:** Modelo de recuperación Nivel 1 (migración voluntaria entre dispositivos con SAS y compromiso previo).
//! - **SPEC-PIP-MIGRATE-001:** Protocolo de migración directa en 4 fases.
//! - **INV-01 / INV-02 / INV-03 / INV-05 / INV-10 / INV-11.**

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_recovery::migration::{
    compute_commitment, compute_transcript, MigrationEngagement, SourceMigrationMachine,
    TargetMigrationMachine, MIGRATION_QR_PREFIX,
};
use gravital_id_recovery::payload::{
    BackupCredential, BackupDeviceSlot, BackupPayload, BackupTenantRole,
};
use gravital_id_recovery::RecoveryError;
use gravital_id_testkit::{FixedClock, SeededRng};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

/// Helper que construye un `BackupPayload` sintético representativo de una wallet con credenciales.
fn create_test_wallet_payload() -> BackupPayload {
    let mut secret_bytes = [0u8; 32];
    for (i, b) in secret_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let recovery_secret = SecretBytes::new(secret_bytes);

    let cred1 = BackupCredential {
        id: "cred-identity-01".to_string(),
        vct: "pip-identity-v1".to_string(),
        issuer: "https://gobierno.pa/id-issuer".to_string(),
        serialized_sd_jwt: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJnb2IifQ.sig~discl1~discl2~".to_string(),
    };

    let cred2 = BackupCredential {
        id: "cred-bank-01".to_string(),
        vct: "pip-financial-v1".to_string(),
        issuer: "https://banco.example.com".to_string(),
        serialized_sd_jwt: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJiYW5rIn0.sig~disclA~".to_string(),
    };

    let slot = BackupDeviceSlot {
        device_factor_class: "mobile".to_string(),
        status_index: 1024,
    };

    let role = BackupTenantRole {
        tenant_id: "tenant-tramites-panama".to_string(),
        role_vct: "pip-tenant-role-v1".to_string(),
        tenant_subject_id: "sub-pseudo-98765".to_string(),
    };

    BackupPayload::new(
        recovery_secret,
        vec![cred1, cred2],
        vec![slot],
        vec![role],
        UnixTime::from_seconds(1_700_000_000),
    )
}

// Verifies: REQ-REC-001
#[test]
fn test_e2e_nominal_device_migration_journey() {
    let target_rng = SeededRng::new(0x42);
    let source_rng = SeededRng::new(0x84);
    let clock = FixedClock::new(1_700_000_100);

    let original_payload = create_test_wallet_payload();

    // 1. Fase 1: Engagement QR generado en el nuevo dispositivo (Target)
    let (mut target_machine, engagement) =
        TargetMigrationMachine::new(&target_rng, &clock).expect("target machine initialization");

    let qr_string = engagement.to_qr_string();
    assert!(qr_string.starts_with(MIGRATION_QR_PREFIX));

    // 2. Dispositivo origen (Source) escanea el QR
    let scanned_engagement =
        MigrationEngagement::from_qr_string(&qr_string).expect("parse scanned QR engagement");
    assert_eq!(scanned_engagement, engagement);

    // 3. Fase 2: Dispositivo origen emite compromiso previo (Commitment)
    let (mut source_machine, commitment) =
        SourceMigrationMachine::from_engagement(scanned_engagement, &source_rng)
            .expect("source machine initialization");

    assert_eq!(commitment.target_id, *target_machine.target_id());

    // 4. Dispositivo destino recibe y acusa el compromiso previo
    let ack = target_machine
        .process_commitment(commitment)
        .expect("target process commitment");
    assert!(ack.accepted);

    // 5. Fase 3: Dispositivo origen procesa el ACK y revela su clave efímera junto al SAS
    let (revelation, source_sas) = source_machine
        .process_ack(ack)
        .expect("source process ack and reveal");

    // 6. Dispositivo destino procesa la revelación, verifica el compromiso previo y deriva el SAS
    let target_sas = target_machine
        .process_revelation(revelation)
        .expect("target process revelation and verify commitment");

    // Ambos dispositivos deben derivar exactamente el mismo código SAS de 6 dígitos
    assert_eq!(source_sas, target_sas);
    assert_eq!(
        source_machine.sas().unwrap().value(),
        target_machine.sas().unwrap().value()
    );

    let sas_formatted = source_sas.formatted();
    assert_eq!(sas_formatted.len(), 7); // "xxx-xxx"
    assert!(sas_formatted.contains('-'));

    // 7. El titular compara visualmente ambos códigos en sus pantallas y los confirma
    source_machine.confirm_sas().expect("source confirm sas");
    target_machine.confirm_sas().expect("target confirm sas");

    // 8. Fase 4: Transferencia cifrada del contenido de la wallet
    let package = source_machine
        .encrypt_payload(&original_payload)
        .expect("source encrypt payload");

    assert_eq!(package.target_id, *target_machine.target_id());

    // 9. Dispositivo destino descifra y autentica la carga útil, y encola re-vinculaciones
    let (completed_result, complete_ack) = target_machine
        .receive_and_decrypt(package)
        .expect("target decrypt and restore");

    assert!(complete_ack.accepted);
    assert!(target_machine.is_completed());

    // Verificación de integridad de la carga útil restaurada
    assert_eq!(
        completed_result.restored_payload.recovery_secret,
        original_payload.recovery_secret
    );
    assert_eq!(
        completed_result.restored_payload.credentials,
        original_payload.credentials
    );
    assert_eq!(
        completed_result.restored_payload.device_slots,
        original_payload.device_slots
    );
    assert_eq!(
        completed_result.restored_payload.tenant_roles,
        original_payload.tenant_roles
    );

    // Verificación del encolado de re-vinculaciones para las 2 credenciales (REQ-REC-001, ADR-0029)
    assert_eq!(completed_result.queued_rebindings.len(), 2);
    assert_eq!(
        completed_result.queued_rebindings[0].issuer_uri,
        "https://gobierno.pa/id-issuer"
    );
    assert_eq!(
        completed_result.queued_rebindings[0].credential_id,
        "cred-identity-01"
    );
    assert_eq!(completed_result.queued_rebindings[0].vct, "pip-identity-v1");

    assert_eq!(
        completed_result.queued_rebindings[1].issuer_uri,
        "https://banco.example.com"
    );
    assert_eq!(
        completed_result.queued_rebindings[1].credential_id,
        "cred-bank-01"
    );
    assert_eq!(
        completed_result.queued_rebindings[1].vct,
        "pip-financial-v1"
    );

    // 10. Dispositivo origen procesa el acuse final de completitud
    source_machine
        .process_complete_ack(complete_ack)
        .expect("source complete ack");
    assert!(source_machine.is_completed());
}

// Verifies: REQ-REC-001
#[test]
fn test_mitm_tampered_key_commitment_mismatch_fails_closed() {
    let target_rng = SeededRng::new(0x101);
    let source_rng = SeededRng::new(0x202);
    let attacker_rng = SeededRng::new(0x666);
    let clock = FixedClock::new(1_700_000_200);

    let (mut target_machine, engagement) =
        TargetMigrationMachine::new(&target_rng, &clock).expect("target machine initialization");

    let (mut source_machine, commitment) =
        SourceMigrationMachine::from_engagement(engagement, &source_rng)
            .expect("source machine initialization");

    let ack = target_machine
        .process_commitment(commitment)
        .expect("target process commitment");

    let (mut revelation, _source_sas) =
        source_machine.process_ack(ack).expect("source process ack");

    // Ataque MitM: Un intermediario sustituye la clave pública del origen por la suya en la revelación
    let attacker_secret = gravital_id_crypto::sign::generate_p256_secret_key(&attacker_rng)
        .expect("attacker secret key");
    let attacker_jwk = gravital_id_crypto::sign::public_key_from_secret_key(&attacker_secret)
        .expect("attacker jwk");
    revelation.source_pub = attacker_jwk.to_sec1_bytes();

    // El destino DEBE detectar la discrepancia contra el compromiso previo y abortar fail-closed
    let err = target_machine
        .process_revelation(revelation)
        .expect_err("tampered revelation must fail");

    assert_eq!(err, RecoveryError::CommitmentMismatch);
    let gid_err: GidError = err.into();
    assert_eq!(gid_err.code, ErrorCode::InvalidSignature);
}

// Verifies: REQ-REC-001
#[test]
fn test_mitm_unconfirmed_sas_refuses_to_transmit_or_decrypt() {
    let target_rng = SeededRng::new(0x303);
    let source_rng = SeededRng::new(0x404);
    let clock = FixedClock::new(1_700_000_300);

    let original_payload = create_test_wallet_payload();

    let (mut target_machine, engagement) =
        TargetMigrationMachine::new(&target_rng, &clock).expect("target machine initialization");

    let (mut source_machine, commitment) =
        SourceMigrationMachine::from_engagement(engagement, &source_rng)
            .expect("source machine initialization");

    let ack = target_machine
        .process_commitment(commitment)
        .expect("target process commitment");

    let (revelation, _source_sas) = source_machine.process_ack(ack).expect("source process ack");

    let _target_sas = target_machine
        .process_revelation(revelation)
        .expect("target process revelation");

    // Caso 1: Origen intenta cifrar antes de que el titular confirme el código SAS
    let err_source = source_machine
        .encrypt_payload(&original_payload)
        .expect_err("encryption before SAS confirmation must fail");
    assert_eq!(err_source, RecoveryError::SasNotConfirmed);
    let gid_err: GidError = err_source.into();
    assert_eq!(gid_err.code, ErrorCode::ConsentPending);

    // Confirmar en el origen para generar un paquete
    source_machine.confirm_sas().expect("source confirm sas");
    let package = source_machine
        .encrypt_payload(&original_payload)
        .expect("source encrypt payload");

    // Caso 2: Destino intenta descifrar antes de que el titular confirme el código SAS en su pantalla
    let err_target = target_machine
        .receive_and_decrypt(package)
        .expect_err("decryption before SAS confirmation must fail");
    assert_eq!(err_target, RecoveryError::SasNotConfirmed);
    let gid_target_err: GidError = err_target.into();
    assert_eq!(gid_target_err.code, ErrorCode::ConsentPending);
}

// Verifies: REQ-REC-001
#[test]
fn test_mitm_ciphertext_tampering_fails_closed() {
    let target_rng = SeededRng::new(0x505);
    let source_rng = SeededRng::new(0x606);
    let clock = FixedClock::new(1_700_000_400);

    let original_payload = create_test_wallet_payload();

    let (mut target_machine, engagement) =
        TargetMigrationMachine::new(&target_rng, &clock).expect("target machine initialization");

    let (mut source_machine, commitment) =
        SourceMigrationMachine::from_engagement(engagement, &source_rng)
            .expect("source machine initialization");

    let ack = target_machine
        .process_commitment(commitment)
        .expect("target process commitment");

    let (revelation, _sas) = source_machine.process_ack(ack).expect("source process ack");

    let _ = target_machine
        .process_revelation(revelation)
        .expect("target process revelation");

    source_machine.confirm_sas().expect("confirm sas source");
    target_machine.confirm_sas().expect("confirm sas target");

    let mut package = source_machine
        .encrypt_payload(&original_payload)
        .expect("encrypt payload");

    // Manipulación maliciosa de 1 byte en el ciphertext cifrado con AEAD
    if let Some(b) = package.encrypted_data.get_mut(10) {
        *b ^= 0x55;
    }

    // El descifrado debe fallar de forma cerrada sin emitir información parcial
    let err = target_machine
        .receive_and_decrypt(package)
        .expect_err("tampered ciphertext must fail AEAD authentication");

    assert_eq!(err, RecoveryError::MigrationAeadFailed);
    let gid_err: GidError = err.into();
    assert_eq!(gid_err.code, ErrorCode::AeadAuthenticationFailed);
}

// Verifies: REQ-REC-001
#[test]
fn test_qr_format_and_tampered_uri_validation() {
    let target_rng = SeededRng::new(0x707);
    let clock = FixedClock::new(1_700_000_500);

    let (_target_machine, engagement) =
        TargetMigrationMachine::new(&target_rng, &clock).expect("target machine initialization");

    let valid_qr = engagement.to_qr_string();
    assert!(MigrationEngagement::from_qr_string(&valid_qr).is_ok());

    // 1. Prefijo inválido
    let invalid_prefix = valid_qr.replace("pip-migrate-v1", "pip-invalid-prefix");
    let err = MigrationEngagement::from_qr_string(&invalid_prefix).unwrap_err();
    assert_eq!(
        err,
        RecoveryError::InvalidMigrationMessage("prefijo de QR de migración desconocido")
    );

    // 2. Número de campos insuficiente
    let truncated_qr = "pip-migrate-v1:1234:5678";
    let err2 = MigrationEngagement::from_qr_string(truncated_qr).unwrap_err();
    assert_eq!(
        err2,
        RecoveryError::InvalidMigrationMessage("formato de QR de migración inválido")
    );

    // 3. Hexadecimal corrupto
    let corrupted_hex = valid_qr.replace(":04", ":ZZ");
    assert!(MigrationEngagement::from_qr_string(&corrupted_hex).is_err());
}

// Verifies: REQ-REC-001, REQ-REC-004
#[test]
fn test_migration_zero_hardware_private_keys_exported_audit() {
    let payload = create_test_wallet_payload();
    let json_bytes = payload.to_canonical_json().expect("to canonical json");
    let json_str = String::from_utf8(json_bytes).expect("valid utf-8");

    // Auditoría forense: La carga útil transferida NO debe contener claves privadas de hardware
    // ni etiquetas de clave privada ("d", "private_key", "secp256r1_secret", etc.)
    assert!(!json_str.contains("\"d\":"));
    assert!(!json_str.contains("private_key"));
    assert!(!json_str.contains("hardware_key"));
    assert!(!json_str.contains("keystore_secret"));

    // Contiene el recovery_secret para que el nuevo dispositivo derive las claves de re-vinculación
    assert!(json_str.contains("recovery_secret"));
    assert!(json_str.contains("cred-identity-01"));
    assert!(json_str.contains("cred-bank-01"));
}

// Verifies: REQ-REC-001
#[test]
fn test_migration_zero_pii_audit() {
    let target_rng = SeededRng::new(0x909);
    let source_rng = SeededRng::new(0xa0a);
    let clock = FixedClock::new(1_700_000_600);

    let (target_machine, engagement) =
        TargetMigrationMachine::new(&target_rng, &clock).expect("target machine initialization");

    let qr_string = engagement.to_qr_string();

    let (source_machine, commitment) =
        SourceMigrationMachine::from_engagement(engagement, &source_rng)
            .expect("source machine initialization");

    let transcript = compute_transcript(
        source_machine.target_id(),
        source_machine.public_key(),
        target_machine.public_key(),
        source_machine.nonce(),
        target_machine.nonce(),
    );

    let commitment_preimage = compute_commitment(
        source_machine.target_id(),
        target_machine.nonce(),
        source_machine.nonce(),
        source_machine.public_key(),
    );

    // Forense: Ningún mensaje de enganche, transcrito ni preimagen contiene datos personales
    let forbidden_pii = [
        "name", "nombre", "apellido", "cedula", "dni", "passport", "email", "phone", "mac", "imei",
        "serial", "panama",
    ];

    for term in forbidden_pii {
        assert!(
            !qr_string.to_lowercase().contains(term),
            "QR string contains PII term: {term}"
        );
        assert!(
            !transcript.to_lowercase().contains(term),
            "transcript contains PII term: {term}"
        );
    }

    assert_eq!(commitment.commitment.len(), 32);
    assert_eq!(commitment_preimage.len(), 32);
}
