//! Pruebas de integración, propiedades, negativas y forenses para recuperación y respaldo (`F8.T01`).
//!
//! Trazabilidad:
//! - `REQ-REC-002`: Código de recuperación (≥128 bits de entropía, mnemónico 12 palabras BIP-39 y compacto Crockford Base32 con checksum) y respaldo cifrado.
//! - `REQ-REC-004`: Claves de recuperación con propósito exclusivo (`HolderRecovery`).
//! - `REQ-REC-007`: Derivación de claves de recuperación por emisor mediante HKDF determinista; aislamiento estricto de huellas.
//! - `INV-01`: Sans-I/O y `no_std` en capa L3.
//! - `INV-02`: Ausencia absoluta de datos personales o identificadores en claro en el respaldo.
//! - `INV-05`: Fail-closed ante cualquier alteración de un solo bit en cabecera o criptograma.
//! - `INV-10`: Sin panics o unwraps no controlados ante datos hostiles o malformados.
//! - `INV-11`: Determinismo e inyección de generadores de aleatoriedad.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_recovery::{
    derive_issuer_recovery_jwk, derive_issuer_recovery_secret, BackupCredential, BackupDeviceSlot,
    BackupPayload, BackupTenantRole, EncryptedBackupPackage, RecoveryCode, RecoveryError,
    RecoveryManager, BACKUP_HEADER_LEN, BACKUP_MAGIC_GIDB,
};
use gravital_id_testkit::SeededRng;
use gravital_id_types::UnixTime;

// // Verifies: REQ-REC-002 (Ciclo completo: código -> exportar -> restaurar)
#[test]
fn e2e_recovery_export_and_restore_cycle() {
    let rng = SeededRng::new(0xCAFE);
    let code = RecoveryCode::generate(&rng).expect("generate recovery code");
    let now = UnixTime::from_seconds(1_780_000_000);

    let pii_identifier = "8-765-4321";
    let pii_name = "Carlos Rodriguez";

    let credentials = vec![
        BackupCredential {
            id: "cred-cedula-panama".into(),
            vct: "https://credentials.te.gob.pa/vct/cedula-v1".into(),
            issuer: "https://issuer.te.gob.pa".into(),
            serialized_sd_jwt: format!(
                "header.payload.{pii_name}.{pii_identifier}.sig~disclosure1~"
            ),
        },
        BackupCredential {
            id: "cred-licencia-conducir".into(),
            vct: "https://credentials.att.gob.pa/vct/licencia-v1".into(),
            issuer: "https://issuer.att.gob.pa".into(),
            serialized_sd_jwt: "licencia.header.payload.sig~disclosure~".into(),
        },
    ];

    let device_slots = vec![
        BackupDeviceSlot {
            device_factor_class: "secure_element".into(),
            status_index: 10,
        },
        BackupDeviceSlot {
            device_factor_class: "biometric_key".into(),
            status_index: 20,
        },
    ];

    let tenant_roles = vec![BackupTenantRole {
        tenant_id: "hospital-san-fernando".into(),
        role_vct: "urn:pip:tenant:role:medico".into(),
        tenant_subject_id: "emp-8899".into(),
    }];

    let master_recovery_secret = SecretBytes::new([0x33; 32]);
    let payload = BackupPayload::new(
        master_recovery_secret,
        credentials.clone(),
        device_slots.clone(),
        tenant_roles.clone(),
        now,
    );

    // Exportar respaldo
    let backup_package =
        RecoveryManager::export_backup(&payload, &code, now, &rng).expect("export must succeed");

    assert_eq!(&backup_package[..4], &BACKUP_MAGIC_GIDB);
    assert!(backup_package.len() > BACKUP_HEADER_LEN);

    // Restaurar respaldo con código de recuperación
    let restored =
        RecoveryManager::restore_backup(&backup_package, &code).expect("restore must succeed");

    assert_eq!(restored.schema_version, payload.schema_version);
    assert_eq!(restored.recovery_secret, payload.recovery_secret);
    assert_eq!(restored.created_at, payload.created_at);
    assert_eq!(restored.credentials, payload.credentials);
    assert_eq!(restored.device_slots, payload.device_slots);
    assert_eq!(restored.tenant_roles, payload.tenant_roles);
}

// // Verifies: INV-02 (Auditoría forense de ausencia de PII en claro en el paquete de respaldo)
#[test]
fn test_zero_pii_in_backup_package() {
    let rng = SeededRng::new(0x1337);
    let code = RecoveryCode::generate(&rng).expect("generate recovery code");
    let now = UnixTime::from_seconds(1_780_000_000);

    let confidential_data = [
        "8-765-4321",
        "Carlos Rodriguez",
        "panama",
        "licencia-conducir",
        "hospital-san-fernando",
        "emp-8899",
    ];

    let payload = BackupPayload::new(
        SecretBytes::new([0x77; 32]),
        vec![BackupCredential {
            id: "cred-01".into(),
            vct: "https://credentials.te.gob.pa/vct/cedula-v1".into(),
            issuer: "https://issuer.te.gob.pa".into(),
            serialized_sd_jwt: "carlos-rodriguez-8-765-4321".into(),
        }],
        vec![],
        vec![BackupTenantRole {
            tenant_id: "hospital-san-fernando".into(),
            role_vct: "urn:pip:tenant:role:medico".into(),
            tenant_subject_id: "emp-8899".into(),
        }],
        now,
    );

    let backup_package =
        RecoveryManager::export_backup(&payload, &code, now, &rng).expect("export must succeed");

    // Verificar que ninguna cadena confidencial aparezca en claro en el paquete cifrado
    for secret in &confidential_data {
        let needle = secret.as_bytes();
        let found = backup_package
            .windows(needle.len())
            .any(|window| window == needle);
        assert!(
            !found,
            "VIOLACIÓN INV-02: El dato confidencial '{secret}' apareció en claro en el paquete binario"
        );
    }
}

// // Verifies: REQ-REC-007, REQ-REC-004 (Aislamiento de claves de recuperación por emisor)
#[test]
fn test_per_issuer_recovery_keys_uncorrelated() {
    let recovery_secret = SecretBytes::new([0xAA; 32]);

    let iss1 = "https://tribunal-electoral.gob.pa";
    let iss2 = "https://banco-general.com";
    let iss3 = "https://caja-seguro-social.gob.pa";

    let key1 = derive_issuer_recovery_secret(&recovery_secret, iss1).expect("k1");
    let key2 = derive_issuer_recovery_secret(&recovery_secret, iss2).expect("k2");
    let key3 = derive_issuer_recovery_secret(&recovery_secret, iss3).expect("k3");

    // Las claves deben ser estrictamente diferentes
    assert_ne!(key1, key2);
    assert_ne!(key2, key3);
    assert_ne!(key1, key3);

    let jwk1 = derive_issuer_recovery_jwk(&recovery_secret, iss1).expect("jwk1");
    let jwk2 = derive_issuer_recovery_jwk(&recovery_secret, iss2).expect("jwk2");
    let jwk3 = derive_issuer_recovery_jwk(&recovery_secret, iss3).expect("jwk3");

    // Los JWKs públicos nunca deben coincidir ni permitir correlación (P-09, INV-02)
    assert_ne!(jwk1.to_canonical_json(), jwk2.to_canonical_json());
    assert_ne!(jwk2.to_canonical_json(), jwk3.to_canonical_json());
    assert_ne!(jwk1.to_canonical_json(), jwk3.to_canonical_json());
}

// // Verifies: INV-05 (Fail-closed: alteración de cualquier bit en el paquete produce error)
#[test]
fn test_fail_closed_on_bit_tampering() {
    let rng = SeededRng::new(0x5555);
    let code = RecoveryCode::generate(&rng).expect("generate recovery code");
    let now = UnixTime::from_seconds(1_780_000_000);

    let payload = BackupPayload::new(
        SecretBytes::new([0x88; 32]),
        vec![BackupCredential {
            id: "cred-01".into(),
            vct: "vct:example".into(),
            issuer: "iss:example".into(),
            serialized_sd_jwt: "header.payload.sig~".into(),
        }],
        vec![],
        vec![],
        now,
    );

    let valid_package =
        RecoveryManager::export_backup(&payload, &code, now, &rng).expect("export must succeed");

    // Probar mutación de 1 solo bit en diferentes posiciones estratégicas
    let offsets_to_test = [
        0,                       // Primer byte de número mágico ('G')
        3,                       // Último byte de número mágico ('B')
        4,                       // Versión de formato
        6,                       // Cipher suite
        7,                       // Timestamp created_at
        15,                      // Salt
        31,                      // Nonce
        BACKUP_HEADER_LEN,       // Primer byte de ciphertext
        BACKUP_HEADER_LEN + 10,  // Byte intermedio de ciphertext
        valid_package.len() - 1, // Último byte (Poly1305 auth tag)
    ];

    for &offset in &offsets_to_test {
        let mut tampered = valid_package.clone();
        tampered[offset] ^= 0x01; // flip 1 bit

        let result = RecoveryManager::restore_backup(&tampered, &code);
        assert!(
            result.is_err(),
            "VIOLACIÓN INV-05: El paquete alterado en offset {offset} fue aceptado"
        );
        match result {
            Err(RecoveryError::DecryptionFailed) | Err(RecoveryError::InvalidBackupHeader(_)) => {
                // Comportamiento correcto fail-closed
            }
            Err(other) => {
                panic!("Error inesperado al rechazar manipulación en offset {offset}: {other:?}");
            }
            Ok(_) => unreachable!(),
        }
    }
}

// // Verifies: REQ-REC-002 (Propiedades y roundtrip de mnemónico y base32 compacto)
#[test]
fn test_recovery_code_property_roundtrips() {
    let rng = SeededRng::new(0x7777);

    for seed in 0..100 {
        let code = RecoveryCode::generate(&rng).expect("generate code");

        // 1. Mnemónico 12 palabras
        let mnemonic = code.to_mnemonic();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(
            words.len(),
            12,
            "Semilla {seed}: Mnemónico debe tener 12 palabras"
        );

        let from_mnemonic = RecoveryCode::from_mnemonic(&mnemonic)
            .expect("Mnemónico generado debe deserializarse sin error");
        assert_eq!(code.entropy(), from_mnemonic.entropy());

        // 2. Base32 Crockford compacto con checksum (27 caracteres alfanuméricos agrupados con guiones: 33 caracteres)
        let compact = code.to_compact_code();
        assert_eq!(
            compact.len(),
            33,
            "Semilla {seed}: Compacto formateado debe tener 33 caracteres"
        );
        assert_eq!(
            compact.chars().filter(|c| *c != '-').count(),
            27,
            "Semilla {seed}: Compacto debe contener 27 caracteres Crockford"
        );

        let from_compact = RecoveryCode::from_compact_code(&compact)
            .expect("Código compacto generado debe deserializarse sin error");
        assert_eq!(code.entropy(), from_compact.entropy());
    }
}

// // Verifies: INV-10 (Ausencia de pánicos ante entradas hostiles arbitrarias)
#[test]
fn test_fuzz_style_arbitrary_inputs_no_panics() {
    let rng = SeededRng::new(0xDEAD);
    let code = RecoveryCode::generate(&rng).expect("generate code");

    let hostile_inputs: &[&[u8]] = &[
        b"",
        b"GID",
        b"GIDB",
        &[0u8; 10],
        &[0xFFu8; 55],
        &[0xAAu8; 100],
        b"GIDB\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ];

    for &hostile in hostile_inputs {
        let res = EncryptedBackupPackage::open(hostile, &code);
        assert!(res.is_err(), "Entrada hostil debe ser rechazada");
    }

    let hostile_mnemonics = [
        "",
        "abandon",
        "abandon ability able about above absent absorb abstract absurd abuse access",
        "abandon ability able about above absent absorb abstract absurd abuse access invalidwordxyz",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
    ];

    for hostile in &hostile_mnemonics {
        let res = RecoveryCode::from_mnemonic(hostile);
        // Debe retornar Err o fallar checksum, nunca entrar en pánico
        let _ = res;
    }
}
