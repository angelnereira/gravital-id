//! Pruebas de integración de la clave de recuperación del titular (`F8.T03`).
//!
//! Trazabilidad:
//! - **REQ-REC-004:** La clave de recuperación DEBE tener propósito exclusivo (`KeyPurpose::HolderRecovery`) y habilitar la re-vinculación.
//! - **REQ-REC-007:** Las claves de recuperación DEBEN derivarse por emisor; la misma huella NO DEBE registrarse ante dos emisores.
//! - **REQ-KEY-001:** Separación tipada de propósitos de clave en el sistema de tipos.
//! - **P-07 / P-09:** Aislamiento y no correlación entre emisores.
//! - **INV-02:** Cero datos personales o secretos en logs o errores.
//! - **INV-05:** Fail-closed ante parámetros vacíos o inconsistentes.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::format;
use std::string::String;
use std::vec::Vec;

use gravital_id_codec::json::{self, Value};
use gravital_id_credential::vc::SdJwtVcClaims;
use gravital_id_crypto::secret::{SecretBytes, SecretKeyBytes};
use gravital_id_crypto::sign::verify_es256_digest_jwk;
use gravital_id_issuer::request::StatusAllocation;
use gravital_id_issuer::{CredentialRequest, Issuer};
use gravital_id_keys::{HolderRecovery, KeyHandle, KeyPurpose, KeyStore, SoftwareKeyStore};
use gravital_id_recovery::kdf::{
    derive_backup_keys, derive_issuer_recovery_jwk, derive_issuer_recovery_thumbprint,
    derive_issuer_recovery_thumbprint_uri,
};
use gravital_id_recovery::key::HolderRecoveryKey;
use gravital_id_recovery::RecoveryCode;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ProfileId, UnixTime};

/// Verifies: REQ-REC-004, REQ-REC-007
#[test]
fn test_recovery_key_deterministic_derivation() {
    let rng = SeededRng::new(0xABCD_0001);
    let code = RecoveryCode::generate(&rng).expect("generate recovery code");
    let salt = [0x77u8; 16];
    let (_enc_key, rec_secret) = derive_backup_keys(code.entropy(), &salt).expect("derive keys");

    let issuer_id = "https://issuer.te.gob.pa";

    let key1 = HolderRecoveryKey::derive(&rec_secret, issuer_id).expect("derive 1");
    let key2 = HolderRecoveryKey::derive(&rec_secret, issuer_id).expect("derive 2");

    assert_eq!(key1.issuer_id(), issuer_id);
    assert_eq!(key2.issuer_id(), issuer_id);
    assert_eq!(key1.secret_bytes(), key2.secret_bytes());
    assert_eq!(
        key1.public_key().to_canonical_json(),
        key2.public_key().to_canonical_json()
    );
    assert_eq!(key1.thumbprint_sha256(), key2.thumbprint_sha256());
    assert_eq!(key1.thumbprint_base64url(), key2.thumbprint_base64url());
    assert_eq!(key1.thumbprint_uri(), key2.thumbprint_uri());

    // Funciones KDF de conveniencia
    let jwk_direct = derive_issuer_recovery_jwk(&rec_secret, issuer_id).expect("kdf jwk");
    assert_eq!(
        key1.public_key().to_canonical_json(),
        jwk_direct.to_canonical_json()
    );

    let tp_b64 = derive_issuer_recovery_thumbprint(&rec_secret, issuer_id).expect("kdf tp b64");
    assert_eq!(key1.thumbprint_base64url(), tp_b64);

    let tp_uri = derive_issuer_recovery_thumbprint_uri(&rec_secret, issuer_id).expect("kdf tp uri");
    assert_eq!(key1.thumbprint_uri(), tp_uri);
}

/// Verifies: REQ-REC-007, P-09 (aislamiento estricto y no correlación entre emisores)
#[test]
fn test_recovery_key_isolation_across_issuers() {
    let rng = SeededRng::new(0xABCD_0002);
    let code = RecoveryCode::generate(&rng).expect("generate code");
    let salt = [0x55u8; 16];
    let (_enc_key, rec_secret) = derive_backup_keys(code.entropy(), &salt).expect("derive keys");

    let issuers = [
        "https://issuer.te.gob.pa",
        "https://issuer.banco-nacional.pa",
        "https://issuer.utp.ac.pa",
        "https://issuer.minsa.gob.pa",
        "https://issuer.dgi.mef.gob.pa",
        "https://issuer.css.gob.pa",
        "https://issuer.mitradel.gob.pa",
        "https://issuer.asep.gob.pa",
        "https://issuer.uip.edu.pa",
        "https://issuer.registro-publico.gob.pa",
    ];

    let mut keys: Vec<HolderRecoveryKey> = Vec::new();
    for &iss in &issuers {
        let key = HolderRecoveryKey::derive(&rec_secret, iss).expect("derive key");
        assert!(key
            .thumbprint_uri()
            .starts_with("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"));
        // 43 caracteres base64url sin relleno para SHA-256 (32 bytes * 8 / 6 = 42.66 -> 43 chars)
        assert_eq!(key.thumbprint_base64url().len(), 43);
        keys.push(key);
    }

    // Comprobación de todas las parejas: ningún par comparte clave privada, pública ni huella
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            let key_i = &keys[i];
            let key_j = &keys[j];

            assert_ne!(
                key_i.secret_bytes(),
                key_j.secret_bytes(),
                "colisión de clave privada entre {} y {}",
                key_i.issuer_id(),
                key_j.issuer_id()
            );

            assert_ne!(
                key_i.public_key().to_canonical_json(),
                key_j.public_key().to_canonical_json(),
                "colisión de clave pública entre {} y {}",
                key_i.issuer_id(),
                key_j.issuer_id()
            );

            assert_ne!(
                key_i.thumbprint_sha256(),
                key_j.thumbprint_sha256(),
                "colisión de digest sha256 entre {} y {}",
                key_i.issuer_id(),
                key_j.issuer_id()
            );

            assert_ne!(
                key_i.thumbprint_base64url(),
                key_j.thumbprint_base64url(),
                "colisión de huella base64url entre {} y {}",
                key_i.issuer_id(),
                key_j.issuer_id()
            );

            assert_ne!(
                key_i.thumbprint_uri(),
                key_j.thumbprint_uri(),
                "colisión de huella URI entre {} y {}",
                key_i.issuer_id(),
                key_j.issuer_id()
            );
        }
    }
}

/// Verifies: REQ-REC-007
#[test]
fn test_recovery_key_different_seeds_different_keys() {
    let rng1 = SeededRng::new(0x1111);
    let rng2 = SeededRng::new(0x2222);

    let code1 = RecoveryCode::generate(&rng1).expect("code 1");
    let code2 = RecoveryCode::generate(&rng2).expect("code 2");

    let salt = [0xAAu8; 16];
    let (_, rec_sec1) = derive_backup_keys(code1.entropy(), &salt).expect("keys 1");
    let (_, rec_sec2) = derive_backup_keys(code2.entropy(), &salt).expect("keys 2");

    let iss = "https://issuer.te.gob.pa";
    let key1 = HolderRecoveryKey::derive(&rec_sec1, iss).expect("key 1");
    let key2 = HolderRecoveryKey::derive(&rec_sec2, iss).expect("key 2");

    assert_ne!(key1.secret_bytes(), key2.secret_bytes());
    assert_ne!(key1.thumbprint_uri(), key2.thumbprint_uri());
}

/// Verifies: REQ-REC-004, REQ-KEY-001 (separación tipada y propósito exclusivo)
#[test]
fn test_key_purpose_holder_recovery_type_safety() {
    // 1. Invariantes del enum KeyPurpose
    let purpose = KeyPurpose::HolderRecovery;
    assert_eq!(purpose.as_str(), "holder-recovery");
    assert!(purpose.allows_signing());
    assert!(!purpose.allows_key_agreement());

    assert_ne!(purpose, KeyPurpose::HolderBinding);
    assert_ne!(purpose, KeyPurpose::IssuerSigning);
    assert_ne!(purpose, KeyPurpose::VerifierRequest);
    assert_ne!(purpose, KeyPurpose::StatusListSigning);
    assert_ne!(purpose, KeyPurpose::TrustRoot);
    assert_ne!(purpose, KeyPurpose::TrustBundle);
    assert_ne!(purpose, KeyPurpose::HpkeKeyAgreement);

    // 2. Operación con SoftwareKeyStore y propósito HolderRecovery
    let rng = SeededRng::new(0x3333);
    let code = RecoveryCode::generate(&rng).expect("code");
    let salt = [0xBBu8; 16];
    let (_, rec_sec) = derive_backup_keys(code.entropy(), &salt).expect("keys");

    let iss = "https://issuer.te.gob.pa";
    let recovery_key = HolderRecoveryKey::derive(&rec_sec, iss).expect("key");

    let mut store = SoftwareKeyStore::new(SeededRng::new(0x4444));
    let kid = recovery_key.thumbprint_base64url();
    let sec_key_bytes = SecretKeyBytes::new(*recovery_key.secret_bytes().expose_secret());

    store.insert_key(
        &kid,
        KeyPurpose::HolderRecovery,
        sec_key_bytes,
        recovery_key.public_key().clone(),
        None,
    );

    // KeyHandle tipado con HolderRecovery
    let handle: KeyHandle<HolderRecovery> = KeyHandle::new(&kid);
    assert_eq!(handle.purpose(), KeyPurpose::HolderRecovery);
    assert_eq!(handle.id(), kid.as_str());

    // Firma con la clave de recuperación
    let challenge = b"rebinding-challenge-nonce-1234567890123456";
    let digest = gravital_id_crypto::sha256(challenge);
    let signature = store
        .sign_digest(handle.id(), &digest)
        .expect("sign rebinding challenge with HolderRecovery key");

    // Verificación de la firma con la clave pública de recuperación
    verify_es256_digest_jwk(recovery_key.public_key(), &digest, &signature)
        .expect("la firma del desafío de recuperación debe ser matemáticamente válida");
}

/// Verifies: REQ-REC-004, REQ-REC-007, PROTOCOL.md §2.2
#[test]
fn test_credential_issuance_with_recovery_thumbprint_extension() {
    let rng = SeededRng::new(0x5555);
    let code = RecoveryCode::generate(&rng).expect("code");
    let salt = [0xCCu8; 16];
    let (_, rec_sec) = derive_backup_keys(code.entropy(), &salt).expect("keys");

    let issuer_id = "https://issuer.te.gob.pa";
    let recovery_key = HolderRecoveryKey::derive(&rec_sec, issuer_id).expect("rec key");
    let rec_uri = recovery_key.thumbprint_uri();

    // Generar par de clave del titular para binding de presentaciones (HolderBinding)
    let holder_rng = SeededRng::new(0x6666);
    let holder_sec = gravital_id_crypto::generate_p256_secret_key(&holder_rng).expect("holder sec");
    let holder_jwk =
        gravital_id_crypto::public_key_from_secret_key(&holder_sec).expect("holder pub");

    // Construir CredentialRequest con extensión de recuperación
    let issued_at = UnixTime::from_seconds(1_791_633_600);
    let profile = ProfileId::parse("pip-personal-v1").expect("profile");
    let request = CredentialRequest::new(issuer_id, profile, issued_at)
        .expect("request new")
        .attribute("given_name", Value::String("Maria".to_string()))
        .expect("given_name")
        .attribute("family_name", Value::String("Gonzalez".to_string()))
        .expect("family_name")
        .attribute("birth_date", Value::String("1990-05-15".to_string()))
        .expect("birth_date")
        .status(
            StatusAllocation::new(42, "https://issuer.te.gob.pa/status/list-1").expect("status"),
        )
        .holder_key(holder_jwk.clone())
        .recovery_thumbprint(&rec_uri);

    assert_eq!(request.recovery_thumbprint_ref(), Some(rec_uri.as_str()));

    // Configurar emisor y su clave de firma
    let issuer_rng = SeededRng::new(0x7777);
    let mut issuer_store = SoftwareKeyStore::new(issuer_rng);
    let issuer_sec =
        gravital_id_crypto::generate_p256_secret_key(&SeededRng::new(0x8888)).expect("iss sec");
    let issuer_jwk = gravital_id_crypto::public_key_from_secret_key(&issuer_sec).expect("iss pub");
    let issuer_kid = "iss-key-2026";
    issuer_store.insert_key(
        issuer_kid,
        KeyPurpose::IssuerSigning,
        issuer_sec,
        issuer_jwk,
        None,
    );
    let signing_handle: KeyHandle<gravital_id_keys::IssuerSigning> = KeyHandle::new(issuer_kid);

    // Emitir credencial con la extensión
    let sign_rng = SeededRng::new(0x9999);
    let issued = Issuer::issue(
        &request,
        &issuer_store,
        &signing_handle,
        Some(gravital_id_types::Kid::parse(issuer_kid).expect("kid")),
        &sign_rng,
    )
    .expect("issue credential");

    // Verificar getter de IssuedCredential
    assert_eq!(issued.recovery_thumbprint(), Some(rec_uri.as_str()));

    // Parsear payload SD-JWT VC para verificar la estructura cnf.rec
    let compact = issued.compact();
    let parts: Vec<&str> = compact.split('~').collect();
    let jwt = parts[0];
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(jwt_parts.len(), 3);

    let payload_bytes = gravital_id_codec::base64url::decode_bounded(jwt_parts[1], 4096)
        .expect("b64 decode payload");
    let payload_val = json::parse_bytes(&payload_bytes, &json::Limits::profile_default())
        .expect("parse payload json");

    let cnf_val = payload_val.member("cnf").expect("cnf member in payload");
    let rec_in_cnf = cnf_val
        .member("rec")
        .and_then(Value::as_str)
        .expect("rec member in cnf");
    assert_eq!(rec_in_cnf, rec_uri);

    let jwk_in_cnf = cnf_val.member("jwk").expect("jwk member in cnf");
    assert_eq!(
        jwk_in_cnf.member("x").and_then(Value::as_str),
        Some(holder_jwk.x_base64url().as_str())
    );

    // Verificación offline con SdJwtVcClaims
    let claims = SdJwtVcClaims {
        iss: issuer_id.to_string(),
        vct: gravital_id_types::Vct::parse("https://spec.gravital.id/v1/personal").expect("vct"),
        iat: issued_at,
        nbf: None,
        exp: None,
        cnf: Some(
            gravital_id_credential::vc::ConfirmationClaim::with_recovery_thumbprint(
                holder_jwk, &rec_uri,
            ),
        ),
        status: None,
    };
    assert_eq!(
        claims.cnf.as_ref().and_then(|c| c.recovery_thumbprint()),
        Some(rec_uri.as_str())
    );
}

/// Verifies: INV-02 (Cero datos personales o secretos en la extensión de recuperación)
#[test]
fn test_zero_pii_in_recovery_extension() {
    let rng = SeededRng::new(0xAAAA);
    let code = RecoveryCode::generate(&rng).expect("code");
    let salt = [0xDDu8; 16];
    let (_, rec_sec) = derive_backup_keys(code.entropy(), &salt).expect("keys");

    let issuer_id = "https://issuer.te.gob.pa";
    let recovery_key = HolderRecoveryKey::derive(&rec_sec, issuer_id).expect("rec key");
    let rec_uri = recovery_key.thumbprint_uri();
    let rec_b64 = recovery_key.thumbprint_base64url();

    let pii_samples = [
        "Juan",
        "Perez",
        "8-123-4567",
        "maria@gmail.com",
        "1990-05-15",
        "Panama",
        "calle",
        "avenida",
    ];

    for sample in &pii_samples {
        assert!(
            !rec_uri.to_lowercase().contains(&sample.to_lowercase()),
            "la URI de recuperación no debe contener PII: {sample}"
        );
        assert!(
            !rec_b64.to_lowercase().contains(&sample.to_lowercase()),
            "la huella base64url no debe contener PII: {sample}"
        );
    }

    // Comprobar que no contenga el secreto de recuperación en claro
    let secret_hex: String = rec_sec
        .expose_secret()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        !rec_uri.contains(&secret_hex),
        "la URI no debe exponer el secreto en claro"
    );
}

/// Verifies: INV-05 (Fail-closed ante emisor vacío)
#[test]
fn test_recovery_key_empty_issuer_fails_closed() {
    let rec_sec = SecretBytes::new([0x88u8; 32]);
    let res = HolderRecoveryKey::derive(&rec_sec, "");
    assert!(matches!(
        res,
        Err(gravital_id_recovery::RecoveryError::KeyDerivationFailed(_))
    ));
}

/// Verifies: REQ-SEC-003, INV-02 (Redacción estricta en Debug)
#[test]
fn test_recovery_key_debug_redaction() {
    let rec_sec = SecretBytes::new([0x77u8; 32]);
    let key = HolderRecoveryKey::derive(&rec_sec, "https://issuer.te.gob.pa").expect("derive");
    let debug_repr = format!("{key:?}");

    assert!(debug_repr.contains("[REDACTED]"));
    assert!(debug_repr.contains("https://issuer.te.gob.pa"));

    let sec_hex: String = key
        .secret_bytes()
        .expose_secret()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        !debug_repr.contains(&sec_hex),
        "Debug no debe filtrar la clave privada"
    );
}
