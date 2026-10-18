//! Pruebas de integración de re-vinculación y reemplazo atómico por clase de dispositivo (`F8.T04`).
//!
//! Trazabilidad:
//! - **REQ-REC-004:** La clave de recuperación DEBE tener propósito exclusivo (`KeyPurpose::HolderRecovery`) y habilitar la re-vinculación.
//! - **REQ-REC-007:** Claves de recuperación aisladas por emisor; huellas no correlacionables.
//! - **REQ-ISS-006:** Soporte de emisión / re-emisión y re-vinculación con gestión de estados.
//! - **REQ-DEVSLOT-001:** Ranura única por clase de dispositivo (`mobile`, `card`, `other`). Exclusión mutua dentro de la misma clase.
//! - **REQ-DEVSLOT-002:** Independencia entre clases (un titular puede portar 1 móvil y 1 tarjeta simultáneamente).
//! - **REQ-DEVSLOT-003:** Reemplazo atómico por clase: al re-vincular un móvil, se revoca atómicamente el móvil previo en la
//!   `TokenStatusList`, mientras que la tarjeta física permanece activa y válida.
//! - **REQ-DEVSLOT-004:** Cero identificadores permanentes de hardware en claro (IMEI, MAC, etc.) ni en logs ni en transcritos.
//! - **ADR-0029:** Ranura única por clase de dispositivo y reemplazo atómico.
//! - **SPEC-PIP-REBIND-001:** Transcrito canónico de re-vinculación y flujo de desafío/respuesta.
//! - **INV-01 / INV-02 / INV-03 / INV-05 / INV-10 / INV-11.**

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_codec::json::Value;
use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_issuer::slot_manager::{ActiveDeviceSlot, DeviceSlotManager};
use gravital_id_issuer::status_manager::IssuerStatusManager;
use gravital_id_issuer::{
    CredentialRequest, Issuer, IssuerSigningContext, RebindingExecutionParams, TokenStatus,
};
use gravital_id_keys::{IssuerSigning, KeyHandle, KeyPurpose, SoftwareKeyStore};
use gravital_id_recovery::kdf::derive_backup_keys;
use gravital_id_recovery::key::HolderRecoveryKey;
use gravital_id_recovery::rebinding::{compute_rebinding_transcript, RebindingChallenge};
use gravital_id_recovery::RecoveryCode;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{DeviceFactorClass, ErrorCode, Kid, ProfileId, UnixTime};

fn setup_test_issuer(
    issuer_uri: &str,
    status_list_id: &str,
    rng: &SeededRng,
) -> (
    IssuerStatusManager,
    DeviceSlotManager,
    SoftwareKeyStore<SeededRng>,
    KeyHandle<IssuerSigning>,
    Kid,
) {
    let mut status_manager =
        IssuerStatusManager::new(issuer_uri, 1).expect("create status manager");
    status_manager
        .register_status_list(
            status_list_id,
            2,
            131072,
            format!("{issuer_uri}/status/{status_list_id}"),
        )
        .expect("register status list");

    let slot_manager = DeviceSlotManager::new();

    let mut key_store = SoftwareKeyStore::new(rng.clone());
    let iss_sec = generate_p256_secret_key(rng).expect("issuer sec key");
    let iss_pub = public_key_from_secret_key(&iss_sec).expect("issuer pub key");
    let kid_str = "iss-rebinding-key-1";
    key_store.insert_key(kid_str, KeyPurpose::IssuerSigning, iss_sec, iss_pub, None);

    let signing_handle = KeyHandle::new(kid_str);
    let kid = Kid::parse(kid_str).expect("kid parse");

    (status_manager, slot_manager, key_store, signing_handle, kid)
}

/// Verifies: REQ-REC-004, REQ-ISS-006, REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, ADR-0029, SPEC-PIP-REBIND-001
#[test]
fn test_e2e_atomic_rebinding_device_slots() {
    let rng = SeededRng::new(0x2026_0104);
    let issuer_uri = "https://identity.panama.gob.pa";
    let status_list_id = "sl-id-panama-v1";

    let (mut status_manager, mut slot_manager, key_store, signing_handle, kid) =
        setup_test_issuer(issuer_uri, status_list_id, &rng);

    // 1. Titular inicializa su código de recuperación y deriva su clave de recuperación ante el emisor
    let rec_code = RecoveryCode::generate(&rng).expect("generate recovery code");
    let salt = [0x55u8; 16];
    let (_enc_key, rec_secret) =
        derive_backup_keys(rec_code.entropy(), &salt).expect("derive keys");
    let recovery_key = HolderRecoveryKey::derive(&rec_secret, issuer_uri).expect("recovery key");
    let rec_thumbprint_uri = recovery_key.thumbprint_uri();

    let now = UnixTime::from_seconds(1_791_640_000);
    let profile = ProfileId::parse("pip-personal-v1").expect("profile parse");

    // 2. Alta inicial de Dispositivo 1 (Teléfono Móvil - DeviceFactorClass::Mobile)
    let phone1_sec = generate_p256_secret_key(&rng).expect("phone1 sec");
    let phone1_jwk = public_key_from_secret_key(&phone1_sec).expect("phone1 jwk");

    let (_sl_id, phone1_alloc) = status_manager
        .allocate_with_list_id(Some(status_list_id), &rng)
        .expect("allocate phone1");
    let phone1_index = phone1_alloc.idx;

    let phone1_request = CredentialRequest::new(issuer_uri, profile.clone(), now)
        .expect("phone1 request")
        .attribute("given_name", Value::String("Angel".into()))
        .expect("given_name")
        .attribute("family_name", Value::String("Nereira".into()))
        .expect("family_name")
        .attribute("birth_date", Value::String("1990-01-01".into()))
        .expect("birth_date")
        .holder_key(phone1_jwk.clone())
        .recovery_thumbprint(&rec_thumbprint_uri)
        .status(phone1_alloc);

    let phone1_cred = Issuer::issue(
        &phone1_request,
        &key_store,
        &signing_handle,
        Some(kid.clone()),
        &rng,
    )
    .expect("issue phone1 credential");
    assert_eq!(phone1_cred.status_index(), Some(phone1_index));

    let phone1_slot = ActiveDeviceSlot {
        device_class: DeviceFactorClass::Mobile,
        status_list_id: status_list_id.into(),
        status_index: phone1_index,
        holder_key: phone1_jwk.clone(),
        issued_at: now,
        expires_at: None,
    };
    slot_manager
        .register_initial_slot(&rec_thumbprint_uri, phone1_slot)
        .expect("register initial phone1 slot");

    // 3. REQ-DEVSLOT-002: Alta inicial de Dispositivo 2 (Tarjeta Inteligente Física Tipo Visa - DeviceFactorClass::Card)
    // Coexistencia permitida entre diferentes clases de factor
    let card_sec = generate_p256_secret_key(&rng).expect("card sec");
    let card_jwk = public_key_from_secret_key(&card_sec).expect("card jwk");

    let (_sl_id, card_alloc) = status_manager
        .allocate_with_list_id(Some(status_list_id), &rng)
        .expect("allocate card");
    let card_index = card_alloc.idx;

    let card_request = CredentialRequest::new(issuer_uri, profile.clone(), now)
        .expect("card request")
        .attribute("given_name", Value::String("Angel".into()))
        .expect("given_name")
        .attribute("family_name", Value::String("Nereira".into()))
        .expect("family_name")
        .attribute("birth_date", Value::String("1990-01-01".into()))
        .expect("birth_date")
        .holder_key(card_jwk.clone())
        .recovery_thumbprint(&rec_thumbprint_uri)
        .status(card_alloc);

    let card_cred = Issuer::issue(
        &card_request,
        &key_store,
        &signing_handle,
        Some(kid.clone()),
        &rng,
    )
    .expect("issue card credential");
    assert_eq!(card_cred.status_index(), Some(card_index));

    let card_slot = ActiveDeviceSlot {
        device_class: DeviceFactorClass::Card,
        status_list_id: status_list_id.into(),
        status_index: card_index,
        holder_key: card_jwk.clone(),
        issued_at: now,
        expires_at: None,
    };
    slot_manager
        .register_initial_slot(&rec_thumbprint_uri, card_slot)
        .expect("register initial card slot");

    // Comprobar estado previo:
    // Ambos dispositivos están 100 % activos y válidos en la Token Status List
    assert_eq!(
        status_manager
            .status_of(status_list_id, phone1_index)
            .expect("check phone1 status"),
        TokenStatus::Valid
    );
    assert_eq!(
        status_manager
            .status_of(status_list_id, card_index)
            .expect("check card status"),
        TokenStatus::Valid
    );
    assert!(slot_manager.has_active_slot(&rec_thumbprint_uri, DeviceFactorClass::Mobile));
    assert!(slot_manager.has_active_slot(&rec_thumbprint_uri, DeviceFactorClass::Card));
    assert_eq!(
        slot_manager
            .active_slots_for_holder(&rec_thumbprint_uri)
            .len(),
        2
    );

    // 4. REQ-DEVSLOT-001: Intentar registrar un Teléfono Móvil 2 sin protocolo de re-vinculación DEBE fallar
    let phone2_sec = generate_p256_secret_key(&rng).expect("phone2 sec");
    let phone2_jwk = public_key_from_secret_key(&phone2_sec).expect("phone2 jwk");
    let duplicate_phone_slot = ActiveDeviceSlot {
        device_class: DeviceFactorClass::Mobile,
        status_list_id: status_list_id.into(),
        status_index: 9999,
        holder_key: phone2_jwk.clone(),
        issued_at: now,
        expires_at: None,
    };
    let duplicate_err = slot_manager
        .register_initial_slot(&rec_thumbprint_uri, duplicate_phone_slot)
        .unwrap_err();
    assert_eq!(duplicate_err.code, ErrorCode::DuplicateDeviceClassActive);

    // 5. Flujo de Re-vinculación y Reemplazo Atómico (SPEC-PIP-REBIND-001, ADR-0029, REQ-DEVSLOT-003):
    // El titular perdió su Teléfono Móvil 1 o migró a Teléfono Móvil 2.
    // Paso a: Emisor crea RebindingChallenge
    let challenge_now = UnixTime::from_seconds(1_791_640_100);
    let expires_at = UnixTime::from_seconds(1_791_640_400); // 300 segundos de validez
    let challenge =
        RebindingChallenge::new(issuer_uri, "nonce-rebind-unique-token-442211", expires_at)
            .expect("challenge new");

    // Paso b: Titular genera RebindingRequest firmado con su HolderRecoveryKey
    let rebinding_req = recovery_key
        .create_rebinding_request(
            &challenge,
            DeviceFactorClass::Mobile,
            phone2_jwk.clone(),
            challenge_now,
        )
        .expect("create rebinding request");

    // Verificar en el cliente la firma
    assert!(rebinding_req
        .verify(&challenge, recovery_key.public_key(), challenge_now)
        .is_ok());

    // Paso c: Emisor recibe RebindingRequest y ejecuta execute_atomic_rebinding
    let base_req = CredentialRequest::new(issuer_uri, profile, challenge_now)
        .expect("base req")
        .attribute("given_name", Value::String("Angel".into()))
        .expect("given_name")
        .attribute("family_name", Value::String("Nereira".into()))
        .expect("family_name")
        .attribute("birth_date", Value::String("1990-01-01".into()))
        .expect("birth_date")
        .recovery_thumbprint(&rec_thumbprint_uri);

    let params = RebindingExecutionParams {
        issuer_uri: rebinding_req.issuer_uri(),
        nonce: rebinding_req.nonce(),
        challenge_expires_at: challenge.expires_at(),
        device_class: rebinding_req.device_class(),
        new_holder_key: rebinding_req.new_holder_key().clone(),
        recovery_public_key: recovery_key.public_key(),
        signature: rebinding_req.signature(),
        preferred_status_list_id: Some(status_list_id),
        now: challenge_now,
    };
    let signing_ctx = IssuerSigningContext {
        key_store: &key_store,
        signing_key: &signing_handle,
        kid: Some(kid),
        rng: &rng,
    };

    let rebinding_result = slot_manager
        .execute_atomic_rebinding(&params, &base_req, &mut status_manager, &signing_ctx)
        .expect("execute atomic rebinding");

    // 6. Verificación de la Semántica Atómica (REQ-DEVSLOT-003, ADR-0029):
    // a) El slot previo de Mobile (phone1) fue revocado
    let revoked = rebinding_result
        .revoked_slot
        .expect("must return revoked slot");
    assert_eq!(revoked.device_class, DeviceFactorClass::Mobile);
    assert_eq!(revoked.status_index, phone1_index);

    // b) En la Token Status List:
    // - El índice de phone1 AHORA está REVOCADO (01)
    assert_eq!(
        status_manager
            .status_of(status_list_id, phone1_index)
            .expect("check phone1 revoked"),
        TokenStatus::Revoked
    );

    // - El índice de Card (tarjeta física) PERMANECE 100 % VÁLIDO E INTACTO (00)
    assert_eq!(
        status_manager
            .status_of(status_list_id, card_index)
            .expect("check card still valid"),
        TokenStatus::Valid
    );

    // - El nuevo índice de phone2 está VÁLIDO (00)
    let new_phone_index = rebinding_result.active_slot.status_index;
    assert_ne!(new_phone_index, phone1_index);
    assert_eq!(
        status_manager
            .status_of(status_list_id, new_phone_index)
            .expect("check phone2 valid"),
        TokenStatus::Valid
    );

    // c) El slot manager ahora tiene exactamente phone2 y card activos
    assert_eq!(
        slot_manager
            .active_slot(&rec_thumbprint_uri, DeviceFactorClass::Mobile)
            .expect("mobile slot active")
            .status_index,
        new_phone_index
    );
    assert_eq!(
        slot_manager
            .active_slot(&rec_thumbprint_uri, DeviceFactorClass::Card)
            .expect("card slot active")
            .status_index,
        card_index
    );
    assert_eq!(
        slot_manager
            .active_slots_for_holder(&rec_thumbprint_uri)
            .len(),
        2
    );
}

/// Verifies: INV-05, REQ-REC-004
#[test]
fn test_rebinding_corrupted_signature_fails_closed() {
    let rng = SeededRng::new(0x2026_0105);
    let issuer_uri = "https://identity.panama.gob.pa";
    let status_list_id = "sl-id-panama-v1";

    let (mut status_manager, mut slot_manager, key_store, signing_handle, kid) =
        setup_test_issuer(issuer_uri, status_list_id, &rng);

    let rec_code = RecoveryCode::generate(&rng).expect("code");
    let (_enc_key, rec_secret) = derive_backup_keys(rec_code.entropy(), &[0x11; 16]).expect("keys");
    let recovery_key = HolderRecoveryKey::derive(&rec_secret, issuer_uri).expect("rec key");
    let rec_uri = recovery_key.thumbprint_uri();

    let now = UnixTime::from_seconds(1_791_640_000);
    let profile = ProfileId::parse("pip-personal-v1").expect("profile");

    // Alta de móvil inicial
    let phone1_sec = generate_p256_secret_key(&rng).expect("phone1 sec");
    let phone1_jwk = public_key_from_secret_key(&phone1_sec).expect("phone1 jwk");
    let (_sl_id, phone1_alloc) = status_manager
        .allocate_with_list_id(Some(status_list_id), &rng)
        .expect("alloc");
    let phone1_index = phone1_alloc.idx;

    let phone1_slot = ActiveDeviceSlot {
        device_class: DeviceFactorClass::Mobile,
        status_list_id: status_list_id.into(),
        status_index: phone1_index,
        holder_key: phone1_jwk,
        issued_at: now,
        expires_at: None,
    };
    slot_manager
        .register_initial_slot(&rec_uri, phone1_slot)
        .expect("reg");

    // Intento de re-vinculación con firma corrupta
    let phone2_sec = generate_p256_secret_key(&rng).expect("phone2 sec");
    let phone2_jwk = public_key_from_secret_key(&phone2_sec).expect("phone2 jwk");
    let challenge = RebindingChallenge::new(
        issuer_uri,
        "nonce-tampered-sig-test",
        UnixTime::from_seconds(1_791_640_500),
    )
    .expect("challenge");

    let req = recovery_key
        .create_rebinding_request(
            &challenge,
            DeviceFactorClass::Mobile,
            phone2_jwk.clone(),
            now,
        )
        .expect("create req");

    let mut tampered_sig = *req.signature();
    tampered_sig[0] ^= 0x5a; // alterar firma

    let base_req = CredentialRequest::new(issuer_uri, profile, now)
        .expect("base req")
        .attribute("given_name", Value::String("Angel".into()))
        .expect("given_name")
        .attribute("family_name", Value::String("Nereira".into()))
        .expect("family_name")
        .attribute("birth_date", Value::String("1990-01-01".into()))
        .expect("birth_date");

    let params = RebindingExecutionParams {
        issuer_uri: req.issuer_uri(),
        nonce: req.nonce(),
        challenge_expires_at: challenge.expires_at(),
        device_class: req.device_class(),
        new_holder_key: phone2_jwk,
        recovery_public_key: recovery_key.public_key(),
        signature: &tampered_sig,
        preferred_status_list_id: Some(status_list_id),
        now,
    };
    let signing_ctx = IssuerSigningContext {
        key_store: &key_store,
        signing_key: &signing_handle,
        kid: Some(kid),
        rng: &rng,
    };

    let res = slot_manager.execute_atomic_rebinding(
        &params,
        &base_req,
        &mut status_manager,
        &signing_ctx,
    );

    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSignature);

    // Fail-closed: El móvil original NO fue revocado
    assert_eq!(
        status_manager
            .status_of(status_list_id, phone1_index)
            .expect("check phone1 still valid"),
        TokenStatus::Valid
    );
    assert_eq!(
        slot_manager
            .active_slot(&rec_uri, DeviceFactorClass::Mobile)
            .expect("phone1 slot remains")
            .status_index,
        phone1_index
    );
}

/// Verifies: INV-05, INV-11
#[test]
fn test_rebinding_expired_challenge_fails_closed() {
    let rng = SeededRng::new(0x2026_0106);
    let issuer_uri = "https://identity.panama.gob.pa";
    let status_list_id = "sl-id-panama-v1";

    let (mut status_manager, mut slot_manager, key_store, signing_handle, kid) =
        setup_test_issuer(issuer_uri, status_list_id, &rng);

    let rec_code = RecoveryCode::generate(&rng).expect("code");
    let (_enc_key, rec_secret) = derive_backup_keys(rec_code.entropy(), &[0x22; 16]).expect("keys");
    let recovery_key = HolderRecoveryKey::derive(&rec_secret, issuer_uri).expect("rec key");
    let _rec_uri = recovery_key.thumbprint_uri();

    let issue_time = UnixTime::from_seconds(1_791_640_000);
    let expires_time = UnixTime::from_seconds(1_791_640_300);
    let late_time = UnixTime::from_seconds(1_791_640_301); // 1 segundo después de expirar

    let challenge =
        RebindingChallenge::new(issuer_uri, "nonce-expired-test", expires_time).expect("challenge");

    let phone_sec = generate_p256_secret_key(&rng).expect("sec");
    let phone_jwk = public_key_from_secret_key(&phone_sec).expect("jwk");

    // Si el titular intenta crear la solicitud después de expirar
    let err = recovery_key.create_rebinding_request(
        &challenge,
        DeviceFactorClass::Mobile,
        phone_jwk.clone(),
        late_time,
    );
    assert!(err.is_err());

    // Si el emisor recibe la solicitud después de expirar
    let valid_req = recovery_key
        .create_rebinding_request(
            &challenge,
            DeviceFactorClass::Mobile,
            phone_jwk.clone(),
            issue_time,
        )
        .expect("create req");

    let profile = ProfileId::parse("pip-personal-v1").expect("profile");
    let base_req = CredentialRequest::new(issuer_uri, profile, late_time)
        .expect("base req")
        .attribute("given_name", Value::String("Angel".into()))
        .expect("given_name")
        .attribute("family_name", Value::String("Nereira".into()))
        .expect("family_name")
        .attribute("birth_date", Value::String("1990-01-01".into()))
        .expect("birth_date");

    let params = RebindingExecutionParams {
        issuer_uri: valid_req.issuer_uri(),
        nonce: valid_req.nonce(),
        challenge_expires_at: challenge.expires_at(),
        device_class: valid_req.device_class(),
        new_holder_key: phone_jwk,
        recovery_public_key: recovery_key.public_key(),
        signature: valid_req.signature(),
        preferred_status_list_id: Some(status_list_id),
        now: late_time,
    };
    let signing_ctx = IssuerSigningContext {
        key_store: &key_store,
        signing_key: &signing_handle,
        kid: Some(kid),
        rng: &rng,
    };

    let res = slot_manager.execute_atomic_rebinding(
        &params,
        &base_req,
        &mut status_manager,
        &signing_ctx,
    );

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, ErrorCode::CredentialExpired);
}

/// Verifies: REQ-REC-007, P-07, P-09
#[test]
fn test_rebinding_cross_issuer_isolation_enforced() {
    let rng = SeededRng::new(0x2026_0107);
    let issuer_uri = "https://identity.panama.gob.pa";
    let different_issuer = "https://bank.example.com";
    let challenge = RebindingChallenge::new(
        issuer_uri,
        "nonce-isolation-test",
        UnixTime::from_seconds(1_791_640_500),
    )
    .expect("challenge");

    let rec_code = RecoveryCode::generate(&rng).expect("code");
    let (_enc_key, rec_secret) = derive_backup_keys(rec_code.entropy(), &[0x33; 16]).expect("keys");

    // Clave derivada para OTRO emisor
    let foreign_recovery_key =
        HolderRecoveryKey::derive(&rec_secret, different_issuer).expect("foreign key");

    let phone_sec = generate_p256_secret_key(&rng).expect("sec");
    let phone_jwk = public_key_from_secret_key(&phone_sec).expect("jwk");

    // El titular rechaza firmar un desafío con una clave que no pertenece al emisor
    let err = foreign_recovery_key.create_rebinding_request(
        &challenge,
        DeviceFactorClass::Mobile,
        phone_jwk,
        UnixTime::from_seconds(1_791_640_000),
    );
    assert!(err.is_err());
}

/// Verifies: INV-02, REQ-DEVSLOT-004
#[test]
fn test_rebinding_zero_pii_audit() {
    let issuer_uri = "https://identity.panama.gob.pa";
    let nonce = "nonce-audit-test-998877";
    let device_class = DeviceFactorClass::Mobile;
    let thumbprint = "thumbprint-abc123xyz";

    let transcript = compute_rebinding_transcript(issuer_uri, nonce, device_class, thumbprint);

    let forbidden_patterns = [
        "imei",
        "IMEI",
        "imsi",
        "IMSI",
        "mac",
        "MAC",
        "serial",
        "Serial",
        "Angel",
        "Nereira",
        "8-765-4321",
        "panama_id",
        "cedula",
    ];

    for pattern in forbidden_patterns {
        assert!(
            !transcript.contains(pattern),
            "INV-02 violation: transcript contains forbidden identifier '{pattern}': {transcript}"
        );
    }
}
