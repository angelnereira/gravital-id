#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de la API de emisor (F3.T08, REQ-CRED-006).
//!
//! Trazabilidad:
//! - **REQ-CRED-006:** Emisión por lotes con claves, sales e índices de estado distintos
//!   por copia.
//! - **REQ-CRED-002:** Cada divulgación usa sal ≥ 128 bits del CSPRNG inyectado.
//! - **REQ-CRED-004 / REQ-CRED-005:** Validación contra el esquema del perfil y predicados
//!   precomputados.
//! - **REQ-VER-003:** Una solicitud inválida se rechaza sin emitir nada.
//! - **INV-03:** La firma se delega al `KeyStore`; solo claves públicas entran en la API.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_issuer::{
    BatchPlan, CredentialRequest, Issuer, StatusAllocation, MAX_BATCH_COPIES,
};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, ProfileId, UnixTime};

const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";
const AT: UnixTime = UnixTime::from_seconds(1_791_849_600); // 2026-10-13
const EXPIRES: UnixTime = UnixTime::from_seconds(1_791_936_000); // +1 día

fn personal_profile() -> ProfileId {
    ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile")
}

/// Solicitud nominal del perfil personal (mayoría de edad + nombre).
fn personal_request() -> CredentialRequest {
    CredentialRequest::new(ISSUER_URI, personal_profile(), AT)
        .expect("request")
        .attribute("given_name", Value::String("Ana".to_string()))
        .expect("attribute")
        .attribute("family_name", Value::String("Perez".to_string()))
        .expect("attribute")
        .attribute("birth_date", Value::String("2000-04-12".to_string()))
        .expect("attribute")
        .status(StatusAllocation::new(7, STATUS_LIST_URI).expect("status"))
        .expires_at(EXPIRES)
        .decoys(2)
}

fn sign_key<S: KeyStore>(store: &mut S) -> gravital_id_keys::KeyHandle<IssuerSigning> {
    store.generate_key::<IssuerSigning>().expect("issuer key")
}

fn holder_key<S: KeyStore>(store: &mut S) -> gravital_id_crypto::JwkEcP256 {
    let handle = store.generate_key::<HolderBinding>().expect("holder key");
    store.public_key(&handle).expect("holder jwk")
}

// Verifies: REQ-CRED-004, REQ-CRED-005, REQ-CRED-008
#[test]
fn issuer_emits_a_credential_validated_against_the_profile_schema() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7001));
    let issuer_handle = sign_key(&mut store);
    let issuer_jwk = store.public_key(&issuer_handle).expect("issuer jwk");
    let holder_jwk = holder_key(&mut store);

    let request = personal_request().holder_key(holder_jwk.clone());
    let rng_emit = SeededRng::new(7002);
    let credential =
        Issuer::issue(&request, &store, &issuer_handle, None, &rng_emit).expect("issue");

    assert_eq!(credential.profile(), &personal_profile());
    assert_eq!(credential.holder_key(), Some(&holder_jwk));
    assert_eq!(credential.status_index(), Some(7));
    assert_eq!(credential.issued_at(), AT);
    assert_eq!(credential.expires_at(), Some(EXPIRES));

    // La credencial resultante verifica contra el esquema del perfil.
    let parsed = gravital_id_credential::ParsedSdJwt::parse(credential.compact()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("issuer signature");
    let claims = parsed
        .verify_vc(
            AT,
            &gravital_id_credential::VcValidityPolicy::default().with_profile(personal_profile()),
        )
        .expect("verify vc");
    assert!(claims.cnf.is_some());

    // El emisor precomputó el predicado desde birth_date (edad 26 años en AT).
    let schema =
        gravital_id_credential::ProfileSchema::lookup(&personal_profile()).expect("schema");
    let predicates =
        gravital_id_credential::disclosed_predicates(schema, parsed.reconstructed_claims());
    let age_over_18 = predicates
        .iter()
        .find(|p| p.name == "age_over_18")
        .expect("age_over_18");
    assert!(age_over_18.is_satisfied());
}

// Verifies: REQ-CRED-006, REQ-CRED-002
#[test]
fn batch_issues_copies_with_distinct_keys_salts_and_status_indices() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7003));
    let issuer_handle = sign_key(&mut store);
    let issuer_jwk = store.public_key(&issuer_handle).expect("issuer jwk");

    // Cinco copias: cinco claves de titular y cinco índices de estado distintos.
    let holder_keys: Vec<gravital_id_crypto::JwkEcP256> =
        (0..5).map(|_| holder_key(&mut store)).collect();
    let status_indices: Vec<u64> = (100..105).collect();
    let plan = BatchPlan::new(holder_keys.clone(), status_indices.clone()).expect("plan");
    assert_eq!(plan.len(), 5);

    let rng_emit = SeededRng::new(7004);
    let credentials = Issuer::issue_batch(
        &personal_request(),
        &plan,
        &store,
        &issuer_handle,
        None,
        &rng_emit,
    )
    .expect("batch");
    assert_eq!(credentials.len(), 5);

    // 1. Claves de titular distintas por copia, en el orden del plan.
    let mut seen_keys: Vec<String> = Vec::new();
    for (credential, expected_key) in credentials.iter().zip(holder_keys.iter()) {
        assert_eq!(credential.holder_key(), Some(expected_key));
        let thumbprint = credential
            .holder_key()
            .expect("holder key")
            .thumbprint_base64url();
        assert!(
            !seen_keys.contains(&thumbprint),
            "clave repetida en el lote"
        );
        seen_keys.push(thumbprint);
    }

    // 2. Índices de estado distintos por copia.
    let mut seen_indices: Vec<u64> = Vec::new();
    for credential in &credentials {
        let idx = credential.status_index().expect("status index");
        assert!(!seen_indices.contains(&idx), "índice repetido en el lote");
        seen_indices.push(idx);
    }
    assert_eq!(seen_indices, status_indices);

    // 3. Sales distintas en todas las copias (cada una genera las suyas del CSPRNG).
    let mut seen_salts: Vec<String> = Vec::new();
    for credential in &credentials {
        for disclosure in credential.disclosures() {
            let salt = disclosure.salt().to_string();
            assert!(
                !seen_salts.contains(&salt),
                "sal repetida entre copias del lote"
            );
            seen_salts.push(salt);
        }
    }

    // 4. Cada copia es una credencial válida y verificable por separado.
    for credential in &credentials {
        let parsed =
            gravital_id_credential::ParsedSdJwt::parse(credential.compact()).expect("parse");
        parsed
            .verify_issuer_signature(&issuer_jwk)
            .expect("issuer signature");
        parsed
            .verify_vc(
                AT,
                &gravital_id_credential::VcValidityPolicy::default()
                    .with_profile(personal_profile()),
            )
            .expect("verify copy");
    }
}

// Verifies: REQ-CRED-006, REQ-VER-003
#[test]
fn batch_plan_rejects_duplicated_keys_or_indices() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7005));
    let holder_keys: Vec<gravital_id_crypto::JwkEcP256> =
        (0..2).map(|_| holder_key(&mut store)).collect();

    // Índices repetidos.
    let err = BatchPlan::new(holder_keys.clone(), vec![10, 10]).expect_err("índices repetidos");
    assert_eq!(err.code, ErrorCode::MalformedStatusList);

    // Clave repetida.
    let err = BatchPlan::new(
        vec![holder_keys[0].clone(), holder_keys[0].clone()],
        vec![10, 11],
    )
    .expect_err("claves repetidas");
    assert_eq!(err.code, ErrorCode::InvalidKeyFormat);

    // Más índices que copias.
    let err = BatchPlan::new(holder_keys.clone(), vec![10, 11, 12]).expect_err("desajuste");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // Lote vacío.
    let err = BatchPlan::new(Vec::new(), Vec::new()).expect_err("lote vacío");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // Lote demasiado grande.
    let key = holder_keys[0].clone();
    let err = BatchPlan::new(vec![key; MAX_BATCH_COPIES.saturating_add(1)], vec![])
        .expect_err("lote enorme");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-CRED-006, INV-05
#[test]
fn batch_request_must_not_declare_its_own_holder_key() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7006));
    let issuer_handle = sign_key(&mut store);
    let holder_keys: Vec<gravital_id_crypto::JwkEcP256> =
        (0..2).map(|_| holder_key(&mut store)).collect();
    let plan = BatchPlan::new(holder_keys, vec![10, 11]).expect("plan");

    // La solicitud declara una clave: el lote debe fijar una por copia.
    let request = personal_request().holder_key(store.public_key(&issuer_handle).expect("jwk"));
    let err = Issuer::issue_batch(
        &request,
        &plan,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7007),
    )
    .expect_err("solicitud de lote con clave propia");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // Sin URI de lista tampoco se puede repartir el lote.
    let request_without_status = CredentialRequest::new(ISSUER_URI, personal_profile(), AT)
        .expect("request")
        .attribute("given_name", Value::String("Ana".to_string()))
        .expect("attribute")
        .attribute("family_name", Value::String("Perez".to_string()))
        .expect("attribute")
        .attribute("birth_date", Value::String("2000-04-12".to_string()))
        .expect("attribute");
    let err = Issuer::issue_batch(
        &request_without_status,
        &plan,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7008),
    )
    .expect_err("solicitud de lote sin URI de lista");
    assert_eq!(err.code, ErrorCode::MalformedStatusList);
}

// Verifies: REQ-CRED-004, REQ-VER-003
#[test]
fn issuer_rejects_attributes_that_violate_the_profile_schema() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7009));
    let issuer_handle = sign_key(&mut store);

    // Falta 'age_over_18' (obligatorio del perfil personal).
    let request = CredentialRequest::new(ISSUER_URI, personal_profile(), AT)
        .expect("request")
        .attribute("given_name", Value::String("Ana".to_string()))
        .expect("attribute")
        .attribute("family_name", Value::String("Perez".to_string()))
        .expect("attribute")
        .status(StatusAllocation::new(7, STATUS_LIST_URI).expect("status"));

    let err = Issuer::issue(
        &request,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7010),
    )
    .expect_err("atributos incompletos");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);

    // Un claim siempre visible de la capa VC no puede declararse como atributo.
    let request = personal_request()
        .attribute("vct", Value::String("otro".to_string()))
        .expect("attribute");
    let err = Issuer::issue(
        &request,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7011),
    )
    .expect_err("claim reservado como atributo");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // Atributo duplicado.
    let request = personal_request()
        .attribute("given_name", Value::String("Otra".to_string()))
        .expect("attribute");
    let err = Issuer::issue(
        &request,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7012),
    )
    .expect_err("atributo duplicado");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-CRED-002, REQ-VER-009
#[test]
fn same_seed_produces_identical_credentials() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7013));
    let issuer_handle = sign_key(&mut store);
    let request = personal_request();

    let first = Issuer::issue(
        &request,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7014),
    )
    .expect("issue");
    let second = Issuer::issue(
        &request,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7014),
    )
    .expect("issue");

    // Determinismo: mismas entradas e misma semilla => misma credencial (REQ-VER-009).
    assert_eq!(first.compact(), second.compact());

    let third = first.clone();
    assert_eq!(first, third);
}

// Verifies: REQ-CRED-003, REQ-CRED-006
#[test]
fn decoys_are_present_in_every_copy_of_the_batch() {
    let mut store = SoftwareKeyStore::new(SeededRng::new(7015));
    let issuer_handle = sign_key(&mut store);
    let holder_keys: Vec<gravital_id_crypto::JwkEcP256> =
        (0..3).map(|_| holder_key(&mut store)).collect();
    let plan = BatchPlan::new(holder_keys, vec![10, 11, 12]).expect("plan");

    let credentials = Issuer::issue_batch(
        &personal_request(),
        &plan,
        &store,
        &issuer_handle,
        None,
        &SeededRng::new(7016),
    )
    .expect("batch");

    for credential in &credentials {
        // 3 atributos + 2 señuelos = al menos 5 divulgaciones por copia.
        assert!(credential.disclosures().len() >= 5);
    }
}
