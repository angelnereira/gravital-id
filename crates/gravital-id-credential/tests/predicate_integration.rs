#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de los claims de predicado (F3.T07, REQ-CRED-005).
//!
//! Trazabilidad:
//! - **REQ-CRED-005:** Los perfiles PUEDEN definir claims de predicado precomputados.
//! El SDK no decide por el valor del predicado: expone los hechos para que la `Policy`
//! del integrador acepte o rechace (P-05).
//! - **INV-11:** La edad se calcula contra el instante que pasa el llamador.
//! - **REQ-VER-003:** Fail-closed ante predicados con forma incorrecta.

extern crate alloc;

use alloc::string::ToString;

use gravital_id_codec::json::Value;
use gravital_id_credential::{
    age_years, disclosed_predicates, profile_age_predicates, ParsedSdJwt, ProfileSchema,
    SdJwtVcBuilder, VcValidityPolicy,
};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, ProfileId, UnixTime, Vct};

const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";

/// Instante de referencia de las pruebas: 2026-10-13 00:00:00 UTC.
const AT: UnixTime = UnixTime::from_seconds(1_791_849_600);

fn personal_schema() -> &'static ProfileSchema {
    ProfileSchema::lookup(&ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"))
        .expect("personal schema")
}

/// Emite una credencial del perfil personal con los predicados precomputados por el emisor.
fn issue_credential_with_predicates(
    key_store: &SoftwareKeyStore<impl gravital_id_crypto::Rng>,
    handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    predicate_value_override: Option<bool>,
    exp: UnixTime,
) -> gravital_id_credential::IssuedSdJwt {
    let schema = personal_schema();
    let predicates = profile_age_predicates(schema, "2006-10-13", AT).expect("predicates");
    let rng_emit = SeededRng::new(6001);

    let mut builder = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), AT)
        .expect("builder")
        .profile(ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"))
        .exp(exp)
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", Value::String("Ana".to_string()))
        .add_sd_claim("family_name", Value::String("Perez".to_string()));

    for predicate in &predicates {
        let value = predicate_value_override.unwrap_or(predicate.value);
        builder = builder.add_sd_claim(predicate.name, Value::Bool(value));
    }

    builder
        .issue_signed(key_store, handle, None, &rng_emit)
        .expect("issue credential with predicates")
}

// Verifies: REQ-CRED-005
#[test]
fn profile_declares_predicate_claims_with_thresholds() {
    let schema = personal_schema();

    let over_18 = schema.claim("age_over_18").expect("age_over_18 declared");
    let over_21 = schema.claim("age_over_21").expect("age_over_21 declared");

    match over_18.kind {
        gravital_id_credential::ClaimKind::Predicate { min_age_years } => {
            assert_eq!(min_age_years, 18)
        }
        ref other => panic!("age_over_18 debería ser predicado, es {other:?}"),
    }
    match over_21.kind {
        gravital_id_credential::ClaimKind::Predicate { min_age_years } => {
            assert_eq!(min_age_years, 21)
        }
        ref other => panic!("age_over_21 debería ser predicado, es {other:?}"),
    }

    // El formato de cable sigue siendo booleano (esquema `{"type": "boolean"}`).
    assert_eq!(over_18.kind.json_type_name(), "boolean");
}

// Verifies: REQ-CRED-005, INV-11
#[test]
fn issuer_precomputes_predicates_at_emission_time() {
    let schema = personal_schema();

    // Titular de 20 años en el instante de referencia.
    let predicates = profile_age_predicates(schema, "2006-10-13", AT).expect("predicates");
    assert_eq!(predicates.len(), 2);
    assert_eq!(predicates.first().map(|p| p.name), Some("age_over_18"));
    assert!(predicates.first().map(|p| p.value).unwrap_or(false));
    assert_eq!(predicates.get(1).map(|p| p.name), Some("age_over_21"));
    assert!(!predicates.get(1).map(|p| p.value).unwrap_or(true));
}

// Verifies: REQ-CRED-005
#[test]
fn credential_with_predicates_is_verified_end_to_end() {
    let rng = SeededRng::new(6002);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    let rng_holder = SeededRng::new(6003);
    let mut holder_store = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let rng_emit = SeededRng::new(6004);
    let builder = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), AT)
        .expect("builder")
        .profile(ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"))
        .cnf_jwk(holder_jwk)
        .exp(AT)
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", Value::String("Ana".to_string()))
        .add_sd_claim("family_name", Value::String("Perez".to_string()))
        .add_sd_claim("age_over_18", Value::Bool(true))
        .add_sd_claim("age_over_21", Value::Bool(false));

    let issued = builder
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect("issue");
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    let policy = VcValidityPolicy::default()
        .with_profile(ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"));
    parsed
        .verify_vc(AT, &policy)
        .expect("los predicados booleanos cumplen el esquema");

    // El verificador lee los predicados divulgados; la decisión es de su Policy.
    let disclosed = disclosed_predicates(personal_schema(), parsed.reconstructed_claims());
    assert_eq!(disclosed.len(), 2);
    let over_18 = disclosed
        .iter()
        .find(|p| p.name == "age_over_18")
        .expect("age_over_18 divulgado");
    assert!(over_18.is_satisfied());
    let over_21 = disclosed
        .iter()
        .find(|p| p.name == "age_over_21")
        .expect("age_over_21 divulgado");
    assert!(!over_21.is_satisfied());

    // El titular presenta únicamente el predicado que necesita (minimización).
    let predicate_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("age_over_18"))
        .expect("age_over_18 disclosure");
    let presentation = gravital_id_credential::KbIssuer::create_presentation(
        &format!("{}~{}~", issued.jwt(), predicate_disc.encoded()),
        "https://verifier.example.com",
        "nonce-abcdefghijklmnop",
        AT,
        &holder_store,
        &holder_handle,
    )
    .expect("presentation");

    let parsed_presentation = ParsedSdJwt::parse(&presentation).expect("parse presentation");
    parsed_presentation
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");
    parsed_presentation
        .verify_vc(AT, &policy)
        .expect("verification of a minimized presentation");

    let only_predicate = disclosed_predicates(
        personal_schema(),
        parsed_presentation.reconstructed_claims(),
    );
    assert_eq!(only_predicate.len(), 1);
    assert_eq!(only_predicate.first().map(|p| p.name), Some("age_over_18"));
    assert!(parsed_presentation
        .reconstructed_claims()
        .member("given_name")
        .is_none());
}

// Verifies: REQ-CRED-005, REQ-VER-003
#[test]
fn predicate_with_non_boolean_shape_is_rejected_by_schema() {
    let schema = personal_schema();
    let claims = Value::Object(vec![
        ("age_over_18".to_string(), Value::String("yes".to_string())),
        ("given_name".to_string(), Value::String("Ana".to_string())),
    ]);
    let err = schema.validate(&claims).expect_err("predicado no booleano");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
}

// Verifies: REQ-CRED-005
#[test]
fn age_calculation_is_deterministic_and_saturating() {
    // Edad 0 el mismo día de nacimiento.
    assert_eq!(age_years("2026-10-13", AT).map(|a| a.as_u8()), Ok(0));

    // Edad máxima admitida.
    let max = age_years("1876-01-01", AT).expect("edad dentro del rango");
    assert_eq!(max.as_u8(), 150);

    // Una edad por encima del límite soportado se rechaza.
    let err = age_years("1870-01-01", AT).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-CRED-005
#[test]
fn predicates_older_than_the_reference_time_are_not_recomputed() {
    // El emisor firmó age_over_18 = true cuando el titular tenía 20 años.
    // El verificador años después no lo recalcula: el valor vigente es el firmado.
    let rng = SeededRng::new(6005);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    // Cinco años después, los predicados siguen siendo los que firmó el emisor.
    let later = UnixTime::from_seconds(AT.as_seconds().saturating_add(5 * 365 * 86_400));

    let issued = issue_credential_with_predicates(&key_store, &issuer_handle, None, later);
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");
    let policy = VcValidityPolicy::default()
        .with_profile(ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"));
    parsed
        .verify_vc(later, &policy)
        .expect("el predicado no se recalcula en verificación");

    let disclosed = disclosed_predicates(personal_schema(), parsed.reconstructed_claims());
    let over_18 = disclosed
        .iter()
        .find(|p| p.name == "age_over_18")
        .expect("age_over_18");
    assert!(over_18.is_satisfied());
}
