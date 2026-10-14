#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de los esquemas de perfil en compilación (F3.T06, REQ-CRED-004).
//!
//! Trazabilidad:
//! - **REQ-CRED-004:** Los claims DEBEN validarse contra el esquema del perfil y del `vct`
//!   en emisión y verificación.
//! - **REQ-VER-003:** Fail-closed: los atributos que incumplen el esquema no se emiten ni
//!   se aceptan.
//! - **INV-05:** Un perfil sin esquema registrado hace fallar la operación, no omite la
//!   comprobación.
//! - Esquemas tomados literalmente de `docs/specs/profiles/*.md` §3.

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec;

use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::{
    KbIssuer, ParsedSdJwt, ProfileSchema, SdJwtVcBuilder, SdJwtVcVerifier, VcValidityPolicy,
    PROFILE_SCHEMAS,
};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, ProfileId, UnixTime, Vct};

const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const FINANCIAL_VCT: &str = "https://credentials.gravital.io/vct/financial/kyc-v1";
const ENTERPRISE_VCT: &str = "https://credentials.gravital.io/vct/enterprise/employee-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";
const NOW: UnixTime = UnixTime::from_seconds(1_700_000_000);

fn personal_profile() -> ProfileId {
    ProfileId::parse(ProfileId::PERSONAL_V1).expect("personal profile")
}

fn financial_profile() -> ProfileId {
    ProfileId::parse(ProfileId::FINANCIAL_V1).expect("financial profile")
}

fn enterprise_profile() -> ProfileId {
    ProfileId::parse(ProfileId::ENTERPRISE_V1).expect("enterprise profile")
}

fn string_attr(value: &str) -> Value {
    Value::String(value.to_string())
}

fn attributes(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// Emite una credencial del perfil personal con el esquema validado en emisión.
fn issue_personal_credential(
    key_store: &SoftwareKeyStore<impl gravital_id_crypto::Rng>,
    handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
) -> gravital_id_credential::IssuedSdJwt {
    let rng_emit = SeededRng::new(5001);
    SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(personal_profile())
        .exp(UnixTime::from_seconds(1_700_086_400))
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .add_sd_claim("age_over_18", Value::Bool(true))
        .add_sd_claim("birth_date", string_attr("1990-04-12"))
        .add_sd_claim("nationality", string_attr("PAN"))
        .set_decoys(1)
        .issue_signed(key_store, handle, None, &rng_emit)
        .expect("issue personal credential")
}

// Verifies: REQ-CRED-004
#[test]
fn schemas_of_the_three_normative_profiles_are_embedded() {
    assert_eq!(PROFILE_SCHEMAS.len(), 3);
    for profile_id in [
        personal_profile(),
        financial_profile(),
        enterprise_profile(),
    ] {
        let schema = ProfileSchema::lookup(&profile_id).expect("schema registered");
        assert!(!schema.claims.is_empty());
        assert!(!schema.required_claims().is_empty());
    }

    let vct = Vct::parse(ENTERPRISE_VCT).expect("vct");
    assert_eq!(
        ProfileSchema::lookup_by_vct(&vct).expect("schema").profile,
        ProfileId::ENTERPRISE_V1
    );
}

// Verifies: REQ-CRED-004
#[test]
fn credential_valid_against_profile_schema_is_emitted_and_verified() {
    let rng = SeededRng::new(5002);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    let issued = issue_personal_credential(&key_store, &issuer_handle);
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    // Sin política de perfil, la verificación VC no depende del esquema.
    let claims = parsed
        .verify_vc(NOW, &VcValidityPolicy::default())
        .expect("verify without profile policy");
    assert_eq!(claims.vct, Vct::parse(PERSONAL_VCT).expect("vct"));

    // Con el perfil declarado, los atributos divulgados se validan contra el esquema.
    let policy = VcValidityPolicy::default().with_profile(personal_profile());
    parsed
        .verify_vc(NOW, &policy)
        .expect("verify with profile schema");

    // El titular presenta un subconjunto de atributos; el esquema sigue cumpliéndose.
    let name_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("given_name"))
        .expect("given_name disclosure");
    let age_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("age_over_18"))
        .expect("age disclosure");

    let prefix = format!(
        "{}~{}~{}~",
        issued.jwt(),
        name_disc.encoded(),
        age_disc.encoded()
    );
    let presented = ParsedSdJwt::parse(&prefix).expect("parse presentation");
    presented
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");
    presented
        .verify_vc(NOW, &policy)
        .expect("minimized presentation still satisfies the schema");
}

// Verifies: REQ-CRED-004, REQ-VER-003
#[test]
fn emission_rejects_attributes_that_violate_the_profile_schema() {
    let rng = SeededRng::new(5003);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let rng_emit = SeededRng::new(5004);

    // Falta 'age_over_18' (obligatorio en el esquema del perfil personal).
    let err = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(personal_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect_err("claim obligatorio ausente");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
    assert!(err.message.contains("age_over_18"));

    // Tipo incorrecto: entero donde el esquema pide booleano.
    let err = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(personal_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .add_sd_claim("age_over_18", Value::Number(Number::PosInt(1)))
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect_err("tipo incorrecto");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
}

// Verifies: REQ-CRED-004
#[test]
fn emission_rejects_vct_that_does_not_match_the_profile() {
    let rng = SeededRng::new(5005);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    // Un vct de business del perfil personal.
    let err = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(FINANCIAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(personal_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .add_sd_claim("age_over_18", Value::Bool(true))
        .issue_signed(&key_store, &issuer_handle, None, &SeededRng::new(5006))
        .expect_err("vct no coincide con el perfil");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
    assert!(err.message.contains(FINANCIAL_VCT));
}

// Verifies: REQ-CRED-004, INV-05
#[test]
fn unknown_profile_makes_the_operation_fail() {
    let unknown = ProfileId::parse("pip-future-v9").expect("profile id válido");
    assert!(ProfileSchema::lookup(&unknown).is_none());

    // En emisión.
    let rng = SeededRng::new(5007);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let err = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(unknown.clone())
        .issue_signed(&key_store, &issuer_handle, None, &SeededRng::new(5008))
        .expect_err("perfil sin esquema");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);

    // En verificación: la política no puede omitir la comprobación que pidió.
    let issued = issue_personal_credential(&key_store, &issuer_handle);
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    let policy = VcValidityPolicy::default().with_profile(unknown);
    let err = parsed
        .verify_vc(NOW, &policy)
        .expect_err("perfil sin esquema en verificación");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
}

// Verifies: REQ-CRED-004 (la minimización de la presentación se verifica en la fase F5)
#[test]
fn minimized_presentation_does_not_require_undisclosed_claims() {
    let schema = ProfileSchema::lookup(&personal_profile()).expect("schema");

    // El titular divulga solo el predicado de mayoría de edad: ni `given_name` ni
    // `family_name` aparecen, y la presentación sigue siendo válida contra el esquema.
    let disclosed = attributes(vec![("age_over_18", Value::Bool(true))]);
    schema
        .validate_disclosed(&disclosed)
        .expect("subconjunto mínimo cumple los tipos");

    // Un tipo inválido entre lo divulgado sí se rechaza en verificación.
    let invalid = attributes(vec![("age_over_18", Value::String("yes".to_string()))]);
    let err = schema
        .validate_disclosed(&invalid)
        .expect_err("tipo inválido entre lo divulgado");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);

    // En emisión, en cambio, el esquema completo sí exige los claims obligatorios.
    let err = schema
        .validate(&disclosed)
        .expect_err("emisión sin claims obligatorios");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
    assert!(err.message.contains("given_name"));
}

// Verifies: REQ-CRED-004, REQ-VER-003
#[test]
fn verification_rejects_attributes_that_violate_the_profile_schema() {
    let rng = SeededRng::new(5009);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    // Credencial emitida sin validación de esquema: 'nationality' no cumple el patrón.
    let rng_emit = SeededRng::new(5010);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .add_sd_claim("age_over_18", Value::Bool(true))
        .add_sd_claim("nationality", string_attr("pan"))
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    let policy = VcValidityPolicy::default().with_profile(personal_profile());
    let err = parsed
        .verify_vc(NOW, &policy)
        .expect_err("atributo fuera del esquema");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
    assert!(err.message.contains("nationality"));

    // Los atributos no declarados por el esquema se admiten (sin additionalProperties: false).
    let rng_emit = SeededRng::new(5011);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(personal_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .add_sd_claim("age_over_18", Value::Bool(true))
        .add_sd_claim("nickname", string_attr("Ani"))
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect("issue with extra attribute");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_vc(NOW, &policy)
        .expect("atributos no declarados se admiten");
}

// Verifies: REQ-CRED-004, REQ-VER-003
#[test]
fn verification_rejects_credential_vct_that_does_not_match_the_policy_profile() {
    let rng = SeededRng::new(5012);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let issued = issue_personal_credential(&key_store, &issuer_handle);
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");

    // La política exige el perfil financiero pero la credencial es personal.
    let policy = VcValidityPolicy::default().with_profile(financial_profile());
    let err = parsed
        .verify_vc(NOW, &policy)
        .expect_err("vct no coincide con el perfil de la política");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
}

// Verifies: REQ-CRED-004, REQ-VER-003
#[test]
fn enterprise_schema_validates_arrays_and_enums() {
    let rng = SeededRng::new(5013);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    // Caso nominal del perfil empresarial.
    let rng_emit = SeededRng::new(5014);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(ENTERPRISE_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(enterprise_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("employee_id", string_attr("E-1001"))
        .add_sd_claim("organization_id", string_attr("ORG-9"))
        .add_sd_claim("security_clearance", string_attr("secret"))
        .add_sd_claim(
            "authorized_zones",
            Value::Array(vec![string_attr("lobby"), string_attr("datacenter")]),
        )
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect("issue enterprise credential");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");
    parsed
        .verify_vc(
            NOW,
            &VcValidityPolicy::default().with_profile(enterprise_profile()),
        )
        .expect("enterprise credential satisfies schema");

    // Array de enteros donde el esquema exige cadenas.
    let rng_emit = SeededRng::new(5015);
    let err = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(ENTERPRISE_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(enterprise_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("employee_id", string_attr("E-1001"))
        .add_sd_claim("organization_id", string_attr("ORG-9"))
        .add_sd_claim("security_clearance", string_attr("ultra"))
        .add_sd_claim(
            "authorized_zones",
            Value::Array(vec![Value::Number(Number::PosInt(1))]),
        )
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect_err("array con tipo inválido");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
}

// Verifies: REQ-CRED-004
#[test]
fn financial_schema_validates_enums_and_date_time() {
    let rng = SeededRng::new(5016);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    // 'aml_cleared_at' no es RFC 3339.
    let err = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(FINANCIAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(financial_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("legal_name", string_attr("Ana Perez"))
        .add_sd_claim("tax_id", string_attr("8-123-456"))
        .add_sd_claim("kyc_tier", string_attr("tier2"))
        .add_sd_claim("aml_cleared", Value::Bool(true))
        .add_sd_claim("aml_cleared_at", string_attr("2026-10-13 09:00:00"))
        .issue_signed(&key_store, &issuer_handle, None, &SeededRng::new(5017))
        .expect_err("date-time inválido");
    assert_eq!(err.code, ErrorCode::SchemaValidationFailed);

    // Caso nominal con fecha-hora RFC 3339.
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(FINANCIAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(financial_profile())
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("legal_name", string_attr("Ana Perez"))
        .add_sd_claim("tax_id", string_attr("8-123-456"))
        .add_sd_claim("kyc_tier", string_attr("tier2"))
        .add_sd_claim("aml_cleared", Value::Bool(true))
        .add_sd_claim("aml_cleared_at", string_attr("2026-10-13T09:00:00-05:00"))
        .issue_signed(&key_store, &issuer_handle, None, &SeededRng::new(5018))
        .expect("issue financial credential");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_vc(
            NOW,
            &VcValidityPolicy::default().with_profile(financial_profile()),
        )
        .expect("financial credential satisfies schema");
}

// Verifies: REQ-CRED-004, REQ-PRES-002
#[test]
fn profile_schema_and_key_binding_compose_in_a_presentation() {
    let rng_issuer = SeededRng::new(5019);
    let mut issuer_store = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("issuer jwk");

    let rng_holder = SeededRng::new(5020);
    let mut holder_store = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let rng_emit = SeededRng::new(5021);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), NOW)
        .expect("builder")
        .profile(personal_profile())
        .cnf_jwk(holder_jwk)
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", string_attr("Ana"))
        .add_sd_claim("family_name", string_attr("Perez"))
        .add_sd_claim("age_over_18", Value::Bool(true))
        .issue_signed(&issuer_store, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let name_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("given_name"))
        .expect("given_name disclosure");

    let presentation = KbIssuer::create_presentation(
        &format!("{}~{}~", issued.jwt(), name_disc.encoded()),
        "https://verifier.example.com",
        "nonce-1234567890abcdef",
        NOW,
        &holder_store,
        &holder_handle,
    )
    .expect("presentation");

    let parsed = ParsedSdJwt::parse(&presentation).expect("parse presentation");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    let policy = VcValidityPolicy::default().with_profile(personal_profile());
    let claims = parsed
        .verify_vc(NOW, &policy)
        .expect("verify vc with schema");
    let cnf_jwk = claims.cnf.expect("cnf claim").jwk;

    parsed
        .verify_key_binding(
            "https://verifier.example.com",
            "nonce-1234567890abcdef",
            &cnf_jwk,
            NOW,
            &gravital_id_credential::KbVerificationPolicy::default(),
        )
        .expect("key binding valid");
}

// Verifies: REQ-CRED-004
#[test]
fn profile_attributes_exclude_always_visible_vc_metadata() {
    let rng = SeededRng::new(5022);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let issued = issue_personal_credential(&key_store, &issuer_handle);
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");

    let attributes = SdJwtVcVerifier::profile_attributes(parsed.reconstructed_claims());
    let Value::Object(entries) = &attributes else {
        panic!("expected object of attributes");
    };
    for (name, _) in entries {
        assert!(
            !["iss", "vct", "iat", "nbf", "exp", "cnf", "status"].contains(&name.as_str()),
            "el metadato siempre visible '{name}' no debe tratarse como atributo"
        );
    }
    assert!(entries.iter().any(|(k, _)| k == "given_name"));
}
