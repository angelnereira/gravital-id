#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de la capa SD-JWT VC (F3.T05, draft-ietf-oauth-sd-jwt-vc-19).
//!
//! Trazabilidad:
//! - **REQ-CRED-001:** El formato v1 DEBE ser SD-JWT VC sobre RFC 9901 (`typ: dc+sd-jwt`).
//! - **REQ-CRED-007:** Toda credencial DEBE incluir referencia de estado (`status`),
//!   salvo perfiles que lo excluyan explícitamente para credenciales de vida corta.
//! - **REQ-CRED-008:** Se DEBEN rechazar algoritmos fuera de la lista del perfil, incluido `none`.
//! - **REQ-VER-003:** Fail-closed ante cualquier error, dato faltante o ambigüedad.
//! - **REQ-VER-008:** Límites acotados de entrada.
//! - **INV-08:** Solo ES256; `alg: none` siempre rechazado.
//! - **INV-11:** La vigencia se evalúa con el reloj inyectado (`UnixTime`).
//! - **ARCHITECTURE.md §8.2:** `iss`, `vct`, `iat`, `nbf`, `exp`, `cnf` y `status` siempre visibles.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::Value;
use gravital_id_credential::{
    JwsHeader, KbIssuer, KbVerificationPolicy, ParsedSdJwt, SdIssuer, SdJwtVcBuilder,
    SdJwtVcVerifier, SdObjectBuilder, VcValidityPolicy,
};
use gravital_id_crypto::sha256;
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime, Vct};

const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";

/// Helper: emite una credencial SD-JWT VC nominal firmada por el emisor.
fn issue_nominal_vc(
    key_store: &SoftwareKeyStore<impl gravital_id_crypto::Rng>,
    handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    now: UnixTime,
    holder_jwk: Option<gravital_id_crypto::JwkEcP256>,
) -> gravital_id_credential::IssuedSdJwt {
    let rng_emit = SeededRng::new(4242);
    let mut builder = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), now)
        .expect("builder")
        .exp(UnixTime::from_seconds(
            now.as_seconds().saturating_add(86_400),
        ))
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", Value::String("Ana".to_string()))
        .add_sd_claim("family_name", Value::String("Perez".to_string()))
        .set_decoys(2);

    if let Some(jwk) = holder_jwk {
        builder = builder.cnf_jwk(jwk);
    }

    builder
        .issue_signed(key_store, handle, None, &rng_emit)
        .expect("issue vc")
}

/// Helper: firma un SD-JWT con payload arbitrario (para la matriz negativa).
fn craft_signed_sd_jwt(
    key_store: &SoftwareKeyStore<impl gravital_id_crypto::Rng>,
    handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    payload_json: &str,
) -> String {
    let header = r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#;
    let header_b64 = base64url::encode(header.as_bytes());
    let payload_b64 = base64url::encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = sha256(signing_input.as_bytes());
    let signature = key_store.sign(handle, &digest).expect("sign");
    format!("{signing_input}.{}~", base64url::encode(&signature))
}

/// Helper: construye un payload SD-JWT VC con los claims indicados.
fn vc_payload(iat: u64, extra: &str) -> String {
    format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status":{{"status_list":{{"idx":7,"uri":"{}"}}}},"vct":"{}"{}}}"#,
        iat.saturating_add(86_400),
        iat,
        ISSUER_URI,
        STATUS_LIST_URI,
        PERSONAL_VCT,
        extra
    )
}

// Verifies: REQ-CRED-001, REQ-CRED-007, REQ-VER-003
#[test]
fn nominal_sd_jwt_vc_issuance_parsing_and_verification() {
    let rng = SeededRng::new(11);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    let now = UnixTime::from_seconds(1_700_000_000);
    let issued = issue_nominal_vc(&key_store, &issuer_handle, now, None);

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    let policy = VcValidityPolicy::default();
    let claims = parsed.verify_vc(now, &policy).expect("verify vc");

    assert_eq!(claims.iss, ISSUER_URI);
    assert_eq!(claims.vct, Vct::parse(PERSONAL_VCT).expect("vct"));
    assert_eq!(claims.iat, now);
    assert!(claims.exp.is_some());
    assert!(claims.cnf.is_none());

    let status = claims.status.expect("status claim");
    assert_eq!(status.status_list.idx, 7);
    assert_eq!(status.status_list.uri, STATUS_LIST_URI);

    // Los metadatos de la capa VC son siempre visibles: no aparecen como claims divulgados.
    assert!(parsed.reconstructed_claims().member("iss").is_some());
    assert_eq!(
        parsed.reconstructed_claims().member("vct"),
        Some(&Value::String(PERSONAL_VCT.to_string()))
    );
}

// Verifies: REQ-CRED-001, REQ-PRES-002, REQ-VER-003
#[test]
fn cnf_jwk_of_credential_binds_the_key_binding_signature() {
    let rng_issuer = SeededRng::new(21);
    let mut issuer_store = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("issuer jwk");

    let rng_holder = SeededRng::new(22);
    let mut holder_store = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let now = UnixTime::from_seconds(1_700_000_000);
    let issued = issue_nominal_vc(&issuer_store, &issuer_handle, now, Some(holder_jwk.clone()));

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    let policy = VcValidityPolicy::default().with_require_cnf(true);
    let claims = parsed.verify_vc(now, &policy).expect("verify vc");

    // La clave pública declarada en `cnf.jwk` es la del titular y permite verificar el KB-JWT.
    // La serialización usa los miembros canónicos RFC 7638 (`crv`, `kty`, `x`, `y`), que es
    // la forma normativa del ejemplo de draft-19 §3.2.2.3; se comparan las coordenadas.
    let cnf_jwk = claims.cnf.expect("cnf claim").jwk;
    assert_eq!(cnf_jwk.x_base64url(), holder_jwk.x_base64url());
    assert_eq!(cnf_jwk.y_base64url(), holder_jwk.y_base64url());
    assert_eq!(
        cnf_jwk.thumbprint_base64url(),
        holder_jwk.thumbprint_base64url()
    );
    assert!(cnf_jwk.kid().is_none());

    let name_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("given_name"))
        .expect("given_name disclosure");

    let prefix = format!("{}~{}~", issued.jwt(), name_disc.encoded());

    let presentation = KbIssuer::create_presentation(
        &prefix,
        "https://verifier.example.com",
        "nonce-abcdefghijklmnop",
        now,
        &holder_store,
        &holder_handle,
    )
    .expect("presentation");

    let parsed_presentation = ParsedSdJwt::parse(&presentation).expect("parse presentation");
    parsed_presentation
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");
    parsed_presentation
        .verify_vc(now, &policy)
        .expect("verify vc of presentation");

    // Un nonce distinto del esperado rompe la vinculación (fail-closed).
    let err = parsed_presentation
        .verify_key_binding(
            "https://verifier.example.com",
            "nonce-different-value-000",
            &cnf_jwk,
            now,
            &KbVerificationPolicy::default(),
        )
        .expect_err("nonce incorrecto");
    assert_eq!(err.code, ErrorCode::KeyBindingFailed);

    // El nonce correcto contra la clave pública declarada en `cnf.jwk` sí vincula.
    parsed_presentation
        .verify_key_binding(
            "https://verifier.example.com",
            "nonce-abcdefghijklmnop",
            &cnf_jwk,
            now,
            &KbVerificationPolicy::default(),
        )
        .expect("key binding valid with cnf.jwk");
}

// Verifies: REQ-CRED-007
#[test]
fn short_lived_profile_can_exclude_status_when_policy_allows_it() {
    let rng = SeededRng::new(31);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    let now = UnixTime::from_seconds(1_700_000_000);
    let rng_emit = SeededRng::new(32);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), now)
        .expect("builder")
        .add_sd_claim("given_name", Value::String("Ana".to_string()))
        .issue_signed(&key_store, &issuer_handle, None, &rng_emit)
        .expect("issue vc without status");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    // Con la política por defecto (que exige estado) la credencial se rechaza.
    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("status required");
    assert_eq!(err.code, ErrorCode::MissingRequiredClaim);

    // Un perfil de credenciales de vida corta puede excluirlo explícitamente (REQ-CRED-007).
    let relaxed = VcValidityPolicy::default().with_require_status(false);
    let claims = parsed.verify_vc(now, &relaxed).expect("status optional");
    assert!(claims.status.is_none());
}

// Verifies: REQ-CRED-001
#[test]
fn rejection_of_typ_other_than_dc_plus_sd_jwt() {
    let rng = SeededRng::new(41);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    let now = UnixTime::from_seconds(1_700_000_000);
    let rng_emit = SeededRng::new(42);

    // Reemitida con `typ: vc+jwt` la cabecera deja de ser la del perfil normativo.
    let header = JwsHeader {
        alg: "ES256".to_string(),
        typ: "vc+jwt".to_string(),
        kid: None,
    };
    let builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String(ISSUER_URI.to_string()))
        .add_plain_claim("vct", Value::String(PERSONAL_VCT.to_string()))
        .add_plain_claim(
            "iat",
            Value::Number(gravital_id_codec::json::Number::PosInt(now.as_seconds())),
        )
        .add_plain_claim(
            "status",
            Value::Object(vec![("status_list".to_string(), value_status_claim())]),
        );
    let reissued = SdIssuer::issue_signed(builder, &key_store, &issuer_handle, header, &rng_emit)
        .expect("issue with wrong typ");

    let parsed = ParsedSdJwt::parse(reissued.to_compact_serialization()).expect("parse");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("typ inválido");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

/// Helper: objeto JSON del claim `status` usado en la matriz negativa.
fn value_status_claim() -> Value {
    Value::Object(vec![
        (
            "idx".to_string(),
            Value::Number(gravital_id_codec::json::Number::PosInt(7)),
        ),
        (
            "uri".to_string(),
            Value::String(STATUS_LIST_URI.to_string()),
        ),
    ])
}

// Verifies: REQ-CRED-008, INV-08
#[test]
fn rejection_of_alg_none_header() {
    let header = r#"{"alg":"none","typ":"dc+sd-jwt"}"#;
    let payload = r#"{"iat":1700000000,"iss":"https://issuer.example.gov"}"#;
    let header_b64 = base64url::encode(header.as_bytes());
    let payload_b64 = base64url::encode(payload.as_bytes());
    let unsigned = format!("{header_b64}.{payload_b64}.");

    let err = ParsedSdJwt::parse(&format!("{unsigned}~")).expect_err("alg none");
    assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);

    // También se rechaza a nivel de política de cabecera (INV-08).
    let policy = VcValidityPolicy::default();
    let header_val = Value::Object(vec![
        ("alg".to_string(), Value::String("none".to_string())),
        ("typ".to_string(), Value::String("dc+sd-jwt".to_string())),
    ]);
    let err = SdJwtVcVerifier::verify_header(&header_val, &policy).expect_err("alg none");
    assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);
}

// Verifies: REQ-CRED-008
#[test]
fn rejection_of_algorithm_outside_profile_algorithm_list() {
    let rng = SeededRng::new(51);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let now = UnixTime::from_seconds(1_700_000_000);
    let issued = issue_nominal_vc(&key_store, &issuer_handle, now, None);
    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");

    // El perfil solo autoriza ES384: ES256 queda fuera de la lista del perfil.
    let policy = VcValidityPolicy::default().with_allowed_algorithms(vec!["ES384".to_string()]);
    let err = parsed
        .verify_vc(now, &policy)
        .expect_err("algoritmo fuera del perfil");
    assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);
}

// Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn rejection_of_missing_required_vc_claims() {
    let rng = SeededRng::new(61);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let now = UnixTime::from_seconds(1_700_000_000);

    // Sin 'vct'
    let payload = r#"{"iat":1700000000,"iss":"https://issuer.example.gov","status":{"status_list":{"idx":7,"uri":"https://status.example.gov/l"}}}"#;
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");
    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("vct ausente");
    assert_eq!(err.code, ErrorCode::MissingRequiredClaim);

    // Sin 'iss'
    let payload = r#"{"iat":1700000000,"status":{"status_list":{"idx":7,"uri":"https://status.example.gov/l"}},"vct":"https://credentials.gravital.io/vct/personal/id-v1"}"#;
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");
    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("iss ausente");
    assert_eq!(err.code, ErrorCode::MissingRequiredClaim);
}

// Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn rejection_of_expired_credential() {
    let rng = SeededRng::new(71);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let iat = UnixTime::from_seconds(1_700_000_000);
    let payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status":{{"status_list":{{"idx":7,"uri":"{}"}}}},"vct":"{}"}}"#,
        1_700_000_100,
        iat.as_seconds(),
        ISSUER_URI,
        STATUS_LIST_URI,
        PERSONAL_VCT
    );
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, &payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    // 1000 s después de la expiración, más allá de la tolerancia de 60 s.
    let now = UnixTime::from_seconds(1_700_001_100);
    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("credencial expirada");
    assert_eq!(err.code, ErrorCode::CredentialExpired);
}

// Verifies: REQ-CRED-001, REQ-VER-003, INV-11
#[test]
fn rejection_of_credential_not_yet_valid() {
    let rng = SeededRng::new(81);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let payload = format!(
        r#"{{"iat":{},"iss":"{}","nbf":{},"status":{{"status_list":{{"idx":7,"uri":"{}"}}}},"vct":"{}"}}"#,
        1_700_000_000, ISSUER_URI, 1_700_010_000, STATUS_LIST_URI, PERSONAL_VCT
    );
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, &payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    let now = UnixTime::from_seconds(1_700_005_000);
    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("nbf futura");
    assert_eq!(err.code, ErrorCode::CredentialNotYetValid);

    // Con reloj adelantado dentro de la ventana, la credencial pasa a ser vigente.
    let future = UnixTime::from_seconds(1_700_010_030);
    parsed
        .verify_vc(future, &VcValidityPolicy::default())
        .expect("nbf dentro de la tolerancia");
}

// Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn rejection_of_nbf_before_iat() {
    let rng = SeededRng::new(91);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let payload = format!(
        r#"{{"iat":{},"iss":"{}","nbf":{},"status":{{"status_list":{{"idx":7,"uri":"{}"}}}},"vct":"{}"}}"#,
        1_700_000_500, ISSUER_URI, 1_700_000_000, STATUS_LIST_URI, PERSONAL_VCT
    );
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, &payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    let err = parsed
        .verify_vc(
            UnixTime::from_seconds(1_700_001_000),
            &VcValidityPolicy::default(),
        )
        .expect_err("nbf anterior a iat");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-CRED-007, REQ-VER-003
#[test]
fn rejection_of_malformed_status_claim() {
    let rng = SeededRng::new(101);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    // 'status_list' sin 'uri'
    let payload = r#"{"iat":1700000000,"iss":"https://issuer.example.gov","status":{"status_list":{"idx":7}},"vct":"https://credentials.gravital.io/vct/personal/id-v1"}"#;
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    let err = parsed
        .verify_vc(
            UnixTime::from_seconds(1_700_000_000),
            &VcValidityPolicy::default(),
        )
        .expect_err("status malformado");
    assert_eq!(err.code, ErrorCode::MalformedStatusList);

    // 'status' sin 'status_list'
    let payload = r#"{"iat":1700000000,"iss":"https://issuer.example.gov","status":{"idx":7},"vct":"https://credentials.gravital.io/vct/personal/id-v1"}"#;
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    let err = parsed
        .verify_vc(
            UnixTime::from_seconds(1_700_000_000),
            &VcValidityPolicy::default(),
        )
        .expect_err("status sin status_list");
    assert_eq!(err.code, ErrorCode::MalformedStatusList);
}

// Verifies: REQ-CRED-001, INV-03
#[test]
fn rejection_of_cnf_with_private_key_material() {
    let rng = SeededRng::new(111);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let payload = r#"{"cnf":{"jwk":{"crv":"P-256","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}},"iat":1700000000,"iss":"https://issuer.example.gov","status":{"status_list":{"idx":7,"uri":"https://status.example.gov/l"}},"vct":"https://credentials.gravital.io/vct/personal/id-v1"}"#;
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    let err = parsed
        .verify_vc(
            UnixTime::from_seconds(1_700_000_000),
            &VcValidityPolicy::default(),
        )
        .expect_err("cnf con clave privada");
    assert_eq!(err.code, ErrorCode::InvalidKeyFormat);
}

// Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn rejection_of_always_visible_claim_declared_selectively_disclosable() {
    let rng = SeededRng::new(121);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let now = UnixTime::from_seconds(1_700_000_000);

    // El constructor tipado lo impide en emisión (ARCHITECTURE §8.2).
    let builder = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(PERSONAL_VCT).expect("vct"), now)
        .expect("builder")
        .add_sd_claim("iss", Value::String("https://attacker.example".to_string()));
    let err = builder
        .issue_signed(&key_store, &issuer_handle, None, &SeededRng::new(122))
        .expect_err("iss no puede ser selectivo");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // Y si un emisor lo hiciera con el constructor genérico, la verificación falla
    // porque el claim falta en el payload siempre visible.
    let rng_emit = SeededRng::new(123);
    let issued = SdIssuer::issue_signed(
        SdObjectBuilder::new()
            .add_sd_claim("iss", Value::String(ISSUER_URI.to_string()))
            .add_plain_claim("vct", Value::String(PERSONAL_VCT.to_string()))
            .add_plain_claim(
                "iat",
                Value::Number(gravital_id_codec::json::Number::PosInt(now.as_seconds())),
            ),
        &key_store,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue with hidden iss");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");
    let err = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect_err("iss oculto tras divulgación");
    assert_eq!(err.code, ErrorCode::MissingRequiredClaim);
}

// Verifies: REQ-CRED-001
#[test]
fn rejection_of_non_https_issuer_identifier_in_builder() {
    let vct = Vct::parse(PERSONAL_VCT).expect("vct");
    let now = UnixTime::from_seconds(1_700_000_000);

    let err = SdJwtVcBuilder::new("http://issuer.example.gov", vct.clone(), now)
        .expect_err("iss no https");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    let err = SdJwtVcBuilder::new("iss-panama-tribunal-electoral", vct, now)
        .expect_err("iss sin esquema https");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-CRED-001, REQ-VER-008
#[test]
fn oversized_issuer_identifier_is_rejected() {
    let vct = Vct::parse(PERSONAL_VCT).expect("vct");
    let now = UnixTime::from_seconds(1_700_000_000);

    let mut oversized: String = String::from("https://issuer.example.gov/");
    while oversized.len() <= 256 {
        oversized.push('a');
    }
    let err = SdJwtVcBuilder::new(oversized, vct, now).expect_err("iss demasiado largo");
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn vc_claims_survive_decoys_and_selective_disclosure() {
    let rng = SeededRng::new(131);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = key_store.public_key(&issuer_handle).expect("issuer jwk");

    let now = UnixTime::from_seconds(1_700_000_000);
    let issued = issue_nominal_vc(&key_store, &issuer_handle, now, None);

    // El titular presenta una única divulgación conservando los claims siempre visibles.
    let family_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("family_name"))
        .expect("family_name disclosure");

    let prefix = format!("{}~{}~", issued.jwt(), family_disc.encoded());
    let parsed = ParsedSdJwt::parse(&prefix).expect("parse minimal presentation");
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("signature");

    let claims = parsed
        .verify_vc(now, &VcValidityPolicy::default())
        .expect("verify vc");
    assert_eq!(claims.iss, ISSUER_URI);
    assert_eq!(
        parsed.reconstructed_claims().member("family_name"),
        Some(&Value::String("Perez".to_string()))
    );
    assert!(parsed.reconstructed_claims().member("given_name").is_none());
}

// Verifies: REQ-CRED-001 (compatibilidad con payload arbitrario firmado)
#[test]
fn crafted_payload_within_limits_is_accepted() {
    let rng = SeededRng::new(141);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let payload = vc_payload(
        1_700_000_000,
        r#","cnf":{"jwk":{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}"#,
    );
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, &payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");

    let claims = parsed
        .verify_vc(
            UnixTime::from_seconds(1_700_000_100),
            &VcValidityPolicy::default(),
        )
        .expect("verify crafted vc");
    assert!(claims.cnf.is_some());
    assert_eq!(claims.iss, ISSUER_URI);

    // Un payload sin ningún claim de la capa VC no es una credencial SD-JWT VC.
    let payload = r#"{"sub":"user_42"}"#;
    let compact = craft_signed_sd_jwt(&key_store, &issuer_handle, payload);
    let parsed = ParsedSdJwt::parse(&compact).expect("parse");
    let err = parsed
        .verify_vc(
            UnixTime::from_seconds(1_700_000_100),
            &VcValidityPolicy::default(),
        )
        .expect_err("payload sin claims VC");
    assert_eq!(err.code, ErrorCode::MissingRequiredClaim);
}

// Verifies: REQ-CRED-001
#[test]
fn status_reference_uri_validation_rejects_whitespace() {
    let err = gravital_id_credential::StatusListReference::new(
        7,
        "https://status.example.gov/with space",
    )
    .expect_err("uri con espacio");
    assert_eq!(err.code, ErrorCode::MalformedStatusList);

    let reference =
        gravital_id_credential::StatusListReference::new(7, STATUS_LIST_URI).expect("uri válida");
    assert_eq!(reference.idx, 7);
    let round_trip = gravital_id_credential::StatusListReference::from_value(&reference.to_value())
        .expect("round trip");
    assert_eq!(round_trip, reference);
}
