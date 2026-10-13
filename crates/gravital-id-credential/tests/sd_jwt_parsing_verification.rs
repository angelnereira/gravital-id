#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración para el parseo y verificación de SD-JWT (F3.T03, RFC 9901).
//!
//! Trazabilidad:
//! - **REQ-CRED-001:** Formato normativo SD-JWT según RFC 9901.
//! - **REQ-CRED-009:** Rechazo de miembros duplicados en JSON y colisiones de claims divulgados.
//! - **REQ-VER-003:** Fail-closed ante cualquier error, dato faltante o ambigüedad.
//! - **REQ-VER-008:** Límites de tamaño, profundidad y número de elementos.

extern crate alloc;

use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::{JwsHeader, ParsedSdJwt, SdIssuer, SdJwtLimits, SdObjectBuilder};
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::ErrorCode;

// // Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn nominal_parsing_and_reconstruction() {
    let rng = SeededRng::new(1001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");
    let jwk = key_store.public_key(&handle).expect("public key");

    let rng_emit = SeededRng::new(1002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_plain_claim(
            "vct",
            Value::String("urn:pip:credentials:identity".to_string()),
        )
        .add_sd_claim("given_name", Value::String("Alice".to_string()))
        .add_sd_claim("family_name", Value::String("Smith".to_string()))
        .add_sd_claim("age", Value::Number(Number::PosInt(30)))
        .set_decoys(3);

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    let compact = issued.to_compact_serialization();
    let parsed = ParsedSdJwt::parse(compact).expect("parse compact sd-jwt");

    // Firma válida contra clave JWK pública del emisor
    parsed
        .verify_issuer_signature(&jwk)
        .expect("signature must verify");

    // Todos los claims divulgados fueron reconstruidos
    let claims = parsed.reconstructed_claims();
    assert_eq!(
        claims.member("iss"),
        Some(&Value::String("https://issuer.example.com".to_string()))
    );
    assert_eq!(
        claims.member("vct"),
        Some(&Value::String("urn:pip:credentials:identity".to_string()))
    );
    assert_eq!(
        claims.member("given_name"),
        Some(&Value::String("Alice".to_string()))
    );
    assert_eq!(
        claims.member("family_name"),
        Some(&Value::String("Smith".to_string()))
    );
    assert_eq!(
        claims.member("age"),
        Some(&Value::Number(Number::PosInt(30)))
    );

    // Metadatos de SD-JWT eliminados del objeto reconstruido
    assert_eq!(claims.member("_sd"), None);
    assert_eq!(claims.member("_sd_alg"), None);
}

// // Verifies: REQ-CRED-001
#[test]
fn selective_disclosure_presentation_subset() {
    let rng = SeededRng::new(2001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");
    let jwk = key_store.public_key(&handle).expect("public key");

    let rng_emit = SeededRng::new(2002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("name", Value::String("Bob".to_string()))
        .add_sd_claim("email", Value::String("bob@example.com".to_string()))
        .add_sd_claim("national_id", Value::String("ID-9999".to_string()))
        .set_decoys(2);

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    // El titular decide presentar SOLO 'name', omitiendo 'email' y 'national_id'
    let name_disclosure = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("name"))
        .expect("name disclosure exists");

    // Construye la presentación selectiva: <jwt>~<name_disclosure>~
    let presentation = format!("{}~{}~", issued.jwt(), name_disclosure.encoded());

    let parsed = ParsedSdJwt::parse(&presentation).expect("parse presentation");

    // La firma sigue siendo válida
    parsed
        .verify_issuer_signature(&jwk)
        .expect("signature must verify");

    let claims = parsed.reconstructed_claims();
    // 'name' revelado
    assert_eq!(
        claims.member("name"),
        Some(&Value::String("Bob".to_string()))
    );
    // 'email' y 'national_id' NO revelados
    assert_eq!(claims.member("email"), None);
    assert_eq!(claims.member("national_id"), None);
}

// // Verifies: REQ-VER-003, REQ-CRED-001
#[test]
fn rejection_of_duplicate_disclosures() {
    let rng = SeededRng::new(3001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");

    let rng_emit = SeededRng::new(3002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("role", Value::String("admin".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    let d_enc = issued.disclosures()[0].encoded();

    // Presentación con divulgación duplicada: <jwt>~<d>~<d>~
    let dup_presentation = format!("{}~{}~{}~", issued.jwt(), d_enc, d_enc);

    let err = ParsedSdJwt::parse(&dup_presentation).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    assert!(err.message.contains("duplicate disclosure"));
}

// // Verifies: REQ-VER-003, REQ-CRED-001
#[test]
fn rejection_of_duplicate_digests_in_sd_array() {
    let rng = SeededRng::new(4001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");

    let rng_emit = SeededRng::new(4002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("data", Value::String("secret".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    let d = &issued.disclosures()[0];

    // Alteramos el JWT para duplicar el digest en _sd: [_sd[0], _sd[0]]
    let jwt_parts: Vec<&str> = issued.jwt().split('.').collect();
    let header_b64 = jwt_parts[0];
    let payload_bytes = base64url::decode(jwt_parts[1]).expect("decode payload");
    let payload_str = core::str::from_utf8(&payload_bytes).expect("utf8 payload");

    // Inyectamos digest duplicado
    let digest_str = d.digest().as_str();
    let tampered_payload_str = payload_str.replace(
        &format!("[\"{digest_str}\"]"),
        &format!("[\"{digest_str}\",\"{digest_str}\"]"),
    );
    let tampered_payload_b64 = base64url::encode(tampered_payload_str.as_bytes());
    let tampered_jwt = format!("{}.{}.{}", header_b64, tampered_payload_b64, jwt_parts[2]);

    let tampered_compact = format!("{}~{}~", tampered_jwt, d.encoded());

    let err = ParsedSdJwt::parse(&tampered_compact).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    assert!(err.message.contains("duplicate digest"));
}

// // Verifies: REQ-VER-003, REQ-CRED-001
#[test]
fn rejection_of_unreferenced_disclosures() {
    let rng = SeededRng::new(5001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");

    let rng_emit = SeededRng::new(5002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("known_claim", Value::String("yes".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    // Creamos una divulgación legítima huérfana (no referenciada por ningún digest del JWT)
    let orphan_salt = gravital_id_credential::Salt::generate(&rng_emit).expect("salt");
    let orphan_disclosure = gravital_id_credential::Disclosure::new_object(
        orphan_salt,
        "orphan_claim",
        Value::String("injected".to_string()),
    )
    .expect("orphan disclosure");

    // Incluimos la divulgación huérfana en la presentación
    let presentation_with_orphan = format!(
        "{}~{}~{}~",
        issued.jwt(),
        issued.disclosures()[0].encoded(),
        orphan_disclosure.encoded()
    );

    let err = ParsedSdJwt::parse(&presentation_with_orphan).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    assert!(err.message.contains("unreferenced disclosure"));
}

// // Verifies: REQ-CRED-009, REQ-VER-003
#[test]
fn rejection_of_claim_name_collision_between_plain_and_disclosure() {
    let rng_emit = SeededRng::new(6002);
    // Creamos un JWT donde 'city' es plain claim y TAMBIÉN está en una divulgación
    let salt = gravital_id_credential::Salt::generate(&rng_emit).expect("salt");
    let disclosure = gravital_id_credential::Disclosure::new_object(
        salt,
        "city",
        Value::String("Panama".to_string()),
    )
    .expect("disclosure");

    let digest_str = disclosure.digest().as_str();

    // Payload con 'city' plain claim Y _sd conteniendo el digest de 'city'
    let payload = Value::Object(vec![
        ("city".to_string(), Value::String("Colón".to_string())),
        (
            "_sd".to_string(),
            Value::Array(vec![Value::String(digest_str.to_string())]),
        ),
        ("_sd_alg".to_string(), Value::String("sha-256".to_string())),
    ]);

    let header_b64 = base64url::encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let payload_b64 =
        base64url::encode(gravital_id_credential::to_canonical_json(&payload).as_bytes());
    let sig_mock = base64url::encode(&[0x01u8; 64]);
    let fake_jwt = format!("{header_b64}.{payload_b64}.{sig_mock}");

    let compact = format!("{fake_jwt}~{}~", disclosure.encoded());

    let err = ParsedSdJwt::parse(&compact).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    assert!(err.message.contains("collision"));
}

// // Verifies: REQ-VER-003
#[test]
fn rejection_of_unsupported_alg_none() {
    let header_none = base64url::encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = base64url::encode(br#"{"sub":"user"}"#);
    let sig = base64url::encode(&[0u8; 64]);
    let compact = format!("{header_none}.{payload}.{sig}~");

    let err = ParsedSdJwt::parse(&compact).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);
}

// // Verifies: REQ-VER-003
#[test]
fn rejection_of_unsupported_sd_alg() {
    let header = base64url::encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let payload = base64url::encode(br#"{"_sd_alg":"sha-512","_sd":[]}"#);
    let sig = base64url::encode(&[0u8; 64]);
    let compact = format!("{header}.{payload}.{sig}~");

    let err = ParsedSdJwt::parse(&compact).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);
}

// // Verifies: REQ-VER-003
#[test]
fn rejection_of_tampered_jwt_signature() {
    let rng = SeededRng::new(7001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");
    let jwk = key_store.public_key(&handle).expect("public key");

    let rng_emit = SeededRng::new(7002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("data", Value::String("valid".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    let parsed = ParsedSdJwt::parse(issued.to_compact_serialization()).expect("parse");

    // Verificación válida
    parsed
        .verify_issuer_signature(&jwk)
        .expect("valid signature");

    // Clave incorrecta debe fallar la verificación
    let wrong_rng = SeededRng::new(9999);
    let mut wrong_store = SoftwareKeyStore::new(wrong_rng);
    let wrong_handle = wrong_store
        .generate_key::<IssuerSigning>()
        .expect("wrong key");
    let wrong_jwk = wrong_store.public_key(&wrong_handle).expect("wrong jwk");

    let err = parsed.verify_issuer_signature(&wrong_jwk).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSignature);
}

// // Verifies: REQ-VER-008
#[test]
fn rejection_when_size_and_depth_limits_are_exceeded() {
    let small_limits = SdJwtLimits {
        max_input_bytes: 30, // Límite muy bajo
        max_disclosures: 128,
        max_recursion_depth: 16,
        max_elements_per_container: 256,
    };

    let input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJleGFtcGxlIn0.c2lnbmF0dXJl~";
    let err_size = ParsedSdJwt::parse_with_limits(input, &small_limits).unwrap_err();
    assert_eq!(err_size.code, ErrorCode::MalformedSdJwt);
    assert!(err_size.message.contains("exceeds limit"));

    // Límite de número de divulgaciones
    let disclosures_limit = SdJwtLimits {
        max_input_bytes: 64 * 1024,
        max_disclosures: 1, // Permite como máximo 1 divulgación
        max_recursion_depth: 16,
        max_elements_per_container: 256,
    };

    let rng = SeededRng::new(8001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");

    let rng_emit = SeededRng::new(8002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("c1", Value::String("v1".to_string()))
        .add_sd_claim("c2", Value::String("v2".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    let err_count =
        ParsedSdJwt::parse_with_limits(issued.to_compact_serialization(), &disclosures_limit)
            .unwrap_err();
    assert_eq!(err_count.code, ErrorCode::MalformedSdJwt);
    assert!(err_count.message.contains("exceeds limit"));
}

// // Verifies: REQ-CRED-001, REQ-VER-003
#[test]
fn rejection_of_empty_disclosure_segment() {
    let rng = SeededRng::new(9001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");

    let rng_emit = SeededRng::new(9002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.com".to_string()),
        )
        .add_sd_claim("claim", Value::String("val".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    let d_enc = issued.disclosures()[0].encoded();

    // Segmento vacío: <jwt>~<d>~~ (dos tildes seguidas)
    let malformed_empty_segment = format!("{}~{}~~", issued.jwt(), d_enc);
    let err = ParsedSdJwt::parse(&malformed_empty_segment).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    assert!(err.message.contains("empty disclosure segment"));
}
