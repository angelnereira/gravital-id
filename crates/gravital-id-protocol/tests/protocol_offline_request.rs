//! Pruebas unitarias y de integración para VerificationRequest (REQ-PRES-005, PROTOCOL.md §3.1).
//!
//! Trazabilidad:
//! - `REQ-PRES-005`: Solicitud offline generada por el verificador con nonce, timing y consulta DCQL.
//! - `INV-01`: Cero dependencias de red en la evaluación y validación sans-I/O.
//! - `INV-05`: Rechazo fail-closed de solicitudes expiradas, prematuras o malformadas.
//! - `INV-11`: Reloj inyectado (`Clock`) sin llamadas a tiempo del sistema.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_holder::DcqlQuery;
use gravital_id_protocol::offline_request::{
    VerificationRequest, MAX_AUDIENCE_LEN, MAX_VERIFIER_ID_LEN, MIN_NONCE_LEN,
    VERIFICATION_REQUEST_TYPE,
};
use gravital_id_testkit::FixedClock;
use gravital_id_types::{ErrorCode, UnixTime};

fn sample_dcql_query() -> DcqlQuery {
    let query_json = br#"{
        "credentials": [
            {
                "id": "cred_offline",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://credentials.gravital.io/vct/personal/id-v1"]
                },
                "claims": ["given_name", "family_name"]
            }
        ]
    }"#;
    DcqlQuery::from_json_bytes(query_json).expect("valid query")
}

// Verifies: REQ-PRES-005 (Creación y serialización JSON canónica de VerificationRequest)
#[test]
fn verification_request_creation_and_json_roundtrip() {
    assert_eq!(VERIFICATION_REQUEST_TYPE, "pip-verification-request-v1");

    let req = VerificationRequest::new(
        "did:gravital:verifier:supermarket-checkout-01",
        "random_nonce_1234567890abcdef",
        "https://verifier.example.com/offline-terminal",
        UnixTime::from_seconds(1700000000),
        UnixTime::from_seconds(1700000300),
        sample_dcql_query(),
        None,
    )
    .expect("valid request");

    assert!(req.nonce.len() >= MIN_NONCE_LEN);

    assert_eq!(
        req.verifier_id,
        "did:gravital:verifier:supermarket-checkout-01"
    );
    assert_eq!(
        req.audience,
        "https://verifier.example.com/offline-terminal"
    );
    assert_eq!(req.nonce, "random_nonce_1234567890abcdef");
    assert_eq!(req.issued_at, UnixTime::from_seconds(1700000000));
    assert_eq!(req.expires_at, UnixTime::from_seconds(1700000300));
    assert!(req.eph_pub.is_none());

    let json_bytes = req.to_json_bytes().expect("serialize");
    let parsed = VerificationRequest::from_json_bytes(&json_bytes).expect("deserialize");

    assert_eq!(parsed.verifier_id, req.verifier_id);
    assert_eq!(parsed.audience, req.audience);
    assert_eq!(parsed.nonce, req.nonce);
    assert_eq!(parsed.issued_at, req.issued_at);
    assert_eq!(parsed.expires_at, req.expires_at);
}

// Verifies: REQ-PRES-005 (Validación temporal con reloj inyectado)
#[test]
fn verification_request_timing_validation() {
    let req = VerificationRequest::new(
        "verifier-1",
        "nonce_16_bytes_min!!",
        "aud-1",
        UnixTime::from_seconds(1000),
        UnixTime::from_seconds(1300),
        sample_dcql_query(),
        None,
    )
    .expect("valid");

    // Nominal: en medio del intervalo [1000, 1300]
    let clock_mid = FixedClock::new(1150);
    assert!(req
        .validate_timing(UnixTime::from_seconds(clock_mid.now()), 0)
        .is_ok());

    // En los límites exactos sin tolerancia
    let clock_iat = FixedClock::new(1000);
    assert!(req
        .validate_timing(UnixTime::from_seconds(clock_iat.now()), 0)
        .is_ok());

    let clock_exp = FixedClock::new(1300);
    assert!(req
        .validate_timing(UnixTime::from_seconds(clock_exp.now()), 0)
        .is_ok());

    // Expirado sin tolerancia (t = 1301)
    let clock_expired = FixedClock::new(1301);
    let err = req
        .validate_timing(UnixTime::from_seconds(clock_expired.now()), 0)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpiredRequest);

    // Expirado con tolerancia de 60s: a 1350s aún es válido, a 1361s expira
    let clock_tolerance_ok = FixedClock::new(1350);
    assert!(req
        .validate_timing(UnixTime::from_seconds(clock_tolerance_ok.now()), 60)
        .is_ok());

    let clock_tolerance_expired = FixedClock::new(1361);
    let err = req
        .validate_timing(UnixTime::from_seconds(clock_tolerance_expired.now()), 60)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpiredRequest);

    // Prematuro (reloj local anterior a iat): t = 950 sin tolerancia -> MalformedMessage
    let clock_future = FixedClock::new(950);
    let err = req
        .validate_timing(UnixTime::from_seconds(clock_future.now()), 0)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Prematuro con tolerancia de 60s: a 950s entra dentro de [1000 - 60 = 940, ...]
    assert!(req
        .validate_timing(UnixTime::from_seconds(clock_future.now()), 60)
        .is_ok());

    // Prematuro más allá de la tolerancia: t = 930s
    let clock_too_early = FixedClock::new(930);
    let err = req
        .validate_timing(UnixTime::from_seconds(clock_too_early.now()), 60)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-005 (Validaciones de sintaxis y límites en campos de solicitud)
#[test]
fn verification_request_field_constraints_and_failures() {
    let query = sample_dcql_query();

    // Nonce demasiado corto (< MIN_NONCE_LEN)
    let err = VerificationRequest::new(
        "v1",
        "short",
        "aud1",
        UnixTime::from_seconds(100),
        UnixTime::from_seconds(200),
        query.clone(),
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // verifier_id demasiado largo (> MAX_VERIFIER_ID_LEN)
    let long_id = "v".repeat(MAX_VERIFIER_ID_LEN + 1);
    let err = VerificationRequest::new(
        &long_id,
        "nonce_16_bytes_min!!",
        "aud1",
        UnixTime::from_seconds(100),
        UnixTime::from_seconds(200),
        query.clone(),
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // audience demasiado largo (> MAX_AUDIENCE_LEN)
    let long_aud = "a".repeat(MAX_AUDIENCE_LEN + 1);
    let err = VerificationRequest::new(
        "v1",
        "nonce_16_bytes_min!!",
        &long_aud,
        UnixTime::from_seconds(100),
        UnixTime::from_seconds(200),
        query.clone(),
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // expires_at <= issued_at
    let err = VerificationRequest::new(
        "v1",
        "nonce_16_bytes_min!!",
        "aud1",
        UnixTime::from_seconds(200),
        UnixTime::from_seconds(100),
        query,
        None,
    )
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-005 (Rechazo fail-closed de JSON corrupto o con tipo incorrecto)
#[test]
fn verification_request_json_deserialization_failures() {
    // JSON malformado
    let err = VerificationRequest::from_json_bytes(b"not json").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // JSON no es un objeto
    let err = VerificationRequest::from_json_bytes(b"[1, 2, 3]").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Tipo de mensaje no coincide
    let wrong_type_json = br#"{
        "type": "wrong_type",
        "verifier_id": "v1",
        "audience": "aud1",
        "nonce": "nonce_16_bytes_min!!",
        "issued_at": 100,
        "expires_at": 200,
        "query": {"credentials": []}
    }"#;
    let err = VerificationRequest::from_json_bytes(wrong_type_json).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedProtocolVersion);

    // Falta campo nonce
    let missing_nonce = format!(
        r#"{{"type":"{VERIFICATION_REQUEST_TYPE}","verifier_id":"v1","audience":"aud1","issued_at":100,"expires_at":200,"query":{{"credentials":[]}}}}"#
    );
    let err = VerificationRequest::from_json_bytes(missing_nonce.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}
