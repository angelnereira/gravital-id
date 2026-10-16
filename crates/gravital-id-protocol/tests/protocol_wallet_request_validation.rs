//! Pruebas de integración de validación de solicitudes por la wallet (F5.T11, REQ-PRES-007).
//!
//! Trazabilidad:
//! - `REQ-PRES-007`: Perfiles y claims sensibles exigen solicitudes firmadas con clave registrada.
//! - `REQ-PRES-001` / `REQ-PRIV-001`: Minimización y comprobación de claims solicitados permitidos.
//! - `INV-01`: Cero dependencias de red en la evaluación y validación de solicitudes.
//! - `INV-05`: Rechazo fail-closed ante cualquier firma inválida, expiración o clave no registrada.
//! - `INV-11`: Determinismo estricto con reloj inyectado (`UnixTime`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_crypto::JwkEcP256;
use gravital_id_holder::{CredentialQuery, DcqlQuery, RequestedClaim};
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_protocol::offline_request::VerificationRequest;
use gravital_id_protocol::offline_signed_request::sign_verification_request;
use gravital_id_protocol::offline_wallet_policy::{WalletRequestPolicy, WalletRequestValidator};
use gravital_id_testkit::SeededRng;
use gravital_id_trust::bundle::TrustBundle;
use gravital_id_types::{ErrorCode, Kid, UnixTime, Vct};

fn make_query_for_claims(claims: &[&str], vct_str: &str) -> DcqlQuery {
    let req_claims: Vec<RequestedClaim> = claims
        .iter()
        .map(|c| RequestedClaim::required(*c))
        .collect();
    let cred_q = CredentialQuery::new(
        "q1",
        vec![Vct::parse(vct_str).expect("valid vct")],
        req_claims,
    )
    .expect("valid cred query");
    DcqlQuery::new(vec![cred_q]).expect("valid query")
}

fn create_sample_trust_bundle(
    verifier_id: &str,
    valid_from: u64,
    valid_until: Option<u64>,
    profiles: &[&str],
    verifier_jwk: Option<JwkEcP256>,
) -> TrustBundle {
    let now = 1_000_000u64;
    let profiles_json = profiles
        .iter()
        .map(|p| format!(r#""{p}""#))
        .collect::<Vec<_>>()
        .join(",");

    let jwk_field = match verifier_jwk {
        Some(jwk) => format!(r#","public_key":{}"#, jwk.to_canonical_json()),
        None => String::new(),
    };

    let until_field = match valid_until {
        Some(u) => format!(r#","valid_until":{u}"#),
        None => String::new(),
    };

    let json = format!(
        r#"{{
            "framework_id": "pip-framework-v1",
            "bundle_epoch": 1,
            "bundle_version": 1,
            "chain_id": 1,
            "registry_address": "0x1234567890123456789012345678901234567890",
            "finalized_block_number": 100,
            "finalized_block_hash": "0xdeadbeef1234567890deadbeef1234567890deadbeef1234567890deadbeef1234",
            "issued_at": {now},
            "valid_until": {},
            "issuers": [],
            "verifiers": [
                {{
                    "verifier_id": "{verifier_id}",
                    "profiles": [{profiles_json}],
                    "valid_from": {valid_from}{until_field}{jwk_field}
                }}
            ],
            "policies": []
        }}"#,
        now + 1_000_000
    );

    TrustBundle::from_json_bytes(json.as_bytes()).expect("valid trust bundle")
}

// Verifies: REQ-PRES-007, INV-11 (Vigencia temporal y duración máxima)
#[test]
fn wallet_request_timing_and_window_validation() {
    let validator = WalletRequestValidator::default();
    let query = make_query_for_claims(&["given_name"], "urn:test:id-v1");

    let req_valid = VerificationRequest::new(
        "verifier-normal",
        "random_nonce_1234567890abcdef",
        "https://verifier.example.com",
        UnixTime::from_seconds(1000),
        UnixTime::from_seconds(1200),
        query.clone(),
        None,
    )
    .expect("valid request");

    // Nominal dentro de la ventana: tiempo actual = 1100
    let validated = validator
        .validate_request(&req_valid, UnixTime::from_seconds(1100), None)
        .expect("nominal request must pass");
    assert!(!validated.is_signed);
    assert!(!validated.is_registered_verifier);
    assert_eq!(validated.request.verifier_id, "verifier-normal");

    // Solicitud expirada: tiempo actual = 1300 (tolerancia 60s -> expira en 1260)
    let err = validator
        .validate_request(&req_valid, UnixTime::from_seconds(1300), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpiredRequest);

    // Solicitud en el futuro: tiempo actual = 900 (tolerancia 60s -> falla si iat > 960)
    let err = validator
        .validate_request(&req_valid, UnixTime::from_seconds(900), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Duración de ventana superior al umbral máximo permitido (max 300s, enviamos 500s)
    let req_too_long = VerificationRequest::new(
        "verifier-normal",
        "random_nonce_1234567890abcdef",
        "https://verifier.example.com",
        UnixTime::from_seconds(1000),
        UnixTime::from_seconds(1500),
        query,
        None,
    )
    .expect("valid struct");

    let err = validator
        .validate_request(&req_too_long, UnixTime::from_seconds(1100), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-007, REQ-PRES-001 (Claims denegados por la política de la wallet)
#[test]
fn wallet_request_disallowed_claims_rejection() {
    let mut policy = WalletRequestPolicy::default();
    policy.disallowed_claims.push("tax_id".to_string());
    policy.disallowed_claims.push("credit_score".to_string());
    let validator = WalletRequestValidator::new(policy);

    let query_bad = make_query_for_claims(&["given_name", "tax_id"], "urn:test:id-v1");
    let req = VerificationRequest::new(
        "verifier-bank",
        "random_nonce_1234567890abcdef",
        "https://bank.example.com",
        UnixTime::from_seconds(1000),
        UnixTime::from_seconds(1200),
        query_bad,
        None,
    )
    .expect("valid request");

    let err = validator
        .validate_request(&req, UnixTime::from_seconds(1100), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-007 (Claims sensibles exigen verificador registrado y solicitud firmada)
#[test]
fn wallet_request_sensitive_claims_reject_unsigned_requests() {
    let validator = WalletRequestValidator::default();

    // Consulta que solicita número de cédula ("document_number")
    let query_doc_num =
        make_query_for_claims(&["given_name", "document_number"], "pip-identity-v1");
    let req = VerificationRequest::new(
        "verifier-anon",
        "random_nonce_1234567890abcdef",
        "https://anon.example.com",
        UnixTime::from_seconds(1000),
        UnixTime::from_seconds(1200),
        query_doc_num,
        None,
    )
    .expect("valid request");

    // Falla fail-closed porque document_number es un claim sensible (Nivel 1)
    let err = validator
        .validate_request(&req, UnixTime::from_seconds(1100), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Consulta que solicita retrato ("portrait")
    let query_portrait = make_query_for_claims(&["portrait"], "pip-identity-v1");
    let req2 = VerificationRequest::new(
        "verifier-anon",
        "random_nonce_1234567890abcdef",
        "https://anon.example.com",
        UnixTime::from_seconds(1000),
        UnixTime::from_seconds(1200),
        query_portrait,
        None,
    )
    .expect("valid request");

    let err2 = validator
        .validate_request(&req2, UnixTime::from_seconds(1100), None)
        .unwrap_err();
    assert_eq!(err2.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-007, INV-05, INV-08 (Solicitud firmada de verificador registrado válida)
#[test]
fn wallet_signed_request_from_registered_verifier_passes() {
    let mut keystore = SoftwareKeyStore::new(SeededRng::new(5555));
    let handle = keystore.generate_key::<IssuerSigning>().expect("key");
    let verifier_pubkey = keystore.public_key(&handle).expect("pubkey");
    let kid = Kid::parse("key-verifier-01").expect("kid");

    let bundle = create_sample_trust_bundle(
        "gov.pa.migracion.checkpoint-01",
        1000,
        Some(5000),
        &["pip-identity-v1", "pip-personal-v1"],
        Some(verifier_pubkey),
    );

    let validator = WalletRequestValidator::default();
    let query_sensitive = make_query_for_claims(
        &["document_number", "birth_date", "given_name"],
        "pip-identity-v1",
    );

    let req = VerificationRequest::new(
        "gov.pa.migracion.checkpoint-01",
        "random_nonce_1234567890abcdef",
        "https://migracion.gob.pa",
        UnixTime::from_seconds(1100),
        UnixTime::from_seconds(1300),
        query_sensitive,
        None,
    )
    .expect("valid request");

    // Firmar la solicitud con la clave del verificador
    let signed_jws = sign_verification_request(&req, &keystore, &handle, Some(&kid))
        .expect("signing must succeed");

    // Validar solicitud firmada contra el TrustBundle
    let validated = validator
        .validate_signed_request(&signed_jws, UnixTime::from_seconds(1150), &bundle)
        .expect("signed request from registered verifier must pass");

    assert!(validated.is_signed);
    assert!(validated.is_registered_verifier);
    assert_eq!(
        validated.request.verifier_id,
        "gov.pa.migracion.checkpoint-01"
    );
    let verifier_info = validated.verifier_entry.expect("entry present");
    assert_eq!(verifier_info.verifier_id, "gov.pa.migracion.checkpoint-01");
}

// Verifies: REQ-PRES-007, INV-05 (Rechazo fail-closed si la firma criptográfica es adulterada)
#[test]
fn wallet_signed_request_tampered_signature_rejected() {
    let mut keystore = SoftwareKeyStore::new(SeededRng::new(6666));
    let handle = keystore.generate_key::<IssuerSigning>().expect("key");
    let verifier_pubkey = keystore.public_key(&handle).expect("pubkey");

    let bundle = create_sample_trust_bundle(
        "verifier-border-control",
        1000,
        Some(5000),
        &["*"],
        Some(verifier_pubkey),
    );

    let validator = WalletRequestValidator::default();
    let query = make_query_for_claims(&["given_name"], "pip-personal-v1");
    let req = VerificationRequest::new(
        "verifier-border-control",
        "random_nonce_1234567890abcdef",
        "https://border.example.com",
        UnixTime::from_seconds(1100),
        UnixTime::from_seconds(1300),
        query,
        None,
    )
    .expect("valid request");

    let signed_jws = sign_verification_request(&req, &keystore, &handle, None).expect("sign");

    // Adulterar firma JWS: decodificar 64 bytes de firma, invertir un bit y re-codificar en base64url
    let parts: Vec<&str> = signed_jws.split('.').collect();
    let mut sig_bytes = gravital_id_codec::base64url::decode(parts[2]).expect("decode sig");
    sig_bytes[0] ^= 0xFF;
    let bad_sig_b64 = gravital_id_codec::base64url::encode(&sig_bytes);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], bad_sig_b64);

    let err = validator
        .validate_signed_request(&tampered, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSignature);
}

// Verifies: REQ-PRES-007 (Rechazo si el verificador no está en el TrustBundle o su registro expiró)
#[test]
fn wallet_signed_request_unregistered_or_expired_verifier_rejected() {
    let mut keystore = SoftwareKeyStore::new(SeededRng::new(7777));
    let handle = keystore.generate_key::<IssuerSigning>().expect("key");
    let verifier_pubkey = keystore.public_key(&handle).expect("pubkey");

    // Verificador registrado expiró en t = 1200
    let bundle = create_sample_trust_bundle(
        "verifier-expired",
        1000,
        Some(1200),
        &["*"],
        Some(verifier_pubkey.clone()),
    );

    let validator = WalletRequestValidator::default();
    let query = make_query_for_claims(&["given_name"], "pip-personal-v1");

    // 1. Verificador no registrado en el bundle
    let req_unknown = VerificationRequest::new(
        "verifier-completely-unknown",
        "random_nonce_1234567890abcdef",
        "https://unknown.org",
        UnixTime::from_seconds(1100),
        UnixTime::from_seconds(1300),
        query.clone(),
        None,
    )
    .expect("valid request");

    let signed_unknown =
        sign_verification_request(&req_unknown, &keystore, &handle, None).expect("sign");
    let err = validator
        .validate_signed_request(&signed_unknown, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 2. Verificador registrado pero su registro en el bundle expiró (now = 1250 > 1200)
    let req_expired = VerificationRequest::new(
        "verifier-expired",
        "random_nonce_1234567890abcdef",
        "https://expired.org",
        UnixTime::from_seconds(1240),
        UnixTime::from_seconds(1290),
        query,
        None,
    )
    .expect("valid request");

    let signed_expired =
        sign_verification_request(&req_expired, &keystore, &handle, None).expect("sign");
    let err2 = validator
        .validate_signed_request(&signed_expired, UnixTime::from_seconds(1250), &bundle)
        .unwrap_err();
    assert_eq!(err2.code, ErrorCode::ExpiredRequest);
}

// Verifies: REQ-PRES-007 (Rechazo si el verificador no está autorizado para el perfil solicitado)
#[test]
fn wallet_signed_request_unauthorized_profile_rejected() {
    let mut keystore = SoftwareKeyStore::new(SeededRng::new(8888));
    let handle = keystore.generate_key::<IssuerSigning>().expect("key");
    let verifier_pubkey = keystore.public_key(&handle).expect("pubkey");

    // Verificador autorizado ÚNICAMENTE para perfil financiero ("pip-financial-v1")
    let bundle = create_sample_trust_bundle(
        "bank-verifier",
        1000,
        Some(5000),
        &["pip-financial-v1"],
        Some(verifier_pubkey),
    );

    let validator = WalletRequestValidator::default();

    // Verificador intenta solicitar credencial de identidad oficial ("pip-identity-v1")
    let query_id = make_query_for_claims(&["given_name"], "pip-identity-v1");
    let req = VerificationRequest::new(
        "bank-verifier",
        "random_nonce_1234567890abcdef",
        "https://bank.example.com",
        UnixTime::from_seconds(1100),
        UnixTime::from_seconds(1300),
        query_id,
        None,
    )
    .expect("valid request");

    let signed_jws = sign_verification_request(&req, &keystore, &handle, None).expect("sign");
    let err = validator
        .validate_signed_request(&signed_jws, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-MAINT-005, REQ-PRES-007 (Cobertura exhaustiva de ramas y casos de error en validación de wallet)
#[test]
fn wallet_validation_edge_cases_and_error_branches() {
    let mut keystore = SoftwareKeyStore::new(SeededRng::new(9999));
    let handle = keystore.generate_key::<IssuerSigning>().expect("key");
    let verifier_pubkey = keystore.public_key(&handle).expect("pubkey");

    let bundle = create_sample_trust_bundle(
        "registered-verifier-01",
        1000,
        Some(3000),
        &["pip-personal-v1"],
        Some(verifier_pubkey.clone()),
    );

    let policy = WalletRequestPolicy::default();
    assert_eq!(policy.clock_skew_tolerance_seconds, 60);
    assert_eq!(policy.max_request_validity_seconds, 300);
    let _ = format!("{policy:?}");
    let cloned_policy = policy.clone();
    assert_eq!(policy, cloned_policy);

    let validator = WalletRequestValidator::new(policy.clone());
    assert_eq!(validator.policy(), &policy);
    let _ = format!("{validator:?}");

    let query = make_query_for_claims(&["given_name"], "pip-personal-v1");
    let req = VerificationRequest::new(
        "registered-verifier-01",
        "random_nonce_1234567890abcdef",
        "https://registered.example.com",
        UnixTime::from_seconds(1100),
        UnixTime::from_seconds(1200),
        query.clone(),
        None,
    )
    .expect("valid request");

    // 1. validate_request con allowlist de verificadores
    let policy_allowlist = WalletRequestPolicy {
        allowed_verifier_ids: Some(vec!["other-verifier".to_string()]),
        ..Default::default()
    };
    let validator_allowlist = WalletRequestValidator::new(policy_allowlist);
    let err = validator_allowlist
        .validate_request(&req, UnixTime::from_seconds(1150), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 2. validate_request con require_registered_verifier = true
    let policy_req_registered = WalletRequestPolicy {
        require_registered_verifier: true,
        ..Default::default()
    };
    let validator_req_registered = WalletRequestValidator::new(policy_req_registered);

    // Sin trust_bundle
    let err = validator_req_registered
        .validate_request(&req, UnixTime::from_seconds(1150), None)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Con trust_bundle pero verificador ausente
    let bundle_empty = create_sample_trust_bundle("other-v", 1000, Some(3000), &["*"], None);
    let err = validator_req_registered
        .validate_request(&req, UnixTime::from_seconds(1150), Some(&bundle_empty))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Con trust_bundle y verificador presente pero expirado
    let bundle_expired = create_sample_trust_bundle(
        "registered-verifier-01",
        1000,
        Some(1120),
        &["*"],
        Some(verifier_pubkey.clone()),
    );
    let err = validator_req_registered
        .validate_request(&req, UnixTime::from_seconds(1150), Some(&bundle_expired))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ExpiredRequest);

    // Con trust_bundle y verificador presente y vigente
    let val_ok = validator_req_registered
        .validate_request(&req, UnixTime::from_seconds(1150), Some(&bundle))
        .expect("registered valid verifier passes");
    assert!(val_ok.is_registered_verifier);
    assert!(!val_ok.is_signed);
    let _ = format!("{val_ok:?}");
    assert_eq!(val_ok.clone(), val_ok);

    // 3. JWS malformado en validate_signed_request
    let err = validator
        .validate_signed_request("part1.part2", UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = validator
        .validate_signed_request("p1.p2.p3.p4", UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = validator
        .validate_signed_request(
            "invalid_b64.invalid_payload.invalid_sig",
            UnixTime::from_seconds(1150),
            &bundle,
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Header sin alg
    let header_no_alg =
        gravital_id_codec::base64url::encode(br#"{"typ":"pip-verification-request-v1"}"#);
    let payload_b64 = gravital_id_codec::base64url::encode(&req.to_json_bytes().unwrap());
    let sig_64 = gravital_id_codec::base64url::encode(&[0x11; 64]);
    let jws_no_alg = format!("{header_no_alg}.{payload_b64}.{sig_64}");
    let err = validator
        .validate_signed_request(&jws_no_alg, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Header con alg != ES256
    let header_bad_alg = gravital_id_codec::base64url::encode(br#"{"alg":"RS256"}"#);
    let jws_bad_alg = format!("{header_bad_alg}.{payload_b64}.{sig_64}");
    let err = validator
        .validate_signed_request(&jws_bad_alg, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedAlgorithm);

    // Header con typ no soportado
    let header_bad_typ =
        gravital_id_codec::base64url::encode(br#"{"alg":"ES256","typ":"unsupported-typ"}"#);
    let jws_bad_typ = format!("{header_bad_typ}.{payload_b64}.{sig_64}");
    let err = validator
        .validate_signed_request(&jws_bad_typ, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedProtocolVersion);

    // Firma con longitud != 64 bytes
    let header_ok = gravital_id_codec::base64url::encode(br#"{"alg":"ES256"}"#);
    let sig_bad_len = gravital_id_codec::base64url::encode(&[0x11; 32]);
    let jws_bad_sig_len = format!("{header_ok}.{payload_b64}.{sig_bad_len}");
    let err = validator
        .validate_signed_request(&jws_bad_sig_len, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSignature);

    // Verificador sin clave pública configurada en el bundle
    let bundle_no_pk = create_sample_trust_bundle(
        "registered-verifier-01",
        1000,
        Some(3000),
        &["pip-personal-v1"],
        None,
    );
    let signed_valid = sign_verification_request(&req, &keystore, &handle, None).unwrap();
    let err = validator
        .validate_signed_request(&signed_valid, UnixTime::from_seconds(1150), &bundle_no_pk)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Solicitud firmada con ventana de validez que supera la política máxima (max 10s, req tiene 100s)
    let policy_short_window = WalletRequestPolicy {
        max_request_validity_seconds: 10,
        ..Default::default()
    };
    let validator_short_window = WalletRequestValidator::new(policy_short_window);
    let err = validator_short_window
        .validate_signed_request(&signed_valid, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Solicitud firmada con verificador no en la lista blanca
    let policy_signed_allowlist = WalletRequestPolicy {
        allowed_verifier_ids: Some(vec!["only-allowed".to_string()]),
        ..Default::default()
    };
    let validator_signed_allowlist = WalletRequestValidator::new(policy_signed_allowlist);
    let err = validator_signed_allowlist
        .validate_signed_request(&signed_valid, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Solicitud firmada que pide claims denegados por política
    let policy_disallow = WalletRequestPolicy {
        disallowed_claims: vec!["given_name".to_string()],
        ..Default::default()
    };
    let validator_disallow = WalletRequestValidator::new(policy_disallow);
    let err = validator_disallow
        .validate_signed_request(&signed_valid, UnixTime::from_seconds(1150), &bundle)
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}
