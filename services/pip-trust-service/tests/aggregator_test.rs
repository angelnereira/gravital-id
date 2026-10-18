//! Pruebas del agregador no confiable y detección de divergencia (F7.T04, REQ-TRUST-001, REQ-TRUST-008).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use gravital_id_ledger::adapter::BlockHeader;
use gravital_id_ledger::{derive_trust_bundle, BundleDerivationParams, LedgerState};
use gravital_id_testkit::SeededRng;
use gravital_id_trust::jws_json::JwsJsonParser;
use pip_trust_service::aggregator::{assemble_jws_json, UntrustedBundleAggregator};
use pip_trust_service::error::TrustServiceError;
use pip_trust_service::operator::OperatorSignatureResponse;
use pip_trust_service::signer::{BundleSignerBackend, LocalDevSigner};
use std::collections::BTreeMap;

fn create_test_signer(id: &str, kid: &str, seed: u64) -> LocalDevSigner {
    let rng = SeededRng::new(seed);
    LocalDevSigner::generate_with_rng(id, kid, &rng).expect("signer created")
}

fn derive_test_bundle() -> gravital_id_ledger::DerivedBundle {
    let state = LedgerState::new(
        31337,
        "0x1234567890123456789012345678901234567890".to_string(),
    );
    let header = BlockHeader::new(100, [1u8; 32], [0u8; 32], 1700000000);
    let params = BundleDerivationParams::new("pip-global-mainnet", 1, 1, header, 604800, vec![]);
    derive_trust_bundle(&state, &params).expect("bundle derived")
}

#[test]
fn test_aggregator_with_3_valid_operators_and_1_divergent() {
    // Criterio de aceptación explícito F7.T04:
    // "suite de pruebas con >=3 operadores y 1 divergente"
    let bundle = derive_test_bundle();
    let payload_b64 = gravital_id_codec::base64url::encode(&bundle.canonical_json_bytes);

    let op1 = create_test_signer("operator-1", "kid-op-1", 101);
    let op2 = create_test_signer("operator-2", "kid-op-2", 102);
    let op3 = create_test_signer("operator-3", "kid-op-3", 103);
    let op_div = create_test_signer("operator-divergent", "kid-op-div", 999);

    let sig1 = op1.sign_payload_b64(&payload_b64).expect("op1 signed");
    let sig2 = op2.sign_payload_b64(&payload_b64).expect("op2 signed");
    let sig3 = op3.sign_payload_b64(&payload_b64).expect("op3 signed");

    // Operador divergente: calculó un payload distinto de forma errónea
    let divergent_payload = gravital_id_codec::base64url::encode(b"{\"divergent\":true}");
    let sig_div = op_div
        .sign_payload_b64(&divergent_payload)
        .expect("op_div signed");

    let responses = vec![
        OperatorSignatureResponse {
            operator_id: "operator-1".to_string(),
            kid: "kid-op-1".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig1,
        },
        OperatorSignatureResponse {
            operator_id: "operator-2".to_string(),
            kid: "kid-op-2".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig2,
        },
        OperatorSignatureResponse {
            operator_id: "operator-3".to_string(),
            kid: "kid-op-3".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig3,
        },
        OperatorSignatureResponse {
            operator_id: "operator-divergent".to_string(),
            kid: "kid-op-div".to_string(),
            payload_sha256: [0xffu8; 32], // Hash divergente
            payload_b64: divergent_payload,
            signature: sig_div,
        },
    ];

    let mut keys = BTreeMap::new();
    keys.insert("kid-op-1".to_string(), op1.public_key().clone());
    keys.insert("kid-op-2".to_string(), op2.public_key().clone());
    keys.insert("kid-op-3".to_string(), op3.public_key().clone());
    keys.insert("kid-op-div".to_string(), op_div.public_key().clone());

    let aggregator = UntrustedBundleAggregator::new(3);
    assert_eq!(aggregator.threshold(), 3);

    let result = aggregator
        .aggregate(&bundle, &responses, &keys)
        .expect("aggregation should succeed with 3 valid operators");

    assert_eq!(result.distinct_operators, 3);
    assert_eq!(result.valid_signatures_count, 3);
    assert_eq!(result.divergent_operators, vec!["operator-divergent"]);
    assert_eq!(result.payload_b64, payload_b64);
    assert_eq!(result.canonical_digest, bundle.sha256_digest);

    // Verificar que el JWS JSON resultante cumple RFC 7515 §7.2
    let parsed_jws = JwsJsonParser::parse(&result.jws_json).expect("valid JWS JSON");
    assert_eq!(parsed_jws.signatures.len(), 3);
    assert_eq!(parsed_jws.payload_b64, payload_b64);

    // Serde roundtrip de AggregatedSignedBundle
    let json_agg = serde_json::to_string(&result).expect("serialize agg");
    let agg_back: pip_trust_service::aggregator::AggregatedSignedBundle =
        serde_json::from_str(&json_agg).expect("deserialize agg");
    assert_eq!(result, agg_back);
}

#[test]
fn test_aggregator_insufficient_signatures() {
    let bundle = derive_test_bundle();
    let payload_b64 = gravital_id_codec::base64url::encode(&bundle.canonical_json_bytes);

    let op1 = create_test_signer("op-1", "kid-1", 1);
    let op2 = create_test_signer("op-2", "kid-2", 2);

    let sig1 = op1.sign_payload_b64(&payload_b64).unwrap();
    let sig2 = op2.sign_payload_b64(&payload_b64).unwrap();

    let responses = vec![
        OperatorSignatureResponse {
            operator_id: "op-1".to_string(),
            kid: "kid-1".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig1,
        },
        OperatorSignatureResponse {
            operator_id: "op-2".to_string(),
            kid: "kid-2".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig2,
        },
    ];

    let mut keys = BTreeMap::new();
    keys.insert("kid-1".to_string(), op1.public_key().clone());
    keys.insert("kid-2".to_string(), op2.public_key().clone());

    // Exigimos 3 operadores, solo tenemos 2
    let aggregator = UntrustedBundleAggregator::new(3);
    let err = aggregator
        .aggregate(&bundle, &responses, &keys)
        .unwrap_err();

    match err {
        TrustServiceError::InsufficientSignatures { required, valid } => {
            assert_eq!(required, 3);
            assert_eq!(valid, 2);
        }
        other => panic!("Expected InsufficientSignatures, got {other:?}"),
    }
}

#[test]
fn test_aggregator_duplicate_operator_signatures() {
    let bundle = derive_test_bundle();
    let payload_b64 = gravital_id_codec::base64url::encode(&bundle.canonical_json_bytes);

    let op1 = create_test_signer("op-1", "kid-1", 1);
    let op2 = create_test_signer("op-2", "kid-2", 2);

    let sig1a = op1.sign_payload_b64(&payload_b64).unwrap();
    let sig1b = op1.sign_payload_b64(&payload_b64).unwrap();
    let sig2 = op2.sign_payload_b64(&payload_b64).unwrap();

    // 3 firmas pero solo 2 operadores distintos (op-1 envía 2 firmas)
    let responses = vec![
        OperatorSignatureResponse {
            operator_id: "op-1".to_string(),
            kid: "kid-1".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig1a,
        },
        OperatorSignatureResponse {
            operator_id: "op-1".to_string(),
            kid: "kid-1".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig1b,
        },
        OperatorSignatureResponse {
            operator_id: "op-2".to_string(),
            kid: "kid-2".to_string(),
            payload_sha256: bundle.sha256_digest,
            payload_b64: payload_b64.clone(),
            signature: sig2,
        },
    ];

    let mut keys = BTreeMap::new();
    keys.insert("kid-1".to_string(), op1.public_key().clone());
    keys.insert("kid-2".to_string(), op2.public_key().clone());

    // Con umbral 3 debe fallar porque solo hay 2 operadores distintos
    let aggregator = UntrustedBundleAggregator::new(3);
    assert!(aggregator.aggregate(&bundle, &responses, &keys).is_err());

    // Con umbral 2 debe pasar y solo contabilizar 2 firmas válidas
    let aggregator2 = UntrustedBundleAggregator::new(2);
    let agg = aggregator2.aggregate(&bundle, &responses, &keys).unwrap();
    assert_eq!(agg.distinct_operators, 2);
    assert_eq!(agg.valid_signatures_count, 2);
}

#[test]
fn test_aggregator_invalid_cryptographic_signature() {
    let bundle = derive_test_bundle();
    let payload_b64 = gravital_id_codec::base64url::encode(&bundle.canonical_json_bytes);

    let op1 = create_test_signer("op-1", "kid-1", 1);
    let mut sig1 = op1.sign_payload_b64(&payload_b64).unwrap();
    // Corromper la firma
    sig1.signature[0] ^= 0xff;

    let responses = vec![OperatorSignatureResponse {
        operator_id: "op-1".to_string(),
        kid: "kid-1".to_string(),
        payload_sha256: bundle.sha256_digest,
        payload_b64: payload_b64.clone(),
        signature: sig1,
    }];

    let mut keys = BTreeMap::new();
    keys.insert("kid-1".to_string(), op1.public_key().clone());

    let aggregator = UntrustedBundleAggregator::new(1);
    assert!(aggregator.aggregate(&bundle, &responses, &keys).is_err());
}

#[test]
fn test_aggregator_unknown_kid() {
    let bundle = derive_test_bundle();
    let payload_b64 = gravital_id_codec::base64url::encode(&bundle.canonical_json_bytes);

    let op1 = create_test_signer("op-1", "kid-1", 1);
    let sig1 = op1.sign_payload_b64(&payload_b64).unwrap();

    let responses = vec![OperatorSignatureResponse {
        operator_id: "op-1".to_string(),
        kid: "kid-1".to_string(),
        payload_sha256: bundle.sha256_digest,
        payload_b64: payload_b64.clone(),
        signature: sig1,
    }];

    // Diccionario de claves vacío (kid desconocido)
    let keys = BTreeMap::new();

    let aggregator = UntrustedBundleAggregator::new(1);
    assert!(aggregator.aggregate(&bundle, &responses, &keys).is_err());
}

#[test]
fn test_assemble_jws_json_direct() {
    let payload_b64 = "eyJzdWIiOiIxMjM0NTY3ODkwIn0";
    let signatures = vec![];
    let jws = assemble_jws_json(payload_b64, &signatures);
    assert!(jws.contains(r#""payload":"eyJzdWIiOiIxMjM0NTY3ODkwIn0""#));
    assert!(jws.contains(r#""signatures":[]"#));
}

#[test]
fn test_aggregator_with_trust_root() {
    let bundle = derive_test_bundle();
    let payload_b64 = gravital_id_codec::base64url::encode(&bundle.canonical_json_bytes);

    let op_auth = create_test_signer("op-auth", "kid-authorized", 777);
    let op_unauth = create_test_signer("op-unauth", "kid-unauthorized", 888);

    let auth_jwk_json = op_auth.public_key().to_canonical_json();

    let root_json = format!(
        r#"{{
            "framework_id": "pip-global-mainnet",
            "root_version": 1,
            "bundle_epoch": 1,
            "issued_at": 1700000000,
            "valid_until": 1800000000,
            "chain_id": 31337,
            "registry_address": "0x1234567890123456789012345678901234567890",
            "root_keys": [
                {{
                    "kid": "root-key-1",
                    "jwk": {auth_jwk_json}
                }}
            ],
            "root_threshold": 1,
            "bundle_signers": [
                {{
                    "operator": "op-auth",
                    "kid": "kid-authorized",
                    "jwk": {auth_jwk_json}
                }}
            ],
            "bundle_threshold": 1
        }}"#
    );

    let parsed_root_val = gravital_id_codec::json::parse(&root_json).expect("parse root json");
    let trust_root = gravital_id_trust::root::TrustRoot::from_payload(&parsed_root_val)
        .expect("build trust root");

    let aggregator = UntrustedBundleAggregator::new(1).with_root(trust_root);

    // 1. Operador no autorizado en la raíz debe ser ignorado
    let sig_unauth = op_unauth.sign_payload_b64(&payload_b64).unwrap();
    let unauth_resp = vec![OperatorSignatureResponse {
        operator_id: "op-unauth".to_string(),
        kid: "kid-unauthorized".to_string(),
        payload_sha256: bundle.sha256_digest,
        payload_b64: payload_b64.clone(),
        signature: sig_unauth,
    }];
    assert!(aggregator
        .aggregate(&bundle, &unauth_resp, &BTreeMap::new())
        .is_err());

    // 2. Operador autorizado en la raíz debe ser aceptado
    let sig_auth = op_auth.sign_payload_b64(&payload_b64).unwrap();
    let auth_resp = vec![OperatorSignatureResponse {
        operator_id: "op-auth".to_string(),
        kid: "kid-authorized".to_string(),
        payload_sha256: bundle.sha256_digest,
        payload_b64: payload_b64.clone(),
        signature: sig_auth,
    }];
    let agg = aggregator
        .aggregate(&bundle, &auth_resp, &BTreeMap::new())
        .expect("authorized operator passes");
    assert_eq!(agg.distinct_operators, 1);
}
