//! Pruebas unitarias de nodo operador institucional (F7.T04, REQ-TRUST-003, REQ-TRUST-008).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use gravital_id_crypto::sign::verify_es256_jwk;
use gravital_id_ledger::adapter::BlockHeader;
use gravital_id_ledger::{
    BundleDerivationParams, EventCoordinate, LedgerEvent, SequencedLedgerEvent,
    VerifierRegisteredEvent,
};
use gravital_id_testkit::SeededRng;
use pip_indexer::storage::{InMemoryIndexerStorage, IndexerStorage};
use pip_trust_service::operator::TrustOperatorNode;
use pip_trust_service::signer::LocalDevSigner;
use std::sync::Arc;

fn make_derivation_params() -> BundleDerivationParams {
    BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(50, [0x50; 32], [0u8; 32], 1700000000),
        604800,
        vec![],
    )
}

#[test]
fn test_operator_node_creation_and_accessors() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let rng = SeededRng::new(1);
    let signer = Arc::new(LocalDevSigner::generate_with_rng("op-test", "kid-test", &rng).unwrap());

    let node = TrustOperatorNode::new(storage, signer, 31337);
    assert_eq!(node.operator_id(), "op-test");
    assert_eq!(node.kid(), "kid-test");
    assert_eq!(node.signer().operator_id(), "op-test");
}

#[test]
fn test_operator_node_derive_and_sign_empty_state() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let rng = SeededRng::new(2);
    let signer =
        Arc::new(LocalDevSigner::generate_with_rng("op-alpha", "kid-alpha", &rng).unwrap());

    let node = TrustOperatorNode::new(storage, signer, 31337);
    let params = make_derivation_params();

    let derived = node.derive_local_bundle(&params).expect("derive bundle");
    assert_eq!(derived.bundle.framework_id(), "pip-global-mainnet");

    let response = node.evaluate_and_sign(&params).expect("evaluate and sign");
    assert_eq!(response.operator_id, "op-alpha");
    assert_eq!(response.kid, "kid-alpha");
    assert_eq!(response.payload_sha256, derived.sha256_digest);

    // Verificar firma criptográficamente
    let signing_input = format!(
        "{}.{}",
        response.signature.protected_b64, response.payload_b64
    );
    assert!(verify_es256_jwk(
        node.signer().public_key(),
        signing_input.as_bytes(),
        &response.signature.signature
    )
    .is_ok());
}

#[test]
fn test_operator_nodes_identical_state_yield_identical_digests() {
    let params = make_derivation_params();

    let storage1 = Arc::new(InMemoryIndexerStorage::new());
    let storage2 = Arc::new(InMemoryIndexerStorage::new());

    // Insertar el mismo evento en ambos almacenamientos
    let event = SequencedLedgerEvent {
        coordinate: EventCoordinate::new(10, 0, 0, 1699990000),
        event: LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
            verifier_id: [1u8; 32],
            uri: "https://verifier1.example.com".to_string(),
            profiles: vec!["pip-personal-v1".to_string()],
            public_key: vec![],
            valid_from: 1699990000,
            valid_until: 1799990000,
        }),
    };

    storage1
        .store_events(31337, core::slice::from_ref(&event))
        .unwrap();
    storage2
        .store_events(31337, core::slice::from_ref(&event))
        .unwrap();

    let rng1 = SeededRng::new(10);
    let rng2 = SeededRng::new(20);
    let signer1 = Arc::new(LocalDevSigner::generate_with_rng("op-1", "kid-1", &rng1).unwrap());
    let signer2 = Arc::new(LocalDevSigner::generate_with_rng("op-2", "kid-2", &rng2).unwrap());

    let node1 = TrustOperatorNode::new(storage1, signer1, 31337);
    let node2 = TrustOperatorNode::new(storage2, signer2, 31337);

    let resp1 = node1.evaluate_and_sign(&params).unwrap();
    let resp2 = node2.evaluate_and_sign(&params).unwrap();

    // Invariante REQ-TRUST-008: Operadores independientes sobre el mismo estado
    // obtienen EXACTAMENTE el mismo digest y payload canónico.
    assert_eq!(resp1.payload_sha256, resp2.payload_sha256);
    assert_eq!(resp1.payload_b64, resp2.payload_b64);

    // Pero firmas distintas porque provienen de distintas claves privadas
    assert_ne!(resp1.signature.signature, resp2.signature.signature);
    assert_ne!(resp1.kid, resp2.kid);
}

#[test]
fn test_operator_nodes_divergent_state_yield_different_digests() {
    let params = make_derivation_params();

    let storage1 = Arc::new(InMemoryIndexerStorage::new());
    let storage2 = Arc::new(InMemoryIndexerStorage::new());

    // Storage 1 recibe evento de registro
    let event = SequencedLedgerEvent {
        coordinate: EventCoordinate::new(10, 0, 0, 1699990000),
        event: LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
            verifier_id: [1u8; 32],
            uri: "https://verifier1.example.com".to_string(),
            profiles: vec!["pip-personal-v1".to_string()],
            public_key: vec![],
            valid_from: 1699990000,
            valid_until: 1799990000,
        }),
    };
    storage1
        .store_events(31337, core::slice::from_ref(&event))
        .unwrap();

    // Storage 2 queda vacío (desincronizado)
    let rng1 = SeededRng::new(10);
    let rng2 = SeededRng::new(20);
    let signer1 = Arc::new(LocalDevSigner::generate_with_rng("op-1", "kid-1", &rng1).unwrap());
    let signer2 = Arc::new(LocalDevSigner::generate_with_rng("op-2", "kid-2", &rng2).unwrap());

    let node1 = TrustOperatorNode::new(storage1, signer1, 31337);
    let node2 = TrustOperatorNode::new(storage2, signer2, 31337);

    let resp1 = node1.evaluate_and_sign(&params).unwrap();
    let resp2 = node2.evaluate_and_sign(&params).unwrap();

    // Los hashes deben ser distintos (divergencia)
    assert_ne!(resp1.payload_sha256, resp2.payload_sha256);
    assert_ne!(resp1.payload_b64, resp2.payload_b64);
}
