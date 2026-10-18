//! Pruebas de integración del motor orquestador de pip-trust-service (F7.T04, REQ-TRUST-003, REQ-TRUST-008).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use gravital_id_ledger::adapter::BlockHeader;
use gravital_id_ledger::{
    EventCoordinate, LedgerEvent, SequencedLedgerEvent, VerifierRegisteredEvent,
};
use gravital_id_testkit::SeededRng;
use gravital_id_trust::jws_json::JwsJsonParser;
use gravital_id_types::Clock;
use pip_indexer::storage::{InMemoryIndexerStorage, IndexerStorage};
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_trust_service::aggregator::UntrustedBundleAggregator;
use pip_trust_service::config::TrustServiceConfig;
use pip_trust_service::engine::{TrustEngineDeps, TrustServiceEngine};
use pip_trust_service::error::TrustServiceError;
use pip_trust_service::operator::TrustOperatorNode;
use pip_trust_service::publisher::{BundlePublisher, InMemoryBundlePublisher};
use pip_trust_service::signer::{BundleSignerBackend, LocalDevSigner};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

struct TestSyncClock(AtomicU64);

impl Clock for TestSyncClock {
    fn now_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn monotonic_elapsed_millis(&self) -> Option<u64> {
        None
    }
}

fn create_operator(
    id: &str,
    kid: &str,
    seed: u64,
    storage: Arc<InMemoryIndexerStorage>,
) -> Arc<TrustOperatorNode> {
    let rng = SeededRng::new(seed);
    let signer = Arc::new(LocalDevSigner::generate_with_rng(id, kid, &rng).unwrap());
    Arc::new(TrustOperatorNode::new(storage, signer, 31337))
}

#[test]
fn test_engine_successful_step_and_publication() {
    let storage = Arc::new(InMemoryIndexerStorage::new());

    // Poblar el almacenamiento con un evento de verificador
    let event = SequencedLedgerEvent {
        coordinate: EventCoordinate::new(10, 0, 0, 1699990000),
        event: LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
            verifier_id: [1u8; 32],
            uri: "https://verifier.example.com".to_string(),
            profiles: vec!["pip-personal-v1".to_string()],
            public_key: vec![],
            valid_from: 1699990000,
            valid_until: 1799990000,
        }),
    };
    storage
        .store_events(31337, core::slice::from_ref(&event))
        .unwrap();

    let op1 = create_operator("op-1", "kid-1", 101, storage.clone());
    let op2 = create_operator("op-2", "kid-2", 102, storage.clone());
    let op3 = create_operator("op-3", "kid-3", 103, storage.clone());

    let mut config = TrustServiceConfig::default();
    config.threshold = 3;
    config.bundle_epoch = 1;
    config.bundle_version = 1;
    config.validity_duration_seconds = 604800;

    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let aggregator = UntrustedBundleAggregator::new(3);
    let clock = Arc::new(TestSyncClock(AtomicU64::new(1700000000)));
    let shutdown = ShutdownCoordinator::new();
    let status = Arc::new(Mutex::new(None));

    let deps = TrustEngineDeps {
        primary_node: op1,
        operator_nodes: vec![op2, op3],
        aggregator,
        publisher: publisher.clone(),
        clock,
        shutdown,
        status: status.clone(),
    };

    let engine = TrustServiceEngine::new(config, deps);

    let header = BlockHeader::new(20, [0x20; 32], [0u8; 32], 1700000000);

    let record = engine.step(header, vec![]).expect("step succeeds");
    assert_eq!(record.current_key, "bundles/current.json");
    assert_eq!(record.versioned_key, "bundles/1/1.json");

    // Verificar en almacenamiento
    let published_json = publisher.get_current_bundle().expect("get bundle");
    let parsed = JwsJsonParser::parse(&published_json).expect("valid jws");
    assert_eq!(parsed.signatures.len(), 3);

    // Verificar estado
    let st = engine.current_status().expect("status available");
    assert!(st.success);
    assert_eq!(st.last_bundle.as_ref().unwrap().distinct_operators, 3);
    assert!(st
        .last_bundle
        .as_ref()
        .unwrap()
        .divergent_operators
        .is_empty());
}

#[test]
fn test_engine_divergence_isolation() {
    let storage_good = Arc::new(InMemoryIndexerStorage::new());
    let storage_bad = Arc::new(InMemoryIndexerStorage::new());

    // Storage bad recibe un evento distinto
    let event = SequencedLedgerEvent {
        coordinate: EventCoordinate::new(99, 0, 0, 1699990000),
        event: LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
            verifier_id: [0x99; 32],
            uri: "https://bad-verifier.example.com".to_string(),
            profiles: vec!["pip-personal-v1".to_string()],
            public_key: vec![],
            valid_from: 1699990000,
            valid_until: 1799990000,
        }),
    };
    storage_bad
        .store_events(31337, core::slice::from_ref(&event))
        .unwrap();

    let op1 = create_operator("op-good-1", "kid-1", 101, storage_good.clone());
    let op2 = create_operator("op-good-2", "kid-2", 102, storage_good.clone());
    let op3 = create_operator("op-good-3", "kid-3", 103, storage_good.clone());
    let op_bad = create_operator("op-divergent", "kid-bad", 999, storage_bad);

    let mut config = TrustServiceConfig::default();
    config.threshold = 3;

    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let aggregator = UntrustedBundleAggregator::new(3);
    let clock = Arc::new(TestSyncClock(AtomicU64::new(1700000000)));
    let shutdown = ShutdownCoordinator::new();
    let status = Arc::new(Mutex::new(None));

    let deps = TrustEngineDeps {
        primary_node: op1,
        operator_nodes: vec![op2, op3, op_bad],
        aggregator,
        publisher,
        clock,
        shutdown,
        status,
    };

    let engine = TrustServiceEngine::new(config, deps);

    let header = BlockHeader::new(20, [0x20; 32], [0u8; 32], 1700000000);

    let record = engine
        .step(header, vec![])
        .expect("step succeeds despite 1 divergent node");
    assert_eq!(record.current_key, "bundles/current.json");

    let st = engine.current_status().expect("status available");
    assert!(st.success);
    let last = st.last_bundle.unwrap();
    assert_eq!(last.distinct_operators, 3);
    assert_eq!(last.divergent_operators, vec!["op-divergent"]);
}

#[test]
fn test_engine_insufficient_operators_records_failure() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let op1 = create_operator("op-sole", "kid-sole", 1, storage);

    let mut config = TrustServiceConfig::default();
    config.threshold = 3; // Exige 3 pero solo hay 1

    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let aggregator = UntrustedBundleAggregator::new(3);
    let clock = Arc::new(TestSyncClock(AtomicU64::new(1700000000)));
    let shutdown = ShutdownCoordinator::new();
    let status = Arc::new(Mutex::new(None));

    let deps = TrustEngineDeps {
        primary_node: op1,
        operator_nodes: vec![],
        aggregator,
        publisher,
        clock,
        shutdown,
        status,
    };

    let engine = TrustServiceEngine::new(config, deps);

    let header = BlockHeader::new(20, [0x20; 32], [0u8; 32], 1700000000);

    assert!(engine.step(header, vec![]).is_err());

    let st = engine.current_status().expect("failure recorded");
    assert!(!st.success);
    assert!(st
        .error_message
        .unwrap()
        .to_lowercase()
        .contains("insuficiente"));
}

#[test]
fn test_engine_run_loop_and_graceful_shutdown() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let op1 = create_operator("op-1", "kid-1", 1, storage.clone());
    let op2 = create_operator("op-2", "kid-2", 2, storage.clone());

    let mut config = TrustServiceConfig::default();
    config.threshold = 2;
    config.poll_interval_millis = 10;

    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let aggregator = UntrustedBundleAggregator::new(2);
    let clock = Arc::new(TestSyncClock(AtomicU64::new(1700000000)));
    let shutdown = ShutdownCoordinator::new();
    let status = Arc::new(Mutex::new(None));

    let deps = TrustEngineDeps {
        primary_node: op1,
        operator_nodes: vec![op2],
        aggregator,
        publisher,
        clock,
        shutdown: shutdown.clone(),
        status,
    };

    let engine = Arc::new(TrustServiceEngine::new(config, deps));

    let engine_clone = engine.clone();
    let shutdown_clone = shutdown.clone();

    let handle = thread::spawn(move || {
        let mut count = 0;
        engine_clone.run_loop(|| {
            count += 1;
            if count == 1 {
                Some((BlockHeader::new(1, [1; 32], [0; 32], 1700000001), vec![]))
            } else {
                shutdown_clone.trigger_shutdown();
                None
            }
        });
    });

    handle.join().expect("thread completes cleanly");
    assert!(shutdown.is_shutting_down());
    assert!(engine.current_status().unwrap().success);
}

struct FailingSigner {
    operator_id: String,
    kid: String,
    jwk: gravital_id_crypto::jwk::JwkEcP256,
}

impl BundleSignerBackend for FailingSigner {
    fn operator_id(&self) -> &str {
        &self.operator_id
    }
    fn kid(&self) -> &str {
        &self.kid
    }
    fn public_key(&self) -> &gravital_id_crypto::jwk::JwkEcP256 {
        &self.jwk
    }
    fn sign_input(&self, _signing_input: &str) -> Result<Vec<u8>, TrustServiceError> {
        Err(TrustServiceError::Crypto(
            "Hardware HSM offline".to_string(),
        ))
    }
}

#[test]
fn test_engine_signer_failures_handled_gracefully() {
    let storage = Arc::new(InMemoryIndexerStorage::new());

    let rng_sample = SeededRng::new(555);
    let sample_signer =
        LocalDevSigner::generate_with_rng("op-sample", "kid-sample", &rng_sample).unwrap();

    let failing_primary_signer = Arc::new(FailingSigner {
        operator_id: "op-primary-fail".to_string(),
        kid: "kid-primary-fail".to_string(),
        jwk: sample_signer.public_key().clone(),
    });
    let failing_peer_signer = Arc::new(FailingSigner {
        operator_id: "op-peer-fail".to_string(),
        kid: "kid-peer-fail".to_string(),
        jwk: sample_signer.public_key().clone(),
    });

    let primary_node = Arc::new(TrustOperatorNode::new(
        storage.clone(),
        failing_primary_signer,
        31337,
    ));
    let failing_peer_node = Arc::new(TrustOperatorNode::new(
        storage.clone(),
        failing_peer_signer,
        31337,
    ));
    let good_peer_1 = create_operator("op-good-1", "kid-g1", 11, storage.clone());
    let good_peer_2 = create_operator("op-good-2", "kid-g2", 22, storage.clone());

    let mut config = TrustServiceConfig::default();
    config.threshold = 2;

    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let aggregator = UntrustedBundleAggregator::new(2);
    let clock = Arc::new(TestSyncClock(AtomicU64::new(1700000000)));
    let shutdown = ShutdownCoordinator::new();
    let status = Arc::new(Mutex::new(None));

    let deps = TrustEngineDeps {
        primary_node,
        operator_nodes: vec![failing_peer_node, good_peer_1, good_peer_2],
        aggregator,
        publisher,
        clock,
        shutdown,
        status,
    };

    let engine = TrustServiceEngine::new(config, deps);
    let header = BlockHeader::new(10, [10; 32], [0; 32], 1700000000);

    // Debe tolerar fallos individuales de firma y alcanzar quórum con los 2 nodos funcionales
    let record = engine
        .step(header, vec![])
        .expect("quorum reached despite failures");
    assert_eq!(record.current_key, "bundles/current.json");
    assert_eq!(
        engine
            .current_status()
            .unwrap()
            .last_bundle
            .unwrap()
            .distinct_operators,
        2
    );
}

struct FailingStoragePublisher;

impl BundlePublisher for FailingStoragePublisher {
    fn publish_bundle(
        &self,
        _epoch: u64,
        _version: u64,
        _jws_json: &str,
        _digest: &[u8; 32],
        _timestamp: u64,
    ) -> Result<pip_trust_service::publisher::PublishedBundleRecord, TrustServiceError> {
        Err(TrustServiceError::Storage(
            "S3 network partition".to_string(),
        ))
    }

    fn get_object(&self, _key: &str) -> Result<Option<String>, TrustServiceError> {
        Err(TrustServiceError::Storage(
            "S3 network partition".to_string(),
        ))
    }
}

#[test]
fn test_engine_publisher_storage_failure() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let op1 = create_operator("op-1", "kid-1", 1, storage.clone());
    let op2 = create_operator("op-2", "kid-2", 2, storage);

    let config = TrustServiceConfig {
        threshold: 2,
        ..Default::default()
    };

    let publisher = Arc::new(FailingStoragePublisher);
    let aggregator = UntrustedBundleAggregator::new(2);
    let clock = Arc::new(TestSyncClock(AtomicU64::new(1700000000)));
    let shutdown = ShutdownCoordinator::new();
    let status = Arc::new(Mutex::new(None));

    let deps = TrustEngineDeps {
        primary_node: op1,
        operator_nodes: vec![op2],
        aggregator,
        publisher,
        clock,
        shutdown,
        status,
    };

    let engine = TrustServiceEngine::new(config, deps);
    let header = BlockHeader::new(10, [10; 32], [0; 32], 1700000000);

    let res = engine.step(header, vec![]);
    assert!(res.is_err());

    let st = engine.current_status().unwrap();
    assert!(!st.success);
    assert!(st.error_message.unwrap().contains("S3 network partition"));
}
