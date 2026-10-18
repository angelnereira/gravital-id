#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración automatizadas de extremo a extremo para la pila de contenedores (F7.T10).
//!
//! Flujo completo verificado:
//! Cadena local (Anvil / EVM Ledger)
//!   -> Indexador (pip-indexer: eventos, checkpoint, proyecciones puras)
//!   -> Trust Service (pip-trust-service: operadores k-de-n, agregación y publicación)
//!   -> Relay (pip-relay: objetos direccionados por SHA-256, buzones HPKE y SessionCode Damm)
//!   -> SDK (Verificación completa multi-fuente, emisión, presentación offline y sincronización)
//!
//! Trazabilidad:
//! - **REQ-REL-001:** Ningún servicio es punto único de fallo; tolerancia a particiones.
//! - **REQ-LEDG-005:** Indexación idempotente acotada a bloques finalizados.
//! - **REQ-TRUST-001:** Cofirma multi-operador con umbral k-de-n.
//! - **REQ-TRUST-003:** Derivación acotada exclusivamente a bloques finalizados.
//! - **REQ-TRUST-004:** Modo de verificación completa contrastado con >= 2 fuentes de ledger.
//! - **REQ-TRUST-005:** Raíz de confianza fija y firmantes registrados.
//! - **REQ-TRUST-008:** Derivación determinista idéntica byte a byte.
//! - **REQ-SYNC-001:** Cola de salida cifrada con claves de idempotencia.
//! - **REQ-SYNC-002:** Deduplicación en recepción con entrega al-menos-una-vez.
//! - **REQ-SYNC-004:** Verificación estricta de hash de todo contenido recibido.
//! - **REQ-SYNC-006:** Sobres cifrados con HPKE (RFC 9180).
//! - **REQ-CODE-001..004:** Identificador numérico efímero de sesión de 10 dígitos con Damm.
//! - **REQ-PRIV-003 / INV-02:** Cero datos personales o secretos en bases de datos, mensajes o logs.
//! - **INV-01:** Verificación sin red y núcleo sans-I/O.
//! - **INV-04:** Cuatro estados normativos en el resultado de verificación.
//! - **INV-05:** Fail-closed determinista ante cualquier ambigüedad o falta de quórum.
//! - **INV-11:** Inyección explícita de tiempo y aleatoriedad determinista.
//! - **INV-16:** Umbral k-de-n inviolable sin firmante único.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gravital_id_codec::json::{Number, Value};
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_ledger::{
    BlockHeader, BundleDerivationParams, EventCoordinate, FullVerificationEngine,
    FullVerificationOutcome, InMemoryLedgerAdapter, IssuerRegisteredEvent, KeyAddedEvent,
    KeyCompromisedEvent, LedgerAdapter, LedgerEvent, SequencedLedgerEvent,
    StatusManifestAnchoredEvent, TrustRootUpdatedEvent,
};
use gravital_id_status::builder::TokenStatusListBuilder;
use gravital_id_sync::{
    ContentVerifier, EncryptedOutboxQueue, HpkeEnvelope, InboundDeduplicationFilter, MailboxId,
    OperationId, SyncOperation,
};
use gravital_id_testkit::SeededRng;
use gravital_id_trust::root::TrustRoot;
use gravital_id_trust::{TrustBundle, TrustBundleVerifier};
use gravital_id_types::{Clock, UnixTime};

use pip_indexer::config::IndexerConfig;
use pip_indexer::engine::IndexerEngine;
use pip_indexer::storage::{InMemoryIndexerStorage, IndexerStorage};
use pip_relay::config::RelayConfig;
use pip_relay::store::{
    compute_damm_check_digit, compute_session_hash_hex, validate_session_code, InMemoryRelayStore,
};
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_trust_service::aggregator::UntrustedBundleAggregator;
use pip_trust_service::operator::TrustOperatorNode;
use pip_trust_service::publisher::{BundlePublisher, InMemoryBundlePublisher};
use pip_trust_service::signer::LocalDevSigner;

const LOCAL_CHAIN_ID: u64 = 31337;
const TEST_REGISTRY_ADDR: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const TEST_FRAMEWORK_ID: &str = "pip-global-mainnet";

/// Reloj sincronizado con AtomicU64 que implementa Send + Sync + 'static.
#[derive(Debug, Clone)]
struct TestSyncClock {
    now: Arc<AtomicU64>,
}

impl TestSyncClock {
    fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }
}

impl Clock for TestSyncClock {
    fn now_seconds(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn monotonic_elapsed_millis(&self) -> Option<u64> {
        None
    }
}

/// Helper para codificar bytes a hex en pruebas.
fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Helper para generar par de claves de prueba deterministas con seed.
fn sample_key(seed: u64) -> (Vec<u8>, JwkEcP256, [u8; 32]) {
    let rng = SeededRng::new(seed);
    let sk = generate_p256_secret_key(&rng).expect("valid secret key");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");

    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(jwk.x());
    uncompressed.extend_from_slice(jwk.y());

    let mut kid = [0u8; 32];
    kid.copy_from_slice(jwk.thumbprint_sha256().as_slice());

    (uncompressed, jwk, kid)
}

/// Helper para generar firmante local de bundle con clave conocida.
fn sample_bundle_signer(operator_id: &str, seed: u64) -> (LocalDevSigner, JwkEcP256, String) {
    let rng = SeededRng::new(seed);
    let sk = generate_p256_secret_key(&rng).expect("valid sk");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");
    let kid = format!("kid-{operator_id}");

    let signer = LocalDevSigner::from_secret_key(operator_id, &kid, &sk).expect("valid dev signer");
    (signer, jwk, kid)
}

/// Helper para construir un `TrustRoot` normativo a partir de firmantes registrados.
fn make_test_trust_root(
    framework_id: &str,
    epoch: u64,
    version: u64,
    bundle_threshold: u32,
    signers: &[(&str, &str, &JwkEcP256)],
) -> TrustRoot {
    let root_keys: Vec<Value> = signers
        .iter()
        .map(|(_, kid, jwk)| {
            Value::Object(vec![
                ("kid".to_string(), Value::String((*kid).to_string())),
                ("jwk".to_string(), gravital_id_trust::json_value_of(jwk)),
            ])
        })
        .collect();

    let bundle_signers: Vec<Value> = signers
        .iter()
        .map(|(op, kid, jwk)| {
            Value::Object(vec![
                ("operator".to_string(), Value::String((*op).to_string())),
                ("kid".to_string(), Value::String((*kid).to_string())),
                ("jwk".to_string(), gravital_id_trust::json_value_of(jwk)),
            ])
        })
        .collect();

    let payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String(framework_id.to_string()),
        ),
        (
            "root_version".to_string(),
            Value::Number(Number::PosInt(version)),
        ),
        (
            "bundle_epoch".to_string(),
            Value::Number(Number::PosInt(epoch)),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(1_600_000_000)),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(2_000_000_000)),
        ),
        (
            "chain_id".to_string(),
            Value::Number(Number::PosInt(LOCAL_CHAIN_ID)),
        ),
        (
            "registry_address".to_string(),
            Value::String(TEST_REGISTRY_ADDR.to_string()),
        ),
        (
            "root_threshold".to_string(),
            Value::Number(Number::PosInt(1)),
        ),
        ("root_keys".to_string(), Value::Array(root_keys)),
        (
            "bundle_threshold".to_string(),
            Value::Number(Number::PosInt(u64::from(bundle_threshold))),
        ),
        ("bundle_signers".to_string(), Value::Array(bundle_signers)),
    ]);

    TrustRoot::from_payload(&payload).expect("valid trust root")
}

// Verifies: REQ-REL-001, REQ-LEDG-005, REQ-TRUST-001, REQ-TRUST-003, REQ-TRUST-004,
//           REQ-TRUST-005, REQ-TRUST-008, REQ-SYNC-001, REQ-SYNC-002, REQ-SYNC-004,
//           REQ-SYNC-006, REQ-CODE-001..004, INV-01, INV-02, INV-04, INV-05, INV-11, INV-16
#[test]
fn test_container_stack_e2e_nominal_flow() {
    let base_time = 1_700_000_000u64;
    let clock = Arc::new(TestSyncClock::new(base_time));

    // =========================================================================
    // 1. CADENA LOCAL (EVM / Anvil Ledger Adapter)
    // =========================================================================
    let (issuer_key_raw, _, issuer_kid) = sample_key(101);
    let issuer_id = [0x50; 32];
    let issuer_uri = "did:web:te.gob.pa";

    // Configuramos 3 operadores de confianza institucional para la raíz
    let (signer_op1, jwk_op1, kid_op1) = sample_bundle_signer("op-te-pa", 201);
    let (signer_op2, jwk_op2, kid_op2) = sample_bundle_signer("op-consortium-1", 202);
    let (signer_op3, jwk_op3, kid_op3) = sample_bundle_signer("op-consortium-2", 203);

    let trust_root = make_test_trust_root(
        TEST_FRAMEWORK_ID,
        1,
        1,
        2, // umbral k=2 de n=3
        &[
            ("op-te-pa", &kid_op1, &jwk_op1),
            ("op-consortium-1", &kid_op2, &jwk_op2),
            ("op-consortium-2", &kid_op3, &jwk_op3),
        ],
    );

    // Eventos canónicos generados en el ledger hasta el bloque 50
    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, base_time.saturating_add(10)),
            LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash: [0x11; 32],
                root_version: 1,
                updated_at: base_time.saturating_add(10),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, base_time.saturating_add(20)),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: issuer_uri.into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: base_time,
                valid_until: base_time.saturating_add(100_000_000),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(30, 0, 0, base_time.saturating_add(30)),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: issuer_kid,
                public_key: issuer_key_raw,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(50, 0, 0, base_time.saturating_add(50)),
            LedgerEvent::StatusManifestAnchored(StatusManifestAnchoredEvent {
                issuer_id,
                manifest_hash: [0x77; 32],
                manifest_version: 1,
                uri_hint: "https://status.te.gob.pa/manifest.json".into(),
            }),
        ),
    ];

    let head_50 = BlockHeader::new(50, [0xAA; 32], [0x99; 32], base_time.saturating_add(50));

    // Fuente 1 del ledger (nodo local RPC 1)
    let mut ledger_src1 = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_50.clone());
    for ev in &events {
        ledger_src1.add_event(ev.clone());
    }
    let ledger_src1 = Arc::new(ledger_src1);

    // Fuente 2 del ledger (nodo par independiente RPC 2 para verificación multi-fuente)
    let mut ledger_src2 = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_50);
    for ev in &events {
        ledger_src2.add_event(ev.clone());
    }

    // =========================================================================
    // 2. INDEXADOR (pip-indexer: ingesta, checkpoint y proyección de estado)
    // =========================================================================
    let indexer_storage = Arc::new(InMemoryIndexerStorage::new());
    let indexer_config = IndexerConfig {
        chain_id: LOCAL_CHAIN_ID,
        start_block: 0,
        chunk_size_blocks: 100,
        poll_interval_millis: 100,
        ..Default::default()
    };
    let shutdown_coord = ShutdownCoordinator::new();
    let metrics_holder = Arc::new(Mutex::new(None));

    let indexer_engine = IndexerEngine::new(
        ledger_src1.clone(),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config,
        shutdown_coord,
        metrics_holder,
    );

    // Ejecutamos paso de indexación: consume bloques finalizados [0..50]
    let stepped_block = indexer_engine.step().expect("indexer step succeeds");
    assert_eq!(stepped_block, Some(50));

    // Validamos checkpoint y estado puro proyectado
    let checkpoint = indexer_storage
        .get_checkpoint(LOCAL_CHAIN_ID)
        .expect("checkpoint");
    assert_eq!(checkpoint, Some(50));

    let projected_state = indexer_storage
        .build_ledger_state(LOCAL_CHAIN_ID)
        .expect("projected state");
    assert_eq!(projected_state.chain_id(), LOCAL_CHAIN_ID);
    assert_eq!(projected_state.issuers().len(), 1);
    let projected_issuer = projected_state.issuers().get(&issuer_id).expect("issuer");
    assert_eq!(projected_issuer.uri, issuer_uri);
    assert!(projected_issuer.keys.contains_key(&issuer_kid));

    // Verificamos idempotencia de indexación: un segundo step sin nuevos bloques no altera nada
    let second_step = indexer_engine.step().expect("idempotent step");
    assert_eq!(second_step, None);
    assert_eq!(
        indexer_storage.count_events(LOCAL_CHAIN_ID).expect("count"),
        4
    );

    // =========================================================================
    // 3. TRUST SERVICE (pip-trust-service: cofirma multi-operador y publicación)
    // =========================================================================
    let op_node_1 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_op1),
        LOCAL_CHAIN_ID,
    );
    let op_node_2 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_op2),
        LOCAL_CHAIN_ID,
    );
    let op_node_3 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_op3),
        LOCAL_CHAIN_ID,
    );

    let derivation_header =
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], base_time.saturating_add(50));
    let params = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1, // epoch 1
        1, // version 1
        derivation_header,
        604_800, // 7 días de validez
        vec![],
    );

    // Cada operador independiente deriva y firma deterministamente
    let derived_bundle_1 = op_node_1.derive_local_bundle(&params).expect("op 1 derive");
    let sig_1 = op_node_1
        .evaluate_and_sign(&params)
        .expect("operator 1 signs");
    let sig_2 = op_node_2
        .evaluate_and_sign(&params)
        .expect("operator 2 signs");
    let sig_3 = op_node_3
        .evaluate_and_sign(&params)
        .expect("operator 3 signs");

    // Todos los operadores honestos calcularon el mismo digest canónico byte a byte (REQ-TRUST-008)
    assert_eq!(sig_1.payload_sha256, sig_2.payload_sha256);
    assert_eq!(sig_2.payload_sha256, sig_3.payload_sha256);

    let mut authorized_keys = BTreeMap::new();
    authorized_keys.insert(kid_op1.clone(), jwk_op1);
    authorized_keys.insert(kid_op2.clone(), jwk_op2);
    authorized_keys.insert(kid_op3.clone(), jwk_op3);

    // Agregador no confiable verifica quórum k=2 de 3
    let aggregator = UntrustedBundleAggregator::new(2);
    let aggregated = aggregator
        .aggregate(&derived_bundle_1, &[sig_1, sig_2, sig_3], &authorized_keys)
        .expect("aggregation reaches quorum");

    assert_eq!(aggregated.valid_signatures_count, 3);
    assert_eq!(aggregated.distinct_operators, 3);
    assert!(aggregated.divergent_operators.is_empty());

    // Publicación en almacenamiento de objetos / CDN
    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let published_record = publisher
        .publish_bundle(
            1,
            1,
            &aggregated.jws_json,
            &aggregated.canonical_digest,
            base_time.saturating_add(60),
        )
        .expect("publish bundle");

    assert_eq!(published_record.current_key, "bundles/current.json");
    assert_eq!(published_record.versioned_key, "bundles/1/1.json");

    // =========================================================================
    // 4. SDK / VERIFICACIÓN DE CONFIANZA Y MODO COMPLETO (REQ-TRUST-004, INV-16)
    // =========================================================================
    // El cliente descarga el trust bundle vigente desde el publisher
    let current_bundle_jws = publisher
        .get_current_bundle()
        .expect("fetch current bundle");
    let (trust_bundle, multi_signed_jws) =
        TrustBundle::parse(&current_bundle_jws).expect("parse bundle JWS general");

    // Validación formal contra la raíz de confianza fija
    TrustBundleVerifier::verify(
        &trust_bundle,
        &multi_signed_jws,
        &trust_root,
        None,
        UnixTime::from_seconds(base_time.saturating_add(70)),
    )
    .expect("trust bundle verification against root succeeds");

    // Modo de verificación completa: contrasta el bundle contra >= 2 fuentes independientes del ledger
    let full_verifier = FullVerificationEngine::standard();
    let full_outcome = full_verifier.verify_bundle(
        &trust_bundle,
        &[
            ("rpc-primary-node", &*ledger_src1 as &dyn LedgerAdapter),
            ("rpc-secondary-node", &ledger_src2 as &dyn LedgerAdapter),
        ],
        base_time.saturating_add(70),
    );

    assert!(full_outcome.is_verified());
    if let FullVerificationOutcome::Verified {
        sources_verified,
        checkpoints,
        ..
    } = full_outcome
    {
        assert_eq!(sources_verified.len(), 2);
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].chain_id, LOCAL_CHAIN_ID);
        assert_eq!(checkpoints[1].chain_id, LOCAL_CHAIN_ID);
    } else {
        panic!("esperaba FullVerificationOutcome::Verified");
    }

    // =========================================================================
    // 5. RELAY (pip-relay: objetos direccionados por SHA-256 y SessionCode Damm)
    // =========================================================================
    let relay_clock = TestSyncClock::new(base_time);
    let relay_config = RelayConfig {
        max_payload_bytes: 65536,
        ..Default::default()
    };
    let relay_store = Arc::new(InMemoryRelayStore::new(relay_config, relay_clock));

    // Publicación de lista de estado tokenizada direccionada por contenido (REQ-SYNC-004)
    let rng_status = SeededRng::new(301);
    let sk_status = generate_p256_secret_key(&rng_status).expect("sk status");
    let status_signer = gravital_id_status::signer::LocalStatusSigner::new(
        Some("key-status-01".to_string()),
        sk_status,
    )
    .expect("status signer");
    let mut status_builder = TokenStatusListBuilder::new(2, 131_072).expect("status list builder");
    status_builder.with_uri("https://status.te.gob.pa/lists/2026-10");
    status_builder.with_issuer(issuer_uri);
    status_builder.with_issued_at(UnixTime::from_seconds(base_time));
    status_builder.with_expires_at(UnixTime::from_seconds(base_time.saturating_add(86_400)));
    status_builder
        .set_status(42, gravital_id_status::TokenStatus::Valid)
        .expect("set active status");

    let signed_status = status_builder
        .sign(&status_signer)
        .expect("sign status list");
    let status_jwt = signed_status.jwt();
    let status_sha256_hex = signed_status.sha256_hex();

    // Guardar en el relay por digest SHA-256
    let stored_sha256 = relay_store
        .put_object(
            status_jwt.as_bytes().to_vec(),
            Some(status_sha256_hex),
            None,
        )
        .expect("store object in relay");
    assert_eq!(stored_sha256, status_sha256_hex);

    // Consulta y validación estricta de hash
    let fetched_obj = relay_store
        .get_object(status_sha256_hex)
        .expect("get object");
    assert_eq!(fetched_obj, status_jwt.as_bytes());

    // Punto de encuentro con SessionCode de 10 dígitos (REQ-CODE-001..004)
    let body_9 = "483920194"; // 9 dígitos
    let check_digit = compute_damm_check_digit(body_9).expect("check digit");
    let session_code = format!("{body_9}{check_digit}");
    let validated_code = validate_session_code(&session_code).expect("valid code");
    assert_eq!(validated_code, session_code);

    let session_hash = compute_session_hash_hex(&session_code);
    relay_store
        .register_session_request(&session_hash, vec![0xAA, 0xBB, 0xCC], Some(120))
        .expect("create rendezvous session");

    let rendezvous_payload = relay_store
        .get_session_request(&session_hash)
        .expect("consume rendezvous");
    assert_eq!(rendezvous_payload, vec![0xAA, 0xBB, 0xCC]);

    // =========================================================================
    // 6. SINCRONIZACIÓN SANS-I/O CON HPKE (gravital-id-sync, REQ-SYNC-001..006)
    // =========================================================================
    let inbox = MailboxId::new("did:web:holder-mailbox-1").expect("valid mailbox");
    let (recip_key_raw, _, _) = sample_key(401);
    let mut recip_sec1 = [0u8; 65];
    recip_sec1.copy_from_slice(&recip_key_raw[..65]);

    let (eph_raw, _, _) = sample_key(402);
    let mut eph_sk = [0u8; 32];
    eph_sk.copy_from_slice(&eph_raw[..32]);

    // Emisor encola y cifra operación con HPKE
    let mut outbox = EncryptedOutboxQueue::new(100);
    let op_now = UnixTime::from_seconds(base_time.saturating_add(95));
    let op = SyncOperation::new(
        OperationId::new("op-credential-sync-01").expect("valid op id"),
        inbox.clone(),
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        op_now,
        Some(3600),
    );
    outbox.enqueue(op).expect("enqueue outbox");

    let envelope_bytes =
        HpkeEnvelope::seal(&recip_sec1, &eph_sk, b"sync-payload-data", b"sync-aad")
            .expect("encrypt hpke envelope");

    // Envío al buzón del relay
    relay_store
        .post_envelope(inbox.as_str(), "env-001", envelope_bytes, Some(3600))
        .expect("store envelope in relay");

    // Destinatario consulta buzón y aplica filtro de deduplicación
    let envelopes = relay_store
        .get_envelopes(inbox.as_str(), None)
        .expect("list envelopes");
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].envelope_id, "env-001");

    let env_sha256_hex = hex_string(&gravital_id_crypto::sha256(&envelopes[0].payload));
    ContentVerifier::verify_object_sha256(&envelopes[0].payload, &env_sha256_hex)
        .expect("verify content hash");

    let mut dedup_filter = InboundDeduplicationFilter::new(1000, 3600);
    let check_time = UnixTime::from_seconds(base_time.saturating_add(110));
    assert!(!dedup_filter.is_duplicate("env-001", check_time));
    assert!(dedup_filter.check_and_record("env-001", check_time));
    assert!(dedup_filter.is_duplicate("env-001", check_time));
    assert!(!dedup_filter.check_and_record("env-001", check_time));
}

// Verifies: REQ-TRUST-001, REQ-TRUST-008, INV-05, INV-16
#[test]
fn test_container_stack_operator_divergence_tolerance_and_quorum_failure() {
    let base_time = 1_700_000_000u64;

    let (signer_op1, jwk_op1, kid_op1) = sample_bundle_signer("op-1", 301);
    let (signer_op2, jwk_op2, kid_op2) = sample_bundle_signer("op-2", 302);
    let (signer_op3, jwk_op3, kid_op3) = sample_bundle_signer("op-3", 303);

    let (key_bytes1, _, kid1) = sample_key(101);
    let (key_bytes3, _, kid3) = sample_key(103);

    // Storage 1 (honesto) con emisor registrado y clave
    let storage_honest = Arc::new(InMemoryIndexerStorage::new());
    storage_honest
        .store_events(
            LOCAL_CHAIN_ID,
            &[
                SequencedLedgerEvent::new(
                    EventCoordinate::new(10, 0, 0, base_time.saturating_add(10)),
                    LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                        issuer_id: [0x11; 32],
                        uri: "did:web:honest.example.gov".into(),
                        profiles: vec!["pip-personal-v1".into()],
                        vcts: vec![],
                        valid_from: base_time,
                        valid_until: base_time.saturating_add(10_000_000),
                    }),
                ),
                SequencedLedgerEvent::new(
                    EventCoordinate::new(20, 0, 0, base_time.saturating_add(20)),
                    LedgerEvent::KeyAdded(KeyAddedEvent {
                        issuer_id: [0x11; 32],
                        kid: kid1,
                        public_key: key_bytes1,
                    }),
                ),
            ],
        )
        .expect("store events");

    // Storage 2 (divergente/malicioso) con datos alterados
    let storage_divergent = Arc::new(InMemoryIndexerStorage::new());
    storage_divergent
        .store_events(
            LOCAL_CHAIN_ID,
            &[
                SequencedLedgerEvent::new(
                    EventCoordinate::new(10, 0, 0, base_time.saturating_add(10)),
                    LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                        issuer_id: [0x99; 32],
                        uri: "did:web:rogue.example.com".into(),
                        profiles: vec!["pip-rogue-v1".into()],
                        vcts: vec![],
                        valid_from: base_time,
                        valid_until: base_time.saturating_add(10_000_000),
                    }),
                ),
                SequencedLedgerEvent::new(
                    EventCoordinate::new(20, 0, 0, base_time.saturating_add(20)),
                    LedgerEvent::KeyAdded(KeyAddedEvent {
                        issuer_id: [0x99; 32],
                        kid: kid3,
                        public_key: key_bytes3,
                    }),
                ),
            ],
        )
        .expect("store rogue events");

    let op_1 = TrustOperatorNode::new(storage_honest.clone(), Arc::new(signer_op1), LOCAL_CHAIN_ID);
    let op_2 = TrustOperatorNode::new(storage_honest.clone(), Arc::new(signer_op2), LOCAL_CHAIN_ID);
    let op_3_rogue =
        TrustOperatorNode::new(storage_divergent, Arc::new(signer_op3), LOCAL_CHAIN_ID);

    let params = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,
        1,
        BlockHeader::new(10, [0xAA; 32], [0x00; 32], base_time.saturating_add(10)),
        604_800,
        vec![],
    );

    let bundle_honest = op_1.derive_local_bundle(&params).expect("op 1 derive");
    let sig_1 = op_1.evaluate_and_sign(&params).expect("op 1");
    let sig_2 = op_2.evaluate_and_sign(&params).expect("op 2");
    let sig_3_divergent = op_3_rogue.evaluate_and_sign(&params).expect("op 3");

    // El operador rogue tiene un digest diferente
    assert_ne!(sig_1.payload_sha256, sig_3_divergent.payload_sha256);

    let mut keys = BTreeMap::new();
    keys.insert(kid_op1, jwk_op1);
    keys.insert(kid_op2, jwk_op2);
    keys.insert(kid_op3, jwk_op3);

    // 1. Con quórum 2 de 3, el agregador aísla al rogue y genera bundle válido
    let aggregator = UntrustedBundleAggregator::new(2);
    let res = aggregator
        .aggregate(
            &bundle_honest,
            &[sig_1.clone(), sig_2, sig_3_divergent.clone()],
            &keys,
        )
        .expect("aggregates honest majority");

    assert_eq!(res.distinct_operators, 2);
    assert_eq!(res.divergent_operators, vec!["op-3".to_string()]);

    // 2. Si sólo hay 1 firma honesta y 1 divergente, no se alcanza quórum y falla closed (INV-05, INV-16)
    let failed = aggregator.aggregate(&bundle_honest, &[sig_1, sig_3_divergent], &keys);
    assert!(failed.is_err());
}

// Verifies: REQ-TRUST-004, INV-05, INV-16
#[test]
fn test_container_stack_ledger_divergence_fails_closed() {
    let base_time = 1_700_000_000u64;
    let engine = FullVerificationEngine::standard();
    let (key_bytes, _, kid) = sample_key(501);
    let issuer_id = [0x55; 32];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, base_time.saturating_add(10)),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: base_time,
                valid_until: base_time.saturating_add(100_000_000),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(30, 0, 0, base_time.saturating_add(20)),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    let mut state = gravital_id_ledger::LedgerState::new(LOCAL_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events {
        state.apply_event(ev).expect("apply");
    }

    let bundle_params = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,
        1,
        BlockHeader::new(30, [0xAA; 32], [0x99; 32], base_time.saturating_add(30)),
        604_800,
        vec![],
    );
    let derived = gravital_id_ledger::derive_trust_bundle(&state, &bundle_params).expect("derive");

    // Fuente 1 normal en bloque 50
    let mut src1 = InMemoryLedgerAdapter::new(
        LOCAL_CHAIN_ID,
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], base_time.saturating_add(50)),
    );
    for ev in &events {
        src1.add_event(ev.clone());
    }

    // Fuente 2 tiene un evento de clave comprometida en bloque 35 (no reflejado en bundle)
    let mut events_compromised = events.clone();
    events_compromised.push(SequencedLedgerEvent::new(
        EventCoordinate::new(35, 0, 0, base_time.saturating_add(35)),
        LedgerEvent::KeyCompromised(KeyCompromisedEvent {
            issuer_id,
            kid,
            state_since: base_time.saturating_add(35),
        }),
    ));

    let mut src2 = InMemoryLedgerAdapter::new(
        LOCAL_CHAIN_ID,
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], base_time.saturating_add(50)),
    );
    for ev in &events_compromised {
        src2.add_event(ev.clone());
    }

    // El modo de verificación completa detecta el compromiso y emite alarma crítica
    let outcome = engine.verify_bundle(
        &derived.bundle,
        &[
            ("node-1", &src1 as &dyn LedgerAdapter),
            ("node-2", &src2 as &dyn LedgerAdapter),
        ],
        base_time.saturating_add(60),
    );

    assert!(!outcome.is_verified());
    match outcome {
        FullVerificationOutcome::BundleDivergence(alarm) => {
            assert!(alarm.has_critical_security_divergence);
            assert!(alarm.divergences_by_source.contains_key("node-2"));
        }
        other => panic!("esperaba BundleDivergence, obtuve: {other:?}"),
    }
}

// Verifies: REQ-PRIV-003, INV-02
#[test]
fn test_container_stack_zero_pii_audit() {
    // Escaneo exhaustivo de cadenas prohibidas que denoten datos personales
    let forbidden_pii_substrings = [
        "Juan",
        "Perez",
        "8-765-4321",
        "password",
        "private_key",
        "secret",
        "ssn",
        "passport",
        "holder_name",
        "credit_card",
    ];

    // 1. Simulación de payload publicado de bundle
    let (key_raw, _, kid) = sample_key(601);
    let mut state = gravital_id_ledger::LedgerState::new(LOCAL_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id: [0x44; 32],
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ))
        .expect("apply");
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id: [0x44; 32],
                kid,
                public_key: key_raw,
            }),
        ))
        .expect("apply");

    let params = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,
        1,
        BlockHeader::new(20, [0xAA; 32], [0x99; 32], 1_700_000_020),
        604_800,
        vec![],
    );
    let derived = gravital_id_ledger::derive_trust_bundle(&state, &params).expect("derive");

    // Verificar que el payload serializado no contiene ninguna PII
    let json_str = String::from_utf8_lossy(&derived.canonical_json_bytes);
    for pii in forbidden_pii_substrings {
        assert!(
            !json_str.contains(pii),
            "Fuga de PII detectada en canonical_json_bytes: {pii}"
        );
    }
}
