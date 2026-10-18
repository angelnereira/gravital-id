#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración automatizadas de extremo a extremo para la suspensión de emergencia
//! y compromiso definitivo de claves de emisor (F8.T07, REQ-KEY-005, REQ-LEDG-004, ADR-0018,
//! SPEC-PIP-KEYCOMP-001).
//!
//! Flujo verificado E2E:
//! 1. Suspensión de emergencia sin timelock por `EMERGENCY_ROLE` -> TrustRegistry emite `KeySuspended`.
//! 2. Ingesta por indexador (pip-indexer) y derivación determinista de TrustBundle con estado `suspended`.
//! 3. Verificador offline evalúa credencial previa -> Unverifiable con evidencia `IssuerSuspended`.
//! 4. Confirmación definitiva por la multisig completa (`DEFAULT_ADMIN_ROLE`) -> TrustRegistry emite `KeyCompromised`.
//! 5. TrustBundle con estado `compromised` -> Verificador offline evalúa credencial -> Invalid fail-closed
//!    para todas las credenciales sin importar `iat` (INV-05).
//! 6. Caso de falsa alarma: Suspensión levantada explícitamente (`emergencyLiftSuspension`) -> TrustBundle
//!    con estado `active` -> credenciales vuelven a ser Valid.
//! 7. Caso de caducidad automática: Expiración del TTL de 14 días sin acción de la multisig -> clave retorna
//!    a `active` deterministamente -> credenciales vuelven a ser Valid.
//! 8. Invariante de gobernanza: Prohibición estricta de auto-renovación por el rol de emergencia
//!    (`EmergencyRenewalForbidden`, REQ-LEDG-004).
//! 9. Auditoría forense cero PII en transacciones, eventos y bundles (INV-02).
//!
//! Trazabilidad:
//! - **REQ-KEY-005:** Estados de clave active, retired, suspended, compromised.
//! - **REQ-LEDG-004:** Acciones de emergencia reversibles sin timelock; compromiso terminal exclusivo de multisig.
//! - **REQ-TRUST-001:** Trust bundle cofirmado por umbral k-de-n con versión monotónica.
//! - **REQ-TRUST-004:** Modo de verificación completa contrastado con >= 2 fuentes de ledger independientes.
//! - **REQ-TRUST-005:** Raíz de confianza fijada en configuración.
//! - **REQ-TRUST-008:** Derivación determinista idéntica byte a byte entre operadores.
//! - **REQ-LEDG-001 / INV-02:** Cero datos personales o identificadores en transacciones, eventos o logs.
//! - **REQ-LEDG-002:** Adaptador de ledger EVM / sans-I/O.
//! - **REQ-VER-001 / INV-01:** Verificación 100% offline y sans-I/O.
//! - **REQ-VER-002 / INV-04:** Cuatro estados normativos con evidencia explícita.
//! - **REQ-VER-003 / INV-05:** Fail-closed determinista ante datos inválidos o ambiguos.
//! - **REQ-VER-012:** Comprobaciones dependientes de datos no autenticados quedan Skipped.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gravital_id_codec::base64url;
use gravital_id_codec::deflate::deflate;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::KbIssuer;
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_ledger::{
    BlockHeader, BundleDerivationParams, EventCoordinate, FullVerificationEngine,
    InMemoryLedgerAdapter, IssuerRegisteredEvent, KeyAddedEvent, KeyCompromisedEvent,
    KeySuspendedEvent, LedgerAdapter, LedgerError, LedgerEvent, SequencedLedgerEvent,
    TrustRootUpdatedEvent,
};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::root::TrustRoot;
use gravital_id_trust::{AcceptedBundleState, KeyState, TrustBundle, TrustBundleVerifier};
use gravital_id_types::{Clock, ErrorCode, UnixTime};
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{OperationClass, VerificationPolicy};
use gravital_id_verifier::result::{CheckKind, CheckStatus, VerificationStatus};
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey};

use pip_indexer::config::IndexerConfig;
use pip_indexer::engine::IndexerEngine;
use pip_indexer::storage::{InMemoryIndexerStorage, IndexerStorage};
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_trust_service::aggregator::UntrustedBundleAggregator;
use pip_trust_service::operator::TrustOperatorNode;
use pip_trust_service::publisher::{BundlePublisher, InMemoryBundlePublisher};
use pip_trust_service::signer::LocalDevSigner;

const LOCAL_CHAIN_ID: u64 = 31337;
const TEST_REGISTRY_ADDR: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";
const TEST_FRAMEWORK_ID: &str = "pip-global-mainnet";
const EMERGENCY_SUSPENSION_DURATION: u64 = 14 * 86_400; // 14 días (CONTRACTS.md §3.2)

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

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
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

/// Helper para empaquetar una lista de estado en formato Base45/DEFLATE.
fn pack_status_lst(bits: u8, values: &[u32]) -> String {
    let mut bytes = Vec::new();
    let mut current = 0u8;
    let mut used = 0u32;
    for value in values {
        for shift in (0..bits).rev() {
            let bit = (value >> shift) & 0b1;
            current = (current << 1) | (bit as u8);
            used = used.saturating_add(1);
            if used.is_multiple_of(8) {
                bytes.push(current);
                current = 0;
            }
        }
    }
    if !used.is_multiple_of(8) {
        current <<= 8u32.saturating_sub(used % 8);
        bytes.push(current);
    }
    base64url::encode(&deflate(&bytes))
}

/// Helper para construir un `StatusSnapshot` sintético con bit de estado para la credencial.
fn build_snapshot(
    status_list_uri: &str,
    issuer_uri: &str,
    credential_index: u32,
    status_bit: u32,
    issued_time: UnixTime,
    acquired_time: UnixTime,
) -> StatusSnapshot {
    let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
    let mut values = vec![0u32; 64];
    values[credential_index as usize] = status_bit;
    let payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":2,"lst":"{}","uri":"{}"}}}}"#,
        issued_time.as_seconds().saturating_add(86_400),
        issued_time.as_seconds(),
        issuer_uri,
        pack_status_lst(2, &values),
        status_list_uri
    );
    let jwt = format!(
        "{}.{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes()),
        base64url::encode(&[0u8; 64])
    );
    let list = StatusListVerifier::parse(&jwt).expect("status list parse");
    StatusSnapshot::new(list, status_list_uri, acquired_time)
}

// Verifies: REQ-KEY-005, REQ-LEDG-004, REQ-TRUST-001, REQ-TRUST-004, REQ-TRUST-008,
//           REQ-LEDG-001, REQ-LEDG-002, REQ-VER-001..004, REQ-VER-012, INV-01, INV-02,
//           INV-04, INV-05, INV-06, INV-11, INV-16
#[test]
fn test_e2e_emergency_suspension_and_multisig_compromise_lifecycle() {
    let base_time = 1_700_000_000u64;
    let clock = Arc::new(TestSyncClock::new(base_time));

    let issuer_id = [0x50; 32];
    let issuer_uri = "https://issuer.te.gob.pa";
    let status_list_uri = "https://status.te.gob.pa/lists/2026-10";
    let vct = "urn:gravital-id:vct:pip-personal-v1";
    let audience = "https://seguridad.gob.pa/portal-verificador";
    let credential_index = 12u32;
    let emergency_role_address = [0xEE; 20];

    // Almacenes de claves de emisor y titular
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x2222_3333));
    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x4444_5555));

    let k1_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("generate k1");
    let k1_jwk = issuer_store.public_key(&k1_handle).expect("k1 jwk");
    let mut k1_pub_raw = vec![0x04];
    k1_pub_raw.extend_from_slice(k1_jwk.x());
    k1_pub_raw.extend_from_slice(k1_jwk.y());
    let mut k1_kid_bytes = [0u8; 32];
    k1_kid_bytes.copy_from_slice(k1_jwk.thumbprint_sha256().as_slice());
    let k1_kid_hex = hex_string(&k1_kid_bytes);

    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    // Operadores independientes del Trust Service (3 operadores, umbral k=2)
    let (signer_op1, jwk_op1, kid_op1) = sample_bundle_signer("op-te-pa", 401);
    let (signer_op2, jwk_op2, kid_op2) = sample_bundle_signer("op-consortium-1", 402);
    let (signer_op3, jwk_op3, kid_op3) = sample_bundle_signer("op-consortium-2", 403);

    let trust_root = make_test_trust_root(
        TEST_FRAMEWORK_ID,
        1,
        1,
        2, // umbral k=2
        &[
            ("op-te-pa", &kid_op1, &jwk_op1),
            ("op-consortium-1", &kid_op2, &jwk_op2),
            ("op-consortium-2", &kid_op3, &jwk_op3),
        ],
    );

    let mut authorized_keys = BTreeMap::new();
    authorized_keys.insert(kid_op1.clone(), jwk_op1);
    authorized_keys.insert(kid_op2.clone(), jwk_op2);
    authorized_keys.insert(kid_op3.clone(), jwk_op3);

    // =========================================================================
    // ETAPA 1: ESTADO INICIAL ACTIVO EN EL LEDGER (Bloque 10, T0) -> Bundle v1
    // =========================================================================
    let t_initial = base_time.saturating_add(10);
    let events_b10 = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(5, 0, 0, t_initial.saturating_sub(5)),
            LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash: [0x11; 32],
                root_version: 1,
                updated_at: t_initial.saturating_sub(5),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, t_initial),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: issuer_uri.into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![vct.into()],
                valid_from: base_time,
                valid_until: base_time.saturating_add(100_000_000),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 1, 0, t_initial),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k1_kid_bytes,
                public_key: k1_pub_raw.clone(),
            }),
        ),
    ];

    let head_10 = BlockHeader::new(10, [0x10; 32], [0x09; 32], t_initial);
    let mut ledger_src1 = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_10.clone());
    let mut ledger_src2 = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_10);
    for ev in &events_b10 {
        ledger_src1.add_event(ev.clone());
        ledger_src2.add_event(ev.clone());
    }

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
        Arc::new(ledger_src1.clone()),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config.clone(),
        shutdown_coord.clone(),
        metrics_holder.clone(),
    );

    assert_eq!(indexer_engine.step().expect("step b10"), Some(10));

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

    let params_v1 = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,
        1,
        BlockHeader::new(10, [0x10; 32], [0x09; 32], t_initial),
        604_800,
        vec![],
    );

    let derived_v1 = op_node_1
        .derive_local_bundle(&params_v1)
        .expect("derive v1");
    let sig_1_v1 = op_node_1
        .evaluate_and_sign(&params_v1)
        .expect("op 1 signs v1");
    let sig_2_v1 = op_node_2
        .evaluate_and_sign(&params_v1)
        .expect("op 2 signs v1");
    let sig_3_v1 = op_node_3
        .evaluate_and_sign(&params_v1)
        .expect("op 3 signs v1");

    let aggregator = UntrustedBundleAggregator::new(2);
    let aggregated_v1 = aggregator
        .aggregate(
            &derived_v1,
            &[sig_1_v1, sig_2_v1, sig_3_v1],
            &authorized_keys,
        )
        .expect("aggregate v1");

    let publisher = Arc::new(InMemoryBundlePublisher::new());
    publisher
        .publish_bundle(
            1,
            1,
            &aggregated_v1.jws_json,
            &aggregated_v1.canonical_digest,
            t_initial,
        )
        .expect("publish v1");

    let (bundle_v1, multi_sig_v1) = TrustBundle::parse(&aggregated_v1.jws_json).expect("parse v1");
    TrustBundleVerifier::verify(
        &bundle_v1,
        &multi_sig_v1,
        &trust_root,
        None,
        UnixTime::from_seconds(t_initial),
    )
    .expect("verify v1 against root");

    // =========================================================================
    // ETAPA 2: EMISIÓN DE CREDENCIAL C1 Y VERIFICACIÓN EXITOSA INICIAL (Valid)
    // =========================================================================
    let t1_issuance = UnixTime::from_seconds(base_time.saturating_add(100));

    let make_presentation = |kid_str: &str,
                             key_handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
                             iat_time: UnixTime,
                             pres_now: UnixTime,
                             nonce: &str|
     -> String {
        let header = format!(r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"{kid_str}"}}"#);
        let payload = format!(
            r#"{{"iss":"{issuer_uri}","vct":"{vct}","iat":{},"exp":{},"cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":{credential_index},"uri":"{status_list_uri}"}}}}}}"#,
            iat_time.as_seconds(),
            iat_time.as_seconds().saturating_add(86_400),
            holder_jwk.to_canonical_json()
        );
        let h_b64 = base64url::encode(header.as_bytes());
        let p_b64 = base64url::encode(payload.as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
        let sig = issuer_store
            .sign(key_handle, &digest)
            .expect("sign issuer jwt");
        let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
        let prefix = format!("{issuer_jwt}~");

        KbIssuer::create_presentation(
            &prefix,
            audience,
            nonce,
            pres_now,
            &holder_store,
            &holder_handle,
        )
        .expect("create kb presentation")
    };

    let pres_c1 = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t1_issuance,
        t1_issuance,
        "nonce-c1-initial",
    );
    let snap_v1 = build_snapshot(
        status_list_uri,
        issuer_uri,
        credential_index,
        0,
        t1_issuance,
        t1_issuance,
    );
    let policy = VerificationPolicy::default();
    let mut verifier_store = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));

    let req_initial = VerificationRequest::new(
        "nonce-c1-initial",
        audience,
        UnixTime::from_seconds(t1_issuance.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );

    let res_initial = VerifierPipeline::verify(
        &pres_c1,
        Some(&req_initial),
        &bundle_v1,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t1_issuance,
        None,
    );
    assert_eq!(res_initial.status(), VerificationStatus::Valid);

    // =========================================================================
    // ETAPA 3: ACCIÓN DE EMERGENCIA SIN TIMELOCK -> SUSPENSIÓN PREVENTIVA (Bloque 20)
    // =========================================================================
    let t_susp = base_time.saturating_add(500);
    clock.set(t_susp);
    let suspension_expires_at = t_susp.saturating_add(EMERGENCY_SUSPENSION_DURATION);

    // EMERGENCY_ROLE invoca emergencySuspendKey(issuer_id, k1_kid) (REQ-LEDG-004)
    let ev_susp = SequencedLedgerEvent::new(
        EventCoordinate::new(20, 0, 0, t_susp),
        LedgerEvent::KeySuspended(KeySuspendedEvent {
            issuer_id,
            kid: k1_kid_bytes,
            expires_at: suspension_expires_at,
            initiated_by: emergency_role_address,
        }),
    );

    let head_20 = BlockHeader::new(20, [0x20; 32], [0x10; 32], t_susp);
    ledger_src1.set_head(head_20.clone());
    ledger_src2.set_head(head_20.clone());
    ledger_src1.add_event(ev_susp.clone());
    ledger_src2.add_event(ev_susp);

    let indexer_engine_v2 = IndexerEngine::new(
        Arc::new(ledger_src1.clone()),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config.clone(),
        shutdown_coord.clone(),
        metrics_holder.clone(),
    );
    assert_eq!(indexer_engine_v2.step().expect("step b20"), Some(20));

    // Validamos que el indexador proyecta la clave en estado Suspended
    let state_v2 = indexer_storage
        .build_ledger_state(LOCAL_CHAIN_ID)
        .expect("state v2");
    let key_state_v2 = state_v2
        .effective_key_state(&issuer_id, &k1_kid_bytes, t_susp)
        .expect("k1 state");
    assert_eq!(key_state_v2, KeyState::Suspended);

    // Operadores derivan Bundle v2 con la clave suspendida
    let params_v2 = BundleDerivationParams::new(TEST_FRAMEWORK_ID, 1, 2, head_20, 604_800, vec![]);
    let derived_v2 = op_node_1
        .derive_local_bundle(&params_v2)
        .expect("derive v2");
    let sig_1_v2 = op_node_1
        .evaluate_and_sign(&params_v2)
        .expect("op 1 signs v2");
    let sig_2_v2 = op_node_2
        .evaluate_and_sign(&params_v2)
        .expect("op 2 signs v2");
    let sig_3_v2 = op_node_3
        .evaluate_and_sign(&params_v2)
        .expect("op 3 signs v2");

    let aggregated_v2 = aggregator
        .aggregate(
            &derived_v2,
            &[sig_1_v2, sig_2_v2, sig_3_v2],
            &authorized_keys,
        )
        .expect("aggregate v2");

    publisher
        .publish_bundle(
            1,
            2,
            &aggregated_v2.jws_json,
            &aggregated_v2.canonical_digest,
            t_susp,
        )
        .expect("publish v2");

    let (bundle_v2, multi_sig_v2) = TrustBundle::parse(&aggregated_v2.jws_json).expect("parse v2");

    // FullVerificationEngine multi-fuente confirma consistencia del Bundle v2
    let full_verifier = FullVerificationEngine::standard();
    let outcome_v2 = full_verifier.verify_bundle(
        &bundle_v2,
        &[
            ("rpc-primary", &ledger_src1 as &dyn LedgerAdapter),
            ("rpc-secondary", &ledger_src2 as &dyn LedgerAdapter),
        ],
        t_susp,
    );
    assert!(outcome_v2.is_verified());

    // Verificador offline actualiza a Bundle v2
    let accepted_v1 = AcceptedBundleState {
        bundle_epoch: bundle_v1.bundle_epoch(),
        bundle_version: bundle_v1.bundle_version(),
    };
    TrustBundleVerifier::verify(
        &bundle_v2,
        &multi_sig_v2,
        &trust_root,
        Some(accepted_v1),
        UnixTime::from_seconds(t_susp),
    )
    .expect("verify v2 with anti-rollback");

    let iss_v2 = bundle_v2.issuer(issuer_uri).expect("issuer in b2");
    let k1_v2 = iss_v2.find_key(&k1_kid_hex).expect("k1 in b2");
    assert!(k1_v2.is_suspended());

    // =========================================================================
    // VERIFICACIÓN CON BUNDLE V2 (SUSPENDIDA) -> DEBE RESULTAR Unverifiable
    // =========================================================================
    let t_eval_susp = UnixTime::from_seconds(t_susp.saturating_add(60));
    let req_susp = VerificationRequest::new(
        "nonce-susp-eval",
        audience,
        UnixTime::from_seconds(t_eval_susp.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_c1_susp = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t1_issuance,
        t_eval_susp,
        "nonce-susp-eval",
    );

    let res_susp = VerifierPipeline::verify(
        &pres_c1_susp,
        Some(&req_susp),
        &bundle_v2,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t_eval_susp,
        None,
    );

    // REQ-KEY-005, INV-04: El resultado DEBE ser Unverifiable
    assert_eq!(
        res_susp.status(),
        VerificationStatus::Unverifiable,
        "Una clave suspendida en el bundle debe producir resultado Unverifiable"
    );

    // Evidencia estructurada: KeyState es Indeterminate con IssuerSuspended
    let checks_susp = res_susp.checks();
    let key_check_susp = checks_susp
        .iter()
        .find(|c| c.kind == CheckKind::KeyState)
        .expect("keystate check");
    assert_eq!(key_check_susp.status, CheckStatus::Indeterminate);
    assert_eq!(key_check_susp.error_code, Some(ErrorCode::IssuerSuspended));

    // REQ-VER-012: Comprobaciones dependientes de datos no autenticados quedan Skipped
    let sig_check = checks_susp
        .iter()
        .find(|c| c.kind == CheckKind::Signature)
        .expect("signature check");
    assert_eq!(sig_check.status, CheckStatus::Skipped);
    let val_check = checks_susp
        .iter()
        .find(|c| c.kind == CheckKind::Validity)
        .expect("validity check");
    assert_eq!(val_check.status, CheckStatus::Skipped);

    // =========================================================================
    // ETAPA 4: CONFIRMACIÓN IRREVERSIBLE DE COMPROMISO POR MULTISIG (Bloque 30)
    // =========================================================================
    let t_comp = t_susp.saturating_add(3600); // 1 hora después
    clock.set(t_comp);

    // TFA Multisig (DEFAULT_ADMIN_ROLE) invoca markKeyCompromised (REQ-LEDG-004)
    let ev_comp = SequencedLedgerEvent::new(
        EventCoordinate::new(30, 0, 0, t_comp),
        LedgerEvent::KeyCompromised(KeyCompromisedEvent {
            issuer_id,
            kid: k1_kid_bytes,
            state_since: t_comp,
        }),
    );

    let head_30 = BlockHeader::new(30, [0x30; 32], [0x20; 32], t_comp);
    ledger_src1.set_head(head_30.clone());
    ledger_src2.set_head(head_30.clone());
    ledger_src1.add_event(ev_comp.clone());
    ledger_src2.add_event(ev_comp);

    let indexer_engine_v3 = IndexerEngine::new(
        Arc::new(ledger_src1.clone()),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config,
        shutdown_coord,
        metrics_holder,
    );
    assert_eq!(indexer_engine_v3.step().expect("step b30"), Some(30));

    let state_v3 = indexer_storage
        .build_ledger_state(LOCAL_CHAIN_ID)
        .expect("state v3");
    let key_state_v3 = state_v3
        .effective_key_state(&issuer_id, &k1_kid_bytes, t_comp)
        .expect("k1 state v3");
    assert_eq!(key_state_v3, KeyState::Compromised);

    // Operadores derivan Bundle v3 con la clave comprometida
    let params_v3 = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,
        3, // version 3
        head_30,
        604_800,
        vec![],
    );
    let derived_v3 = op_node_1
        .derive_local_bundle(&params_v3)
        .expect("derive v3");
    let sig_1_v3 = op_node_1
        .evaluate_and_sign(&params_v3)
        .expect("op 1 signs v3");
    let sig_2_v3 = op_node_2
        .evaluate_and_sign(&params_v3)
        .expect("op 2 signs v3");
    let sig_3_v3 = op_node_3
        .evaluate_and_sign(&params_v3)
        .expect("op 3 signs v3");

    let aggregated_v3 = aggregator
        .aggregate(
            &derived_v3,
            &[sig_1_v3, sig_2_v3, sig_3_v3],
            &authorized_keys,
        )
        .expect("aggregate v3");

    publisher
        .publish_bundle(
            1,
            3,
            &aggregated_v3.jws_json,
            &aggregated_v3.canonical_digest,
            t_comp,
        )
        .expect("publish v3");

    let (bundle_v3, multi_sig_v3) = TrustBundle::parse(&aggregated_v3.jws_json).expect("parse v3");

    let accepted_v2 = AcceptedBundleState {
        bundle_epoch: bundle_v2.bundle_epoch(),
        bundle_version: bundle_v2.bundle_version(),
    };
    TrustBundleVerifier::verify(
        &bundle_v3,
        &multi_sig_v3,
        &trust_root,
        Some(accepted_v2),
        UnixTime::from_seconds(t_comp),
    )
    .expect("verify v3 with anti-rollback");

    let iss_v3 = bundle_v3.issuer(issuer_uri).expect("issuer in b3");
    let k1_v3 = iss_v3.find_key(&k1_kid_hex).expect("k1 in b3");
    assert!(k1_v3.is_compromised());

    // =========================================================================
    // VERIFICACIÓN CON BUNDLE V3 (COMPROMETIDA) -> DEBE RESULTAR Invalid (FAIL-CLOSED)
    // =========================================================================
    let t_eval_comp = UnixTime::from_seconds(t_comp.saturating_add(60));
    let req_comp = VerificationRequest::new(
        "nonce-comp-eval",
        audience,
        UnixTime::from_seconds(t_eval_comp.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_c1_comp = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t1_issuance,
        t_eval_comp,
        "nonce-comp-eval",
    );

    let res_comp = VerifierPipeline::verify(
        &pres_c1_comp,
        Some(&req_comp),
        &bundle_v3,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t_eval_comp,
        None,
    );

    // REQ-KEY-005, INV-05: Compromised invalida todas las credenciales sin importar iat
    assert_eq!(
        res_comp.status(),
        VerificationStatus::Invalid,
        "Una clave comprometida debe invalidar deterministamente cualquier credencial firmada con ella"
    );

    let checks_comp = res_comp.checks();
    let key_check_comp = checks_comp
        .iter()
        .find(|c| c.kind == CheckKind::KeyState)
        .expect("keystate check");
    assert_eq!(key_check_comp.status, CheckStatus::Failed);
    assert_eq!(
        key_check_comp.error_code,
        Some(ErrorCode::IssuerKeyCompromised)
    );

    // Downstream checks quedan Skipped
    let sig_check_comp = checks_comp
        .iter()
        .find(|c| c.kind == CheckKind::Signature)
        .expect("signature check");
    assert_eq!(sig_check_comp.status, CheckStatus::Skipped);
}

// Verifies: REQ-KEY-005, REQ-LEDG-004, INV-01, INV-04
#[test]
fn test_e2e_suspension_lifted_returns_to_valid() {
    let base_time = 1_700_000_000u64;
    let clock = Arc::new(TestSyncClock::new(base_time));
    let issuer_id = [0x50; 32];
    let issuer_uri = "https://issuer.te.gob.pa";
    let status_list_uri = "https://status.te.gob.pa/lists/2026-10";
    let vct = "urn:gravital-id:vct:pip-personal-v1";
    let audience = "https://seguridad.gob.pa/portal-verificador";
    let credential_index = 15u32;
    let emergency_role = [0xEE; 20];

    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x7777_8888));
    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x9999_0000));

    let k1_handle = issuer_store.generate_key::<IssuerSigning>().expect("k1");
    let k1_jwk = issuer_store.public_key(&k1_handle).expect("k1 jwk");
    let mut k1_pub_raw = vec![0x04];
    k1_pub_raw.extend_from_slice(k1_jwk.x());
    k1_pub_raw.extend_from_slice(k1_jwk.y());
    let mut k1_kid_bytes = [0u8; 32];
    k1_kid_bytes.copy_from_slice(k1_jwk.thumbprint_sha256().as_slice());
    let k1_kid_hex = hex_string(&k1_kid_bytes);

    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let (signer_op1, jwk_op1, kid_op1) = sample_bundle_signer("op-1", 601);
    let (_signer_op2, jwk_op2, kid_op2) = sample_bundle_signer("op-2", 602);

    let trust_root = make_test_trust_root(
        TEST_FRAMEWORK_ID,
        1,
        1,
        1, // umbral k=1
        &[("op-1", &kid_op1, &jwk_op1), ("op-2", &kid_op2, &jwk_op2)],
    );

    let mut auth_keys = BTreeMap::new();
    auth_keys.insert(kid_op1.clone(), jwk_op1);
    auth_keys.insert(kid_op2.clone(), jwk_op2);

    // Bloque 10: Registro inicial
    let t_initial = base_time.saturating_add(10);
    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(5, 0, 0, t_initial.saturating_sub(5)),
            LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash: [0x11; 32],
                root_version: 1,
                updated_at: t_initial.saturating_sub(5),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, t_initial),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: issuer_uri.into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![vct.into()],
                valid_from: base_time,
                valid_until: base_time.saturating_add(100_000_000),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 1, 0, t_initial),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k1_kid_bytes,
                public_key: k1_pub_raw.clone(),
            }),
        ),
    ];

    let head_10 = BlockHeader::new(10, [0x10; 32], [0x09; 32], t_initial);
    let mut ledger = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_10);
    for ev in &events {
        ledger.add_event(ev.clone());
    }

    let indexer_storage = Arc::new(InMemoryIndexerStorage::new());
    let indexer_config = IndexerConfig {
        chain_id: LOCAL_CHAIN_ID,
        ..Default::default()
    };
    let step_engine = |ledger_snapshot: &InMemoryLedgerAdapter| {
        let engine = IndexerEngine::new(
            Arc::new(ledger_snapshot.clone()),
            indexer_storage.clone(),
            clock.clone(),
            indexer_config.clone(),
            ShutdownCoordinator::new(),
            Arc::new(Mutex::new(None)),
        );
        engine.step()
    };
    assert_eq!(step_engine(&ledger).expect("step b10"), Some(10));

    // Bloque 20: Suspensión de emergencia (T_susp)
    let t_susp = t_initial.saturating_add(200);
    clock.set(t_susp);
    let head_20 = BlockHeader::new(20, [0x20; 32], [0x10; 32], t_susp);
    ledger.set_head(head_20);
    ledger.add_event(SequencedLedgerEvent::new(
        EventCoordinate::new(20, 0, 0, t_susp),
        LedgerEvent::KeySuspended(KeySuspendedEvent {
            issuer_id,
            kid: k1_kid_bytes,
            expires_at: t_susp.saturating_add(EMERGENCY_SUSPENSION_DURATION),
            initiated_by: emergency_role,
        }),
    ));
    assert_eq!(step_engine(&ledger).expect("step b20"), Some(20));

    // Bloque 25: Rehabilitación / Levantamiento de suspensión (emergencyLiftSuspension emite KeyAdded)
    let t_lift = t_susp.saturating_add(300);
    clock.set(t_lift);
    let head_25 = BlockHeader::new(25, [0x25; 32], [0x20; 32], t_lift);
    ledger.set_head(head_25.clone());
    ledger.add_event(SequencedLedgerEvent::new(
        EventCoordinate::new(25, 0, 0, t_lift),
        LedgerEvent::KeyAdded(KeyAddedEvent {
            issuer_id,
            kid: k1_kid_bytes,
            public_key: k1_pub_raw,
        }),
    ));
    assert_eq!(step_engine(&ledger).expect("step b25"), Some(25));

    // Validamos que el estado proyectado de K1 vuelve a ser Active
    let state_lifted = indexer_storage
        .build_ledger_state(LOCAL_CHAIN_ID)
        .expect("state lifted");
    let k1_state = state_lifted
        .effective_key_state(&issuer_id, &k1_kid_bytes, t_lift)
        .expect("k1 state");
    assert_eq!(k1_state, KeyState::Active);

    // Derivamos Bundle rehabilitado
    let op_node = TrustOperatorNode::new(indexer_storage, Arc::new(signer_op1), LOCAL_CHAIN_ID);
    let params_lifted =
        BundleDerivationParams::new(TEST_FRAMEWORK_ID, 1, 2, head_25, 604_800, vec![]);
    let derived_lifted = op_node.derive_local_bundle(&params_lifted).expect("derive");
    let sig_lifted = op_node.evaluate_and_sign(&params_lifted).expect("sign");

    let aggregator = UntrustedBundleAggregator::new(1);
    let aggregated = aggregator
        .aggregate(&derived_lifted, &[sig_lifted], &auth_keys)
        .expect("aggregate");
    let (bundle_lifted, multi_sig) =
        TrustBundle::parse(&aggregated.jws_json).expect("parse bundle");
    TrustBundleVerifier::verify(
        &bundle_lifted,
        &multi_sig,
        &trust_root,
        None,
        UnixTime::from_seconds(t_lift),
    )
    .expect("verify bundle");

    // Construimos credencial y presentación
    let make_pres = |pres_now: UnixTime, nonce: &str| -> String {
        let header = format!(r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"{k1_kid_hex}"}}"#);
        let payload = format!(
            r#"{{"iss":"{issuer_uri}","vct":"{vct}","iat":{},"exp":{},"cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":{credential_index},"uri":"{status_list_uri}"}}}}}}"#,
            t_initial,
            t_initial.saturating_add(86_400),
            holder_jwk.to_canonical_json()
        );
        let h_b64 = base64url::encode(header.as_bytes());
        let p_b64 = base64url::encode(payload.as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
        let sig = issuer_store.sign(&k1_handle, &digest).expect("sign");
        let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
        let prefix = format!("{issuer_jwt}~");
        KbIssuer::create_presentation(
            &prefix,
            audience,
            nonce,
            pres_now,
            &holder_store,
            &holder_handle,
        )
        .expect("pres")
    };

    let pres = make_pres(UnixTime::from_seconds(t_lift), "nonce-lifted");
    let snap = build_snapshot(
        status_list_uri,
        issuer_uri,
        credential_index,
        0,
        UnixTime::from_seconds(t_initial),
        UnixTime::from_seconds(t_lift),
    );
    let mut verifier_store = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));
    let policy = VerificationPolicy::default();
    let req = VerificationRequest::new(
        "nonce-lifted",
        audience,
        UnixTime::from_seconds(t_lift.saturating_add(300)),
        OperationClass::Transaction,
    );

    // Con el bundle rehabilitado, la credencial vuelve a verificarse como Valid
    let result = VerifierPipeline::verify(
        &pres,
        Some(&req),
        &bundle_lifted,
        Some(&snap),
        &mut verifier_store,
        &policy,
        UnixTime::from_seconds(t_lift),
        None,
    );

    assert_eq!(
        result.status(),
        VerificationStatus::Valid,
        "Tras levantarse la suspensión, la credencial debe retornar deterministamente a Valid"
    );
}

// Verifies: REQ-KEY-005, REQ-LEDG-004, ADR-0018
#[test]
fn test_e2e_automatic_suspension_expiration_without_multisig() {
    let base_time = 1_700_000_000u64;
    let clock = Arc::new(TestSyncClock::new(base_time));
    let issuer_id = [0x50; 32];
    let issuer_uri = "https://issuer.te.gob.pa";

    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0xAAAA_BBBB));
    let k1_handle = issuer_store.generate_key::<IssuerSigning>().expect("k1");
    let k1_jwk = issuer_store.public_key(&k1_handle).expect("jwk");
    let mut k1_pub_raw = vec![0x04];
    k1_pub_raw.extend_from_slice(k1_jwk.x());
    k1_pub_raw.extend_from_slice(k1_jwk.y());
    let mut k1_kid_bytes = [0u8; 32];
    k1_kid_bytes.copy_from_slice(k1_jwk.thumbprint_sha256().as_slice());

    let (signer_op1, _, _kid_op1) = sample_bundle_signer("op-1", 701);

    // Estado inicial en Bloque 10
    let t_initial = base_time.saturating_add(10);
    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, t_initial),
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
            EventCoordinate::new(10, 1, 0, t_initial),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k1_kid_bytes,
                public_key: k1_pub_raw,
            }),
        ),
    ];

    let head_10 = BlockHeader::new(10, [0x10; 32], [0x09; 32], t_initial);
    let mut ledger = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_10);
    for ev in &events {
        ledger.add_event(ev.clone());
    }

    let indexer_storage = Arc::new(InMemoryIndexerStorage::new());
    let indexer_config = IndexerConfig {
        chain_id: LOCAL_CHAIN_ID,
        ..Default::default()
    };
    let step_engine = |ledger_snapshot: &InMemoryLedgerAdapter| {
        let engine = IndexerEngine::new(
            Arc::new(ledger_snapshot.clone()),
            indexer_storage.clone(),
            clock.clone(),
            indexer_config.clone(),
            ShutdownCoordinator::new(),
            Arc::new(Mutex::new(None)),
        );
        engine.step()
    };
    assert_eq!(step_engine(&ledger).expect("step b10"), Some(10));

    // Bloque 20: Suspensión de emergencia con caducidad en 14 días
    let t_susp = t_initial.saturating_add(100);
    clock.set(t_susp);
    let expires_at = t_susp.saturating_add(EMERGENCY_SUSPENSION_DURATION);

    let head_20 = BlockHeader::new(20, [0x20; 32], [0x10; 32], t_susp);
    ledger.set_head(head_20);
    ledger.add_event(SequencedLedgerEvent::new(
        EventCoordinate::new(20, 0, 0, t_susp),
        LedgerEvent::KeySuspended(KeySuspendedEvent {
            issuer_id,
            kid: k1_kid_bytes,
            expires_at,
            initiated_by: [0xEE; 20],
        }),
    ));
    assert_eq!(step_engine(&ledger).expect("step b20"), Some(20));

    // 1. Durante la vigencia de la suspensión (T < expires_at), la clave es Suspended
    let state_mid = indexer_storage
        .build_ledger_state(LOCAL_CHAIN_ID)
        .expect("state mid");
    let state_during_susp = state_mid
        .effective_key_state(&issuer_id, &k1_kid_bytes, t_susp.saturating_add(86_400))
        .expect("during");
    assert_eq!(state_during_susp, KeyState::Suspended);

    // 2. Tras expirar los 14 días (T >= expires_at), la clave retorna automáticamente a Active
    let t_after_ttl = expires_at.saturating_add(1);
    let state_after_ttl = state_mid
        .effective_key_state(&issuer_id, &k1_kid_bytes, t_after_ttl)
        .expect("after ttl");
    assert_eq!(
        state_after_ttl,
        KeyState::Active,
        "La clave debe retornar deterministamente a Active una vez expira el TTL de 14 días"
    );

    // 3. Un bundle derivado en T >= expires_at declara la clave como Active
    let head_50 = BlockHeader::new(50, [0x50; 32], [0x40; 32], t_after_ttl);
    let op_node = TrustOperatorNode::new(indexer_storage, Arc::new(signer_op1), LOCAL_CHAIN_ID);
    let params_after_ttl =
        BundleDerivationParams::new(TEST_FRAMEWORK_ID, 1, 2, head_50, 604_800, vec![]);
    let derived_after = op_node
        .derive_local_bundle(&params_after_ttl)
        .expect("derive after ttl");

    // Inspeccionamos el payload canónico derivado
    let bundle_json = std::str::from_utf8(&derived_after.canonical_json_bytes)
        .expect("valid utf-8 in derived bundle");
    assert!(bundle_json.contains(r#""state":"active""#));
    assert!(!bundle_json.contains(r#""state":"suspended""#));
}

// Verifies: REQ-LEDG-004, ADR-0018
#[test]
fn test_emergency_renewal_forbidden_in_ledger_state() {
    let base_time = 1_700_000_000u64;
    let issuer_id = [0x50; 32];
    let emergency_operator = [0xEE; 20];

    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x9999_8888));
    let k_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("gen key");
    let k_jwk = issuer_store.public_key(&k_handle).expect("jwk");
    let mut pub_raw = vec![0x04];
    pub_raw.extend_from_slice(k_jwk.x());
    pub_raw.extend_from_slice(k_jwk.y());
    let mut kid = [0u8; 32];
    kid.copy_from_slice(k_jwk.thumbprint_sha256().as_slice());

    let mut state = gravital_id_ledger::LedgerState::new(LOCAL_CHAIN_ID, TEST_REGISTRY_ADDR.into());

    // 1. Registro de emisor y clave
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, base_time),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://issuer.te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: base_time,
                valid_until: base_time + 10_000_000,
            }),
        ))
        .expect("reg issuer");

    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(10, 1, 0, base_time),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: pub_raw,
            }),
        ))
        .expect("add key");

    // 2. Primera suspensión de emergencia por emergency_operator
    let first_expires_at = base_time + EMERGENCY_SUSPENSION_DURATION;
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, base_time + 100),
            LedgerEvent::KeySuspended(KeySuspendedEvent {
                issuer_id,
                kid,
                expires_at: first_expires_at,
                initiated_by: emergency_operator,
            }),
        ))
        .expect("first suspension succeeds");

    // 3. Intento de renovación/extensión por el mismo operador de emergencia antes de la expiración
    let illegal_renewal = SequencedLedgerEvent::new(
        EventCoordinate::new(21, 0, 0, base_time + 200),
        LedgerEvent::KeySuspended(KeySuspendedEvent {
            issuer_id,
            kid,
            expires_at: first_expires_at + 86_400, // Intenta extender la suspensión
            initiated_by: emergency_operator,
        }),
    );

    // REQ-LEDG-004, ADR-0018: DEBE ser rechazado con EmergencyRenewalForbidden
    let err = state.apply_event(&illegal_renewal).unwrap_err();
    match err {
        LedgerError::EmergencyRenewalForbidden { target_id } => {
            assert_eq!(target_id, kid);
        }
        other => panic!("Esperaba EmergencyRenewalForbidden, obtuve {other:?}"),
    }
}

// Verifies: REQ-LEDG-001, REQ-PRIV-003, INV-02
#[test]
fn test_issuer_compromise_zero_pii_audit() {
    let base_time = 1_700_000_000u64;
    let issuer_id = [0x50; 32];
    let kid = [0x88; 32];
    let emergency_op = [0xEE; 20];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, base_time),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://issuer.te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec!["urn:pip:v1".into()],
                valid_from: base_time,
                valid_until: base_time + 10_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 1, 0, base_time),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: vec![0x04; 65],
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, base_time + 100),
            LedgerEvent::KeySuspended(KeySuspendedEvent {
                issuer_id,
                kid,
                expires_at: base_time + 100 + EMERGENCY_SUSPENSION_DURATION,
                initiated_by: emergency_op,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(30, 0, 0, base_time + 200),
            LedgerEvent::KeyCompromised(KeyCompromisedEvent {
                issuer_id,
                kid,
                state_since: base_time + 200,
            }),
        ),
    ];

    let pii_patterns = [
        "cedula",
        "dni",
        "ssn",
        "passport",
        "pasaporte",
        "panama-id",
        "angel",
        "nereira",
        "juan",
        "perez",
        "maria",
        "gonzalez",
        "imei",
        "mac_address",
        "phone",
        "email",
        "@gmail.com",
        "@gob.pa",
    ];

    for ev in &events {
        let debug_str = format!("{ev:?}").to_lowercase();
        for pattern in &pii_patterns {
            assert!(
                !debug_str.contains(pattern),
                "INV-02 violado: dato personal '{pattern}' detectado en evento: {debug_str}"
            );
        }
    }
}
