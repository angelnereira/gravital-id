#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración automatizadas de extremo a extremo para la rotación de claves
//! de emisor (F8.T06, REQ-KEY-006, ADR-0018, SPEC-PIP-KEYROT-001).
//!
//! Flujo verificado E2E:
//! 1. Registro de emisor y clave inicial K1 en el ledger (TrustRegistry on-chain).
//! 2. Ingesta por indexador (pip-indexer) y emisión del TrustBundle v1 cofirmado por
//!    operadores independientes con quórum k-de-n (pip-trust-service).
//! 3. Emisión de credencial C1 firmada con K1 en T1. Verificación offline en dispositivo -> Valid.
//! 4. Rotación en el ledger en T_rot (T_rot > T1): adición de clave K2 (active) y retiro de K1
//!    (retired con state_since = T_rot).
//! 5. Ingesta por el indexador y regeneración determinista de TrustBundle v2 por operadores.
//! 6. Verificación multi-fuente (FullVerificationEngine) contrastada contra >= 2 fuentes independientes.
//! 7. Sincronización del bundle v2 en el verificador offline con anti-rollback monotónico.
//! 8. REQ-KEY-006: Verificación de C1 emitida antes del retiro (iat < T_rot) -> sigue siendo Valid.
//! 9. Emisión de credencial C2 con nueva clave activa K2 -> Valid.
//! 10. Caso negativo (Fail-Closed, INV-05): Credencial C_bad emitida con clave K1 después del retiro
//!     (iat >= T_rot) -> Invalid con evidencia IssuerKeyRetired.
//! 11. Caso negativo: Detección de divergencia inter-ledger o manipulación de estado de clave.
//! 12. Auditoría forense cero PII en transacciones, eventos y bundles (INV-02).
//!
//! Trazabilidad:
//! - **REQ-KEY-006:** La rotación de una clave de emisor NO DEBE invalidar credenciales firmadas antes de su retiro.
//! - **REQ-KEY-005:** Estados de clave active, retired, suspended, compromised.
//! - **REQ-TRUST-001:** Trust bundle cofirmado por umbral k-de-n con versión monotónica.
//! - **REQ-TRUST-004:** Modo de verificación completa contrastado con >= 2 fuentes de ledger independientes.
//! - **REQ-TRUST-005:** Raíz de confianza fijada en configuración.
//! - **REQ-TRUST-008:** Derivación determinista idéntica byte a byte entre operadores.
//! - **REQ-LEDG-001 / INV-02:** Cero datos personales o identificadores en transacciones, eventos o logs.
//! - **REQ-LEDG-002:** Adaptador de ledger EVM / sans-I/O.
//! - **REQ-VER-001 / INV-01:** Verificación 100% offline y sans-I/O.
//! - **REQ-VER-002 / INV-04:** Cuatro estados normativos con evidencia explícita.
//! - **REQ-VER-003 / INV-05:** Fail-closed determinista ante datos inválidos o ambiguos.
//! - **REQ-VER-004 / INV-06:** Claves de emisor obtenidas solo del trust bundle (nunca de cabeceras).
//! - **REQ-VER-011:** VerifierStateStore con integridad y detección de replay.

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
    FullVerificationOutcome, InMemoryLedgerAdapter, IssuerRegisteredEvent, KeyAddedEvent,
    KeyRetiredEvent, LedgerAdapter, LedgerEvent, SequencedLedgerEvent, TrustRootUpdatedEvent,
};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::root::TrustRoot;
use gravital_id_trust::{TrustBundle, TrustBundleVerifier};
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

// Verifies: REQ-KEY-006, REQ-KEY-005, REQ-TRUST-001, REQ-TRUST-004, REQ-TRUST-008,
//           REQ-LEDG-001, REQ-LEDG-002, REQ-VER-001..004, INV-01, INV-02, INV-04,
//           INV-05, INV-06, INV-11, INV-16
#[test]
fn test_e2e_issuer_key_rotation_lifecycle_and_historical_validity() {
    let base_time = 1_700_000_000u64;
    let clock = Arc::new(TestSyncClock::new(base_time));

    let issuer_id = [0x50; 32];
    let issuer_uri = "https://issuer.te.gob.pa";
    let status_list_uri = "https://status.te.gob.pa/lists/2026-10";
    let vct = "urn:gravital-id:vct:pip-personal-v1";
    let audience = "https://seguridad.gob.pa/portal-verificador";
    let credential_index = 10u32;

    // Generamos almacenes de claves de software
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x1111_1111));
    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x3333_3333));

    // Clave 1 del Emisor (K1)
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

    // Clave 2 del Emisor (K2 - para rotación posterior)
    let k2_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("generate k2");
    let k2_jwk = issuer_store.public_key(&k2_handle).expect("k2 jwk");
    let mut k2_pub_raw = vec![0x04];
    k2_pub_raw.extend_from_slice(k2_jwk.x());
    k2_pub_raw.extend_from_slice(k2_jwk.y());
    let mut k2_kid_bytes = [0u8; 32];
    k2_kid_bytes.copy_from_slice(k2_jwk.thumbprint_sha256().as_slice());
    let k2_kid_hex = hex_string(&k2_kid_bytes);

    // Clave del Titular (Holder)
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    // Operadores independientes del Trust Service (3 operadores, umbral k=2)
    let (signer_op1, jwk_op1, kid_op1) = sample_bundle_signer("op-te-pa", 201);
    let (signer_op2, jwk_op2, kid_op2) = sample_bundle_signer("op-consortium-1", 202);
    let (signer_op3, jwk_op3, kid_op3) = sample_bundle_signer("op-consortium-2", 203);

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

    // =========================================================================
    // PASO 1: ESTADO INICIAL EN EL LEDGER (Bloque 10, T0+10): Emisor con Clave K1 activa
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

    // =========================================================================
    // PASO 2: INDEXADOR Y PUBLICACIÓN DE TRUST BUNDLE V1
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
        Arc::new(ledger_src1.clone()),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config.clone(),
        shutdown_coord.clone(),
        metrics_holder.clone(),
    );

    let stepped = indexer_engine.step().expect("step block 10");
    assert_eq!(stepped, Some(10));

    // Derivación determinista por operadores independientes
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

    let derivation_header_10 = BlockHeader::new(10, [0x10; 32], [0x09; 32], t_initial);
    let params_v1 = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1, // epoch 1
        1, // version 1
        derivation_header_10,
        604_800,
        vec![],
    );

    let derived_v1 = op_node_1
        .derive_local_bundle(&params_v1)
        .expect("op 1 derive v1");
    let sig_1_v1 = op_node_1
        .evaluate_and_sign(&params_v1)
        .expect("op 1 signs v1");
    let sig_2_v1 = op_node_2
        .evaluate_and_sign(&params_v1)
        .expect("op 2 signs v1");
    let sig_3_v1 = op_node_3
        .evaluate_and_sign(&params_v1)
        .expect("op 3 signs v1");

    // Todos los operadores independientes obtienen el mismo digest SHA-256 (REQ-TRUST-008)
    assert_eq!(sig_1_v1.payload_sha256, sig_2_v1.payload_sha256);
    assert_eq!(sig_2_v1.payload_sha256, sig_3_v1.payload_sha256);

    let mut authorized_keys = BTreeMap::new();
    authorized_keys.insert(kid_op1.clone(), jwk_op1);
    authorized_keys.insert(kid_op2.clone(), jwk_op2);
    authorized_keys.insert(kid_op3.clone(), jwk_op3);

    let aggregator = UntrustedBundleAggregator::new(2);
    let aggregated_v1 = aggregator
        .aggregate(
            &derived_v1,
            &[sig_1_v1, sig_2_v1, sig_3_v1],
            &authorized_keys,
        )
        .expect("aggregation v1");

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

    // Verificador offline descarga e inicializa Bundle v1
    let (bundle_v1, multi_sig_v1) =
        TrustBundle::parse(&aggregated_v1.jws_json).expect("parse bundle v1");
    TrustBundleVerifier::verify(
        &bundle_v1,
        &multi_sig_v1,
        &trust_root,
        None,
        UnixTime::from_seconds(t_initial),
    )
    .expect("bundle v1 verified against root");

    // En Bundle v1, K1 es activa
    let iss_entry_v1 = bundle_v1.issuer(issuer_uri).expect("issuer in bundle v1");
    let k1_in_b1 = iss_entry_v1.find_key(&k1_kid_hex).expect("k1 in b1");
    assert!(k1_in_b1.is_active());
    assert!(!k1_in_b1.is_retired());

    // =========================================================================
    // PASO 3: EMISIÓN DE CREDENCIAL C1 CON CLAVE K1 EN T1 (T1 = T0 + 100)
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

    let pres_c1_t1 = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t1_issuance,
        t1_issuance,
        "nonce-c1-t1",
    );

    let policy = VerificationPolicy::default();
    let mut verifier_store = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));
    let snap_v1 = build_snapshot(
        status_list_uri,
        issuer_uri,
        credential_index,
        0,
        t1_issuance,
        t1_issuance,
    );
    let req_t1 = VerificationRequest::new(
        "nonce-c1-t1",
        audience,
        UnixTime::from_seconds(t1_issuance.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );

    // Verificación de C1 con Bundle v1 en T1 -> DEBE ser Valid
    let res_c1_v1 = VerifierPipeline::verify(
        &pres_c1_t1,
        Some(&req_t1),
        &bundle_v1,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t1_issuance,
        None,
    );
    assert_eq!(res_c1_v1.status(), VerificationStatus::Valid);
    assert_eq!(res_c1_v1.issuer_id(), Some(issuer_uri));
    assert_eq!(res_c1_v1.kid_used(), Some(k1_kid_hex.as_str()));

    // =========================================================================
    // PASO 4: ROTACIÓN ON-CHAIN EN EL LEDGER EN BLOQUE 20 (T_rot = T0 + 500)
    // =========================================================================
    // El emisor registra la nueva clave K2 y retira ordenadamente K1 (REQ-KEY-006, CONTRACTS.md §3)
    let t_rot = base_time.saturating_add(500);
    clock.set(t_rot);

    let events_b20 = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, t_rot),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k2_kid_bytes,
                public_key: k2_pub_raw.clone(),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 1, 0, t_rot),
            LedgerEvent::KeyRetired(KeyRetiredEvent {
                issuer_id,
                kid: k1_kid_bytes,
                state_since: t_rot,
            }),
        ),
    ];

    let head_20 = BlockHeader::new(20, [0x20; 32], [0x10; 32], t_rot);
    ledger_src1.set_head(head_20.clone());
    ledger_src2.set_head(head_20.clone());
    for ev in &events_b20 {
        ledger_src1.add_event(ev.clone());
        ledger_src2.add_event(ev.clone());
    }

    // =========================================================================
    // PASO 5: INGESTA POR INDEXADOR Y GENERACIÓN DETERMINISTA DE BUNDLE V2
    // =========================================================================
    let indexer_engine_v2 = IndexerEngine::new(
        Arc::new(ledger_src1.clone()),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config,
        shutdown_coord,
        metrics_holder,
    );

    let stepped_v2 = indexer_engine_v2.step().expect("step block 20");
    assert_eq!(stepped_v2, Some(20));

    // Validamos estado proyectado en el indexador
    let state_v2 = indexer_storage
        .build_ledger_state(LOCAL_CHAIN_ID)
        .expect("build state v2");
    let issuer_state_v2 = state_v2
        .issuers()
        .get(&issuer_id)
        .expect("issuer state in indexer");
    assert_eq!(issuer_state_v2.keys.len(), 2);

    let key_k1_state = state_v2
        .effective_key_state(&issuer_id, &k1_kid_bytes, t_rot)
        .expect("k1 effective state");
    assert_eq!(key_k1_state, gravital_id_trust::KeyState::Retired);

    let key_k2_state = state_v2
        .effective_key_state(&issuer_id, &k2_kid_bytes, t_rot)
        .expect("k2 effective state");
    assert_eq!(key_k2_state, gravital_id_trust::KeyState::Active);

    // Derivación de Bundle v2 por los operadores independientes
    let params_v2 = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1, // epoch 1
        2, // version 2 (monotónico incremental)
        head_20,
        604_800,
        vec![],
    );

    let derived_v2 = op_node_1
        .derive_local_bundle(&params_v2)
        .expect("op 1 derive v2");
    let sig_1_v2 = op_node_1
        .evaluate_and_sign(&params_v2)
        .expect("op 1 signs v2");
    let sig_2_v2 = op_node_2
        .evaluate_and_sign(&params_v2)
        .expect("op 2 signs v2");
    let sig_3_v2 = op_node_3
        .evaluate_and_sign(&params_v2)
        .expect("op 3 signs v2");

    assert_eq!(sig_1_v2.payload_sha256, sig_2_v2.payload_sha256);
    assert_eq!(sig_2_v2.payload_sha256, sig_3_v2.payload_sha256);

    let aggregated_v2 = aggregator
        .aggregate(
            &derived_v2,
            &[sig_1_v2, sig_2_v2, sig_3_v2],
            &authorized_keys,
        )
        .expect("aggregation v2");

    publisher
        .publish_bundle(
            1,
            2,
            &aggregated_v2.jws_json,
            &aggregated_v2.canonical_digest,
            t_rot,
        )
        .expect("publish v2");

    // =========================================================================
    // PASO 6: MODO DE VERIFICACIÓN COMPLETA MULTI-FUENTE (REQ-TRUST-004, INV-16)
    // =========================================================================
    let (bundle_v2, multi_sig_v2) =
        TrustBundle::parse(&aggregated_v2.jws_json).expect("parse bundle v2");

    let full_verifier = FullVerificationEngine::standard();
    let full_outcome = full_verifier.verify_bundle(
        &bundle_v2,
        &[
            ("rpc-primary-node", &ledger_src1 as &dyn LedgerAdapter),
            ("rpc-secondary-node", &ledger_src2 as &dyn LedgerAdapter),
        ],
        t_rot,
    );
    assert!(
        full_outcome.is_verified(),
        "verificación completa multi-fuente debe confirmar bundle v2"
    );

    // =========================================================================
    // PASO 7: VERIFICADOR OFFLINE ACTUALIZA A TRUST BUNDLE V2
    // =========================================================================
    // Se valida contra la raíz de confianza y contra el bundle v1 anterior (anti-rollback)
    let accepted_v1 = gravital_id_trust::AcceptedBundleState {
        bundle_epoch: bundle_v1.bundle_epoch(),
        bundle_version: bundle_v1.bundle_version(),
    };
    TrustBundleVerifier::verify(
        &bundle_v2,
        &multi_sig_v2,
        &trust_root,
        Some(accepted_v1),
        UnixTime::from_seconds(t_rot),
    )
    .expect("bundle v2 verified against root and bundle v1 anti-rollback");

    let iss_entry_v2 = bundle_v2.issuer(issuer_uri).expect("issuer in bundle v2");
    let k1_in_b2 = iss_entry_v2.find_key(&k1_kid_hex).expect("k1 in b2");
    let k2_in_b2 = iss_entry_v2.find_key(&k2_kid_hex).expect("k2 in b2");

    assert!(
        k1_in_b2.is_retired(),
        "K1 debe estar en estado retired en bundle v2"
    );
    assert_eq!(k1_in_b2.state_since.as_seconds(), t_rot);
    assert!(
        k2_in_b2.is_active(),
        "K2 debe estar en estado active en bundle v2"
    );
    assert_eq!(k2_in_b2.state_since.as_seconds(), t_rot);

    // =========================================================================
    // PASO 8: DEMOSTRACIÓN NORMATIVA REQ-KEY-006:
    // Credencial C1 emitida antes del retiro (iat = T1 < T_rot) SIGUE SIENDO VÁLIDA
    // =========================================================================
    let t_eval = UnixTime::from_seconds(t_rot.saturating_add(300));
    let req_c1_after_rot = VerificationRequest::new(
        "nonce-c1-eval-post-rot",
        audience,
        UnixTime::from_seconds(t_eval.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_c1_eval = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t1_issuance,
        t_eval,
        "nonce-c1-eval-post-rot",
    );

    let res_c1_after_rot = VerifierPipeline::verify(
        &pres_c1_eval,
        Some(&req_c1_after_rot),
        &bundle_v2, // Verificado con el bundle rotado v2
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t_eval,
        None,
    );

    // REQ-KEY-006: DEBE ser Valid
    assert_eq!(
        res_c1_after_rot.status(),
        VerificationStatus::Valid,
        "REQ-KEY-006 violado: la credencial C1 emitida antes del retiro debe ser Valid tras la rotación"
    );

    // Verificamos la evidencia por paso en el resultado
    let checks_c1 = res_c1_after_rot.checks();
    let key_state_check = checks_c1
        .iter()
        .find(|c| c.kind == CheckKind::KeyState)
        .expect("check key state");
    assert_eq!(key_state_check.status, CheckStatus::Passed);
    assert!(key_state_check.message.contains("retired"));

    let validity_check = checks_c1
        .iter()
        .find(|c| c.kind == CheckKind::Validity)
        .expect("check validity");
    assert_eq!(validity_check.status, CheckStatus::Passed);

    // =========================================================================
    // PASO 9: EMISIÓN Y VERIFICACIÓN DE NUEVA CREDENCIAL C2 CON LA NUEVA CLAVE K2
    // =========================================================================
    let t2_issuance = UnixTime::from_seconds(t_rot.saturating_add(100));
    let req_c2 = VerificationRequest::new(
        "nonce-c2-fresh",
        audience,
        UnixTime::from_seconds(t_eval.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_c2 = make_presentation(
        &k2_kid_hex,
        &k2_handle,
        t2_issuance,
        t_eval,
        "nonce-c2-fresh",
    );

    let res_c2 = VerifierPipeline::verify(
        &pres_c2,
        Some(&req_c2),
        &bundle_v2,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t_eval,
        None,
    );

    assert_eq!(
        res_c2.status(),
        VerificationStatus::Valid,
        "La credencial C2 firmada con la nueva clave activa K2 debe ser Valid"
    );
    assert_eq!(res_c2.kid_used(), Some(k2_kid_hex.as_str()));

    // =========================================================================
    // PASO 10: CASO NEGATIVO FAIL-CLOSED (INV-05, REQ-KEY-006):
    // Credencial firmada con la clave retirada K1 DESPUÉS del retiro (iat >= T_rot) DEBE ser Invalid
    // =========================================================================
    let t_spurious_issuance = UnixTime::from_seconds(t_rot.saturating_add(50));
    let req_bad = VerificationRequest::new(
        "nonce-c-spurious",
        audience,
        UnixTime::from_seconds(t_eval.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_bad = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t_spurious_issuance,
        t_eval,
        "nonce-c-spurious",
    );

    let res_bad = VerifierPipeline::verify(
        &pres_bad,
        Some(&req_bad),
        &bundle_v2,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t_eval,
        None,
    );

    assert_eq!(
        res_bad.status(),
        VerificationStatus::Invalid,
        "Fail-closed violado: una credencial firmada con clave retirada después de su retiro debe ser Invalid"
    );

    let checks_bad = res_bad.checks();
    let validity_bad = checks_bad
        .iter()
        .find(|c| c.kind == CheckKind::Validity)
        .expect("check validity bad");
    assert_eq!(validity_bad.status, CheckStatus::Failed);
    assert_eq!(validity_bad.error_code, Some(ErrorCode::IssuerKeyRetired));

    // =========================================================================
    // PASO 11: CASO NEGATIVO BORDE (iat == T_rot) CON CLAVE RETIRADA -> Invalid
    // =========================================================================
    let t_boundary = UnixTime::from_seconds(t_rot);
    let req_boundary = VerificationRequest::new(
        "nonce-boundary",
        audience,
        UnixTime::from_seconds(t_eval.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_boundary = make_presentation(
        &k1_kid_hex,
        &k1_handle,
        t_boundary,
        t_eval,
        "nonce-boundary",
    );

    let res_boundary = VerifierPipeline::verify(
        &pres_boundary,
        Some(&req_boundary),
        &bundle_v2,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        t_eval,
        None,
    );

    assert_eq!(
        res_boundary.status(),
        VerificationStatus::Invalid,
        "Límite iat == state_since debe ser rechazado como Invalid con IssuerKeyRetired"
    );
    let validity_boundary = res_boundary
        .checks()
        .iter()
        .find(|c| c.kind == CheckKind::Validity)
        .expect("boundary validity");
    assert_eq!(validity_boundary.status, CheckStatus::Failed);
    assert_eq!(
        validity_boundary.error_code,
        Some(ErrorCode::IssuerKeyRetired)
    );
}

// Verifies: REQ-TRUST-004, INV-05, INV-16
#[test]
fn test_tampered_key_state_divergence_fails_closed() {
    let base_time = 1_700_000_000u64;
    let issuer_id = [0x50; 32];
    let issuer_uri = "https://issuer.te.gob.pa";

    let (signer_op1, jwk_op1, kid_op1) = sample_bundle_signer("op-1", 301);
    let (_signer_op2, jwk_op2, kid_op2) = sample_bundle_signer("op-2", 302);

    let (k1_pub_raw, _, k1_kid) = {
        let rng = SeededRng::new(401);
        let sk = generate_p256_secret_key(&rng).expect("sk");
        let jwk = public_key_from_secret_key(&sk).expect("jwk");
        let mut raw = vec![0x04];
        raw.extend_from_slice(jwk.x());
        raw.extend_from_slice(jwk.y());
        let mut kid = [0u8; 32];
        kid.copy_from_slice(jwk.thumbprint_sha256().as_slice());
        (raw, jwk, kid)
    };

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, base_time),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: issuer_uri.into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: base_time,
                valid_until: base_time.saturating_add(10_000_000),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 1, 0, base_time),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k1_kid,
                public_key: k1_pub_raw,
            }),
        ),
    ];

    let head_10 = BlockHeader::new(10, [0x10; 32], [0x00; 32], base_time);

    // Ledger 1: Fuente honesta
    let mut ledger1 = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_10.clone());
    for ev in &events {
        ledger1.add_event(ev.clone());
    }

    // Ledger 2: Fuente manipulada donde la clave K1 fue falsamente marcada como Compromised
    let mut ledger2 = InMemoryLedgerAdapter::new(LOCAL_CHAIN_ID, head_10.clone());
    for ev in &events {
        ledger2.add_event(ev.clone());
    }
    ledger2.add_event(SequencedLedgerEvent::new(
        EventCoordinate::new(10, 2, 0, base_time),
        LedgerEvent::KeyCompromised(gravital_id_ledger::KeyCompromisedEvent {
            issuer_id,
            kid: k1_kid,
            state_since: base_time,
        }),
    ));

    // Derivamos un bundle que reporta K1 como activa (según ledger1)
    let indexer_storage = Arc::new(InMemoryIndexerStorage::new());
    let indexer_config = IndexerConfig {
        chain_id: LOCAL_CHAIN_ID,
        ..Default::default()
    };
    let indexer_engine = IndexerEngine::new(
        Arc::new(ledger1.clone()),
        indexer_storage.clone(),
        Arc::new(TestSyncClock::new(base_time)),
        indexer_config,
        ShutdownCoordinator::new(),
        Arc::new(Mutex::new(None)),
    );
    indexer_engine.step().expect("indexer step");

    let op_node = TrustOperatorNode::new(indexer_storage, Arc::new(signer_op1), LOCAL_CHAIN_ID);
    let params = BundleDerivationParams::new(TEST_FRAMEWORK_ID, 1, 1, head_10, 604_800, vec![]);
    let derived = op_node.derive_local_bundle(&params).expect("derive");
    let sig1 = op_node.evaluate_and_sign(&params).expect("sign");

    let mut auth_keys = BTreeMap::new();
    auth_keys.insert(kid_op1, jwk_op1);
    auth_keys.insert(kid_op2, jwk_op2);

    let aggregator = UntrustedBundleAggregator::new(1);
    let aggregated = aggregator
        .aggregate(&derived, &[sig1], &auth_keys)
        .expect("aggregate");
    let (bundle, _) = TrustBundle::parse(&aggregated.jws_json).expect("parse bundle");

    // FullVerificationEngine debe detectar la discrepancia entre ledger1 y ledger2
    let full_verifier = FullVerificationEngine::standard();
    let outcome = full_verifier.verify_bundle(
        &bundle,
        &[
            ("rpc-honest", &ledger1 as &dyn LedgerAdapter),
            ("rpc-tampered", &ledger2 as &dyn LedgerAdapter),
        ],
        base_time,
    );

    // Fail-closed: Debe rechazar con BundleDivergence o CrossLedgerDivergence
    assert!(
        !outcome.is_verified(),
        "El verificador multi-fuente debe rechazar la discrepancia entre RPCs (fail-closed)"
    );

    match outcome {
        FullVerificationOutcome::BundleDivergence(alarm) => {
            assert!(
                alarm.has_critical_security_divergence,
                "Debe marcar discrepancia crítica de seguridad por alteración de estado de clave"
            );
        }
        FullVerificationOutcome::CrossLedgerDivergence(_) => {
            // También es válido si detecta la discrepancia cruzada entre fuentes
        }
        other => panic!("Esperaba BundleDivergence o CrossLedgerDivergence, obtuve {other:?}"),
    }
}

// Verifies: REQ-VER-004, INV-06
#[test]
fn test_untrusted_header_keys_rejected_in_rotation() {
    let base_time = UnixTime::from_seconds(1_700_000_000);
    let issuer_uri = "https://issuer.te.gob.pa";

    // Bundle minimal donde el emisor solo tiene una clave registrada
    let (_signer_op1, _, _kid_op1) = sample_bundle_signer("op-1", 501);
    let (_, jwk_reg, _) = {
        let rng = SeededRng::new(601);
        let sk = generate_p256_secret_key(&rng).expect("sk");
        let jwk = public_key_from_secret_key(&sk).expect("jwk");
        (sk, jwk, [0u8; 32])
    };

    let bundle_payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String("pip-global".to_string()),
        ),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(1)),
        ),
        ("bundle_epoch".to_string(), Value::Number(Number::PosInt(1))),
        ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
        (
            "registry_address".to_string(),
            Value::String("0x1234".to_string()),
        ),
        (
            "finalized_block_number".to_string(),
            Value::Number(Number::PosInt(10)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xabcd".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(base_time.as_seconds())),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(base_time.as_seconds() + 86400)),
        ),
        (
            "issuers".to_string(),
            Value::Array(vec![Value::Object(vec![
                (
                    "issuer_id".to_string(),
                    Value::String(issuer_uri.to_string()),
                ),
                (
                    "profiles".to_string(),
                    Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
                ),
                (
                    "vcts".to_string(),
                    Value::Array(vec![Value::String("urn:pip:v1".to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(base_time.as_seconds())),
                ),
                ("state".to_string(), Value::String("active".to_string())),
                (
                    "keys".to_string(),
                    Value::Array(vec![Value::Object(vec![
                        (
                            "kid".to_string(),
                            Value::String("registered-key-01".to_string()),
                        ),
                        (
                            "jwk".to_string(),
                            gravital_id_trust::json_value_of(&jwk_reg),
                        ),
                        ("state".to_string(), Value::String("active".to_string())),
                        (
                            "state_since".to_string(),
                            Value::Number(Number::PosInt(base_time.as_seconds())),
                        ),
                    ])]),
                ),
            ])]),
        ),
    ]);
    let bundle = TrustBundle::from_payload(&bundle_payload).expect("bundle");

    // Atacante crea una credencial intentando inyectar una clave en cabecera 'jwk'
    let mut fake_store = SoftwareKeyStore::new(SeededRng::new(999));
    let fake_handle = fake_store
        .generate_key::<IssuerSigning>()
        .expect("fake key");
    let fake_jwk = fake_store.public_key(&fake_handle).expect("fake jwk");

    let header = format!(
        r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"unregistered-key-99","jwk":{}}}"#,
        fake_jwk.to_canonical_json()
    );
    let payload = format!(
        r#"{{"iss":"{issuer_uri}","vct":"urn:pip:v1","iat":{},"exp":{}}}"#,
        base_time.as_seconds(),
        base_time.as_seconds() + 3600
    );
    let signing_input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes())
    );
    let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
    let sig = fake_store.sign(&fake_handle, &digest).expect("sign");
    let fake_sd_jwt = format!("{signing_input}.{}~", base64url::encode(&sig));

    let mut verifier_store = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));
    let policy = VerificationPolicy::default();

    // INV-06: VerifierPipeline ignora la cabecera 'jwk' y busca 'unregistered-key-99' en el TrustBundle.
    // Al no estar registrada en el bundle, el resultado es Unverifiable con UntrustedIssuer.
    let result = VerifierPipeline::verify(
        &fake_sd_jwt,
        None,
        &bundle,
        None,
        &mut verifier_store,
        &policy,
        base_time,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Unverifiable);
    let key_check = result
        .checks()
        .iter()
        .find(|c| c.kind == CheckKind::KeyState)
        .expect("key check");
    assert_eq!(key_check.status, CheckStatus::Indeterminate);
    assert_eq!(key_check.error_code, Some(ErrorCode::UntrustedIssuer));
}

// Verifies: REQ-LEDG-001, REQ-PRIV-003, INV-02
#[test]
fn test_key_rotation_zero_pii_audit() {
    let base_time = 1_700_000_000u64;
    let issuer_id = [0x50; 32];
    let k1_kid = [0x11; 32];
    let k2_kid = [0x22; 32];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, base_time),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://issuer.te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec!["urn:pip:v1".into()],
                valid_from: base_time,
                valid_until: base_time.saturating_add(10_000_000),
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 1, 0, base_time),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k1_kid,
                public_key: vec![0x04; 65],
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, base_time + 500),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: k2_kid,
                public_key: vec![0x04; 65],
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 1, 0, base_time + 500),
            LedgerEvent::KeyRetired(KeyRetiredEvent {
                issuer_id,
                kid: k1_kid,
                state_since: base_time + 500,
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
                "INV-02 violado: patrón de dato personal '{pattern}' encontrado en evento: {debug_str}"
            );
        }
    }
}
