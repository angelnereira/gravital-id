#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración automatizadas de caos e inyección de fallos (F7.T12).
//!
//! Trazabilidad:
//! - **REQ-REL-004:** La falta de datos y los fallos de red DEBEN expresarse como estados del resultado, nunca como pánicos.
//! - **REQ-SYNC-004:** Todo contenido recibido de relays DEBE verificarse por firma o hash antes de usarse.
//! - **REQ-SYNC-007:** El cliente DEBE soportar múltiples endpoints de relay con failover automático ante caídas.
//! - **REQ-TRUST-004:** El modo de verificación completa DEBE contrastar el bundle con >= 2 fuentes de ledger independientes.
//! - **REQ-STAT-008:** Mitigación anti-rollback fail-closed en versiones de IssuerStatusManifest.
//! - **REQ-PRIV-003 / INV-02:** Cero datos personales o secretos en logs, errores o diagnósticos de fallos.
//! - **INV-01:** Verificación sin red y núcleo sans-I/O.
//! - **INV-04:** Cuatro estados normativos (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
//! - **INV-05:** Fail-closed determinista ante cualquier ambigüedad, falta de datos o divergencia.
//! - **INV-10:** Cero pánicos en el núcleo y bibliotecas ante datos corruptos o caídas.
//! - **INV-11:** Inyección explícita de tiempo y aleatoriedad determinista.
//! - **INV-16:** Prohibición absoluta de relajar umbrales multi-fuente o k-de-n.

use gravital_id_codec::base64url;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::KbIssuer;
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_ledger::{
    BlockHeader, FullVerificationEngine, FullVerificationOutcome, InMemoryLedgerAdapter,
    LedgerAdapter, LedgerError, LedgerResult, SequencedLedgerEvent, StatusCommitmentRecord,
};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::manifest::StatusManifestVerifier;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_sync::{
    ContentVerifier, EncryptedOutboxQueue, HpkeEnvelope, InboundDeduplicationFilter, MailboxId,
    MockTransport, OperationId, OutboxStepResult, RelayPool, RetryPolicy, SyncEngine, SyncError,
    SyncOperation,
};
use gravital_id_testkit::{FixedClock, SeededRng};
use gravital_id_trust::bundle::TrustBundle;
use gravital_id_types::UnixTime;
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{OperationClass, VerificationPolicy};
use gravital_id_verifier::result::VerificationStatus;
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey};
use pip_cli::{pack_status_lst, run_demo_chaos};

#[derive(Debug, Clone)]
struct TestFailingLedgerAdapter {
    chain_id: u64,
}

impl LedgerAdapter for TestFailingLedgerAdapter {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
    fn finalized_head(&self) -> LedgerResult<BlockHeader> {
        Err(LedgerError::Adapter(
            "simulated RPC outage: connection refused (500)".into(),
        ))
    }
    fn fetch_events(&self, _from: u64, _to: u64) -> LedgerResult<Vec<SequencedLedgerEvent>> {
        Err(LedgerError::Adapter(
            "simulated RPC outage: failed fetching events".into(),
        ))
    }
    fn get_status_commitment(
        &self,
        _issuer: &[u8; 32],
    ) -> LedgerResult<Option<StatusCommitmentRecord>> {
        Err(LedgerError::Adapter(
            "simulated RPC outage: status commitment unavailable".into(),
        ))
    }
}

// Verifies: REQ-REL-004, REQ-SYNC-004, REQ-SYNC-007, REQ-TRUST-004, REQ-STAT-008, REQ-PRIV-003
#[test]
fn cli_demo_chaos_completes_all_scenarios_successfully() {
    assert!(run_demo_chaos().is_ok());
}

// Verifies: REQ-STAT-008, REQ-SYNC-002, INV-05
#[test]
fn test_chaos_malicious_relay_rollback_and_replay_rejection() {
    let now = UnixTime::from_seconds(1_770_000_000);

    // 1. Rollback de versión de manifiesto
    let manifest_payload_v1 = Value::Object(vec![
        (
            "issuer_id".to_string(),
            Value::String("https://issuer.te.gob.pa".to_string()),
        ),
        (
            "manifest_version".to_string(),
            Value::Number(Number::PosInt(1)),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(now.as_seconds())),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_add(86_400))),
        ),
        ("status_lists".to_string(), Value::Array(vec![])),
    ]);
    let manifest_v1 = StatusManifestVerifier::from_payload(&manifest_payload_v1)
        .expect("manifest v1 parse must succeed");

    // Intento de inyectar v1 cuando la última aceptada es v2
    let rollback_check = manifest_v1.check_monotonic_version(Some(2));
    assert!(
        rollback_check.is_err(),
        "Rollback de versión de manifiesto v1 <= v2 DEBE ser rechazado fail-closed"
    );

    // 2. Replay de sobre de sincronización
    let mut dedup = InboundDeduplicationFilter::new(50, 3600);
    let envelope_id = "op-replay-test-01";
    assert!(dedup.check_and_record(envelope_id, now));
    assert!(dedup.is_duplicate(envelope_id, now));

    // Reintento malicioso
    let duplicate_detected = !dedup.check_and_record(envelope_id, now);
    assert!(
        duplicate_detected,
        "Sobre de sincronización retransmitido DEBE ser descartado como duplicado"
    );
}

// Verifies: REQ-SYNC-007, REQ-REL-004, INV-10
#[test]
fn test_chaos_malicious_relay_withholding_and_failover() {
    let now = UnixTime::from_seconds(1_770_000_000);
    let pool = RelayPool::new(
        vec![
            "https://relay-1.example".to_string(),
            "https://relay-2.example".to_string(),
        ],
        60,
    )
    .expect("pool creation");

    let transport = MockTransport::new();
    transport.set_simulate_failures("https://relay-1.example", 1);

    let mut outbox = EncryptedOutboxQueue::new(10);
    let op_id = OperationId::new("op-chaos-failover").expect("valid op id");
    let mailbox = MailboxId::new("inbox-recipient").expect("valid mailbox");
    outbox
        .enqueue(SyncOperation::new(
            op_id.clone(),
            mailbox,
            vec![1, 2, 3],
            now,
            Some(3600),
        ))
        .expect("enqueue");

    let policy = RetryPolicy::new(5, 60, 3, 20);
    let mut engine = SyncEngine::new(
        pool,
        outbox,
        InboundDeduplicationFilter::new(10, 3600),
        policy,
    );
    let clock = FixedClock::new(now.as_seconds());

    // Paso 1: Falla contra relay-1
    let step1 = engine
        .step_outbox(&transport, &clock, 0x1111)
        .expect("step 1");
    match step1 {
        OutboxStepResult::RetryScheduled {
            relay_url,
            retry_count,
            ..
        } => {
            assert_eq!(relay_url, "https://relay-1.example");
            assert_eq!(retry_count, 1);
        }
        other => panic!("Esperaba RetryScheduled en fallo de relay primario, obtuve {other:?}"),
    }

    // Paso 2: Failover exitoso hacia relay-2
    let clock2 = FixedClock::new(now.as_seconds().saturating_add(20));
    let step2 = engine
        .step_outbox(&transport, &clock2, 0x1111)
        .expect("step 2");
    match step2 {
        OutboxStepResult::Delivered {
            relay_url,
            operation_id,
        } => {
            assert_eq!(relay_url, "https://relay-2.example");
            assert_eq!(operation_id, op_id);
        }
        other => panic!("Esperaba Delivered hacia relay-2 tras failover, obtuve {other:?}"),
    }
}

// Verifies: REQ-SYNC-004, REQ-SYNC-006, INV-05
#[test]
fn test_chaos_malicious_relay_tampering_hash_mismatch_and_aead_failure() {
    // 1. Discrepancia SHA-256 en objeto direccionado por contenido
    let raw_payload = b"ORIGINAL_STATUS_BITSTRING_PAYLOAD";
    let hash = gravital_id_crypto::sha256(raw_payload);
    let mut hash_hex = String::new();
    for b in hash {
        use std::fmt::Write;
        let _ = write!(&mut hash_hex, "{b:02x}");
    }

    let mut corrupted = raw_payload.to_vec();
    corrupted[0] ^= 0xFF;
    let res = ContentVerifier::verify_object_sha256(&corrupted, &hash_hex);
    assert!(
        matches!(res, Err(SyncError::ContentIntegrityFailed { .. })),
        "Alteración de bytes DEBE provocar fallo de integridad SHA-256"
    );

    // 2. Corrupción de sobre HPKE
    let recipient_pub: [u8; 65] = [
        0x04, 0xa6, 0x97, 0xbf, 0xfd, 0xe9, 0x40, 0x5c, 0x99, 0x28, 0x83, 0xc5, 0xc4, 0x39, 0xd6,
        0xcc, 0x35, 0x81, 0x70, 0xb5, 0x1a, 0xf7, 0x28, 0x12, 0x33, 0x3b, 0x01, 0x56, 0x21, 0xdc,
        0x0f, 0x40, 0xba, 0xd9, 0xbb, 0x72, 0x6f, 0x68, 0xa5, 0xc0, 0x13, 0x80, 0x6a, 0x79, 0x0e,
        0xc7, 0x16, 0xab, 0x86, 0x69, 0xf8, 0x4f, 0x6b, 0x69, 0x45, 0x96, 0xc2, 0x98, 0x7c, 0xf3,
        0x5b, 0xab, 0xa2, 0xa0, 0x06,
    ];
    let recipient_priv: [u8; 32] = [
        0xa4, 0xd1, 0xc5, 0x58, 0x36, 0xaa, 0x30, 0xf9, 0xb3, 0xfb, 0xb6, 0xac, 0x98, 0xd3, 0x38,
        0xc8, 0x77, 0xc2, 0x86, 0x7d, 0xd3, 0xa7, 0x73, 0x96, 0xd1, 0x3f, 0x68, 0xd3, 0xab, 0x15,
        0x0d, 0x3b,
    ];
    let mut envelope = HpkeEnvelope::seal(
        &recipient_pub,
        &[0x77; 32],
        b"confidential-data",
        b"aad-proof",
    )
    .expect("seal");

    // Corromper el último byte del tag de autenticación
    if let Some(last) = envelope.last_mut() {
        *last ^= 0x55;
    }
    let open_res = HpkeEnvelope::open(&recipient_priv, &envelope, b"aad-proof");
    assert!(
        matches!(open_res, Err(SyncError::DecryptionFailed(_))),
        "Sobre HPKE con tag alterado DEBE fallar autenticación AEAD"
    );
}

// Verifies: REQ-TRUST-004, INV-05, INV-16
#[test]
fn test_chaos_rpc_outage_and_cross_ledger_divergence() {
    let now = UnixTime::from_seconds(1_770_000_000);
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
            Value::Number(Number::PosInt(100)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdeadbeef".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_add(86_400))),
        ),
        ("issuers".to_string(), Value::Array(vec![])),
        ("verifiers".to_string(), Value::Array(vec![])),
        ("operators".to_string(), Value::Array(vec![])),
    ]);
    let bundle = TrustBundle::from_payload(&bundle_payload).expect("bundle parse");
    let engine = FullVerificationEngine::standard();

    // 1. Caída total de RPC
    let failing = TestFailingLedgerAdapter { chain_id: 1 };
    let sources_failing: [(&str, &dyn LedgerAdapter); 2] =
        [("rpc-1-down", &failing), ("rpc-2-down", &failing)];
    let outcome_down = engine.verify_bundle(&bundle, &sources_failing, now.as_seconds());
    match outcome_down {
        FullVerificationOutcome::InsufficientSources {
            required,
            available,
            failed_sources,
        } => {
            assert_eq!(required, 2);
            assert_eq!(available, 0);
            assert_eq!(failed_sources.len(), 2);
        }
        other => panic!("Esperaba InsufficientSources ante RPC caído, obtuve {other:?}"),
    }

    // 2. Divergencia de bloques / drift excesivo
    let head1 = BlockHeader::new(300, [0x11; 32], [0x10; 32], now.as_seconds());
    let head2 = BlockHeader::new(
        100,
        [0x22; 32],
        [0x20; 32],
        now.as_seconds().saturating_sub(200),
    );
    let adapter1 = InMemoryLedgerAdapter::new(1, head1);
    let adapter2 = InMemoryLedgerAdapter::new(1, head2);
    let sources_drift: [(&str, &dyn LedgerAdapter); 2] =
        [("node-alpha", &adapter1), ("node-beta", &adapter2)];
    let outcome_drift = engine.verify_bundle(&bundle, &sources_drift, now.as_seconds());
    assert!(
        matches!(
            outcome_drift,
            FullVerificationOutcome::CrossLedgerDivergence(_)
        ),
        "Drift excesivo (> 100 bloques) DEBE generar CrossLedgerDivergence"
    );
}

// Verifies: REQ-REL-004, REQ-STAT-004, INV-04, INV-05
#[test]
fn test_chaos_cdn_outage_verifier_graceful_degradation() {
    let now = UnixTime::from_seconds(1_770_000_000);
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x1234_5678));
    let issuer_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("issuer jwk");
    let issuer_jwk_parsed =
        gravital_id_codec::json::parse(&issuer_jwk.to_canonical_json()).expect("parse");

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x8765_4321));
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let issuer_uri = "https://issuer.cdn-down.test";
    let status_uri = "https://status.cdn-down.test/lists/1";
    let kid = "cdn-down-key-01";
    let audience = "https://verifier.offline.test";

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
            Value::Number(Number::PosInt(100)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdeadbeef".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_add(86_400))),
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
                    Value::Array(vec![Value::String("urn:pip:vct:id".to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
                ),
                ("state".to_string(), Value::String("active".to_string())),
                (
                    "keys".to_string(),
                    Value::Array(vec![Value::Object(vec![
                        ("kid".to_string(), Value::String(kid.to_string())),
                        ("jwk".to_string(), issuer_jwk_parsed),
                        ("state".to_string(), Value::String("active".to_string())),
                        (
                            "state_since".to_string(),
                            Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
                        ),
                    ])]),
                ),
            ])]),
        ),
        ("verifiers".to_string(), Value::Array(vec![])),
        ("operators".to_string(), Value::Array(vec![])),
    ]);
    let bundle = TrustBundle::from_payload(&bundle_payload).expect("bundle");

    // Construcción de presentación válida
    let claims = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":5,"uri":"{}"}}}},"vct":"urn:pip:vct:id"}}"#,
        now.as_seconds().saturating_add(86_400),
        now.as_seconds(),
        issuer_uri,
        holder_jwk.to_canonical_json(),
        status_uri,
    );
    let jwt_header = r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#;
    let signing_input = format!(
        "{}.{}",
        base64url::encode(jwt_header.as_bytes()),
        base64url::encode(claims.as_bytes())
    );
    let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
    let sig = issuer_store.sign(&issuer_handle, &digest).expect("sign");
    let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
    let prefix = format!("{issuer_jwt}~");

    let pres = KbIssuer::create_presentation(
        &prefix,
        audience,
        "nonce-cdn-chaos",
        now,
        &holder_store,
        &holder_handle,
    )
    .expect("presentation");

    let req = VerificationRequest::new(
        "nonce-cdn-chaos",
        audience,
        UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let policy = VerificationPolicy::default();
    let mut state = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));

    // 1. Estado envejecido (> 1800s en Transaction) -> ValidWithStaleStatus
    let values = vec![0u32; 64];
    let jwt_status = format!(
        "{}.{}.{}",
        base64url::encode(r#"{"alg":"ES256","typ":"statuslist+jwt"}"#.as_bytes()),
        base64url::encode(
            format!(
                r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":2,"lst":"{}","uri":"{}"}}}}"#,
                now.as_seconds().saturating_add(86_400),
                now.as_seconds().saturating_sub(3_000),
                issuer_uri,
                pack_status_lst(2, &values),
                status_uri,
            )
            .as_bytes()
        ),
        base64url::encode(&[0u8; 64])
    );
    let status_list = StatusListVerifier::parse(&jwt_status).expect("status list");
    let stale_snapshot = StatusSnapshot::new(
        status_list,
        status_uri,
        UnixTime::from_seconds(now.as_seconds().saturating_sub(2_500)),
    );

    let res_stale = VerifierPipeline::verify(
        &pres,
        Some(&req),
        &bundle,
        Some(&stale_snapshot),
        &mut state,
        &policy,
        now,
        None,
    );
    assert_eq!(
        res_stale.status(),
        VerificationStatus::ValidWithStaleStatus,
        "Caché envejecida por CDN caída DEBE degradar a ValidWithStaleStatus"
    );

    // 2. Estado ausente totalmente (sin caché) -> Unverifiable
    let mut state2 = InMemoryStateStore::new(StateIntegrityKey::new([0x44; 32]));
    let req2 = VerificationRequest::new(
        "nonce-cdn-chaos-empty",
        audience,
        UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres2 = KbIssuer::create_presentation(
        &prefix,
        audience,
        "nonce-cdn-chaos-empty",
        now,
        &holder_store,
        &holder_handle,
    )
    .expect("presentation 2");

    let res_empty = VerifierPipeline::verify(
        &pres2,
        Some(&req2),
        &bundle,
        None,
        &mut state2,
        &policy,
        now,
        None,
    );
    assert_eq!(
        res_empty.status(),
        VerificationStatus::Unverifiable,
        "Estado no disponible por CDN caída DEBE degradar a Unverifiable fail-closed"
    );
}

// Verifies: REQ-PRIV-003, INV-02
#[test]
fn test_chaos_zero_pii_and_zero_panic_forensic_audit() {
    let raw_error_sample = format!(
        "Error in transport: {:?}, outcome: {:?}, code: {:?}",
        SyncError::ContentIntegrityFailed {
            expected_hash: "abcd".into(),
            actual_hash: "ef01".into(),
        },
        FullVerificationOutcome::InsufficientSources {
            required: 2,
            available: 0,
            failed_sources: vec![("rpc-node".into(), "timeout".into())],
        },
        gravital_id_types::ErrorCode::MalformedStatusList,
    );

    let forbidden_pii = [
        "holder_name",
        "first_name",
        "last_name",
        "document_number",
        "cedula",
        "panama",
        "private_key",
        "bearer_token",
    ];

    for forbidden in &forbidden_pii {
        assert!(
            !raw_error_sample.to_lowercase().contains(forbidden),
            "Fallo de privacidad INV-02: Se encontró '{forbidden}' en mensaje de error"
        );
    }
}
