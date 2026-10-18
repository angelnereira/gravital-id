#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración E2E de rotación de firmantes de bundle, rotación de raíz de confianza
//! con doble umbral, solapamiento sin interrupción y recuperación ante avance forzado de versión
//! (*Forced Version Advance*) mediante incremento de `bundle_epoch` (F8.T08).
//!
//! Trazabilidad:
//! - **REQ-TRUST-006:** Los firmantes de bundle y las claves de raíz DEBEN poder rotarse
//!   mediante una raíz nueva encadenada, con solapamiento y sin interrumpir clientes.
//! - **REQ-TRUST-009:** El cliente DEBE aceptar una raíz nueva solo si la firman el umbral de la
//!   raíz anterior y el de la nueva; una raíz nueva DEBE poder incrementar `bundle_epoch` para
//!   recuperar de un avance forzado de versión.
//! - **REQ-TRUST-001:** Cofirma k-de-n de firmantes distintos, versión monotónica y vigencia.
//! - **REQ-TRUST-002:** Anti-rollback monotónico por `(bundle_epoch, bundle_version)`.
//! - **REQ-TRUST-008:** Derivación determinista idéntica byte a byte por operadores independientes.
//! - **REQ-VER-001..004:** Verificación offline sans-I/O sin red y resolución de claves del bundle.
//! - **INV-01:** Sans-I/O en verificación offline.
//! - **INV-02:** Cero datos personales o identificadores de titulares en raíces, bundles o eventos.
//! - **INV-04:** Cuatro estados de verificación con evidencia estructurada.
//! - **INV-05:** Fail-closed determinista.
//! - **INV-11:** Determinismo estricto e inyección de reloj.
//! - **INV-16:** Umbral k-de-n inviolable: ninguna clave única sostiene la confianza offline.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gravital_id_codec::base64url;
use gravital_id_codec::deflate::deflate;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::KbIssuer;
use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_crypto::{sha256, JwkEcP256};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_ledger::{
    BlockHeader, BundleDerivationParams, EventCoordinate, InMemoryLedgerAdapter,
    IssuerRegisteredEvent, KeyAddedEvent, LedgerEvent, SequencedLedgerEvent,
};
use gravital_id_status::StatusListVerifier;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::{
    to_canonical_json, AcceptedBundleState, MultiSignedJws, TrustBundle, TrustBundleVerifier,
    TrustRoot, TrustRootVerifier,
};
use gravital_id_types::{Clock, ErrorCode, UnixTime};
use gravital_id_verifier::{
    InMemoryStateStore, OperationClass, StateIntegrityKey, VerificationPolicy, VerificationRequest,
    VerificationStatus, VerifierPipeline,
};
use pip_indexer::storage::InMemoryIndexerStorage;
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_trust_service::aggregator::UntrustedBundleAggregator;
use pip_trust_service::operator::TrustOperatorNode;
use pip_trust_service::signer::LocalDevSigner;

const TEST_FRAMEWORK_ID: &str = "pip-panama-trust-v1";
const LOCAL_CHAIN_ID: u64 = 31337;
const TEST_REGISTRY_ADDR: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

/// Reloj sincronizable entre hilos para coordinar el indexador y las pruebas.
#[derive(Debug)]
struct TestSyncClock {
    now: AtomicU64,
}

impl TestSyncClock {
    fn new(initial_time: u64) -> Self {
        Self {
            now: AtomicU64::new(initial_time),
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

/// Estructura auxiliar para gestionar claves deterministas en las pruebas.
struct KeyRegistry {
    store: SoftwareKeyStore<SeededRng>,
    handles: BTreeMap<String, gravital_id_keys::KeyHandle<IssuerSigning>>,
    jwks: BTreeMap<String, JwkEcP256>,
    kids: BTreeMap<String, String>,
}

impl KeyRegistry {
    fn new(seed: u64) -> Self {
        Self {
            store: SoftwareKeyStore::new(SeededRng::new(seed)),
            handles: BTreeMap::new(),
            jwks: BTreeMap::new(),
            kids: BTreeMap::new(),
        }
    }

    fn generate(&mut self, label: &str) -> (String, JwkEcP256) {
        let handle = self.store.generate_key::<IssuerSigning>().expect("key");
        let jwk = self.store.public_key(&handle).expect("jwk");
        let kid = jwk.kid().expect("thumbprint kid").to_string();
        self.handles.insert(label.to_string(), handle);
        self.jwks.insert(label.to_string(), jwk.clone());
        self.kids.insert(label.to_string(), kid.clone());
        (kid, jwk)
    }

    fn kid(&self, label: &str) -> String {
        self.kids
            .get(label)
            .cloned()
            .unwrap_or_else(|| panic!("label '{label}' not registered"))
    }

    fn sign(&self, label: &str, signing_input: &str) -> [u8; 64] {
        let handle = self
            .handles
            .get(label)
            .unwrap_or_else(|| panic!("label '{label}' not registered"));
        let digest = sha256(signing_input.as_bytes());
        self.store.sign(handle, &digest).expect("sign")
    }
}

/// Construye el documento JWS multi-firma para una raíz de confianza.
#[allow(clippy::too_many_arguments)]
fn build_root_jws(
    framework_id: &str,
    root_version: u64,
    bundle_epoch: u64,
    issued_at: u64,
    valid_until: u64,
    root_keys: &[(&str, &JwkEcP256)],
    root_threshold: u32,
    bundle_signers: &[(&str, &str, &JwkEcP256)],
    bundle_threshold: u32,
    signing_keys: &[(&KeyRegistry, &str)],
) -> (String, TrustRoot, MultiSignedJws) {
    let root_entries: Vec<Value> = root_keys
        .iter()
        .map(|(kid, jwk)| {
            Value::Object(vec![
                ("crv".to_string(), Value::String("P-256".to_string())),
                ("kid".to_string(), Value::String(kid.to_string())),
                ("kty".to_string(), Value::String("EC".to_string())),
                ("x".to_string(), Value::String(jwk.x_base64url())),
                ("y".to_string(), Value::String(jwk.y_base64url())),
            ])
        })
        .collect();

    let signer_entries: Vec<Value> = bundle_signers
        .iter()
        .map(|(operator, kid, jwk)| {
            Value::Object(vec![
                (
                    "jwk".to_string(),
                    Value::Object(vec![
                        ("crv".to_string(), Value::String("P-256".to_string())),
                        ("kty".to_string(), Value::String("EC".to_string())),
                        ("x".to_string(), Value::String(jwk.x_base64url())),
                        ("y".to_string(), Value::String(jwk.y_base64url())),
                    ]),
                ),
                ("kid".to_string(), Value::String(kid.to_string())),
                ("operator".to_string(), Value::String(operator.to_string())),
            ])
        })
        .collect();

    let payload_val = Value::Object(vec![
        (
            "bundle_epoch".to_string(),
            Value::Number(Number::PosInt(bundle_epoch)),
        ),
        ("bundle_signers".to_string(), Value::Array(signer_entries)),
        (
            "bundle_threshold".to_string(),
            Value::Number(Number::PosInt(bundle_threshold as u64)),
        ),
        (
            "chain_id".to_string(),
            Value::Number(Number::PosInt(LOCAL_CHAIN_ID)),
        ),
        (
            "framework_id".to_string(),
            Value::String(framework_id.to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(issued_at)),
        ),
        (
            "registry_address".to_string(),
            Value::String(TEST_REGISTRY_ADDR.to_string()),
        ),
        ("root_keys".to_string(), Value::Array(root_entries)),
        (
            "root_threshold".to_string(),
            Value::Number(Number::PosInt(root_threshold as u64)),
        ),
        (
            "root_version".to_string(),
            Value::Number(Number::PosInt(root_version)),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(valid_until)),
        ),
    ]);

    let payload_json = to_canonical_json(&payload_val);
    let payload_b64 = base64url::encode(payload_json.as_bytes());

    let mut signatures = Vec::new();
    for (reg, label) in signing_keys {
        let kid = reg.kid(label);
        let protected = format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#);
        let protected_b64 = base64url::encode(protected.as_bytes());
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = reg.sign(label, &signing_input);
        signatures.push(format!(
            r#"{{"protected":"{protected_b64}","signature":"{}"}}"#,
            base64url::encode(&sig)
        ));
    }

    let document = format!(
        r#"{{"payload":"{payload_b64}","signatures":[{}]}}"#,
        signatures.join(",")
    );

    let (root, jws) = TrustRoot::parse(&document).expect("parse root document");
    (document, root, jws)
}

/// Helper para instanciar un `LocalDevSigner` determinista.
fn make_operator_signer(seed: u64, label: &str) -> (LocalDevSigner, JwkEcP256, String) {
    let rng = SeededRng::new(seed);
    let sk = generate_p256_secret_key(&rng).expect("valid sk");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");
    let kid = format!("urn:pip:signer:{label}");
    let signer = LocalDevSigner::from_secret_key(label, &kid, &sk).expect("valid dev signer");
    (signer, jwk, kid)
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

/// Helper para construir StatusSnapshot sintético de prueba.
fn build_test_snapshot(
    status_list_uri: &str,
    issuer_uri: &str,
    idx: u32,
    bit: u32,
    iat: UnixTime,
    acq: UnixTime,
) -> gravital_id_status::StatusSnapshot {
    let mut values = vec![0u32; 64];
    values[idx as usize] = bit;
    let mut bytes = Vec::new();
    let mut current = 0u8;
    let mut used = 0u32;
    for &val in &values {
        current = (current << 2) | (val as u8 & 0x03);
        used = used.saturating_add(2);
        if used == 8 {
            bytes.push(current);
            current = 0;
            used = 0;
        }
    }
    if !used.is_multiple_of(8) {
        current <<= 8u32.saturating_sub(used % 8);
        bytes.push(current);
    }
    let lst = base64url::encode(&deflate(&bytes));
    let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
    let payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":2,"lst":"{}","uri":"{}"}}}}"#,
        iat.as_seconds().saturating_add(86_400),
        iat.as_seconds(),
        issuer_uri,
        lst,
        status_list_uri
    );
    let jwt = format!(
        "{}.{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes()),
        base64url::encode(&[0u8; 64])
    );
    let list = StatusListVerifier::parse(&jwt).expect("status list parse");
    gravital_id_status::StatusSnapshot::new(list, status_list_uri, acq)
}

// =============================================================================
// TEST 1: ROTACIÓN ENCADENADA CON DOBLE UMBRAL (REQ-TRUST-009, REQ-TRUST-006, INV-16)
// =============================================================================

// Verifies: REQ-TRUST-006, REQ-TRUST-009, INV-16, INV-05
#[test]
fn test_e2e_root_and_bundle_signer_rotation_chain_with_dual_threshold() {
    let base_time = 1_700_000_000u64;

    // 1. Claves de raíz previa (R1) y candidata (R2)
    let mut reg_r1 = KeyRegistry::new(0x1111_0001);
    let (kid_r1_0, jwk_r1_0) = reg_r1.generate("root-0");
    let (kid_r1_1, jwk_r1_1) = reg_r1.generate("root-1");
    let (kid_r1_2, jwk_r1_2) = reg_r1.generate("root-2");

    let mut reg_r2 = KeyRegistry::new(0x2222_0002);
    // R2 conserva root-0 y root-1, pero reemplaza root-2 por root-3 (rotación de clave de raíz)
    let (kid_r2_3, jwk_r2_3) = reg_r2.generate("root-3");

    // Operadores de bundle en R1: [op-alpha, op-beta, op-gamma]
    let (_, jwk_op_alpha, kid_op_alpha) = make_operator_signer(101, "alpha");
    let (_, jwk_op_beta, kid_op_beta) = make_operator_signer(102, "beta");
    let (_, jwk_op_gamma, kid_op_gamma) = make_operator_signer(103, "gamma");

    // Operadores de bundle en R2: reemplaza op-gamma por op-delta (rotación de firmante de bundle)
    let (_, jwk_op_delta, kid_op_delta) = make_operator_signer(104, "delta");

    // Construcción de Raíz R1 (versión 1, época 1, umbral k_root=2 de 3, umbral k_bundle=2 de 3)
    let root_keys_r1 = [
        (kid_r1_0.as_str(), &jwk_r1_0),
        (kid_r1_1.as_str(), &jwk_r1_1),
        (kid_r1_2.as_str(), &jwk_r1_2),
    ];
    let bundle_signers_r1 = [
        ("op-alpha.org", kid_op_alpha.as_str(), &jwk_op_alpha),
        ("op-beta.com", kid_op_beta.as_str(), &jwk_op_beta),
        ("op-gamma.io", kid_op_gamma.as_str(), &jwk_op_gamma),
    ];
    let (_doc_r1, r1, r1_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        1,
        1,
        base_time,
        base_time + 100_000_000,
        &root_keys_r1,
        2,
        &bundle_signers_r1,
        2,
        &[(&reg_r1, "root-0"), (&reg_r1, "root-1")],
    );

    // Construcción de Raíz R2 (versión 2, época 1, umbral k_root=2 de 3, umbral k_bundle=2 de 3)
    let root_keys_r2 = [
        (kid_r1_0.as_str(), &jwk_r1_0),
        (kid_r1_1.as_str(), &jwk_r1_1),
        (kid_r2_3.as_str(), &jwk_r2_3),
    ];
    let bundle_signers_r2 = [
        ("op-alpha.org", kid_op_alpha.as_str(), &jwk_op_alpha),
        ("op-beta.com", kid_op_beta.as_str(), &jwk_op_beta),
        ("op-delta.io", kid_op_delta.as_str(), &jwk_op_delta),
    ];

    // R2 firmada con el DOBLE UMBRAL:
    // - 2 firmas de claves de R1: root-0 y root-1 (ambas pertenecen a R1.root_keys)
    // - 2 firmas de claves de R2: root-0 y root-3 (ambas pertenecen a R2.root_keys)
    let (_doc_r2, r2, r2_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        2,
        1,
        base_time + 500,
        base_time + 100_000_000,
        &root_keys_r2,
        2,
        &bundle_signers_r2,
        2,
        &[
            (&reg_r1, "root-0"), // Firma válida para R1 y para R2
            (&reg_r1, "root-1"), // Firma válida para R1 y para R2
            (&reg_r2, "root-3"), // Firma válida para R2
        ],
    );

    // Verificación nominal de la cadena de raíces (REQ-TRUST-009)
    TrustRootVerifier::verify_chain(&r1, &r1_jws, &r2, &r2_jws)
        .expect("verify_chain succeeds with dual threshold");
    assert!(!TrustRootVerifier::forces_new_epoch(&r1, &r2));

    // =========================================================================
    // CASOS NEGATIVOS DE ENCADENAMIENTO (FAIL-CLOSED, INV-05)
    // =========================================================================

    // 1. Versión no creciente (root_version=1 <= 1)
    let (_doc_stale, r_stale, r_stale_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        1,
        1,
        base_time + 500,
        base_time + 100_000_000,
        &root_keys_r2,
        2,
        &bundle_signers_r2,
        2,
        &[(&reg_r1, "root-0"), (&reg_r1, "root-1")],
    );
    let err_stale = TrustRootVerifier::verify_chain(&r1, &r1_jws, &r_stale, &r_stale_jws)
        .expect_err("stale version rejected");
    assert_eq!(err_stale.code, ErrorCode::TrustRootChainBroken);

    // 2. Marco diferente
    let (_doc_other, r_other, r_other_jws) = build_root_jws(
        "pip-other-framework",
        2,
        1,
        base_time + 500,
        base_time + 100_000_000,
        &root_keys_r2,
        2,
        &bundle_signers_r2,
        2,
        &[(&reg_r1, "root-0"), (&reg_r1, "root-1")],
    );
    let err_other = TrustRootVerifier::verify_chain(&r1, &r1_jws, &r_other, &r_other_jws)
        .expect_err("mismatched framework rejected");
    assert_eq!(err_other.code, ErrorCode::TrustRootChainBroken);

    // 3. Época decreciente (candidate.bundle_epoch < current.bundle_epoch)
    let (_doc_high_epoch, r_high_epoch, _r_high_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        1,
        5, // época 5
        base_time,
        base_time + 100_000_000,
        &root_keys_r1,
        2,
        &bundle_signers_r1,
        2,
        &[(&reg_r1, "root-0"), (&reg_r1, "root-1")],
    );
    let err_dec_epoch = TrustRootVerifier::verify_chain(&r_high_epoch, &r1_jws, &r2, &r2_jws)
        .expect_err("decreasing epoch rejected");
    assert_eq!(err_dec_epoch.code, ErrorCode::TrustRootChainBroken);

    // 4. Umbral de raíz previa insuficiente (solo 1 firma de R1 cuando se requieren 2)
    let (_doc_weak_prev, r_weak_prev, r_weak_prev_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        2,
        1,
        base_time + 500,
        base_time + 100_000_000,
        &root_keys_r2,
        2,
        &bundle_signers_r2,
        2,
        &[
            (&reg_r1, "root-0"), // Solo 1 firma de R1
            (&reg_r2, "root-3"), // 1 firma de R2
        ],
    );
    let err_weak_prev =
        TrustRootVerifier::verify_chain(&r1, &r1_jws, &r_weak_prev, &r_weak_prev_jws)
            .expect_err("insufficient prev signatures");
    assert_eq!(err_weak_prev.code, ErrorCode::InsufficientBundleSignatures);
}

// =============================================================================
// TEST 2: SOLAPAMIENTO SIN INTERRUPCIÓN DE CLIENTES (REQ-TRUST-006)
// =============================================================================

// Verifies: REQ-TRUST-006, REQ-TRUST-001, REQ-TRUST-008, REQ-VER-001..004, INV-01, INV-16
#[test]
fn test_e2e_overlap_without_client_disruption() {
    let base_time = 1_700_000_000u64;
    let issuer_id = [0x42; 32];
    let issuer_uri = "https://panama-id.te.gob.pa";

    // 1. Claves de raíz y operadores
    let mut reg_r1 = KeyRegistry::new(0x3333_0001);
    let (kid_r1_0, jwk_r1_0) = reg_r1.generate("root-0");
    let (kid_r1_1, jwk_r1_1) = reg_r1.generate("root-1");

    let mut reg_r2 = KeyRegistry::new(0x3333_0002);
    let (kid_r2_2, jwk_r2_2) = reg_r2.generate("root-2");

    // Operadores: alpha y beta están en AMBAS raíces (solapamiento). gamma está solo en R1, delta solo en R2.
    let (signer_alpha, jwk_op_alpha, kid_op_alpha) = make_operator_signer(201, "alpha");
    let (signer_beta, jwk_op_beta, kid_op_beta) = make_operator_signer(202, "beta");
    let (_signer_gamma, jwk_op_gamma, kid_op_gamma) = make_operator_signer(203, "gamma");
    let (_signer_delta, jwk_op_delta, kid_op_delta) = make_operator_signer(204, "delta");

    // Raíz R1 (instalada en Clientes versión 1)
    let root_keys_r1 = [
        (kid_r1_0.as_str(), &jwk_r1_0),
        (kid_r1_1.as_str(), &jwk_r1_1),
    ];
    let bundle_signers_r1 = [
        ("op-alpha.org", kid_op_alpha.as_str(), &jwk_op_alpha),
        ("op-beta.com", kid_op_beta.as_str(), &jwk_op_beta),
        ("op-gamma.io", kid_op_gamma.as_str(), &jwk_op_gamma),
    ];
    let (_doc_r1, root_v1, _r1_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        1,
        1,
        base_time,
        base_time + 100_000_000,
        &root_keys_r1,
        2,
        &bundle_signers_r1,
        2,
        &[(&reg_r1, "root-0"), (&reg_r1, "root-1")],
    );

    // Raíz R2 (instalada en Clientes actualizados a versión 2)
    let root_keys_r2 = [
        (kid_r1_0.as_str(), &jwk_r1_0),
        (kid_r2_2.as_str(), &jwk_r2_2),
    ];
    let bundle_signers_r2 = [
        ("op-alpha.org", kid_op_alpha.as_str(), &jwk_op_alpha),
        ("op-beta.com", kid_op_beta.as_str(), &jwk_op_beta),
        ("op-delta.io", kid_op_delta.as_str(), &jwk_op_delta),
    ];
    let (_doc_r2, root_v2, _r2_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        2,
        1,
        base_time + 100,
        base_time + 100_000_000,
        &root_keys_r2,
        2,
        &bundle_signers_r2,
        2,
        &[
            (&reg_r1, "root-0"),
            (&reg_r1, "root-1"),
            (&reg_r2, "root-2"),
        ],
    );

    // 2. Emisor institucional y clave de firma
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x4444_0001));
    let issuer_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("jwk");
    let mut pub_raw = vec![0x04];
    pub_raw.extend_from_slice(issuer_jwk.x());
    pub_raw.extend_from_slice(issuer_jwk.y());
    let mut kid_bytes = [0u8; 32];
    kid_bytes.copy_from_slice(issuer_jwk.thumbprint_sha256().as_slice());

    // 3. Indexación en ledger
    let indexer_storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(base_time + 200));
    let mut ledger = InMemoryLedgerAdapter::new(
        LOCAL_CHAIN_ID,
        BlockHeader::new(10, [0x10; 32], [0x09; 32], base_time + 200),
    );
    ledger.add_event(SequencedLedgerEvent::new(
        EventCoordinate::new(10, 0, 0, base_time + 200),
        LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id,
            uri: issuer_uri.into(),
            profiles: vec!["pip-personal-v1".into()],
            vcts: vec!["urn:pip:panama:cedula-v1".into()],
            valid_from: base_time,
            valid_until: base_time + 10_000_000,
        }),
    ));
    ledger.add_event(SequencedLedgerEvent::new(
        EventCoordinate::new(10, 1, 0, base_time + 200),
        LedgerEvent::KeyAdded(KeyAddedEvent {
            issuer_id,
            kid: kid_bytes,
            public_key: pub_raw,
        }),
    ));

    let indexer_config = pip_indexer::config::IndexerConfig {
        chain_id: LOCAL_CHAIN_ID,
        ..Default::default()
    };
    let indexer_engine = pip_indexer::engine::IndexerEngine::new(
        Arc::new(ledger),
        indexer_storage.clone(),
        clock.clone(),
        indexer_config,
        ShutdownCoordinator::new(),
        Arc::new(std::sync::Mutex::new(None)),
    );
    assert_eq!(indexer_engine.step().expect("step b10"), Some(10));

    // 4. Los operadores en común (alpha y beta) derivan y cofirman el bundle v10
    let node_alpha = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_alpha),
        LOCAL_CHAIN_ID,
    );
    let node_beta = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_beta),
        LOCAL_CHAIN_ID,
    );

    let params_v10 = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,  // bundle_epoch 1
        10, // bundle_version 10
        BlockHeader::new(10, [0x10; 32], [0x09; 32], base_time + 200),
        604_800,
        vec![],
    );
    let derived_v10 = node_alpha.derive_local_bundle(&params_v10).expect("derive");
    let sig_alpha = node_alpha
        .evaluate_and_sign(&params_v10)
        .expect("sign alpha");
    let sig_beta = node_beta.evaluate_and_sign(&params_v10).expect("sign beta");

    let mut authorized_signers = BTreeMap::new();
    authorized_signers.insert(kid_op_alpha.clone(), jwk_op_alpha.clone());
    authorized_signers.insert(kid_op_beta.clone(), jwk_op_beta.clone());

    let aggregator = UntrustedBundleAggregator::new(2);
    let aggregated_v10 = aggregator
        .aggregate(&derived_v10, &[sig_alpha, sig_beta], &authorized_signers)
        .expect("aggregate bundle v10");

    let (bundle_parsed, bundle_jws) =
        TrustBundle::parse(&aggregated_v10.jws_json).expect("parse bundle v10");

    // =========================================================================
    // SOLAPAMIENTO DE VERIFICACIÓN (REQ-TRUST-006):
    // El bundle es aceptado simultáneamente por Clientes con R1 y Clientes con R2
    // =========================================================================
    let eval_time = UnixTime::from_seconds(base_time + 300);

    // Cliente A (raíz R1 instalada):
    TrustBundleVerifier::verify(&bundle_parsed, &bundle_jws, &root_v1, None, eval_time)
        .expect("Cliente A acepta bundle v10 bajo Raíz R1");

    // Cliente B (raíz R2 instalada):
    TrustBundleVerifier::verify(&bundle_parsed, &bundle_jws, &root_v2, None, eval_time)
        .expect("Cliente B acepta bundle v10 bajo Raíz R2");

    // 5. Emisión de credencial y verificación offline por ambos clientes
    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x5555_0001));
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let kid_hex = hex_string(&kid_bytes);
    let header = format!(r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"{kid_hex}"}}"#);
    let header_b64 = base64url::encode(header.as_bytes());
    let claims = format!(
        r#"{{"iss":"{}","vct":"urn:pip:panama:cedula-v1","iat":{},"exp":{},"cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":5,"uri":"https://panama-id.te.gob.pa/status/v1.jwt"}}}}}}"#,
        issuer_uri,
        eval_time.as_seconds(),
        eval_time.as_seconds().saturating_add(86_400),
        holder_jwk.to_canonical_json()
    );
    let payload_b64 = base64url::encode(claims.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = sha256(signing_input.as_bytes());
    let issuer_sig = issuer_store.sign(&issuer_handle, &digest).expect("sign");
    let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&issuer_sig));
    let sd_jwt = format!("{issuer_jwt}~");

    let presentation = KbIssuer::create_presentation(
        &sd_jwt,
        "https://portal.gob.pa",
        "nonce-overlap-1",
        eval_time,
        &holder_store,
        &holder_handle,
    )
    .expect("create presentation");

    let snapshot = build_test_snapshot(
        "https://panama-id.te.gob.pa/status/v1.jwt",
        issuer_uri,
        5,
        0,
        eval_time,
        eval_time,
    );
    let policy = VerificationPolicy::default();

    // Verificación offline por Cliente A (con Bundle verificado bajo R1)
    let mut store_a = InMemoryStateStore::new(StateIntegrityKey::new([0xAA; 32]));
    let req_a = VerificationRequest::new(
        "nonce-overlap-1",
        "https://portal.gob.pa",
        UnixTime::from_seconds(eval_time.as_seconds() + 300),
        OperationClass::Transaction,
    );
    let res_a = VerifierPipeline::verify(
        presentation.as_str(),
        Some(&req_a),
        &bundle_parsed,
        Some(&snapshot),
        &mut store_a,
        &policy,
        eval_time,
        None,
    );
    assert_eq!(
        res_a.status(),
        VerificationStatus::Valid,
        "Cliente A verifica con éxito en solapamiento"
    );

    // Verificación offline por Cliente B (con Bundle verificado bajo R2)
    let mut store_b = InMemoryStateStore::new(StateIntegrityKey::new([0xBB; 32]));
    let req_b = VerificationRequest::new(
        "nonce-overlap-1",
        "https://portal.gob.pa",
        UnixTime::from_seconds(eval_time.as_seconds() + 300),
        OperationClass::Transaction,
    );
    let res_b = VerifierPipeline::verify(
        presentation.as_str(),
        Some(&req_b),
        &bundle_parsed,
        Some(&snapshot),
        &mut store_b,
        &policy,
        eval_time,
        None,
    );
    assert_eq!(
        res_b.status(),
        VerificationStatus::Valid,
        "Cliente B verifica con éxito en solapamiento"
    );
}

// =============================================================================
// TEST 3: ATAQUE DE AVANCE FORZADO Y RECUPERACIÓN POR BUNDLE_EPOCH
// =============================================================================

// Verifies: REQ-TRUST-002, REQ-TRUST-009, REQ-TRUST-006, INV-05, INV-16
#[test]
fn test_e2e_forced_version_advance_and_epoch_recovery() {
    let base_time = 1_700_000_000u64;

    // 1. Claves de la Autoridad TFA y Operadores iniciales de Época 1
    let mut reg_tfa = KeyRegistry::new(0x6666_0001);
    let (kid_root_0, jwk_root_0) = reg_tfa.generate("root-0");
    let (kid_root_1, jwk_root_1) = reg_tfa.generate("root-1");

    // Operadores de época 1 (algunos comprometidos):
    let (signer_rogue_1, jwk_rogue_1, kid_rogue_1) = make_operator_signer(301, "rogue-1");
    let (signer_rogue_2, jwk_rogue_2, kid_rogue_2) = make_operator_signer(302, "rogue-2");

    let root_keys_r1 = [
        (kid_root_0.as_str(), &jwk_root_0),
        (kid_root_1.as_str(), &jwk_root_1),
    ];
    let bundle_signers_r1 = [
        ("rogue-op-1.org", kid_rogue_1.as_str(), &jwk_rogue_1),
        ("rogue-op-2.org", kid_rogue_2.as_str(), &jwk_rogue_2),
    ];

    // Raíz R1 (versión 1, ÉPOCA 1, umbral k=2)
    let (_doc_r1, root_epoch1, _r1_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        1,
        1, // bundle_epoch = 1
        base_time,
        base_time + 100_000_000,
        &root_keys_r1,
        2,
        &bundle_signers_r1,
        2,
        &[(&reg_tfa, "root-0"), (&reg_tfa, "root-1")],
    );

    // Estado local nominal del verificador: bundle aceptado en época 1, versión 5
    let mut accepted_state = AcceptedBundleState {
        bundle_epoch: 1,
        bundle_version: 5,
    };

    // =========================================================================
    // ETAPA 1: ATAQUE DE AVANCE FORZADO (Forced Version Advance Attack)
    // Los operadores maliciosos publican un bundle con bundle_version = 999_999_999
    // =========================================================================
    let indexer_storage = Arc::new(InMemoryIndexerStorage::new());
    let op_malicious_1 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_rogue_1),
        LOCAL_CHAIN_ID,
    );
    let op_malicious_2 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_rogue_2),
        LOCAL_CHAIN_ID,
    );

    let params_attack = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1,           // época 1
        999_999_999, // VERSIÓN EXTREMA MALICIOSA
        BlockHeader::new(50, [0x50; 32], [0x49; 32], base_time + 100),
        604_800,
        vec![],
    );
    let derived_attack = op_malicious_1
        .derive_local_bundle(&params_attack)
        .expect("derive attack");
    let sig_atk_1 = op_malicious_1
        .evaluate_and_sign(&params_attack)
        .expect("sig 1");
    let sig_atk_2 = op_malicious_2
        .evaluate_and_sign(&params_attack)
        .expect("sig 2");

    let mut attack_authorized = BTreeMap::new();
    attack_authorized.insert(kid_rogue_1.clone(), jwk_rogue_1.clone());
    attack_authorized.insert(kid_rogue_2.clone(), jwk_rogue_2.clone());

    let aggregator = UntrustedBundleAggregator::new(2);
    let aggregated_attack = aggregator
        .aggregate(&derived_attack, &[sig_atk_1, sig_atk_2], &attack_authorized)
        .expect("aggregate attack bundle");

    let (bundle_attack, jws_attack) =
        TrustBundle::parse(&aggregated_attack.jws_json).expect("parse attack bundle");

    let t_attack = UnixTime::from_seconds(base_time + 200);

    // El verificador (ingenuamente) acepta el bundle con versión 999_999_999
    // porque 999_999_999 > 5 (cumple anti-rollback en ese momento).
    TrustBundleVerifier::verify(
        &bundle_attack,
        &jws_attack,
        &root_epoch1,
        Some(accepted_state),
        t_attack,
    )
    .expect("el verificador ingesta el avance forzado");

    // El verificador actualiza su estado local al valor astronómico
    accepted_state = AcceptedBundleState {
        bundle_epoch: 1,
        bundle_version: 999_999_999,
    };

    // =========================================================================
    // ETAPA 2: INTENTO DE PUBLICAR UN BUNDLE LEGÍTIMO POSTERIOR DE ÉPOCA 1
    // (Ej. versión 6). El anti-rollback BLOQUEA el ecosistema (REQ-TRUST-002)
    // =========================================================================
    let params_legit_v6 = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        1, // época 1
        6, // versión honesta
        BlockHeader::new(60, [0x60; 32], [0x50; 32], base_time + 300),
        604_800,
        vec![],
    );
    let derived_v6 = op_malicious_1
        .derive_local_bundle(&params_legit_v6)
        .expect("derive v6");
    let sig_v6_1 = op_malicious_1
        .evaluate_and_sign(&params_legit_v6)
        .expect("sig v6 1");
    let sig_v6_2 = op_malicious_2
        .evaluate_and_sign(&params_legit_v6)
        .expect("sig v6 2");

    let agg_v6 = aggregator
        .aggregate(&derived_v6, &[sig_v6_1, sig_v6_2], &attack_authorized)
        .expect("aggregate v6");
    let (bundle_v6, jws_v6) = TrustBundle::parse(&agg_v6.jws_json).expect("parse v6");

    let err_blocked = TrustBundleVerifier::verify(
        &bundle_v6,
        &jws_v6,
        &root_epoch1,
        Some(accepted_state),
        UnixTime::from_seconds(base_time + 400),
    )
    .expect_err("bundle legítimo bloqueado por rollback detection");

    assert_eq!(
        err_blocked.code,
        ErrorCode::BundleVersionRollback,
        "La regla anti-rollback bloquea el bundle legítimo de versión menor en época 1"
    );

    // =========================================================================
    // ETAPA 3: RECUPERACIÓN POR LA TFA MEDIANTE RAÍZ ENCADENADA CON BUNDLE_EPOCH = 2
    // (REQ-TRUST-009, TRUST_BUNDLE.md §6)
    // =========================================================================

    // Nuevos operadores íntegros para Época 2:
    let (signer_clean_1, jwk_clean_1, kid_clean_1) = make_operator_signer(401, "clean-1");
    let (signer_clean_2, jwk_clean_2, kid_clean_2) = make_operator_signer(402, "clean-2");

    let bundle_signers_r2 = [
        ("clean-op-1.org", kid_clean_1.as_str(), &jwk_clean_1),
        ("clean-op-2.org", kid_clean_2.as_str(), &jwk_clean_2),
    ];

    // Raíz R2 con incremento de bundle_epoch = 2 y root_version = 2
    let (_doc_r2, root_epoch2, r2_jws) = build_root_jws(
        TEST_FRAMEWORK_ID,
        2, // root_version 2
        2, // BUNDLE_EPOCH INCREMENTADO A 2 (RECUPERACIÓN)
        base_time + 500,
        base_time + 100_000_000,
        &root_keys_r1,
        2,
        &bundle_signers_r2,
        2,
        &[(&reg_tfa, "root-0"), (&reg_tfa, "root-1")],
    );

    // Verificación de la cadena de raíces:
    TrustRootVerifier::verify_chain(&root_epoch1, &_r1_jws, &root_epoch2, &r2_jws)
        .expect("cadena de raíces válida con doble umbral");

    // Detección obligatoria de cambio de época (forces_new_epoch):
    let forces_new_epoch = TrustRootVerifier::forces_new_epoch(&root_epoch1, &root_epoch2);
    assert!(
        forces_new_epoch,
        "La nueva raíz incrementa bundle_epoch y fuerza descarte de época anterior"
    );

    // Al forzar nueva época, el cliente de verificación descarta el bundle anterior
    // y reinicia su estado local:
    let recovered_accepted_state = None; // Reinicio a estado sin bundle aceptado en época 2

    // =========================================================================
    // ETAPA 4: OPERACIÓN RESTAURADA EN ÉPOCA 2 CON VERSIÓN INICIAL (bundle_version = 1)
    // =========================================================================
    let op_clean_1 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_clean_1),
        LOCAL_CHAIN_ID,
    );
    let op_clean_2 = TrustOperatorNode::new(
        indexer_storage.clone(),
        Arc::new(signer_clean_2),
        LOCAL_CHAIN_ID,
    );

    let params_recovered = BundleDerivationParams::new(
        TEST_FRAMEWORK_ID,
        2, // ÉPOCA 2
        1, // VERSIÓN INICIAL 1 (REINICIADA TRAS EL ATAQUE)
        BlockHeader::new(70, [0x70; 32], [0x60; 32], base_time + 600),
        604_800,
        vec![],
    );
    let derived_recovered = op_clean_1
        .derive_local_bundle(&params_recovered)
        .expect("derive rec");
    let sig_rec_1 = op_clean_1
        .evaluate_and_sign(&params_recovered)
        .expect("sig 1");
    let sig_rec_2 = op_clean_2
        .evaluate_and_sign(&params_recovered)
        .expect("sig 2");

    let mut clean_authorized = BTreeMap::new();
    clean_authorized.insert(kid_clean_1.clone(), jwk_clean_1.clone());
    clean_authorized.insert(kid_clean_2.clone(), jwk_clean_2.clone());

    let agg_recovered = aggregator
        .aggregate(
            &derived_recovered,
            &[sig_rec_1, sig_rec_2],
            &clean_authorized,
        )
        .expect("aggregate recovered bundle");

    let (bundle_recovered, jws_recovered) =
        TrustBundle::parse(&agg_recovered.jws_json).expect("parse recovered bundle");

    let t_eval_rec = UnixTime::from_seconds(base_time + 700);

    // El verificador acepta el bundle v1 de época 2 contra la Raíz R2:
    TrustBundleVerifier::verify(
        &bundle_recovered,
        &jws_recovered,
        &root_epoch2,
        recovered_accepted_state,
        t_eval_rec,
    )
    .expect("¡Recuperación exitosa! El verificador acepta bundle v1 en Época 2");

    // =========================================================================
    // COMPROBACIÓN NEGATIVA: INTENTO DE REPLAY DE BUNDLE DE ÉPOCA ANTERIOR (ÉPOCA 1)
    // =========================================================================
    let err_stale_epoch = TrustBundleVerifier::verify(
        &bundle_attack, // tiene bundle_epoch = 1
        &jws_attack,
        &root_epoch2, // exige bundle_epoch = 2
        None,
        t_eval_rec,
    )
    .expect_err("bundle con época antigua debe ser rechazado fail-closed");

    assert_eq!(
        err_stale_epoch.code,
        ErrorCode::MalformedSdJwt,
        "Rechazo fail-closed cuando bundle_epoch != root.bundle_epoch"
    );
}

// =============================================================================
// TEST 4: AUDITORÍA FORENSE CERO DATOS PERSONALES (INV-02, REQ-LEDG-001)
// =============================================================================

// Verifies: INV-02, REQ-LEDG-001
#[test]
fn test_root_rotation_zero_pii_audit() {
    let mut reg = KeyRegistry::new(0x7777_0001);
    let (kid_0, jwk_0) = reg.generate("r0");
    let (kid_1, jwk_1) = reg.generate("r1");
    let (_, jwk_op, kid_op) = make_operator_signer(501, "op1");

    let (doc_r1, _, _) = build_root_jws(
        TEST_FRAMEWORK_ID,
        1,
        1,
        1_700_000_000,
        1_800_000_000,
        &[(kid_0.as_str(), &jwk_0), (kid_1.as_str(), &jwk_1)],
        2,
        &[("op-audit.org", kid_op.as_str(), &jwk_op)],
        1,
        &[(&reg, "r0"), (&reg, "r1")],
    );

    let forbidden_patterns = [
        "name",
        "given_name",
        "family_name",
        "cedula",
        "email",
        "phone",
        "birthdate",
        "address",
        "holder",
        "subject",
        "dni",
        "passport",
        "imei",
        "serial",
    ];

    let doc_lower = doc_r1.to_lowercase();
    for pattern in &forbidden_patterns {
        assert!(
            !doc_lower.contains(pattern),
            "Fuga potencial de dato personal detectada en documento de raíz: '{pattern}'"
        );
    }
}
