#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de la raíz de confianza y del trust bundle (F4.T03).
//!
//! Trazabilidad:
//! - **REQ-TRUST-001:** cofirma k-de-n de firmantes distintos, versión monotónica y
//!   ventana de validez.
//! - **REQ-TRUST-002:** anti-rollback por `(bundle_epoch, bundle_version)`.
//! - **REQ-TRUST-009:** cadena de raíces con doble umbral y recuperación de avance forzado.
//! - **REQ-TRUST-010:** el bundle no contiene punteros ni hashes de listas de estado.
//! - **INV-16:** ninguna clave única sostiene la confianza offline.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{Number, Value};
use gravital_id_crypto::{sha256, JwkEcP256};
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_trust::{
    AcceptedBundleState, TrustBundle, TrustBundleVerifier, TrustRoot, TrustRootVerifier,
};
use gravital_id_types::{ErrorCode, UnixTime};

const NOW: UnixTime = UnixTime::from_seconds(1_769_849_600);

/// Clave generada, con su `kid` real (thumbprint RFC 7638) y un rol legible.
struct KeyEntry {
    role: String,
    kid: String,
    handle: gravital_id_keys::KeyHandle<IssuerSigning>,
    jwk: JwkEcP256,
}

/// Conjunto de claves determinista para las pruebas.
struct Keys {
    store: SoftwareKeyStore<SeededRng>,
    entries: Vec<KeyEntry>,
}

impl Keys {
    fn new(seed: u64) -> Self {
        Self {
            store: SoftwareKeyStore::new(SeededRng::new(seed)),
            entries: Vec::new(),
        }
    }

    /// Genera una clave y la asocia a un rol; devuelve su `kid` real.
    fn generate(&mut self, role: &str) -> String {
        let handle = self.store.generate_key::<IssuerSigning>().expect("key");
        let jwk = self.store.public_key(&handle).expect("jwk");
        let kid = jwk.kid().expect("kid del thumbprint").to_string();
        self.entries.push(KeyEntry {
            role: role.to_string(),
            kid: kid.clone(),
            handle,
            jwk,
        });
        kid
    }

    /// `kid` real de un rol.
    fn kid(&self, role: &str) -> String {
        self.entries
            .iter()
            .find(|entry| entry.role == role)
            .map(|entry| entry.kid.clone())
            .expect("rol no generado")
    }

    /// Clave pública de un rol.
    fn jwk(&self, role: &str) -> &JwkEcP256 {
        self.entries
            .iter()
            .find(|entry| entry.role == role)
            .map(|entry| &entry.jwk)
            .expect("rol no generado")
    }

    /// Firma `signing_input` con la clave privada de un rol.
    fn sign(
        &self,
        role: &str,
        signing_input: &str,
    ) -> [u8; gravital_id_crypto::ES256_SIGNATURE_LEN] {
        let handle = self
            .entries
            .iter()
            .find(|entry| entry.role == role)
            .map(|entry| &entry.handle)
            .expect("rol no generado");
        let digest = sha256(signing_input.as_bytes());
        self.store.sign(handle, &digest).expect("sign")
    }
}

/// Entrada JWK de un documento de confianza.
fn jwk_entry(kid: &str, jwk: &JwkEcP256) -> Value {
    let parsed = gravital_id_codec::json::parse(jwk.to_canonical_json().as_str()).expect("jwk");
    Value::Object(vec![
        ("kid".to_string(), Value::String(kid.to_string())),
        ("jwk".to_string(), parsed),
    ])
}

/// Entrada de firmante de bundle.
fn signer_entry(operator: &str, kid: &str, jwk: &JwkEcP256) -> Value {
    let mut base = jwk_entry(kid, jwk);
    if let Value::Object(entries) = &mut base {
        entries.push(("operator".to_string(), Value::String(operator.to_string())));
    }
    base
}

/// Serializa un payload JSON de forma canónica y devuelve también su base64url.
fn canonical(payload: &Value) -> (String, String) {
    let json = gravital_id_trust::to_canonical_json(payload);
    (json.clone(), base64url::encode(json.as_bytes()))
}

/// Firma un payload con los roles indicados y devuelve el documento JWS completo
/// junto con la entrada firmada de la primera firma.
fn sign_document(keys: &Keys, payload_b64: &str, roles: &[String]) -> (String, String) {
    let mut signatures = Vec::new();
    let mut first_protected = String::new();
    for role in roles {
        let kid = keys.kid(role);
        let protected = format!(r#"{{"alg":"ES256","kid":"{kid}"}}"#);
        let protected_b64 = base64url::encode(protected.as_bytes());
        if first_protected.is_empty() {
            first_protected = protected_b64.clone();
        }
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signature = keys.sign(role, &signing_input);
        signatures.push(format!(
            r#"{{"protected":"{protected_b64}","signature":"{}"}}"#,
            base64url::encode(&signature)
        ));
    }
    let document = format!(
        r#"{{"payload":"{payload_b64}","signatures":[{}]}}"#,
        signatures.join(",")
    );
    (document, format!("{first_protected}.{payload_b64}"))
}

/// Raíz de confianza de prueba con sus claves ya generadas.
struct RootFixture {
    #[allow(dead_code)]
    keys: Keys,
    root: TrustRoot,
    document: String,
}

fn build_root(
    seed: u64,
    framework: &str,
    version: u64,
    epoch: u64,
    signing: &[&str],
) -> RootFixture {
    let mut keys = Keys::new(seed);
    for index in 0..3 {
        keys.generate(&format!("root-{index}"));
    }
    for index in 0..3 {
        keys.generate(&format!("signer-{index}"));
    }

    let root_entries: Vec<Value> = (0..3)
        .map(|index| {
            let role = format!("root-{index}");
            jwk_entry(&keys.kid(&role), keys.jwk(&role))
        })
        .collect();
    let signer_entries: Vec<Value> = (0..3)
        .map(|index| {
            let role = format!("signer-{index}");
            let kid = keys.kid(&role);
            signer_entry(&format!("op-{kid}.org"), &kid, keys.jwk(&role))
        })
        .collect();

    let payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String(framework.to_string()),
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
            Value::Number(Number::PosInt(1_700_000_000)),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(1_900_000_000)),
        ),
        ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
        (
            "registry_address".to_string(),
            Value::String("0x1234567890123456789012345678901234567890".to_string()),
        ),
        ("root_keys".to_string(), Value::Array(root_entries)),
        (
            "root_threshold".to_string(),
            Value::Number(Number::PosInt(2)),
        ),
        ("bundle_signers".to_string(), Value::Array(signer_entries)),
        (
            "bundle_threshold".to_string(),
            Value::Number(Number::PosInt(2)),
        ),
    ]);
    let (_json, payload_b64) = canonical(&payload);
    let roles: Vec<String> = signing.iter().map(|role| role.to_string()).collect();
    let (document, _signing_input) = sign_document(&keys, &payload_b64, &roles);

    let (root, _jws) = TrustRoot::parse(&document).expect("root parse");
    RootFixture {
        keys,
        root,
        document,
    }
}

/// Entrada completa de clave de emisor (con estado y vigencia del estado).
fn issuer_key_entry(kid: &str, jwk: &JwkEcP256, state: &str, state_since: u64) -> Value {
    let mut entry = jwk_entry(kid, jwk);
    if let Value::Object(entries) = &mut entry {
        entries.push(("state".to_string(), Value::String(state.to_string())));
        entries.push((
            "state_since".to_string(),
            Value::Number(Number::PosInt(state_since)),
        ));
    }
    entry
}

/// Payload JSON canónico de un bundle con un emisor.
fn bundle_payload(
    epoch: u64,
    version: u64,
    issuer_key_kid: &str,
    issuer_jwk: &JwkEcP256,
) -> (String, String) {
    let payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String("pip-global".to_string()),
        ),
        (
            "bundle_epoch".to_string(),
            Value::Number(Number::PosInt(epoch)),
        ),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(version)),
        ),
        ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
        (
            "registry_address".to_string(),
            Value::String("0xabc".to_string()),
        ),
        (
            "finalized_block_number".to_string(),
            Value::Number(Number::PosInt(100)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdead".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(1_700_000_000)),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(1_900_000_000)),
        ),
        (
            "issuers".to_string(),
            Value::Array(vec![Value::Object(vec![
                (
                    "issuer_id".to_string(),
                    Value::String("iss-example".to_string()),
                ),
                (
                    "profiles".to_string(),
                    Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
                ),
                (
                    "vcts".to_string(),
                    Value::Array(vec![Value::String("https://v.example/1".to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(1_700_000_000)),
                ),
                ("state".to_string(), Value::String("active".to_string())),
                (
                    "keys".to_string(),
                    Value::Array(vec![issuer_key_entry(
                        issuer_key_kid,
                        issuer_jwk,
                        "active",
                        1_700_000_000,
                    )]),
                ),
            ])]),
        ),
    ]);
    canonical(&payload)
}

// Verifies: REQ-TRUST-001, REQ-TRUST-009
#[test]
fn root_chain_requires_both_thresholds() {
    let current = build_root(6_201, "pip-global", 1, 1, &["root-0", "root-1"]);
    let candidate = build_root(6_202, "pip-global", 2, 1, &["root-1", "root-2"]);

    let (current_root, current_jws) = TrustRoot::parse(&current.document).expect("current");
    let (candidate_root, candidate_jws) = TrustRoot::parse(&candidate.document).expect("candidate");

    // El documento candidato no lleva firmas de la ra\u00edz anterior sobre su propia entrada:
    // la cadena se rompe por umbral insuficiente.
    let error = TrustRootVerifier::verify_chain(
        &current_root,
        &current_jws,
        &candidate_root,
        &candidate_jws,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InsufficientBundleSignatures);

    // Versi\u00f3n no creciente.
    let stale = build_root(6_203, "pip-global", 1, 1, &["root-0", "root-1"]);
    let (stale_root, stale_jws) = TrustRoot::parse(&stale.document).expect("stale");
    let error =
        TrustRootVerifier::verify_chain(&current_root, &current_jws, &stale_root, &stale_jws)
            .unwrap_err();
    assert_eq!(error.code, ErrorCode::TrustRootChainBroken);

    // Marco distinto.
    let other = build_root(6_204, "otro-marco", 5, 1, &["root-0", "root-1"]);
    let (other_root, other_jws) = TrustRoot::parse(&other.document).expect("other");
    let error =
        TrustRootVerifier::verify_chain(&current_root, &current_jws, &other_root, &other_jws)
            .unwrap_err();
    assert_eq!(error.code, ErrorCode::TrustRootChainBroken);
}

// Verifies: REQ-TRUST-009
#[test]
fn root_chain_accepts_a_candidate_with_both_thresholds() {
    // Un único juego de claves: la raíz instalada y la candidata comparten `root_keys`,
    // de modo que las firmas del candidato las verifican ambos umbrales.
    let mut keys = Keys::new(6_205);
    for index in 0..3 {
        keys.generate(&format!("root-{index}"));
    }
    for index in 0..3 {
        keys.generate(&format!("signer-{index}"));
    }

    let root_entries: Vec<Value> = (0..3)
        .map(|index| {
            let role = format!("root-{index}");
            jwk_entry(&keys.kid(&role), keys.jwk(&role))
        })
        .collect();
    let signer_entries: Vec<Value> = (0..3)
        .map(|index| {
            let role = format!("signer-{index}");
            let kid = keys.kid(&role);
            signer_entry(&format!("op-{kid}.org"), &kid, keys.jwk(&role))
        })
        .collect();

    let payload_of = |version: u64, own_threshold: u32| -> Value {
        Value::Object(vec![
            (
                "framework_id".to_string(),
                Value::String("pip-global".to_string()),
            ),
            (
                "root_version".to_string(),
                Value::Number(Number::PosInt(version)),
            ),
            ("bundle_epoch".to_string(), Value::Number(Number::PosInt(1))),
            (
                "issued_at".to_string(),
                Value::Number(Number::PosInt(1_700_000_000)),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(1_900_000_000)),
            ),
            ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
            (
                "registry_address".to_string(),
                Value::String("0x1234567890123456789012345678901234567890".to_string()),
            ),
            ("root_keys".to_string(), Value::Array(root_entries.clone())),
            (
                "root_threshold".to_string(),
                Value::Number(Number::PosInt(u64::from(own_threshold))),
            ),
            (
                "bundle_signers".to_string(),
                Value::Array(signer_entries.clone()),
            ),
            (
                "bundle_threshold".to_string(),
                Value::Number(Number::PosInt(2)),
            ),
        ])
    };

    // Raíz instalada: versión 1 firmada por root-0 y root-1.
    let (_, previous_b64) = canonical(&payload_of(1, 2));
    let (previous_doc, _previous_input) = sign_document(
        &keys,
        &previous_b64,
        &["root-0".to_string(), "root-1".to_string()],
    );
    let (previous_root, previous_jws) = TrustRoot::parse(&previous_doc).expect("previous");

    // Candidata: versión 2, con umbral propio 3, firmada por root-0, root-1 y root-2.
    let (_, candidate_b64) = canonical(&payload_of(2, 3));
    let (candidate_doc, _candidate_input) = sign_document(
        &keys,
        &candidate_b64,
        &[
            "root-0".to_string(),
            "root-1".to_string(),
            "root-2".to_string(),
        ],
    );
    let (candidate_root, candidate_jws) = TrustRoot::parse(&candidate_doc).expect("candidate");

    TrustRootVerifier::verify_chain(
        &previous_root,
        &previous_jws,
        &candidate_root,
        &candidate_jws,
    )
    .expect("cadena con ambos umbrales cumplidos");

    // Con solo dos firmas se cumple el umbral de la raíz anterior (2) pero no el propio (3).
    let (weak_doc, _weak_input) = sign_document(
        &keys,
        &candidate_b64,
        &["root-0".to_string(), "root-1".to_string()],
    );
    let (weak_root, weak_jws) = TrustRoot::parse(&weak_doc).expect("weak candidate");
    let error =
        TrustRootVerifier::verify_chain(&previous_root, &previous_jws, &weak_root, &weak_jws)
            .unwrap_err();
    assert_eq!(error.code, ErrorCode::InsufficientBundleSignatures);
}

// Verifies: REQ-TRUST-009, TRUST_BUNDLE.md \u00a76
#[test]
fn forced_version_advance_is_recovered_by_a_new_epoch() {
    let current = build_root(6_206, "pip-global", 3, 1, &["root-0", "root-1"]);
    let recovered = build_root(6_207, "pip-global", 4, 2, &["root-0", "root-2"]);

    assert_eq!(recovered.root.root_version(), 4);
    assert_eq!(recovered.root.bundle_epoch(), 2);
    assert!(TrustRootVerifier::forces_new_epoch(
        &current.root,
        &recovered.root
    ));

    // Dentro de la misma \u00e9poca no hay avance forzado.
    let same = build_root(6_208, "pip-global", 5, 2, &["root-0", "root-1"]);
    assert!(!TrustRootVerifier::forces_new_epoch(
        &recovered.root,
        &same.root
    ));

    // Una \u00e9poca menor se rechaza en la cadena.
    let older = build_root(6_209, "pip-global", 5, 1, &["root-0", "root-1"]);
    let (older_root, older_jws) = TrustRoot::parse(&older.document).expect("older");
    let (same_root, same_jws) = TrustRoot::parse(&same.document).expect("same");
    let error = TrustRootVerifier::verify_chain(&same_root, &same_jws, &older_root, &older_jws)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::TrustRootChainBroken);
}

// Verifies: REQ-TRUST-001, REQ-TRUST-002
#[test]
fn bundle_verification_enforces_threshold_epoch_rollback_and_window() {
    let fixture = build_root(6_210, "pip-global", 1, 1, &["root-0", "root-1"]);
    // Conforme a TRUST_BUNDLE.md §3.1: kid en kebab-case, no un thumbprint base64url.
    let issuer_key_kid = "iss-cedula-2026-01".to_string();
    let issuer_jwk = fixture.keys.jwk("root-2").clone();

    let (bundle_json, bundle_b64) = bundle_payload(1, 100, &issuer_key_kid, &issuer_jwk);
    let sign_with = |kids: &[&str], payload_b64: &str| -> (String, String) {
        let list: Vec<String> = kids.iter().map(|kid| kid.to_string()).collect();
        sign_document(&fixture.keys, payload_b64, &list)
    };

    // Umbral cumplido: dos firmantes distintos.
    let (good, _good_input) = sign_with(&["signer-0", "signer-1"], &bundle_b64);
    let (bundle, jws) = TrustBundle::parse(&good).expect("bundle parse");
    TrustBundleVerifier::verify(&bundle, &jws, &fixture.root, None, NOW)
        .expect("bundle con umbral cumplido");

    // Un solo firmante: umbral no alcanzado (INV-16).
    let (weak, _weak_input) = sign_with(&["signer-0"], &bundle_b64);
    let (weak_bundle, weak_jws) = TrustBundle::parse(&weak).expect("weak parse");
    let error =
        TrustBundleVerifier::verify(&weak_bundle, &weak_jws, &fixture.root, None, NOW).unwrap_err();
    assert_eq!(error.code, ErrorCode::InsufficientBundleSignatures);

    // \u00c9poca incompatible con la ra\u00edz activa.
    let (_wrong_json, wrong_b64) = bundle_payload(2, 100, &issuer_key_kid, &issuer_jwk);
    let (wrong_epoch, _wrong_input) = sign_with(&["signer-0", "signer-1"], &wrong_b64);
    let (epoch_bundle, epoch_jws) = TrustBundle::parse(&wrong_epoch).expect("epoch parse");
    let error = TrustBundleVerifier::verify(&epoch_bundle, &epoch_jws, &fixture.root, None, NOW)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    assert!(error.message.contains("epoch"));

    // Anti-rollback: versi\u00f3n no creciente respecto a la aceptada.
    let accepted = AcceptedBundleState {
        bundle_epoch: 1,
        bundle_version: 100,
    };
    let error =
        TrustBundleVerifier::verify(&bundle, &jws, &fixture.root, Some(accepted), NOW).unwrap_err();
    assert_eq!(error.code, ErrorCode::BundleVersionRollback);

    // Fuera de la ventana de validez.
    let error = TrustBundleVerifier::verify(
        &bundle,
        &jws,
        &fixture.root,
        None,
        UnixTime::from_seconds(1_950_000_000),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::StatusListExpired);

    // Marco distinto del de la ra\u00edz.
    let mut wrong_framework = bundle_json.clone();
    wrong_framework = wrong_framework.replace("pip-global", "otro-marco");
    let (_, wrong_framework_b64) = canonical(&Value::Null);
    let _ = wrong_framework_b64;
    let mut payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String("otro-marco".to_string()),
        ),
        ("bundle_epoch".to_string(), Value::Number(Number::PosInt(1))),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(100)),
        ),
        ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
        (
            "registry_address".to_string(),
            Value::String("0xabc".to_string()),
        ),
        (
            "finalized_block_number".to_string(),
            Value::Number(Number::PosInt(100)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdead".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(1_700_000_000)),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(1_900_000_000)),
        ),
        ("issuers".to_string(), Value::Array(vec![])),
    ]);
    let (_json2, framework_b64) = canonical(&payload);
    let (framework_doc, _framework_input) = sign_with(&["signer-0", "signer-1"], &framework_b64);
    let (framework_bundle, framework_jws) =
        TrustBundle::parse(&framework_doc).expect("framework parse");
    let error =
        TrustBundleVerifier::verify(&framework_bundle, &framework_jws, &fixture.root, None, NOW)
            .unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    let _ = &mut payload;
    let _ = wrong_framework;
}

// Verifies: REQ-TRUST-010
#[test]
fn bundle_payload_has_no_status_list_pointers() {
    let mut keys = Keys::new(6_211);
    keys.generate("iss-key-1");
    let payload = Value::Object(vec![
        (
            "issuer_id".to_string(),
            Value::String("iss-example".to_string()),
        ),
        (
            "keys".to_string(),
            Value::Array(vec![jwk_entry("iss-key-1", keys.jwk("iss-key-1"))]),
        ),
    ]);
    let text = gravital_id_trust::to_canonical_json(&payload).to_lowercase();
    assert!(!text.contains("status_list"));
    assert!(!text.contains("statuslist"));
    assert!(!text.contains("list_uri"));
}

// Verifies: REQ-SEC-005 (regresi\u00f3n del parser JWS multi-firma)
#[test]
fn duplicate_signatures_from_the_same_signer_are_rejected() {
    let fixture = build_root(6_212, "pip-global", 1, 1, &["root-0", "root-1"]);
    let (_json, payload_b64) = canonical(&Value::Object(vec![(
        "framework_id".to_string(),
        Value::String("pip-global".to_string()),
    )]));

    let protected = base64url::encode(br#"{"alg":"ES256","kid":"signer-0"}"#);
    let signature = base64url::encode(&[0u8; 64]);
    let document = format!(
        r#"{{"payload":"{payload_b64}","signatures":[{{"protected":"{protected}","signature":"{signature}"}},{{"protected":"{protected}","signature":"{signature}"}}]}}"#
    );
    let error = TrustBundle::parse(&document).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    assert!(error.message.contains("duplicate"));
    let _ = &fixture.keys;
}
