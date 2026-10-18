#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración automatizadas para la revocación durante periodos offline
//! y sincronización (F7.T11, ROADMAP.md §24 Criterio MVP-05).
//!
//! Trazabilidad:
//! - **REQ-STAT-004:** La frescura máxima DEBE definirse por perfil y clase de operación.
//! - **REQ-STAT-007:** Los estados soportados DEBEN ser válido, revocado y suspendido.
//! - **REQ-STAT-008:** Manifiesto de estado firmado con versión monotónica y anti-rollback.
//! - **REQ-REL-004:** Degradación explícita a `ValidWithStaleStatus` cuando el estado supera la frescura.
//! - **INV-01:** Verificación sin I/O de red.
//! - **INV-02:** Cero datos personales o identificadores de titular en el pipeline y estado.
//! - **INV-04:** Cuatro estados normativos (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
//! - **INV-05:** Fail-closed determinista.
//! - **INV-11:** Reloj inyectado determinista.

use gravital_id_codec::base64url;
use gravital_id_codec::deflate::deflate;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::KbIssuer;
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::manifest::StatusManifestVerifier;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::bundle::TrustBundle;
use gravital_id_types::UnixTime;
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{OperationClass, VerificationPolicy};
use gravital_id_verifier::result::{CheckKind, CheckStatus, VerificationStatus};
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey};
use std::process::Command;

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

// Verifies: REQ-STAT-004, REQ-STAT-008, REQ-REL-004, INV-01, INV-04, INV-05, INV-11
#[test]
fn cli_demo_mvp05_completes_all_steps_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .arg("demo-mvp05")
        .output()
        .expect("ejecutar pip-cli demo-mvp05");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains(
            "Gravital ID (PIP) — Demostración Oficial de Revocación Offline (F7.T11, MVP-05)"
        ),
        "Debe contener encabezado de MVP-05"
    );
    assert!(
        stdout.contains("Verificación inicial fresca: Valid"),
        "Paso 1 debe ser Valid"
    );
    assert!(
        stdout.contains("Degradación explícita determinista: ValidWithStaleStatus"),
        "Paso 3 debe degradar a ValidWithStaleStatus"
    );
    assert!(
        stdout
            .contains("Credencial revocada reflejada deterministamente tras sincronizar: Invalid"),
        "Paso 5 debe ser Invalid"
    );
    assert!(
        stdout.contains("Intento de rollback de estado rechazado fail-closed"),
        "Paso 6 debe rechazar rollback"
    );
    assert!(
        stdout.contains("HITO M2 & ESCENARIO MVP-05 CUMPLIDO"),
        "Debe certificar cumplimiento de MVP-05"
    );
}

// Verifies: REQ-STAT-004, REQ-STAT-007, REQ-REL-004, INV-01, INV-04, INV-05, INV-11
#[test]
fn test_mvp05_lifecycle_offline_stale_to_invalid_after_sync() {
    let base_time = UnixTime::from_seconds(1_770_000_000);

    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0x1111_2222));
    let issuer_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("issuer jwk");
    let issuer_jwk_parsed =
        gravital_id_codec::json::parse(&issuer_jwk.to_canonical_json()).expect("jwk parse");

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x3333_4444));
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    let issuer_uri = "https://issuer.te.gob.pa";
    let status_list_uri = "https://status.te.gob.pa/lists/2026-10";
    let vct = "urn:gravital-id:vct:pip-personal-v1";
    let audience = "https://policia.gob.pa/terminal-transito";
    let kid = "key-te-01";
    let credential_index = 42u32;

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
            Value::Number(Number::PosInt(200)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdeadbeef".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(
                base_time.as_seconds().saturating_sub(86_400),
            )),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(
                base_time.as_seconds().saturating_add(86_400),
            )),
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
                    Value::Array(vec![Value::String(vct.to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(
                        base_time.as_seconds().saturating_sub(86_400),
                    )),
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
                            Value::Number(Number::PosInt(
                                base_time.as_seconds().saturating_sub(86_400),
                            )),
                        ),
                    ])]),
                ),
            ])]),
        ),
    ]);
    let bundle = TrustBundle::from_payload(&bundle_payload).expect("trust bundle");

    let make_presentation = |now: UnixTime, nonce: &str| -> String {
        let header = format!(r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"{kid}"}}"#);
        let payload = format!(
            r#"{{"iss":"{issuer_uri}","vct":"{vct}","iat":{},"exp":{},"cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":{credential_index},"uri":"{status_list_uri}"}}}}}}"#,
            base_time.as_seconds(),
            base_time.as_seconds().saturating_add(86_400),
            holder_jwk.to_canonical_json()
        );
        let h_b64 = base64url::encode(header.as_bytes());
        let p_b64 = base64url::encode(payload.as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
        let sig = issuer_store
            .sign(&issuer_handle, &digest)
            .expect("sign issuer jwt");
        let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
        let prefix = format!("{issuer_jwt}~");

        KbIssuer::create_presentation(&prefix, audience, nonce, now, &holder_store, &holder_handle)
            .expect("create kb presentation")
    };

    let build_snapshot = |status_bit: u32,
                          issued_time: UnixTime,
                          acquired_time: UnixTime|
     -> StatusSnapshot {
        let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
        let mut values = vec![0u32; 64];
        values[credential_index as usize] = status_bit;
        let payload = format!(
            r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":2,"lst":"{}","uri":"{}"}}}}"#,
            base_time.as_seconds().saturating_add(86_400),
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
    };

    let policy = VerificationPolicy::default();
    let mut verifier_store = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));

    // 1. T0: Estado inicial activo (bit 0 = Valid)
    let snap_v1 = build_snapshot(0, base_time, base_time);
    let req_t0 = VerificationRequest::new(
        "nonce-t0-fresh",
        audience,
        UnixTime::from_seconds(base_time.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_t0 = make_presentation(base_time, "nonce-t0-fresh");
    let res_t0 = VerifierPipeline::verify(
        &pres_t0,
        Some(&req_t0),
        &bundle,
        Some(&snap_v1),
        &mut verifier_store,
        &policy,
        base_time,
        None,
    );
    assert_eq!(res_t0.status(), VerificationStatus::Valid);

    // 2. T_offline: Verificador desconectado. En emisor ocurre revocación a T0+600s.
    // El verificador presenta a T0+3600s (> umbral Transaction de 1800s).
    let t_offline = UnixTime::from_seconds(base_time.as_seconds().saturating_add(3600));
    let req_offline = VerificationRequest::new(
        "nonce-offline-stale",
        audience,
        UnixTime::from_seconds(t_offline.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_offline = make_presentation(t_offline, "nonce-offline-stale");
    let res_offline = VerifierPipeline::verify(
        &pres_offline,
        Some(&req_offline),
        &bundle,
        Some(&snap_v1), // Sigue en posesión del snapshot V1
        &mut verifier_store,
        &policy,
        t_offline,
        None,
    );
    assert_eq!(
        res_offline.status(),
        VerificationStatus::ValidWithStaleStatus
    );
    assert_eq!(res_offline.status_age_seconds(), Some(3600));
    assert!(res_offline.status().is_success()); // ValidWithStaleStatus sigue siendo éxito condicional

    // 3. T_sync: Verificador sincroniza y obtiene snapshot V2 (bit 1 = Revoked).
    let t_sync = UnixTime::from_seconds(base_time.as_seconds().saturating_add(3650));
    let snap_v2 = build_snapshot(
        1,
        UnixTime::from_seconds(base_time.as_seconds().saturating_add(600)),
        t_sync,
    );
    let req_sync = VerificationRequest::new(
        "nonce-sync-revoked",
        audience,
        UnixTime::from_seconds(t_sync.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let pres_sync = make_presentation(t_sync, "nonce-sync-revoked");
    let res_sync = VerifierPipeline::verify(
        &pres_sync,
        Some(&req_sync),
        &bundle,
        Some(&snap_v2),
        &mut verifier_store,
        &policy,
        t_sync,
        None,
    );
    assert_eq!(res_sync.status(), VerificationStatus::Invalid);
    assert!(!res_sync.status().is_success());
    assert_eq!(
        res_sync.check(CheckKind::Status).map(|c| c.status),
        Some(CheckStatus::Failed)
    );
}

// Verifies: REQ-STAT-004
#[test]
fn test_mvp05_freshness_thresholds_per_operation_class() {
    let policy = VerificationPolicy::default();

    // Verificación de los umbrales normativos de VerificationPolicy:
    // - Transaction: 30 minutos (1800 s)
    // - Query: 4 horas (14400 s)
    // - Default: 7 días (604800 s)
    let fresh_tx = policy.status_freshness(OperationClass::Transaction);
    let fresh_query = policy.status_freshness(OperationClass::Query);
    let fresh_default = policy.status_freshness(OperationClass::Default);

    assert_eq!(fresh_tx.max_age_seconds, 1800);
    assert_eq!(fresh_query.max_age_seconds, 14400);
    assert_eq!(fresh_default.max_age_seconds, 604800);

    // Un snapshot con 3600 segundos (1 hora) de antigüedad:
    let age_1h = 3600u64;
    // Excede Transaction (1800s) -> no lo admite
    assert!(!fresh_tx.admits(age_1h));
    // Cumple Query (14400s) -> lo admite
    assert!(fresh_query.admits(age_1h));
    // Cumple Default (604800s) -> lo admite
    assert!(fresh_default.admits(age_1h));

    // Un snapshot con 20000 segundos (~5.5 horas) de antigüedad:
    let age_5h = 20000u64;
    assert!(!fresh_tx.admits(age_5h));
    assert!(!fresh_query.admits(age_5h));
    assert!(fresh_default.admits(age_5h));
}

// Verifies: REQ-STAT-008, INV-05
#[test]
fn test_mvp05_status_manifest_anti_rollback_enforcement() {
    let base_time = UnixTime::from_seconds(1_770_000_000);

    let build_manifest = |version: u64| {
        let payload = Value::Object(vec![
            (
                "issuer_id".to_string(),
                Value::String("https://issuer.te.gob.pa".to_string()),
            ),
            (
                "manifest_version".to_string(),
                Value::Number(Number::PosInt(version)),
            ),
            (
                "issued_at".to_string(),
                Value::Number(Number::PosInt(base_time.as_seconds())),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(
                    base_time.as_seconds().saturating_add(86_400),
                )),
            ),
            (
                "status_lists".to_string(),
                Value::Array(vec![Value::Object(vec![
                    (
                        "status_list_id".to_string(),
                        Value::String("list-1".to_string()),
                    ),
                    (
                        "type".to_string(),
                        Value::String("TokenStatusList".to_string()),
                    ),
                    (
                        "uri".to_string(),
                        Value::String("https://status.te.gob.pa/lists/2026-10".to_string()),
                    ),
                    ("sha256".to_string(), Value::String("11".repeat(32))),
                ])]),
            ),
        ]);
        StatusManifestVerifier::from_payload(&payload).expect("manifest parse")
    };

    let manifest_v1 = build_manifest(1);
    let manifest_v2 = build_manifest(2);
    let manifest_v3 = build_manifest(3);

    // 1. Primer manifiesto aceptado: sin versión previa
    assert!(manifest_v1.check_monotonic_version(None).is_ok());

    // 2. Avance legítimo monotónico: v2 > v1
    assert!(manifest_v2.check_monotonic_version(Some(1)).is_ok());

    // 3. Intento de re-inyección de la misma versión (v2 cuando ya se aceptó v2) -> Rechazado
    assert!(manifest_v2.check_monotonic_version(Some(2)).is_err());

    // 4. Intento de ataque de rollback (v1 cuando ya se aceptó v2) -> Rechazado fail-closed
    assert!(manifest_v1.check_monotonic_version(Some(2)).is_err());

    // 5. Avance legítimo a v3
    assert!(manifest_v3.check_monotonic_version(Some(2)).is_ok());

    // 6. Intento de rollback a v2 tras aceptar v3 -> Rechazado fail-closed
    assert!(manifest_v2.check_monotonic_version(Some(3)).is_err());
}
