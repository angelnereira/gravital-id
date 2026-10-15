#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración del pipeline completo de verificación offline (F4.T06).
//!
//! Trazabilidad:
//! - **REQ-VER-002:** El resultado DEBE ser uno de `Valid`, `ValidWithStaleStatus`,
//!   `Unverifiable`, `Invalid`, con lista de comprobaciones y evidencia exhaustiva.
//! - **REQ-VER-004:** Las claves de emisor se obtienen exclusivamente del trust bundle (INV-06).
//! - **REQ-VER-010:** Precedencia normativa de estados: `Invalid` > `Unverifiable` >
//!   `ValidWithStaleStatus` > `Valid`.
//! - **REQ-VER-012:** Las comprobaciones que dependen de datos no autenticados quedan
//!   estrictamente `Skipped` ante fallo de firma del emisor.
//! - **REQ-PRES-004:** Caché de nonces anti-replay integrada con `VerifierStateStore`.
//! - **REQ-STAT-004:** Frescura de estado evaluada por perfil y por clase de operación.
//! - **REQ-CRED-007:** Verificación de referencia de estado en el payload.
//! - **REQ-CRED-008:** Rechazo de algoritmos fuera de la lista y de `alg: none`.
//! - **INV-01:** Verificación 100 % desconectada sin I/O de red.
//! - **INV-04:** Modelo cerrado de cuatro estados con evidencia exhaustiva.
//! - **INV-05:** Fail-closed ante cualquier error, ambigüedad o inconsistencia.
//! - **INV-06:** Claves de emisor obtenidas únicamente del trust bundle.
//! - **INV-11:** Reloj inyectado determinista (`now: UnixTime`).

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::deflate::deflate;
use gravital_id_codec::json::{Number, Value};
use gravital_id_crypto::JwkEcP256;
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::bundle::TrustBundle;
use gravital_id_types::{ErrorCode, Kid, UnixTime, Vct};
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{OperationClass, VerificationPolicy};
use gravital_id_verifier::result::{CheckKind, CheckStatus, VerificationStatus};
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey, VerifierStateStore};

const NOW: UnixTime = UnixTime::from_seconds(1_770_000_000);
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";
const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const VERIFIER_AUDIENCE: &str = "https://verifier.example.com";
const NONCE: &str = "session-nonce-128bit-random-challenge";

/// Helper: Empaqueta una lista de bits y la comprime con DEFLATE.
fn pack_lst(bits: u8, values: &[u32]) -> String {
    let mut bytes = Vec::new();
    let mut current = 0u8;
    let mut used = 0u32;
    for value in values {
        for shift in (0..bits).rev() {
            let bit = (value >> shift) & 0b1;
            current = (current << 1) | (bit as u8);
            used = used.saturating_add(1);
            if used % 8 == 0 {
                bytes.push(current);
                current = 0;
            }
        }
    }
    if used % 8 != 0 {
        current <<= 8u32.saturating_sub(used % 8);
        bytes.push(current);
    }
    base64url::encode(&deflate(&bytes))
}

/// Helper: Construye un StatusSnapshot verificado para las pruebas.
fn build_status_snapshot(
    bits: u8,
    values: &[u32],
    uri: &str,
    acquired_at: UnixTime,
) -> StatusSnapshot {
    let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
    let payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":{},"lst":"{}","uri":"{}"}}}}"#,
        NOW.as_seconds().saturating_add(86_400),
        NOW.as_seconds().saturating_sub(3_600),
        ISSUER_URI,
        bits,
        pack_lst(bits, values),
        uri
    );
    let jwt = format!(
        "{}.{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes()),
        base64url::encode(&[0u8; 64])
    );
    let list = StatusListVerifier::parse(&jwt).expect("status list parse");
    StatusSnapshot::new(list, uri, acquired_at)
}

/// Helper: Construye un TrustBundle con el emisor y clave dados.
fn build_trust_bundle(
    issuer_uri: &str,
    issuer_state: &str,
    kid: &str,
    jwk: &JwkEcP256,
    key_state: &str,
    key_since: u64,
) -> TrustBundle {
    let jwk_parsed = gravital_id_codec::json::parse(jwk.to_canonical_json().as_str()).expect("jwk");
    let key_entry = Value::Object(vec![
        ("kid".to_string(), Value::String(kid.to_string())),
        ("jwk".to_string(), jwk_parsed),
        ("state".to_string(), Value::String(key_state.to_string())),
        (
            "state_since".to_string(),
            Value::Number(Number::PosInt(key_since)),
        ),
    ]);

    let payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String("pip-global".to_string()),
        ),
        ("bundle_epoch".to_string(), Value::Number(Number::PosInt(1))),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(1)),
        ),
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
            Value::Number(Number::PosInt(NOW.as_seconds().saturating_sub(86_400))),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(NOW.as_seconds().saturating_add(86_400))),
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
                    Value::Array(vec![Value::String(PERSONAL_VCT.to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(NOW.as_seconds().saturating_sub(86_400))),
                ),
                ("state".to_string(), Value::String(issuer_state.to_string())),
                ("keys".to_string(), Value::Array(vec![key_entry])),
            ])]),
        ),
    ]);

    TrustBundle::from_payload(&payload).expect("trust bundle from payload")
}

const ISSUER_KID: &str = "key-2026-issuer-01";

/// Fixture de prueba con emisor, titular, credencial y almacén de estado.
struct VerificationFixture {
    issuer_store: SoftwareKeyStore<SeededRng>,
    issuer_handle: gravital_id_keys::KeyHandle<IssuerSigning>,
    issuer_kid: String,
    issuer_jwk: JwkEcP256,

    holder_store: SoftwareKeyStore<SeededRng>,
    holder_handle: gravital_id_keys::KeyHandle<HolderBinding>,
    holder_jwk: JwkEcP256,

    state_store: InMemoryStateStore,
}

impl VerificationFixture {
    fn new(seed: u64) -> Self {
        let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(seed));
        let issuer_handle = issuer_store
            .generate_key::<IssuerSigning>()
            .expect("issuer key");
        let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("jwk");
        let issuer_kid = ISSUER_KID.to_string();

        let mut holder_store = SoftwareKeyStore::new(SeededRng::new(seed.saturating_add(100)));
        let holder_handle = holder_store
            .generate_key::<HolderBinding>()
            .expect("holder key");
        let holder_jwk = holder_store.public_key(&holder_handle).expect("jwk");

        let state_store = InMemoryStateStore::new(StateIntegrityKey::new([0x42; 32]));

        Self {
            issuer_store,
            issuer_handle,
            issuer_kid,
            issuer_jwk,
            holder_store,
            holder_handle,
            holder_jwk,
            state_store,
        }
    }

    /// Emite y presenta un SD-JWT VC con Key Binding JWT completo.
    fn issue_presentation(&self, now: UnixTime) -> String {
        let rng = SeededRng::new(999);
        let parsed_kid = Kid::parse(&self.issuer_kid).expect("kid");
        let builder = gravital_id_credential::SdJwtVcBuilder::new(
            ISSUER_URI,
            Vct::parse(PERSONAL_VCT).expect("vct"),
            now,
        )
        .expect("builder")
        .exp(UnixTime::from_seconds(
            now.as_seconds().saturating_add(86_400),
        ))
        .status_list(7, STATUS_LIST_URI)
        .expect("status list")
        .add_sd_claim("given_name", Value::String("Ana".to_string()))
        .add_sd_claim("family_name", Value::String("Perez".to_string()))
        .set_decoys(2)
        .cnf_jwk(self.holder_jwk.clone());

        let issued = builder
            .issue_signed(
                &self.issuer_store,
                &self.issuer_handle,
                Some(parsed_kid),
                &rng,
            )
            .expect("issue vc");

        // Presentación con divulgación de todos los claims y vinculación de titular (KB-JWT)
        let disclosures = issued.disclosures();
        let prefix = format!(
            "{}~{}~{}~",
            issued.jwt(),
            disclosures[0].encoded(),
            disclosures[1].encoded()
        );

        gravital_id_credential::KbIssuer::create_presentation(
            &prefix,
            VERIFIER_AUDIENCE,
            NONCE,
            now,
            &self.holder_store,
            &self.holder_handle,
        )
        .expect("holder presentation")
    }
}

// Verifies: REQ-VER-002, REQ-VER-004, REQ-VER-010, REQ-VER-012, INV-01, INV-04, INV-06, INV-11
#[test]
fn nominal_valid_presentation_passes_all_checks() {
    let mut fixture = VerificationFixture::new(1001);
    let presentation = fixture.issue_presentation(NOW);

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    // Lista con índice 7 = 00 (Válido) en 2 bits por entrada
    let mut values = vec![0u32; 16];
    values[7] = 0; // Valid
    let snapshot = build_status_snapshot(2, &values, STATUS_LIST_URI, NOW);

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        Some(&snapshot),
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Valid);
    assert!(result.is_valid());
    assert_eq!(result.issuer_id(), Some(ISSUER_URI));
    assert_eq!(result.kid_used(), Some(fixture.issuer_kid.as_str()));
    assert_eq!(result.vct(), Some(PERSONAL_VCT));

    // Verificar que las 11 comprobaciones están registradas y todas pasaron
    assert_eq!(result.checks().len(), 11);
    for check in result.checks() {
        assert_eq!(
            check.status,
            CheckStatus::Passed,
            "check {:?} expected to pass but got status {:?}",
            check.kind,
            check.status
        );
    }

    // Comprobar que los claims revelados fueron reconstruidos
    let claims = result.verified_claims().expect("claims");
    assert_eq!(
        claims.member("given_name"),
        Some(&Value::String("Ana".to_string()))
    );
    assert_eq!(
        claims.member("family_name"),
        Some(&Value::String("Perez".to_string()))
    );
}

// Verifies: REQ-VER-012, ADR-0020 (Typestate & Fail-Closed)
#[test]
fn unauthenticated_signature_strictly_skips_subsequent_checks() {
    let mut fixture = VerificationFixture::new(2002);
    let presentation = fixture.issue_presentation(NOW);

    // Modificar la firma del SD-JWT (corromper el segmento de firma antes de la primera tilde)
    let parts: Vec<&str> = presentation.split('~').collect();
    let jwt = parts[0];
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(jwt_parts.len(), 3);

    // Alterar un carácter de la firma
    let mut tampered_sig = jwt_parts[2].to_string();
    if tampered_sig.starts_with('A') {
        tampered_sig.replace_range(0..1, "B");
    } else {
        tampered_sig.replace_range(0..1, "A");
    }

    let tampered_jwt = format!("{}.{}.{}", jwt_parts[0], jwt_parts[1], tampered_sig);
    let mut tampered_presentation = tampered_jwt;
    for disclosure in &parts[1..] {
        tampered_presentation.push('~');
        tampered_presentation.push_str(disclosure);
    }

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let mut values = vec![0u32; 16];
    values[7] = 0;
    let snapshot = build_status_snapshot(2, &values, STATUS_LIST_URI, NOW);

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &tampered_presentation,
        Some(&request),
        &bundle,
        Some(&snapshot),
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Invalid);
    assert!(!result.is_valid());

    let checks = result.checks();
    assert_eq!(checks.len(), 11);

    // 1..=3: Structure, IssuerAuthorized, KeyState deben haber pasado
    assert_eq!(checks[0].kind, CheckKind::Structure);
    assert_eq!(checks[0].status, CheckStatus::Passed);

    assert_eq!(checks[1].kind, CheckKind::IssuerAuthorized);
    assert_eq!(checks[1].status, CheckStatus::Passed);

    assert_eq!(checks[2].kind, CheckKind::KeyState);
    assert_eq!(checks[2].status, CheckStatus::Passed);

    // 4: Signature falló con InvalidSignature
    assert_eq!(checks[3].kind, CheckKind::Signature);
    assert_eq!(checks[3].status, CheckStatus::Failed);
    assert_eq!(checks[3].error_code, Some(ErrorCode::InvalidSignature));

    // 5..=11: Validity, Disclosures, Schema, KeyBinding, Nonce, Status, Policy DEBEN ser Skipped (REQ-VER-012)
    let skipped_kinds = [
        CheckKind::Validity,
        CheckKind::Disclosures,
        CheckKind::Schema,
        CheckKind::KeyBinding,
        CheckKind::Nonce,
        CheckKind::Status,
        CheckKind::Policy,
    ];

    for (index, &kind) in skipped_kinds.iter().enumerate() {
        let check = &checks[4 + index];
        assert_eq!(check.kind, kind);
        assert_eq!(
            check.status,
            CheckStatus::Skipped,
            "check {:?} should be Skipped due to signature failure",
            kind
        );
    }
}

// Verifies: REQ-STAT-004, REQ-VER-002, REQ-VER-010 (ValidWithStaleStatus)
#[test]
fn stale_status_snapshot_yields_valid_with_stale_status() {
    let mut fixture = VerificationFixture::new(3003);
    let presentation = fixture.issue_presentation(NOW);

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let mut values = vec![0u32; 16];
    values[7] = 0; // Valid bit

    // Snapshot obtenido hace 8 días (límite de Personal es 7 días = 604_800s)
    let eight_days_ago = UnixTime::from_seconds(NOW.as_seconds().saturating_sub(8 * 24 * 3600));
    let snapshot = build_status_snapshot(2, &values, STATUS_LIST_URI, eight_days_ago);

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        Some(&snapshot),
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::ValidWithStaleStatus);
    assert!(!result.is_valid()); // Solo Valid puro responde true a is_valid()
    assert!(result.is_success()); // Pero es exitoso bajo modo degradado/offline
    assert!(result.status_age_seconds().is_some());
    assert!(result.status_age_seconds().unwrap() >= 8 * 24 * 3600);
}

// Verifies: REQ-CRED-007, REQ-VER-010 (Revoked status produces Invalid)
#[test]
fn revoked_status_bit_yields_invalid() {
    let mut fixture = VerificationFixture::new(4004);
    let presentation = fixture.issue_presentation(NOW);

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    // Lista con índice 7 = 01 (Revocado) en 2 bits por entrada
    let mut values = vec![0u32; 16];
    values[7] = 1; // 1 = Revoked
    let snapshot = build_status_snapshot(2, &values, STATUS_LIST_URI, NOW);

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        Some(&snapshot),
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Invalid);
    assert!(!result.is_valid());

    let status_check = result
        .checks()
        .iter()
        .find(|c| c.kind == CheckKind::Status)
        .expect("status check");
    assert_eq!(status_check.status, CheckStatus::Failed);
    assert_eq!(status_check.error_code, Some(ErrorCode::CredentialRevoked));
}

// Verifies: REQ-VER-004, INV-06 (Untrusted issuer yields Unverifiable)
#[test]
fn untrusted_issuer_not_in_bundle_yields_unverifiable() {
    let mut fixture = VerificationFixture::new(5005);
    let presentation = fixture.issue_presentation(NOW);

    // Trust bundle con otro emisor distinto
    let bundle = build_trust_bundle(
        "https://different.issuer.org",
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        None,
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Unverifiable);
    assert!(!result.is_valid());

    let issuer_check = &result.checks()[1];
    assert_eq!(issuer_check.kind, CheckKind::IssuerAuthorized);
    assert_eq!(issuer_check.status, CheckStatus::Indeterminate);
    assert_eq!(issuer_check.error_code, Some(ErrorCode::UntrustedIssuer));
}

// Verifies: REQ-KEY-005, INV-05 (Compromised key yields Invalid)
#[test]
fn permanently_compromised_key_yields_invalid() {
    let mut fixture = VerificationFixture::new(6006);
    let presentation = fixture.issue_presentation(NOW);

    // Clave marcada como compromised en el trust bundle
    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "compromised",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        None,
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Invalid);
    assert!(!result.is_valid());

    let key_check = &result.checks()[2];
    assert_eq!(key_check.kind, CheckKind::KeyState);
    assert_eq!(key_check.status, CheckStatus::Failed);
    assert_eq!(key_check.error_code, Some(ErrorCode::IssuerKeyCompromised));
}

// Verifies: REQ-PRES-004 (Nonce anti-replay rejection)
#[test]
fn nonce_replay_detected_by_state_store_yields_invalid() {
    let mut fixture = VerificationFixture::new(7007);
    let presentation = fixture.issue_presentation(NOW);

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let mut values = vec![0u32; 16];
    values[7] = 0;
    let snapshot = build_status_snapshot(2, &values, STATUS_LIST_URI, NOW);

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    // 1ª verificación: Éxito y nonce registrado
    let first_result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        Some(&snapshot),
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(first_result.status(), VerificationStatus::Valid);

    // 2ª verificación: Mismo nonce -> Detección de replay -> Invalid
    let second_result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        Some(&snapshot),
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(second_result.status(), VerificationStatus::Invalid);
    let nonce_check = second_result
        .checks()
        .iter()
        .find(|c| c.kind == CheckKind::Nonce)
        .expect("nonce check");
    assert_eq!(nonce_check.status, CheckStatus::Failed);
    assert_eq!(nonce_check.error_code, Some(ErrorCode::NonceReused));
}

// Verifies: REQ-VER-006, REQ-VER-011 (Clock rollback yields Unverifiable)
#[test]
fn clock_rollback_detected_yields_unverifiable() {
    let mut fixture = VerificationFixture::new(8008);
    let presentation = fixture.issue_presentation(NOW);

    // Elevar el piso de tiempo al futuro respecto a now
    let future_floor = UnixTime::from_seconds(NOW.as_seconds().saturating_add(3_600));
    fixture
        .state_store
        .raise_time_floor(future_floor)
        .expect("raise floor");

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let request = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &presentation,
        Some(&request),
        &bundle,
        None,
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Unverifiable);
    assert!(!result.is_valid());

    let structure_check = &result.checks()[0];
    assert_eq!(structure_check.status, CheckStatus::Indeterminate);
    assert_eq!(
        structure_check.error_code,
        Some(ErrorCode::ClockRollbackDetected)
    );
}

// Verifies: INV-08, REQ-CRED-008 (alg: none is strictly rejected)
#[test]
fn alg_none_is_strictly_rejected_at_structure_stage() {
    let mut fixture = VerificationFixture::new(9009);

    let header = r#"{"alg":"none","typ":"dc+sd-jwt"}"#;
    let payload = format!(r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}"}}"#);
    let fake_presentation = format!(
        "{}.{}.~",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes())
    );

    let bundle = build_trust_bundle(
        ISSUER_URI,
        "active",
        &fixture.issuer_kid,
        &fixture.issuer_jwk,
        "active",
        NOW.as_seconds().saturating_sub(86_400),
    );

    let policy = VerificationPolicy::default();

    let result = VerifierPipeline::verify(
        &fake_presentation,
        None,
        &bundle,
        None,
        &mut fixture.state_store,
        &policy,
        NOW,
        None,
    );

    assert_eq!(result.status(), VerificationStatus::Invalid);
    let structure_check = &result.checks()[0];
    assert_eq!(structure_check.status, CheckStatus::Failed);
    assert_eq!(
        structure_check.error_code,
        Some(ErrorCode::UnsupportedAlgorithm)
    );
}
