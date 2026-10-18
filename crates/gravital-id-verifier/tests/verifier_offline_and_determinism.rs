#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de verificación sin red (sans-I/O) y determinismo estricto (F4.T10, F4.T11).
//!
//! Trazabilidad:
//! - **REQ-VER-001:** La verificación DEBE poder realizarse completamente offline, sin I/O de red,
//!   usando únicamente el trust bundle local, el estado local y el reloj inyectado.
//! - **REQ-VER-009:** El verificador DEBE ser determinista: a entradas idénticas y mismo tiempo inyectado,
//!   la salida es idéntica bit a bit.
//! - **REQ-SDK-008:** El verificador opera sin I/O de red (sans-I/O): todo dato externo (bundle,
//!   revocación, reloj) se inyecta por el integrador o la plataforma.
//! - **REQ-PRIV-002:** La verificación local sin red protege la privacidad del titular: ningún tercero
//!   ni servidor central se entera de las presentaciones en tiempo real.
//! - **REQ-REL-004:** Degradación explícita a `Unverifiable` o `ValidWithStaleStatus` cuando falta
//!   sincronización, sin aceptar jamás datos inválidos.
//! - **INV-01:** La verificación nunca realiza I/O de red. Ningún crate L1–L4 hace I/O.
//! - **INV-04:** Cuatro estados con evidencia (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
//! - **INV-05:** Fail-closed determinista ante cualquier inconsistencia.
//! - **INV-11:** El núcleo no lee el reloj ni aleatoriedad implícita: se inyectan deterministamente.

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
use gravital_id_types::{ErrorCode, UnixTime};
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{OperationClass, VerificationPolicy};
use gravital_id_verifier::result::{CheckKind, CheckStatus, VerificationStatus};
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey};
use proptest::prelude::*;

const BASE_TIME: UnixTime = UnixTime::from_seconds(1_770_000_000);
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";
const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const VERIFIER_AUDIENCE: &str = "https://verifier.example.com";
const NONCE: &str = "offline-determinism-nonce-128bit";
const ISSUER_KID: &str = "key-2026-issuer-offline";

fn pack_lst(bits: u8, values: &[u32]) -> String {
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

fn build_status_snapshot(
    bits: u8,
    values: &[u32],
    uri: &str,
    acquired_at: UnixTime,
) -> StatusSnapshot {
    let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
    let payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":{},"lst":"{}","uri":"{}"}}}}"#,
        BASE_TIME.as_seconds().saturating_add(86_400),
        BASE_TIME.as_seconds().saturating_sub(3_600),
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

struct OfflineTestFixture {
    issuer_store: SoftwareKeyStore<SeededRng>,
    issuer_handle: gravital_id_keys::KeyHandle<IssuerSigning>,
    issuer_jwk: JwkEcP256,
    holder_store: SoftwareKeyStore<SeededRng>,
    holder_handle: gravital_id_keys::KeyHandle<HolderBinding>,
    holder_jwk: JwkEcP256,
}

impl OfflineTestFixture {
    fn new(seed: u64) -> Self {
        let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(seed));
        let issuer_handle = issuer_store
            .generate_key::<IssuerSigning>()
            .expect("gen issuer");
        let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("jwk issuer");

        let mut holder_store = SoftwareKeyStore::new(SeededRng::new(seed.wrapping_add(100_000)));
        let holder_handle = holder_store
            .generate_key::<HolderBinding>()
            .expect("gen holder");
        let holder_jwk = holder_store.public_key(&holder_handle).expect("jwk holder");

        Self {
            issuer_store,
            issuer_handle,
            issuer_jwk,
            holder_store,
            holder_handle,
            holder_jwk,
        }
    }

    fn trust_bundle(&self) -> TrustBundle {
        let jwk_parsed =
            gravital_id_codec::json::parse(self.issuer_jwk.to_canonical_json().as_str())
                .expect("jwk");
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
                Value::Number(Number::PosInt(
                    BASE_TIME.as_seconds().saturating_sub(86_400),
                )),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(
                    BASE_TIME.as_seconds().saturating_add(86_400),
                )),
            ),
            (
                "issuers".to_string(),
                Value::Array(vec![Value::Object(vec![
                    (
                        "issuer_id".to_string(),
                        Value::String(ISSUER_URI.to_string()),
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
                        Value::Number(Number::PosInt(
                            BASE_TIME.as_seconds().saturating_sub(86_400),
                        )),
                    ),
                    ("state".to_string(), Value::String("active".to_string())),
                    (
                        "keys".to_string(),
                        Value::Array(vec![Value::Object(vec![
                            ("kid".to_string(), Value::String(ISSUER_KID.to_string())),
                            ("jwk".to_string(), jwk_parsed),
                            ("state".to_string(), Value::String("active".to_string())),
                            (
                                "state_since".to_string(),
                                Value::Number(Number::PosInt(
                                    BASE_TIME.as_seconds().saturating_sub(86_400),
                                )),
                            ),
                        ])]),
                    ),
                ])]),
            ),
        ]);
        TrustBundle::from_payload(&payload).expect("trust bundle")
    }

    fn sign_presentation(
        &self,
        exp: u64,
        status_idx: Option<u32>,
        aud: &str,
        nonce: &str,
        now: UnixTime,
    ) -> String {
        let header = format!(r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"{ISSUER_KID}"}}"#);
        let status_claim = if let Some(idx) = status_idx {
            format!(r#","status":{{"status_list":{{"idx":{idx},"uri":"{STATUS_LIST_URI}"}}}}"#)
        } else {
            String::new()
        };
        let payload = format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"cnf":{{"jwk":{}}}{status_claim}}}"#,
            BASE_TIME.as_seconds(),
            exp,
            self.holder_jwk.to_canonical_json()
        );
        let h_b64 = base64url::encode(header.as_bytes());
        let p_b64 = base64url::encode(payload.as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
        let sig = self
            .issuer_store
            .sign(&self.issuer_handle, &digest)
            .expect("sign");
        let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
        let prefix = format!("{issuer_jwt}~");

        gravital_id_credential::KbIssuer::create_presentation(
            &prefix,
            aud,
            nonce,
            now,
            &self.holder_store,
            &self.holder_handle,
        )
        .expect("kb-jwt")
    }
}

// Verifies: REQ-VER-001, REQ-SDK-008, REQ-PRIV-002, REQ-REL-004, INV-01, INV-04, INV-05
#[test]
fn offline_sans_io_verification_produces_all_four_states_without_network() {
    let fixture = OfflineTestFixture::new(42);
    let bundle = fixture.trust_bundle();
    let mut state_store = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));
    let policy = VerificationPolicy::default();
    let req = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(BASE_TIME.as_seconds() + 300),
        OperationClass::Transaction,
    );

    // 1. STATE: Valid (fresh status snapshot, valid exp, valid KB-JWT)
    let valid_pres = fixture.sign_presentation(
        BASE_TIME.as_seconds() + 3600,
        Some(1),
        VERIFIER_AUDIENCE,
        NONCE,
        BASE_TIME,
    );
    let fresh_snap = build_status_snapshot(2, &[0u32; 8], STATUS_LIST_URI, BASE_TIME);
    let res_valid = VerifierPipeline::verify(
        &valid_pres,
        Some(&req),
        &bundle,
        Some(&fresh_snap),
        &mut state_store,
        &policy,
        BASE_TIME,
        None,
    );
    assert_eq!(
        res_valid.status(),
        VerificationStatus::Valid,
        "Offline verification with fresh bundle and status must be Valid (REQ-VER-001)"
    );
    assert!(res_valid.is_valid());
    assert_ne!(res_valid.status(), VerificationStatus::Invalid);
    assert_eq!(res_valid.checks().len(), 11);
    for check in res_valid.checks() {
        assert_eq!(
            check.status,
            CheckStatus::Passed,
            "All checks must pass for Valid: {}",
            check.kind.as_str()
        );
    }
    assert!(res_valid.status_age_seconds().is_some());

    // 2. STATE: ValidWithStaleStatus (snapshot older than policy freshness for transaction)
    let stale_time = UnixTime::from_seconds(BASE_TIME.as_seconds() - 3_600); // 1 hour old (> 30 min transaction limit)
    let stale_snap = build_status_snapshot(2, &[0u32; 8], STATUS_LIST_URI, stale_time);
    let mut state_store2 = InMemoryStateStore::new(StateIntegrityKey::new([0x34; 32]));
    let res_stale = VerifierPipeline::verify(
        &valid_pres,
        Some(&req),
        &bundle,
        Some(&stale_snap),
        &mut state_store2,
        &policy,
        BASE_TIME,
        None,
    );
    assert_eq!(
        res_stale.status(),
        VerificationStatus::ValidWithStaleStatus,
        "Offline verification with stale status must degrade to ValidWithStaleStatus (REQ-REL-004)"
    );
    assert_eq!(
        res_stale.check(CheckKind::Status).unwrap().status,
        CheckStatus::Passed,
        "Status check passed cryptographically but snapshot was stale"
    );
    assert!(res_stale.status_age_seconds().unwrap() >= 3_600);

    // 3. STATE: Unverifiable (missing status snapshot when required by policy)
    let mut state_store3 = InMemoryStateStore::new(StateIntegrityKey::new([0x35; 32]));
    let res_unverifiable = VerifierPipeline::verify(
        &valid_pres,
        Some(&req),
        &bundle,
        None, // No snapshot provided offline
        &mut state_store3,
        &policy,
        BASE_TIME,
        None,
    );
    assert_eq!(
        res_unverifiable.status(),
        VerificationStatus::Unverifiable,
        "Offline verification missing required status snapshot must be Unverifiable (REQ-REL-004)"
    );
    assert_eq!(
        res_unverifiable.check(CheckKind::Status).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res_unverifiable
            .check(CheckKind::Status)
            .unwrap()
            .error_code,
        Some(ErrorCode::StatusIndexOutOfRange)
    );

    // 4. STATE: Invalid (expired credential, revoked status, or tampered signature)
    let expired_pres = fixture.sign_presentation(
        BASE_TIME.as_seconds() - 100, // Expired before BASE_TIME
        Some(1),
        VERIFIER_AUDIENCE,
        NONCE,
        BASE_TIME,
    );
    let mut state_store4 = InMemoryStateStore::new(StateIntegrityKey::new([0x36; 32]));
    let res_invalid = VerifierPipeline::verify(
        &expired_pres,
        Some(&req),
        &bundle,
        Some(&fresh_snap),
        &mut state_store4,
        &policy,
        BASE_TIME,
        None,
    );
    assert_eq!(
        res_invalid.status(),
        VerificationStatus::Invalid,
        "Offline verification with expired credential must be Invalid (INV-05)"
    );
    assert_eq!(
        res_invalid.check(CheckKind::Validity).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res_invalid.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::CredentialExpired)
    );
}

// Verifies: REQ-VER-009, INV-11
#[test]
fn determinism_identical_inputs_produce_identical_results() {
    let fixture = OfflineTestFixture::new(99);
    let bundle = fixture.trust_bundle();
    let snap = build_status_snapshot(2, &[0u32; 8], STATUS_LIST_URI, BASE_TIME);
    let policy = VerificationPolicy::default();
    let req = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(BASE_TIME.as_seconds() + 300),
        OperationClass::Default,
    );
    let pres = fixture.sign_presentation(
        BASE_TIME.as_seconds() + 3600,
        Some(0),
        VERIFIER_AUDIENCE,
        NONCE,
        BASE_TIME,
    );

    let mut store_a = InMemoryStateStore::new(StateIntegrityKey::new([0x42; 32]));
    let mut store_b = InMemoryStateStore::new(StateIntegrityKey::new([0x42; 32]));

    let res_a = VerifierPipeline::verify(
        &pres,
        Some(&req),
        &bundle,
        Some(&snap),
        &mut store_a,
        &policy,
        BASE_TIME,
        None,
    );

    let res_b = VerifierPipeline::verify(
        &pres,
        Some(&req),
        &bundle,
        Some(&snap),
        &mut store_b,
        &policy,
        BASE_TIME,
        None,
    );

    assert_eq!(res_a.status(), res_b.status());
    assert_eq!(res_a.status_age_seconds(), res_b.status_age_seconds());
    assert_eq!(res_a.checks().len(), res_b.checks().len());
    for (ca, cb) in res_a.checks().iter().zip(res_b.checks().iter()) {
        assert_eq!(ca.kind, cb.kind);
        assert_eq!(ca.status, cb.status);
        assert_eq!(ca.error_code, cb.error_code);
        assert_eq!(ca.message, cb.message);
    }
}

// Verifies: REQ-VER-009, REQ-VER-005, INV-11
proptest! {
    #[test]
    fn prop_verifier_determinism_across_arbitrary_time_and_nonces(
        seed in 1u64..10_000,
        offset_seconds in 0u64..1_800,
        nonce_suffix in 100u32..999,
    ) {
        let fixture = OfflineTestFixture::new(seed);
        let bundle = fixture.trust_bundle();
        let snap = build_status_snapshot(2, &[0u32; 8], STATUS_LIST_URI, BASE_TIME);
        let policy = VerificationPolicy::default();
        let nonce = format!("nonce-proptest-{nonce_suffix}");
        let now = UnixTime::from_seconds(BASE_TIME.as_seconds().saturating_add(offset_seconds));
        let req = VerificationRequest::new(
            &nonce,
            VERIFIER_AUDIENCE,
            UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
            OperationClass::Default,
        );
        let pres = fixture.sign_presentation(
            BASE_TIME.as_seconds().saturating_add(3600),
            Some(0),
            VERIFIER_AUDIENCE,
            &nonce,
            now,
        );

        let mut store_1 = InMemoryStateStore::new(StateIntegrityKey::new([0x55; 32]));
        let mut store_2 = InMemoryStateStore::new(StateIntegrityKey::new([0x55; 32]));

        let res1 = VerifierPipeline::verify(
            &pres,
            Some(&req),
            &bundle,
            Some(&snap),
            &mut store_1,
            &policy,
            now,
            None,
        );

        let res2 = VerifierPipeline::verify(
            &pres,
            Some(&req),
            &bundle,
            Some(&snap),
            &mut store_2,
            &policy,
            now,
            None,
        );

        prop_assert_eq!(res1.status(), res2.status());
        prop_assert_eq!(res1.status_age_seconds(), res2.status_age_seconds());
        prop_assert_eq!(res1.checks().len(), res2.checks().len());
        for (c1, c2) in res1.checks().iter().zip(res2.checks().iter()) {
            prop_assert_eq!(c1.kind, c2.kind);
            prop_assert_eq!(c1.status, c2.status);
            prop_assert_eq!(c1.error_code, c2.error_code);
            prop_assert_eq!(&c1.message, &c2.message);
        }
    }
}
