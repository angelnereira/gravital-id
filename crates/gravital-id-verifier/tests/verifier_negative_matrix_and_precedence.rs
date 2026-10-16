#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Matriz negativa exhaustiva de las 11 etapas y tabla de verdad de precedencia (F4.T09).
//!
//! Trazabilidad:
//! - **REQ-MAINT-003:** Al menos un caso negativo por cada regla de rechazo del pipeline.
//! - **REQ-MAINT-005:** Cobertura de líneas $\ge 90\%$ en los crates críticos de verificación.
//! - **REQ-MAINT-006:** Aserciones estrictas por etapa y código de error contra mutantes de reglas de rechazo.
//! - **REQ-VER-010:** Precedencia estricta: `Invalid` > `Unverifiable` > `ValidWithStaleStatus` > `Valid`.
//! - **REQ-REL-004:** Degradación explícita a `Unverifiable` o `ValidWithStaleStatus` cuando falta
//!   sincronización, sin aceptar jamás datos inválidos.

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
use gravital_id_types::{ErrorCode, GidError, ProfileId, UnixTime};
use gravital_id_verifier::nonce::NonceCache;
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{
    IssuerSelection, OperationClass, VctSelection, VerificationPolicy,
};
use gravital_id_verifier::result::{CheckKind, CheckStatus, VerificationStatus};
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey, VerifierStateStore};

const NOW: UnixTime = UnixTime::from_seconds(1_770_000_000);
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";
const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const CUSTOM_VCT: &str = "https://credentials.gravital.io/vct/custom-v1";
const VERIFIER_AUDIENCE: &str = "https://verifier.example.com";
const NONCE: &str = "session-nonce-128bit-random-challenge";
const ISSUER_KID: &str = "key-2026-issuer-01";

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

fn build_trust_bundle_with_vcts(
    issuer_uri: &str,
    issuer_state: &str,
    vcts: Vec<&str>,
    keys: Vec<Value>,
) -> TrustBundle {
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
                    Value::Array(
                        vcts.into_iter()
                            .map(|s| Value::String(s.to_string()))
                            .collect(),
                    ),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(NOW.as_seconds().saturating_sub(86_400))),
                ),
                ("state".to_string(), Value::String(issuer_state.to_string())),
                ("keys".to_string(), Value::Array(keys)),
            ])]),
        ),
    ]);
    TrustBundle::from_payload(&payload).expect("trust bundle")
}

fn make_key_entry(kid: &str, jwk: &JwkEcP256, state: &str, since: u64) -> Value {
    let jwk_parsed = gravital_id_codec::json::parse(jwk.to_canonical_json().as_str()).expect("jwk");
    Value::Object(vec![
        ("kid".to_string(), Value::String(kid.to_string())),
        ("jwk".to_string(), jwk_parsed),
        ("state".to_string(), Value::String(state.to_string())),
        (
            "state_since".to_string(),
            Value::Number(Number::PosInt(since)),
        ),
    ])
}

struct SignedCustomPresentation {
    issuer_store: SoftwareKeyStore<SeededRng>,
    issuer_handle: gravital_id_keys::KeyHandle<IssuerSigning>,
    issuer_jwk: JwkEcP256,
    holder_store: SoftwareKeyStore<SeededRng>,
    holder_handle: gravital_id_keys::KeyHandle<HolderBinding>,
    holder_jwk: JwkEcP256,
    state_store: InMemoryStateStore,
}

impl SignedCustomPresentation {
    fn new(seed: u64) -> Self {
        let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(seed));
        let issuer_handle = issuer_store.generate_key::<IssuerSigning>().expect("iss");
        let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("jwk");

        let mut holder_store = SoftwareKeyStore::new(SeededRng::new(seed.saturating_add(50)));
        let holder_handle = holder_store.generate_key::<HolderBinding>().expect("hol");
        let holder_jwk = holder_store.public_key(&holder_handle).expect("jwk");

        let state_store = InMemoryStateStore::new(StateIntegrityKey::new([0x55; 32]));
        Self {
            issuer_store,
            issuer_handle,
            issuer_jwk,
            holder_store,
            holder_handle,
            holder_jwk,
            state_store,
        }
    }

    fn sign_raw_issuer_jwt(&self, header_json: &str, payload_json: &str) -> String {
        let h_b64 = base64url::encode(header_json.as_bytes());
        let p_b64 = base64url::encode(payload_json.as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
        let sig = self
            .issuer_store
            .sign(&self.issuer_handle, &digest)
            .expect("sign");
        format!("{signing_input}.{}", base64url::encode(&sig))
    }

    fn attach_kb_jwt(
        &self,
        prefix_with_tilde: &str,
        aud: &str,
        nonce: &str,
        iat: UnixTime,
    ) -> String {
        gravital_id_credential::KbIssuer::create_presentation(
            prefix_with_tilde,
            aud,
            nonce,
            iat,
            &self.holder_store,
            &self.holder_handle,
        )
        .expect("kb-jwt")
    }

    fn default_bundle(&self) -> TrustBundle {
        build_trust_bundle_with_vcts(
            ISSUER_URI,
            "active",
            vec![PERSONAL_VCT, CUSTOM_VCT],
            vec![make_key_entry(
                ISSUER_KID,
                &self.issuer_jwk,
                "active",
                NOW.as_seconds().saturating_sub(86_400),
            )],
        )
    }
}

// Verifies: REQ-MAINT-003, REQ-MAINT-005, REQ-MAINT-006, REQ-VER-011
#[test]
fn negative_matrix_stage_0_and_1_structure_rejections() {
    let mut env = SignedCustomPresentation::new(100);
    let bundle = env.default_bundle();
    let policy = VerificationPolicy::default();

    // 1. Malformed compact SD-JWT (no tilde separator)
    let res = VerifierPipeline::verify(
        "not-an-sd-jwt",
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::MalformedSdJwt)
    );

    // 2. Wrong typ header ("jwt" instead of "dc+sd-jwt")
    let bad_typ_jwt = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"jwt","kid":"key-2026-issuer-01"}"#,
        r#"{"iss":"https://issuer.cedula.example.gov"}"#,
    );
    let res = VerifierPipeline::verify(
        &format!("{bad_typ_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::MalformedSdJwt)
    );

    // 3. Disallowed alg header ("ES384" not in policy allowed_algorithms)
    let bad_alg_jwt = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES384","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        r#"{"iss":"https://issuer.cedula.example.gov"}"#,
    );
    let res = VerifierPipeline::verify(
        &format!("{bad_alg_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::UnsupportedAlgorithm)
    );
}

// Verifies: REQ-MAINT-003, REQ-MAINT-006, REQ-VER-004, INV-06
#[test]
fn negative_matrix_stage_2_and_3_issuer_and_key_resolution() {
    let mut env = SignedCustomPresentation::new(200);
    let bundle = env.default_bundle();

    // 1. Missing 'iss' claim -> Invalid (MissingRequiredClaim)
    let no_iss_jwt = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        r#"{"vct":"pip-personal-v1","iat":1770000000}"#,
    );
    let res = VerifierPipeline::verify(
        &format!("{no_iss_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default(),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::IssuerAuthorized).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 2. Issuer denied by policy Denylist -> Invalid (UntrustedIssuer)
    let deny_policy = VerificationPolicy::default()
        .with_issuers(IssuerSelection::DenyList(vec![ISSUER_URI.to_string()]));
    let valid_iss_jwt = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{}}}"#,
            NOW.as_seconds()
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{valid_iss_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &deny_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::IssuerAuthorized).unwrap().error_code,
        Some(ErrorCode::UntrustedIssuer)
    );

    // 3. Unknown kid in header -> Unverifiable (UntrustedIssuer) at KeyState
    let unknown_kid_jwt = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"unknown-kid-999"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{}}}"#,
            NOW.as_seconds()
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{unknown_kid_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default(),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Unverifiable);
    assert_eq!(
        res.check(CheckKind::KeyState).unwrap().error_code,
        Some(ErrorCode::UntrustedIssuer)
    );

    // 4. Header without kid resolves active key from bundle when present
    let no_kid_jwt = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{},"cnf":{{"jwk":{}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600,
            env.holder_jwk.to_canonical_json()
        ),
    );
    let no_status_policy = VerificationPolicy::default().with_require_status(false);
    let pres = env.attach_kb_jwt(&format!("{no_kid_jwt}~"), VERIFIER_AUDIENCE, NONCE, NOW);
    let req = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds() + 300),
        OperationClass::Default,
    );
    let res = VerifierPipeline::verify(
        &pres,
        Some(&req),
        &bundle,
        None,
        &mut env.state_store,
        &no_status_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Valid);
}

// Verifies: REQ-MAINT-003, REQ-MAINT-006, REQ-VER-003
#[test]
fn negative_matrix_stage_5_validity_and_stage_6_disclosures() {
    let mut env = SignedCustomPresentation::new(300);
    let bundle = env.default_bundle();
    let policy = VerificationPolicy::default()
        .with_require_status(false)
        .with_require_cnf(false);

    let header = r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#;

    // 1. Missing 'iat'
    let no_iat = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","exp":{}}}"#,
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{no_iat}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 2. Future 'iat' beyond clock skew
    let future_iat = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{}}}"#,
            NOW.as_seconds() + 10_000,
            NOW.as_seconds() + 20_000
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{future_iat}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::CredentialNotYetValid)
    );

    // 3. Future 'nbf' beyond clock skew
    let future_nbf = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"nbf":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 10_000,
            NOW.as_seconds() + 20_000
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{future_nbf}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::CredentialNotYetValid)
    );

    // 4. 'nbf' before 'iat'
    let nbf_before_iat = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"nbf":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() - 1_000,
            NOW.as_seconds() + 20_000
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{nbf_before_iat}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::MalformedSdJwt)
    );

    // 5. Expired 'exp' beyond clock skew
    let expired_exp = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{}}}"#,
            NOW.as_seconds() - 20_000,
            NOW.as_seconds() - 10_000
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{expired_exp}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::CredentialExpired)
    );

    // 6. 'exp' before 'iat'
    let exp_before_iat = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() - 10
        ),
    );
    let policy = policy.with_clock_skew_seconds(60).expect("skew");
    let res = VerifierPipeline::verify(
        &format!("{exp_before_iat}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::MalformedSdJwt)
    );

    // 7. Missing 'exp' when policy requires_exp() is true
    let missing_exp = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{}}}"#,
            NOW.as_seconds()
        ),
    );
    let exp_req_policy = policy.clone().with_require_exp(true);
    let res = VerifierPipeline::verify(
        &format!("{missing_exp}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &exp_req_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 8. Stage 6 (Disclosures): orphan unreferenced disclosure rejected fail-closed
    let orphan_disc = base64url::encode(r#"["MDEyMzQ1Njc4OWFiY2RlZg","extra","val"]"#.as_bytes());
    let res = VerifierPipeline::verify(
        &format!("{missing_exp}~{orphan_disc}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::MalformedSdJwt)
    );
}

// Verifies: REQ-MAINT-003, REQ-MAINT-006, REQ-CRED-004, REQ-PRES-002, REQ-CRED-007
#[test]
fn negative_matrix_stages_7_to_11_schema_kb_status_and_policy() {
    let mut env = SignedCustomPresentation::new(400);
    let bundle = env.default_bundle();
    let header = r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#;

    let base_policy = VerificationPolicy::default()
        .with_require_status(false)
        .with_require_cnf(false);

    // Stage 7a: Missing 'vct'
    let no_vct = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","iat":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{no_vct}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &base_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Schema).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // Stage 7b: Malformed 'vct' (whitespace/empty)
    let bad_vct = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"bad vct with spaces","iat":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{bad_vct}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &base_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Schema).unwrap().error_code,
        Some(ErrorCode::MalformedSdJwt)
    );

    // Stage 7c: VCT rejected by policy VctSelection::DenyList
    let vct_deny_policy = base_policy
        .clone()
        .with_vcts(VctSelection::DenyList(vec![CUSTOM_VCT.to_string()]));
    let custom_vct_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{custom_vct_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &vct_deny_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Schema).unwrap().error_code,
        Some(ErrorCode::SchemaValidationFailed)
    );

    // Stage 7d: VCT not in issuer's authorized vcts list in TrustBundle
    let unauth_vct_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"pip-financial-v1","iat":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{unauth_vct_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &base_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Schema).unwrap().error_code,
        Some(ErrorCode::UntrustedIssuer)
    );

    // Stage 7e: Disclosed claim violates profile schema (given_name as number instead of string in pip-personal-v1)
    let bad_schema_claim_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"given_name":12345}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{bad_schema_claim_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &base_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Schema).unwrap().error_code,
        Some(ErrorCode::SchemaValidationFailed)
    );

    // Stage 8a: Missing 'cnf' when requires_cnf is true
    let cnf_policy = base_policy.clone().with_require_cnf(true);
    let res = VerifierPipeline::verify(
        &format!("{custom_vct_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &cnf_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::KeyBinding).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // Stage 8b: Wrong audience in KB-JWT -> KeyBindingFailed
    let with_cnf_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{},"cnf":{{"jwk":{}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600,
            env.holder_jwk.to_canonical_json()
        ),
    );
    let wrong_aud_pres = env.attach_kb_jwt(
        &format!("{with_cnf_jwt}~"),
        "https://wrong-verifier.example.org",
        NONCE,
        NOW,
    );
    let req = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds() + 300),
        OperationClass::Default,
    );
    let res = VerifierPipeline::verify(
        &wrong_aud_pres,
        Some(&req),
        &bundle,
        None,
        &mut env.state_store,
        &cnf_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::KeyBinding).unwrap().error_code,
        Some(ErrorCode::KeyBindingFailed)
    );

    // Stage 10a: Missing 'status' when requires_status is true
    let status_req_policy = base_policy.clone().with_require_status(true);
    let res = VerifierPipeline::verify(
        &format!("{custom_vct_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &status_req_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // Stage 10b: Malformed status claim (missing status_list object)
    let bad_status_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{},"status":{{}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{bad_status_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &status_req_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::MalformedStatusList)
    );

    // Stage 10c: Status bit is Suspended (2) -> Unverifiable (CredentialSuspended, REQ-REL-004)
    let status_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"status_list":{{"idx":3,"uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let mut vals = vec![0u32; 16];
    vals[3] = 2; // 2 = Suspended
    let snap = build_status_snapshot(2, &vals, STATUS_LIST_URI, NOW);
    let res = VerifierPipeline::verify(
        &format!("{status_jwt}~"),
        None,
        &bundle,
        Some(&snap),
        &mut env.state_store,
        &status_req_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Unverifiable);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::CredentialSuspended)
    );

    // Stage 11: Policy required profile not matched -> Invalid (SchemaValidationFailed)
    let profile_policy =
        base_policy.with_profiles(vec![ProfileId::parse("pip-financial-v1").expect("profile")]);
    let personal_valid_jwt = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{personal_valid_jwt}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &profile_policy,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Policy).unwrap().error_code,
        Some(ErrorCode::SchemaValidationFailed)
    );
}

struct FailingRememberNonceStore {
    inner: InMemoryStateStore,
}

impl VerifierStateStore for FailingRememberNonceStore {
    fn time_floor(&self) -> Result<Option<UnixTime>, GidError> {
        self.inner.time_floor()
    }
    fn raise_time_floor(&mut self, floor: UnixTime) -> Result<(), GidError> {
        self.inner.raise_time_floor(floor)
    }
    fn accepted_bundle(&self) -> Result<Option<gravital_id_trust::AcceptedBundleState>, GidError> {
        self.inner.accepted_bundle()
    }
    fn record_accepted_bundle(
        &mut self,
        state: gravital_id_trust::AcceptedBundleState,
    ) -> Result<(), GidError> {
        self.inner.record_accepted_bundle(state)
    }
    fn nonce_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError> {
        self.inner.nonce_seen(nonce, now)
    }
    fn remember_nonce(&mut self, _nonce: &str, _expires_at: UnixTime) -> Result<(), GidError> {
        Err(GidError::new(
            ErrorCode::StorageReadFailed,
            "simulated storage failure on remember_nonce",
        ))
    }
    fn integrity_check(&self) -> Result<(), GidError> {
        self.inner.integrity_check()
    }
    fn reset(&mut self) {
        self.inner.reset();
    }
}

// Verifies: REQ-VER-010, REQ-REL-004, INV-04, INV-05
#[test]
fn state_precedence_truth_table_invalid_over_unverifiable_over_stale_over_valid() {
    let mut env = SignedCustomPresentation::new(500);
    let bundle = env.default_bundle();
    let header = r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#;

    // Case 1: Invalid (expired exp) + Unverifiable (missing status snapshot) => Invalid
    let expired_with_status = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"status_list":{{"idx":1,"uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds() - 20_000,
            NOW.as_seconds() - 10_000
        ),
    );
    let pol = VerificationPolicy::default().with_require_cnf(false);
    let res = VerifierPipeline::verify(
        &format!("{expired_with_status}~"),
        None,
        &bundle,
        None, // missing snapshot -> Status is Indeterminate
        &mut env.state_store,
        &pol,
        NOW,
        None,
    );
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res.status(),
        VerificationStatus::Invalid,
        "Invalid must strictly dominate Unverifiable (REQ-VER-010)"
    );

    // Case 2: Invalid (policy profile mismatch) + ValidWithStaleStatus (stale snapshot) => Invalid
    let valid_with_status = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"status_list":{{"idx":1,"uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let stale_time = UnixTime::from_seconds(NOW.as_seconds() - 9 * 86_400);
    let stale_snap = build_status_snapshot(2, &[0u32; 8], STATUS_LIST_URI, stale_time);
    let mismatch_pol = pol
        .clone()
        .with_profiles(vec![ProfileId::parse("pip-financial-v1").expect("profile")]);
    let res = VerifierPipeline::verify(
        &format!("{valid_with_status}~"),
        None,
        &bundle,
        Some(&stale_snap),
        &mut env.state_store,
        &mismatch_pol,
        NOW,
        None,
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Passed
    );
    assert_eq!(
        res.check(CheckKind::Policy).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.status(),
        VerificationStatus::Invalid,
        "Invalid must strictly dominate ValidWithStaleStatus (REQ-VER-010)"
    );

    // Case 3: Unverifiable (remember_nonce storage error) + ValidWithStaleStatus (stale snapshot) => Unverifiable
    let mut failing_store = FailingRememberNonceStore {
        inner: InMemoryStateStore::new(StateIntegrityKey::new([0x77; 32])),
    };
    let req = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds() + 300),
        OperationClass::Default,
    );
    let with_cnf_and_status = env.sign_raw_issuer_jwt(
        header,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":1,"uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600,
            env.holder_jwk.to_canonical_json()
        ),
    );
    let pres = env.attach_kb_jwt(
        &format!("{with_cnf_and_status}~"),
        VERIFIER_AUDIENCE,
        NONCE,
        NOW,
    );
    let res = VerifierPipeline::verify(
        &pres,
        Some(&req),
        &bundle,
        Some(&stale_snap),
        &mut failing_store,
        &VerificationPolicy::default(),
        NOW,
        None,
    );
    assert_eq!(
        res.check(CheckKind::Nonce).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res.status(),
        VerificationStatus::Unverifiable,
        "Unverifiable must strictly dominate ValidWithStaleStatus (REQ-VER-010)"
    );

    // Verify canonical string representations of VerificationStatus and CheckKind
    assert_eq!(VerificationStatus::Valid.as_str(), "Valid");
    assert_eq!(
        VerificationStatus::ValidWithStaleStatus.as_str(),
        "ValidWithStaleStatus"
    );
    assert_eq!(VerificationStatus::Unverifiable.as_str(), "Unverifiable");
    assert_eq!(VerificationStatus::Invalid.as_str(), "Invalid");
    assert_eq!(CheckKind::Structure.as_str(), "structure");
    assert_eq!(CheckKind::IssuerAuthorized.as_str(), "issuer_authorized");
    assert_eq!(CheckKind::KeyState.as_str(), "key_state");
    assert_eq!(CheckKind::Signature.as_str(), "signature");
    assert_eq!(CheckKind::Validity.as_str(), "validity");
    assert_eq!(CheckKind::Disclosures.as_str(), "disclosures");
    assert_eq!(CheckKind::Schema.as_str(), "schema");
    assert_eq!(CheckKind::KeyBinding.as_str(), "key_binding");
    assert_eq!(CheckKind::Nonce.as_str(), "nonce");
    assert_eq!(CheckKind::Status.as_str(), "status");
    assert_eq!(CheckKind::Policy.as_str(), "policy");
}

struct FailingCurrentTimeFloorStore {
    inner: InMemoryStateStore,
    code: ErrorCode,
}

impl VerifierStateStore for FailingCurrentTimeFloorStore {
    fn time_floor(&self) -> Result<Option<UnixTime>, GidError> {
        Err(GidError::new(self.code, "simulated time floor failure"))
    }
    fn raise_time_floor(&mut self, _floor: UnixTime) -> Result<(), GidError> {
        Err(GidError::new(
            self.code,
            "simulated raise time floor failure",
        ))
    }
    fn accepted_bundle(&self) -> Result<Option<gravital_id_trust::AcceptedBundleState>, GidError> {
        self.inner.accepted_bundle()
    }
    fn record_accepted_bundle(
        &mut self,
        state: gravital_id_trust::AcceptedBundleState,
    ) -> Result<(), GidError> {
        self.inner.record_accepted_bundle(state)
    }
    fn nonce_seen(&self, nonce: &str, now: UnixTime) -> Result<bool, GidError> {
        self.inner.nonce_seen(nonce, now)
    }
    fn remember_nonce(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError> {
        self.inner.remember_nonce(nonce, expires_at)
    }
    fn integrity_check(&self) -> Result<(), GidError> {
        self.inner.integrity_check()
    }
    fn reset(&mut self) {
        self.inner.reset();
    }
}

struct FailingNonceSeenStore {
    inner: InMemoryStateStore,
}

impl VerifierStateStore for FailingNonceSeenStore {
    fn time_floor(&self) -> Result<Option<UnixTime>, GidError> {
        self.inner.time_floor()
    }
    fn raise_time_floor(&mut self, floor: UnixTime) -> Result<(), GidError> {
        self.inner.raise_time_floor(floor)
    }
    fn accepted_bundle(&self) -> Result<Option<gravital_id_trust::AcceptedBundleState>, GidError> {
        self.inner.accepted_bundle()
    }
    fn record_accepted_bundle(
        &mut self,
        state: gravital_id_trust::AcceptedBundleState,
    ) -> Result<(), GidError> {
        self.inner.record_accepted_bundle(state)
    }
    fn nonce_seen(&self, _nonce: &str, _now: UnixTime) -> Result<bool, GidError> {
        Err(GidError::new(
            ErrorCode::StorageReadFailed,
            "simulated nonce_seen failure",
        ))
    }
    fn remember_nonce(&mut self, nonce: &str, expires_at: UnixTime) -> Result<(), GidError> {
        self.inner.remember_nonce(nonce, expires_at)
    }
    fn integrity_check(&self) -> Result<(), GidError> {
        self.inner.integrity_check()
    }
    fn reset(&mut self) {
        self.inner.reset();
    }
}

// Verifies: REQ-MAINT-003, REQ-MAINT-005, REQ-MAINT-006, REQ-VER-002, REQ-VER-004
#[test]
fn negative_matrix_pipeline_exhaustive_branches() {
    let mut env = SignedCustomPresentation::new(777);
    let bundle = env.default_bundle();
    let valid_payload = format!(
        r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{}}}"#,
        NOW.as_seconds(),
        NOW.as_seconds() + 3600
    );
    let valid_cred = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &valid_payload,
    );

    // 1. Corrupted verifier state store
    let mut corrupted_store = FailingCurrentTimeFloorStore {
        inner: InMemoryStateStore::new(StateIntegrityKey::new([0x88; 32])),
        code: ErrorCode::VerifierStateCorrupted,
    };
    let res = VerifierPipeline::verify(
        &format!("{valid_cred}~"),
        None,
        &bundle,
        None,
        &mut corrupted_store,
        &VerificationPolicy::default()
            .with_require_cnf(false)
            .with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Unverifiable);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::VerifierStateCorrupted)
    );

    // 2. Generic storage error in state store
    let mut storage_err_store = FailingCurrentTimeFloorStore {
        inner: InMemoryStateStore::new(StateIntegrityKey::new([0x88; 32])),
        code: ErrorCode::StorageReadFailed,
    };
    let res = VerifierPipeline::verify(
        &format!("{valid_cred}~"),
        None,
        &bundle,
        None,
        &mut storage_err_store,
        &VerificationPolicy::default()
            .with_require_cnf(false)
            .with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Unverifiable);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::StorageReadFailed)
    );

    // 3. Missing alg header in SD-JWT VC
    let missing_alg = env.sign_raw_issuer_jwt(
        r#"{"typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &valid_payload,
    );
    let res = VerifierPipeline::verify(
        &format!("{missing_alg}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default()
            .with_require_cnf(false)
            .with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::UnsupportedAlgorithm)
    );

    // 4. Algorithm in credential not allowed by policy allowed_algorithms
    let policy_without_es256 = VerificationPolicy::default()
        .with_allowed_algorithms(vec!["Ed25519".to_string()])
        .unwrap()
        .with_require_cnf(false)
        .with_require_status(false);
    let res = VerifierPipeline::verify(
        &format!("{valid_cred}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy_without_es256,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Structure).unwrap().error_code,
        Some(ErrorCode::UnsupportedAlgorithm)
    );

    // 4b. Profile schema lookup for unrecognized custom vct
    let custom_vct_payload = format!(
        r#"{{"iss":"{ISSUER_URI}","vct":"{CUSTOM_VCT}","iat":{},"exp":{}}}"#,
        NOW.as_seconds(),
        NOW.as_seconds() + 3600
    );
    let custom_vct_cred = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &custom_vct_payload,
    );
    let custom_vct_bundle = build_trust_bundle_with_vcts(
        ISSUER_URI,
        "active",
        vec![CUSTOM_VCT],
        vec![make_key_entry(
            ISSUER_KID,
            &env.issuer_jwk,
            "active",
            NOW.as_seconds() - 100,
        )],
    );
    let policy_with_profile = VerificationPolicy::default()
        .with_require_cnf(false)
        .with_require_status(false)
        .with_profiles(vec![ProfileId::parse("pip-personal-v1").unwrap()]);
    let res = VerifierPipeline::verify(
        &format!("{custom_vct_cred}~"),
        None,
        &custom_vct_bundle,
        None,
        &mut env.state_store,
        &policy_with_profile,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Policy).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Policy).unwrap().error_code,
        Some(ErrorCode::SchemaValidationFailed)
    );

    // 5. Credential with no kid header and issuer has only a suspended key (fallback to first key)
    let cred_no_kid =
        env.sign_raw_issuer_jwt(r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#, &valid_payload);
    let key_entry = make_key_entry(
        "key-suspended-only",
        &env.issuer_jwk,
        "suspended",
        NOW.as_seconds() - 100,
    );
    let suspended_bundle =
        build_trust_bundle_with_vcts(ISSUER_URI, "active", vec![PERSONAL_VCT], vec![key_entry]);
    let res = VerifierPipeline::verify(
        &format!("{cred_no_kid}~"),
        None,
        &suspended_bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default()
            .with_require_cnf(false)
            .with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Unverifiable);
    assert_eq!(
        res.check(CheckKind::KeyState).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res.check(CheckKind::KeyState).unwrap().error_code,
        Some(ErrorCode::IssuerSuspended)
    );

    // 6. KeyBinding: Missing cnf claim when request expected
    let req = VerificationRequest::new(
        NONCE,
        VERIFIER_AUDIENCE,
        UnixTime::from_seconds(NOW.as_seconds() + 300),
        OperationClass::Default,
    );
    let pres_no_cnf = env.attach_kb_jwt(&format!("{valid_cred}~"), VERIFIER_AUDIENCE, NONCE, NOW);
    let res = VerifierPipeline::verify(
        &pres_no_cnf,
        Some(&req),
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default().with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::KeyBinding).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::KeyBinding).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 7. KeyBinding: Malformed cnf claim (not an object)
    let malformed_cnf = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"cnf":"not_object"}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let pres_malformed_cnf =
        env.attach_kb_jwt(&format!("{malformed_cnf}~"), VERIFIER_AUDIENCE, NONCE, NOW);
    let res = VerifierPipeline::verify(
        &pres_malformed_cnf,
        Some(&req),
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default().with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::KeyBinding).unwrap().status,
        CheckStatus::Failed
    );

    // 8. KeyBinding: Malformed cnf claim (cnf.jwk is not an object)
    let malformed_cnf_jwk = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"cnf":{{"jwk":123}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let pres_malformed_cnf_jwk = env.attach_kb_jwt(
        &format!("{malformed_cnf_jwk}~"),
        VERIFIER_AUDIENCE,
        NONCE,
        NOW,
    );
    let res = VerifierPipeline::verify(
        &pres_malformed_cnf_jwk,
        Some(&req),
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default().with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::KeyBinding).unwrap().status,
        CheckStatus::Failed
    );

    // 9. Nonce check failure: nonce_seen returns error
    let with_cnf = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"cnf":{{"jwk":{}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600,
            env.holder_jwk.to_canonical_json()
        ),
    );
    let pres_valid_kb = env.attach_kb_jwt(&format!("{with_cnf}~"), VERIFIER_AUDIENCE, NONCE, NOW);
    let mut failing_nonce_seen_store = FailingNonceSeenStore {
        inner: InMemoryStateStore::new(StateIntegrityKey::new([0x88; 32])),
    };
    let res = VerifierPipeline::verify(
        &pres_valid_kb,
        Some(&req),
        &bundle,
        None,
        &mut failing_nonce_seen_store,
        &VerificationPolicy::default().with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Unverifiable);
    assert_eq!(
        res.check(CheckKind::Nonce).unwrap().status,
        CheckStatus::Indeterminate
    );
    assert_eq!(
        res.check(CheckKind::Nonce).unwrap().error_code,
        Some(ErrorCode::StorageReadFailed)
    );

    // 10. Status check: Status list lookup error (index out of range in snapshot)
    let out_of_range_status_cred = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"status_list":{{"idx":9999,"uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let small_snap = build_status_snapshot(1, &[0u32; 1], STATUS_LIST_URI, NOW);
    let res = VerifierPipeline::verify(
        &format!("{out_of_range_status_cred}~"),
        None,
        &bundle,
        Some(&small_snap),
        &mut env.state_store,
        &VerificationPolicy::default().with_require_cnf(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::StatusIndexOutOfRange)
    );

    // 11. Status check: Missing idx or uri in status_list
    let missing_idx = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"status_list":{{"uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{missing_idx}~"),
        None,
        &bundle,
        Some(&small_snap),
        &mut env.state_store,
        &VerificationPolicy::default().with_require_cnf(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::MalformedStatusList)
    );

    // 12. Status check: status claim missing status_list object
    let missing_status_list_obj = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"other":123}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{missing_status_list_obj}~"),
        None,
        &bundle,
        Some(&small_snap),
        &mut env.state_store,
        &VerificationPolicy::default().with_require_cnf(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::MalformedStatusList)
    );

    // 13. Status check: Policy requires status claim, but credential has none
    let res = VerifierPipeline::verify(
        &format!("{valid_cred}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default()
            .with_require_cnf(false)
            .with_require_status(true),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 14. Policy profile match succeeds when credential vct matches policy profile
    let policy_with_personal = VerificationPolicy::default()
        .with_require_cnf(false)
        .with_require_status(false)
        .with_profiles(vec![ProfileId::parse("pip-personal-v1").unwrap()]);
    let res = VerifierPipeline::verify(
        &format!("{valid_cred}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy_with_personal,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Valid);
    assert_eq!(
        res.check(CheckKind::Policy).unwrap().status,
        CheckStatus::Passed
    );
}

// Verifies: REQ-MAINT-003, REQ-MAINT-005, REQ-VER-004
#[test]
fn negative_matrix_pipeline_remaining_branches() {
    let mut env = SignedCustomPresentation::new(888);
    let bundle = env.default_bundle();

    // 1. iat claim is not a positive integer (e.g. string)
    let cred_string_iat = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":"invalid_timestamp","exp":{}}}"#,
            NOW.as_seconds() + 3600
        ),
    );
    let res = VerifierPipeline::verify(
        &format!("{cred_string_iat}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &VerificationPolicy::default()
            .with_require_cnf(false)
            .with_require_status(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 2. exp claim is required by policy, but is a string instead of number
    let cred_string_exp = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":"not_a_number"}}"#,
            NOW.as_seconds()
        ),
    );
    let policy_req_exp = VerificationPolicy::default()
        .with_require_cnf(false)
        .with_require_status(false)
        .with_require_exp(true);
    let res = VerifierPipeline::verify(
        &format!("{cred_string_exp}~"),
        None,
        &bundle,
        None,
        &mut env.state_store,
        &policy_req_exp,
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Validity).unwrap().error_code,
        Some(ErrorCode::MissingRequiredClaim)
    );

    // 3. idx in status_list is a string instead of positive integer
    let cred_string_idx = env.sign_raw_issuer_jwt(
        r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#,
        &format!(
            r#"{{"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}","iat":{},"exp":{},"status":{{"status_list":{{"idx":"not_an_int","uri":"{STATUS_LIST_URI}"}}}}}}"#,
            NOW.as_seconds(),
            NOW.as_seconds() + 3600
        ),
    );
    let snap = build_status_snapshot(1, &[0u32; 1], STATUS_LIST_URI, NOW);
    let res = VerifierPipeline::verify(
        &format!("{cred_string_idx}~"),
        None,
        &bundle,
        Some(&snap),
        &mut env.state_store,
        &VerificationPolicy::default().with_require_cnf(false),
        NOW,
        None,
    );
    assert_eq!(res.status(), VerificationStatus::Invalid);
    assert_eq!(
        res.check(CheckKind::Status).unwrap().status,
        CheckStatus::Failed
    );
    assert_eq!(
        res.check(CheckKind::Status).unwrap().error_code,
        Some(ErrorCode::MalformedStatusList)
    );
}

// Verifies: REQ-MAINT-005, REQ-VER-005, REQ-VER-006, REQ-VER-007
#[test]
fn policy_and_state_store_coverage() {
    // 1. VerificationPolicy getters and constructors
    let pol = VerificationPolicy::new();
    assert_eq!(pol.clock_skew_seconds(), 60);
    assert_eq!(pol.max_clock_skew_seconds(), 300);
    assert!(pol.status_freshness(OperationClass::Default).admits(100));
    assert!(pol.validate().is_ok());

    // 2. VerificationPolicy validation errors
    let skew_err = VerificationPolicy::default().with_clock_skew_seconds(500);
    assert!(skew_err.is_err());
    assert_eq!(skew_err.unwrap_err().code, ErrorCode::MalformedSdJwt);

    let hard_skew_err = VerificationPolicy::default().with_max_clock_skew_seconds(400);
    assert!(hard_skew_err.is_err());
    assert_eq!(hard_skew_err.unwrap_err().code, ErrorCode::MalformedSdJwt);

    let max_lower_than_skew_err = VerificationPolicy::default().with_max_clock_skew_seconds(10);
    assert!(max_lower_than_skew_err.is_err());
    assert_eq!(
        max_lower_than_skew_err.unwrap_err().code,
        ErrorCode::MalformedSdJwt
    );

    let empty_alg = VerificationPolicy::default().with_allowed_algorithms(vec![]);
    assert!(empty_alg.is_err());
    assert_eq!(empty_alg.unwrap_err().code, ErrorCode::UnsupportedAlgorithm);

    let none_alg = VerificationPolicy::default().with_allowed_algorithms(vec!["none".to_string()]);
    assert!(none_alg.is_err());
    assert_eq!(none_alg.unwrap_err().code, ErrorCode::UnsupportedAlgorithm);

    // 3. InMemoryStateStore NonceCache forwarding and getters
    let mut store = InMemoryStateStore::new(StateIntegrityKey::new([0x99; 32]));
    assert_eq!(store.nonce_cache().len(), 0);
    assert!(store.nonce_cache_mut().capacity() > 0);

    let exp = UnixTime::from_seconds(NOW.as_seconds() + 100);
    assert!(store.check_and_consume_nonce("nonce-1", exp, NOW).unwrap());
    assert!(!store.check_and_consume_nonce("nonce-1", exp, NOW).unwrap());

    // Trait NonceCache implementation on InMemoryStateStore
    assert!(NonceCache::is_seen(&store, "nonce-1", NOW).unwrap());
    assert!(!NonceCache::is_seen(&store, "nonce-2", NOW).unwrap());
    assert!(NonceCache::remember(&mut store, "nonce-2", exp).is_ok());
    assert!(!NonceCache::check_and_consume(&mut store, "nonce-2", exp, NOW).unwrap());
    assert_eq!(NonceCache::len(&store), 2);
    assert!(NonceCache::capacity(&store) >= 2);
    NonceCache::purge_expired(&mut store, UnixTime::from_seconds(NOW.as_seconds() + 200));
    assert_eq!(NonceCache::len(&store), 0);
    NonceCache::clear(&mut store);

    // 4. Accepted bundle state in InMemoryStateStore
    let bundle_state = gravital_id_trust::AcceptedBundleState {
        bundle_epoch: 2,
        bundle_version: 5,
    };
    assert!(store.record_accepted_bundle(bundle_state).is_ok());
    assert_eq!(store.accepted_bundle().unwrap().unwrap().bundle_epoch, 2);
    assert!(store.integrity_check().is_ok());
}
