//! Pruebas de consultas DCQL, planes de divulgación y presentaciones con KB-JWT (F5.T08, REQ-PRES-001, REQ-PRES-002, REQ-PRES-003, REQ-PRIV-001).
//!
//! Trazabilidad:
//! - `REQ-PRES-001`: Consentimiento explícito y selección de atributos por el titular.
//! - `REQ-PRES-002`: Key Binding JWT (`KB-JWT`) con `nonce`, `aud`, `iat` y `sd_hash`.
//! - `REQ-PRES-003`: Consultas basadas en subconjunto de DCQL.
//! - `REQ-PRIV-001`: Divulgación selectiva compartiendo únicamente los atributos necesarios.
//! - `INV-03`: Ninguna clave privada cruza FFI; firma delegada a KeyStore.
//! - `INV-05`: Fail-closed ante cualquier error.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_codec::json::Value;
use gravital_id_credential::{KbJwtVerifier, KbVerificationPolicy, ParsedSdJwt, SdJwtVcBuilder};
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_holder::{CredentialQuery, DcqlQuery, HolderWallet, RequestedClaim};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_storage::InMemoryStorageBackend;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime, Vct};

const TEST_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";

fn setup_wallet_with_test_credential() -> (
    HolderWallet<InMemoryStorageBackend, SeededRng>,
    SoftwareKeyStore<SeededRng>,
    gravital_id_keys::KeyHandle<HolderBinding>,
    UnixTime,
) {
    let rng_holder = SeededRng::new(1001);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);

    let rng_issuer = SeededRng::new(2002);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let rng_emit = SeededRng::new(3003);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(TEST_VCT).expect("vct"), now)
        .expect("builder")
        .exp(UnixTime::from_seconds(
            now.as_seconds().saturating_add(3600),
        ))
        .cnf_jwk(holder_pub)
        .status_list(1, STATUS_LIST_URI)
        .expect("status")
        .add_sd_claim("given_name", Value::String("Angel".into()))
        .add_sd_claim("family_name", Value::String("Nereira".into()))
        .add_sd_claim("birth_date", Value::String("1995-05-15".into()))
        .add_sd_claim("nationality", Value::String("PA".into()))
        .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x33u8; 32]);
    let rng_wallet = SeededRng::new(4004);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    wallet
        .import_credential(
            issued.to_compact_serialization(),
            holder_handle.id(),
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("import");

    (wallet, holder_keystore, holder_handle, now)
}

// // Verifies: REQ-PRES-003 (Parseo de consultas DCQL según PROTOCOL.md §3.1)
#[test]
fn dcql_query_json_parsing_and_serialization() {
    let query_json = br#"{
        "credentials": [
            {
                "id": "cred1",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://credentials.gravital.io/vct/personal/id-v1"]
                },
                "claims": [
                    "given_name",
                    {"name": "family_name", "required": true},
                    {"name": "nationality", "required": false}
                ]
            }
        ]
    }"#;

    let dcql = DcqlQuery::from_json_bytes(query_json).expect("parse dcql");
    assert_eq!(dcql.credentials.len(), 1);

    let cred_q = &dcql.credentials[0];
    assert_eq!(cred_q.id, "cred1");
    assert_eq!(cred_q.vct_values.len(), 1);
    assert_eq!(cred_q.vct_values[0].as_str(), TEST_VCT);
    assert_eq!(cred_q.claims.len(), 3);

    assert_eq!(cred_q.claims[0].name, "given_name");
    assert!(cred_q.claims[0].required);

    assert_eq!(cred_q.claims[1].name, "family_name");
    assert!(cred_q.claims[1].required);

    assert_eq!(cred_q.claims[2].name, "nationality");
    assert!(!cred_q.claims[2].required);

    // Round-trip de serialización canónica
    let canonical = dcql.to_canonical_json();
    let reparsed = DcqlQuery::from_json_bytes(canonical.as_bytes()).expect("reparse");
    assert_eq!(dcql, reparsed);
}

// // Verifies: REQ-PRES-001, REQ-PRIV-001 (Plan de divulgación, selección y consentimiento del titular)
#[test]
fn disclosure_plan_selection_and_consent() {
    let (wallet, _, _, _) = setup_wallet_with_test_credential();

    let query = CredentialQuery::new(
        "auth_gate",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![
            RequestedClaim::required("given_name"),
            RequestedClaim::required("family_name"),
            RequestedClaim::optional("nationality"),
        ],
    )
    .expect("query");

    // 1. Preparar plan de divulgación
    let mut plan = wallet.prepare_disclosure_plan(&query, None).expect("plan");
    assert!(plan.is_satisfiable());
    assert_eq!(plan.query_id, "auth_gate");
    assert_eq!(plan.claims.len(), 3);

    // Por defecto, todos los claims solicitados están seleccionados
    assert_eq!(
        plan.disclosed_claim_names(),
        vec!["given_name", "family_name", "nationality"]
    );

    // 2. El titular desmarca un claim opcional (ej. nationality)
    plan.set_claim_disclosed("nationality", false)
        .expect("uncheck optional");
    assert_eq!(
        plan.disclosed_claim_names(),
        vec!["given_name", "family_name"]
    );
    assert!(plan.is_satisfiable());

    // 3. El titular intenta desmarcar un claim obligatorio: rechazo fail-closed (REQ-PRES-001)
    let err = plan
        .set_claim_disclosed("given_name", false)
        .expect_err("should reject omitting required claim");
    assert_eq!(err.code, ErrorCode::MissingRequiredClaim);

    // 4. Intentar desmarcar un claim inexistente en el plan
    let err_nf = plan
        .set_claim_disclosed("non_existent", false)
        .expect_err("not found");
    assert_eq!(err_nf.code, ErrorCode::MalformedMessage);
}

// // Verifies: REQ-PRES-001, REQ-PRES-002, REQ-PRIV-001 (Confirmación y presentación con KB-JWT)
#[test]
fn presentation_construction_and_verification_e2e() {
    let (mut wallet, holder_keystore, holder_handle, now) = setup_wallet_with_test_credential();

    let query = CredentialQuery::new(
        "gate_session_42",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![
            RequestedClaim::required("given_name"),
            RequestedClaim::optional("nationality"),
        ],
    )
    .expect("query");

    let mut plan = wallet.prepare_disclosure_plan(&query, None).expect("plan");

    // El titular decide no divulgar 'nationality' (divulgación selectiva estricta, REQ-PRIV-001)
    plan.set_claim_disclosed("nationality", false)
        .expect("uncheck");

    let aud = "https://verifier.org/gate-42";
    let nonce = "challenge_nonce_xyz_1234567890123456";

    // Confirmar presentación y firmar KB-JWT
    let presentation = wallet
        .confirm_presentation(&plan, aud, nonce, now, &holder_keystore, &holder_handle)
        .expect("confirm presentation");

    // Verificar estructura compacta del SD-JWT presentado: <issuer_jwt>~<d_selected>~<kb_jwt>
    assert!(presentation.contains('~'));
    assert!(presentation.contains('.'));

    let parsed = ParsedSdJwt::parse(&presentation).expect("parse presentation");
    assert!(parsed.has_kb_jwt());
    let kb_jwt = parsed.kb_jwt().expect("kb_jwt");

    // Verificar que SOLO el claim aprobado ('given_name') fue divulgado
    assert_eq!(parsed.disclosures().len(), 1);
    assert_eq!(parsed.disclosures()[0].claim_name(), Some("given_name"));
    assert_eq!(
        parsed.disclosures()[0].claim_value(),
        Some(&Value::String("Angel".into()))
    );

    // Verificar criptográficamente el KB-JWT contra la clave pública del titular (RFC 9901 §6, REQ-PRES-002)
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");
    let kb_policy = KbVerificationPolicy::default();
    let verified_kb = KbJwtVerifier::verify(
        kb_jwt,
        parsed.sd_jwt_prefix(),
        aud,
        nonce,
        &holder_pub,
        now,
        &kb_policy,
    )
    .expect("verify kb-jwt");

    assert_eq!(verified_kb.aud, aud);
    assert_eq!(verified_kb.nonce, nonce);
    assert_eq!(verified_kb.iat, now);
}

// // Verifies: INV-05, REQ-VER-003 (Rechazo de plan no satisfecho o claves cruzadas)
#[test]
fn presentation_rejects_unsatisfied_plan_or_mismatched_key() {
    let (mut wallet, holder_keystore, holder_handle, now) = setup_wallet_with_test_credential();

    // Consulta que exige un claim que la credencial NO tiene
    let query_unsatisfiable = CredentialQuery::new(
        "query_impossible",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![
            RequestedClaim::required("given_name"),
            RequestedClaim::required("driver_license_category"), // No existe en la credencial
        ],
    )
    .expect("query");

    let plan_unsatisfied = wallet
        .prepare_disclosure_plan(&query_unsatisfiable, None)
        .expect("plan");
    assert!(!plan_unsatisfied.is_satisfiable());
    assert_eq!(
        plan_unsatisfied.missing_required_claims,
        vec!["driver_license_category".to_string()]
    );

    // Intentar confirmar un plan insatisfecho falla fail-closed
    let err_unsatisfied = wallet
        .confirm_presentation(
            &plan_unsatisfied,
            "https://aud",
            "nonce1234567890123456",
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect_err("should reject unsatisfied plan");
    assert_eq!(err_unsatisfied.code, ErrorCode::MissingRequiredClaim);

    // Caso de clave cruzada: usar otro handle para firmar la presentación
    let rng_other = SeededRng::new(8888);
    let mut other_keystore = SoftwareKeyStore::new(rng_other);
    let other_handle = other_keystore
        .generate_key::<HolderBinding>()
        .expect("other key");

    let query_ok = CredentialQuery::new(
        "query_ok",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![RequestedClaim::required("given_name")],
    )
    .expect("query");
    let plan_ok = wallet
        .prepare_disclosure_plan(&query_ok, None)
        .expect("plan");

    let err_key = wallet
        .confirm_presentation(
            &plan_ok,
            "https://aud",
            "nonce1234567890123456",
            now,
            &other_keystore,
            &other_handle,
        )
        .expect_err("should reject wrong key handle");
    assert_eq!(err_key.code, ErrorCode::KeyBindingFailed);
}
