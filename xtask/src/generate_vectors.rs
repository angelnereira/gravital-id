//! Generador del corpus de vectores de conformidad SD-JWT VC (F3.T09).
//!
//! Escribe los vectores en `conformance/vectors/sd-jwt-vc/` usando datos sintéticos y
//! claves deterministas (`SeededRng`). Los vectores publicados son **inmutables**
//! (INV-12): este generador solo se ejecuta para crear vectores nuevos; nunca para
//! modificar los existentes.
//!
//! Uso: `cargo xtask gen-conformance-vectors` (requiere `--write` para escribir).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use gravital_id_codec::base64url;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::{
    to_canonical_json, IssuedSdJwt, JwsHeader, KbIssuer, SdIssuer, SdObjectBuilder,
};
use gravital_id_crypto::{sha256, JwkEcP256};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, ProfileId, UnixTime};

use crate::conformance::VECTOR_DIR;

/// Instante de referencia de los vectores (2026-10-13 00:00:00 UTC).
const NOW: u64 = 1_791_849_600;

/// Perfiles usados por los vectores.
const PERSONAL_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const FINANCIAL_VCT: &str = "https://credentials.gravital.io/vct/financial/kyc-v1";
const ENTERPRISE_VCT: &str = "https://credentials.gravital.io/vct/enterprise/employee-v1";
const ISSUER_URI: &str = "https://issuer.cedula.example.gov";
const STATUS_LIST_URI: &str = "https://status.cedula.example.gov/lists/2026-10";

/// Conjunto determinista de claves del corpus (públicas; las privadas nunca se publican).
struct Keys {
    store: SoftwareKeyStore<SeededRng>,
}

impl Keys {
    fn new(seed: u64) -> Self {
        Self {
            store: SoftwareKeyStore::new(SeededRng::new(seed)),
        }
    }

    fn issuer(&mut self) -> gravital_id_keys::KeyHandle<IssuerSigning> {
        self.store
            .generate_key::<IssuerSigning>()
            .expect("issuer key")
    }

    fn issuer_jwk(&self, handle: &gravital_id_keys::KeyHandle<IssuerSigning>) -> JwkEcP256 {
        self.store.public_key(handle).expect("issuer jwk")
    }

    fn holder(&mut self) -> gravital_id_keys::KeyHandle<HolderBinding> {
        self.store
            .generate_key::<HolderBinding>()
            .expect("holder key")
    }

    fn holder_jwk(&self, handle: &gravital_id_keys::KeyHandle<HolderBinding>) -> JwkEcP256 {
        self.store.public_key(handle).expect("holder jwk")
    }
}

fn obj(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn s(value: &str) -> Value {
    Value::String(value.to_string())
}

fn n(value: u64) -> Value {
    Value::Number(Number::PosInt(value))
}

fn b(value: bool) -> Value {
    Value::Bool(value)
}

fn strs(values: &[&str]) -> Value {
    Value::Array(values.iter().map(|v| s(v)).collect())
}

/// Valor JSON de una JWK pública.
fn jwk_value(jwk: &JwkEcP256) -> Value {
    let json = jwk.to_canonical_json();
    gravital_id_codec::json::parse(json.as_str()).expect("jwk json")
}

/// Firma un payload arbitrario con la clave del emisor (para vectores negativos).
fn craft(
    keys: &Keys,
    issuer_handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    payload_json: &str,
) -> String {
    let header = r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#;
    let signing_input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload_json.as_bytes())
    );
    let digest = sha256(signing_input.as_bytes());
    let signature = keys.store.sign(issuer_handle, &digest).expect("sign");
    format!("{signing_input}.{}~", base64url::encode(&signature))
}

/// Firma un payload con cabecera `alg: none` (vector negativo de algoritmo prohibido).
fn craft_alg_none(payload_json: &str) -> String {
    let header = r#"{"alg":"none","typ":"dc+sd-jwt"}"#;
    format!(
        "{}.{}.~",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload_json.as_bytes())
    )
}

/// Descripción de un vector antes de serializarlo.
pub(crate) struct VectorSpec {
    name: String,
    description: String,
    verifies: Vec<String>,
    kind: String,
    sd_jwt: String,
    issuer_jwk: Option<JwkEcP256>,
    holder_jwk: Option<JwkEcP256>,
    aud: Option<String>,
    nonce: Option<String>,
    now: u64,
    policy: Value,
    expected: Value,
    expected_predicates: Option<Value>,
}

impl VectorSpec {
    pub(crate) fn valid(name: &str, description: &str, verifies: &[&str], sd_jwt: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            verifies: verifies.iter().map(|v| v.to_string()).collect(),
            kind: "credential".to_string(),
            sd_jwt: sd_jwt.to_string(),
            issuer_jwk: None,
            holder_jwk: None,
            aud: None,
            nonce: None,
            now: NOW,
            policy: Value::Object(Vec::new()),
            expected: obj(vec![("result", s("valid"))]),
            expected_predicates: None,
        }
    }

    pub(crate) fn invalid(
        name: &str,
        description: &str,
        verifies: &[&str],
        sd_jwt: &str,
        code: ErrorCode,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            verifies: verifies.iter().map(|v| v.to_string()).collect(),
            kind: "credential".to_string(),
            sd_jwt: sd_jwt.to_string(),
            issuer_jwk: None,
            holder_jwk: None,
            aud: None,
            nonce: None,
            now: NOW,
            policy: Value::Object(Vec::new()),
            expected: obj(vec![
                ("result", s("invalid")),
                ("error_code", s(code.code_str())),
            ]),
            expected_predicates: None,
        }
    }

    pub(crate) fn with_issuer_jwk(mut self, jwk: JwkEcP256) -> Self {
        self.issuer_jwk = Some(jwk);
        self
    }

    pub(crate) fn with_policy(mut self, policy: Value) -> Self {
        self.policy = policy;
        self
    }

    pub(crate) fn with_expected(mut self, expected: Value) -> Self {
        self.expected = expected;
        self
    }

    pub(crate) fn with_expected_predicates(mut self, predicates: Vec<(&str, bool)>) -> Self {
        let entries: Vec<(String, Value)> = predicates
            .into_iter()
            .map(|(name, value)| (name.to_string(), b(value)))
            .collect();
        self.expected_predicates = Some(Value::Object(entries));
        self
    }

    pub(crate) fn presentation(mut self) -> Self {
        self.kind = "presentation".to_string();
        self
    }

    pub(crate) fn with_holder(mut self, jwk: JwkEcP256, aud: &str, nonce: &str) -> Self {
        self.holder_jwk = Some(jwk);
        self.aud = Some(aud.to_string());
        self.nonce = Some(nonce.to_string());
        self
    }

    fn to_value(&self) -> Value {
        let mut entries = vec![
            ("name", s(&self.name)),
            ("description", s(&self.description)),
            (
                "verifies",
                Value::Array(self.verifies.iter().map(|v| s(v)).collect()),
            ),
            ("kind", s(&self.kind)),
            ("sd_jwt", s(&self.sd_jwt)),
        ];
        if let Some(jwk) = &self.issuer_jwk {
            entries.push(("issuer_jwk", jwk_value(jwk)));
        }
        if let Some(jwk) = &self.holder_jwk {
            entries.push(("holder_jwk", jwk_value(jwk)));
        }
        if let Some(aud) = &self.aud {
            entries.push(("aud", s(aud)));
        }
        if let Some(nonce) = &self.nonce {
            entries.push(("nonce", s(nonce)));
        }
        entries.push(("now", n(self.now)));
        entries.push(("policy", self.policy.clone()));
        entries.push(("expected", self.expected.clone()));
        if let Some(predicates) = &self.expected_predicates {
            entries.push(("expected_predicates", predicates.clone()));
        }
        obj(entries)
    }
}

/// Política por defecto de los vectores positivos.
fn default_policy(profile: Option<&str>) -> Value {
    let mut entries = vec![
        ("require_status", b(true)),
        ("require_exp", b(false)),
        ("require_cnf", b(false)),
        ("clock_skew_seconds", n(60)),
        ("allowed_algorithms", strs(&["ES256"])),
    ];
    if let Some(profile) = profile {
        entries.push(("profile", s(profile)));
    }
    obj(entries)
}

/// Emite una credencial del perfil personal con los predicados ya precomputados.
fn issue_personal_credential(
    keys: &Keys,
    issuer_handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    holder: Option<&gravital_id_keys::KeyHandle<HolderBinding>>,
    status_idx: u64,
) -> gravital_id_issuer::IssuedCredential {
    let profile = ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile");
    let schema = gravital_id_credential::ProfileSchema::lookup(&profile).expect("schema");
    let rng_emit = SeededRng::new(9_001);
    let mut request = gravital_id_issuer::CredentialRequest::new(
        ISSUER_URI,
        profile,
        UnixTime::from_seconds(NOW),
    )
    .expect("request")
    .attribute("given_name", s("Ana"))
    .expect("attribute")
    .attribute("family_name", s("Perez"))
    .expect("attribute")
    .attribute("birth_date", s("2000-04-12"))
    .expect("attribute")
    .status(gravital_id_issuer::StatusAllocation::new(status_idx, STATUS_LIST_URI).expect("status"))
    .decoys(2);
    if let Some(handle) = holder {
        request = request.holder_key(keys.holder_jwk(handle));
    }
    let _ = schema;
    gravital_id_issuer::Issuer::issue(&request, &keys.store, issuer_handle, None, &rng_emit)
        .expect("issue")
}

fn issue_profile(
    keys: &Keys,
    issuer_handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    profile_id: &str,
    attributes: Vec<(&str, Value)>,
    status_idx: u64,
) -> gravital_id_issuer::IssuedCredential {
    let profile = ProfileId::parse(profile_id).expect("profile");
    let rng_emit = SeededRng::new(9_002);
    let mut request = gravital_id_issuer::CredentialRequest::new(
        ISSUER_URI,
        profile,
        UnixTime::from_seconds(NOW),
    )
    .expect("request")
    .status(
        gravital_id_issuer::StatusAllocation::new(status_idx, STATUS_LIST_URI).expect("status"),
    );
    for (name, value) in attributes {
        request = request.attribute(name, value).expect("attribute");
    }
    gravital_id_issuer::Issuer::issue(&request, &keys.store, issuer_handle, None, &rng_emit)
        .expect("issue")
}

/// Construye una credencial con la API de bajo nivel, sin validar el esquema del perfil.
///
/// Se usa para los vectores negativos que deben violar el esquema a propósito: si se
/// emitiera con `Issuer::issue`, la validación impediría crear el vector.
fn craft_profile_credential(
    keys: &Keys,
    issuer_handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    vct: &str,
    attributes: Vec<(&str, Value)>,
    status_idx: u64,
) -> IssuedSdJwt {
    let mut builder = SdObjectBuilder::new()
        .add_plain_claim("iss", s(ISSUER_URI))
        .add_plain_claim("vct", s(vct))
        .add_plain_claim("iat", n(NOW))
        .add_plain_claim(
            "status",
            obj(vec![(
                "status_list",
                obj(vec![("idx", n(status_idx)), ("uri", s(STATUS_LIST_URI))]),
            )]),
        );
    for (name, value) in attributes {
        builder = builder.add_sd_claim(name, value);
    }
    SdIssuer::issue_signed(
        builder,
        &keys.store,
        issuer_handle,
        JwsHeader::default(),
        &SeededRng::new(9_005),
    )
    .expect("issue crafted credential")
}

pub fn build_vectors() -> Vec<VectorSpec> {
    let mut keys = Keys::new(4_242);
    let issuer_handle = keys.issuer();
    let issuer_jwk = keys.issuer_jwk(&issuer_handle);
    let holder_handle = keys.holder();
    let holder_jwk = keys.holder_jwk(&holder_handle);

    let mut vectors = Vec::new();

    // --- Positivos ---
    let personal = issue_personal_credential(&keys, &issuer_handle, None, 7);
    vectors.push(
        VectorSpec::valid(
            "sd-jwt-vc-personal-nominal",
            "Credencial SD-JWT VC del perfil personal con predicado precomputado y referencia de estado",
            &["REQ-CRED-001", "REQ-CRED-004", "REQ-CRED-005", "REQ-CRED-007", "REQ-CRED-008"],
            personal.compact(),
        )
        .with_issuer_jwk(issuer_jwk.clone())
        .with_policy(default_policy(Some(ProfileId::PERSONAL_V1)))
        .with_expected(obj(vec![
            ("result", s("valid")),
            ("iss", s(ISSUER_URI)),
            ("vct", s(PERSONAL_VCT)),
            ("iat", n(NOW)),
            ("cnf", b(false)),
            ("status", b(true)),
        ])),
    );

    // Presentación mínima con KB-JWT: solo el predicado de mayoría de edad.
    let predicate_disc = personal
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("age_over_18"))
        .expect("age_over_18 disclosure");
    let presentation_prefix = format!("{}~{}~", personal.jwt(), predicate_disc.encoded());
    let nonce = "conformance-nonce-0123456789abcdef";
    let presentation = KbIssuer::create_presentation(
        &presentation_prefix,
        "https://verifier.example.com",
        nonce,
        UnixTime::from_seconds(NOW),
        &keys.store,
        &holder_handle,
    )
    .expect("presentation");

    let presentation_vector = VectorSpec::valid(
        "sd-jwt-vc-presentation-minimized",
        "Presentación con KB-JWT que divulga únicamente el predicado age_over_18",
        &["REQ-CRED-001", "REQ-CRED-005", "REQ-PRES-002"],
        &presentation,
    )
    .with_issuer_jwk(issuer_jwk.clone())
    .with_policy(default_policy(Some(ProfileId::PERSONAL_V1)))
    .with_expected(obj(vec![
        ("result", s("valid")),
        ("iss", s(ISSUER_URI)),
        ("vct", s(PERSONAL_VCT)),
        ("iat", n(NOW)),
        ("cnf", b(false)),
        ("status", b(true)),
    ]))
    .presentation()
    .with_holder(holder_jwk.clone(), "https://verifier.example.com", nonce)
    .with_expected_predicates(vec![("age_over_18", true)]);
    vectors.push(presentation_vector);

    let financial = issue_profile(
        &keys,
        &issuer_handle,
        ProfileId::FINANCIAL_V1,
        vec![
            ("legal_name", s("Ana Perez")),
            ("tax_id", s("8-123-456")),
            ("kyc_tier", s("tier2")),
            ("aml_cleared", b(true)),
            ("country_of_residence", s("PAN")),
        ],
        21,
    );
    vectors.push(
        VectorSpec::valid(
            "sd-jwt-vc-financial-nominal",
            "Credencial SD-JWT VC del perfil financiero con enum e país ISO 3166-1 alfa-3",
            &["REQ-CRED-001", "REQ-CRED-004", "REQ-CRED-007"],
            financial.compact(),
        )
        .with_issuer_jwk(issuer_jwk.clone())
        .with_policy(default_policy(Some(ProfileId::FINANCIAL_V1)))
        .with_expected(obj(vec![
            ("result", s("valid")),
            ("iss", s(ISSUER_URI)),
            ("vct", s(FINANCIAL_VCT)),
            ("iat", n(NOW)),
            ("cnf", b(false)),
            ("status", b(true)),
        ])),
    );

    let enterprise = issue_profile(
        &keys,
        &issuer_handle,
        ProfileId::ENTERPRISE_V1,
        vec![
            ("employee_id", s("E-1001")),
            ("organization_id", s("ORG-9")),
            ("security_clearance", s("secret")),
            ("authorized_zones", strs(&["lobby", "datacenter"])),
        ],
        31,
    );
    vectors.push(
        VectorSpec::valid(
            "sd-jwt-vc-enterprise-nominal",
            "Credencial SD-JWT VC del perfil empresarial con array de zonas autorizadas",
            &["REQ-CRED-001", "REQ-CRED-004", "REQ-CRED-007"],
            enterprise.compact(),
        )
        .with_issuer_jwk(issuer_jwk.clone())
        .with_policy(default_policy(Some(ProfileId::ENTERPRISE_V1)))
        .with_expected(obj(vec![
            ("result", s("valid")),
            ("iss", s(ISSUER_URI)),
            ("vct", s(ENTERPRISE_VCT)),
            ("iat", n(NOW)),
            ("cnf", b(false)),
            ("status", b(true)),
        ])),
    );

    // Copias de un lote: misma credencial, claves e índices distintos.
    let mut batch_keys = Keys::new(4_243);
    let batch_issuer = batch_keys.issuer();
    let batch_issuer_jwk = batch_keys.issuer_jwk(&batch_issuer);
    let batch_holders: Vec<gravital_id_keys::KeyHandle<HolderBinding>> =
        (0..2).map(|_| batch_keys.holder()).collect();
    let batch_holder_jwks: Vec<JwkEcP256> = batch_holders
        .iter()
        .map(|handle| batch_keys.holder_jwk(handle))
        .collect();
    let plan =
        gravital_id_issuer::BatchPlan::new(batch_holder_jwks, vec![100, 101]).expect("batch plan");
    let request = gravital_id_issuer::CredentialRequest::new(
        ISSUER_URI,
        ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"),
        UnixTime::from_seconds(NOW),
    )
    .expect("request")
    .attribute("given_name", s("Ana"))
    .expect("attribute")
    .attribute("family_name", s("Perez"))
    .expect("attribute")
    .attribute("birth_date", s("2000-04-12"))
    .expect("attribute")
    .status(gravital_id_issuer::StatusAllocation::new(100, STATUS_LIST_URI).expect("status"));
    let batch = gravital_id_issuer::Issuer::issue_batch(
        &request,
        &plan,
        &batch_keys.store,
        &batch_issuer,
        None,
        &SeededRng::new(9_003),
    )
    .expect("batch");

    for (index, credential) in batch.iter().enumerate() {
        let expected_idx = 100u64.saturating_add(index as u64);
        vectors.push(
            VectorSpec::valid(
                &format!("sd-jwt-vc-batch-copy-{index}"),
                &format!(
                    "Copia {index} de un lote: clave de vinculación e índice de estado distintos (índice {expected_idx})"
                ),
                &["REQ-CRED-006", "REQ-CRED-002"],
                credential.compact(),
            )
            .with_issuer_jwk(batch_issuer_jwk.clone())
            .with_policy(default_policy(Some(ProfileId::PERSONAL_V1)))
            .with_expected(obj(vec![
                ("result", s("valid")),
                ("iss", s(ISSUER_URI)),
                ("vct", s(PERSONAL_VCT)),
                ("iat", n(NOW)),
                ("cnf", b(true)),
                ("status", b(true)),
            ])),
        );
    }

    // --- Negativos: una regla de rechazo por vector ---
    let status_claim = obj(vec![(
        "status_list",
        obj(vec![("idx", n(7)), ("uri", s(STATUS_LIST_URI))]),
    )]);

    // 1. alg: none
    let alg_none_payload = format!(
        r#"{{"iat":{NOW},"iss":"{ISSUER_URI}","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        to_canonical_json(&status_claim)
    );
    vectors.push(VectorSpec::invalid(
        "sd-jwt-vc-alg-none-rejected",
        "Rechazo de alg: none (prohibido incondicionalmente)",
        &["REQ-CRED-008"],
        &craft_alg_none(&alg_none_payload),
        ErrorCode::UnsupportedAlgorithm,
    ));

    // 2. Algoritmo fuera de la lista del perfil.
    let mut out_of_profile_policy = default_policy(Some(ProfileId::PERSONAL_V1));
    if let Value::Object(entries) = &mut out_of_profile_policy {
        for (key, value) in entries.iter_mut() {
            if key == "allowed_algorithms" {
                *value = strs(&["ES384"]);
            }
        }
    }
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-algorithm-outside-profile-rejected",
            "Rechazo de ES256 cuando el perfil solo autoriza ES384",
            &["REQ-CRED-008"],
            personal.compact(),
            ErrorCode::UnsupportedAlgorithm,
        )
        .with_issuer_jwk(issuer_jwk.clone())
        .with_policy(out_of_profile_policy),
    );

    // 3. typ distinto de dc+sd-jwt
    let wrong_typ = SdIssuer::issue_signed(
        SdObjectBuilder::new()
            .add_plain_claim("iss", s(ISSUER_URI))
            .add_plain_claim("vct", s(PERSONAL_VCT))
            .add_plain_claim("iat", n(NOW))
            .add_plain_claim("status", status_claim.clone()),
        &keys.store,
        &issuer_handle,
        JwsHeader {
            alg: "ES256".to_string(),
            typ: "vc+jwt".to_string(),
            kid: None,
        },
        &SeededRng::new(9_004),
    )
    .expect("issue wrong typ");
    vectors.push(VectorSpec::invalid(
        "sd-jwt-vc-wrong-typ-rejected",
        "Rechazo de typ distinto de dc+sd-jwt",
        &["REQ-CRED-001"],
        wrong_typ.to_compact_serialization(),
        ErrorCode::MalformedSdJwt,
    ));

    // 4. iss que no es URL HTTPS
    let non_https_payload = format!(
        r#"{{"iat":{NOW},"iss":"iss-panama-tribunal-electoral","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-iss-not-https-rejected",
            "Rechazo de iss que no es una URL HTTPS",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &non_https_payload),
            ErrorCode::MalformedSdJwt,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 5. Claim obligatorio ausente (vct)
    let missing_vct_payload = format!(
        r#"{{"iat":{NOW},"iss":"{ISSUER_URI}","status":{}}}"#,
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-missing-vct-rejected",
            "Rechazo por claim obligatorio vct ausente",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &missing_vct_payload),
            ErrorCode::MissingRequiredClaim,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 6. Sin referencia de estado
    let missing_status_payload =
        format!(r#"{{"iat":{NOW},"iss":"{ISSUER_URI}","vct":"{PERSONAL_VCT}"}}"#);
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-missing-status-rejected",
            "Rechazo por claim status ausente con la política por defecto",
            &["REQ-CRED-007"],
            &craft(&keys, &issuer_handle, &missing_status_payload),
            ErrorCode::MissingRequiredClaim,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 7. Credencial expirada
    let expired_payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{ISSUER_URI}","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        NOW.saturating_sub(1_000),
        NOW.saturating_sub(2_000),
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-expired-rejected",
            "Rechazo de credencial expirada más allá de la tolerancia de reloj",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &expired_payload),
            ErrorCode::CredentialExpired,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 8. Aún no vigente
    let not_yet_payload = format!(
        r#"{{"iat":{NOW},"iss":"{ISSUER_URI}","nbf":{},"status":{},"vct":"{PERSONAL_VCT}"}}"#,
        NOW.saturating_add(3_600),
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-not-yet-valid-rejected",
            "Rechazo de credencial con nbf en el futuro",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &not_yet_payload),
            ErrorCode::CredentialNotYetValid,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 9. status malformado (sin uri)
    let malformed_status_payload = format!(
        r#"{{"iat":{NOW},"iss":"{ISSUER_URI}","status":{{"status_list":{{"idx":7}}}},"vct":"{PERSONAL_VCT}"}}"#
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-malformed-status-rejected",
            "Rechazo de status_list sin uri",
            &["REQ-CRED-007"],
            &craft(&keys, &issuer_handle, &malformed_status_payload),
            ErrorCode::MalformedStatusList,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 10. cnf con material privado
    let cnf_private_payload = format!(
        r#"{{"cnf":{{"jwk":{{"crv":"P-256","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}}},"iat":{NOW},"iss":"{ISSUER_URI}","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-cnf-private-material-rejected",
            "Rechazo de cnf.jwk que contiene el parámetro privado d",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &cnf_private_payload),
            ErrorCode::InvalidKeyFormat,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 11. Divulgación duplicada
    let duplicate = format!("{}~{}~", personal.jwt(), predicate_disc.encoded());
    let duplicated = format!("{duplicate}{}~", predicate_disc.encoded());
    vectors.push(VectorSpec::invalid(
        "sd-jwt-vc-duplicate-disclosure-rejected",
        "Rechazo de la misma divulgación repetida en la presentación",
        &["REQ-CRED-009"],
        &duplicated,
        ErrorCode::MalformedSdJwt,
    ));

    // 12. Divulgación no referenciada
    let mut orphan_keys = Keys::new(4_244);
    let orphan_issuer = orphan_keys.issuer();
    let orphan_jwk = orphan_keys.issuer_jwk(&orphan_issuer);
    let orphan = issue_personal_credential(&orphan_keys, &orphan_issuer, None, 41);
    let orphan_disc = orphan
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("given_name"))
        .expect("given_name disclosure");
    let unreferenced = format!(
        "{}~{}~{}~{}~",
        personal.jwt(),
        predicate_disc.encoded(),
        orphan_disc.encoded(),
        predicate_disc.encoded()
    );
    let _ = orphan;
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-unreferenced-disclosure-rejected",
            "Rechazo de una divulgación válida pero no referenciada por ningún digest de la credencial",
            &["REQ-CRED-009"],
            &unreferenced,
            ErrorCode::MalformedSdJwt,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );
    let _ = orphan_jwk;

    // 13. Atributo fuera del esquema del perfil (país en minúsculas)
    // Emitida con la API de bajo nivel para poder violar el esquema a propósito.
    let bad_country = craft_profile_credential(
        &keys,
        &issuer_handle,
        PERSONAL_VCT,
        vec![
            ("given_name", s("Ana")),
            ("family_name", s("Perez")),
            ("age_over_18", b(true)),
            ("nationality", s("pan")),
        ],
        51,
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-attribute-outside-schema-rejected",
            "Rechazo de un atributo que no cumple el patrón del esquema del perfil",
            &["REQ-CRED-004"],
            bad_country.to_compact_serialization(),
            ErrorCode::SchemaValidationFailed,
        )
        .with_issuer_jwk(issuer_jwk.clone())
        .with_policy(default_policy(Some(ProfileId::PERSONAL_V1))),
    );

    // 14. vct no coincidente con el perfil de la política
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-vct-profile-mismatch-rejected",
            "Rechazo cuando el vct de la credencial no coincide con el perfil de la política",
            &["REQ-CRED-004"],
            personal.compact(),
            ErrorCode::SchemaValidationFailed,
        )
        .with_issuer_jwk(issuer_jwk.clone())
        .with_policy(default_policy(Some(ProfileId::FINANCIAL_V1))),
    );

    // 15. Firma manipulada
    let jwt = personal.jwt();
    let mut segments: Vec<&str> = jwt.split('.').collect();
    let signature = segments.get(2).copied().unwrap_or_default();
    let replacement = if signature.ends_with('A') { "B" } else { "A" };
    let tampered_signature = format!("{signature}{replacement}");
    if let Some(slot) = segments.get_mut(2) {
        *slot = tampered_signature.as_str();
    }
    let tampered = format!("{}~{}~", segments.join("."), predicate_disc.encoded());
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-tampered-signature-rejected",
            "Rechazo de una credencial con la firma manipulada",
            &["REQ-CRED-001"],
            &tampered,
            ErrorCode::InvalidSignature,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 16. _sd_alg no soportado
    let bad_sd_alg_payload = format!(
        r#"{{"_sd_alg":"sha-512","iat":{NOW},"iss":"{ISSUER_URI}","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-unsupported-sd-alg-rejected",
            "Rechazo de _sd_alg distinto de sha-256",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &bad_sd_alg_payload),
            ErrorCode::UnsupportedAlgorithm,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 17. Nombre de claim duplicado en el payload
    let duplicate_claim_payload = format!(
        r#"{{"iat":{NOW},"iat":{},"iss":"{ISSUER_URI}","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        NOW,
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-duplicate-claim-name-rejected",
            "Rechazo de un payload con el mismo claim repetido: el miembro duplicado se detecta al parsear el JSON",
            &["REQ-CRED-009"],
            &craft(&keys, &issuer_handle, &duplicate_claim_payload),
            ErrorCode::MalformedSdJwt,
        )
        .with_issuer_jwk(issuer_jwk.clone()),
    );

    // 18. Credencial sin reclamar vigencia (iat en el futuro)
    let future_iat_payload = format!(
        r#"{{"iat":{},"iss":"{ISSUER_URI}","status":{},"vct":"{PERSONAL_VCT}"}}"#,
        NOW.saturating_add(3_600),
        to_canonical_json(&status_claim)
    );
    vectors.push(
        VectorSpec::invalid(
            "sd-jwt-vc-future-iat-rejected",
            "Rechazo de iat en el futuro más allá de la tolerancia de reloj",
            &["REQ-CRED-001"],
            &craft(&keys, &issuer_handle, &future_iat_payload),
            ErrorCode::CredentialNotYetValid,
        )
        .with_issuer_jwk(issuer_jwk),
    );

    vectors
}

/// Escribe el corpus de vectores en disco.
pub fn generate_vectors(workspace_root: &Path) -> Result<()> {
    let dir = workspace_root.join(VECTOR_DIR);
    fs::create_dir_all(&dir).with_context(|| format!("no se pudo crear {}", dir.display()))?;

    let vectors = build_vectors();
    let mut written = 0usize;
    for vector in &vectors {
        let path = dir.join(format!("{}.json", vector.name));
        let json = to_canonical_json(&vector.to_value());
        fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("no se pudo escribir {}", path.display()))?;
        written = written.saturating_add(1);
    }

    println!("xtask: {written} vectores escritos en {}", dir.display());
    Ok(())
}
