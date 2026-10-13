#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración para Key Binding JWT (KB-JWT) (F3.T04, RFC 9901 §6).
//!
//! Trazabilidad:
//! - **REQ-PRES-002:** Toda presentación interactiva DEBE incluir KB-JWT con
//!   `nonce`, `aud`, `iat` y `sd_hash`.
//! - **REQ-CRED-001:** Formato normativo de Key Binding según RFC 9901 §6.
//! - **REQ-VER-003:** Fail-closed ante cualquier discrepancia o error en el KB-JWT.

extern crate alloc;

use alloc::format;
use alloc::string::ToString;

use gravital_id_codec::base64url;
use gravital_id_codec::json::Value;
use gravital_id_credential::{
    calculate_sd_hash, JwsHeader, KbIssuer, KbVerificationPolicy, ParsedSdJwt, SdIssuer,
    SdObjectBuilder,
};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime};

// // Verifies: REQ-PRES-002, REQ-CRED-001, REQ-VER-003
#[test]
fn complete_presentation_with_key_binding_nominal() {
    // 1. Emisor genera su clave y emite una credencial SD-JWT
    let rng_issuer = SeededRng::new(1001);
    let mut issuer_store = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let issuer_jwk = issuer_store.public_key(&issuer_handle).expect("issuer jwk");

    let rng_emit = SeededRng::new(1002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://authority.example.gov".to_string()),
        )
        .add_plain_claim(
            "vct",
            Value::String("urn:pip:credentials:driver-license".to_string()),
        )
        .add_sd_claim("license_number", Value::String("D-12345678".to_string()))
        .add_sd_claim("full_name", Value::String("Carlos Gomez".to_string()))
        .add_sd_claim("is_organ_donor", Value::Bool(true))
        .set_decoys(2);

    let issued = SdIssuer::issue_signed(
        builder,
        &issuer_store,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue sd-jwt");

    // 2. Titular genera su clave de vinculación (HolderBinding) en su KeyStore seguro
    let rng_holder = SeededRng::new(2001);
    let mut holder_store = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_store
        .generate_key::<HolderBinding>()
        .expect("holder binding key");
    let holder_jwk = holder_store.public_key(&holder_handle).expect("holder jwk");

    // 3. Verificador solicita presentación interactiva con nonce y aud
    let aud = "https://verifier.transport.gov";
    let nonce = "verifier_session_nonce_987654321";
    let now = UnixTime::from_seconds(1_700_500_000);

    // 4. Titular selecciona divulgar solo 'license_number' y 'full_name'
    let license_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("license_number"))
        .expect("license disclosure");
    let name_disc = issued
        .disclosures()
        .iter()
        .find(|d| d.claim_name() == Some("full_name"))
        .expect("name disclosure");

    let sd_jwt_presentation_prefix = format!(
        "{}~{}~{}~",
        issued.jwt(),
        license_disc.encoded(),
        name_disc.encoded()
    );

    // Titular genera y firma el KB-JWT con su clave
    let full_presentation = KbIssuer::create_presentation(
        &sd_jwt_presentation_prefix,
        aud,
        nonce,
        now,
        &holder_store,
        &holder_handle,
    )
    .expect("create presentation with kb");

    // 5. Verificador parsea y valida la presentación completa
    let parsed = ParsedSdJwt::parse(&full_presentation).expect("parse presentation");
    assert!(parsed.has_kb_jwt());
    assert_eq!(parsed.sd_jwt_prefix(), sd_jwt_presentation_prefix);

    // Verificación de firma del emisor
    parsed
        .verify_issuer_signature(&issuer_jwk)
        .expect("issuer signature is valid");

    // Verificación de vinculación de clave (KB-JWT) del titular
    let policy = KbVerificationPolicy::default();
    let kb_claims = parsed
        .verify_key_binding(aud, nonce, &holder_jwk, now, &policy)
        .expect("key binding must be valid");

    assert_eq!(kb_claims.aud, aud);
    assert_eq!(kb_claims.nonce, nonce);
    assert_eq!(kb_claims.iat, now);
    assert_eq!(
        kb_claims.sd_hash,
        calculate_sd_hash(&sd_jwt_presentation_prefix).expect("sd_hash")
    );

    // Claims reconstruidos
    let claims = parsed.reconstructed_claims();
    assert_eq!(
        claims.member("license_number"),
        Some(&Value::String("D-12345678".to_string()))
    );
    assert_eq!(
        claims.member("full_name"),
        Some(&Value::String("Carlos Gomez".to_string()))
    );
    // 'is_organ_donor' no fue divulgado
    assert_eq!(claims.member("is_organ_donor"), None);
}

// // Verifies: REQ-PRES-002, REQ-VER-003
#[test]
fn rejection_of_tampered_presentation_with_kb_jwt() {
    let rng = SeededRng::new(3001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let holder_handle = key_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = key_store.public_key(&holder_handle).expect("holder jwk");

    let rng_emit = SeededRng::new(3002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String("https://example.com".to_string()))
        .add_sd_claim("status", Value::String("active".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue");

    let prefix = format!("{}~{}~", issued.jwt(), issued.disclosures()[0].encoded());
    let aud = "https://verifier.example.com";
    let nonce = "nonce_123";
    let now = UnixTime::from_seconds(1_700_000_000);

    let presentation =
        KbIssuer::create_presentation(&prefix, aud, nonce, now, &key_store, &holder_handle)
            .expect("create");

    let parsed = ParsedSdJwt::parse(&presentation).expect("parse");

    // Intento de verificar con sd_jwt_prefix manipulado o con divulgación alterada
    // Simula ataque donde un intermediario inyecta una divulgación extra sin regenerar el KB-JWT
    let fake_salt = gravital_id_credential::Salt::generate(&rng_emit).expect("salt");
    let fake_disc = gravital_id_credential::Disclosure::new_object(
        fake_salt,
        "injected",
        Value::String("fake".to_string()),
    )
    .expect("fake disclosure");

    let tampered_presentation = format!(
        "{}~{}~{}~{}",
        issued.jwt(),
        issued.disclosures()[0].encoded(),
        fake_disc.encoded(),
        parsed.kb_jwt().expect("kb")
    );

    // Falla porque el hash del prefijo no coincide con el sd_hash firmado en el KB-JWT
    let tampered_parsed = ParsedSdJwt::parse(&tampered_presentation);
    // Si la divulgación falsa es huérfana, falla en parseo; si estuviera en _sd, falla en verify_key_binding
    match tampered_parsed {
        Err(e) => {
            assert_eq!(e.code, ErrorCode::MalformedSdJwt);
        }
        Ok(tampered_ok) => {
            let policy = KbVerificationPolicy::default();
            let err = tampered_ok
                .verify_key_binding(aud, nonce, &holder_jwk, now, &policy)
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::KeyBindingFailed);
        }
    }
}

// // Verifies: REQ-PRES-002, REQ-VER-003
#[test]
fn rejection_of_nonce_and_audience_mismatch() {
    let rng = SeededRng::new(4001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let holder_handle = key_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = key_store.public_key(&holder_handle).expect("holder jwk");

    let rng_emit = SeededRng::new(4002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String("https://example.com".to_string()))
        .add_sd_claim("data", Value::String("confidential".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue");

    let prefix = format!("{}~{}~", issued.jwt(), issued.disclosures()[0].encoded());
    let aud = "https://real-verifier.com";
    let nonce = "valid_nonce_abc";
    let now = UnixTime::from_seconds(1_700_000_000);

    let presentation =
        KbIssuer::create_presentation(&prefix, aud, nonce, now, &key_store, &holder_handle)
            .expect("create presentation");

    let parsed = ParsedSdJwt::parse(&presentation).expect("parse");
    let policy = KbVerificationPolicy::default();

    // 1. Nonce mismatch (ataque de repetición con otro desafío)
    let err_nonce = parsed
        .verify_key_binding(aud, "different_nonce_xyz", &holder_jwk, now, &policy)
        .unwrap_err();
    assert_eq!(err_nonce.code, ErrorCode::KeyBindingFailed);
    assert!(err_nonce.message.contains("nonce mismatch"));

    // 2. Audience mismatch (ataque de retransmisión a otro verificador)
    let err_aud = parsed
        .verify_key_binding(
            "https://attacker-verifier.com",
            nonce,
            &holder_jwk,
            now,
            &policy,
        )
        .unwrap_err();
    assert_eq!(err_aud.code, ErrorCode::KeyBindingFailed);
    assert!(err_aud.message.contains("aud mismatch"));
}

// // Verifies: REQ-PRES-002, REQ-VER-003
#[test]
fn rejection_of_wrong_holder_signature_on_kb_jwt() {
    let rng_a = SeededRng::new(5001);
    let mut store_a = SoftwareKeyStore::new(rng_a);
    let issuer_handle = store_a.generate_key::<IssuerSigning>().expect("issuer key");
    let holder_handle_a = store_a
        .generate_key::<HolderBinding>()
        .expect("holder a key");

    // Otro titular malicioso
    let rng_b = SeededRng::new(5002);
    let mut store_b = SoftwareKeyStore::new(rng_b);
    let holder_handle_b = store_b
        .generate_key::<HolderBinding>()
        .expect("holder b key");
    let holder_jwk_b = store_b.public_key(&holder_handle_b).expect("holder b jwk");

    let rng_emit = SeededRng::new(5003);
    let builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String("https://example.com".to_string()))
        .add_sd_claim("data", Value::String("value".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &store_a,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue");

    let prefix = format!("{}~{}~", issued.jwt(), issued.disclosures()[0].encoded());
    let aud = "https://verifier.com";
    let nonce = "nonce";
    let now = UnixTime::from_seconds(1_700_000_000);

    // El titular A firma el KB-JWT
    let presentation =
        KbIssuer::create_presentation(&prefix, aud, nonce, now, &store_a, &holder_handle_a)
            .expect("create");

    let parsed = ParsedSdJwt::parse(&presentation).expect("parse");
    let policy = KbVerificationPolicy::default();

    // Verificador comprueba contra la clave del titular B (mismatch de clave)
    let err = parsed
        .verify_key_binding(aud, nonce, &holder_jwk_b, now, &policy)
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::KeyBindingFailed);
    assert!(err.message.contains("signature verification failed"));
}

// // Verifies: REQ-VER-003
#[test]
fn rejection_when_key_binding_is_missing() {
    let rng = SeededRng::new(6001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let holder_handle = key_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = key_store.public_key(&holder_handle).expect("holder jwk");

    let rng_emit = SeededRng::new(6002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String("https://example.com".to_string()))
        .add_sd_claim("val", Value::String("data".to_string()));

    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue");

    // Presentación emitida SIN KB-JWT (termina en '~')
    let compact_no_kb = issued.to_compact_serialization();
    let parsed = ParsedSdJwt::parse(compact_no_kb).expect("parse");
    assert!(!parsed.has_kb_jwt());

    let policy = KbVerificationPolicy::default();
    let now = UnixTime::from_seconds(1_700_000_000);

    let err = parsed
        .verify_key_binding("aud", "nonce", &holder_jwk, now, &policy)
        .unwrap_err();

    assert_eq!(err.code, ErrorCode::KeyBindingFailed);
    assert!(err.message.contains("does not contain"));
}

// // Verifies: REQ-VER-003
#[test]
fn rejection_of_invalid_typ_or_alg_in_kb_jwt() {
    let rng = SeededRng::new(7001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let issuer_handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("issuer key");
    let holder_handle = key_store
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_jwk = key_store.public_key(&holder_handle).expect("holder jwk");

    let rng_emit = SeededRng::new(7002);
    let builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String("https://example.com".to_string()));
    let issued = SdIssuer::issue_signed(
        builder,
        &key_store,
        &issuer_handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue");
    let prefix = issued.to_compact_serialization();
    let sd_hash = calculate_sd_hash(prefix).expect("sd_hash");

    // 1. typ inválido ("JWT" en vez de "kb+jwt")
    let header_bad_typ = base64url::encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let payload = base64url::encode(
        format!(r#"{{"aud":"aud","iat":1700000000,"nonce":"nonce","sd_hash":"{sd_hash}"}}"#)
            .as_bytes(),
    );
    let sig = base64url::encode(&[0x01u8; 64]);
    let kb_jwt_bad_typ = format!("{header_bad_typ}.{payload}.{sig}");

    let presentation_bad_typ = format!("{prefix}{kb_jwt_bad_typ}");
    let parsed = ParsedSdJwt::parse(&presentation_bad_typ).expect("parse");

    let policy = KbVerificationPolicy::default();
    let now = UnixTime::from_seconds(1_700_000_000);

    let err_typ = parsed
        .verify_key_binding("aud", "nonce", &holder_jwk, now, &policy)
        .unwrap_err();
    assert_eq!(err_typ.code, ErrorCode::KeyBindingFailed);
    assert!(err_typ.message.contains("typ must be 'kb+jwt'"));

    // 2. alg inválido ("none")
    let header_bad_alg = base64url::encode(br#"{"alg":"none","typ":"kb+jwt"}"#);
    let kb_jwt_bad_alg = format!("{header_bad_alg}.{payload}.{sig}");
    let presentation_bad_alg = format!("{prefix}{kb_jwt_bad_alg}");
    let parsed_bad_alg = ParsedSdJwt::parse(&presentation_bad_alg).expect("parse");

    let err_alg = parsed_bad_alg
        .verify_key_binding("aud", "nonce", &holder_jwk, now, &policy)
        .unwrap_err();
    assert_eq!(err_alg.code, ErrorCode::UnsupportedAlgorithm);
}
