//! Pruebas integrales de ciclo de vida de claves, propósitos y almacenes seguros.
//!
//! Trazabilidad:
//! - **REQ-KEY-001:** Separación estricta por propósito.
//! - **REQ-KEY-004:** Trait `KeyStore` e implementación `SoftwareKeyStore`.
//! - **REQ-KEY-007:** Thumbprints RFC 7638 como identificadores de clave.
//! - **REQ-KEY-009:** Claves HPKE con propósito propio separado de firma.
//! - **REQ-KEY-010:** Normalización de firmas DER ↔ IEEE P1363.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::SHA256_OUTPUT_LEN;
use gravital_id_keys::purpose::{
    HolderBinding, HolderRecovery, HpkeKeyAgreement, IssuerSigning, StatusListSigning, TrustBundle,
    TrustRoot, VerifierRequest,
};
use gravital_id_keys::{
    normalize_signature_to_p1363, signature_to_der, KeyHandle, KeyPurpose, KeyStore,
    SoftwareKeyStore,
};
use gravital_id_testkit::SeededRng;
use gravital_id_types::ErrorCode;

fn setup_keystore(seed: u64) -> SoftwareKeyStore<SeededRng> {
    SoftwareKeyStore::new(SeededRng::new(seed))
}

// Verifies: REQ-KEY-001, REQ-KEY-004, REQ-KEY-007
#[test]
fn generates_keys_for_all_purposes_with_rfc7638_thumbprints() {
    let mut ks = setup_keystore(0x1234_5678);

    let k1: KeyHandle<HolderBinding> = ks.generate_key().expect("holder binding");
    let k2: KeyHandle<VerifierRequest> = ks.generate_key().expect("verifier request");
    let k3: KeyHandle<HolderRecovery> = ks.generate_key().expect("holder recovery");
    let k4: KeyHandle<IssuerSigning> = ks.generate_key().expect("issuer signing");
    let k5: KeyHandle<StatusListSigning> = ks.generate_key().expect("status list");
    let k6: KeyHandle<TrustRoot> = ks.generate_key().expect("trust root");
    let k7: KeyHandle<TrustBundle> = ks.generate_key().expect("trust bundle");
    let k8: KeyHandle<HpkeKeyAgreement> = ks.generate_key().expect("hpke agreement");

    assert_eq!(ks.key_count(), 8);
    assert_eq!(k1.purpose(), KeyPurpose::HolderBinding);
    assert_eq!(k2.purpose(), KeyPurpose::VerifierRequest);
    assert_eq!(k3.purpose(), KeyPurpose::HolderRecovery);
    assert_eq!(k4.purpose(), KeyPurpose::IssuerSigning);
    assert_eq!(k5.purpose(), KeyPurpose::StatusListSigning);
    assert_eq!(k6.purpose(), KeyPurpose::TrustRoot);
    assert_eq!(k7.purpose(), KeyPurpose::TrustBundle);
    assert_eq!(k8.purpose(), KeyPurpose::HpkeKeyAgreement);

    // Cada kid es un thumbprint SHA-256 base64url no vacío
    let pub1 = ks.public_key(&k1).expect("pub1");
    assert_eq!(pub1.kid(), Some(k1.id()));
    assert!(!k1.id().is_empty());
}

// Verifies: REQ-KEY-001, REQ-KEY-004
#[test]
fn sign_and_verify_round_trip() {
    let mut ks = setup_keystore(0xA1B2_C3D4);
    let key: KeyHandle<HolderBinding> = ks.generate_key().expect("generate key");
    let pubkey = ks.public_key(&key).expect("public key");

    let digest = [0x5Au8; SHA256_OUTPUT_LEN];
    let signature = ks.sign(&key, &digest).expect("sign digest");
    assert_eq!(signature.len(), 64);

    // La firma producida verifica contra la clave pública JWK
    assert!(gravital_id_crypto::verify_es256_digest_jwk(&pubkey, &digest, &signature).is_ok());

    // Determinismo RFC 6979
    let signature_repeat = ks.sign(&key, &digest).expect("sign repeat");
    assert_eq!(signature, signature_repeat);
}

// Verifies: REQ-KEY-009, REQ-KEY-001, REQ-KEY-004
#[test]
fn hpke_key_agreement_between_parties() {
    let mut ks_alice = setup_keystore(0xAAAA_1111);
    let mut ks_bob = setup_keystore(0xBBBB_2222);

    let alice_key: KeyHandle<HpkeKeyAgreement> = ks_alice.generate_key().expect("alice key");
    let bob_key: KeyHandle<HpkeKeyAgreement> = ks_bob.generate_key().expect("bob key");

    let alice_pub = ks_alice.public_key(&alice_key).expect("alice pub");
    let bob_pub = ks_bob.public_key(&bob_key).expect("bob pub");

    let secret_alice = ks_alice
        .agree_key(&alice_key, &bob_pub)
        .expect("alice agrees");
    let secret_bob = ks_bob.agree_key(&bob_key, &alice_pub).expect("bob agrees");

    // Ambos extremos deben llegar exactamente al mismo secreto acordado
    assert_eq!(secret_alice, secret_bob);
}

// Verifies: REQ-KEY-004
#[test]
fn delete_key_removes_from_keystore() {
    let mut ks = setup_keystore(0x9999_8888);
    let key: KeyHandle<HolderBinding> = ks.generate_key().expect("generate key");
    let kid = key.id().to_string();

    assert!(ks.contains_key(&kid));
    ks.delete_key(&key).expect("delete key");
    assert!(!ks.contains_key(&kid));

    // Operaciones posteriores con la clave eliminada deben fallar con KeyNotFound
    let err_pub = ks.public_key(&key).expect_err("should fail after delete");
    assert_eq!(err_pub.code, ErrorCode::KeyNotFound);

    let digest = [0u8; 32];
    let err_sign = ks
        .sign(&key, &digest)
        .expect_err("sign should fail after delete");
    assert_eq!(err_sign.code, ErrorCode::KeyNotFound);

    let err_del = ks.delete_key(&key).expect_err("delete twice should fail");
    assert_eq!(err_del.code, ErrorCode::KeyNotFound);
}

// Verifies: REQ-KEY-001, REQ-KEY-009
#[test]
fn runtime_defense_in_depth_rejects_cross_purpose_operations() {
    let mut ks = setup_keystore(0x5555_4444);

    let signing_kid = ks
        .generate_key_for_purpose(KeyPurpose::HolderBinding)
        .expect("signing key");
    let agreement_kid = ks
        .generate_key_for_purpose(KeyPurpose::HpkeKeyAgreement)
        .expect("hpke key");

    let digest = [0x42u8; 32];
    let dummy_jwk = ks.public_key_by_id(&signing_kid).expect("jwk");

    // Intentar firmar con clave HPKE a través de API de bajo nivel falla en tiempo de ejecución
    let err_sign_hpke = ks
        .sign_digest(&agreement_kid, &digest)
        .expect_err("cannot sign with hpke key");
    assert_eq!(err_sign_hpke.code, ErrorCode::InvalidKeyFormat);

    // Intentar acuerdo Diffie-Hellman con clave de firma a través de API de bajo nivel falla
    let err_agree_signing = ks
        .agree_key_by_id(&signing_kid, &dummy_jwk)
        .expect_err("cannot agree with signing key");
    assert_eq!(err_agree_signing.code, ErrorCode::InvalidKeyFormat);
}

// Verifies: REQ-KEY-010
#[test]
fn signature_normalization_p1363_and_der() {
    let mut ks = setup_keystore(0x7777_6666);
    let key: KeyHandle<HolderBinding> = ks.generate_key().expect("key");
    let digest = [0x33u8; 32];

    let p1363_sig = ks.sign(&key, &digest).expect("sign");
    assert_eq!(p1363_sig.len(), 64);

    // Normalización directa de P1363 a P1363
    let normalized = normalize_signature_to_p1363(&p1363_sig).expect("norm p1363");
    assert_eq!(normalized, p1363_sig);

    // Conversión a DER y normalización de vuelta a P1363
    let der_sig = signature_to_der(&p1363_sig).expect("to der");
    assert!(der_sig.starts_with(&[0x30]));

    let from_der = normalize_signature_to_p1363(&der_sig).expect("from der");
    assert_eq!(from_der, p1363_sig);

    // Verificación flexible de DER
    let pubkey = ks.public_key(&key).expect("pubkey");
    assert!(gravital_id_crypto::verify_es256_digest_jwk(&pubkey, &digest, &der_sig).is_ok());

    // Rechazo de firma corrupta o truncada
    assert_eq!(
        normalize_signature_to_p1363(&p1363_sig[..63])
            .expect_err("short")
            .code,
        ErrorCode::InvalidSignature
    );
    assert_eq!(
        normalize_signature_to_p1363(&[0x00; 64])
            .expect_err("zero scalar")
            .code,
        ErrorCode::InvalidSignature
    );
}
