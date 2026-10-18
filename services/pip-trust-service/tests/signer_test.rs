//! Pruebas unitarias de firmantes para pip-trust-service (F7.T04, REQ-TRUST-001, REQ-TRUST-008).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use gravital_id_crypto::secret::SecretKeyBytes;
use gravital_id_crypto::sign::verify_es256_jwk;
use gravital_id_testkit::SeededRng;
use pip_trust_service::signer::{
    build_protected_header, BundleSignerBackend, LocalDevSigner, MockKmsSigner,
};

#[test]
fn test_build_protected_header() {
    let header_b64 = build_protected_header("test-kid-123");
    let decoded = gravital_id_codec::base64url::decode(&header_b64).expect("valid base64url");
    let decoded_str = String::from_utf8(decoded).expect("valid utf-8");
    assert_eq!(decoded_str, r#"{"alg":"ES256","kid":"test-kid-123"}"#);
}

#[test]
fn test_local_dev_signer_generate_with_rng() {
    let rng = SeededRng::new(42);
    let signer = LocalDevSigner::generate_with_rng("op-1", "kid-op-1", &rng).expect("generate ok");

    assert_eq!(signer.operator_id(), "op-1");
    assert_eq!(signer.kid(), "kid-op-1");
    assert_eq!(signer.public_key().x().len(), 32);
    assert_eq!(signer.public_key().y().len(), 32);

    let message = "hello.signing.world";
    let sig = signer.sign_input(message).expect("signing succeeds");
    assert_eq!(sig.len(), 64);

    let verify_res = verify_es256_jwk(signer.public_key(), message.as_bytes(), &sig);
    assert!(
        verify_res.is_ok(),
        "Signature must verify cryptographically"
    );
}

#[test]
fn test_local_dev_signer_from_secret_key() {
    let raw_key = [7u8; 32];
    let secret = SecretKeyBytes::new(raw_key);
    let signer = LocalDevSigner::from_secret_key("op-2", "kid-op-2", &secret).expect("valid key");

    let payload_b64 = gravital_id_codec::base64url::encode(b"{\"test\":true}");
    let jws_sig = signer.sign_payload_b64(&payload_b64).expect("sign payload");

    assert_eq!(jws_sig.kid.as_deref(), Some("kid-op-2"));
    let signing_input = format!("{}.{}", jws_sig.protected_b64, payload_b64);
    let verify_res = verify_es256_jwk(
        signer.public_key(),
        signing_input.as_bytes(),
        &jws_sig.signature,
    );
    assert!(verify_res.is_ok());
}

#[test]
fn test_local_dev_signer_from_hex() {
    let hex_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let signer = LocalDevSigner::from_hex("op-hex", "kid-hex", hex_key).expect("hex ok");
    assert_eq!(signer.operator_id(), "op-hex");

    // Con prefijo 0x y espacios
    let hex_key_prefix = "  0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20  ";
    let signer2 =
        LocalDevSigner::from_hex("op-hex-2", "kid-hex-2", hex_key_prefix).expect("hex with 0x ok");
    assert_eq!(signer.public_key(), signer2.public_key());
}

#[test]
fn test_local_dev_signer_from_hex_errors() {
    // Caracter no hexadecimal
    assert!(LocalDevSigner::from_hex("op", "kid", "0102zz").is_err());

    // Longitud incorrecta (16 bytes en vez de 32)
    assert!(LocalDevSigner::from_hex("op", "kid", "0102030405060708090a0b0c0d0e0f10").is_err());
}

#[test]
fn test_mock_kms_signer() {
    let rng = SeededRng::new(99);
    let local = LocalDevSigner::generate_with_rng("op-kms", "kid-kms", &rng).unwrap();
    let kms_arn = "arn:aws:kms:us-east-1:123456789012:key/test-kms-key-id";
    let kms_signer = MockKmsSigner::new("op-kms", "kid-kms", kms_arn, local);

    assert_eq!(kms_signer.operator_id(), "op-kms");
    assert_eq!(kms_signer.kid(), "kid-kms");
    assert_eq!(kms_signer.kms_key_arn(), kms_arn);

    let input = "sign.me.kms";
    let sig = kms_signer.sign_input(input).expect("kms signing succeeds");
    assert!(verify_es256_jwk(kms_signer.public_key(), input.as_bytes(), &sig).is_ok());

    let payload = "dGVzdC1wYXlsb2Fk";
    let jws_sig = kms_signer
        .sign_payload_b64(payload)
        .expect("kms jws signing succeeds");
    assert_eq!(jws_sig.kid.as_deref(), Some("kid-kms"));
}
