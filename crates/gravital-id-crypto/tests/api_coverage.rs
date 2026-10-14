//! Pruebas de cobertura exhaustiva para la API de `gravital-id-crypto`.
//!
//! // Verifies: REQ-SEC-002, REQ-SEC-003, REQ-KEY-007, REQ-KEY-010

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use gravital_id_crypto::aead::AEAD_KEY_LEN;
use gravital_id_crypto::ecdh::{agree, agree_ephemeral, ecdh_agree_keys};
use gravital_id_crypto::hpke::{
    hpke_open_base_p256_hkdf_sha256_chacha20poly1305,
    hpke_seal_base_p256_hkdf_sha256_chacha20poly1305, hpke_setup_recipient, ENC_LEN,
};
use gravital_id_crypto::jwk::{
    jwk_thumbprint_base64url, jwk_thumbprint_sha256, JwkEcP256, ES256_COORDINATE_LEN,
};
use gravital_id_crypto::secret::{
    AeadKeyBytes, HmacKeyBytes, SecretBytes, SecretKeyBytes, SecretVec, SharedSecret,
};
use gravital_id_crypto::sign::{
    der_to_p1363, generate_p256_secret_key, p1363_to_der, public_key_from_secret_key,
    sign_es256_digest, verify_es256_der, verify_es256_digest_jwk, verify_es256_jwk,
    ES256_PUBLIC_KEY_LEN,
};
use gravital_id_testkit::SeededRng;
use p256::elliptic_curve::rand_core::{CryptoRng, Error as RngError, RngCore};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use subtle::ConstantTimeEq;

struct TestRng(SeededRng);

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.0.fill(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

#[test]
fn test_ecdh_extended_coverage() {
    let rng = SeededRng::new(0x123);
    let sk_alice = generate_p256_secret_key(&rng).unwrap();
    let sk_bob = generate_p256_secret_key(&rng).unwrap();

    let pk_alice = public_key_from_secret_key(&sk_alice).unwrap();
    let pk_bob = public_key_from_secret_key(&sk_bob).unwrap();

    // ecdh_agree_keys
    let shared_ab = ecdh_agree_keys(&sk_alice, &pk_bob).unwrap();
    let shared_ba = ecdh_agree_keys(&sk_bob, &pk_alice).unwrap();
    assert_eq!(shared_ab.expose_secret(), shared_ba.expose_secret());

    // ecdh_agree_keys error with zero scalar (invalid P-256 secret)
    let invalid_sk = SecretKeyBytes::new([0u8; 32]);
    assert!(ecdh_agree_keys(&invalid_sk, &pk_bob).is_err());

    // agree_ephemeral
    let alice_p256_sk = p256::SecretKey::from_slice(sk_alice.expose_secret()).unwrap();
    let bob_p256_pk = pk_bob.to_public_key();
    let mut test_rng = TestRng(SeededRng::new(0x999));
    let ephemeral = p256::ecdh::EphemeralSecret::random(&mut test_rng);
    let ephemeral_pk = ephemeral.public_key();

    let ephemeral_shared = agree_ephemeral(ephemeral, &bob_p256_pk).unwrap();
    assert_eq!(ephemeral_shared.len(), 32);

    let agree_shared = agree(&alice_p256_sk, &ephemeral_pk).unwrap();
    assert_eq!(agree_shared.len(), 32);
}

#[test]
fn test_sign_extended_coverage() {
    let rng = SeededRng::new(0x456);
    let sk = generate_p256_secret_key(&rng).unwrap();
    let jwk = public_key_from_secret_key(&sk).unwrap();

    let msg = b"message to sign and verify across formats";
    let digest = gravital_id_crypto::sha::sha256(msg);

    // sign_es256_digest
    let p1363_sig = sign_es256_digest(&sk, &digest).unwrap();

    // verify_es256_digest_jwk
    assert!(verify_es256_digest_jwk(&jwk, &digest, &p1363_sig).is_ok());

    // verify_es256_jwk
    assert!(verify_es256_jwk(&jwk, msg, &p1363_sig).is_ok());

    // DER conversion & verify_es256_der
    let der_sig = p1363_to_der(&p1363_sig).unwrap();
    let p1363_reconverted = der_to_p1363(&der_sig).unwrap();
    assert_eq!(p1363_sig, p1363_reconverted);

    let p256_pk = p256::ecdsa::VerifyingKey::from(jwk.to_public_key());
    assert!(verify_es256_der(&p256_pk, msg, &der_sig).is_ok());

    // Error cases
    assert!(der_to_p1363(&[0x00, 0x01, 0x02]).is_err());
    assert!(verify_es256_der(&p256_pk, msg, &[0x00]).is_err());
    assert!(verify_es256_digest_jwk(&jwk, &digest, &[0xaa; 10]).is_err());

    let invalid_sk = SecretKeyBytes::new([0u8; 32]);
    assert!(sign_es256_digest(&invalid_sk, &digest).is_err());
    assert!(public_key_from_secret_key(&invalid_sk).is_err());
}

#[test]
fn test_jwk_methods_and_error_coverage() {
    let rng = SeededRng::new(0x789);
    let sk = generate_p256_secret_key(&rng).unwrap();
    let jwk = public_key_from_secret_key(&sk).unwrap();

    // Coordinates and SEC1 representation
    let x = *jwk.x();
    let y = *jwk.y();
    let from_coords = JwkEcP256::from_coordinates(x, y).unwrap();
    assert_eq!(jwk, from_coords);

    let sec1 = jwk.to_sec1_bytes();
    assert_eq!(sec1.len(), ES256_PUBLIC_KEY_LEN);
    assert_eq!(sec1[0], 0x04);
    let from_sec1 = JwkEcP256::from_sec1_bytes(&sec1).unwrap();
    assert_eq!(jwk, from_sec1);

    // SEC1 errors
    assert!(JwkEcP256::from_sec1_bytes(&[0x04; 64]).is_err());
    assert!(JwkEcP256::from_sec1_bytes(&[0x04; 66]).is_err());
    let mut bad_prefix = sec1;
    bad_prefix[0] = 0x02;
    assert!(JwkEcP256::from_sec1_bytes(&bad_prefix).is_err());

    // Coordinates not on curve
    let bad_x = [0xffu8; ES256_COORDINATE_LEN];
    let bad_y = [0xffu8; ES256_COORDINATE_LEN];
    assert!(JwkEcP256::from_coordinates(bad_x, bad_y).is_err());

    // Metadata setters and getters
    let enriched = jwk
        .clone()
        .with_kid("key-42")
        .with_key_use("sig")
        .with_alg("ES256");

    assert_eq!(enriched.kid(), Some("key-42"));
    assert_eq!(enriched.key_use(), Some("sig"));
    assert_eq!(enriched.alg(), Some("ES256"));
    assert_eq!(enriched.x_base64url(), jwk.x_base64url());
    assert_eq!(enriched.y_base64url(), jwk.y_base64url());

    let dbg = format!("{:?}", enriched);
    assert!(dbg.contains("key-42"));

    // Thumbprint functions
    let thumb_b64 = jwk_thumbprint_base64url(&enriched);
    let thumb_sha = jwk_thumbprint_sha256(&enriched);
    assert!(!thumb_b64.is_empty());
    assert_eq!(thumb_sha.len(), 32);

    // JSON parsing errors
    assert!(JwkEcP256::parse("not a json").is_err());
    assert!(JwkEcP256::parse("[]").is_err());
    assert!(JwkEcP256::parse(r#"{"kty":"RSA"}"#).is_err());
    assert!(JwkEcP256::parse(r#"{"kty":"EC","crv":"P-384"}"#).is_err());
    assert!(JwkEcP256::parse(r#"{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}"#).is_err());
    assert!(JwkEcP256::parse_bytes(b"invalid bytes").is_err());
}

#[test]
fn test_secret_hygiene_methods_coverage() {
    // SecretBytes methods
    let sb: SecretBytes<16> = SecretBytes::new([7u8; 16]);
    assert_eq!(sb.len(), 16);
    assert!(!sb.is_empty());
    assert!(SecretBytes::<16>::from_slice(&[7u8; 15]).is_err());
    assert!(SecretBytes::<16>::from_slice(&[7u8; 17]).is_err());
    let sb_from_slice = SecretBytes::<16>::from_slice(&[7u8; 16]).unwrap();
    assert_eq!(sb, sb_from_slice);

    // Empty SecretBytes
    let empty_sb: SecretBytes<0> = SecretBytes::new([]);
    assert_eq!(empty_sb.len(), 0);
    assert!(empty_sb.is_empty());

    // SecretVec methods
    let sv = SecretVec::from_slice(&[1, 2, 3, 4]);
    assert_eq!(sv.len(), 4);
    assert!(!sv.is_empty());
    let sv_empty = SecretVec::new(vec![]);
    assert_eq!(sv_empty.len(), 0);
    assert!(sv_empty.is_empty());

    let sv2 = SecretVec::from_slice(&[1, 2, 3]);
    assert!(!bool::from(sv.ct_eq(&sv2)));
    assert_ne!(sv, sv2);

    // SecretKeyBytes
    assert!(SecretKeyBytes::from_slice(&[1u8; 31]).is_err());
    let skb = SecretKeyBytes::from_slice(&[1u8; 32]).unwrap();
    assert_eq!(skb.expose_secret(), &[1u8; 32]);

    // AeadKeyBytes
    let akb = AeadKeyBytes::new([2u8; AEAD_KEY_LEN]);
    assert_eq!(akb.expose_secret(), &[2u8; AEAD_KEY_LEN]);
    assert_eq!(format!("{:?}", akb), "AeadKeyBytes([REDACTED])");
    assert_eq!(format!("{}", akb), "[REDACTED]");
    assert!(AeadKeyBytes::from_slice(&[2u8; 10]).is_err());
    let akb2 = AeadKeyBytes::from_slice(&[2u8; AEAD_KEY_LEN]).unwrap();
    assert_eq!(akb, akb2);

    // HmacKeyBytes
    let hkb = HmacKeyBytes::new(vec![3u8; 32]);
    assert_eq!(hkb.expose_secret(), &[3u8; 32]);
    assert_eq!(format!("{:?}", hkb), "HmacKeyBytes([REDACTED])");
    assert_eq!(format!("{}", hkb), "[REDACTED]");
    assert_eq!(hkb.len(), 32);
    assert!(!hkb.is_empty());
    let hkb2 = HmacKeyBytes::from_slice(&[3u8; 32]);
    assert_eq!(hkb, hkb2);

    // SharedSecret
    let ss = SharedSecret::new([4u8; 32]);
    assert_eq!(ss.expose_secret(), &[4u8; 32]);
    assert_eq!(format!("{:?}", ss), "SharedSecret([REDACTED])");
    assert_eq!(format!("{}", ss), "[REDACTED]");
    assert!(SharedSecret::from_slice(&[4u8; 33]).is_err());
    let ss2 = SharedSecret::from_slice(&[4u8; 32]).unwrap();
    assert_eq!(ss, ss2);
}

#[test]
fn test_hpke_setup_and_errors_coverage() {
    let rng = SeededRng::new(0xabc);
    let sk = generate_p256_secret_key(&rng).unwrap();
    let pk = public_key_from_secret_key(&sk).unwrap();
    let pk_encoded = pk.to_public_key().to_encoded_point(false);
    let pk_bytes: [u8; ENC_LEN] = pk_encoded.as_bytes().try_into().unwrap();

    let ephemeral_sk = generate_p256_secret_key(&rng).unwrap();
    let ephemeral_sk_bytes = *ephemeral_sk.expose_secret();

    let info = b"info";
    let aad = b"aad";
    let pt = b"plaintext";

    let (enc, ct) = hpke_seal_base_p256_hkdf_sha256_chacha20poly1305(
        &pk_bytes,
        &ephemeral_sk_bytes,
        info,
        pt,
        aad,
    )
    .unwrap();

    // hpke_setup_recipient
    let p256_sk = p256::SecretKey::from_slice(sk.expose_secret()).unwrap();
    let setup = hpke_setup_recipient(&p256_sk, &enc, info);
    assert!(setup.is_ok());

    // Invalid encapsulated key to setup
    let bad_enc = [0x04; ENC_LEN];
    assert!(hpke_setup_recipient(&p256_sk, &bad_enc, info).is_err());

    // Corrupted ct to open
    let mut corrupted_ct = ct;
    if let Some(first) = corrupted_ct.first_mut() {
        *first ^= 0xff;
    }
    assert!(hpke_open_base_p256_hkdf_sha256_chacha20poly1305(
        sk.expose_secret(),
        &enc,
        &corrupted_ct,
        info,
        aad,
    )
    .is_err());
}
