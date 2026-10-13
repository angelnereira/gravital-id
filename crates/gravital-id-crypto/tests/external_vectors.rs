//! Pruebas de vectores externos (F2.T08, REQ-SEC-002).
//!
//! Suite de pruebas contra vectores publicados e independientes:
//! - RFC 7515 (ES256, Apéndice A.3)
//! - RFC 7638 (JWK Thumbprint EC P-256)
//! - RFC 5869 (HKDF SHA-256, Casos 1, 2 y 3)
//! - RFC 9180 (HPKE Modo Base, DHKEM P-256 + HKDF-SHA256 + ChaCha20Poly1305, Apéndice A.5.1)
//! - Project Wycheproof (ECDSA P-256 / SHA-256 y XChaCha20-Poly1305)

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use gravital_id_crypto::aead::{
    open as aead_open, seal as aead_seal, AEAD_KEY_LEN, AEAD_NONCE_LEN,
};
use gravital_id_crypto::hpke::{
    hpke_open_base_p256_hkdf_sha256_chacha20poly1305,
    hpke_seal_base_p256_hkdf_sha256_chacha20poly1305, hpke_setup_recipient,
};
use gravital_id_crypto::jwk::{jwk_thumbprint_base64url, jwk_thumbprint_sha256, JwkEcP256};
use gravital_id_crypto::kdf::{hkdf_extract_sha256, hkdf_sha256};
use gravital_id_crypto::sign::{
    der_to_p1363, p1363_to_der, sign_es256, verify_es256, verify_es256_der, ES256_PUBLIC_KEY_LEN,
    ES256_SECRET_KEY_LEN, ES256_SIGNATURE_LEN,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::SecretKey;
use serde::Deserialize;

fn decode_hex(s: &str) -> Vec<u8> {
    if s.is_empty() {
        return Vec::new();
    }
    assert_eq!(s.len() % 2, 0, "longitud hex impar: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex invalido"))
        .collect()
}

// =========================================================================
// 1. RFC 7515 — ES256 (Apéndice A.3)
// =========================================================================

// // Verifies: REQ-SEC-002 (RFC 7515 Apéndice A.3 ES256)
#[test]
fn test_rfc7515_appendix_a3_es256() {
    let header_b64 = "eyJhbGciOiJFUzI1NiJ9";
    let payload_b64 =
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    let signing_input = format!("{header_b64}.{payload_b64}");

    let jwk_x_b64 = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    let jwk_y_b64 = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    let jwk_d_b64 = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

    let sig_p1363_b64 =
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

    let jwk_json = format!(r#"{{"kty":"EC","crv":"P-256","x":"{jwk_x_b64}","y":"{jwk_y_b64}"}}"#);
    let jwk = JwkEcP256::parse(&jwk_json).expect("JWK RFC 7515 A.3 valido");

    let pubkey_bytes = jwk.to_sec1_bytes();
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes).expect("VerifyingKey valida");

    let sig_bytes =
        gravital_id_codec::base64url::decode(sig_p1363_b64).expect("firma base64url valida");
    assert_eq!(sig_bytes.len(), ES256_SIGNATURE_LEN);

    // 1. Verificación directa de la firma P1363 del RFC
    verify_es256(&verifying_key, signing_input.as_bytes(), &sig_bytes)
        .expect("firma P1363 RFC 7515 verifica con exito");

    // 2. Conversión a DER y verificación con verify_es256_der
    let der_sig = p1363_to_der(&sig_bytes).expect("conversion a DER valida");
    verify_es256_der(&verifying_key, signing_input.as_bytes(), &der_sig)
        .expect("firma DER convertida verifica con exito");

    // 3. Conversión bidireccional DER -> P1363 -> DER
    let roundtrip_p1363 = der_to_p1363(&der_sig).expect("DER a P1363");
    assert_eq!(roundtrip_p1363.as_slice(), sig_bytes.as_slice());

    // 4. Firma determinista con la clave privada 'd' de RFC 7515 A.3
    let d_bytes = gravital_id_codec::base64url::decode(jwk_d_b64).expect("d b64");
    assert_eq!(d_bytes.len(), ES256_SECRET_KEY_LEN);
    let signing_key = SigningKey::from_slice(&d_bytes).expect("SigningKey valida");
    let det_sig =
        sign_es256(&signing_key, signing_input.as_bytes()).expect("firma determinista RFC 6979");
    assert_eq!(det_sig.len(), ES256_SIGNATURE_LEN);
    verify_es256(&verifying_key, signing_input.as_bytes(), &det_sig)
        .expect("firma determinista propia verifica");

    // 5. Casos negativos: alteración de mensaje
    let mut corrupted_input = signing_input.clone().into_bytes();
    corrupted_input[0] ^= 0x01;
    assert!(
        verify_es256(&verifying_key, &corrupted_input, &sig_bytes).is_err(),
        "mensaje alterado debe fallar"
    );

    // 6. Casos negativos: alteración de componente r y s de la firma
    let mut corrupted_sig = sig_bytes.clone();
    corrupted_sig[0] ^= 0x01;
    assert!(
        verify_es256(&verifying_key, signing_input.as_bytes(), &corrupted_sig).is_err(),
        "componente r alterado debe fallar"
    );
    corrupted_sig = sig_bytes;
    corrupted_sig[63] ^= 0x01;
    assert!(
        verify_es256(&verifying_key, signing_input.as_bytes(), &corrupted_sig).is_err(),
        "componente s alterado debe fallar"
    );
}

// =========================================================================
// 2. RFC 7638 — JWK Thumbprints
// =========================================================================

// // Verifies: REQ-SEC-002 (RFC 7638 JWK Thumbprint)
#[test]
fn test_rfc7638_jwk_thumbprint() {
    // Vector 1: EC P-256 oficial
    let jwk1_x = "jJ6Flys3zK9jUhnOHf6G49Dyp5hah6CNP84-gY-n9eo";
    let jwk1_y = "nhI6iD5eFXgBTLt_1p3aip-5VbZeMhxeFSpjfEAf7Ww";
    let expected_thumbprint_b64 = "w9eYdC6_s_tLQ8lH6PUpc0mddazaqtPgeC2IgWDiqY8";
    let expected_sha256_hex = "c3d798742ebfb3fb4b43c947e8f52973499d75acdaaad3e0782d888160e2a98f";

    let jwk1_json = format!(r#"{{"kty":"EC","crv":"P-256","x":"{jwk1_x}","y":"{jwk1_y}"}}"#);
    let jwk1 = JwkEcP256::parse(&jwk1_json).expect("JWK valido");

    assert_eq!(jwk1.thumbprint_base64url(), expected_thumbprint_b64);
    assert_eq!(jwk_thumbprint_base64url(&jwk1), expected_thumbprint_b64);
    assert_eq!(
        jwk1.thumbprint_sha256().as_slice(),
        decode_hex(expected_sha256_hex).as_slice()
    );
    assert_eq!(
        jwk_thumbprint_sha256(&jwk1).as_slice(),
        decode_hex(expected_sha256_hex).as_slice()
    );
    assert_eq!(
        jwk1.thumbprint_uri(),
        format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{expected_thumbprint_b64}")
    );

    // Vector 2: Clave de RFC 7515 Apéndice A.3
    let jwk2_x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    let jwk2_y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    let expected_thumbprint2_b64 = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U";
    let expected_sha256_2_hex = "a0a232c2f194a53553cb1310ddbc0821e414b9d7ebfc290b323084d7d1020fe5";

    let jwk2_json = format!(r#"{{"kty":"EC","crv":"P-256","x":"{jwk2_x}","y":"{jwk2_y}"}}"#);
    let jwk2 = JwkEcP256::parse(&jwk2_json).expect("JWK 2 valido");
    assert_eq!(jwk2.thumbprint_base64url(), expected_thumbprint2_b64);
    assert_eq!(
        jwk2.thumbprint_sha256().as_slice(),
        decode_hex(expected_sha256_2_hex).as_slice()
    );

    // Canónico lexicográfico estricto sin espacios: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
    let canonical = jwk2.to_canonical_json();
    assert_eq!(
        canonical,
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{jwk2_x}","y":"{jwk2_y}"}}"#)
    );

    // Caso negativo: miembro privado 'd' rechazado
    let private_json =
        format!(r#"{{"kty":"EC","crv":"P-256","x":"{jwk1_x}","y":"{jwk1_y}","d":"abc"}}"#);
    assert!(JwkEcP256::parse(&private_json).is_err());
}

// =========================================================================
// 3. RFC 5869 — HKDF SHA-256
// =========================================================================

// // Verifies: REQ-SEC-002 (RFC 5869 HKDF SHA-256 Casos 1, 2 y 3)
#[test]
fn test_rfc5869_hkdf_sha256() {
    // Caso 1 (Apéndice A.1)
    {
        let ikm = vec![0x0bu8; 22];
        let salt = decode_hex("000102030405060708090a0b0c");
        let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
        let l = 42usize;
        let expected_prk =
            decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let expected_okm = decode_hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let prk = hkdf_extract_sha256(&salt, &ikm).expect("extract");
        assert_eq!(prk.as_slice(), expected_prk.as_slice());

        let okm = hkdf_sha256(&salt, &ikm, &info, l).expect("HKDF Caso 1");
        assert_eq!(okm, expected_okm);
    }

    // Caso 2 (Apéndice A.2 - entradas largas de 80 bytes)
    {
        let ikm: Vec<u8> = (0x00u8..=0x4fu8).collect();
        let salt: Vec<u8> = (0x60u8..=0xafu8).collect();
        let info: Vec<u8> = (0xb0u8..=0xffu8).collect();
        let l = 82usize;
        let expected_prk =
            decode_hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        let expected_okm = decode_hex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );

        let prk = hkdf_extract_sha256(&salt, &ikm).expect("extract");
        assert_eq!(prk.as_slice(), expected_prk.as_slice());

        let okm = hkdf_sha256(&salt, &ikm, &info, l).expect("HKDF Caso 2");
        assert_eq!(okm, expected_okm);
    }

    // Caso 3 (Apéndice A.3 - salt e info vacíos)
    {
        let ikm = vec![0x0bu8; 22];
        let salt = Vec::new();
        let info = Vec::new();
        let l = 42usize;
        let expected_prk =
            decode_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        let expected_okm = decode_hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );

        let prk = hkdf_extract_sha256(&salt, &ikm).expect("extract");
        assert_eq!(prk.as_slice(), expected_prk.as_slice());

        let okm = hkdf_sha256(&salt, &ikm, &info, l).expect("HKDF Caso 3");
        assert_eq!(okm, expected_okm);
    }

    // Caso negativo: L > 255 * 32 (8160 bytes)
    assert!(hkdf_sha256(&[], &[0x42], &[], 8161).is_err());
}

// =========================================================================
// 4. RFC 9180 — HPKE Modo Base (Apéndice A.5.1)
// =========================================================================

// // Verifies: REQ-SEC-002 (RFC 9180 HPKE Apéndice A.5.1 DHKEM P-256 + HKDF-SHA256 + ChaCha20Poly1305)
#[test]
fn test_rfc9180_hpke_p256_hkdf_chacha20poly1305() {
    let sk_rm_bytes =
        decode_hex("a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b");
    let pk_rm_bytes = decode_hex(
        "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006",
    );
    let sk_em_bytes =
        decode_hex("7550253e1147aae48839c1f8af80d2770fb7a4c763afe7d0afa7e0f42a5b3689");
    let enc_bytes = decode_hex(
        "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",
    );
    let info = decode_hex("4f6465206f6e2061204772656369616e2055726e"); // "Ode on a Grecian Urn"
    let pt = decode_hex("4265617574792069732074727574682c20747275746820626561757479"); // "Beauty is truth, truth beauty"
    let aad = decode_hex("436f756e742d30"); // "Count-0"
    let ct = decode_hex(
        "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f03ea2952a27bb458b",
    );

    assert_eq!(sk_rm_bytes.len(), ES256_SECRET_KEY_LEN);
    assert_eq!(sk_em_bytes.len(), ES256_SECRET_KEY_LEN);
    assert_eq!(pk_rm_bytes.len(), ES256_PUBLIC_KEY_LEN);
    assert_eq!(enc_bytes.len(), ES256_PUBLIC_KEY_LEN);

    let mut sk_rm = [0u8; ES256_SECRET_KEY_LEN];
    sk_rm.copy_from_slice(&sk_rm_bytes);
    let mut pk_rm = [0u8; ES256_PUBLIC_KEY_LEN];
    pk_rm.copy_from_slice(&pk_rm_bytes);
    let mut sk_em = [0u8; ES256_SECRET_KEY_LEN];
    sk_em.copy_from_slice(&sk_em_bytes);
    let mut enc = [0u8; ES256_PUBLIC_KEY_LEN];
    enc.copy_from_slice(&enc_bytes);

    // 1. Verificación del contexto del receptor (derivación exacta según RFC 9180 A.5.1)
    let recipient_secret = SecretKey::from_bytes((&sk_rm).into()).expect("sk_rm valida");
    let (derived_key, base_nonce) =
        hpke_setup_recipient(&recipient_secret, &enc, &info).expect("setup_recipient exitoso");
    let expected_key =
        decode_hex("a8f45490a92a3b04d1dbf6cf2c3939ad8bfc9bfcb97c04bffe116730c9dfe3fc");
    let expected_nonce = decode_hex("726b4390ed2209809f58c693");
    assert_eq!(derived_key.as_slice(), expected_key.as_slice());
    assert_eq!(base_nonce.as_slice(), expected_nonce.as_slice());

    // 2. Apertura del mensaje según el vector de prueba
    let decrypted =
        hpke_open_base_p256_hkdf_sha256_chacha20poly1305(&sk_rm, &enc, &ct, &info, &aad)
            .expect("descifrado HPKE exitoso");
    assert_eq!(decrypted, pt);

    // 3. Sellado del mensaje por el emisor efímero según el vector de prueba
    let (sealed_enc, sealed_ct) =
        hpke_seal_base_p256_hkdf_sha256_chacha20poly1305(&pk_rm, &sk_em, &info, &pt, &aad)
            .expect("sellado HPKE exitoso");
    assert_eq!(sealed_enc.as_slice(), enc.as_slice());
    assert_eq!(sealed_ct, ct);

    // 4. Casos negativos: alteración de texto cifrado
    let mut corrupted_ct = ct.clone();
    corrupted_ct[0] ^= 0x01;
    assert!(
        hpke_open_base_p256_hkdf_sha256_chacha20poly1305(&sk_rm, &enc, &corrupted_ct, &info, &aad)
            .is_err(),
        "texto cifrado corrupto debe fallar"
    );

    // 5. Casos negativos: alteración de AAD
    let mut corrupted_aad = aad.clone();
    corrupted_aad[0] ^= 0x01;
    assert!(
        hpke_open_base_p256_hkdf_sha256_chacha20poly1305(&sk_rm, &enc, &ct, &info, &corrupted_aad)
            .is_err(),
        "AAD corrupto debe fallar"
    );

    // 6. Casos negativos: alteración de info
    let mut corrupted_info = info.clone();
    corrupted_info[0] ^= 0x01;
    assert!(
        hpke_open_base_p256_hkdf_sha256_chacha20poly1305(&sk_rm, &enc, &ct, &corrupted_info, &aad)
            .is_err(),
        "info corrupto debe fallar"
    );
}

// =========================================================================
// 5. Project Wycheproof — ECDSA secp256r1 SHA-256
// =========================================================================

#[derive(Deserialize)]
struct WycheproofEcdsaFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofEcdsaGroup>,
}

#[derive(Deserialize)]
struct WycheproofEcdsaGroup {
    #[serde(rename = "publicKey")]
    public_key: WycheproofEcdsaPublicKey,
    tests: Vec<WycheproofEcdsaTest>,
}

#[derive(Deserialize)]
struct WycheproofEcdsaPublicKey {
    uncompressed: String,
}

#[derive(Deserialize)]
struct WycheproofEcdsaTest {
    #[serde(rename = "tcId")]
    tc_id: usize,
    comment: String,
    msg: String,
    sig: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

// // Verifies: REQ-SEC-002 (Project Wycheproof ECDSA P-256 SHA-256)
#[test]
fn test_wycheproof_ecdsa_secp256r1_sha256() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/wycheproof_ecdsa_secp256r1_sha256.json"
    );
    let content = std::fs::read_to_string(path).expect("lectura de vectores wycheproof ecdsa");
    let file: WycheproofEcdsaFile =
        serde_json::from_str(&content).expect("parseo JSON wycheproof ecdsa");

    assert_eq!(file.number_of_tests, 484);

    let mut passed = 0;
    let mut total = 0;

    for group in &file.test_groups {
        let pubkey_bytes = decode_hex(&group.public_key.uncompressed);
        let verifying_key_res = VerifyingKey::from_sec1_bytes(&pubkey_bytes);

        for test in &group.tests {
            total += 1;
            let msg = decode_hex(&test.msg);
            let sig = decode_hex(&test.sig);

            let is_valid = match &verifying_key_res {
                Ok(vk) => verify_es256_der(vk, &msg, &sig).is_ok(),
                Err(_) => false,
            };

            match test.result.as_str() {
                "valid" => {
                    assert!(
                        is_valid,
                        "tcId {}: caso valido falló la verificación (comment: {}, flags: {:?})",
                        test.tc_id, test.comment, test.flags
                    );
                    passed += 1;
                }
                "invalid" => {
                    assert!(
                        !is_valid,
                        "tcId {}: caso invalido fue indebidamente aceptado (comment: {}, flags: {:?})",
                        test.tc_id, test.comment, test.flags
                    );
                    passed += 1;
                }
                other => {
                    panic!("resultado desconocido en Wycheproof: {other}");
                }
            }
        }
    }

    assert_eq!(total, 484);
    assert_eq!(passed, 484);
}

// =========================================================================
// 6. Project Wycheproof — XChaCha20-Poly1305
// =========================================================================

#[derive(Deserialize)]
struct WycheproofAeadFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofAeadGroup>,
}

#[derive(Deserialize)]
struct WycheproofAeadGroup {
    tests: Vec<WycheproofAeadTest>,
}

#[derive(Deserialize)]
struct WycheproofAeadTest {
    #[serde(rename = "tcId")]
    tc_id: usize,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

// // Verifies: REQ-SEC-002 (Project Wycheproof XChaCha20-Poly1305)
#[test]
fn test_wycheproof_xchacha20_poly1305() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/wycheproof_xchacha20_poly1305.json"
    );
    let content = std::fs::read_to_string(path).expect("lectura de vectores wycheproof aead");
    let file: WycheproofAeadFile =
        serde_json::from_str(&content).expect("parseo JSON wycheproof aead");

    assert_eq!(file.number_of_tests, 315);

    let mut passed = 0;
    let mut total = 0;

    for group in &file.test_groups {
        for test in &group.tests {
            total += 1;
            let key_bytes = decode_hex(&test.key);
            let iv_bytes = decode_hex(&test.iv);
            let aad = decode_hex(&test.aad);
            let msg = decode_hex(&test.msg);
            let ct = decode_hex(&test.ct);
            let tag = decode_hex(&test.tag);

            let mut ciphertext = ct.clone();
            ciphertext.extend_from_slice(&tag);

            let can_form_params =
                key_bytes.len() == AEAD_KEY_LEN && iv_bytes.len() == AEAD_NONCE_LEN;

            let open_res = if can_form_params {
                let mut key_arr = [0u8; AEAD_KEY_LEN];
                key_arr.copy_from_slice(&key_bytes);
                let mut iv_arr = [0u8; AEAD_NONCE_LEN];
                iv_arr.copy_from_slice(&iv_bytes);

                aead_open(&key_arr, &iv_arr, &ciphertext, &aad)
            } else {
                Err(gravital_id_types::GidError::new(
                    gravital_id_types::ErrorCode::InvalidKeyFormat,
                    "tamano de clave o iv invalido",
                ))
            };

            match test.result.as_str() {
                "valid" => {
                    let decrypted = open_res.unwrap_or_else(|e| {
                        panic!(
                            "tcId {}: caso valido fallo apertura AEAD: {e:?} (comment: {}, flags: {:?})",
                            test.tc_id, test.comment, test.flags
                        )
                    });
                    assert_eq!(
                        decrypted, msg,
                        "tcId {}: mensaje descifrado no coincide",
                        test.tc_id
                    );

                    // Verificar además el cifrado (seal)
                    let mut key_arr = [0u8; AEAD_KEY_LEN];
                    key_arr.copy_from_slice(&key_bytes);
                    let mut iv_arr = [0u8; AEAD_NONCE_LEN];
                    iv_arr.copy_from_slice(&iv_bytes);
                    let sealed =
                        aead_seal(&key_arr, &iv_arr, &msg, &aad).expect("seal caso valido");
                    assert_eq!(
                        sealed, ciphertext,
                        "tcId {}: ciphertext sellado no coincide con el vector",
                        test.tc_id
                    );

                    passed += 1;
                }
                "invalid" => {
                    assert!(
                        open_res.is_err(),
                        "tcId {}: caso invalido fue descifrado indebidamente (comment: {}, flags: {:?})",
                        test.tc_id, test.comment, test.flags
                    );
                    passed += 1;
                }
                other => {
                    panic!("resultado desconocido en Wycheproof AEAD: {other}");
                }
            }
        }
    }

    assert_eq!(total, 315);
    assert_eq!(passed, 315);
}
