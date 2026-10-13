#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración para la emisión SD-JWT (F3.T02, RFC 9901).
//!
//! Trazabilidad:
//! - REQ-CRED-002: Cada divulgación DEBE usar una sal de ≥ 128 bits de un CSPRNG.
//! - REQ-CRED-003: El emisor DEBE soportar digests señuelo configurables por perfil.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::Value;
use gravital_id_credential::{
    generate_decoy_digest, generate_decoy_digests, Disclosure, DisclosureDigest, JwsHeader,
    SdArrayBuilder, SdIssuer, SdObjectBuilder, DIGEST_BASE64URL_LEN, MIN_SALT_BYTES,
};
use gravital_id_crypto::verify_es256_jwk;
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_testkit::SeededRng;
use gravital_id_types::ErrorCode;

// Verifies: REQ-CRED-002
#[test]
fn salt_minimum_128_bits_entropy_enforced() {
    let rng = SeededRng::new(1001);

    // 1. Sal generada contiene exactamente 16 bytes (128 bits)
    let salt = gravital_id_credential::Salt::generate(&rng).expect("generate salt");
    let decoded = base64url::decode(salt.as_str()).expect("decode salt");
    assert_eq!(decoded.len(), MIN_SALT_BYTES);
    assert_eq!(decoded.len(), 16);

    // 2. Sal creada desde slice con menos de 16 bytes es rechazada con InsufficientEntropy
    let short_bytes = [0xAAu8; 15]; // 120 bits < 128 bits
    let err = gravital_id_credential::Salt::from_slice(&short_bytes).unwrap_err();
    assert_eq!(err.code, ErrorCode::InsufficientEntropy);

    // 3. Sal creada desde slice con exactamente 16 bytes es aceptada
    let exact_bytes = [0xBBu8; 16];
    let ok_salt = gravital_id_credential::Salt::from_slice(&exact_bytes).expect("16 bytes salt");
    assert_eq!(ok_salt.as_str().len(), 22);

    // 4. Sal creada desde base64url con menos de 128 bits es rechazada
    let short_b64 = base64url::encode(&[0xCCu8; 14]);
    let err_b64 = gravital_id_credential::Salt::from_base64url(&short_b64).unwrap_err();
    assert_eq!(err_b64.code, ErrorCode::InsufficientEntropy);
}

// Verifies: REQ-CRED-003
#[test]
fn decoy_digests_configurable_for_objects_and_arrays() {
    let rng = SeededRng::new(1002);

    // 1. Generación directa de decoys
    let decoy = generate_decoy_digest(&rng).expect("generate decoy");
    assert_eq!(decoy.as_str().len(), DIGEST_BASE64URL_LEN);

    let batch = generate_decoy_digests(&rng, 4).expect("generate batch decoys");
    assert_eq!(batch.len(), 4);
    assert_ne!(batch[0], batch[1]);

    // 2. Objeto con decoys configurables
    let obj_builder = SdObjectBuilder::new()
        .add_plain_claim("iss", Value::String("https://issuer.com".to_string()))
        .add_sd_claim("sub", Value::String("alice".to_string()))
        .set_decoys(3);

    let emitted_obj = obj_builder.build(&rng).expect("build obj with decoys");
    // Solo 1 divulgación real emitida
    assert_eq!(emitted_obj.disclosures.len(), 1);

    // El array _sd contiene 4 digests en total (1 real + 3 decoys)
    match emitted_obj.value {
        Value::Object(entries) => {
            let sd = entries.iter().find(|(k, _)| k == "_sd").map(|(_, v)| v);
            match sd {
                Some(Value::Array(items)) => {
                    assert_eq!(items.len(), 4);
                }
                _ => panic!("expected _sd array"),
            }
        }
        _ => panic!("expected object"),
    }

    // 3. Array con decoys configurables
    let arr_builder = SdArrayBuilder::new()
        .add_plain_element(Value::String("item1".to_string()))
        .add_sd_element(Value::String("item2".to_string()))
        .set_decoys(2);

    let emitted_arr = arr_builder.build(&rng).expect("build arr with decoys");
    assert_eq!(emitted_arr.disclosures.len(), 1);

    match emitted_arr.value {
        Value::Array(items) => {
            // 1 plain + 1 sd + 2 decoys = 4 items
            assert_eq!(items.len(), 4);
        }
        _ => panic!("expected array"),
    }
}

// Verifies: REQ-CRED-002, REQ-CRED-003
#[test]
fn complete_emission_with_rfc9901_features() {
    let rng = SeededRng::new(2001);
    let mut key_store = SoftwareKeyStore::new(rng);
    let handle = key_store
        .generate_key::<IssuerSigning>()
        .expect("generate key");
    let jwk = key_store.public_key(&handle).expect("public key");

    let rng_emit = SeededRng::new(2002);

    // Objeto anidado de dirección (recursivo: 'address' es divulgable y sus sub-claims son divulgables)
    let address = SdObjectBuilder::new()
        .add_sd_claim("street_address", Value::String("123 Main St".to_string()))
        .add_sd_claim("locality", Value::String("Panama City".to_string()))
        .add_plain_claim("country", Value::String("PA".to_string()))
        .set_decoys(2);

    // Array anidado de nacionalidades
    let nationalities = SdArrayBuilder::new()
        .add_sd_element(Value::String("PA".to_string()))
        .add_sd_element(Value::String("ES".to_string()))
        .set_decoys(1);

    let root_builder = SdObjectBuilder::new()
        .add_plain_claim(
            "iss",
            Value::String("https://issuer.example.org".to_string()),
        )
        .add_plain_claim(
            "vct",
            Value::String("urn:pip:credentials:identity".to_string()),
        )
        .add_sd_claim("given_name", Value::String("John".to_string()))
        .add_sd_claim("family_name", Value::String("Doe".to_string()))
        .add_nested_object_sd("address", address)
        .add_nested_array_plain("nationalities", nationalities)
        .set_decoys(3);

    let issued = SdIssuer::issue_signed(
        root_builder,
        &key_store,
        &handle,
        JwsHeader::default(),
        &rng_emit,
    )
    .expect("issue signed sd-jwt");

    // Total de divulgaciones reales:
    // given_name (1) + family_name (1) + address (1) + street_address (1) + locality (1) + PA (1) + ES (1) = 7
    assert_eq!(issued.disclosures().len(), 7);

    // Serialización compacta
    let compact = issued.to_compact_serialization();
    assert!(compact.starts_with("eyJ"));
    assert!(compact.ends_with('~'));

    // Debe contener exactamente 8 separadores '~' (1 tras JWT + 7 tras cada divulgación)
    assert_eq!(compact.matches('~').count(), 8);

    // Parseo inverso
    let parsed = gravital_id_credential::IssuedSdJwt::from_compact(compact).expect("from compact");
    assert_eq!(parsed.jwt(), issued.jwt());
    assert_eq!(parsed.disclosures().len(), 7);

    // Validación de firma ES256 del JWS emitido
    let parts: Vec<&str> = issued.jwt().split('.').collect();
    assert_eq!(parts.len(), 3);
    let signing_input = alloc::format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = base64url::decode(parts[2]).expect("decode sig");
    let mut sig_fixed = [0u8; 64];
    sig_fixed.copy_from_slice(&sig_bytes);

    verify_es256_jwk(&jwk, signing_input.as_bytes(), &sig_fixed).expect("verify ES256 signature");
}

// Verifies: REQ-CRED-002
#[test]
fn negative_tests_disclosure_and_emission() {
    let rng = SeededRng::new(3001);
    let salt = gravital_id_credential::Salt::generate(&rng).expect("generate salt");

    // 1. Intento de usar claim reservado '_sd' en divulgación de objeto
    let err_sd =
        Disclosure::new_object(salt.clone(), "_sd", Value::String("val".to_string())).unwrap_err();
    assert_eq!(err_sd.code, ErrorCode::MalformedSdJwt);

    // 2. Intento de usar claim reservado '...' en divulgación de objeto
    let err_dots =
        Disclosure::new_object(salt.clone(), "...", Value::String("val".to_string())).unwrap_err();
    assert_eq!(err_dots.code, ErrorCode::MalformedSdJwt);

    // 3. Digest con longitud distinta de 32 bytes es rechazado
    let short_digest_b64 = base64url::encode(&[0xFFu8; 31]);
    let err_digest = DisclosureDigest::from_base64url(&short_digest_b64).unwrap_err();
    assert_eq!(err_digest.code, ErrorCode::MalformedSdJwt);

    // 4. Parseo de SD-JWT compacto sin delimitador '~' falla
    let err_compact =
        gravital_id_credential::IssuedSdJwt::from_compact("header.payload.sig").unwrap_err();
    assert_eq!(err_compact.code, ErrorCode::MalformedSdJwt);

    // 5. Parseo de SD-JWT compacto con JWT malformado falla
    let err_jwt = gravital_id_credential::IssuedSdJwt::from_compact("header.payload~disclosure~")
        .unwrap_err();
    assert_eq!(err_jwt.code, ErrorCode::MalformedSdJwt);

    // 6. Divulgación malformada (array JSON de 1 solo elemento) es rechazada
    let invalid_json_array = base64url::encode(b"[\"salt_only\"]");
    let err_parse_disc = Disclosure::parse(&invalid_json_array).unwrap_err();
    assert_eq!(err_parse_disc.code, ErrorCode::MalformedSdJwt);

    // 7. Divulgación malformada (no es array JSON, sino objeto) es rechazada
    let invalid_json_obj = base64url::encode(b"{\"key\":\"value\"}");
    let err_parse_obj = Disclosure::parse(&invalid_json_obj).unwrap_err();
    assert_eq!(err_parse_obj.code, ErrorCode::MalformedSdJwt);
}
