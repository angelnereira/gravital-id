//! Pruebas de transcodificación binaria biyectiva y codificación Base45 para presentaciones offline (REQ-PRES-005, PROTOCOL.md §3.2, ADR-0011).
//!
//! Trazabilidad:
//! - `REQ-PRES-005`: Transcodificación binaria sin pérdida entre SD-JWT y tupla CBOR determinista, compresión DEFLATE y Base45.
//! - `ADR-0011`: Prefijo canónico `GID1:` y tolerancia a prefijo legado `PIP1:`.
//! - `INV-01`: Cero I/O de red.
//! - `INV-05`: Rechazo fail-closed de presentaciones malformadas, ratios anómalos o firmas corruptas.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_codec::base64url;
use gravital_id_codec::cbor::{self, Value as CborValue};
use gravital_id_codec::json::Value;
use gravital_id_credential::SdJwtVcBuilder;
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_holder::{CredentialQuery, HolderWallet, RequestedClaim};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_protocol::offline_transcoding::{
    decode_presentation_from_base45, encode_presentation_to_base45, reconstruct_sd_jwt_from_cbor,
    transcode_sd_jwt_to_cbor, BASE45_CANONICAL_PREFIX, BASE45_LEGACY_PREFIX,
    TRANSCODED_PRESENTATION_VERSION,
};
use gravital_id_storage::InMemoryStorageBackend;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime, Vct};

const TEST_VCT: &str = "https://credentials.gravital.io/vct/personal/id-v1";
const ISSUER_URI: &str = "https://issuer.example.org";

fn setup_presentation_with_kb() -> (String, String) {
    let rng_holder = SeededRng::new(5001);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);
    let rng_issuer = SeededRng::new(6002);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let rng_emit = SeededRng::new(7003);
    let issued = SdJwtVcBuilder::new(ISSUER_URI, Vct::parse(TEST_VCT).expect("vct"), now)
        .expect("builder")
        .exp(UnixTime::from_seconds(
            now.as_seconds().saturating_add(3600),
        ))
        .cnf_jwk(holder_pub)
        .status_list(1, "https://status.example.org/list")
        .expect("status")
        .add_sd_claim("given_name", Value::String("Angel".into()))
        .add_sd_claim("family_name", Value::String("Nereira".into()))
        .add_sd_claim("birth_date", Value::String("1995-05-15".into()))
        .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
        .expect("issue");

    let raw_issued = issued.to_compact_serialization();

    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x44u8; 32]);
    let rng_wallet = SeededRng::new(8004);
    let mut wallet = HolderWallet::new(storage, kek, rng_wallet).expect("wallet");

    wallet
        .import_credential(
            raw_issued,
            holder_handle.id(),
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("import");

    let query = CredentialQuery::new(
        "gate_session_1",
        vec![Vct::parse(TEST_VCT).expect("vct")],
        vec![
            RequestedClaim::required("given_name"),
            RequestedClaim::required("family_name"),
        ],
    )
    .expect("query");

    let plan = wallet.prepare_disclosure_plan(&query, None).expect("plan");
    let presentation = wallet
        .confirm_presentation(
            &plan,
            "https://verifier.example.com",
            "test_session_nonce_12345678",
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("confirm presentation");

    (raw_issued.to_string(), presentation)
}

// Verifies: REQ-PRES-005 (Biyectividad sin pérdida de la transcodificación CBOR con KB-JWT)
#[test]
fn cbor_transcoding_lossless_roundtrip_with_kb_jwt() {
    let (_, presentation) = setup_presentation_with_kb();

    // 1. Transcodificar a CBOR determinista
    let cbor_bytes = transcode_sd_jwt_to_cbor(&presentation).expect("transcode");

    // Verificar estructura CBOR: array de 8 elementos
    let val = cbor::parse(&cbor_bytes).expect("cbor parse");
    if let CborValue::Array(arr) = val {
        assert_eq!(arr.len(), 8);
        assert_eq!(arr[0], CborValue::UInt(TRANSCODED_PRESENTATION_VERSION));
    } else {
        panic!("expected CBOR array");
    }

    // 2. Reconstruir a cadena compacta SD-JWT
    let reconstructed = reconstruct_sd_jwt_from_cbor(&cbor_bytes).expect("reconstruct");

    // Garantía biyectiva byte a byte
    assert_eq!(reconstructed, presentation);
}

// Verifies: REQ-PRES-005 (Biyectividad sin pérdida de transcodificación de credencial emitida sin KB-JWT)
#[test]
fn cbor_transcoding_lossless_roundtrip_without_kb_jwt() {
    let (issued_compact, _) = setup_presentation_with_kb();
    assert!(issued_compact.ends_with('~'));

    let cbor_bytes = transcode_sd_jwt_to_cbor(&issued_compact).expect("transcode");
    let reconstructed = reconstruct_sd_jwt_from_cbor(&cbor_bytes).expect("reconstruct");

    assert_eq!(reconstructed, issued_compact);
}

// Verifies: REQ-PRES-005, ADR-0011 (Codificación y decodificación Base45 para transporte QR)
#[test]
fn base45_transport_encoding_and_canonical_prefix() {
    let (_, presentation) = setup_presentation_with_kb();

    let encoded_b45 = encode_presentation_to_base45(&presentation).expect("encode base45");
    assert!(encoded_b45.starts_with(BASE45_CANONICAL_PREFIX));

    // Decodificar con prefijo canónico GID1:
    let decoded = decode_presentation_from_base45(&encoded_b45).expect("decode canonical");
    assert_eq!(decoded, presentation);

    // Decodificar con prefijo legado PIP1: (compatibilidad ADR-0001)
    let legacy_b45 = format!(
        "{}{}",
        BASE45_LEGACY_PREFIX,
        encoded_b45.strip_prefix(BASE45_CANONICAL_PREFIX).unwrap()
    );
    let decoded_legacy = decode_presentation_from_base45(&legacy_b45).expect("decode legacy");
    assert_eq!(decoded_legacy, presentation);
}

// Verifies: REQ-PRES-005 (Rechazo fail-closed ante prefijo ausente o inválido)
#[test]
fn base45_decoding_missing_prefix_rejected() {
    let (_, presentation) = setup_presentation_with_kb();
    let encoded_b45 = encode_presentation_to_base45(&presentation).expect("encode");

    // Quitar prefijo
    let no_prefix = encoded_b45.strip_prefix(BASE45_CANONICAL_PREFIX).unwrap();
    let err = decode_presentation_from_base45(no_prefix).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Prefijo desconocido
    let wrong_prefix = format!("UNKNOWN:{no_prefix}");
    let err = decode_presentation_from_base45(&wrong_prefix).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-005 (Rechazo fail-closed ante firmas malformadas o incompletas)
#[test]
fn transcode_corrupted_signature_length_rejected() {
    // Firma con 32 bytes en vez de 64
    let header_b64 = base64url::encode(br#"{"alg":"ES256","typ":"vc+sd-jwt"}"#);
    let payload_b64 = base64url::encode(br#"{"iss":"https://issuer.example.com"}"#);
    let short_sig_b64 = base64url::encode(&[0xaa; 32]); // Deberían ser 64 bytes

    let bad_sd_jwt = format!("{header_b64}.{payload_b64}.{short_sig_b64}~");
    let err = transcode_sd_jwt_to_cbor(&bad_sd_jwt).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-PRES-005 (Rechazo de CBOR malformado o de versión incorrecta)
#[test]
fn reconstruct_invalid_cbor_structures_rejected() {
    // No es array (cadena de texto CBOR "abc": 0x63, 'a', 'b', 'c')
    let not_array = vec![0x63, b'a', b'b', b'c'];
    let err = reconstruct_sd_jwt_from_cbor(&not_array).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Array con menos de 8 elementos ([1, 2]: 0x82, 0x01, 0x02)
    let short_arr = vec![0x82, 0x01, 0x02];
    let err = reconstruct_sd_jwt_from_cbor(&short_arr).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Array de 8 elementos con versión no soportada (versión 99)
    // 0x88 (array 8 items): 0x18, 99 (uint 99), 0x40 (bstr 0), 0x40, 0x40, 0x80 (arr 0), 0x40, 0x40, 0x40
    let wrong_ver_arr = vec![0x88, 0x18, 99, 0x40, 0x40, 0x40, 0x80, 0x40, 0x40, 0x40];
    let err = reconstruct_sd_jwt_from_cbor(&wrong_ver_arr).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}
