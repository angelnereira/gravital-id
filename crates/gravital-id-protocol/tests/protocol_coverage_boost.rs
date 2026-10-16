//! Pruebas de cobertura exhaustiva para gravital-id-protocol (F5.T09, F5.T10, REQ-MAINT-005).
//!
//! Trazabilidad:
//! - `REQ-MAINT-005`: Cobertura de líneas >= 90 % con pruebas negativas rigurosas.
//! - `INV-05`: Verificación de todos los rechazos fail-closed (mensajes corruptos, desbordamientos, tipos erróneos).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_holder::DcqlQuery;
use gravital_id_protocol::offline_multi_qr::{segment_presentation, MultiQrCollector};
use gravital_id_protocol::offline_request::{VerificationRequest, VERIFICATION_REQUEST_TYPE};
use gravital_id_protocol::offline_transcoding::{
    decode_presentation_from_base45, reconstruct_sd_jwt_from_cbor, transcode_sd_jwt_to_cbor,
};
use gravital_id_types::{ErrorCode, UnixTime};

fn minimal_dcql_query() -> DcqlQuery {
    let query_json = br#"{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{"vct_values":["urn:test"]},"claims":["a"]}]}"#;
    DcqlQuery::from_json_bytes(query_json).expect("valid query")
}

// Verifies: REQ-MAINT-005 (Cobertura de todos los casos de error en MultiQrCollector y segmentación)
#[test]
fn multi_qr_edge_cases_and_error_branches() {
    // 1. Exceder límite máximo de fragmentos (total > MAX_MULTI_QR_FRAGMENTS)
    // 900 * 8 = 7200 chars. Si enviamos 7201 caracteres -> requiere 9 fragmentos
    let massive_text = "M".repeat(7201);
    let err = segment_presentation(&massive_text).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let mut collector = MultiQrCollector::new();

    // 2. is_complete sin fragmentos, derivados Default, Clone y Debug
    assert!(!collector.is_complete());
    assert_eq!(collector.expected_total(), None);
    assert_eq!(collector.received_count(), 0);

    let default_collector = MultiQrCollector::default();
    let cloned_collector = collector.clone();
    let _ = format!("{collector:?}");
    let _ = format!("{default_collector:?}");
    let _ = format!("{cloned_collector:?}");

    // 3. add_fragment con prefijo faltante
    let err = collector.add_fragment("INVALID_PREFIX").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 4. Formato de cabecera con menos partes o partes incompletas
    let err = collector.add_fragment("GID01/P").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = collector.add_fragment("GID01/P1").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = collector.add_fragment("GID01/P1/2").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = collector.add_fragment("GID01/P1/2/ABC").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = collector.add_fragment("PIP1/M/1/2/12345678").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 5. Índice inválido (no número)
    let err = collector
        .add_fragment("GID01/Px/2/ABCDEF12/chunk")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 6. Total inválido (no número)
    let err = collector
        .add_fragment("GID01/P1/y/ABCDEF12/chunk")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 7. Total fuera de rango (< 2 o > 8)
    let err = collector
        .add_fragment("GID01/P1/1/ABCDEF12/chunk")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = collector
        .add_fragment("GID01/P1/9/ABCDEF12/chunk")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 8. Índice fuera de rango (0 o > total)
    let err = collector
        .add_fragment("GID01/P0/2/ABCDEF12/chunk")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    let err = collector
        .add_fragment("GID01/P3/2/ABCDEF12/chunk")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 9. Longitud de hash8 != 8
    let err = collector.add_fragment("GID01/P1/2/ABC/chunk").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 10. Primer fragmento válido: index 1 de 2
    assert!(collector
        .add_fragment("GID01/P1/2/ABCDEF12/hello_")
        .unwrap()
        .is_none());
    assert_eq!(collector.expected_total(), Some(2));
    assert_eq!(collector.received_count(), 1);

    // 11. Segundo fragmento con total discrepante (total 3 en vez de 2)
    let err = collector
        .add_fragment("GID01/P2/3/ABCDEF12/world")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 12. Segundo fragmento con hash8 discrepante (ZBCDEF12 en vez de ABCDEF12)
    let err = collector
        .add_fragment("GID01/P2/2/ZBCDEF12/world")
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // 13. Verificación de fallo de integridad SHA-256 cuando se completa el reensamblaje
    let payload = "T".repeat(1500);
    let frags = segment_presentation(&payload).unwrap();
    let mut collector_tamper = MultiQrCollector::new();
    collector_tamper.add_fragment(&frags[0]).unwrap();
    // Fragmento 2 con chunk adulterado pero con el mismo hash8 de sesión
    let hash8 = frags[1].split('/').nth(3).unwrap();
    let tampered_frag = format!("GID01/P2/2/{hash8}/TAMPERED_PAYLOAD_CHUNK");
    let err = collector_tamper.add_fragment(&tampered_frag).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-MAINT-005 (Cobertura de VerificationRequest con eph_pub y rechazos de JSON)
#[test]
fn verification_request_eph_pub_and_missing_json_fields() {
    use gravital_id_keys::{HolderBinding, KeyStore, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    let mut keystore = SoftwareKeyStore::new(SeededRng::new(1234));
    let handle = keystore.generate_key::<HolderBinding>().expect("key");
    let eph_jwk = keystore.public_key(&handle).expect("pubkey");

    let req = VerificationRequest::new(
        "v1",
        "nonce_16_bytes_min!!",
        "aud1",
        UnixTime::from_seconds(100),
        UnixTime::from_seconds(200),
        minimal_dcql_query(),
        Some(eph_jwk),
    )
    .expect("valid request with eph_pub");

    let cloned = req.clone();
    assert_eq!(req, cloned);
    let _ = format!("{req:?}");

    let json_bytes = req.to_json_bytes().expect("serialize");
    let parsed = VerificationRequest::from_json_bytes(&json_bytes).expect("deserialize");
    assert!(parsed.eph_pub.is_some());

    // Faltan campos individuales en JSON
    let base_json = format!(
        r#"{{"type":"{VERIFICATION_REQUEST_TYPE}","verifier_id":"v1","nonce":"nonce_16_bytes_min!!","audience":"aud1","issued_at":100,"expires_at":200,"query":{{"credentials":[]}}}}"#
    );

    // Tipo erróneo
    let wrong_type = base_json.replace(VERIFICATION_REQUEST_TYPE, "unsupported-type-v9");
    let err = VerificationRequest::from_json_bytes(wrong_type.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedProtocolVersion);

    // Falta verifier_id
    let missing_v_id = base_json.replace(r#""verifier_id":"v1","#, "");
    let err = VerificationRequest::from_json_bytes(missing_v_id.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Falta audience
    let missing_aud = base_json.replace(r#""audience":"aud1","#, "");
    let err = VerificationRequest::from_json_bytes(missing_aud.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Falta issued_at
    let missing_iat = base_json.replace(r#""issued_at":100,"#, "");
    let err = VerificationRequest::from_json_bytes(missing_iat.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // issued_at no numérico
    let bad_iat = base_json.replace(r#""issued_at":100"#, r#""issued_at":"not_a_number""#);
    let err = VerificationRequest::from_json_bytes(bad_iat.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Falta expires_at
    let missing_exp = base_json.replace(r#""expires_at":200,"#, "");
    let err = VerificationRequest::from_json_bytes(missing_exp.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // expires_at no numérico
    let bad_exp = base_json.replace(r#""expires_at":200"#, r#""expires_at":"not_a_number""#);
    let err = VerificationRequest::from_json_bytes(bad_exp.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Falta query
    let missing_query = base_json.replace(r#","query":{"credentials":[]}"#, "");
    let err = VerificationRequest::from_json_bytes(missing_query.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // eph_pub malformado
    let bad_eph = format!(
        r#"{{"type":"{VERIFICATION_REQUEST_TYPE}","verifier_id":"v1","nonce":"nonce_16_bytes_min!!","audience":"aud1","issued_at":100,"expires_at":200,"query":{{"credentials":[]}},"eph_pub":"invalid_jwk"}}"#
    );
    let err = VerificationRequest::from_json_bytes(bad_eph.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-MAINT-005 (Cobertura de ramas de transcodificación CBOR y fallos de formato)
#[test]
fn transcoding_edge_cases_and_error_branches() {
    // 1. SD-JWT vacío
    let err = transcode_sd_jwt_to_cbor("").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // 2. Issuer JWT con menos de 3 partes
    let err = transcode_sd_jwt_to_cbor("part1.part2~").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // 3. Issuer JWT con más de 3 partes
    let err = transcode_sd_jwt_to_cbor("p1.p2.p3.p4~").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedSdJwt);

    // 4. KB-JWT con formato inválido (ej. 2 partes con puntos o 4 partes)
    let header_b64 = "eyJhbGciOiJFUzI1NiJ9";
    let payload_b64 = "eyJpc3MiOiJleCJ9";
    let sig64 = gravital_id_codec::base64url::encode(&[0x11; 64]);
    let valid_issuer_jwt = format!("{header_b64}.{payload_b64}.{sig64}");

    // KB-JWT con 2 partes
    let bad_kb_2 = format!("{valid_issuer_jwt}~kbpart1.kbpart2");
    let err = transcode_sd_jwt_to_cbor(&bad_kb_2).unwrap_err();
    assert_eq!(err.code, ErrorCode::KeyBindingFailed);

    // KB-JWT con 4 partes
    let bad_kb_4 = format!("{valid_issuer_jwt}~k1.k2.k3.k4");
    let err = transcode_sd_jwt_to_cbor(&bad_kb_4).unwrap_err();
    assert_eq!(err.code, ErrorCode::KeyBindingFailed);

    // KB-JWT con firma != 64 bytes
    let bad_kb_sig = format!("{valid_issuer_jwt}~{header_b64}.{payload_b64}.shortsig");
    let err = transcode_sd_jwt_to_cbor(&bad_kb_sig).unwrap_err();
    assert_eq!(err.code, ErrorCode::KeyBindingFailed);

    // 5. reconstruct_sd_jwt_from_cbor con elementos que no son bytes
    // Estructura válida: [version, issuer_h, issuer_p, issuer_sig, disclosures, kb_h, kb_p, kb_sig]
    let make_cbor = |idx_to_spoil: usize| -> Vec<u8> {
        let mut out = vec![0x88]; // array de 8 elementos
        for i in 0..8 {
            if i == idx_to_spoil {
                out.push(0x18); // uint en vez de bstr o array
                out.push(123);
            } else if i == 0 {
                out.push(0x01); // version 1
            } else if i == 4 {
                out.push(0x80); // array vacío para disclosures
            } else {
                out.push(0x40); // bstr vacío
            }
        }
        out
    };

    // Item 1 no bytes
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(1))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Item 2 no bytes
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(2))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Item 3 no bytes
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(3))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Item 4 no array
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(4))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Item 5 no bytes
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(5))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Item 6 no bytes
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(6))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Item 7 no bytes
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&make_cbor(7))
            .unwrap_err()
            .code,
        ErrorCode::MalformedMessage
    );

    // Disclosure en item 4 que no sea bytes (array de 1 uint: 0x81, 0x18, 123)
    let spoil_disc = vec![
        0x88, 0x01, 0x40, 0x40, 0x40, 0x81, 0x18, 123, 0x40, 0x40, 0x40,
    ];
    assert_eq!(
        reconstruct_sd_jwt_from_cbor(&spoil_disc).unwrap_err().code,
        ErrorCode::MalformedMessage
    );

    // 6. Base45 decoding errors
    // Prefijo inválido
    let err = decode_presentation_from_base45("UNKNOWN_PREFIX:ABCD").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Caracteres Base45 inválidos
    let err = decode_presentation_from_base45("GID1:INVALID_CHARS!@#$%").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);

    // Base45 válido pero no es stream zlib válido
    let err = decode_presentation_from_base45("GID1:00").unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}
