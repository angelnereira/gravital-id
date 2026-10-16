//! Pruebas de segmentación Multi-QR, acumulador de fragmentos y presupuesto de tamaño en CI (REQ-PRES-005, REQ-PRES-006, REQ-PERF-003, PROTOCOL.md §3.3).
//!
//! Trazabilidad:
//! - `REQ-PRES-005`: Transporte QR bidireccional offline entre verificador y titular.
//! - `REQ-PRES-006`: Segmentación y reconstrucción determinista multi-código con verificación de integridad SHA-256.
//! - `REQ-PERF-003`: Presupuesto de tamaño: presentación típica $\le 1.200$ caracteres Base45 (cabe en un único código QR).
//! - `ADR-0011`: Formato de fragmentación `GID01/P` y compatibilidad con `PIP1/M/`.
//! - `INV-01`: Cero llamadas de red.
//! - `INV-05`: Rechazo fail-closed ante hashes discrepantes, índices fuera de rango o fragmentos incompletos (`GID-E1008`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_codec::json::Value;
use gravital_id_credential::SdJwtVcBuilder;
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_holder::{CredentialQuery, HolderWallet, RequestedClaim};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_protocol::offline_multi_qr::{
    segment_presentation, MultiQrCollector, MAX_SINGLE_QR_CHARS, MULTI_QR_CANONICAL_PREFIX,
    MULTI_QR_LEGACY_PREFIX,
};
use gravital_id_protocol::offline_transcoding::encode_presentation_to_base45;
use gravital_id_storage::InMemoryStorageBackend;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime, Vct};

// Verifies: REQ-PRES-005, REQ-PERF-003 (Carga útil dentro de presupuesto de QR único <= 1200 chars)
#[test]
fn single_qr_threshold_under_budget() {
    let small_payload = "GID1:0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let segments = segment_presentation(small_payload).expect("segmentation");
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0], small_payload);

    // Exactamente 1.200 caracteres
    let exact_1200 = "G".repeat(MAX_SINGLE_QR_CHARS);
    let segments_1200 = segment_presentation(&exact_1200).expect("segmentation");
    assert_eq!(segments_1200.len(), 1);
    assert_eq!(segments_1200[0], exact_1200);
}

// Verifies: REQ-PRES-006, ADR-0011 (Segmentación Multi-QR cuando supera 1.200 caracteres)
#[test]
fn multi_qr_segmentation_over_budget() {
    // 1.201 caracteres -> requiere fragmentación
    let payload_1201 = "G".repeat(1201);
    let fragments = segment_presentation(&payload_1201).expect("segmentation");

    assert_eq!(fragments.len(), 2);
    for (idx, frag) in fragments.iter().enumerate() {
        assert!(frag.starts_with(MULTI_QR_CANONICAL_PREFIX));
        let expected_header_prefix = format!("{MULTI_QR_CANONICAL_PREFIX}{}/2/", idx + 1);
        assert!(frag.starts_with(&expected_header_prefix));
    }

    // Reensamblaje secuencial en orden
    let mut collector = MultiQrCollector::new();
    assert_eq!(collector.expected_total(), None);
    assert_eq!(collector.received_count(), 0);

    let res1 = collector.add_fragment(&fragments[0]).expect("add frag 1");
    assert!(res1.is_none());
    assert_eq!(collector.expected_total(), Some(2));
    assert_eq!(collector.received_count(), 1);
    assert!(!collector.is_complete());

    let res2 = collector.add_fragment(&fragments[1]).expect("add frag 2");
    assert_eq!(collector.received_count(), 2);
    assert!(collector.is_complete());

    let full = res2.expect("complete payload");
    assert_eq!(full, payload_1201);
}

// Verifies: REQ-PRES-006 (Reensamblaje desordenado e idempotente de fragmentos Multi-QR)
#[test]
fn multi_qr_out_of_order_and_idempotent_reassembly() {
    // 2.500 caracteres -> ceil(2500 / 900) = 3 fragmentos
    let payload_2500 = "M".repeat(2500);
    let fragments = segment_presentation(&payload_2500).expect("segmentation");
    assert_eq!(fragments.len(), 3);

    let mut collector = MultiQrCollector::new();

    // Llega fragmento 3 primero
    assert!(collector.add_fragment(&fragments[2]).unwrap().is_none());
    assert_eq!(collector.received_count(), 1);

    // Duplicado de fragmento 3 (escaneo repetido por el usuario)
    assert!(collector.add_fragment(&fragments[2]).unwrap().is_none());
    assert_eq!(collector.received_count(), 1);

    // Llega fragmento 1
    assert!(collector.add_fragment(&fragments[0]).unwrap().is_none());
    assert_eq!(collector.received_count(), 2);

    // Llega fragmento 2 (completa la captura)
    let full = collector
        .add_fragment(&fragments[1])
        .unwrap()
        .expect("done");
    assert_eq!(full, payload_2500);

    // Finalize devuelve la misma cadena
    let finalized = collector.finalize().expect("finalized");
    assert_eq!(finalized, payload_2500);
}

// Verifies: REQ-PRES-006, ADR-0011 (Compatibilidad con prefijo legado PIP1/M/)
#[test]
fn multi_qr_legacy_prefix_acceptance() {
    let payload = "L".repeat(1500);
    let fragments = segment_presentation(&payload).expect("segment");

    // Convertir fragmentos canónicos a prefijo legado
    let legacy_fragments: Vec<String> = fragments
        .iter()
        .map(|f| f.replace(MULTI_QR_CANONICAL_PREFIX, MULTI_QR_LEGACY_PREFIX))
        .collect();

    let mut collector = MultiQrCollector::new();
    assert!(collector
        .add_fragment(&legacy_fragments[0])
        .unwrap()
        .is_none());
    let full = collector
        .add_fragment(&legacy_fragments[1])
        .unwrap()
        .expect("done");
    assert_eq!(full, payload);
}

// Verifies: REQ-PRES-006 (Detección de manipulación o corrupción por hash SHA-256)
#[test]
fn multi_qr_tampered_payload_integrity_rejected() {
    let payload = "T".repeat(1500);
    let fragments = segment_presentation(&payload).expect("segment");

    // Alterar el contenido del segundo fragmento manteniendo la cabecera
    let parts: Vec<&str> = fragments[1].splitn(4, '/').collect();
    let tampered_frag = format!("{}/{}/{}/TAMPERED_CONTENT", parts[0], parts[1], parts[2]);

    let mut collector = MultiQrCollector::new();
    collector.add_fragment(&fragments[0]).unwrap();
    let err = collector.add_fragment(&tampered_frag).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedMessage);
}

// Verifies: REQ-PRES-006 (Finalización incompleta por timeout retorna GID-E1008)
#[test]
fn multi_qr_incomplete_finalization_returns_multi_qr_incomplete() {
    let payload = "I".repeat(1500);
    let fragments = segment_presentation(&payload).expect("segment");

    let mut collector = MultiQrCollector::new();
    collector.add_fragment(&fragments[0]).unwrap(); // Falta el fragmento 2

    let err = collector.finalize().unwrap_err();
    assert_eq!(err.code, ErrorCode::MultiQrIncomplete);
}

// Verifies: REQ-PERF-003 (Presupuesto de tamaño en CI: credencial estándar cabe en un único QR <= 1200 chars)
#[test]
fn standard_credential_presentation_stays_within_single_qr_budget() {
    // Generar credencial típica con 5 claims selectivos
    let rng_holder = SeededRng::new(8001);
    let mut holder_keystore = SoftwareKeyStore::new(rng_holder);
    let holder_handle = holder_keystore
        .generate_key::<HolderBinding>()
        .expect("holder key");
    let holder_pub = holder_keystore.public_key(&holder_handle).expect("pub");

    let now = UnixTime::from_seconds(1700000000);
    let rng_issuer = SeededRng::new(8002);
    let mut issuer_keystore = SoftwareKeyStore::new(rng_issuer);
    let issuer_handle = issuer_keystore
        .generate_key::<IssuerSigning>()
        .expect("issuer key");

    let rng_emit = SeededRng::new(8003);
    let issued = SdJwtVcBuilder::new(
        "https://issuer.gravital.id",
        Vct::parse("urn:gravital-id:vct:pip-personal-v1").expect("vct"),
        now,
    )
    .expect("builder")
    .exp(UnixTime::from_seconds(now.as_seconds() + 3600 * 24 * 365))
    .cnf_jwk(holder_pub)
    .status_list(42, "https://status.gravital.id/sl/1")
    .expect("status")
    .add_sd_claim("given_name", Value::String("Angel".into()))
    .add_sd_claim("family_name", Value::String("Nereira".into()))
    .add_sd_claim("age_over_18", Value::Bool(true))
    .issue_signed(&issuer_keystore, &issuer_handle, None, &rng_emit)
    .expect("issue");

    // Guardar en wallet del titular
    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x55u8; 32]);
    let rng_wallet = SeededRng::new(8004);
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

    // Solicitud DCQL solicitando 2 claims (mayoría de edad cívica según pip-personal-v1 §1)
    let query = CredentialQuery::new(
        "checkout_session_99",
        vec![Vct::parse("urn:gravital-id:vct:pip-personal-v1").expect("vct")],
        vec![
            RequestedClaim::required("given_name"),
            RequestedClaim::required("age_over_18"),
        ],
    )
    .expect("query");

    let plan = wallet.prepare_disclosure_plan(&query, None).expect("plan");
    let presentation = wallet
        .confirm_presentation(
            &plan,
            "verifier:pos-01",
            "nonce_16_bytes!!",
            now,
            &holder_keystore,
            &holder_handle,
        )
        .expect("presentation");

    // Codificar a Base45 comprimido para transporte QR
    let b45_encoded = encode_presentation_to_base45(&presentation).expect("encode base45");

    // REQ-PERF-003: Presupuesto normativo <= 1.200 caracteres Base45
    assert!(
        b45_encoded.len() <= MAX_SINGLE_QR_CHARS,
        "presentation size {} exceeded 1.200 chars budget (REQ-PERF-003)",
        b45_encoded.len()
    );

    // Debe segmentarse en exactamente 1 único código QR
    let segments = segment_presentation(&b45_encoded).expect("segmentation");
    assert_eq!(
        segments.len(),
        1,
        "standard presentation should not require multi-QR segmentation"
    );
}
