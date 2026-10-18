#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas unitarias y de integración para constructores de Token Status List y Manifiesto (F7.T05).
//!
//! Trazabilidad:
//! - **REQ-ISS-003:** Gestión de listas de estado por el emisor.
//! - **REQ-STAT-001:** Token Status List en formato JWT.
//! - **REQ-STAT-002:** Tamaño mínimo normativo (>= 131.072 bits / entradas).
//! - **REQ-STAT-005:** Publicación direccionada por contenido (URI con digest SHA-256).
//! - **REQ-STAT-007:** Estados válido, revocado y suspendido.
//! - **REQ-STAT-008:** Manifiesto de estado firmado con versión monotónica incremental.
//! - **INV-05:** Fail-closed ante cualquier parámetro inválido.

extern crate alloc;

use gravital_id_status::{
    IssuerStatusManifestBuilder, LocalStatusSigner, StatusListVerifier, StatusManifestVerifier,
    StatusSigner, TokenStatus, TokenStatusListBuilder, MIN_STATUS_LIST_ENTRIES,
};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime};

#[test]
fn test_builder_minimum_capacity_enforced() {
    // // Verifies: REQ-STAT-002 (Tamaño mínimo normativo >= 131.072 entradas)
    assert!(TokenStatusListBuilder::new(1, 0).is_err());
    assert!(TokenStatusListBuilder::new(1, 100).is_err());
    assert!(TokenStatusListBuilder::new(1, 10_000).is_err());
    assert!(TokenStatusListBuilder::new(1, MIN_STATUS_LIST_ENTRIES - 1).is_err());

    let err = TokenStatusListBuilder::new(1, 131_071).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedStatusList);
    assert!(err.message.contains("minimum allowed"));

    // Capacidad exacta mínima es aceptada
    let builder = TokenStatusListBuilder::new(1, MIN_STATUS_LIST_ENTRIES);
    assert!(builder.is_ok());
    assert_eq!(builder.unwrap().capacity(), MIN_STATUS_LIST_ENTRIES);

    // Capacidades mayores son aceptadas
    let builder_large = TokenStatusListBuilder::new(1, 262_144);
    assert!(builder_large.is_ok());
}

#[test]
fn test_builder_unsupported_bits_per_entry() {
    // Solo 1 y 2 bits por entrada son admitidos
    assert!(TokenStatusListBuilder::new(0, MIN_STATUS_LIST_ENTRIES).is_err());
    assert!(TokenStatusListBuilder::new(3, MIN_STATUS_LIST_ENTRIES).is_err());
    assert!(TokenStatusListBuilder::new(4, MIN_STATUS_LIST_ENTRIES).is_err());
    assert!(TokenStatusListBuilder::new(8, MIN_STATUS_LIST_ENTRIES).is_err());

    assert!(TokenStatusListBuilder::new(1, MIN_STATUS_LIST_ENTRIES).is_ok());
    assert!(TokenStatusListBuilder::new(2, MIN_STATUS_LIST_ENTRIES).is_ok());
}

#[test]
fn test_builder_1_bit_lifecycle() {
    // // Verifies: REQ-STAT-001, REQ-STAT-007
    let mut builder = TokenStatusListBuilder::new(1, MIN_STATUS_LIST_ENTRIES).unwrap();

    // Estado inicial: todo válido
    assert_eq!(builder.get_status(0).unwrap(), TokenStatus::Valid);
    assert_eq!(builder.get_status(500).unwrap(), TokenStatus::Valid);
    assert_eq!(
        builder
            .get_status((MIN_STATUS_LIST_ENTRIES - 1) as u64)
            .unwrap(),
        TokenStatus::Valid
    );

    // Modificar estados
    builder.set_status(0, TokenStatus::Revoked).unwrap();
    builder.set_status(7, TokenStatus::Revoked).unwrap();
    builder.set_status(8, TokenStatus::Revoked).unwrap();
    builder
        .set_status((MIN_STATUS_LIST_ENTRIES - 1) as u64, TokenStatus::Revoked)
        .unwrap();

    assert_eq!(builder.get_status(0).unwrap(), TokenStatus::Revoked);
    assert_eq!(builder.get_status(1).unwrap(), TokenStatus::Valid);
    assert_eq!(builder.get_status(7).unwrap(), TokenStatus::Revoked);
    assert_eq!(builder.get_status(8).unwrap(), TokenStatus::Revoked);
    assert_eq!(
        builder
            .get_status((MIN_STATUS_LIST_ENTRIES - 1) as u64)
            .unwrap(),
        TokenStatus::Revoked
    );

    // Revertir a válido
    builder.set_status(7, TokenStatus::Valid).unwrap();
    assert_eq!(builder.get_status(7).unwrap(), TokenStatus::Valid);

    // Intentar suspender en lista de 1 bit debe fallar (REQ-STAT-007)
    let err = builder.set_status(5, TokenStatus::Suspended).unwrap_err();
    assert_eq!(err.code, ErrorCode::MalformedStatusList);

    // Fuera de rango
    let err_oob = builder
        .set_status(MIN_STATUS_LIST_ENTRIES as u64, TokenStatus::Revoked)
        .unwrap_err();
    assert_eq!(err_oob.code, ErrorCode::StatusIndexOutOfRange);
    assert_eq!(
        builder
            .get_status(MIN_STATUS_LIST_ENTRIES as u64)
            .unwrap_err()
            .code,
        ErrorCode::StatusIndexOutOfRange
    );

    // Firma y auto-verificación
    let rng = SeededRng::new(42);
    let signer = LocalStatusSigner::generate_with_rng(Some("kid-status-1".into()), &rng).unwrap();

    builder
        .with_issuer("https://issuer.example.gov")
        .with_issued_at(UnixTime::from_seconds(1_700_000_000))
        .with_expires_at(UnixTime::from_seconds(1_700_100_000));

    let signed = builder.sign(&signer).expect("signing succeeds");
    assert_eq!(signed.bits_per_entry(), 1);
    assert_eq!(signed.capacity(), MIN_STATUS_LIST_ENTRIES);

    // Parseo independiente con el verificador del núcleo
    let parsed = StatusListVerifier::parse(signed.jwt()).expect("core parser accepts JWT");
    assert_eq!(parsed.bits_per_entry(), 1);
    assert_eq!(parsed.status_of(0).unwrap(), TokenStatus::Revoked);
    assert_eq!(parsed.status_of(1).unwrap(), TokenStatus::Valid);
    assert_eq!(parsed.status_of(7).unwrap(), TokenStatus::Valid);
    assert_eq!(parsed.status_of(8).unwrap(), TokenStatus::Revoked);
    assert_eq!(
        parsed
            .status_of((MIN_STATUS_LIST_ENTRIES - 1) as u64)
            .unwrap(),
        TokenStatus::Revoked
    );
}

#[test]
fn test_builder_2_bits_lifecycle() {
    // // Verifies: REQ-STAT-007 (Soporte de estados válido, revocado y suspendido)
    let mut builder = TokenStatusListBuilder::new(2, MIN_STATUS_LIST_ENTRIES).unwrap();

    builder.set_status(10, TokenStatus::Suspended).unwrap();
    builder.set_status(20, TokenStatus::Revoked).unwrap();
    builder.set_status(30, TokenStatus::Valid).unwrap();

    assert_eq!(builder.get_status(10).unwrap(), TokenStatus::Suspended);
    assert_eq!(builder.get_status(20).unwrap(), TokenStatus::Revoked);
    assert_eq!(builder.get_status(30).unwrap(), TokenStatus::Valid);

    // Cambiar de suspendido a revocado
    builder.set_status(10, TokenStatus::Revoked).unwrap();
    assert_eq!(builder.get_status(10).unwrap(), TokenStatus::Revoked);

    // Cambiar de revocado a válido
    builder.set_status(10, TokenStatus::Valid).unwrap();
    assert_eq!(builder.get_status(10).unwrap(), TokenStatus::Valid);

    // Firma y verificación
    let rng = SeededRng::new(99);
    let signer = LocalStatusSigner::generate_with_rng(Some("kid-status-2".into()), &rng).unwrap();

    let signed = builder.sign(&signer).unwrap();
    let parsed = StatusListVerifier::parse(signed.jwt()).unwrap();
    assert_eq!(parsed.bits_per_entry(), 2);
    assert_eq!(parsed.status_of(10).unwrap(), TokenStatus::Valid);
    assert_eq!(parsed.status_of(20).unwrap(), TokenStatus::Revoked);
}

#[test]
fn test_content_addressed_uri_and_hash() {
    // // Verifies: REQ-STAT-005 (Distribución direccionada por contenido con digest SHA-256)
    let builder = TokenStatusListBuilder::new(1, MIN_STATUS_LIST_ENTRIES).unwrap();
    let rng = SeededRng::new(123);
    let signer = LocalStatusSigner::generate_with_rng(Some("kid-1".into()), &rng).unwrap();

    let signed = builder.sign(&signer).unwrap();
    assert_eq!(signed.sha256_hex().len(), 64);
    assert!(signed.sha256_hex().chars().all(|c| c.is_ascii_hexdigit()));

    let uri1 = signed.content_addressed_uri("https://cdn.example.gov/status");
    let uri2 = signed.content_addressed_uri("https://cdn.example.gov/status/");
    assert_eq!(uri1, uri2);
    assert_eq!(
        uri1,
        format!("https://cdn.example.gov/status/{}.jwt", signed.sha256_hex())
    );
}

#[test]
fn test_manifest_builder_nominal_and_verification() {
    // // Verifies: REQ-STAT-008 (Manifiesto firmado con versión monotónica incremental)
    let rng = SeededRng::new(777);
    let signer = LocalStatusSigner::generate_with_rng(Some("kid-manifest".into()), &rng).unwrap();

    // Generar una Token Status List previa
    let mut list_builder = TokenStatusListBuilder::new(1, MIN_STATUS_LIST_ENTRIES).unwrap();
    list_builder.set_status(42, TokenStatus::Revoked).unwrap();
    let signed_list = list_builder.sign(&signer).unwrap();
    let list_uri = signed_list.content_addressed_uri("https://cdn.example.gov/lists");

    // Construir Manifiesto de Estado
    let mut manifest_builder =
        IssuerStatusManifestBuilder::new("iss-panama-te", 101).expect("valid builder");
    manifest_builder
        .with_issued_at(UnixTime::from_seconds(1_700_000_000))
        .with_valid_until(UnixTime::from_seconds(1_700_864_000))
        .add_status_list(
            "sl-personal-v1",
            &list_uri,
            signed_list.sha256_hex(),
            Some(UnixTime::from_seconds(1_700_864_000)),
        )
        .expect("add status list succeeds");

    let signed_manifest = manifest_builder.sign(&signer).expect("manifest sign ok");
    assert_eq!(signed_manifest.manifest_version(), 101);
    assert_eq!(signed_manifest.manifest_hash_hex().len(), 64);
    assert_eq!(signed_manifest.manifest_hash().len(), 32);

    // Auto-verificación y comprobación contra la clave pública
    let parsed_manifest =
        StatusManifestVerifier::parse(signed_manifest.jwt()).expect("parse manifest");
    assert_eq!(parsed_manifest.issuer_id(), "iss-panama-te");
    assert_eq!(parsed_manifest.manifest_version(), 101);
    assert_eq!(parsed_manifest.lists().len(), 1);

    StatusManifestVerifier::verify_signature(signed_manifest.jwt(), signer.public_key())
        .expect("signature verifies");

    // Comprobación de digest de lista vinculada (REQ-STAT-005, REQ-STAT-008)
    StatusManifestVerifier::check_list_digest(
        &parsed_manifest,
        &list_uri,
        signed_list.sha256_hex(),
    )
    .expect("digest matches");

    // Monotonic version check (REQ-STAT-008)
    assert!(parsed_manifest.check_monotonic_version(Some(100)).is_ok());
    assert!(parsed_manifest.check_monotonic_version(Some(101)).is_err());
    assert!(parsed_manifest.check_monotonic_version(Some(102)).is_err());
}

#[test]
fn test_manifest_builder_error_conditions() {
    // // Verifies: INV-05 (Fail-closed ante datos inválidos)
    assert!(IssuerStatusManifestBuilder::new("", 1).is_err());
    assert!(IssuerStatusManifestBuilder::new("   ", 1).is_err());

    let mut builder = IssuerStatusManifestBuilder::new("iss-1", 1).unwrap();
    builder
        .with_issued_at(UnixTime::from_seconds(1000))
        .with_valid_until(UnixTime::from_seconds(500)); // Incoherente: valid_until < issued_at

    let rng = SeededRng::new(1);
    let signer = LocalStatusSigner::generate_with_rng(None, &rng).unwrap();
    assert!(builder.sign(&signer).is_err());

    // Validaciones de entradas de lista
    let mut builder2 = IssuerStatusManifestBuilder::new("iss-2", 2).unwrap();
    assert!(builder2
        .add_status_list("", "https://example.com/l.jwt", "a".repeat(64), None)
        .is_err());
    assert!(builder2
        .add_status_list("sl-1", "", "a".repeat(64), None)
        .is_err());
    assert!(builder2
        .add_status_list("sl-1", "https://example.com/l.jwt", "demasiado-corto", None)
        .is_err());
    assert!(builder2
        .add_status_list("sl-1", "https://example.com/l.jwt", "g".repeat(64), None) // 'g' no es hex
        .is_err());
}

#[test]
fn test_signer_and_builder_accessors_and_edge_cases() {
    let rng = SeededRng::new(42);
    let signer =
        LocalStatusSigner::generate_with_rng(Some("kid-status-test".into()), &rng).unwrap();

    assert_eq!(signer.kid(), Some("kid-status-test"));
    assert!(!signer.secret_key().expose_secret().iter().all(|&b| b == 0));
    assert!(!signer.public_key().x().is_empty());

    // LocalStatusSigner::new a partir de clave secreta existente
    let cloned_signer =
        LocalStatusSigner::new(Some("kid-2".into()), signer.secret_key().clone()).unwrap();
    assert_eq!(cloned_signer.kid(), Some("kid-2"));
    assert_eq!(cloned_signer.public_key().x(), signer.public_key().x());

    // Builder getters
    let builder = TokenStatusListBuilder::new(2, MIN_STATUS_LIST_ENTRIES).unwrap();
    assert_eq!(builder.bits_per_entry(), 2);
    assert_eq!(builder.capacity(), MIN_STATUS_LIST_ENTRIES);
    assert_eq!(builder.raw_bitmap().len(), MIN_STATUS_LIST_ENTRIES / 4);

    let signed_list = builder.sign(&signer).unwrap();
    assert_eq!(signed_list.bits_per_entry(), 2);
    assert_eq!(signed_list.capacity(), MIN_STATUS_LIST_ENTRIES);
    assert_eq!(signed_list.sha256_digest().len(), 32);
    assert_eq!(signed_list.sha256_hex().len(), 64);
    assert!(!signed_list.jwt().is_empty());

    // Manifest builder getters
    let mut manifest_builder = IssuerStatusManifestBuilder::new("iss-acc", 5).unwrap();
    assert_eq!(manifest_builder.manifest_version(), 5);

    let sha_dummy = "a".repeat(64);
    manifest_builder
        .add_status_list("sl-1", "https://cdn.example/1", &sha_dummy, None)
        .unwrap();

    // Sign manifest and verify SignedStatusManifest getters
    let signed_manifest = manifest_builder.sign(&signer).unwrap();
    assert!(!signed_manifest.jwt().is_empty());
    assert_eq!(signed_manifest.manifest_version(), 5);
    assert_eq!(signed_manifest.manifest().issuer_id(), "iss-acc");
    assert!(!signed_manifest.manifest_hash().iter().all(|&b| b == 0));
    assert_eq!(signed_manifest.manifest_hash_hex().len(), 64);
}
