#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de ciclo de vida de asignación aleatoria, listas de estado y manifiestos (F7.T05).
//!
//! Trazabilidad:
//! - **REQ-ISS-003:** El emisor DEBE gestionar listas de estado: asignación, actualización y publicación periódica.
//! - **REQ-STAT-002:** Asignación aleatoria de índices sobre listas con capacidad mínima normada (>= 131.072).
//! - **REQ-STAT-005:** Publicación direccionada por contenido vinculada por digest SHA-256.
//! - **REQ-STAT-006:** Compromisos de manifiesto listos para anclaje en `StatusAnchor.sol`.
//! - **REQ-STAT-008:** Manifiesto firmado con versión monotónica incremental.
//! - **INV-05:** Fail-closed ante cualquier parámetro o estado inválido.

extern crate alloc;

use alloc::collections::BTreeSet;

use gravital_id_issuer::{IssuerStatusManager, StatusIndexAllocator};
use gravital_id_status::{
    LocalStatusSigner, StatusListVerifier, StatusManifestVerifier, TokenStatus,
    MIN_STATUS_LIST_ENTRIES,
};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime};

#[test]
fn test_allocator_enforces_minimum_capacity() {
    // // Verifies: REQ-STAT-002 (Capacidad mínima de 131.072 entradas)
    assert!(StatusIndexAllocator::new(0).is_err());
    assert!(StatusIndexAllocator::new(100).is_err());
    assert!(StatusIndexAllocator::new(MIN_STATUS_LIST_ENTRIES - 1).is_err());

    let allocator = StatusIndexAllocator::new(MIN_STATUS_LIST_ENTRIES).expect("nominal capacity");
    assert_eq!(allocator.capacity(), MIN_STATUS_LIST_ENTRIES);
    assert_eq!(allocator.allocated_count(), 0);
    assert_eq!(allocator.available_count(), MIN_STATUS_LIST_ENTRIES);
    assert!(!allocator.is_full());
}

#[test]
fn test_allocator_random_allocation_uniformity_and_no_collision() {
    // // Verifies: REQ-STAT-002, REQ-ISS-003, P-09 (Asignación aleatoria no correlacionada)
    let mut allocator = StatusIndexAllocator::new(MIN_STATUS_LIST_ENTRIES).unwrap();
    let rng = SeededRng::new(12345);

    let mut seen = BTreeSet::new();
    let to_allocate = 1000;

    for _ in 0..to_allocate {
        let index = allocator.allocate_random(&rng).expect("allocation ok");
        assert!(
            (index as usize) < MIN_STATUS_LIST_ENTRIES,
            "allocated index {index} out of capacity"
        );
        assert!(seen.insert(index), "Collision detected for index {index}!");
        assert!(allocator.is_allocated(index));
    }

    assert_eq!(allocator.allocated_count(), to_allocate);
    assert_eq!(
        allocator.available_count(),
        MIN_STATUS_LIST_ENTRIES - to_allocate
    );

    // Liberar el primer índice
    let first = *seen.iter().next().unwrap();
    allocator.release(first).expect("release succeeds");
    assert!(!allocator.is_allocated(first));
    assert_eq!(allocator.allocated_count(), to_allocate - 1);

    // Volver a marcar asignado
    allocator.mark_allocated(first).expect("mark succeeds");
    assert!(allocator.is_allocated(first));
    assert_eq!(allocator.allocated_count(), to_allocate);
}

#[test]
fn test_allocator_boundary_and_error_conditions() {
    // // Verifies: INV-10 (Límites de índice y errores controlados)
    let mut allocator = StatusIndexAllocator::new(MIN_STATUS_LIST_ENTRIES).unwrap();

    let err_oob = allocator
        .release(MIN_STATUS_LIST_ENTRIES as u64)
        .unwrap_err();
    assert_eq!(err_oob.code, ErrorCode::StatusIndexOutOfRange);

    let err_mark_oob = allocator
        .mark_allocated(MIN_STATUS_LIST_ENTRIES as u64)
        .unwrap_err();
    assert_eq!(err_mark_oob.code, ErrorCode::StatusIndexOutOfRange);

    assert!(!allocator.is_allocated(MIN_STATUS_LIST_ENTRIES as u64));
}

#[test]
fn test_issuer_status_manager_nominal_flow() {
    // // Verifies: REQ-ISS-003, REQ-STAT-007
    let mut manager =
        IssuerStatusManager::new("iss-panama-tribunal-electoral", 1).expect("manager new");
    assert_eq!(manager.issuer_id(), "iss-panama-tribunal-electoral");
    assert_eq!(manager.manifest_version(), 1);

    // Registrar dos listas de estado: una de 1 bit y otra de 2 bits
    manager
        .register_status_list(
            "sl-1",
            1,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example.gov/sl1",
        )
        .expect("sl-1 ok");
    manager
        .register_status_list(
            "sl-2",
            2,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example.gov/sl2",
        )
        .expect("sl-2 ok");

    assert_eq!(manager.list_count(), 2);

    // Intentar registrar duplicado debe fallar
    assert!(manager
        .register_status_list(
            "sl-1",
            1,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example.gov/sl1"
        )
        .is_err());

    let rng = SeededRng::new(555);

    // Asignar en sl-1
    let alloc1 = manager
        .allocate_for_credential(Some("sl-1"), &rng)
        .expect("alloc sl-1");
    assert!(alloc1.uri.contains("sl1"));

    // Asignar en sl-2
    let alloc2 = manager
        .allocate_for_credential(Some("sl-2"), &rng)
        .expect("alloc sl-2");
    assert!(alloc2.uri.contains("sl2"));

    // Asignar automáticamente en la primera disponible
    let alloc_auto = manager
        .allocate_for_credential(None, &rng)
        .expect("alloc auto");
    assert!(alloc_auto.idx < MIN_STATUS_LIST_ENTRIES as u64);

    // Estados iniciales
    assert_eq!(
        manager.status_of("sl-1", alloc1.idx).unwrap(),
        TokenStatus::Valid
    );
    assert_eq!(
        manager.status_of("sl-2", alloc2.idx).unwrap(),
        TokenStatus::Valid
    );

    // Revocar en sl-1
    manager.revoke("sl-1", alloc1.idx).expect("revoke ok");
    assert_eq!(
        manager.status_of("sl-1", alloc1.idx).unwrap(),
        TokenStatus::Revoked
    );

    // Suspender en sl-2 (permitido en 2 bits)
    manager.suspend("sl-2", alloc2.idx).expect("suspend ok");
    assert_eq!(
        manager.status_of("sl-2", alloc2.idx).unwrap(),
        TokenStatus::Suspended
    );

    // Reactivar en sl-2
    manager
        .reactivate("sl-2", alloc2.idx)
        .expect("reactivate ok");
    assert_eq!(
        manager.status_of("sl-2", alloc2.idx).unwrap(),
        TokenStatus::Valid
    );

    // Suspender en sl-1 (1 bit) debe fallar
    let err_susp = manager.suspend("sl-1", alloc1.idx).unwrap_err();
    assert_eq!(err_susp.code, ErrorCode::MalformedStatusList);

    // Operación sobre lista inexistente
    assert!(manager.revoke("sl-inexistente", 0).is_err());
}

#[test]
fn test_issuer_status_manager_publish_snapshot_and_commitment() {
    // // Verifies: REQ-ISS-003, REQ-STAT-005, REQ-STAT-006, REQ-STAT-008
    let mut manager = IssuerStatusManager::new("iss-identity-panama", 10).unwrap();
    manager
        .register_status_list(
            "sl-main",
            1,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example.gov/status",
        )
        .unwrap();

    let rng = SeededRng::new(77);
    let alloc = manager.allocate_for_credential(None, &rng).unwrap();
    manager.revoke("sl-main", alloc.idx).unwrap();

    let signer =
        LocalStatusSigner::generate_with_rng(Some("kid-issuer-status".into()), &rng).unwrap();
    let now = UnixTime::from_seconds(1_700_000_000);

    let snapshot = manager
        .publish_snapshot(
            &signer,
            now,
            86400,
            86400,
            "https://cdn.example.gov/manifest.jwt",
        )
        .expect("publish snapshot ok");

    // Verificar versiones incrementales (REQ-STAT-008)
    assert_eq!(snapshot.signed_manifest.manifest_version(), 11);
    assert_eq!(manager.manifest_version(), 11);

    // Verificar listas publicadas
    assert_eq!(snapshot.published_lists.len(), 1);
    let published_list = &snapshot.published_lists[0];

    let parsed_list = StatusListVerifier::parse(published_list.jwt()).unwrap();
    assert_eq!(
        parsed_list.status_of(alloc.idx).unwrap(),
        TokenStatus::Revoked
    );

    let content_uri = published_list.content_addressed_uri("https://cdn.example.gov/status");
    assert!(content_uri.ends_with(&format!("{}.jwt", published_list.sha256_hex())));

    // Verificar manifiesto firmado
    let parsed_manifest = StatusManifestVerifier::parse(snapshot.signed_manifest.jwt()).unwrap();
    assert_eq!(parsed_manifest.manifest_version(), 11);
    assert_eq!(parsed_manifest.issuer_id(), "iss-identity-panama");

    StatusManifestVerifier::verify_signature(snapshot.signed_manifest.jwt(), signer.public_key())
        .expect("manifest signature is valid");

    // Digest de la lista coincide exactamente con el manifiesto (REQ-STAT-005, REQ-STAT-008)
    StatusManifestVerifier::check_list_digest(
        &parsed_manifest,
        &content_uri,
        published_list.sha256_hex(),
    )
    .expect("list digest matches manifest");

    // Compromiso para StatusAnchor.sol (REQ-STAT-006)
    assert_eq!(snapshot.commitment.issuer_id, *manager.issuer_id_bytes());
    assert_eq!(snapshot.commitment.manifest_version, 11);
    assert_eq!(
        snapshot.commitment.manifest_hash,
        *snapshot.signed_manifest.manifest_hash()
    );
    assert_eq!(
        snapshot.commitment.uri_hint,
        "https://cdn.example.gov/manifest.jwt"
    );
}

#[test]
fn test_issuer_status_manager_monotonic_versioning() {
    // // Verifies: REQ-STAT-008 (Anti-rollback de manifiestos sucesivos)
    let mut manager = IssuerStatusManager::new("iss-monotonic", 0).unwrap();
    manager
        .register_status_list(
            "sl-1",
            1,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example.gov/lists",
        )
        .unwrap();

    let rng = SeededRng::new(999);
    let signer = LocalStatusSigner::generate_with_rng(Some("kid-mon".into()), &rng).unwrap();

    let snap1 = manager
        .publish_snapshot(&signer, UnixTime::from_seconds(100), 1000, 1000, "hint1")
        .unwrap();
    assert_eq!(snap1.signed_manifest.manifest_version(), 1);

    let snap2 = manager
        .publish_snapshot(&signer, UnixTime::from_seconds(200), 1000, 1000, "hint2")
        .unwrap();
    assert_eq!(snap2.signed_manifest.manifest_version(), 2);

    let snap3 = manager
        .publish_snapshot(&signer, UnixTime::from_seconds(300), 1000, 1000, "hint3")
        .unwrap();
    assert_eq!(snap3.signed_manifest.manifest_version(), 3);

    // Anti-rollback entre snapshots
    assert!(snap2
        .signed_manifest
        .manifest()
        .check_monotonic_version(Some(snap1.signed_manifest.manifest_version()))
        .is_ok());

    assert!(snap3
        .signed_manifest
        .manifest()
        .check_monotonic_version(Some(snap2.signed_manifest.manifest_version()))
        .is_ok());

    assert!(snap1
        .signed_manifest
        .manifest()
        .check_monotonic_version(Some(snap2.signed_manifest.manifest_version()))
        .is_err());
}

#[test]
fn test_issuer_status_manager_error_cases() {
    let rng = SeededRng::new(42);

    // 1. Emisor vacío
    assert!(IssuerStatusManager::new("", 0).is_err());

    let mut manager = IssuerStatusManager::new("iss-error-test", 1).unwrap();
    assert_eq!(manager.issuer_id(), "iss-error-test");
    assert_eq!(manager.manifest_version(), 1);
    assert_eq!(manager.list_count(), 0);

    // 2. Registro inválido: bits per entry inválido
    assert!(manager
        .register_status_list(
            "sl-bad-bits",
            3,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example/s"
        )
        .is_err());

    // 3. Registro inválido: capacidad menor a la mínima
    assert!(manager
        .register_status_list("sl-bad-cap", 1, 100, "https://cdn.example/s")
        .is_err());

    // 4. Registro exitoso
    manager
        .register_status_list(
            "sl-1bit",
            1,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example/1",
        )
        .unwrap();
    assert_eq!(manager.list_count(), 1);

    // 5. Registro duplicado
    let err_dup = manager
        .register_status_list(
            "sl-1bit",
            1,
            MIN_STATUS_LIST_ENTRIES,
            "https://cdn.example/1",
        )
        .unwrap_err();
    assert_eq!(err_dup.code, ErrorCode::MalformedStatusList);

    // 6. Operaciones en lista inexistente
    assert!(manager
        .allocate_for_credential(Some("sl-unknown"), &rng)
        .is_err());
    assert!(manager.status_of("sl-unknown", 0).is_err());
    assert!(manager.revoke("sl-unknown", 0).is_err());
    assert!(manager.suspend("sl-unknown", 0).is_err());
    assert!(manager.reactivate("sl-unknown", 0).is_err());

    // 7. Suspender en lista de 1 bit rechaza
    assert!(manager.suspend("sl-1bit", 0).is_err());

    // 8. Fuera de rango en lista de 1 bit
    assert!(manager
        .revoke("sl-1bit", MIN_STATUS_LIST_ENTRIES as u64)
        .is_err());
    assert!(manager
        .status_of("sl-1bit", MIN_STATUS_LIST_ENTRIES as u64)
        .is_err());
    assert!(manager
        .reactivate("sl-1bit", MIN_STATUS_LIST_ENTRIES as u64)
        .is_err());
}

#[test]
fn test_allocator_full_exhaustion() {
    let mut allocator = StatusIndexAllocator::new(MIN_STATUS_LIST_ENTRIES).unwrap();
    let rng = SeededRng::new(111);

    assert_eq!(allocator.bitmap().len(), MIN_STATUS_LIST_ENTRIES / 64);

    // Llenar todas las entradas
    for i in 0..(MIN_STATUS_LIST_ENTRIES as u64) {
        allocator.mark_allocated(i).unwrap();
    }

    assert!(allocator.is_full());
    assert_eq!(allocator.available_count(), 0);
    assert!(allocator.allocate_random(&rng).is_err());
}

#[test]
fn test_allocator_non_multiple_of_64_and_last_element() {
    let cap = MIN_STATUS_LIST_ENTRIES + 13;
    let mut allocator = StatusIndexAllocator::new(cap).unwrap();
    let rng = SeededRng::new(555);

    // Llenar casi todas las entradas salvo 1
    for i in 1..(cap as u64) {
        allocator.mark_allocated(i).unwrap();
    }
    assert_eq!(allocator.available_count(), 1);

    // Asignar el último restante (ejecuta sample_uniform_index con limit == 1)
    let last = allocator.allocate_random(&rng).unwrap();
    assert_eq!(last, 0);
    assert!(allocator.is_full());
}
