#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración del estado del verificador (F4.T04).
//!
//! Trazabilidad:
//! - **REQ-VER-006:** detección de retroceso de reloj mediante el piso de tiempo confiable.
//! - **REQ-VER-011:** si el estado falta o no es íntegro, el resultado es `Unverifiable`
//!   hasta una reinicialización explícita.
//! - **REQ-PRES-004:** caché de nonces con expiración y rechazo de reutilización.
//! - **INV-05:** fail-closed ante cualquier duda sobre el estado.

extern crate alloc;

use alloc::string::ToString;

use gravital_id_types::UnixTime;
use gravital_id_verifier::{
    InMemoryStateStore, StateIntegrityKey, TimeFloorCheck, TimeFloorGuard, VerifierStateStore,
};

/// Almacén que simula un estado persistente corrupto (restaurado o manipulado).
struct CorruptedStore;

impl VerifierStateStore for CorruptedStore {
    fn time_floor(&self) -> Result<Option<UnixTime>, gravital_id_types::GidError> {
        Ok(Some(UnixTime::from_seconds(1_000)))
    }

    fn raise_time_floor(&mut self, _floor: UnixTime) -> Result<(), gravital_id_types::GidError> {
        Ok(())
    }

    fn accepted_bundle(
        &self,
    ) -> Result<Option<gravital_id_trust::AcceptedBundleState>, gravital_id_types::GidError> {
        Ok(None)
    }

    fn record_accepted_bundle(
        &mut self,
        _state: gravital_id_trust::AcceptedBundleState,
    ) -> Result<(), gravital_id_types::GidError> {
        Ok(())
    }

    fn nonce_seen(
        &self,
        _nonce: &str,
        _now: UnixTime,
    ) -> Result<bool, gravital_id_types::GidError> {
        Ok(false)
    }

    fn remember_nonce(
        &mut self,
        _nonce: &str,
        _expires_at: UnixTime,
    ) -> Result<(), gravital_id_types::GidError> {
        Ok(())
    }

    fn integrity_check(&self) -> Result<(), gravital_id_types::GidError> {
        Err(gravital_id_types::GidError::new(
            gravital_id_types::ErrorCode::VerifierStateCorrupted,
            "stored MAC does not match the state",
        ))
    }

    fn reset(&mut self) {}
}

fn key() -> StateIntegrityKey {
    StateIntegrityKey::new([3u8; 32])
}

// Verifies: REQ-VER-006
#[test]
fn first_run_and_subsequent_runs_raise_the_time_floor() {
    let mut store = InMemoryStateStore::new(key());
    let mut guard = TimeFloorGuard::new(&mut store);

    assert_eq!(
        guard.check(UnixTime::from_seconds(1_000), None).unwrap(),
        TimeFloorCheck::FirstRun,
        "la primera ejecución no tiene piso previo"
    );
    assert_eq!(
        guard
            .check(UnixTime::from_seconds(2_000), Some(1_000))
            .unwrap(),
        TimeFloorCheck::Ok
    );
    assert_eq!(
        store.time_floor().unwrap(),
        Some(UnixTime::from_seconds(2_000))
    );
}

// Verifies: REQ-VER-006, REQ-VER-003
#[test]
fn clock_rollback_never_produces_a_valid_result() {
    let mut store = InMemoryStateStore::new(key());
    let mut guard = TimeFloorGuard::new(&mut store);
    guard.check(UnixTime::from_seconds(5_000), None).unwrap();

    // Reloj atrásado, incluso con monotónico avanzando: el piso manda.
    for monotonic in [None, Some(1_000_000)] {
        let error = guard
            .check(UnixTime::from_seconds(4_999), monotonic)
            .unwrap_err();
        assert_eq!(
            error.code,
            gravital_id_types::ErrorCode::ClockRollbackDetected,
            "un reloj atrasado nunca debe aceptarse (INV-05)"
        );
    }
}

// Verifies: REQ-VER-011, INV-05
#[test]
fn corrupted_state_yields_unverifiable_and_reset_recovers() {
    let mut corrupted = CorruptedStore;
    let mut guard = TimeFloorGuard::new(&mut corrupted);

    let error = guard
        .check(UnixTime::from_seconds(1_000), None)
        .unwrap_err();
    assert_eq!(
        error.code,
        gravital_id_types::ErrorCode::VerifierStateCorrupted
    );
    assert!(error.message.contains("Unverifiable"));

    // La única salida documentada es la reinicialización explícita.
    let mut healthy = InMemoryStateStore::new(key());
    healthy
        .raise_time_floor(UnixTime::from_seconds(500))
        .unwrap();
    healthy.reset();
    assert!(healthy.time_floor().unwrap().is_none());
    let mut guard = TimeFloorGuard::new(&mut healthy);
    assert_eq!(
        guard.check(UnixTime::from_seconds(1_000), None).unwrap(),
        TimeFloorCheck::FirstRun,
        "tras el reset el verificador vuelve a un estado conocido"
    );
}

// Verifies: REQ-PRES-004
#[test]
fn nonce_cache_rejects_reuse_until_expiry() {
    let mut store = InMemoryStateStore::new(key());
    let now = UnixTime::from_seconds(1_000);
    store.remember_nonce("verifier-nonce-1", now).unwrap();

    assert!(store.nonce_seen("verifier-nonce-1", now).unwrap());
    assert!(!store.nonce_seen("verifier-nonce-2", now).unwrap());

    // Tras la expiración el nonce puede volver a usarse (ventana acabada).
    let later = UnixTime::from_seconds(1_001);
    assert!(!store.nonce_seen("verifier-nonce-1", later).unwrap());
    store.remember_nonce("verifier-nonce-1", later).unwrap();
    assert!(store.nonce_seen("verifier-nonce-1", later).unwrap());
}

// Verifies: REQ-VER-011
#[test]
fn accepted_bundle_version_survives_across_sessions() {
    let mut store = InMemoryStateStore::new(key());
    let state = gravital_id_trust::AcceptedBundleState {
        bundle_epoch: 3,
        bundle_version: 900,
    };
    store.record_accepted_bundle(state).unwrap();
    assert_eq!(store.accepted_bundle().unwrap(), Some(state));

    // El estado se usa para el anti-rollback sin necesidad de releer el bundle.
    let remembered = store.accepted_bundle().unwrap().unwrap();
    assert!(remembered.bundle_version > 899);
    assert_eq!(remembered.bundle_epoch, 3);
}

// Verifies: REQ-SEC-003, INV-02
#[test]
fn integrity_key_never_leaks_material() {
    let key = key();
    let debug = format!("{key:?}");
    let display = format!("{key}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains([3u8; 32][0].to_string().as_str()));
    assert!(display.contains("REDACTED") || display.is_empty());
}
