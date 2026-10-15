#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración y propiedades de la caché de nonces anti-replay (F4.T07).
//!
//! Trazabilidad:
//! - **REQ-PRES-004:** El verificador DEBE mantener una caché de nonces con expiración y
//!   rechazar nonces desconocidos o reutilizados.
//! - **REQ-VER-008:** Cotas estrictas de memoria (`capacity`), sin crecimiento desmedido.
//! - **INV-01:** Sin I/O de red (`no_std` + `alloc`).
//! - **INV-05:** Fail-closed determinista ante repetición de nonces.
//! - **INV-11:** Reloj inyectado determinista (`now: UnixTime`).

extern crate alloc;

use alloc::format;

use gravital_id_types::UnixTime;
use gravital_id_verifier::nonce::{InMemoryNonceCache, NonceCache};
use proptest::prelude::*;

// Verifies: REQ-PRES-004, INV-05
#[test]
fn nominal_nonce_lifecycle_remember_seen_and_expire() {
    let mut cache = InMemoryNonceCache::new();
    let now = UnixTime::from_seconds(1_000);
    let expires_at = UnixTime::from_seconds(1_300);

    // Nonce no visto antes
    assert!(!cache.is_seen("session-nonce-xyz", now).unwrap());

    // Se recuerda
    cache.remember("session-nonce-xyz", expires_at).unwrap();
    assert_eq!(cache.len(), 1);

    // Mientras no expire, se detecta visto
    assert!(cache.is_seen("session-nonce-xyz", now).unwrap());
    assert!(cache
        .is_seen("session-nonce-xyz", UnixTime::from_seconds(1_299))
        .unwrap());
    assert!(cache
        .is_seen("session-nonce-xyz", UnixTime::from_seconds(1_300))
        .unwrap());

    // Una vez expirado, ya no bloquea
    assert!(!cache
        .is_seen("session-nonce-xyz", UnixTime::from_seconds(1_301))
        .unwrap());
}

// Verifies: REQ-PRES-004
#[test]
fn atomic_check_and_consume_behavior() {
    let mut cache = InMemoryNonceCache::new();
    let now = UnixTime::from_seconds(2_000);
    let expires_at = UnixTime::from_seconds(2_180);

    // Primer consumo: es fresco, lo registra y devuelve true
    let first = cache
        .check_and_consume("nonce-unique-123", expires_at, now)
        .unwrap();
    assert!(first);

    // Segundo consumo inmediato con el mismo nonce: replay detectado, devuelve false
    let second = cache
        .check_and_consume("nonce-unique-123", expires_at, now)
        .unwrap();
    assert!(!second);

    // Tras la expiración, check_and_consume vuelve a admitirlo
    let after_expiry = UnixTime::from_seconds(2_181);
    let third = cache
        .check_and_consume(
            "nonce-unique-123",
            UnixTime::from_seconds(2_500),
            after_expiry,
        )
        .unwrap();
    assert!(third);
}

// Verifies: REQ-VER-008
#[test]
fn eviction_preserves_latest_expiring_entries() {
    let mut cache = InMemoryNonceCache::with_capacity(3);

    cache.remember("n1", UnixTime::from_seconds(1_100)).unwrap();
    cache.remember("n2", UnixTime::from_seconds(1_200)).unwrap();
    cache.remember("n3", UnixTime::from_seconds(1_300)).unwrap();

    assert_eq!(cache.len(), 3);

    // Añadir un 4º nonce desaloja n1 (expira a 1.100, la menor de las 3)
    cache.remember("n4", UnixTime::from_seconds(1_400)).unwrap();

    assert_eq!(cache.len(), 3);
    assert!(!cache.is_seen("n1", UnixTime::from_seconds(1_000)).unwrap());
    assert!(cache.is_seen("n2", UnixTime::from_seconds(1_000)).unwrap());
    assert!(cache.is_seen("n3", UnixTime::from_seconds(1_000)).unwrap());
    assert!(cache.is_seen("n4", UnixTime::from_seconds(1_000)).unwrap());
}

// Verifies: REQ-PRES-004
#[test]
fn purge_expired_cleans_only_dead_entries() {
    let mut cache = InMemoryNonceCache::with_capacity(10);

    cache
        .remember("dead-1", UnixTime::from_seconds(500))
        .unwrap();
    cache
        .remember("dead-2", UnixTime::from_seconds(600))
        .unwrap();
    cache
        .remember("alive-1", UnixTime::from_seconds(1_500))
        .unwrap();
    cache
        .remember("alive-2", UnixTime::from_seconds(1_600))
        .unwrap();

    assert_eq!(cache.len(), 4);
    cache.purge_expired(UnixTime::from_seconds(700));

    assert_eq!(cache.len(), 2);
    assert!(!cache
        .is_seen("dead-1", UnixTime::from_seconds(400))
        .unwrap());
    assert!(!cache
        .is_seen("dead-2", UnixTime::from_seconds(400))
        .unwrap());
    assert!(cache
        .is_seen("alive-1", UnixTime::from_seconds(700))
        .unwrap());
    assert!(cache
        .is_seen("alive-2", UnixTime::from_seconds(700))
        .unwrap());
}

proptest! {
    // Verifies: REQ-VER-008
    #[test]
    fn prop_nonce_cache_never_exceeds_configured_capacity(
        capacity in 1usize..25,
        entries in proptest::collection::vec(
            (0u32..50, 1_000u64..10_000),
            1..100
        )
    ) {
        let mut cache = InMemoryNonceCache::with_capacity(capacity);

        for (id, exp_sec) in entries {
            let nonce_str = format!("nonce-{id}");
            cache.remember(&nonce_str, UnixTime::from_seconds(exp_sec)).unwrap();

            // La longitud de la caché NUNCA debe exceder la capacidad (REQ-VER-008)
            prop_assert!(cache.len() <= capacity);
            prop_assert_eq!(cache.capacity(), capacity);
        }
    }

    // Verifies: REQ-PRES-004, INV-05
    #[test]
    fn prop_unseen_nonce_is_always_fresh(
        nonces in proptest::collection::vec("[a-z0-9]{8,16}", 1..20),
        now_sec in 1_000u64..10_000
    ) {
        let cache = InMemoryNonceCache::new();
        let now = UnixTime::from_seconds(now_sec);

        for nonce in nonces {
            prop_assert!(!cache.is_seen(&nonce, now).unwrap());
        }
    }

    // Verifies: REQ-PRES-004, INV-11
    #[test]
    fn prop_expired_nonces_never_block(
        now_sec in 5_000u64..10_000,
        age in 1u64..1_000
    ) {
        let mut cache = InMemoryNonceCache::new();
        let expired_at = UnixTime::from_seconds(now_sec.saturating_sub(age));
        let now = UnixTime::from_seconds(now_sec);

        cache.remember("expired-prop-nonce", expired_at).unwrap();

        // Si now > expired_at, el nonce NUNCA debe bloquear (debe retornar false en is_seen)
        prop_assert!(!cache.is_seen("expired-prop-nonce", now).unwrap());
    }
}
