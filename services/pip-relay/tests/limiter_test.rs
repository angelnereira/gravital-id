//! Pruebas unitarias para el limitador de tasa de `pip-relay`.
//!
//! Verifies: REQ-SYNC-004, REQ-SYNC-006

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gravital_id_types::Clock;
use pip_relay::error::RelayError;
use pip_relay::limiter::RateLimiter;

#[derive(Debug, Clone)]
struct TestSyncClock {
    now: Arc<AtomicU64>,
}

impl TestSyncClock {
    fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }

    fn advance_seconds(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestSyncClock {
    fn now_seconds(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn monotonic_elapsed_millis(&self) -> Option<u64> {
        None
    }
}

#[test]
fn test_rate_limiter_burst_and_exhaustion() {
    let clock = TestSyncClock::new(1000);
    // 60 peticiones/minuto = 1 token/segundo, ráfaga máxima = 3 tokens
    let limiter = RateLimiter::new(60, 3, clock);

    // 3 peticiones consecutivas deben permitirse (burst)
    assert!(limiter.check_rate_limit("client-1").is_ok());
    assert_eq!(limiter.tracked_clients_count(), 1);
    assert!(limiter.check_rate_limit("client-1").is_ok());
    assert!(limiter.check_rate_limit("client-1").is_ok());

    // 4ª petición agota la cubeta inmediatamente
    let err = limiter.check_rate_limit("client-1").unwrap_err();
    assert!(matches!(err, RelayError::RateLimitExceeded));

    // Un cliente diferente tiene su propia cubeta aislada
    assert!(limiter.check_rate_limit("client-2").is_ok());
    assert_eq!(limiter.tracked_clients_count(), 2);
}

#[test]
fn test_rate_limiter_replenishment_over_time() {
    let clock = TestSyncClock::new(1000);
    // 60 rpm = 1 token / s, burst = 2
    let limiter = RateLimiter::new(60, 2, clock.clone());

    assert!(limiter.check_rate_limit("client-a").is_ok());
    assert!(limiter.check_rate_limit("client-a").is_ok());
    assert!(limiter.check_rate_limit("client-a").is_err());

    // Avanzamos 1 segundo: se repone 1 token
    clock.advance_seconds(1);
    assert!(limiter.check_rate_limit("client-a").is_ok());
    assert!(limiter.check_rate_limit("client-a").is_err());

    // Avanzamos 5 segundos: la cubeta se llena hasta el tope del burst (2 tokens)
    clock.advance_seconds(5);
    assert!(limiter.check_rate_limit("client-a").is_ok());
    assert!(limiter.check_rate_limit("client-a").is_ok());
    assert!(limiter.check_rate_limit("client-a").is_err());
}
