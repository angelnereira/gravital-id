//! Pruebas unitarias para configuración, reloj, errores y salud de `pip-relay`.
//!
//! Verifies: REQ-REL-001, REQ-OBS-001, REQ-SYNC-004, REQ-SYNC-006, REQ-CODE-001..004

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::env;
use std::sync::{Arc, Mutex};

use gravital_id_types::Clock;
use pip_relay::clock::SystemClock;
use pip_relay::config::RelayConfig;
use pip_relay::error::RelayError;
use pip_relay::health::RelayHealthCheck;
use pip_relay::store::InMemoryRelayStore;
use pip_service_common::health::{HealthCheck, HealthStatus};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_default_config_is_valid() {
    let config = RelayConfig::default();
    assert!(config.validate().is_ok());
    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.server.port, 8083);
    assert_eq!(config.max_payload_bytes, 128 * 1024);
    assert_eq!(config.session_code_ttl_secs, 180);
    assert_eq!(config.max_rendezvous_capacity, 2_000);
}

#[test]
fn test_config_from_env_parsing() {
    let _guard = ENV_LOCK.lock().unwrap();
    let prefix = "PIP_RELAY_TEST_PARSING_";

    env::set_var(format!("{prefix}HOST"), "127.0.0.1");
    env::set_var(format!("{prefix}PORT"), "9090");
    env::set_var(format!("{prefix}MAX_PAYLOAD_BYTES"), "65536");
    env::set_var(format!("{prefix}DEFAULT_OBJECT_TTL_SECS"), "1000");
    env::set_var(format!("{prefix}MAX_OBJECT_TTL_SECS"), "5000");
    env::set_var(format!("{prefix}DEFAULT_ENVELOPE_TTL_SECS"), "500");
    env::set_var(format!("{prefix}MAX_ENVELOPE_TTL_SECS"), "2000");
    env::set_var(format!("{prefix}SESSION_CODE_TTL_SECS"), "120");
    env::set_var(format!("{prefix}MAX_OBJECTS_CAPACITY"), "500");
    env::set_var(format!("{prefix}MAX_MAILBOXES_CAPACITY"), "300");
    env::set_var(format!("{prefix}MAX_ENVELOPES_PER_MAILBOX"), "50");
    env::set_var(format!("{prefix}MAX_RENDEZVOUS_CAPACITY"), "100");
    env::set_var(format!("{prefix}RATE_LIMIT_REQUESTS_PER_MINUTE"), "300");
    env::set_var(format!("{prefix}RATE_LIMIT_BURST"), "50");
    env::set_var(format!("{prefix}LOG_LEVEL"), "debug");

    let cfg = RelayConfig::from_env_with_prefix(prefix).expect("valid config");
    assert_eq!(cfg.server.host, "127.0.0.1");
    assert_eq!(cfg.server.port, 9090);
    assert_eq!(cfg.max_payload_bytes, 65536);
    assert_eq!(cfg.default_object_ttl_secs, 1000);
    assert_eq!(cfg.max_object_ttl_secs, 5000);
    assert_eq!(cfg.default_envelope_ttl_secs, 500);
    assert_eq!(cfg.max_envelope_ttl_secs, 2000);
    assert_eq!(cfg.session_code_ttl_secs, 120);
    assert_eq!(cfg.max_objects_capacity, 500);
    assert_eq!(cfg.max_mailboxes_capacity, 300);
    assert_eq!(cfg.max_envelopes_per_mailbox, 50);
    assert_eq!(cfg.max_rendezvous_capacity, 100);
    assert_eq!(cfg.rate_limit_requests_per_minute, 300);
    assert_eq!(cfg.rate_limit_burst, 50);
    assert_eq!(cfg.telemetry.log_level, "debug");

    // Probar from_env() directo
    let direct = RelayConfig::from_env();
    assert!(direct.is_ok());
}

#[test]
fn test_config_from_env_invalid_numbers() {
    let _guard = ENV_LOCK.lock().unwrap();
    let prefix = "PIP_RELAY_TEST_INV_";

    let keys = [
        "PORT",
        "MAX_PAYLOAD_BYTES",
        "DEFAULT_OBJECT_TTL_SECS",
        "MAX_OBJECT_TTL_SECS",
        "DEFAULT_ENVELOPE_TTL_SECS",
        "MAX_ENVELOPE_TTL_SECS",
        "SESSION_CODE_TTL_SECS",
        "MAX_OBJECTS_CAPACITY",
        "MAX_MAILBOXES_CAPACITY",
        "MAX_ENVELOPES_PER_MAILBOX",
        "MAX_RENDEZVOUS_CAPACITY",
        "RATE_LIMIT_REQUESTS_PER_MINUTE",
        "RATE_LIMIT_BURST",
    ];

    for key in keys {
        env::set_var(format!("{prefix}{key}"), "not_a_number");
        let res = RelayConfig::from_env_with_prefix(prefix);
        assert!(res.is_err(), "Expected error for key {key}");
        env::remove_var(format!("{prefix}{key}"));
    }
}

#[test]
fn test_config_validation_failures() {
    let mut cfg = RelayConfig::default();
    cfg.server.port = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.max_payload_bytes = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.max_payload_bytes = 20 * 1024 * 1024;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.default_object_ttl_secs = 2000;
    cfg.max_object_ttl_secs = 1000;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.default_envelope_ttl_secs = 2000;
    cfg.max_envelope_ttl_secs = 1000;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.session_code_ttl_secs = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.session_code_ttl_secs = 181; // Excede límite normativo de 180s
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.max_objects_capacity = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.max_mailboxes_capacity = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.max_envelopes_per_mailbox = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = RelayConfig::default();
    cfg.rate_limit_requests_per_minute = 0;
    assert!(cfg.validate().is_err());
}

#[test]
fn test_system_clock() {
    let clock = SystemClock;
    let now = clock.now_seconds();
    assert!(now > 1_700_000_000);
    assert_eq!(clock.monotonic_elapsed_millis(), None);
}

#[test]
fn test_relay_error_formatting_and_status() {
    let errors: Vec<RelayError> = vec![
        RelayError::PayloadTooLarge {
            max: 100,
            actual: 200,
        },
        RelayError::ObjectNotFound("abc".into()),
        RelayError::ObjectHashMismatch {
            expected: "a".into(),
            actual: "b".into(),
        },
        RelayError::InvalidIdentifier("bad id".into()),
        RelayError::InvalidSessionCode("bad code".into()),
        RelayError::SessionAlreadyConsumed,
        RelayError::SessionExpired,
        RelayError::SessionNotFound,
        RelayError::RateLimitExceeded,
        RelayError::CapacityExceeded("full".into()),
        RelayError::Config("bad cfg".into()),
        RelayError::Internal("crash".into()),
    ];

    for err in errors {
        let status = err.status_code();
        assert!((400..600).contains(&status));
        let json = err.to_json_response();
        assert!(json.contains("\"error\":"));
        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"message\":"));
    }
}

#[test]
fn test_relay_health_check() {
    let mut config = RelayConfig::default();
    config.max_objects_capacity = 10;
    let clock = SystemClock;
    let store = Arc::new(InMemoryRelayStore::new(config, clock));

    let check = RelayHealthCheck::new(Arc::clone(&store));
    assert_eq!(check.name(), "pip-relay-storage");

    // Vacío: estado UP
    let res = check.check();
    assert_eq!(res.status, HealthStatus::Up);

    // Llenar al 90% (9 de 10)
    for i in 0..9 {
        let _ = store.put_object(format!("obj-{i}").into_bytes(), None, None);
    }

    let res_degraded = check.check();
    assert_eq!(res_degraded.status, HealthStatus::Degraded);
}
