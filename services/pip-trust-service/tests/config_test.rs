//! Pruebas unitarias de configuración para pip-trust-service (F7.T04, REQ-TRUST-003, REQ-REL-001).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use pip_trust_service::config::TrustServiceConfig;

#[test]
fn test_default_config() {
    let cfg = TrustServiceConfig::default();
    assert_eq!(cfg.server.host, "0.0.0.0");
    assert_eq!(cfg.server.port, 8082);
    assert_eq!(cfg.server.shutdown_timeout_secs, 5);
    assert_eq!(cfg.telemetry.service_name, "pip-trust-service");
    assert_eq!(cfg.telemetry.log_level, "info");
    assert!(cfg.telemetry.json_format);
    assert!(cfg.telemetry.enable_redaction);
    assert_eq!(cfg.framework_id, "pip-global-mainnet");
    assert_eq!(cfg.chain_id, 31337);
    assert_eq!(cfg.bundle_epoch, 1);
    assert_eq!(cfg.bundle_version, 1);
    assert_eq!(cfg.validity_duration_seconds, 604_800);
    assert_eq!(cfg.threshold, 2);
    assert_eq!(cfg.operator_id, "operator-primary");
    assert_eq!(cfg.operator_kid, "urn:pip:signer:operator-primary");
    assert_eq!(cfg.operator_private_key_hex, None);
    assert_eq!(cfg.storage_backend, "memory");
    assert_eq!(cfg.storage_local_dir, "/var/data/pip/bundles");
    assert_eq!(cfg.s3_bucket, "pip-trust-bundles");
    assert_eq!(cfg.s3_endpoint, "http://127.0.0.1:9000");
    assert_eq!(cfg.poll_interval_millis, 5000);
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_validate_fail_closed_threshold_zero() {
    let mut cfg = TrustServiceConfig::default();
    cfg.threshold = 0;
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("threshold debe ser al menos 1"));
}

#[test]
fn test_validate_fail_closed_empty_framework() {
    let mut cfg = TrustServiceConfig::default();
    cfg.framework_id = "   ".to_string();
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("framework_id"));
}

#[test]
fn test_validate_fail_closed_empty_operator() {
    let mut cfg = TrustServiceConfig::default();
    cfg.operator_id = "".to_string();
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("operator_id no puede ser vacío"));

    cfg.operator_id = "op-1".to_string();
    cfg.operator_kid = "   ".to_string();
    let err2 = cfg.validate().unwrap_err();
    assert!(err2.to_string().contains("operator_kid no puede ser vacío"));
}

#[test]
fn test_validate_fail_closed_zero_validity() {
    let mut cfg = TrustServiceConfig::default();
    cfg.validity_duration_seconds = 0;
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("validity_duration_seconds"));
}

#[test]
fn test_validate_fail_closed_invalid_storage_backend() {
    let mut cfg = TrustServiceConfig::default();
    cfg.storage_backend = "ftp".to_string();
    let err = cfg.validate().unwrap_err();
    assert!(err
        .to_string()
        .contains("storage_backend 'ftp' desconocido"));
}

#[test]
fn test_validate_filesystem_storage() {
    let mut cfg = TrustServiceConfig::default();
    cfg.storage_backend = "filesystem".to_string();
    cfg.storage_local_dir = "".to_string();
    assert!(cfg.validate().is_err());

    cfg.storage_local_dir = "/tmp/trust".to_string();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_validate_s3_storage() {
    let mut cfg = TrustServiceConfig::default();
    cfg.storage_backend = "s3".to_string();
    cfg.s3_bucket = "".to_string();
    assert!(cfg.validate().is_err());

    cfg.s3_bucket = "my-bucket".to_string();
    cfg.s3_endpoint = "".to_string();
    assert!(cfg.validate().is_err());

    cfg.s3_endpoint = "http://minio:9000".to_string();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_from_env_with_prefix() {
    let prefix = "TEST_CFG_TRUST_";
    std::env::set_var(format!("{prefix}FRAMEWORK_ID"), "pip-testnet-1");
    std::env::set_var(format!("{prefix}CHAIN_ID"), "11155111");
    std::env::set_var(format!("{prefix}BUNDLE_EPOCH"), "2");
    std::env::set_var(format!("{prefix}BUNDLE_VERSION"), "42");
    std::env::set_var(format!("{prefix}VALIDITY_SECONDS"), "86400");
    std::env::set_var(format!("{prefix}THRESHOLD"), "5");
    std::env::set_var(format!("{prefix}OPERATOR_ID"), "operator-alpha");
    std::env::set_var(format!("{prefix}OPERATOR_KID"), "alpha-key-2026");
    std::env::set_var(
        format!("{prefix}OPERATOR_PRIVATE_KEY_HEX"),
        "0x0123456789abcdef",
    );
    std::env::set_var(format!("{prefix}STORAGE_BACKEND"), "memory");
    std::env::set_var(format!("{prefix}POLL_INTERVAL_MS"), "5000");

    let cfg = TrustServiceConfig::from_env_with_prefix(prefix).unwrap();
    assert_eq!(cfg.framework_id, "pip-testnet-1");
    assert_eq!(cfg.chain_id, 11155111);
    assert_eq!(cfg.bundle_epoch, 2);
    assert_eq!(cfg.bundle_version, 42);
    assert_eq!(cfg.validity_duration_seconds, 86400);
    assert_eq!(cfg.threshold, 5);
    assert_eq!(cfg.operator_id, "operator-alpha");
    assert_eq!(cfg.operator_kid, "alpha-key-2026");
    assert_eq!(
        cfg.operator_private_key_hex,
        Some("0x0123456789abcdef".to_string())
    );
    assert_eq!(cfg.poll_interval_millis, 5000);

    // Limpiar variables
    std::env::remove_var(format!("{prefix}FRAMEWORK_ID"));
    std::env::remove_var(format!("{prefix}CHAIN_ID"));
    std::env::remove_var(format!("{prefix}BUNDLE_EPOCH"));
    std::env::remove_var(format!("{prefix}BUNDLE_VERSION"));
    std::env::remove_var(format!("{prefix}VALIDITY_SECONDS"));
    std::env::remove_var(format!("{prefix}THRESHOLD"));
    std::env::remove_var(format!("{prefix}OPERATOR_ID"));
    std::env::remove_var(format!("{prefix}OPERATOR_KID"));
    std::env::remove_var(format!("{prefix}OPERATOR_PRIVATE_KEY_HEX"));
    std::env::remove_var(format!("{prefix}STORAGE_BACKEND"));
    std::env::remove_var(format!("{prefix}POLL_INTERVAL_MS"));
}

#[test]
fn test_from_env_default() {
    let cfg = TrustServiceConfig::from_env();
    assert!(cfg.is_ok());
}

#[test]
fn test_validate_additional_fail_closed_limits() {
    let mut cfg = TrustServiceConfig::default();
    cfg.chain_id = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = TrustServiceConfig::default();
    cfg.bundle_epoch = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = TrustServiceConfig::default();
    cfg.bundle_version = 0;
    assert!(cfg.validate().is_err());

    let mut cfg = TrustServiceConfig::default();
    cfg.validity_duration_seconds = 31_536_001; // Mayor a 1 año
    assert!(cfg.validate().is_err());

    let mut cfg = TrustServiceConfig::default();
    cfg.poll_interval_millis = 10; // Menor a 50 ms
    assert!(cfg.validate().is_err());

    let mut cfg = TrustServiceConfig::default();
    cfg.poll_interval_millis = 600_001; // Mayor a 10 min
    assert!(cfg.validate().is_err());

    let mut cfg = TrustServiceConfig::default();
    cfg.framework_id = "a".repeat(65); // Mayor a 64 chars
    assert!(cfg.validate().is_err());
}

#[test]
fn test_from_env_parse_errors() {
    let prefix = "TEST_PARSE_ERR_";

    // Invalid CHAIN_ID
    std::env::set_var(format!("{prefix}CHAIN_ID"), "abc");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var(format!("{prefix}CHAIN_ID"));

    // Invalid BUNDLE_EPOCH
    std::env::set_var(format!("{prefix}BUNDLE_EPOCH"), "xyz");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var(format!("{prefix}BUNDLE_EPOCH"));

    // Invalid BUNDLE_VERSION
    std::env::set_var(format!("{prefix}BUNDLE_VERSION"), "not_num");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var(format!("{prefix}BUNDLE_VERSION"));

    // Invalid VALIDITY_SECONDS
    std::env::set_var(format!("{prefix}VALIDITY_SECONDS"), "bad");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var(format!("{prefix}VALIDITY_SECONDS"));

    // Invalid THRESHOLD
    std::env::set_var(format!("{prefix}THRESHOLD"), "invalid");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var(format!("{prefix}THRESHOLD"));

    // Invalid POLL_INTERVAL_MS
    std::env::set_var(format!("{prefix}POLL_INTERVAL_MS"), "slow");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var(format!("{prefix}POLL_INTERVAL_MS"));

    // PIP_SERVER_PORT invalid
    std::env::set_var("PIP_SERVER_PORT", "bad_port");
    assert!(TrustServiceConfig::from_env_with_prefix(prefix).is_err());
    std::env::remove_var("PIP_SERVER_PORT");

    // Optional strings parsed correctly
    std::env::set_var("PIP_LOG_LEVEL", "debug");
    std::env::set_var(format!("{prefix}STORAGE_LOCAL_DIR"), "/custom/dir");
    std::env::set_var(format!("{prefix}S3_BUCKET"), "custom-bkt");
    std::env::set_var(format!("{prefix}S3_ENDPOINT"), "http://s3.local");
    let ok_cfg = TrustServiceConfig::from_env_with_prefix(prefix).unwrap();
    assert_eq!(ok_cfg.telemetry.log_level, "debug");
    assert_eq!(ok_cfg.storage_local_dir, "/custom/dir");
    assert_eq!(ok_cfg.s3_bucket, "custom-bkt");
    assert_eq!(ok_cfg.s3_endpoint, "http://s3.local");
    std::env::remove_var("PIP_LOG_LEVEL");
    std::env::remove_var(format!("{prefix}STORAGE_LOCAL_DIR"));
    std::env::remove_var(format!("{prefix}S3_BUCKET"));
    std::env::remove_var(format!("{prefix}S3_ENDPOINT"));
}
