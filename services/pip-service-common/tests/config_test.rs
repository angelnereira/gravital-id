//! Pruebas de configuración y validaciones fail-closed (REQ-REL-001, INV-02).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pip_service_common::config::{Environment, ServerConfig, ServiceConfig, TelemetryConfig};
use std::env;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn environment_parsing_is_case_insensitive_and_validates_production() {
    assert_eq!(Environment::parse_str("local").unwrap(), Environment::Local);
    assert_eq!(Environment::parse_str("dev").unwrap(), Environment::Dev);
    assert_eq!(
        Environment::parse_str("Development").unwrap(),
        Environment::Dev
    );
    assert_eq!(
        Environment::parse_str("TESTNET").unwrap(),
        Environment::Testnet
    );
    assert_eq!(Environment::parse_str("pilot").unwrap(), Environment::Pilot);
    assert_eq!(
        Environment::parse_str("Prod").unwrap(),
        Environment::Production
    );
    assert_eq!(
        Environment::parse_str("production").unwrap(),
        Environment::Production
    );

    assert!(Environment::parse_str("invalid_env").is_err());

    assert!(!Environment::Local.is_production());
    assert!(!Environment::Dev.is_production());
    assert!(!Environment::Testnet.is_production());
    assert!(Environment::Pilot.is_production());
    assert!(Environment::Production.is_production());
}

#[test]
fn defaults_and_env_variables_parsing() {
    let _guard = ENV_LOCK.lock().unwrap();

    let server_default = ServerConfig::default();
    assert_eq!(server_default.host, "0.0.0.0");
    assert_eq!(server_default.port, 8080);
    assert_eq!(server_default.shutdown_timeout_secs, 15);

    let telemetry_default = TelemetryConfig::default();
    assert_eq!(telemetry_default.service_name, "gravital-id-service");
    assert_eq!(telemetry_default.log_level, "info");
    assert!(!telemetry_default.json_format);
    assert!(telemetry_default.enable_redaction);

    env::set_var("ENVIRONMENT", "dev");
    env::set_var("HOST", "127.0.0.1");
    env::set_var("PORT", "8888");
    env::set_var("SHUTDOWN_TIMEOUT_SECS", "30");
    env::set_var("LOG_FORMAT", "json");
    env::set_var("RUST_LOG", "debug");
    env::set_var("ENABLE_LOG_REDACTION", "true");

    let cfg = ServiceConfig::from_env("custom-service", 9090).unwrap();
    assert_eq!(cfg.environment, Environment::Dev);
    assert_eq!(cfg.server.host, "127.0.0.1");
    assert_eq!(cfg.server.port, 8888);
    assert_eq!(cfg.server.shutdown_timeout_secs, 30);
    assert_eq!(cfg.telemetry.log_level, "debug");
    assert!(cfg.telemetry.json_format);
    assert!(cfg.telemetry.enable_redaction);

    // Limpieza
    env::remove_var("ENVIRONMENT");
    env::remove_var("HOST");
    env::remove_var("PORT");
    env::remove_var("SHUTDOWN_TIMEOUT_SECS");
    env::remove_var("LOG_FORMAT");
    env::remove_var("RUST_LOG");
    env::remove_var("ENABLE_LOG_REDACTION");
}

#[test]
fn invalid_configuration_fails_closed() {
    let _guard = ENV_LOCK.lock().unwrap();

    // Puerto 0 debe fallar
    env::set_var("PORT", "0");
    assert!(ServiceConfig::from_env("test", 8080).is_err());
    env::remove_var("PORT");

    // Puerto no numérico
    env::set_var("PORT", "not_a_number");
    assert!(ServiceConfig::from_env("test", 8080).is_err());
    env::remove_var("PORT");

    // Timeout inválido
    env::set_var("SHUTDOWN_TIMEOUT_SECS", "invalid");
    assert!(ServiceConfig::from_env("test", 8080).is_err());
    env::remove_var("SHUTDOWN_TIMEOUT_SECS");

    // Desactivar redacción en producción debe fallar
    env::set_var("ENVIRONMENT", "production");
    env::set_var("ENABLE_LOG_REDACTION", "false");
    assert!(ServiceConfig::from_env("prod-service", 8080).is_err());

    // Limpieza
    env::remove_var("ENVIRONMENT");
    env::remove_var("ENABLE_LOG_REDACTION");
}
