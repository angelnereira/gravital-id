//! Pruebas unitarias de comprobación de salud para pip-trust-service (F7.T04, REQ-REL-001, REQ-OBS-001).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use pip_service_common::health::{HealthCheck, HealthStatus};
use pip_trust_service::aggregator::AggregatedSignedBundle;
use pip_trust_service::health::{LastAggregationStatus, TrustServiceHealthCheck};
use pip_trust_service::publisher::{BundlePublisher, InMemoryBundlePublisher};
use std::sync::{Arc, Mutex};

use pip_trust_service::error::TrustServiceError;
use pip_trust_service::publisher::PublishedBundleRecord;

struct FailingPublisher;

impl BundlePublisher for FailingPublisher {
    fn publish_bundle(
        &self,
        _epoch: u64,
        _version: u64,
        _jws_json: &str,
        _digest: &[u8; 32],
        _timestamp: u64,
    ) -> Result<PublishedBundleRecord, TrustServiceError> {
        Err(TrustServiceError::Storage("Conexión rechazada".to_string()))
    }

    fn get_object(&self, _key: &str) -> Result<Option<String>, TrustServiceError> {
        Err(TrustServiceError::Storage(
            "Almacenamiento desconectado".to_string(),
        ))
    }
}

#[test]
fn test_health_check_unhealthy_when_storage_fails() {
    let publisher = Arc::new(FailingPublisher);
    let status = Arc::new(Mutex::new(None));

    let check = TrustServiceHealthCheck::new(publisher, status);
    assert_eq!(check.name(), "pip-trust-service");

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Down);
    assert!(result
        .message
        .unwrap()
        .contains("Almacenamiento de bundles no disponible"));
}

#[test]
fn test_health_check_degraded_when_starting_up() {
    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let status = Arc::new(Mutex::new(None));

    let check = TrustServiceHealthCheck::new(publisher, status);
    let result = check.check();
    assert_eq!(result.status, HealthStatus::Degraded);
    assert!(result.message.unwrap().contains("Servicio iniciando"));
}

#[test]
fn test_health_check_healthy_nominal() {
    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let status = Arc::new(Mutex::new(None));

    // Publicar bundle inicial para que el storage esté disponible
    publisher
        .publish_bundle(1, 1, r#"{"payload":"test"}"#, &[1u8; 32], 1700000000)
        .unwrap();

    let check = TrustServiceHealthCheck::new(publisher, status.clone());

    // Estado exitoso sin operadores divergentes
    *status.lock().unwrap() = Some(LastAggregationStatus {
        timestamp: 1700000000,
        success: true,
        last_bundle: Some(AggregatedSignedBundle {
            jws_json: "{}".to_string(),
            payload_b64: "test".to_string(),
            canonical_digest: [1u8; 32],
            valid_signatures_count: 3,
            distinct_operators: 3,
            divergent_operators: vec![],
        }),
        error_message: None,
    });

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Up);
    assert_eq!(result.message, None);
}

#[test]
fn test_health_check_degraded_divergent_operators() {
    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let status = Arc::new(Mutex::new(None));

    publisher
        .publish_bundle(1, 1, r#"{"payload":"test"}"#, &[1u8; 32], 1700000000)
        .unwrap();

    let check = TrustServiceHealthCheck::new(publisher, status.clone());

    // Estado exitoso pero con 1 operador divergente detectado
    *status.lock().unwrap() = Some(LastAggregationStatus {
        timestamp: 1700000000,
        success: true,
        last_bundle: Some(AggregatedSignedBundle {
            jws_json: "{}".to_string(),
            payload_b64: "test".to_string(),
            canonical_digest: [1u8; 32],
            valid_signatures_count: 3,
            distinct_operators: 3,
            divergent_operators: vec!["operator-divergent-node".to_string()],
        }),
        error_message: None,
    });

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Degraded);
    assert!(result
        .message
        .unwrap()
        .contains("operadores divergentes detectados"));
}

#[test]
fn test_health_check_degraded_last_aggregation_failed() {
    let publisher = Arc::new(InMemoryBundlePublisher::new());
    let status = Arc::new(Mutex::new(None));

    publisher
        .publish_bundle(1, 1, r#"{"payload":"test"}"#, &[1u8; 32], 1700000000)
        .unwrap();

    let check = TrustServiceHealthCheck::new(publisher, status.clone());

    // Última agregación falló
    *status.lock().unwrap() = Some(LastAggregationStatus {
        timestamp: 1700000000,
        success: false,
        last_bundle: None,
        error_message: Some("Umbral de firmas insuficiente".to_string()),
    });

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Degraded);
    assert!(result
        .message
        .unwrap()
        .contains("Última generación de trust bundle falló"));
}
