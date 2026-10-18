//! Pruebas unitarias de IndexerHealthCheck para pip-indexer (F7.T03, REQ-REL-001, REQ-OBS-001).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use gravital_id_ledger::{LedgerState, SequencedLedgerEvent};
use pip_indexer::error::IndexerError;
use pip_indexer::health::IndexerHealthCheck;
use pip_indexer::metrics::LagMetrics;
use pip_indexer::storage::{InMemoryIndexerStorage, IndexerStorage};
use pip_service_common::health::{HealthCheck, HealthStatus};
use std::sync::{Arc, Mutex};

struct FailingStorage;

impl IndexerStorage for FailingStorage {
    fn get_checkpoint(&self, _chain_id: u64) -> Result<Option<u64>, IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }

    fn save_checkpoint(
        &self,
        _chain_id: u64,
        _block_number: u64,
        _block_hash: Option<&str>,
        _timestamp: u64,
    ) -> Result<(), IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }

    fn store_events(
        &self,
        _chain_id: u64,
        _events: &[SequencedLedgerEvent],
    ) -> Result<usize, IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }

    fn get_events(
        &self,
        _chain_id: u64,
        _from_block: u64,
        _to_block: u64,
    ) -> Result<Vec<SequencedLedgerEvent>, IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }

    fn rewind_to_block(
        &self,
        _chain_id: u64,
        _target_block: u64,
        _timestamp: u64,
    ) -> Result<(), IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }

    fn count_events(&self, _chain_id: u64) -> Result<usize, IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }

    fn build_ledger_state(&self, _chain_id: u64) -> Result<LedgerState, IndexerError> {
        Err(IndexerError::Database("DB connection refused".to_string()))
    }
}

#[test]
fn health_check_returns_up_when_storage_is_ready_and_no_metrics() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));
    let check = IndexerHealthCheck::new(storage, 421614, 50, metrics);

    assert_eq!(check.name(), "pip-indexer");
    let result = check.check();
    assert_eq!(result.status, HealthStatus::Up);
    assert!(result.message.is_none());
}

#[test]
fn health_check_returns_up_when_lag_is_within_threshold() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let metrics = Arc::new(Mutex::new(Some(LagMetrics::compute(
        1000,
        980,
        1_700_000_000,
    ))));
    let check = IndexerHealthCheck::new(storage, 421614, 50, metrics);

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Up);
}

#[test]
fn health_check_returns_degraded_when_lag_exceeds_threshold() {
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let metrics = Arc::new(Mutex::new(Some(LagMetrics::compute(
        1000,
        900,
        1_700_000_000,
    ))));
    let check = IndexerHealthCheck::new(storage, 421614, 50, metrics);

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Degraded);
    assert!(result
        .message
        .unwrap()
        .contains("Retraso de sincronización elevado"));
}

#[test]
fn health_check_returns_down_when_storage_fails() {
    let storage = Arc::new(FailingStorage);
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));
    let check = IndexerHealthCheck::new(storage, 421614, 50, metrics);

    let result = check.check();
    assert_eq!(result.status, HealthStatus::Down);
    assert!(result.message.unwrap().contains("DB connection refused"));
}
