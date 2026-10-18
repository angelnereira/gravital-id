//! Pruebas de integración del motor de indexación pip-indexer (F7.T03, REQ-LEDG-005, INV-11).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use gravital_id_ledger::adapter::{BlockHeader, InMemoryLedgerAdapter};
use gravital_id_ledger::{
    EventCoordinate, IssuerRegisteredEvent, LedgerEvent, SequencedLedgerEvent,
};
use gravital_id_types::Clock;
use pip_indexer::config::IndexerConfig;
use pip_indexer::engine::IndexerEngine;
use pip_indexer::metrics::LagMetrics;
use pip_indexer::storage::{InMemoryIndexerStorage, IndexerStorage};
use pip_service_common::shutdown::ShutdownCoordinator;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Default)]
struct TestSyncClock {
    now: AtomicU64,
}

impl TestSyncClock {
    fn new(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
        }
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

fn make_header(block_number: u64, timestamp: u64) -> BlockHeader {
    BlockHeader::new(block_number, [1u8; 32], [0u8; 32], timestamp)
}

fn make_event(block: u64, tx: u32, log: u32) -> SequencedLedgerEvent {
    let coord = EventCoordinate::new(block, tx, log, 1_700_000_000u64.saturating_add(block));
    let event = LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
        issuer_id: [1u8; 32],
        uri: "https://issuer.example.com".to_string(),
        profiles: vec!["pip-personal-v1".to_string()],
        vcts: vec!["https://schema.example.com".to_string()],
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
    });
    SequencedLedgerEvent::new(coord, event)
}

#[test]
fn engine_advances_cursor_and_updates_lag_metrics() {
    let chain_id = 421614;
    let initial_head = make_header(100, 1_700_000_100);
    let mut adapter = InMemoryLedgerAdapter::new(chain_id, initial_head);

    // Añadir eventos en bloques 10, 50, 100
    adapter.add_event(make_event(10, 0, 0));
    adapter.add_event(make_event(50, 0, 0));
    adapter.add_event(make_event(100, 0, 0));

    let adapter = Arc::new(adapter);
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(1_700_000_100));
    let shutdown = ShutdownCoordinator::new();
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));

    let config = IndexerConfig {
        chain_id,
        start_block: 0,
        chunk_size_blocks: 500,
        ..Default::default()
    };

    let engine = IndexerEngine::new(adapter, storage.clone(), clock, config, shutdown, metrics);

    // 1. Paso de indexación
    let processed = engine.step().unwrap();
    assert_eq!(processed, Some(100));

    // 2. Verificar checkpoint y eventos almacenados
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(100));
    assert_eq!(storage.count_events(chain_id).unwrap(), 3);

    // 3. Verificar métricas de lag
    let m = engine.current_metrics().unwrap();
    assert_eq!(m.finalized_head, 100);
    assert_eq!(m.indexed_head, 100);
    assert_eq!(m.lag_blocks, 0);
    assert!(m.is_caught_up);

    // 4. Paso subsiguiente cuando ya está al día devuelve Ok(None)
    let next_step = engine.step().unwrap();
    assert_eq!(next_step, None);
}

#[test]
fn engine_chunks_large_event_ranges_correctly() {
    let chain_id = 421614;
    let head = make_header(120, 1_700_000_120);
    let mut adapter = InMemoryLedgerAdapter::new(chain_id, head);

    for b in 1..=120 {
        adapter.add_event(make_event(b, 0, 0));
    }

    let adapter = Arc::new(adapter);
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(1_700_000_120));
    let shutdown = ShutdownCoordinator::new();
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));

    let config = IndexerConfig {
        chain_id,
        start_block: 1,
        chunk_size_blocks: 50,
        ..Default::default()
    };

    let engine = IndexerEngine::new(adapter, storage.clone(), clock, config, shutdown, metrics);

    // Paso 1: 1..=50
    let step1 = engine.step().unwrap();
    assert_eq!(step1, Some(50));
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(50));
    assert_eq!(storage.count_events(chain_id).unwrap(), 50);

    // Paso 2: 51..=100
    let step2 = engine.step().unwrap();
    assert_eq!(step2, Some(100));
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(100));
    assert_eq!(storage.count_events(chain_id).unwrap(), 100);

    // Paso 3: 101..=120
    let step3 = engine.step().unwrap();
    assert_eq!(step3, Some(120));
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(120));
    assert_eq!(storage.count_events(chain_id).unwrap(), 120);

    // Paso 4: Al día -> None
    let step4 = engine.step().unwrap();
    assert_eq!(step4, None);
}

#[test]
fn engine_reorganizes_safely_if_finalized_head_retrocedes() {
    let chain_id = 421614;
    let initial_head = make_header(100, 1_700_000_100);
    let mut adapter = InMemoryLedgerAdapter::new(chain_id, initial_head);
    adapter.add_event(make_event(50, 0, 0));
    adapter.add_event(make_event(100, 0, 0));

    let adapter = Arc::new(adapter);
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(1_700_000_100));
    let shutdown = ShutdownCoordinator::new();
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));

    let config = IndexerConfig {
        chain_id,
        start_block: 0,
        chunk_size_blocks: 500,
        ..Default::default()
    };

    let engine = IndexerEngine::new(
        adapter.clone(),
        storage.clone(),
        clock,
        config,
        shutdown,
        metrics,
    );

    // Indexar hasta 100
    assert_eq!(engine.step().unwrap(), Some(100));
    assert_eq!(storage.count_events(chain_id).unwrap(), 2);

    // Simular que el adaptador retrocede a 80 por reorg
    // Para mutar InMemoryLedgerAdapter creamos un nuevo adapter con head=80
    let reorg_head = make_header(80, 1_700_000_080);
    let mut new_adapter = InMemoryLedgerAdapter::new(chain_id, reorg_head);
    new_adapter.add_event(make_event(50, 0, 0));

    let engine_reorg = IndexerEngine::new(
        Arc::new(new_adapter),
        storage.clone(),
        Arc::new(TestSyncClock::new(1_700_000_080)),
        IndexerConfig {
            chain_id,
            start_block: 0,
            chunk_size_blocks: 500,
            ..Default::default()
        },
        ShutdownCoordinator::new(),
        Arc::new(Mutex::new(None)),
    );

    // El paso detecta reorg: rebobina a 80
    let step_reorg = engine_reorg.step().unwrap();
    assert_eq!(step_reorg, Some(80));
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(80));
    // El evento del bloque 100 fue eliminado, queda el del bloque 50
    assert_eq!(storage.count_events(chain_id).unwrap(), 1);
}

#[test]
fn reprocess_from_block_rewinds_and_allows_reindexing() {
    let chain_id = 421614;
    let head = make_header(100, 1_700_000_100);
    let mut adapter = InMemoryLedgerAdapter::new(chain_id, head);
    adapter.add_event(make_event(40, 0, 0));
    adapter.add_event(make_event(80, 0, 0));

    let adapter = Arc::new(adapter);
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(1_700_000_100));
    let shutdown = ShutdownCoordinator::new();
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));

    let config = IndexerConfig {
        chain_id,
        start_block: 0,
        chunk_size_blocks: 500,
        ..Default::default()
    };

    let engine = IndexerEngine::new(adapter, storage.clone(), clock, config, shutdown, metrics);

    // Indexar hasta 100
    engine.step().unwrap();
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(100));
    assert_eq!(storage.count_events(chain_id).unwrap(), 2);

    // Solicitar reprocesamiento desde bloque 50
    engine.reprocess_from_block(50).unwrap();
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(50));
    // Solo quedó el evento del bloque 40
    assert_eq!(storage.count_events(chain_id).unwrap(), 1);

    // El siguiente paso re-indexa de 51 a 100
    let reindexed = engine.step().unwrap();
    assert_eq!(reindexed, Some(100));
    assert_eq!(storage.get_checkpoint(chain_id).unwrap(), Some(100));
    assert_eq!(storage.count_events(chain_id).unwrap(), 2);
}

#[test]
fn run_loop_terminates_cleanly_on_shutdown_signal() {
    let chain_id = 421614;
    let head = make_header(10, 1_700_000_010);
    let adapter = Arc::new(InMemoryLedgerAdapter::new(chain_id, head));
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(1_700_000_010));
    let shutdown = ShutdownCoordinator::new();
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));

    let config = IndexerConfig {
        chain_id,
        poll_interval_millis: 50,
        ..Default::default()
    };

    let engine = Arc::new(IndexerEngine::new(
        adapter,
        storage,
        clock,
        config,
        shutdown.clone(),
        metrics,
    ));

    let engine_clone = engine.clone();
    let handle = thread::spawn(move || {
        engine_clone.run_loop();
    });

    // Dejar correr brevemente y luego disparar apagado
    thread::sleep(Duration::from_millis(100));
    shutdown.trigger_shutdown();

    // El hilo debe unirse rápidamente sin colgarse
    handle.join().unwrap();
    assert!(engine.current_metrics().is_some());
}

struct FailingLedgerAdapter;

impl gravital_id_ledger::LedgerAdapter for FailingLedgerAdapter {
    fn chain_id(&self) -> u64 {
        421614
    }

    fn finalized_head(&self) -> gravital_id_ledger::LedgerResult<BlockHeader> {
        Err(gravital_id_ledger::LedgerError::Adapter(
            "RPC unreachable".to_string(),
        ))
    }

    fn fetch_events(
        &self,
        _from_block: u64,
        _to_block: u64,
    ) -> gravital_id_ledger::LedgerResult<Vec<SequencedLedgerEvent>> {
        Err(gravital_id_ledger::LedgerError::Adapter(
            "RPC unreachable".to_string(),
        ))
    }

    fn get_status_commitment(
        &self,
        _issuer_id: &[u8; 32],
    ) -> gravital_id_ledger::LedgerResult<Option<gravital_id_ledger::StatusCommitmentRecord>> {
        Err(gravital_id_ledger::LedgerError::Adapter(
            "RPC unreachable".to_string(),
        ))
    }
}

#[test]
fn run_loop_handles_step_error_gracefully() {
    let adapter = Arc::new(FailingLedgerAdapter);
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let clock = Arc::new(TestSyncClock::new(1_700_000_010));
    let shutdown = ShutdownCoordinator::new();
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));

    let config = IndexerConfig {
        poll_interval_millis: 20,
        ..Default::default()
    };

    let engine = Arc::new(IndexerEngine::new(
        adapter,
        storage,
        clock,
        config,
        shutdown.clone(),
        metrics,
    ));

    let engine_clone = engine.clone();
    let handle = thread::spawn(move || {
        engine_clone.run_loop();
    });

    thread::sleep(Duration::from_millis(50));
    shutdown.trigger_shutdown();
    handle.join().unwrap();
}
