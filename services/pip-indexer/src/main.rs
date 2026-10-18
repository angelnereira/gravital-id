//! Punto de entrada ejecutable de `pip-indexer` (F7.T03, REQ-LEDG-005, REQ-OBS-001).

#![forbid(unsafe_code)]

use gravital_id_ledger_evm::adapter::{EvmContractAddresses, EvmLedgerAdapter};
use gravital_id_ledger_evm::client::{MultiRpcClient, MultiRpcConfig};
use pip_indexer::config::IndexerConfig;
use pip_indexer::engine::IndexerEngine;
use pip_indexer::health::IndexerHealthCheck;
use pip_indexer::metrics::LagMetrics;
use pip_indexer::storage::{IndexerStorage, SqliteIndexerStorage};
use pip_service_common::health::HealthRegistry;
use pip_service_common::server::start_health_server;
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_service_common::telemetry::init_telemetry;
use std::sync::{Arc, Mutex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Cargar configuración tipada desde variables de entorno (REQ-REL-001)
    let config = IndexerConfig::from_env()?;

    // 2. Inicializar observabilidad con capa de redacción no-PII (REQ-OBS-001, REQ-PRIV-003)
    let _telemetry_guard = init_telemetry(&config.telemetry)?;
    tracing::info!(
        service = "pip-indexer",
        chain_id = config.chain_id,
        "Iniciando servicio indexador"
    );

    // 3. Coordinador de apagado ordenado
    let shutdown = ShutdownCoordinator::new();

    // 4. Inicializar capa de almacenamiento relacional
    let storage: Arc<dyn IndexerStorage> = if config.database_url.starts_with("sqlite://") {
        let path = config
            .database_url
            .strip_prefix("sqlite://")
            .unwrap_or(":memory:");
        Arc::new(SqliteIndexerStorage::new_from_path(path)?)
    } else {
        // En ausencia de SQLite URI directa, iniciar almacenamiento relacional en memoria/disco local
        Arc::new(SqliteIndexerStorage::new_in_memory()?)
    };

    // 5. Adaptador EVM multi-RPC con tolerancia a fallos (REQ-LEDG-006)
    let transport = Arc::new(gravital_id_ledger_evm::transport::MockRpcTransport::new());
    let rpc_config = MultiRpcConfig::new(config.rpc_endpoints.clone());
    let rpc_client = MultiRpcClient::new(rpc_config, transport)?;
    let contracts = EvmContractAddresses::new(
        config.trust_registry_address.clone(),
        config.status_anchor_address.clone(),
    );
    let adapter = Arc::new(EvmLedgerAdapter::new(rpc_client, contracts)?);

    // 6. Registro y servidor HTTP de salud (/healthz, /readyz)
    let metrics = Arc::new(Mutex::new(None::<LagMetrics>));
    let mut health_registry = HealthRegistry::new("pip-indexer", "0.1.0");
    let health_check = IndexerHealthCheck::new(
        storage.clone(),
        config.chain_id,
        config.max_allowed_lag,
        metrics.clone(),
    );
    health_registry.register_check(health_check);

    let (port, server_handle) = start_health_server(
        &config.server.host,
        config.server.port,
        health_registry,
        shutdown.clone(),
    )?;
    tracing::info!(port = port, "Servidor de salud HTTP iniciado");

    // 7. Motor de indexación
    let clock = Arc::new(pip_indexer::clock::SystemClock);
    let engine = IndexerEngine::new(adapter, storage, clock, config, shutdown.clone(), metrics);

    // Ejecutar bucle principal
    engine.run_loop();

    // Esperar terminación del servidor de salud
    let _ = server_handle.join();
    tracing::info!("Servicio pip-indexer detenido limpiamente");
    Ok(())
}
