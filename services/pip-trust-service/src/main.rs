//! Punto de entrada ejecutable de `pip-trust-service` (F7.T04, REQ-TRUST-003, REQ-OBS-001).

#![forbid(unsafe_code)]

use pip_indexer::storage::InMemoryIndexerStorage;
use pip_service_common::health::HealthRegistry;
use pip_service_common::server::start_health_server;
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_service_common::telemetry::init_telemetry;
use pip_trust_service::aggregator::UntrustedBundleAggregator;
use pip_trust_service::config::TrustServiceConfig;
use pip_trust_service::engine::{TrustEngineDeps, TrustServiceEngine};
use pip_trust_service::health::{LastAggregationStatus, TrustServiceHealthCheck};
use pip_trust_service::operator::TrustOperatorNode;
use pip_trust_service::publisher::{
    BundlePublisher, FileSystemBundlePublisher, InMemoryBundlePublisher,
};
use pip_trust_service::signer::{BundleSignerBackend, LocalDevSigner};
use std::sync::{Arc, Mutex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Cargar configuración tipada desde variables de entorno (REQ-REL-001)
    let config = TrustServiceConfig::from_env()?;

    // 2. Inicializar observabilidad con capa de redacción no-PII (REQ-OBS-001, REQ-PRIV-003)
    let _telemetry_guard = init_telemetry(&config.telemetry)?;
    tracing::info!(
        service = "pip-trust-service",
        chain_id = config.chain_id,
        operator_id = %config.operator_id,
        "Iniciando servicio de confianza y cofirma"
    );

    // 3. Coordinador de apagado ordenado
    let shutdown = ShutdownCoordinator::new();

    // 4. Inicializar firmante del operador
    let signer: Arc<dyn BundleSignerBackend> =
        if let Some(hex_key) = &config.operator_private_key_hex {
            Arc::new(LocalDevSigner::from_hex(
                &config.operator_id,
                &config.operator_kid,
                hex_key,
            )?)
        } else {
            return Err(pip_trust_service::error::TrustServiceError::Config(
            "Clave de operador no configurada: PIP_TRUST_OPERATOR_PRIVATE_KEY_HEX es obligatoria"
                .to_string(),
        )
        .into());
        };

    // 5. Inicializar nodo operador local con almacenamiento indexador
    let storage = Arc::new(InMemoryIndexerStorage::new());
    let primary_node = Arc::new(TrustOperatorNode::new(storage, signer, config.chain_id));

    // 6. Inicializar publicador de artefactos
    let publisher: Arc<dyn BundlePublisher> = match config.storage_backend.as_str() {
        "filesystem" => Arc::new(FileSystemBundlePublisher::new(&config.storage_local_dir)?),
        _ => Arc::new(InMemoryBundlePublisher::new()),
    };

    // 7. Registro de salud HTTP (/healthz, /readyz)
    let status = Arc::new(Mutex::new(None::<LastAggregationStatus>));
    let mut health_registry = HealthRegistry::new("pip-trust-service", "0.1.0");
    let health_check = TrustServiceHealthCheck::new(publisher.clone(), status.clone());
    health_registry.register_check(health_check);

    let (port, server_handle) = start_health_server(
        &config.server.host,
        config.server.port,
        health_registry,
        shutdown.clone(),
    )?;
    tracing::info!(port = port, "Servidor de salud HTTP iniciado");

    // 8. Motor orquestador
    let aggregator = UntrustedBundleAggregator::new(config.threshold);
    let clock = Arc::new(pip_indexer::clock::SystemClock);
    let deps = TrustEngineDeps {
        primary_node,
        operator_nodes: vec![],
        aggregator,
        publisher,
        clock,
        shutdown: shutdown.clone(),
        status,
    };
    let engine = TrustServiceEngine::new(config, deps);

    // Ejecutar bucle principal
    engine.run_loop(|| None);

    // Esperar terminación del servidor de salud
    let _ = server_handle.join();
    tracing::info!("Servicio pip-trust-service detenido limpiamente");
    Ok(())
}
