//! Binario ejecutable para el microservicio `pip-relay` (F7.T06, REQ-SYNC-004, REQ-SYNC-006).

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pip_relay::clock::SystemClock;
use pip_relay::config::RelayConfig;
use pip_relay::health::RelayHealthCheck;
use pip_relay::limiter::RateLimiter;
use pip_relay::server::{start_relay_server, RelayHttpService};
use pip_relay::store::InMemoryRelayStore;
use pip_service_common::health::HealthRegistry;
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_service_common::telemetry::init_telemetry;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Cargar configuración tipada desde variables de entorno (REQ-REL-001)
    let config = RelayConfig::from_env()?;

    // 2. Inicializar observabilidad con capa de redacción no-PII (REQ-OBS-001, REQ-PRIV-003)
    let _telemetry = init_telemetry(&config.telemetry)?;

    tracing::info!(
        port = config.server.port,
        host = %config.server.host,
        max_payload_bytes = config.max_payload_bytes,
        "Iniciando microservicio pip-relay"
    );

    // 3. Coordinador de apagado ordenado
    let shutdown = ShutdownCoordinator::new();

    // 4. Componentes principales del relay
    let clock = SystemClock;
    let store = Arc::new(InMemoryRelayStore::new(config.clone(), clock));
    let limiter = Arc::new(RateLimiter::new(
        config.rate_limit_requests_per_minute,
        config.rate_limit_burst,
        clock,
    ));

    // 5. Registro de salud
    let mut health_registry = HealthRegistry::new("pip-relay", "0.1.0");
    health_registry.register_check(RelayHealthCheck::new(Arc::clone(&store)));

    // 6. Servicio HTTP
    let http_service = Arc::new(RelayHttpService::new(
        Arc::clone(&store),
        limiter,
        health_registry,
    ));

    // 7. Servidor TCP
    let (bound_port, server_handle) = start_relay_server(
        &config.server.host,
        config.server.port,
        http_service,
        shutdown.clone(),
    )?;

    tracing::info!(bound_port = bound_port, "Servidor pip-relay en escucha");

    // 8. Hilo de mantenimiento periódico para purgar entradas caducadas
    let cleanup_store = Arc::clone(&store);
    let cleanup_shutdown = shutdown.clone();
    let cleanup_handle = thread::spawn(move || {
        while !cleanup_shutdown.is_shutting_down() {
            cleanup_store.cleanup_expired();
            thread::sleep(Duration::from_secs(60));
        }
    });

    // Esperar hasta que se solicite el apagado
    while !shutdown.is_shutting_down() {
        thread::sleep(Duration::from_millis(200));
    }
    tracing::info!("Señal de apagado recibida; procediendo a cierre ordenado");

    let _ = server_handle.join();
    let _ = cleanup_handle.join();

    tracing::info!("pip-relay apagado satisfactoriamente");
    Ok(())
}
