//! Pruebas de comprobaciones de salud /healthz y /readyz y servidor HTTP (REQ-REL-001).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_types)] // Pruebas locales deterministas en capa L5 de servicios (PROJECT_STRUCTURE.md §5.1, INV-01).

use pip_service_common::config::TelemetryConfig;
use pip_service_common::health::{ComponentHealth, HealthCheck, HealthRegistry, HealthStatus};
use pip_service_common::server::{handle_http_request, start_health_server};
use pip_service_common::shutdown::ShutdownCoordinator;
use pip_service_common::telemetry::init_telemetry;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

struct MockDependency {
    name: &'static str,
    status: HealthStatus,
}

impl HealthCheck for MockDependency {
    fn name(&self) -> &str {
        self.name
    }

    fn check(&self) -> ComponentHealth {
        match self.status {
            HealthStatus::Up => ComponentHealth::healthy(self.name),
            HealthStatus::Degraded => {
                ComponentHealth::degraded(self.name, "Latencia alta observada")
            }
            HealthStatus::Down => ComponentHealth::unhealthy(self.name, "Conexión rechazada"),
        }
    }
}

#[test]
fn health_registry_evaluates_liveness_and_readiness() {
    let mut registry = HealthRegistry::new("pip-indexer", "0.1.0");

    // Liveness siempre está UP si el proceso responde
    let liveness = registry.check_liveness();
    assert_eq!(liveness.status, HealthStatus::Up);
    assert_eq!(liveness.service, "pip-indexer");

    // Sin comprobaciones adicionales, readiness es UP
    let readiness = registry.check_readiness();
    assert_eq!(readiness.status, HealthStatus::Up);

    // Añadir dependencia saludable
    registry.register_check(MockDependency {
        name: "postgres",
        status: HealthStatus::Up,
    });
    let readiness = registry.check_readiness();
    assert_eq!(readiness.status, HealthStatus::Up);
    assert_eq!(readiness.components.len(), 1);

    // Añadir dependencia degradada -> general Degraded
    registry.register_check(MockDependency {
        name: "rpc_secondary",
        status: HealthStatus::Degraded,
    });
    let readiness = registry.check_readiness();
    assert_eq!(readiness.status, HealthStatus::Degraded);
    assert!(readiness.status.is_ready());

    // Añadir dependencia caída -> general Down
    registry.register_check(MockDependency {
        name: "ledger_primary",
        status: HealthStatus::Down,
    });
    let readiness = registry.check_readiness();
    assert_eq!(readiness.status, HealthStatus::Down);
    assert!(!readiness.status.is_ready());
}

#[test]
fn http_request_handler_returns_correct_status_codes() {
    let mut registry = HealthRegistry::new("pip-relay", "0.1.0");

    let (status, body) = handle_http_request("GET", "/healthz", &registry);
    assert_eq!(status, 200);
    assert!(body.contains("\"status\": \"UP\""));

    let (status, body) = handle_http_request("GET", "/readyz", &registry);
    assert_eq!(status, 200);
    assert!(body.contains("\"status\": \"UP\""));

    // Con dependencia caída, /readyz devuelve 503 Service Unavailable
    registry.register_check(MockDependency {
        name: "s3_storage",
        status: HealthStatus::Down,
    });
    let (status, body) = handle_http_request("GET", "/readyz", &registry);
    assert_eq!(status, 503);
    assert!(body.contains("\"status\": \"DOWN\""));

    // Rutas no encontradas -> 404
    let (status, _) = handle_http_request("GET", "/unknown", &registry);
    assert_eq!(status, 404);

    // Métodos no permitidos -> 405
    let (status, _) = handle_http_request("POST", "/healthz", &registry);
    assert_eq!(status, 405);
}

#[test]
fn shutdown_coordinator_signals_correctly() {
    let coordinator = ShutdownCoordinator::default();
    assert!(!coordinator.is_shutting_down());

    // Timeout antes de señal
    assert!(!coordinator.wait_for_signal(Duration::from_millis(50)));

    // Disparar señal
    coordinator.trigger_shutdown();
    assert!(coordinator.is_shutting_down());
    assert!(coordinator.wait_for_signal(Duration::from_millis(50)));
}

#[test]
fn health_server_starts_and_handles_requests_and_graceful_shutdown() {
    let registry = HealthRegistry::new("test-server", "1.0.0");
    let shutdown = ShutdownCoordinator::new();

    // Puerto 0 asigna automáticamente un puerto libre del sistema operativo
    let (bound_port, handle) =
        start_health_server("127.0.0.1", 0, registry, shutdown.clone()).unwrap();
    assert!(bound_port > 0);

    // 1. Petición GET válida
    let mut stream = TcpStream::connect(format!("127.0.0.1:{bound_port}")).unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("\"status\": \"UP\""));

    // 2. Petición malformada -> 400 Bad Request
    let mut stream_bad = TcpStream::connect(format!("127.0.0.1:{bound_port}")).unwrap();
    stream_bad.write_all(b"MALFORMED_LINE\r\n\r\n").unwrap();
    let mut response_bad = String::new();
    stream_bad.read_to_string(&mut response_bad).unwrap();
    assert!(response_bad.contains("HTTP/1.1 400 Bad Request"));

    // 3. Disparar apagado ordenado y verificar que el hilo termina limpiamente
    shutdown.trigger_shutdown();
    handle.join().unwrap();
}

#[test]
fn telemetry_init_sets_up_guard() {
    let config = TelemetryConfig {
        service_name: "test-telemetry-service".to_string(),
        log_level: "info".to_string(),
        json_format: false,
        enable_redaction: true,
    };

    // La inicialización puede ocurrir una vez; si ya fue inicializado por otro test, devuelve error controlado
    let res = init_telemetry(&config);
    if let Ok(guard) = res {
        assert_eq!(guard.service_name(), "test-telemetry-service");
        let res2 = init_telemetry(&config);
        assert!(res2.is_err());
    } else {
        assert!(res.is_err());
    }
}

#[test]
fn telemetry_helpers_and_formatting() {
    let filter = pip_service_common::telemetry::create_env_filter("debug");
    assert_eq!(filter.to_string(), "debug");

    let cfg1 = TelemetryConfig {
        service_name: "relay".to_string(),
        log_level: "warn".to_string(),
        json_format: true,
        enable_redaction: true,
    };
    let desc1 = pip_service_common::telemetry::format_description(&cfg1);
    assert!(desc1.contains("service=relay"));
    assert!(desc1.contains("format=json"));

    let cfg2 = TelemetryConfig {
        service_name: "indexer".to_string(),
        log_level: "info".to_string(),
        json_format: false,
        enable_redaction: false,
    };
    let desc2 = pip_service_common::telemetry::format_description(&cfg2);
    assert!(desc2.contains("format=compact"));
    assert!(desc2.contains("redaction=false"));
}

#[test]
fn handle_connection_edge_cases() {
    let registry = HealthRegistry::new("test", "1.0");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // 1. Conexión cerrada inmediatamente (0 bytes)
    let stream_client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let (stream_server, _) = listener.accept().unwrap();
    drop(stream_client);
    pip_service_common::server::handle_connection(stream_server, &registry);

    // 2. Línea vacía
    let mut stream_client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let (stream_server, _) = listener.accept().unwrap();
    stream_client.write_all(b"\r\n\r\n").unwrap();
    pip_service_common::server::handle_connection(stream_server, &registry);

    // 3. Ruta no encontrada vía handle_connection
    let mut stream_client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let (stream_server, _) = listener.accept().unwrap();
    stream_client
        .write_all(b"GET /notfound HTTP/1.1\r\n\r\n")
        .unwrap();
    pip_service_common::server::handle_connection(stream_server, &registry);

    // 4. Método no permitido vía handle_connection
    let mut stream_client = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let (stream_server, _) = listener.accept().unwrap();
    stream_client
        .write_all(b"POST /healthz HTTP/1.1\r\n\r\n")
        .unwrap();
    pip_service_common::server::handle_connection(stream_server, &registry);

    // 5. Validar is_ready en todos los estados
    assert!(HealthStatus::Up.is_ready());
    assert!(HealthStatus::Degraded.is_ready());
    assert!(!HealthStatus::Down.is_ready());
}

#[test]
fn telemetry_build_layer_covers_all_configurations() {
    let configs = [
        TelemetryConfig {
            service_name: "s1".to_string(),
            log_level: "info".to_string(),
            json_format: true,
            enable_redaction: true,
        },
        TelemetryConfig {
            service_name: "s2".to_string(),
            log_level: "debug".to_string(),
            json_format: false,
            enable_redaction: true,
        },
        TelemetryConfig {
            service_name: "s3".to_string(),
            log_level: "warn".to_string(),
            json_format: true,
            enable_redaction: false,
        },
        TelemetryConfig {
            service_name: "s4".to_string(),
            log_level: "error".to_string(),
            json_format: false,
            enable_redaction: false,
        },
    ];

    for cfg in &configs {
        let _layer =
            pip_service_common::telemetry::build_layer::<tracing_subscriber::Registry>(cfg);
    }
}

#[test]
fn telemetry_create_env_filter_handles_invalid_filter() {
    let filter = pip_service_common::telemetry::create_env_filter("invalid[filter(syntax");
    assert_eq!(filter.to_string(), "info");
}

#[test]
fn start_health_server_fails_on_invalid_address() {
    let registry = HealthRegistry::new("test", "1.0");
    let shutdown = ShutdownCoordinator::new();
    let res = start_health_server("999.999.999.999", 80, registry, shutdown);
    assert!(res.is_err());
}
