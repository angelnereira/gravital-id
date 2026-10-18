//! Infraestructura y componentes comunes para los microservicios de Gravital ID (`pip-service-common`).
//!
//! Cumple con:
//! - **REQ-OBS-001:** Instrumentación y observabilidad compatible con OpenTelemetry.
//! - **REQ-PRIV-003:** Capa de redacción estricta que previene la fuga de datos personales o secretos a los logs.
//! - **REQ-REL-001:** Endpoints estándar de salud (`/healthz` y `/readyz`) y apagado ordenado.
//! - **INV-02:** Cero datos personales ni secretos en logs o métricas.
//! - **INV-09:** Prohibición absoluta de código inseguro (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod health;
pub mod redaction;
pub mod server;
pub mod shutdown;
pub mod telemetry;

pub use config::{Environment, ServerConfig, ServiceConfig, TelemetryConfig};
pub use error::CommonError;
pub use health::{ComponentHealth, HealthCheck, HealthRegistry, HealthResponse, HealthStatus};
pub use redaction::{redact_text, RedactingWriter};
pub use server::{handle_connection, handle_http_request, start_health_server};
pub use shutdown::ShutdownCoordinator;
pub use telemetry::{create_env_filter, format_description, init_telemetry, TelemetryGuard};
