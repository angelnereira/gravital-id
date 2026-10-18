//! Servidor HTTP minimalista para endpoints de salud y telemetría (F7.T02, REQ-REL-001).
//!
//! Expone `/healthz` y `/readyz` sin añadir dependencias externas pesadas en el plano de servicios base.

// Capa L5 (Servicios): Se permite I/O de red y sockets TCP para endpoints de salud y observabilidad
// conforme a PROJECT_STRUCTURE.md §4 e INV-01.
#![allow(clippy::disallowed_types)]

use crate::error::CommonError;
use crate::health::{HealthRegistry, HealthStatus};
use crate::shutdown::ShutdownCoordinator;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Procesa una solicitud HTTP entrante y devuelve el código de estado y el cuerpo JSON.
#[must_use]
pub fn handle_http_request(method: &str, path: &str, registry: &HealthRegistry) -> (u16, String) {
    if method != "GET" {
        return (
            405,
            "{\"error\":\"Method Not Allowed\",\"allowed\":[\"GET\"]}".to_string(),
        );
    }

    match path {
        "/healthz" => {
            let res = registry.check_liveness();
            let json = serde_json::to_string_pretty(&res).unwrap_or_else(|_| "{}".to_string());
            (200, json)
        }
        "/readyz" => {
            let res = registry.check_readiness();
            let json = serde_json::to_string_pretty(&res).unwrap_or_else(|_| "{}".to_string());
            let status_code = if res.status == HealthStatus::Down {
                503
            } else {
                200
            };
            (status_code, json)
        }
        _ => (
            404,
            format!("{{\"error\":\"Not Found\",\"path\":\"{path}\"}}"),
        ),
    }
}

/// Inicia el servidor de salud en un hilo en segundo plano respetando la señal de apagado ordenado.
pub fn start_health_server(
    host: &str,
    port: u16,
    registry: HealthRegistry,
    shutdown: ShutdownCoordinator,
) -> Result<(u16, thread::JoinHandle<()>), CommonError> {
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).map_err(|e| {
        CommonError::Server(format!("No se pudo vincular TcpListener a '{addr}': {e}"))
    })?;

    let bound_port = listener
        .local_addr()
        .map_err(|e| CommonError::Server(format!("Error obteniendo local_addr: {e}")))?
        .port();

    listener.set_nonblocking(true).map_err(|e| {
        CommonError::Server(format!("Error configurando non-blocking en socket: {e}"))
    })?;

    let handle = thread::spawn(move || {
        while !shutdown.is_shutting_down() {
            match listener.accept() {
                Ok((stream, _)) => {
                    handle_connection(stream, &registry);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });

    Ok((bound_port, handle))
}

/// Maneja una conexión entrante TCP procesando la solicitud HTTP.
pub fn handle_connection(mut stream: TcpStream, registry: &HealthRegistry) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let mut buffer = [0u8; 1024];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let slice = buffer.get(..bytes_read).unwrap_or(&[]);
    let request_str = String::from_utf8_lossy(slice);
    let mut lines = request_str.lines();
    let request_line = match lines.next() {
        Some(line) => line,
        None => return,
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        let _ = write_http_response(&mut stream, 400, "{\"error\":\"Bad Request\"}");
        return;
    }

    let method = parts.first().copied().unwrap_or("");
    let path = parts.get(1).copied().unwrap_or("");

    let (status_code, body) = handle_http_request(method, path, registry);
    let _ = write_http_response(&mut stream, status_code, &body);
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status_code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };

    let response = format!(
        "HTTP/1.1 {status_code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );

    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}
