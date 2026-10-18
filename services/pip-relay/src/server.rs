//! Servidor HTTP y despachador de rutas para pip-relay (F7.T06, REQ-SYNC-004, REQ-SYNC-006).
//!
//! Implementa la API REST de retransmisión:
//! - `/healthz` y `/readyz` (Liveness / Readiness)
//! - `/v1/objects` y `/v1/objects/{sha256}` (Objetos inmutables por digest)
//! - `/v1/mailboxes/{inbox_id}/envelopes` (Buzones de sobres HPKE con idempotencia)
//! - `/v1/rendezvous/{session_hash}/request` y `/response` (Punto de encuentro efímero)
//! - `/v1/rendezvous/code/validate` (Validación de SessionCode con algoritmo de Damm)

// Capa L5 (Servicios): Se permite I/O de red y sockets TCP conforme a PROJECT_STRUCTURE.md §4 e INV-01.
#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use gravital_id_codec::base64url;
use gravital_id_types::{Clock, UnixTime};
use pip_service_common::error::CommonError;
use pip_service_common::health::HealthRegistry;
use pip_service_common::shutdown::ShutdownCoordinator;
use serde::{Deserialize, Serialize};

use crate::error::RelayError;
use crate::limiter::RateLimiter;
use crate::store::{
    compute_session_hash_hex, validate_session_code, EnvelopeRecord, InMemoryRelayStore,
};

/// Solicitud de publicación de sobre en un buzón.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostEnvelopeRequest {
    /// Identificador único del sobre (clave de idempotencia).
    pub envelope_id: String,
    /// Carga cifrada en base64url (HPKE ciphertext).
    pub payload_b64: String,
    /// TTL opcional en segundos.
    pub ttl_secs: Option<u64>,
}

/// Representación JSON de un sobre retornado por el buzón.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeResponse {
    /// Identificador del sobre.
    pub envelope_id: String,
    /// Carga cifrada en base64url.
    pub payload_b64: String,
    /// Timestamp Unix de creación.
    pub created_at: u64,
    /// Timestamp Unix de caducidad.
    pub expires_at: u64,
}

impl From<&EnvelopeRecord> for EnvelopeResponse {
    fn from(rec: &EnvelopeRecord) -> Self {
        Self {
            envelope_id: rec.envelope_id.clone(),
            payload_b64: base64url::encode(&rec.payload),
            created_at: rec.created_at.as_seconds(),
            expires_at: rec.expires_at.as_seconds(),
        }
    }
}

/// Solicitud de registro de petición o respuesta de punto de encuentro.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousPayload {
    /// Contenido binario en base64url (`ProximityRequest` o `ProximityResponse`).
    pub payload_b64: String,
    /// TTL opcional en segundos (máx. 180 s).
    pub ttl_secs: Option<u64>,
}

/// Solicitud de validación de código de sesión.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateSessionCodeRequest {
    /// Código numérico de sesión (10 dígitos).
    pub session_code: String,
}

/// Respuesta de validación de código de sesión.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateSessionCodeResponse {
    /// Indica si el código es válido (Damm verificado).
    pub valid: bool,
    /// Código canónico de 10 dígitos sin separadores.
    pub canonical_code: String,
    /// Hash de sesión hex de 64 caracteres para rendezvous en el relay.
    pub session_hash: String,
}

/// Servicio HTTP principal de `pip-relay`.
pub struct RelayHttpService<C: Clock + Send + Sync + 'static> {
    store: Arc<InMemoryRelayStore<C>>,
    limiter: Arc<RateLimiter<C>>,
    health_registry: HealthRegistry,
}

impl<C: Clock + Send + Sync + 'static> RelayHttpService<C> {
    /// Construye una nueva instancia del servicio HTTP.
    pub fn new(
        store: Arc<InMemoryRelayStore<C>>,
        limiter: Arc<RateLimiter<C>>,
        health_registry: HealthRegistry,
    ) -> Self {
        Self {
            store,
            limiter,
            health_registry,
        }
    }

    /// Retorna una referencia al almacén interno.
    #[must_use]
    pub fn store(&self) -> &InMemoryRelayStore<C> {
        &self.store
    }

    /// Despacha una solicitud HTTP y genera el código de estado, cabeceras y cuerpo.
    ///
    /// Método sans-I/O invocable directamente en pruebas unitarias y de integración.
    pub fn handle_request(
        &self,
        client_id: &str,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        // Endpoints de salud exentos de límite de tasa
        if path == "/healthz" && method == "GET" {
            let res = self.health_registry.check_liveness();
            let json = serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string());
            return (
                200,
                vec![("Content-Type".into(), "application/json".into())],
                json.into_bytes(),
            );
        }

        if path == "/readyz" && method == "GET" {
            let res = self.health_registry.check_readiness();
            let json = serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string());
            let status = if res.status == pip_service_common::health::HealthStatus::Down {
                503
            } else {
                200
            };
            return (
                status,
                vec![("Content-Type".into(), "application/json".into())],
                json.into_bytes(),
            );
        }

        // Control de tasa de peticiones (Rate Limiting)
        if let Err(err) = self.limiter.check_rate_limit(client_id) {
            return self.error_response(err);
        }

        let clean_path = path.split('?').next().unwrap_or(path);

        // Enrutamiento de objetos por hash
        if clean_path.starts_with("/v1/objects") {
            return self.route_objects(method, clean_path, body);
        }

        // Enrutamiento de buzones de sobres
        if clean_path.starts_with("/v1/mailboxes") {
            let query = path.split('?').nth(1);
            return self.route_mailboxes(method, clean_path, query, body);
        }

        // Enrutamiento de punto de encuentro (Rendezvous)
        if clean_path.starts_with("/v1/rendezvous") {
            return self.route_rendezvous(method, clean_path, body);
        }

        (
            404,
            vec![("Content-Type".into(), "application/json".into())],
            format!("{{\"error\":\"not_found\",\"path\":\"{clean_path}\"}}").into_bytes(),
        )
    }

    fn route_objects(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        if path == "/v1/objects" {
            if method != "POST" {
                return (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec());
            }

            // POST /v1/objects: puede ser binario directo o JSON { "payload_b64": "..." }
            let data = if let Ok(parsed) = serde_json::from_slice::<RendezvousPayload>(body) {
                base64url::decode(&parsed.payload_b64).unwrap_or_else(|_| body.to_vec())
            } else {
                body.to_vec()
            };

            match self.store.put_object(data, None, None) {
                Ok(sha256_hex) => {
                    let resp = format!(
                        "{{\"sha256\":\"{sha256_hex}\",\"uri\":\"/v1/objects/{sha256_hex}\"}}"
                    );
                    (
                        201,
                        vec![("Content-Type".into(), "application/json".into())],
                        resp.into_bytes(),
                    )
                }
                Err(e) => self.error_response(e),
            }
        } else if let Some(hash) = path.strip_prefix("/v1/objects/") {
            let clean_hash = hash.trim_matches('/');
            match method {
                "GET" => match self.store.get_object(clean_hash) {
                    Ok(data) => (
                        200,
                        vec![
                            ("Content-Type".into(), "application/octet-stream".into()),
                            (
                                "Cache-Control".into(),
                                "public, max-age=604800, immutable".into(),
                            ),
                            ("ETag".into(), format!("\"{clean_hash}\"")),
                        ],
                        data,
                    ),
                    Err(e) => self.error_response(e),
                },
                "PUT" => match self.store.put_object(body.to_vec(), Some(clean_hash), None) {
                    Ok(sha) => {
                        let resp = format!("{{\"sha256\":\"{sha}\",\"status\":\"stored\"}}");
                        (
                            201,
                            vec![("Content-Type".into(), "application/json".into())],
                            resp.into_bytes(),
                        )
                    }
                    Err(e) => self.error_response(e),
                },
                _ => (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec()),
            }
        } else {
            (404, vec![], b"{\"error\":\"not_found\"}".to_vec())
        }
    }

    fn route_mailboxes(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        // Expecting: ["v1", "mailboxes", inbox_id, "envelopes", (envelope_id)]
        if segments.len() < 4
            || segments.get(1) != Some(&"mailboxes")
            || segments.get(3) != Some(&"envelopes")
        {
            return (404, vec![], b"{\"error\":\"not_found\"}".to_vec());
        }

        let inbox_id = match segments.get(2) {
            Some(id) => *id,
            None => return (400, vec![], b"{\"error\":\"missing_inbox_id\"}".to_vec()),
        };

        if segments.len() == 4 {
            match method {
                "POST" => {
                    let req: PostEnvelopeRequest = match serde_json::from_slice(body) {
                        Ok(r) => r,
                        Err(_) => {
                            return (
                                400,
                                vec![("Content-Type".into(), "application/json".into())],
                                b"{\"error\":\"invalid_json_payload\"}".to_vec(),
                            );
                        }
                    };

                    let payload_bytes = match base64url::decode(&req.payload_b64) {
                        Ok(b) => b,
                        Err(_) => {
                            return (
                                400,
                                vec![("Content-Type".into(), "application/json".into())],
                                b"{\"error\":\"invalid_base64url_payload\"}".to_vec(),
                            );
                        }
                    };

                    match self.store.post_envelope(
                        inbox_id,
                        &req.envelope_id,
                        payload_bytes,
                        req.ttl_secs,
                    ) {
                        Ok(newly_inserted) => {
                            let status = if newly_inserted { 201 } else { 200 };
                            let resp = format!(
                                "{{\"status\":\"{}\",\"envelope_id\":\"{}\"}}",
                                if newly_inserted {
                                    "created"
                                } else {
                                    "duplicate_acknowledged"
                                },
                                req.envelope_id
                            );
                            (
                                status,
                                vec![("Content-Type".into(), "application/json".into())],
                                resp.into_bytes(),
                            )
                        }
                        Err(e) => self.error_response(e),
                    }
                }
                "GET" => {
                    let since_time = query.and_then(|q| {
                        q.split('&')
                            .find(|param| param.starts_with("since="))
                            .and_then(|param| param.strip_prefix("since="))
                            .and_then(|val| val.parse::<u64>().ok())
                            .map(UnixTime::from_seconds)
                    });

                    match self.store.get_envelopes(inbox_id, since_time) {
                        Ok(envelopes) => {
                            let dtos: Vec<EnvelopeResponse> =
                                envelopes.iter().map(EnvelopeResponse::from).collect();
                            let json = serde_json::to_string(&dtos).unwrap_or_else(|_| "[]".into());
                            (
                                200,
                                vec![("Content-Type".into(), "application/json".into())],
                                json.into_bytes(),
                            )
                        }
                        Err(e) => self.error_response(e),
                    }
                }
                _ => (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec()),
            }
        } else if segments.len() == 5 {
            let envelope_id = match segments.get(4) {
                Some(id) => *id,
                None => return (400, vec![], b"{\"error\":\"missing_envelope_id\"}".to_vec()),
            };

            if method == "DELETE" {
                match self.store.delete_envelope(inbox_id, envelope_id) {
                    Ok(deleted) => {
                        let resp = format!("{{\"deleted\":{deleted}}}");
                        let status = if deleted { 200 } else { 404 };
                        (
                            status,
                            vec![("Content-Type".into(), "application/json".into())],
                            resp.into_bytes(),
                        )
                    }
                    Err(e) => self.error_response(e),
                }
            } else {
                (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec())
            }
        } else {
            (404, vec![], b"{\"error\":\"not_found\"}".to_vec())
        }
    }

    fn route_rendezvous(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        if path == "/v1/rendezvous/code/validate" {
            if method != "POST" {
                return (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec());
            }

            let req: ValidateSessionCodeRequest = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => {
                    return (
                        400,
                        vec![("Content-Type".into(), "application/json".into())],
                        b"{\"error\":\"invalid_json_payload\"}".to_vec(),
                    );
                }
            };

            match validate_session_code(&req.session_code) {
                Ok(canonical_code) => {
                    let session_hash = compute_session_hash_hex(&canonical_code);
                    let resp = ValidateSessionCodeResponse {
                        valid: true,
                        canonical_code,
                        session_hash,
                    };
                    let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
                    (
                        200,
                        vec![("Content-Type".into(), "application/json".into())],
                        json.into_bytes(),
                    )
                }
                Err(e) => self.error_response(e),
            }
        } else {
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            // Expecting: ["v1", "rendezvous", session_hash, ("request" | "response")]
            if segments.len() != 4 || segments.get(1) != Some(&"rendezvous") {
                return (404, vec![], b"{\"error\":\"not_found\"}".to_vec());
            }

            let session_hash = match segments.get(2) {
                Some(h) => *h,
                None => {
                    return (
                        400,
                        vec![],
                        b"{\"error\":\"missing_session_hash\"}".to_vec(),
                    )
                }
            };

            let subpath = match segments.get(3) {
                Some(s) => *s,
                None => return (404, vec![], b"{\"error\":\"not_found\"}".to_vec()),
            };

            match subpath {
                "request" => match method {
                    "POST" => {
                        let (bytes, ttl) =
                            if let Ok(parsed) = serde_json::from_slice::<RendezvousPayload>(body) {
                                let b = base64url::decode(&parsed.payload_b64)
                                    .unwrap_or_else(|_| body.to_vec());
                                (b, parsed.ttl_secs)
                            } else {
                                (body.to_vec(), None)
                            };

                        match self
                            .store
                            .register_session_request(session_hash, bytes, ttl)
                        {
                            Ok(()) => (
                                201,
                                vec![("Content-Type".into(), "application/json".into())],
                                b"{\"status\":\"registered\"}".to_vec(),
                            ),
                            Err(e) => self.error_response(e),
                        }
                    }
                    "GET" => match self.store.get_session_request(session_hash) {
                        Ok(data) => (
                            200,
                            vec![("Content-Type".into(), "application/octet-stream".into())],
                            data,
                        ),
                        Err(e) => self.error_response(e),
                    },
                    _ => (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec()),
                },
                "response" => match method {
                    "POST" => {
                        let bytes = if let Ok(parsed) =
                            serde_json::from_slice::<RendezvousPayload>(body)
                        {
                            base64url::decode(&parsed.payload_b64).unwrap_or_else(|_| body.to_vec())
                        } else {
                            body.to_vec()
                        };

                        match self.store.submit_session_response(session_hash, bytes) {
                            Ok(()) => (
                                201,
                                vec![("Content-Type".into(), "application/json".into())],
                                b"{\"status\":\"submitted\"}".to_vec(),
                            ),
                            Err(e) => self.error_response(e),
                        }
                    }
                    "GET" => match self.store.get_session_response(session_hash) {
                        Ok(data) => (
                            200,
                            vec![("Content-Type".into(), "application/octet-stream".into())],
                            data,
                        ),
                        Err(e) => self.error_response(e),
                    },
                    _ => (405, vec![], b"{\"error\":\"method_not_allowed\"}".to_vec()),
                },
                _ => (404, vec![], b"{\"error\":\"not_found\"}".to_vec()),
            }
        }
    }

    fn error_response(&self, err: RelayError) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let status = err.status_code();
        let json = err.to_json_response();
        (
            status,
            vec![("Content-Type".into(), "application/json".into())],
            json.into_bytes(),
        )
    }
}

/// Inicia el servidor TCP de `pip-relay` en un hilo en segundo plano con apagado ordenado.
pub fn start_relay_server<C: Clock + Send + Sync + 'static>(
    host: &str,
    port: u16,
    service: Arc<RelayHttpService<C>>,
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
                Ok((stream, peer_addr)) => {
                    let svc = Arc::clone(&service);
                    let client_id = peer_addr.ip().to_string();
                    thread::spawn(move || {
                        handle_connection(stream, &client_id, &svc);
                    });
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

fn handle_connection<C: Clock + Send + Sync + 'static>(
    mut stream: TcpStream,
    client_id: &str,
    service: &RelayHttpService<C>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut buffer = [0u8; 4096];
    let bytes_read = match stream.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req_str = match std::str::from_utf8(buffer.get(..bytes_read).unwrap_or(&[])) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut lines = req_str.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    // Extraer Content-Length para el body si existe
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(val) = line.to_lowercase().strip_prefix("content-length:") {
            if let Ok(len) = val.trim().parse::<usize>() {
                content_length = len;
            }
        }
    }

    // Ubicar inicio del body tras "\r\n\r\n" o "\n\n"
    let body_start = if let Some(pos) = req_str.find("\r\n\r\n") {
        pos.saturating_add(4)
    } else if let Some(pos) = req_str.find("\n\n") {
        pos.saturating_add(2)
    } else {
        bytes_read
    };

    let mut body = req_str
        .get(body_start..)
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();
    while body.len() < content_length {
        let mut extra = [0u8; 4096];
        match stream.read(&mut extra) {
            Ok(n) if n > 0 => {
                if let Some(chunk) = extra.get(..n) {
                    body.extend_from_slice(chunk);
                }
            }
            _ => break,
        }
    }

    let (status, headers, response_bytes) = service.handle_request(client_id, method, path, &body);

    let status_line = match status {
        200 => "HTTP/1.1 200 OK",
        201 => "HTTP/1.1 201 Created",
        204 => "HTTP/1.1 204 No Content",
        400 => "HTTP/1.1 400 Bad Request",
        404 => "HTTP/1.1 404 Not Found",
        405 => "HTTP/1.1 405 Method Not Allowed",
        409 => "HTTP/1.1 409 Conflict",
        410 => "HTTP/1.1 410 Gone",
        413 => "HTTP/1.1 413 Payload Too Large",
        429 => "HTTP/1.1 429 Too Many Requests",
        503 => "HTTP/1.1 503 Service Unavailable",
        _ => "HTTP/1.1 500 Internal Server Error",
    };

    let mut response_head = format!(
        "{status_line}\r\nContent-Length: {}\r\n",
        response_bytes.len()
    );
    for (k, v) in headers {
        response_head.push_str(&format!("{k}: {v}\r\n"));
    }
    response_head.push_str("Connection: close\r\n\r\n");

    let _ = stream.write_all(response_head.as_bytes());
    let _ = stream.write_all(&response_bytes);
    let _ = stream.flush();
}
