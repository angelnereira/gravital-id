//! # `gravital-id-transport-http`
//!
//! Adaptador de transporte de red HTTP para sincronización de Gravital ID (F7.T07).
//!
//! Implementa el trait [`Transport`] de `gravital-id-sync` sobre HTTP 1.1 REST.
//!
//! - **Capa arquitectónica:** L5 (Adaptadores de red y sistema)
//! - **Garantía no_std:** No (usa `std::net::TcpStream` para I/O de red)
//! - **Invariantes:** INV-01 (I/O restringido a adaptadores L5), INV-02 (sin PII en logs).

#![forbid(unsafe_code)]
// Adaptador de Capa L5: la regla INV-01 autoriza explícitamente operaciones de I/O de red en adaptadores L5.
#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use gravital_id_codec::base64url;
use gravital_id_sync::{SyncEnvelope, SyncError, Transport};
use gravital_id_types::UnixTime;
use serde::{Deserialize, Serialize};

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// DTO de sobre para publicación en buzón (`pip-relay`).
#[derive(Debug, Serialize, Deserialize)]
struct PostEnvelopeDto {
    envelope_id: String,
    payload_b64: String,
    ttl_secs: Option<u64>,
}

/// DTO de sobre recibido de un buzón (`pip-relay`).
#[derive(Debug, Serialize, Deserialize)]
struct EnvelopeDto {
    envelope_id: String,
    payload_b64: String,
    created_at: u64,
    expires_at: u64,
}

/// Adaptador de transporte HTTP para comunicación con relays.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    timeout: Duration,
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}

impl HttpTransport {
    /// Crea un nuevo transporte con el timeout especificado.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Parsea una URL básica `http://host:port` o `host:port`.
    fn parse_host_port<'a>(&self, url: &'a str) -> Result<(&'a str, u16), SyncError> {
        let stripped = url
            .strip_prefix("http://")
            .unwrap_or_else(|| url.strip_prefix("https://").unwrap_or(url));

        let host_port = stripped.split('/').next().unwrap_or(stripped);

        if let Some((host, port_str)) = host_port.split_once(':') {
            let port = port_str
                .parse::<u16>()
                .map_err(|e| SyncError::TransportError {
                    relay_url: url.to_string(),
                    detail: format!("invalid port in url '{url}': {e}"),
                })?;
            Ok((host, port))
        } else {
            Ok((host_port, 80))
        }
    }

    /// Ejecuta una petición HTTP/1.1 sincrónica básica.
    fn execute_request(
        &self,
        relay_url: &str,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Result<(u16, Vec<u8>), SyncError> {
        let (host, port) = self.parse_host_port(relay_url)?;
        let addr_str = format!("{host}:{port}");

        let socket_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to resolve address '{addr_str}': {e}"),
            })?
            .next()
            .ok_or_else(|| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("no addresses found for '{addr_str}'"),
            })?;

        let mut stream = TcpStream::connect_timeout(&socket_addr, self.timeout).map_err(|e| {
            SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to connect to '{addr_str}': {e}"),
            }
        })?;

        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to set read timeout: {e}"),
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to set write timeout: {e}"),
            })?;

        let body_bytes = body.unwrap_or(&[]);
        let ct_header = content_type
            .map(|ct| format!("Content-Type: {ct}\r\n"))
            .unwrap_or_default();

        let request_headers = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: close\r\n\
             Content-Length: {}\r\n\
             {ct_header}\r\n",
            body_bytes.len()
        );

        stream
            .write_all(request_headers.as_bytes())
            .map_err(|e| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to write request headers: {e}"),
            })?;

        if !body_bytes.is_empty() {
            stream
                .write_all(body_bytes)
                .map_err(|e| SyncError::TransportError {
                    relay_url: relay_url.to_string(),
                    detail: format!("failed to write request body: {e}"),
                })?;
        }

        let mut response_bytes = Vec::new();
        stream
            .read_to_end(&mut response_bytes)
            .map_err(|e| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to read response: {e}"),
            })?;

        // Parsear cabecera y cuerpo
        let header_end = response_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: "malformed HTTP response: missing header separator".to_string(),
            })?;

        let headers_bytes =
            response_bytes
                .get(..header_end)
                .ok_or_else(|| SyncError::TransportError {
                    relay_url: relay_url.to_string(),
                    detail: "invalid response slice for headers".to_string(),
                })?;
        let headers_str = String::from_utf8_lossy(headers_bytes);
        let status_line = headers_str
            .lines()
            .next()
            .ok_or_else(|| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: "empty status line".to_string(),
            })?;

        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("failed to parse status code from '{status_line}'"),
            })?;

        let body_start = header_end.saturating_add(4);
        let body_part = response_bytes
            .get(body_start..)
            .map(|b| b.to_vec())
            .unwrap_or_default();
        Ok((status_code, body_part))
    }
}

impl Transport for HttpTransport {
    fn put_object(&self, relay_url: &str, data: &[u8]) -> Result<String, SyncError> {
        let (status, body) = self.execute_request(
            relay_url,
            "POST",
            "/v1/objects",
            Some(data),
            Some("application/octet-stream"),
        )?;

        if status != 201 && status != 200 {
            return Err(SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("unexpected status code {status} for put_object"),
            });
        }

        let json_val: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| SyncError::SerializationError(e.to_string()))?;

        json_val
            .get("sha256")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                SyncError::SerializationError("missing 'sha256' field in response".into())
            })
    }

    fn get_object(&self, relay_url: &str, sha256_hex: &str) -> Result<Vec<u8>, SyncError> {
        let path = format!("/v1/objects/{sha256_hex}");
        let (status, body) = self.execute_request(relay_url, "GET", &path, None, None)?;

        if status != 200 {
            return Err(SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("status code {status} for get_object {sha256_hex}"),
            });
        }

        Ok(body)
    }

    fn post_envelope(
        &self,
        relay_url: &str,
        inbox_id: &str,
        envelope_id: &str,
        payload: &[u8],
        ttl_secs: Option<u64>,
    ) -> Result<(), SyncError> {
        let path = format!("/v1/mailboxes/{inbox_id}/envelopes");
        let dto = PostEnvelopeDto {
            envelope_id: envelope_id.to_string(),
            payload_b64: base64url::encode(payload),
            ttl_secs,
        };
        let body =
            serde_json::to_vec(&dto).map_err(|e| SyncError::SerializationError(e.to_string()))?;

        let (status, _) = self.execute_request(
            relay_url,
            "POST",
            &path,
            Some(&body),
            Some("application/json"),
        )?;

        if status != 201 && status != 200 {
            return Err(SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("status code {status} for post_envelope {envelope_id}"),
            });
        }

        Ok(())
    }

    fn fetch_envelopes(
        &self,
        relay_url: &str,
        inbox_id: &str,
        since: Option<UnixTime>,
    ) -> Result<Vec<SyncEnvelope>, SyncError> {
        let path = match since {
            Some(s) => format!(
                "/v1/mailboxes/{inbox_id}/envelopes?since={}",
                s.as_seconds()
            ),
            None => format!("/v1/mailboxes/{inbox_id}/envelopes"),
        };

        let (status, body) = self.execute_request(relay_url, "GET", &path, None, None)?;

        if status != 200 {
            return Err(SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("status code {status} for fetch_envelopes in {inbox_id}"),
            });
        }

        let dtos: Vec<EnvelopeDto> = serde_json::from_slice(&body)
            .map_err(|e| SyncError::SerializationError(e.to_string()))?;

        let mut envelopes = Vec::with_capacity(dtos.len());
        for dto in dtos {
            let payload = base64url::decode(&dto.payload_b64).map_err(|e| {
                SyncError::SerializationError(format!("invalid base64url payload: {e}"))
            })?;

            envelopes.push(SyncEnvelope {
                envelope_id: dto.envelope_id,
                payload,
                created_at: UnixTime::from_seconds(dto.created_at),
                expires_at: UnixTime::from_seconds(dto.expires_at),
            });
        }

        Ok(envelopes)
    }

    fn ack_envelope(
        &self,
        relay_url: &str,
        inbox_id: &str,
        envelope_id: &str,
    ) -> Result<(), SyncError> {
        let path = format!("/v1/mailboxes/{inbox_id}/envelopes/{envelope_id}");
        let (status, _) = self.execute_request(relay_url, "DELETE", &path, None, None)?;

        if status != 200 && status != 204 && status != 404 {
            return Err(SyncError::TransportError {
                relay_url: relay_url.to_string(),
                detail: format!("status code {status} for ack_envelope {envelope_id}"),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // Verifies: REQ-SYNC-007
    #[test]
    fn parse_host_port_handles_various_url_formats() {
        let transport = HttpTransport::default();

        let (host, port) = transport
            .parse_host_port("http://127.0.0.1:8080/v1/objects")
            .unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);

        let (host, port) = transport
            .parse_host_port("https://relay.gravital.id:8443")
            .unwrap();
        assert_eq!(host, "relay.gravital.id");
        assert_eq!(port, 8443);

        let (host, port) = transport.parse_host_port("http://localhost").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 80);

        let err = transport.parse_host_port("http://localhost:invalid-port");
        assert!(err.is_err());
    }

    // Verifies: REQ-SYNC-001
    #[test]
    fn envelope_dto_serialization_roundtrip() {
        let dto = PostEnvelopeDto {
            envelope_id: "env-123".to_string(),
            payload_b64: "aGVsbG8".to_string(),
            ttl_secs: Some(3600),
        };
        let json_str = serde_json::to_string(&dto).unwrap();
        let parsed: PostEnvelopeDto = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.envelope_id, "env-123");
        assert_eq!(parsed.payload_b64, "aGVsbG8");
        assert_eq!(parsed.ttl_secs, Some(3600));
    }

    // Verifies: REQ-SYNC-007, INV-05
    #[test]
    fn execute_request_fails_closed_on_unreachable_endpoint() {
        let transport = HttpTransport::new(Duration::from_millis(50));
        let res = transport.get_object(
            "http://127.0.0.1:1",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(res.is_err());
        match res.unwrap_err() {
            SyncError::TransportError { relay_url, .. } => {
                assert_eq!(relay_url, "http://127.0.0.1:1");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
