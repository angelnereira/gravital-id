//! Pruebas para el servidor HTTP y despachador de rutas de `pip-relay`.
//!
//! Verifies: REQ-SYNC-004, REQ-SYNC-006, REQ-CODE-001, REQ-CODE-002, REQ-CODE-003, REQ-CODE-004, REQ-REL-001

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    clippy::disallowed_types
)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gravital_id_codec::base64url;
use gravital_id_crypto::sha256;
use gravital_id_types::Clock;
use pip_relay::config::RelayConfig;
use pip_relay::health::RelayHealthCheck;
use pip_relay::limiter::RateLimiter;
use pip_relay::server::{
    start_relay_server, PostEnvelopeRequest, RelayHttpService, RendezvousPayload,
    ValidateSessionCodeRequest, ValidateSessionCodeResponse,
};
use pip_relay::store::{compute_damm_check_digit, hex_encode, InMemoryRelayStore};
use pip_service_common::health::HealthRegistry;
use pip_service_common::shutdown::ShutdownCoordinator;

#[derive(Debug, Clone)]
struct TestSyncClock {
    now: Arc<AtomicU64>,
}

impl TestSyncClock {
    fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
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

fn create_test_service() -> (
    Arc<RelayHttpService<TestSyncClock>>,
    Arc<InMemoryRelayStore<TestSyncClock>>,
    TestSyncClock,
) {
    let mut config = RelayConfig::default();
    config.max_payload_bytes = 1024;
    config.rate_limit_requests_per_minute = 120;
    config.rate_limit_burst = 20;

    let clock = TestSyncClock::new(1000);
    let store = Arc::new(InMemoryRelayStore::new(config.clone(), clock.clone()));
    let limiter = Arc::new(RateLimiter::new(
        config.rate_limit_requests_per_minute,
        config.rate_limit_burst,
        clock.clone(),
    ));

    let mut health = HealthRegistry::new("pip-relay", "0.1.0");
    health.register_check(RelayHealthCheck::new(Arc::clone(&store)));

    let service = Arc::new(RelayHttpService::new(Arc::clone(&store), limiter, health));

    (service, store, clock)
}

// =============================================================================
// HEALTH ENDPOINTS TESTS (/healthz, /readyz)
// =============================================================================

#[test]
fn test_health_endpoints() {
    let (service, _, _) = create_test_service();

    // /healthz
    let (status, headers, body) = service.handle_request("c1", "GET", "/healthz", &[]);
    assert_eq!(status, 200);
    assert!(headers
        .iter()
        .any(|(k, v)| k == "Content-Type" && v == "application/json"));
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("\"status\":\"UP\""));

    // /readyz
    let (status, _, body) = service.handle_request("c1", "GET", "/readyz", &[]);
    assert_eq!(status, 200);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("\"status\":\"UP\""));
}

// =============================================================================
// CONTENT-ADDRESSED OBJECTS ENDPOINTS (REQ-SYNC-004)
// =============================================================================

#[test]
fn test_objects_endpoints_flow() {
    let (service, _, _) = create_test_service();

    let data = b"content-addressed-binary-blob".to_vec();
    let expected_hash = hex_encode(&sha256(&data));

    // 1. POST /v1/objects
    let (status, _, body) = service.handle_request("c1", "POST", "/v1/objects", &data);
    assert_eq!(status, 201);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains(&expected_hash));

    // 2. GET /v1/objects/{sha256}
    let get_path = format!("/v1/objects/{expected_hash}");
    let (status, headers, body) = service.handle_request("c1", "GET", &get_path, &[]);
    assert_eq!(status, 200);
    assert_eq!(body, data);
    assert!(headers
        .iter()
        .any(|(k, v)| k == "Content-Type" && v == "application/octet-stream"));
    assert!(headers
        .iter()
        .any(|(k, v)| k == "ETag" && v == &format!("\"{expected_hash}\"")));

    // 3. GET /v1/objects/{unknown} -> 404
    let unknown_path = format!("/v1/objects/{}", "00".repeat(32));
    let (status, _, _) = service.handle_request("c1", "GET", &unknown_path, &[]);
    assert_eq!(status, 404);

    // 4. PUT /v1/objects/{sha256} con hash correcto -> 201
    let (status, _, _) = service.handle_request("c1", "PUT", &get_path, &data);
    assert_eq!(status, 201);

    // 5. PUT /v1/objects/{sha256} con mismatch -> 400
    let (status, _, _) = service.handle_request("c1", "PUT", &unknown_path, &data);
    assert_eq!(status, 400);

    // 6. DELETE /v1/objects -> 405 Method Not Allowed
    let (status, _, _) = service.handle_request("c1", "DELETE", "/v1/objects", &[]);
    assert_eq!(status, 405);
}

// =============================================================================
// MAILBOXES ENDPOINTS (REQ-SYNC-006)
// =============================================================================

#[test]
fn test_mailboxes_endpoints_flow() {
    let (service, _, _) = create_test_service();

    let inbox_id = "inbox-test-123";
    let post_path = format!("/v1/mailboxes/{inbox_id}/envelopes");

    let req = PostEnvelopeRequest {
        envelope_id: "env-uuid-1".into(),
        payload_b64: base64url::encode(b"ciphertext-content"),
        ttl_secs: Some(300),
    };
    let req_body = serde_json::to_vec(&req).unwrap();

    // 1. POST /v1/mailboxes/{inbox_id}/envelopes (primer intento) -> 201 Created
    let (status, _, body) = service.handle_request("c1", "POST", &post_path, &req_body);
    assert_eq!(status, 201);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("\"status\":\"created\""));

    // 2. POST idéntico (idempotencia) -> 200 OK duplicate_acknowledged
    let (status, _, body) = service.handle_request("c1", "POST", &post_path, &req_body);
    assert_eq!(status, 200);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("\"status\":\"duplicate_acknowledged\""));

    // 3. GET /v1/mailboxes/{inbox_id}/envelopes -> 200 OK con lista de sobres
    let (status, _, body) = service.handle_request("c1", "GET", &post_path, &[]);
    assert_eq!(status, 200);
    let envelopes: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0]["envelope_id"], "env-uuid-1");

    // 4. DELETE /v1/mailboxes/{inbox_id}/envelopes/{envelope_id} -> 200 OK
    let del_path = format!("/v1/mailboxes/{inbox_id}/envelopes/env-uuid-1");
    let (status, _, body) = service.handle_request("c1", "DELETE", &del_path, &[]);
    assert_eq!(status, 200);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("\"deleted\":true"));

    // 5. DELETE de nuevo -> 404
    let (status, _, _) = service.handle_request("c1", "DELETE", &del_path, &[]);
    assert_eq!(status, 404);

    // 6. POST con JSON inválido -> 400 Bad Request
    let (status, _, _) = service.handle_request("c1", "POST", &post_path, b"not json");
    assert_eq!(status, 400);
}

// =============================================================================
// EPHEMERAL RENDEZVOUS ENDPOINTS (REQ-CODE-001..004, PROTOCOL.md §7.7)
// =============================================================================

#[test]
fn test_rendezvous_endpoints_flow() {
    let (service, _, _) = create_test_service();

    // 1. Validar código de sesión con Damm vía /v1/rendezvous/code/validate
    let code_9 = "736192845";
    let check = compute_damm_check_digit(code_9).unwrap();
    let valid_code = format!("{code_9}{check}");

    let val_req = ValidateSessionCodeRequest {
        session_code: format!("{code_9}-{check}"),
    };
    let val_body = serde_json::to_vec(&val_req).unwrap();
    let (status, _, body) =
        service.handle_request("c1", "POST", "/v1/rendezvous/code/validate", &val_body);
    assert_eq!(status, 200);
    let val_resp: ValidateSessionCodeResponse = serde_json::from_slice(&body).unwrap();
    assert!(val_resp.valid);
    assert_eq!(val_resp.canonical_code, valid_code);
    let session_hash = val_resp.session_hash;

    // 2. Registrar request en /v1/rendezvous/{session_hash}/request
    let req_path = format!("/v1/rendezvous/{session_hash}/request");
    let req_payload = RendezvousPayload {
        payload_b64: base64url::encode(b"sample-request-data"),
        ttl_secs: Some(120),
    };
    let req_body = serde_json::to_vec(&req_payload).unwrap();
    let (status, _, _) = service.handle_request("c1", "POST", &req_path, &req_body);
    assert_eq!(status, 201);

    // 3. Obtener request vía GET
    let (status, _, body) = service.handle_request("c1", "GET", &req_path, &[]);
    assert_eq!(status, 200);
    assert_eq!(body, b"sample-request-data");

    // 4. Enviar response en /v1/rendezvous/{session_hash}/response
    let resp_path = format!("/v1/rendezvous/{session_hash}/response");
    let resp_payload = RendezvousPayload {
        payload_b64: base64url::encode(b"sample-response-data"),
        ttl_secs: Some(120),
    };
    let resp_body = serde_json::to_vec(&resp_payload).unwrap();
    let (status, _, _) = service.handle_request("c1", "POST", &resp_path, &resp_body);
    assert_eq!(status, 201);

    // 5. Consumir response vía GET (consumo de un solo uso) -> 200 OK
    let (status, _, body) = service.handle_request("c1", "GET", &resp_path, &[]);
    assert_eq!(status, 200);
    assert_eq!(body, b"sample-response-data");

    // 6. Segundo GET sobre la respuesta consumida -> 409 Conflict (SessionAlreadyConsumed, REQ-CODE-004)
    let (status, _, _) = service.handle_request("c1", "GET", &resp_path, &[]);
    assert_eq!(status, 409);

    // 7. Validar código inválido -> 400 Bad Request
    let bad_val_req = ValidateSessionCodeRequest {
        session_code: "1234567899".into(), // Damm check digit incorrecto
    };
    let bad_body = serde_json::to_vec(&bad_val_req).unwrap();
    let (status, _, _) =
        service.handle_request("c1", "POST", "/v1/rendezvous/code/validate", &bad_body);
    assert_eq!(status, 400);
}

// =============================================================================
// RATE LIMITING AND ERROR RESPONSES
// =============================================================================

#[test]
fn test_rate_limiting_rejection() {
    let mut config = RelayConfig::default();
    config.rate_limit_requests_per_minute = 60;
    config.rate_limit_burst = 2; // Ráfaga de 2
    let clock = TestSyncClock::new(1000);
    let store = Arc::new(InMemoryRelayStore::new(config.clone(), clock.clone()));
    let limiter = Arc::new(RateLimiter::new(
        config.rate_limit_requests_per_minute,
        config.rate_limit_burst,
        clock,
    ));
    let health = HealthRegistry::new("pip-relay", "0.1.0");
    let service = RelayHttpService::new(store, limiter, health);

    // Petición 1: permitida
    let (status, _, _) = service.handle_request("abuser", "POST", "/v1/objects", b"test1");
    assert_eq!(status, 201);

    // Petición 2: permitida
    let (status, _, _) = service.handle_request("abuser", "POST", "/v1/objects", b"test2");
    assert_eq!(status, 201);

    // Petición 3: 429 Too Many Requests
    let (status, _, body) = service.handle_request("abuser", "POST", "/v1/objects", b"test3");
    assert_eq!(status, 429);
    let body_str = String::from_utf8(body).unwrap();
    assert!(body_str.contains("\"error\":\"rate_limit_exceeded\""));
}

// =============================================================================
// TCP SERVER SOCKET INTEGRATION TEST
// =============================================================================

#[test]
fn test_tcp_server_lifecycle() {
    let (service, _, _) = create_test_service();
    let shutdown = ShutdownCoordinator::new();

    // Iniciar servidor en puerto efímero 0
    let (port, server_handle) =
        start_relay_server("127.0.0.1", 0, service, shutdown.clone()).expect("start server ok");
    assert!(port > 0);

    // Conectar por socket TCP real
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect(&addr).expect("connect ok");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write ok");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read ok");
    let resp_str = String::from_utf8_lossy(&response);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("\"status\":\"UP\""));

    // POST con Content-Length a través del socket TCP real
    let mut stream2 = TcpStream::connect(&addr).expect("connect ok");
    let req_bytes = b"POST /v1/objects HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest";
    stream2.write_all(req_bytes).expect("write ok");
    let mut response2 = Vec::new();
    stream2.read_to_end(&mut response2).expect("read ok");
    let resp_str2 = String::from_utf8_lossy(&response2);
    assert!(resp_str2.contains("HTTP/1.1 201 Created"));

    // Detener servidor
    shutdown.trigger_shutdown();
    let _ = server_handle.join();
}

#[test]
fn test_server_edge_cases_and_routes() {
    let (service, _, _) = create_test_service();

    // store()
    assert_eq!(service.store().object_count(), 0);

    // POST /v1/objects con JSON payload
    let json_obj = RendezvousPayload {
        payload_b64: base64url::encode(b"json-payload-data"),
        ttl_secs: Some(300),
    };
    let json_body = serde_json::to_vec(&json_obj).unwrap();
    let (status, _, _) = service.handle_request("c1", "POST", "/v1/objects", &json_body);
    assert_eq!(status, 201);

    // GET /v1/mailboxes/{inbox}/envelopes con query param ?since=
    let (status, _, _) = service.handle_request(
        "c1",
        "GET",
        "/v1/mailboxes/inbox-q/envelopes?since=1000",
        &[],
    );
    assert_eq!(status, 200);

    // POST /v1/mailboxes/{inbox}/envelopes con base64 inválido
    let bad_b64_json = b"{\"envelope_id\":\"e1\",\"payload_b64\":\"***not_b64***\"}";
    let (status, _, _) = service.handle_request(
        "c1",
        "POST",
        "/v1/mailboxes/inbox-q/envelopes",
        bad_b64_json,
    );
    assert_eq!(status, 400);

    // POST /v1/rendezvous/{hash}/request con payload binario directo (no json)
    let session_hash = "cc".repeat(32);
    let req_path = format!("/v1/rendezvous/{session_hash}/request");
    let (status, _, _) = service.handle_request("c1", "POST", &req_path, b"raw binary request");
    assert_eq!(status, 201);

    // 404 en rutas desconocidas
    assert_eq!(service.handle_request("c1", "GET", "/unknown", &[]).0, 404);
    assert_eq!(
        service
            .handle_request("c1", "GET", "/v1/objects/a/b", &[])
            .0,
        404
    );
    assert_eq!(
        service
            .handle_request("c1", "GET", "/v1/mailboxes/a", &[])
            .0,
        404
    );
    assert_eq!(
        service
            .handle_request("c1", "GET", "/v1/rendezvous/a", &[])
            .0,
        404
    );

    // 405 en métodos inválidos
    assert_eq!(service.handle_request("c1", "PUT", "/healthz", &[]).0, 404); // /healthz solo GET
    assert_eq!(
        service
            .handle_request("c1", "PUT", "/v1/mailboxes/a/envelopes", &[])
            .0,
        405
    );
    assert_eq!(
        service
            .handle_request("c1", "GET", "/v1/rendezvous/code/validate", &[])
            .0,
        405
    );
    assert_eq!(service.handle_request("c1", "PUT", &req_path, &[]).0, 405);
}
