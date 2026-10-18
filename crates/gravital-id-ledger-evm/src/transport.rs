//! Abstracciones de transporte JSON-RPC para el adaptador EVM (F6.T09, F6.T10).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Abstracción del ledger con `LedgerAdapter`.
//! - **REQ-LEDG-006:** Soporte de múltiples proveedores RPC y failover.
//! - **INV-01:** Verificación determinista sans-I/O en pruebas mediante `MockRpcTransport`.
//! - **INV-10:** Cero pánicos, manejo riguroso de errores.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::error::{EvmLedgerError, EvmLedgerResult};

/// Registro de una llamada JSON-RPC efectuada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRpcCall {
    /// Endpoint al que se dirigió la llamada.
    pub endpoint: String,
    /// Método JSON-RPC invocado (ej. `eth_getBlockByNumber`).
    pub method: String,
    /// Parámetros enviados en la petición.
    pub params: serde_json::Value,
}

/// Trait para el transporte de peticiones JSON-RPC hacia nodos EVM.
pub trait RpcTransport: Send + Sync {
    /// Envía una llamada JSON-RPC a un endpoint determinado.
    ///
    /// # Errores
    /// Retorna [`EvmLedgerError`] si ocurre un fallo de transporte, error HTTP o error del nodo RPC.
    fn send_request(
        &self,
        endpoint: &str,
        method: &str,
        params: serde_json::Value,
    ) -> EvmLedgerResult<serde_json::Value>;
}

impl<T: RpcTransport + ?Sized> RpcTransport for Arc<T> {
    fn send_request(
        &self,
        endpoint: &str,
        method: &str,
        params: serde_json::Value,
    ) -> EvmLedgerResult<serde_json::Value> {
        (**self).send_request(endpoint, method, params)
    }
}

/// Adaptador funcional para closures o funciones libres.
pub struct FnRpcTransport<F>
where
    F: Fn(&str, &str, serde_json::Value) -> EvmLedgerResult<serde_json::Value> + Send + Sync,
{
    handler: F,
}

impl<F> FnRpcTransport<F>
where
    F: Fn(&str, &str, serde_json::Value) -> EvmLedgerResult<serde_json::Value> + Send + Sync,
{
    /// Crea un nuevo transporte basado en closure.
    pub const fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F> RpcTransport for FnRpcTransport<F>
where
    F: Fn(&str, &str, serde_json::Value) -> EvmLedgerResult<serde_json::Value> + Send + Sync,
{
    fn send_request(
        &self,
        endpoint: &str,
        method: &str,
        params: serde_json::Value,
    ) -> EvmLedgerResult<serde_json::Value> {
        (self.handler)(endpoint, method, params)
    }
}

#[derive(Default)]
struct MockRpcInner {
    recorded_calls: Vec<RecordedRpcCall>,
    /// Respuestas por (endpoint, method)
    endpoint_responses: BTreeMap<(String, String), serde_json::Value>,
    /// Respuestas por (endpoint, method, serialized_params) exactos
    param_responses: BTreeMap<(String, String, String), serde_json::Value>,
    /// Respuestas globales por method (si no coincide endpoint exacto)
    global_responses: BTreeMap<String, serde_json::Value>,
    /// Errores fijos por endpoint (ej. nodo completamente caído)
    endpoint_errors: BTreeMap<String, EvmLedgerError>,
    /// Errores transitorios por (endpoint, method): (fallos_restantes, error, eventual_respuesta)
    transient_failures: BTreeMap<(String, String), (usize, EvmLedgerError, serde_json::Value)>,
}

/// Transporte simulado en memoria para pruebas deterministas y tolerancia a fallos (F6.T10).
#[derive(Default, Clone)]
pub struct MockRpcTransport {
    inner: Arc<Mutex<MockRpcInner>>,
}

impl MockRpcTransport {
    /// Crea una nueva instancia de `MockRpcTransport`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockRpcInner::default())),
        }
    }

    /// Registra una respuesta exitosa específica para un endpoint y método.
    pub fn set_response(&self, endpoint: &str, method: &str, result: serde_json::Value) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.endpoint_responses
                .insert((endpoint.to_string(), method.to_string()), result);
        }
    }

    /// Registra una respuesta exitosa para un endpoint, método y parámetros exactos.
    pub fn set_response_for_params(
        &self,
        endpoint: &str,
        method: &str,
        params: serde_json::Value,
        result: serde_json::Value,
    ) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.param_responses.insert(
                (endpoint.to_string(), method.to_string(), params.to_string()),
                result,
            );
        }
    }

    /// Registra una respuesta exitosa global para un método en cualquier endpoint.
    pub fn set_global_response(&self, method: &str, result: serde_json::Value) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.global_responses.insert(method.to_string(), result);
        }
    }

    /// Configura un error persistente para un endpoint (simula un nodo caído o no disponible).
    pub fn set_endpoint_error(&self, endpoint: &str, error: EvmLedgerError) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.endpoint_errors.insert(endpoint.to_string(), error);
        }
    }

    /// Configura un fallo transitorio que fallará `fail_count` veces antes de devolver la respuesta exitosa.
    pub fn set_transient_failure(
        &self,
        endpoint: &str,
        method: &str,
        fail_count: usize,
        error: EvmLedgerError,
        eventual_result: serde_json::Value,
    ) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.transient_failures.insert(
                (endpoint.to_string(), method.to_string()),
                (fail_count, error, eventual_result),
            );
        }
    }

    /// Retorna una copia de todas las llamadas registradas.
    #[must_use]
    pub fn recorded_calls(&self) -> Vec<RecordedRpcCall> {
        self.inner
            .lock()
            .map(|l| l.recorded_calls.clone())
            .unwrap_or_default()
    }

    /// Retorna el número de veces que se invocó un método en un endpoint.
    #[must_use]
    pub fn call_count(&self, endpoint: &str, method: &str) -> usize {
        self.inner
            .lock()
            .map(|l| {
                l.recorded_calls
                    .iter()
                    .filter(|c| c.endpoint == endpoint && c.method == method)
                    .count()
            })
            .unwrap_or_default()
    }

    /// Limpia todo el historial y configuraciones.
    pub fn reset(&self) {
        if let Ok(mut lock) = self.inner.lock() {
            *lock = MockRpcInner::default();
        }
    }
}

impl RpcTransport for MockRpcTransport {
    fn send_request(
        &self,
        endpoint: &str,
        method: &str,
        params: serde_json::Value,
    ) -> EvmLedgerResult<serde_json::Value> {
        let mut lock = self
            .inner
            .lock()
            .map_err(|_| EvmLedgerError::Transport("mutex lock poisoned".to_string()))?;

        lock.recorded_calls.push(RecordedRpcCall {
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            params: params.clone(),
        });

        // 1. Revisar si el endpoint tiene fallo permanente
        if let Some(err) = lock.endpoint_errors.get(endpoint) {
            return Err(err.clone());
        }

        // 2. Revisar si hay un fallo transitorio configurado
        let key = (endpoint.to_string(), method.to_string());
        if let Some((remaining, err, eventual)) = lock.transient_failures.get_mut(&key) {
            if *remaining > 0 {
                if let Some(next) = remaining.checked_sub(1) {
                    *remaining = next;
                }
                return Err(err.clone());
            }
            return Ok(eventual.clone());
        }

        // 3. Revisar si hay respuesta específica por parámetros exactos
        let param_key = (endpoint.to_string(), method.to_string(), params.to_string());
        if let Some(resp) = lock.param_responses.get(&param_key) {
            return Ok(resp.clone());
        }

        // 4. Revisar respuesta específica para (endpoint, method)
        if let Some(resp) = lock.endpoint_responses.get(&key) {
            return Ok(resp.clone());
        }

        // 5. Revisar respuesta global para method
        if let Some(resp) = lock.global_responses.get(method) {
            return Ok(resp.clone());
        }

        // 6. Si no hay nada configurado, retornar error explicito
        Err(EvmLedgerError::RpcError {
            code: -32601,
            message: format!("Method {method} not mocked for endpoint {endpoint}"),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mock_transport_records_calls_and_returns_responses() {
        let transport = MockRpcTransport::new();
        transport.set_response("https://rpc-1.example.com", "eth_chainId", json!("0xa4b1"));

        let res = transport
            .send_request("https://rpc-1.example.com", "eth_chainId", json!([]))
            .expect("should return configured response");
        assert_eq!(res, json!("0xa4b1"));

        assert_eq!(
            transport.call_count("https://rpc-1.example.com", "eth_chainId"),
            1
        );
        let calls = transport.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].endpoint, "https://rpc-1.example.com");
        assert_eq!(calls[0].method, "eth_chainId");
    }

    #[test]
    fn mock_transport_handles_transient_failures() {
        let transport = MockRpcTransport::new();
        transport.set_transient_failure(
            "https://rpc-1.example.com",
            "eth_blockNumber",
            2,
            EvmLedgerError::Transport("connection reset".to_string()),
            json!("0x64"),
        );

        // Intento 1: falla
        assert!(transport
            .send_request("https://rpc-1.example.com", "eth_blockNumber", json!([]))
            .is_err());
        // Intento 2: falla
        assert!(transport
            .send_request("https://rpc-1.example.com", "eth_blockNumber", json!([]))
            .is_err());
        // Intento 3: exito
        let res = transport
            .send_request("https://rpc-1.example.com", "eth_blockNumber", json!([]))
            .expect("should succeed after 2 transient failures");
        assert_eq!(res, json!("0x64"));
    }

    #[test]
    fn fn_rpc_transport_dispatches_correctly() {
        let transport = FnRpcTransport::new(|ep, method, _params| {
            if ep == "https://custom.rpc" && method == "ping" {
                Ok(json!("pong"))
            } else {
                Err(EvmLedgerError::Transport("unknown".to_string()))
            }
        });

        let res = transport
            .send_request("https://custom.rpc", "ping", json!([]))
            .expect("fn transport handles call");
        assert_eq!(res, json!("pong"));
    }

    #[test]
    fn test_mock_transport_reset_and_global_response() {
        let transport = MockRpcTransport::new();
        transport.set_global_response("global_method", json!("global_ok"));

        let res = transport
            .send_request("https://any.rpc", "global_method", json!([]))
            .expect("global response works");
        assert_eq!(res, json!("global_ok"));

        transport.reset();
        assert_eq!(transport.recorded_calls().len(), 0);
        assert!(transport
            .send_request("https://any.rpc", "global_method", json!([]))
            .is_err());
    }
}
