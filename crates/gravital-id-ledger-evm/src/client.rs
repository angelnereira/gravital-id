//! Cliente JSON-RPC con soporte multi-proveedor, failover y verificación de consistencia (F6.T09, F6.T10).
//!
//! Trazabilidad:
//! - **REQ-LEDG-005:** Consumo acotado a bloques finalizados y tolerancia a fallos.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC con failover y verificación de consistencia.
//! - **REQ-SYNC-003:** Reintentos con backoff exponencial.
//! - **ADR-0004 §53:** Verificación de consistencia entre al menos dos proveedores independientes.
//! - **INV-01 / INV-10:** Sans-I/O en pruebas, cero pánicos, indexación segura.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use gravital_id_ledger::BlockHeader;
use serde_json::json;

use crate::error::{EvmLedgerError, EvmLedgerResult};
use crate::transport::RpcTransport;

/// Estructura de un log en crudo devuelto por `eth_getLogs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvmLog {
    /// Dirección del contrato emisor del evento.
    pub address: String,
    /// Topics indexados del log (topic0 = hash de firma, topic1..3 = indexed params).
    pub topics: Vec<[u8; 32]>,
    /// Datos no indexados del log (`data`).
    pub data: Vec<u8>,
    /// Altura del bloque en que se emitió.
    pub block_number: u64,
    /// Hash del bloque.
    pub block_hash: [u8; 32],
    /// Índice de la transacción dentro del bloque.
    pub transaction_index: u32,
    /// Índice del log dentro del bloque.
    pub log_index: u32,
}

/// Configuración para el cliente multi-RPC.
#[derive(Debug, Clone)]
pub struct MultiRpcConfig {
    /// Lista ordenada de URLs de endpoints RPC.
    pub endpoints: Vec<String>,
    /// Número máximo de reintentos por endpoint antes de pasar al siguiente.
    pub max_retries_per_endpoint: usize,
    /// Backoff inicial en milisegundos.
    pub initial_backoff_ms: u64,
    /// Backoff máximo en milisegundos.
    pub max_backoff_ms: u64,
    /// Si debe verificarse consistencia de bloques entre múltiples proveedores (REQ-LEDG-006).
    pub require_quorum_consistency: bool,
    /// Número mínimo de endpoints que deben concordar en bloque finalizado.
    pub min_consistent_endpoints: usize,
    /// Rango máximo de bloques por consulta de logs (`eth_getLogs`) para evitar sobrecarga del nodo.
    pub max_block_range: u64,
}

impl Default for MultiRpcConfig {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            max_retries_per_endpoint: 3,
            initial_backoff_ms: 100,
            max_backoff_ms: 5000,
            require_quorum_consistency: true,
            min_consistent_endpoints: 2,
            max_block_range: 1000,
        }
    }
}

impl MultiRpcConfig {
    /// Construye una nueva configuración con una lista de endpoints.
    #[must_use]
    pub fn new(endpoints: Vec<String>) -> Self {
        let min_consistent = if endpoints.len() >= 2 { 2 } else { 1 };
        Self {
            endpoints,
            min_consistent_endpoints: min_consistent,
            ..Default::default()
        }
    }
}

/// Cliente multi-RPC para nodos EVM con failover y verificación de consistencia.
#[derive(Clone)]
pub struct MultiRpcClient {
    config: MultiRpcConfig,
    transport: Arc<dyn RpcTransport>,
    primary_index: Arc<AtomicUsize>,
}

impl MultiRpcClient {
    /// Crea un nuevo cliente con la configuración y transporte suministrados.
    ///
    /// # Errores
    /// Retorna [`EvmLedgerError::NoRpcEndpointsConfigured`] si la lista de endpoints está vacía.
    pub fn new(config: MultiRpcConfig, transport: Arc<dyn RpcTransport>) -> EvmLedgerResult<Self> {
        if config.endpoints.is_empty() {
            return Err(EvmLedgerError::NoRpcEndpointsConfigured);
        }
        Ok(Self {
            config,
            transport,
            primary_index: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Retorna la configuración activa.
    #[must_use]
    pub fn config(&self) -> &MultiRpcConfig {
        &self.config
    }

    /// Retorna el índice del endpoint primario activo.
    #[must_use]
    pub fn primary_index(&self) -> usize {
        let idx = self.primary_index.load(Ordering::Relaxed);
        if self.config.endpoints.is_empty() {
            0
        } else {
            idx.checked_rem(self.config.endpoints.len()).unwrap_or(0)
        }
    }

    /// Ejecuta una llamada JSON-RPC con failover automático entre endpoints y reintentos (REQ-LEDG-006).
    pub fn call_with_failover(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> EvmLedgerResult<serde_json::Value> {
        let total_endpoints = self.config.endpoints.len();
        if total_endpoints == 0 {
            return Err(EvmLedgerError::NoRpcEndpointsConfigured);
        }

        let start_idx = self.primary_index();
        let mut last_error_msg = String::from("unknown error");

        // Recorrer endpoints a partir del primario actual
        for offset in 0..total_endpoints {
            let ep_idx = (start_idx.saturating_add(offset))
                .checked_rem(total_endpoints)
                .unwrap_or(0);
            let endpoint = match self.config.endpoints.get(ep_idx) {
                Some(ep) => ep,
                None => continue,
            };

            let mut backoff = self.config.initial_backoff_ms;
            let mut endpoint_last_err = String::new();

            // Intentos en este endpoint
            for attempt in 0..=self.config.max_retries_per_endpoint {
                match self
                    .transport
                    .send_request(endpoint, method, params.clone())
                {
                    Ok(val) => {
                        // Si el endpoint cambió respecto al anterior primario, actualizar primario
                        if ep_idx != start_idx {
                            self.primary_index.store(ep_idx, Ordering::Relaxed);
                        }
                        return Ok(val);
                    }
                    Err(err) => {
                        endpoint_last_err = err.to_string();
                        if attempt < self.config.max_retries_per_endpoint {
                            // Backoff exponencial sin float: saturating_mul(2)
                            backoff = backoff.saturating_mul(2).min(self.config.max_backoff_ms);
                        }
                    }
                }
            }

            last_error_msg = format!("endpoint {endpoint}: {endpoint_last_err}");
        }

        Err(EvmLedgerError::AllEndpointsFailed {
            endpoints_count: total_endpoints,
            last_error: last_error_msg,
        })
    }

    /// Obtiene el identificador de red (chain ID).
    pub fn get_chain_id(&self) -> EvmLedgerResult<u64> {
        let val = self.call_with_failover("eth_chainId", json!([]))?;
        let hex_str = val.as_str().ok_or_else(|| {
            EvmLedgerError::JsonSerialization("expected hex string for eth_chainId".to_string())
        })?;
        parse_hex_u64(hex_str)
    }

    /// Consulta y verifica la cabecera del bloque finalizado más reciente (REQ-LEDG-005, REQ-LEDG-006).
    pub fn get_finalized_head(&self) -> EvmLedgerResult<BlockHeader> {
        self.get_block_with_consistency("finalized")
    }

    /// Consulta una cabecera de bloque por su número, verificando consistencia si aplica.
    pub fn get_block_by_number(&self, block_number: u64) -> EvmLedgerResult<BlockHeader> {
        let hex_tag = format!("0x{block_number:x}");
        self.get_block_with_consistency(&hex_tag)
    }

    /// Consulta una cabecera de bloque con verificación cruzada entre proveedores (REQ-LEDG-006).
    fn get_block_with_consistency(&self, tag: &str) -> EvmLedgerResult<BlockHeader> {
        let endpoints_count = self.config.endpoints.len();

        // Si no se requiere quorum o solo hay 1 endpoint configurado
        if !self.config.require_quorum_consistency || endpoints_count < 2 {
            let res = self.call_with_failover("eth_getBlockByNumber", json!([tag, false]))?;
            return parse_block_header(&res);
        }

        // Si hay >= 2 endpoints y se requiere consistencia:
        // Consultar a min_consistent_endpoints distintos y comparar hash, number y parentHash.
        let needed = self.config.min_consistent_endpoints.min(endpoints_count);
        let mut headers: Vec<(String, BlockHeader)> = Vec::new();

        for endpoint in &self.config.endpoints {
            if headers.len() >= needed {
                break;
            }
            match self
                .transport
                .send_request(endpoint, "eth_getBlockByNumber", json!([tag, false]))
            {
                Ok(val) => {
                    let header = parse_block_header(&val)?;
                    headers.push((endpoint.clone(), header));
                }
                Err(_) => {
                    // Si un endpoint falla en la verificación de consistencia, continuar con el siguiente
                    continue;
                }
            }
        }

        if headers.is_empty() {
            return Err(EvmLedgerError::AllEndpointsFailed {
                endpoints_count,
                last_error: format!("could not fetch block {tag} from any provider"),
            });
        }

        if headers.len() < needed {
            return Err(EvmLedgerError::ProviderInconsistency {
                reason: format!(
                    "only {} of {} required endpoints responded for block {}",
                    headers.len(),
                    needed,
                    tag
                ),
            });
        }

        // Comparar consistencia entre todos los que respondieron
        let first = match headers.first() {
            Some((_, h)) => h,
            None => {
                return Err(EvmLedgerError::ProviderInconsistency {
                    reason: "empty headers list".to_string(),
                });
            }
        };

        let first_ep = headers.first().map(|(ep, _)| ep.as_str()).unwrap_or("");

        for (ep, h) in headers.iter().skip(1) {
            if h.block_number != first.block_number {
                return Err(EvmLedgerError::ProviderInconsistency {
                    reason: format!(
                        "block number mismatch between providers for tag {tag}: {} ({first_ep}) != {} ({ep})",
                        first.block_number, h.block_number
                    ),
                });
            }
            if h.block_hash != first.block_hash {
                return Err(EvmLedgerError::ProviderInconsistency {
                    reason: format!(
                        "block hash mismatch between providers for block {}: 0x{} ({first_ep}) != 0x{} ({ep})",
                        first.block_number,
                        hex_encode(&first.block_hash),
                        hex_encode(&h.block_hash)
                    ),
                });
            }
            if h.parent_hash != first.parent_hash {
                return Err(EvmLedgerError::ProviderInconsistency {
                    reason: format!(
                        "parent hash mismatch between providers for block {}: 0x{} ({first_ep}) != 0x{} ({ep})",
                        first.block_number,
                        hex_encode(&first.parent_hash),
                        hex_encode(&h.parent_hash)
                    ),
                });
            }
        }

        Ok(first.clone())
    }

    /// Realiza una llamada de solo lectura `eth_call` al ledger.
    pub fn eth_call(&self, to: &str, data: &str, block_tag: &str) -> EvmLedgerResult<Vec<u8>> {
        let call_obj = json!({
            "to": to,
            "data": data,
        });
        let res = self.call_with_failover("eth_call", json!([call_obj, block_tag]))?;
        let hex_str = res.as_str().ok_or_else(|| {
            EvmLedgerError::JsonSerialization(
                "expected hex string return from eth_call".to_string(),
            )
        })?;
        parse_hex_bytes(hex_str)
    }

    /// Obtiene logs de eventos en el rango `[from_block, to_block]`, particionando por chunks (REQ-LEDG-005).
    pub fn get_logs(
        &self,
        from_block: u64,
        to_block: u64,
        contract_addresses: &[&str],
        topics: &[Option<&[u8; 32]>],
    ) -> EvmLedgerResult<Vec<RawEvmLog>> {
        if from_block > to_block {
            return Err(EvmLedgerError::InvalidBlockRange {
                from_block,
                to_block,
            });
        }

        let chunk_size = self.config.max_block_range.max(1);
        let mut all_logs = Vec::new();
        let mut current_from = from_block;

        while current_from <= to_block {
            let current_to =
                (current_from.saturating_add(chunk_size.saturating_sub(1))).min(to_block);

            let from_hex = format!("0x{current_from:x}");
            let to_hex = format!("0x{current_to:x}");

            let mut filter_obj = serde_json::Map::new();
            filter_obj.insert("fromBlock".to_string(), json!(from_hex));
            filter_obj.insert("toBlock".to_string(), json!(to_hex));

            if !contract_addresses.is_empty() {
                filter_obj.insert("address".to_string(), json!(contract_addresses));
            }

            if !topics.is_empty() {
                let topics_val: Vec<serde_json::Value> = topics
                    .iter()
                    .map(|top_opt| match top_opt {
                        Some(top) => json!(format!("0x{}", hex_encode(*top))),
                        None => serde_json::Value::Null,
                    })
                    .collect();
                filter_obj.insert("topics".to_string(), json!(topics_val));
            }

            let res = self.call_with_failover("eth_getLogs", json!([filter_obj]))?;
            let logs_array = res.as_array().ok_or_else(|| {
                EvmLedgerError::JsonSerialization(
                    "expected JSON array from eth_getLogs".to_string(),
                )
            })?;

            for item in logs_array {
                let parsed = parse_raw_log(item)?;
                all_logs.push(parsed);
            }

            if current_to == u64::MAX || current_to >= to_block {
                break;
            }
            match current_to.checked_add(1) {
                Some(next) => current_from = next,
                None => break,
            }
        }

        // Deduplicación y ordenamiento canónico por (block_number, transaction_index, log_index)
        all_logs.sort_by(|a, b| {
            a.block_number
                .cmp(&b.block_number)
                .then(a.transaction_index.cmp(&b.transaction_index))
                .then(a.log_index.cmp(&b.log_index))
        });
        all_logs.dedup_by(|a, b| {
            a.block_number == b.block_number
                && a.transaction_index == b.transaction_index
                && a.log_index == b.log_index
        });

        Ok(all_logs)
    }
}

// =============================================================================
// HELPERS DE PARSEO HEXADECIMAL Y DE LOGS
// =============================================================================

/// Codifica un slice de bytes a representación hexadecimal en minúsculas.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().saturating_mul(2));
    for byte in data {
        use core::fmt::Write;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Parsea un número hexadecimal prefijado o no por `0x`.
pub fn parse_hex_u64(s: &str) -> EvmLedgerResult<u64> {
    let clean = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if clean.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(clean, 16)
        .map_err(|e| EvmLedgerError::JsonSerialization(format!("invalid hex integer '{s}': {e}")))
}

/// Parsea un entero hexadecimal de 32 bits (`u32`).
pub fn parse_hex_u32(s: &str) -> EvmLedgerResult<u32> {
    let clean = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if clean.is_empty() {
        return Ok(0);
    }
    u32::from_str_radix(clean, 16)
        .map_err(|e| EvmLedgerError::JsonSerialization(format!("invalid hex integer '{s}': {e}")))
}

/// Parsea un hash o valor de exactamente 32 bytes en hexadecimal.
pub fn parse_hex_32bytes(s: &str) -> EvmLedgerResult<[u8; 32]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 32 {
        return Err(EvmLedgerError::JsonSerialization(format!(
            "expected 32 bytes for hash, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parsea una cadena hexadecimal arbitraria prefijada o no por `0x`.
pub fn parse_hex_bytes(s: &str) -> EvmLedgerResult<Vec<u8>> {
    let clean = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if clean.is_empty() {
        return Ok(Vec::new());
    }

    let len = clean.len();
    if !len.is_multiple_of(2) {
        return Err(EvmLedgerError::JsonSerialization(format!(
            "invalid odd-length hex string '{s}'"
        )));
    }

    let mut out = Vec::with_capacity(len / 2);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i < len {
        let hi_char = match bytes.get(i) {
            Some(&b) => b as char,
            None => break,
        };
        let lo_char = match bytes.get(i.saturating_add(1)) {
            Some(&b) => b as char,
            None => break,
        };

        let hi = hi_char.to_digit(16).ok_or_else(|| {
            EvmLedgerError::JsonSerialization(format!("invalid hex digit '{hi_char}' in '{s}'"))
        })?;
        let lo = lo_char.to_digit(16).ok_or_else(|| {
            EvmLedgerError::JsonSerialization(format!("invalid hex digit '{lo_char}' in '{s}'"))
        })?;

        let byte = (hi << 4) | lo;
        #[allow(clippy::cast_possible_truncation)]
        out.push(byte as u8);
        i = i.saturating_add(2);
    }

    Ok(out)
}

fn parse_block_header(val: &serde_json::Value) -> EvmLedgerResult<BlockHeader> {
    if val.is_null() {
        return Err(EvmLedgerError::JsonSerialization(
            "block returned null (not found or reorg)".to_string(),
        ));
    }

    let obj = val.as_object().ok_or_else(|| {
        EvmLedgerError::JsonSerialization("expected JSON object for block".to_string())
    })?;

    let number_str = obj.get("number").and_then(|v| v.as_str()).ok_or_else(|| {
        EvmLedgerError::JsonSerialization("missing 'number' in block".to_string())
    })?;
    let block_number = parse_hex_u64(number_str)?;

    let hash_str = obj
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| EvmLedgerError::JsonSerialization("missing 'hash' in block".to_string()))?;
    let block_hash = parse_hex_32bytes(hash_str)?;

    let parent_str = obj
        .get("parentHash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvmLedgerError::JsonSerialization("missing 'parentHash' in block".to_string())
        })?;
    let parent_hash = parse_hex_32bytes(parent_str)?;

    let timestamp_str = obj
        .get("timestamp")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            EvmLedgerError::JsonSerialization("missing 'timestamp' in block".to_string())
        })?;
    let timestamp = parse_hex_u64(timestamp_str)?;

    Ok(BlockHeader::new(
        block_number,
        block_hash,
        parent_hash,
        timestamp,
    ))
}

fn parse_raw_log(val: &serde_json::Value) -> EvmLedgerResult<RawEvmLog> {
    let obj = val.as_object().ok_or_else(|| {
        EvmLedgerError::JsonSerialization("expected JSON object for log".to_string())
    })?;

    let address = obj
        .get("address")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let topics_array = obj
        .get("topics")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            EvmLedgerError::JsonSerialization("missing 'topics' array in log".to_string())
        })?;

    let mut topics = Vec::with_capacity(topics_array.len());
    for top_val in topics_array {
        let top_str = top_val.as_str().ok_or_else(|| {
            EvmLedgerError::JsonSerialization("expected string for topic".to_string())
        })?;
        let top_bytes = parse_hex_32bytes(top_str)?;
        topics.push(top_bytes);
    }

    let data_str = obj.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    let data = parse_hex_bytes(data_str)?;

    let block_number = match obj.get("blockNumber").and_then(|v| v.as_str()) {
        Some(s) => parse_hex_u64(s)?,
        None => 0,
    };

    let block_hash = match obj.get("blockHash").and_then(|v| v.as_str()) {
        Some(s) => parse_hex_32bytes(s)?,
        None => [0u8; 32],
    };

    let transaction_index = match obj.get("transactionIndex").and_then(|v| v.as_str()) {
        Some(s) => parse_hex_u32(s)?,
        None => 0,
    };

    let log_index = match obj.get("logIndex").and_then(|v| v.as_str()) {
        Some(s) => parse_hex_u32(s)?,
        None => 0,
    };

    Ok(RawEvmLog {
        address,
        topics,
        data,
        block_number,
        block_hash,
        transaction_index,
        log_index,
    })
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
    use crate::transport::MockRpcTransport;

    #[test]
    fn multi_rpc_requires_configured_endpoints() {
        let transport = Arc::new(MockRpcTransport::new());
        let res = MultiRpcClient::new(MultiRpcConfig::default(), transport);
        assert_eq!(res.err(), Some(EvmLedgerError::NoRpcEndpointsConfigured));
    }

    #[test]
    fn multi_rpc_failover_when_primary_fails() {
        let transport = Arc::new(MockRpcTransport::new());
        transport.set_endpoint_error(
            "https://rpc-1.example.com",
            EvmLedgerError::Transport("connection refused".to_string()),
        );
        transport.set_response("https://rpc-2.example.com", "eth_chainId", json!("0xa4b1"));

        let config = MultiRpcConfig::new(vec![
            "https://rpc-1.example.com".to_string(),
            "https://rpc-2.example.com".to_string(),
        ]);
        let client = MultiRpcClient::new(config, transport.clone()).expect("valid client");

        let chain_id = client.get_chain_id().expect("should failover to rpc-2");
        assert_eq!(chain_id, 42161);
        assert_eq!(client.primary_index(), 1);
    }

    #[test]
    fn consistency_check_detects_hash_mismatch() {
        let transport = Arc::new(MockRpcTransport::new());
        // rpc-1 devuelve hash A
        transport.set_response(
            "https://rpc-1.example.com",
            "eth_getBlockByNumber",
            json!({
                "number": "0x64",
                "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "0x60000000"
            }),
        );
        // rpc-2 devuelve hash B para el mismo bloque (split-view o reorganización no consensuada)
        transport.set_response(
            "https://rpc-2.example.com",
            "eth_getBlockByNumber",
            json!({
                "number": "0x64",
                "hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "0x60000000"
            }),
        );

        let config = MultiRpcConfig::new(vec![
            "https://rpc-1.example.com".to_string(),
            "https://rpc-2.example.com".to_string(),
        ]);
        let client = MultiRpcClient::new(config, transport).expect("valid client");

        let err = client
            .get_finalized_head()
            .expect_err("must reject inconsistency");
        match err {
            EvmLedgerError::ProviderInconsistency { reason } => {
                assert!(reason.contains("block hash mismatch"));
            }
            other => panic!("expected ProviderInconsistency, got {other:?}"),
        }
    }

    #[test]
    fn test_hex_parsers_positive_and_negative() {
        assert_eq!(parse_hex_u64("").unwrap(), 0);
        assert_eq!(parse_hex_u64("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u64("0X10").unwrap(), 16);
        assert_eq!(parse_hex_u64("ff").unwrap(), 255);
        assert!(parse_hex_u64("invalid").is_err());

        assert_eq!(parse_hex_u32("").unwrap(), 0);
        assert_eq!(parse_hex_u32("0x2a").unwrap(), 42);
        assert_eq!(parse_hex_u32("0Xff").unwrap(), 255);
        assert!(parse_hex_u32("invalid").is_err());

        assert_eq!(parse_hex_bytes("").unwrap(), Vec::<u8>::new());
        assert_eq!(parse_hex_bytes("0x").unwrap(), Vec::<u8>::new());
        assert_eq!(parse_hex_bytes("0xaabb").unwrap(), vec![0xaa, 0xbb]);
        assert_eq!(parse_hex_bytes("0X0102").unwrap(), vec![0x01, 0x02]);
        assert!(parse_hex_bytes("0x1").is_err()); // odd length
        assert!(parse_hex_bytes("0xgg").is_err()); // invalid hex digit

        assert_eq!(
            parse_hex_32bytes(&format!("0x{}", "11".repeat(32))).unwrap(),
            [0x11; 32]
        );
        assert!(parse_hex_32bytes("0x11").is_err()); // not 32 bytes
    }

    #[test]
    fn test_block_and_log_parsing_errors() {
        assert!(parse_block_header(&serde_json::Value::Null).is_err());
        assert!(parse_block_header(&json!("not an object")).is_err());
        assert!(parse_block_header(&json!({})).is_err()); // missing number
        assert!(parse_block_header(&json!({"number": "0x1"})).is_err()); // missing hash
        assert!(parse_block_header(&json!({"number": "0x1", "hash": "0x11"})).is_err()); // missing parentHash

        assert!(parse_raw_log(&serde_json::Value::Null).is_err());
        assert!(parse_raw_log(&json!({})).is_err()); // missing topics
        assert!(parse_raw_log(&json!({"topics": [123]})).is_err()); // topic not string
    }

    #[test]
    fn test_client_config_getter() {
        let transport = Arc::new(MockRpcTransport::new());
        let config = MultiRpcConfig::new(vec!["https://rpc.example.com".to_string()]);
        let client = MultiRpcClient::new(config, transport).unwrap();
        assert_eq!(client.config().endpoints.len(), 1);
    }

    #[test]
    fn test_consistency_check_block_number_mismatch_and_insufficient() {
        let transport = Arc::new(MockRpcTransport::new());
        let ep1 = "https://rpc-1.example.com";
        let ep2 = "https://rpc-2.example.com";

        // ep1 da bloque 100
        transport.set_response(
            ep1,
            "eth_getBlockByNumber",
            json!({
                "number": "0x64",
                "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "0x60000000"
            }),
        );
        // ep2 da bloque 101
        transport.set_response(
            ep2,
            "eth_getBlockByNumber",
            json!({
                "number": "0x65",
                "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "0x60000000"
            }),
        );

        let config = MultiRpcConfig::new(vec![ep1.to_string(), ep2.to_string()]);
        let client = MultiRpcClient::new(config, transport.clone()).unwrap();
        let err = client.get_finalized_head().unwrap_err();
        assert!(err.to_string().contains("block number mismatch"));

        // Insufficient responses: ep2 da error
        transport.set_endpoint_error(ep2, EvmLedgerError::Transport("failed".into()));
        let err_insuff = client.get_finalized_head().unwrap_err();
        assert!(err_insuff.to_string().contains("only 1 of 2 required"));
    }

    #[test]
    fn test_get_logs_with_topics_filter() {
        let transport = Arc::new(MockRpcTransport::new());
        let ep = "https://rpc.example.com";
        transport.set_response(ep, "eth_getLogs", json!([]));

        let config = MultiRpcConfig::new(vec![ep.to_string()]);
        let client = MultiRpcClient::new(config, transport.clone()).unwrap();

        let topic1 = [0x11u8; 32];
        let logs = client
            .get_logs(100, 100, &["0x1234"], &[Some(&topic1), None])
            .unwrap();
        assert_eq!(logs.len(), 0);

        // from_block > to_block
        assert!(client.get_logs(200, 100, &[], &[]).is_err());

        // eth_getLogs returning non-array
        transport.set_response(ep, "eth_getLogs", json!({"error": "not array"}));
        assert!(client.get_logs(100, 100, &[], &[]).is_err());

        // eth_chainId returning non-string
        transport.set_response(ep, "eth_chainId", json!(12345));
        assert!(client.get_chain_id().is_err());

        // eth_call returning non-string
        transport.set_response(ep, "eth_call", json!(false));
        assert!(client.eth_call("0x1234", "0x5678", "finalized").is_err());
    }

    #[test]
    fn test_parse_block_header_missing_timestamp() {
        assert!(parse_block_header(&json!({
            "number": "0x1",
            "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
        }))
        .is_err());
    }
}
