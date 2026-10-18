//! Adaptador concreto para redes EVM que implementa `LedgerAdapter` (F6.T09, F6.T10).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Abstracción del ledger con `LedgerAdapter`.
//! - **REQ-LEDG-005:** Consumo acotado a bloques finalizados y tolerancia a fallos.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC con failover y verificación de consistencia.
//! - **INV-01 / INV-10:** Verificación sans-I/O en pruebas, cero pánicos, indexación segura.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use gravital_id_ledger::{
    BlockHeader, EventCoordinate, LedgerAdapter, LedgerError, LedgerResult, SequencedLedgerEvent,
    StatusCommitmentRecord,
};

use crate::abi::{
    decode_event_log, decode_get_latest_commitment_return, encode_get_latest_commitment_call,
};
use crate::client::{hex_encode, MultiRpcClient};
use crate::error::{EvmLedgerError, EvmLedgerResult};

/// Configuración de direcciones para el adaptador EVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmContractAddresses {
    /// Dirección del contrato `TrustRegistry.sol` (ej. `0x1234...`).
    pub trust_registry: String,
    /// Dirección del contrato `StatusAnchor.sol` (ej. `0x5678...`).
    pub status_anchor: String,
}

impl EvmContractAddresses {
    /// Crea una nueva configuración de direcciones.
    #[must_use]
    pub const fn new(trust_registry: String, status_anchor: String) -> Self {
        Self {
            trust_registry,
            status_anchor,
        }
    }
}

/// Adaptador EVM para Gravital ID que implementa el trait L4 `LedgerAdapter`.
#[derive(Clone)]
pub struct EvmLedgerAdapter {
    client: MultiRpcClient,
    chain_id: u64,
    contracts: EvmContractAddresses,
    block_timestamps_cache: Arc<Mutex<BTreeMap<u64, u64>>>,
}

impl EvmLedgerAdapter {
    /// Crea un nuevo adaptador EVM conectándose a través del cliente multi-RPC.
    ///
    /// # Errores
    /// Retorna [`EvmLedgerError`] si la inicialización o consulta del `chain_id` falla.
    pub fn new(client: MultiRpcClient, contracts: EvmContractAddresses) -> EvmLedgerResult<Self> {
        let chain_id = client.get_chain_id()?;
        Ok(Self {
            client,
            chain_id,
            contracts,
            block_timestamps_cache: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Crea un adaptador con `chain_id` pre-fijado (útil para pruebas y entornos offline).
    #[must_use]
    pub fn new_with_chain_id(
        client: MultiRpcClient,
        chain_id: u64,
        contracts: EvmContractAddresses,
    ) -> Self {
        Self {
            client,
            chain_id,
            contracts,
            block_timestamps_cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Retorna una referencia al cliente multi-RPC subyacente.
    #[must_use]
    pub fn client(&self) -> &MultiRpcClient {
        &self.client
    }

    /// Retorna las direcciones de contratos configuradas.
    #[must_use]
    pub fn contracts(&self) -> &EvmContractAddresses {
        &self.contracts
    }

    /// Obtiene la marca de tiempo de un bloque, utilizando caché interna.
    fn get_cached_or_fetch_timestamp(&self, block_number: u64) -> EvmLedgerResult<u64> {
        if let Ok(lock) = self.block_timestamps_cache.lock() {
            if let Some(&ts) = lock.get(&block_number) {
                return Ok(ts);
            }
        }

        let header = self.client.get_block_by_number(block_number)?;
        if let Ok(mut lock) = self.block_timestamps_cache.lock() {
            lock.insert(block_number, header.timestamp);
        }
        Ok(header.timestamp)
    }
}

impl LedgerAdapter for EvmLedgerAdapter {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn finalized_head(&self) -> LedgerResult<BlockHeader> {
        self.client.get_finalized_head().map_err(LedgerError::from)
    }

    fn fetch_events(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> LedgerResult<Vec<SequencedLedgerEvent>> {
        if from_block > to_block {
            return Err(EvmLedgerError::InvalidBlockRange {
                from_block,
                to_block,
            }
            .into());
        }

        // REQ-LEDG-005: Verificar que to_block esté finalizado
        let head = self.finalized_head()?;
        if to_block > head.block_number {
            return Err(EvmLedgerError::BlockNotFinalized {
                requested: to_block,
                finalized_head: head.block_number,
            }
            .into());
        }

        let contracts = [
            self.contracts.trust_registry.as_str(),
            self.contracts.status_anchor.as_str(),
        ];

        let raw_logs = self
            .client
            .get_logs(from_block, to_block, &contracts, &[])
            .map_err(LedgerError::from)?;

        let mut sequenced_events = Vec::new();

        for log in raw_logs {
            // Decodificar el log ABI
            if let Some(event) =
                decode_event_log(&log.topics, &log.data).map_err(LedgerError::from)?
            {
                let timestamp = self
                    .get_cached_or_fetch_timestamp(log.block_number)
                    .map_err(LedgerError::from)?;

                let coordinate = EventCoordinate::new(
                    log.block_number,
                    log.transaction_index,
                    log.log_index,
                    timestamp,
                );

                sequenced_events.push(SequencedLedgerEvent::new(coordinate, event));
            }
        }

        // Ordenar estrictamente por coordenada y deduplicar
        sequenced_events.sort_by_key(|a| a.coordinate);
        sequenced_events.dedup_by(|a, b| a.coordinate == b.coordinate);

        Ok(sequenced_events)
    }

    fn get_status_commitment(
        &self,
        issuer_id: &[u8; 32],
    ) -> LedgerResult<Option<StatusCommitmentRecord>> {
        let call_data = encode_get_latest_commitment_call(issuer_id);
        let call_data_hex = format!("0x{}", hex_encode(&call_data));

        let return_bytes = self
            .client
            .eth_call(&self.contracts.status_anchor, &call_data_hex, "finalized")
            .map_err(LedgerError::from)?;

        decode_get_latest_commitment_return(*issuer_id, &return_bytes).map_err(LedgerError::from)
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
    use crate::client::MultiRpcConfig;
    use crate::transport::MockRpcTransport;
    use serde_json::json;

    #[test]
    fn evm_adapter_checks_finalized_head_and_rejects_unfinalized_range() {
        let transport = Arc::new(MockRpcTransport::new());
        // Head finalizado = 100
        transport.set_response(
            "https://rpc-1.example.com",
            "eth_getBlockByNumber",
            json!({
                "number": "0x64", // 100
                "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": "0x60000000"
            }),
        );

        let config = MultiRpcConfig::new(vec!["https://rpc-1.example.com".to_string()]);
        let client = MultiRpcClient::new(config, transport).expect("valid client");
        let adapter = EvmLedgerAdapter::new_with_chain_id(
            client,
            42161,
            EvmContractAddresses::new(
                "0x1111111111111111111111111111111111111111".to_string(),
                "0x2222222222222222222222222222222222222222".to_string(),
            ),
        );

        assert_eq!(adapter.client().primary_index(), 0);
        assert_eq!(
            adapter.contracts().trust_registry,
            "0x1111111111111111111111111111111111111111"
        );

        // Rango [50, 105] excede bloque 100 finalizado -> debe ser rechazado (REQ-LEDG-005)
        let err = adapter
            .fetch_events(50, 105)
            .expect_err("must reject unfinalized block");
        assert!(err.to_string().contains("is not finalized"));
    }
}
