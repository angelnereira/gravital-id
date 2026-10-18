//! Pruebas de tolerancia a fallos, reorganizaciones y multi-RPC para el adaptador EVM (F6.T10).
//!
//! Trazabilidad:
//! - **REQ-LEDG-005:** Consumo acotado a bloques finalizados y tolerancia a reorganizaciones.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC con failover y verificación de consistencia.
//! - **REQ-SYNC-003:** Reintentos con backoff exponencial ante fallos transitorios.
//! - **ADR-0004 §53:** Verificación de consistencia entre al menos dos proveedores independientes.
//! - **INV-01:** Pruebas deterministas sans-I/O mediante `MockRpcTransport`.
//! - **INV-10:** Cero pánicos, manejo riguroso de errores.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use gravital_id_ledger::{LedgerAdapter, LedgerError};
use gravital_id_ledger_evm::abi::TOPIC_KEY_RETIRED;
use gravital_id_ledger_evm::{
    hex_encode, EvmContractAddresses, EvmLedgerAdapter, EvmLedgerError, MockRpcTransport,
    MultiRpcClient, MultiRpcConfig,
};
use serde_json::json;

fn encode_uint64_word(val: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&val.to_be_bytes());
    word
}

#[test]
fn test_reorg_tolerance_rejects_unfinalized_blocks() {
    // Verifies: REQ-LEDG-005
    let transport = Arc::new(MockRpcTransport::new());
    let ep = "https://rpc.example.com";

    // Head finalizado = 300
    transport.set_response(
        ep,
        "eth_getBlockByNumber",
        json!({
            "number": "0x12c", // 300
            "hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "parentHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "timestamp": "0x65000000"
        }),
    );

    let config = MultiRpcConfig {
        endpoints: vec![ep.to_string()],
        require_quorum_consistency: false,
        ..MultiRpcConfig::new(vec![ep.to_string()])
    };

    let client = MultiRpcClient::new(config, transport).expect("valid client");
    let adapter = EvmLedgerAdapter::new_with_chain_id(
        client,
        1,
        EvmContractAddresses::new(
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ),
    );

    // Consulta de rango que excede el bloque finalizado (301 > 300)
    let err = adapter
        .fetch_events(200, 301)
        .expect_err("must reject block beyond finalized head");

    match err {
        LedgerError::Adapter(msg) => {
            assert!(msg.contains("is not finalized"));
            assert!(msg.contains("301"));
            assert!(msg.contains("300"));
        }
        other => panic!("expected Adapter error with BlockNotFinalized, got {other:?}"),
    }
}

#[test]
fn test_invalid_block_range_is_rejected() {
    // Verifies: REQ-LEDG-005
    let transport = Arc::new(MockRpcTransport::new());
    let config = MultiRpcConfig::new(vec!["https://rpc.example.com".to_string()]);
    let client = MultiRpcClient::new(config, transport).expect("valid client");
    let adapter = EvmLedgerAdapter::new_with_chain_id(
        client,
        1,
        EvmContractAddresses::new("0x11".to_string(), "0x22".to_string()),
    );

    let err = adapter
        .fetch_events(500, 400)
        .expect_err("from_block > to_block must be rejected");

    match err {
        LedgerError::Adapter(msg) => {
            assert!(msg.contains("invalid block range"));
        }
        other => panic!("expected InvalidBlockRange error, got {other:?}"),
    }
}

#[test]
fn test_multi_rpc_failover_and_sticky_primary() {
    // Verifies: REQ-LEDG-006
    let transport = Arc::new(MockRpcTransport::new());
    let ep1 = "https://rpc-1.example.com";
    let ep2 = "https://rpc-2.example.com";
    let ep3 = "https://rpc-3.example.com";

    // ep1 está caído permanentemente
    transport.set_endpoint_error(
        ep1,
        EvmLedgerError::Transport("connection refused (node down)".to_string()),
    );
    // ep2 responde normalmente
    transport.set_response(ep2, "eth_chainId", json!("0xa4b1"));
    // ep3 responde normalmente
    transport.set_response(ep3, "eth_chainId", json!("0xa4b1"));

    let config = MultiRpcConfig {
        endpoints: vec![ep1.to_string(), ep2.to_string(), ep3.to_string()],
        max_retries_per_endpoint: 1,
        ..MultiRpcConfig::new(vec![ep1.to_string(), ep2.to_string(), ep3.to_string()])
    };

    let client = MultiRpcClient::new(config, transport.clone()).expect("valid client");
    assert_eq!(client.primary_index(), 0);

    // Primera llamada: debe probar ep1 (falla), conmutar a ep2 (éxito) y actualizar primary_index a 1
    let chain_id = client.get_chain_id().expect("failover succeeds");
    assert_eq!(chain_id, 42161);
    assert_eq!(client.primary_index(), 1);

    // Segunda llamada: debe empezar directamente en ep2 (sticky primary) sin reintentar ep1
    let recorded_before = transport.call_count(ep1, "eth_chainId");
    let chain_id_2 = client.get_chain_id().expect("second call succeeds");
    assert_eq!(chain_id_2, 42161);
    let recorded_after = transport.call_count(ep1, "eth_chainId");

    // ep1 no fue reconsultado en la segunda llamada porque ep2 ya es el primario
    assert_eq!(recorded_before, recorded_after);
}

#[test]
fn test_provider_inconsistency_split_view_hash_mismatch() {
    // Verifies: REQ-LEDG-006, ADR-0004 §53
    let transport = Arc::new(MockRpcTransport::new());
    let ep1 = "https://rpc-1.example.com";
    let ep2 = "https://rpc-2.example.com";

    // ep1 reporta hash A para el bloque finalizado 100
    transport.set_response(
        ep1,
        "eth_getBlockByNumber",
        json!({
            "number": "0x64",
            "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "parentHash": "0x9999999999999999999999999999999999999999999999999999999999999999",
            "timestamp": "0x60000000"
        }),
    );

    // ep2 reporta hash B para el mismo bloque finalizado 100 (partición de red o reorg no consensuada)
    transport.set_response(
        ep2,
        "eth_getBlockByNumber",
        json!({
            "number": "0x64",
            "hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "parentHash": "0x9999999999999999999999999999999999999999999999999999999999999999",
            "timestamp": "0x60000000"
        }),
    );

    let config = MultiRpcConfig {
        endpoints: vec![ep1.to_string(), ep2.to_string()],
        require_quorum_consistency: true,
        min_consistent_endpoints: 2,
        ..MultiRpcConfig::new(vec![ep1.to_string(), ep2.to_string()])
    };

    let client = MultiRpcClient::new(config, transport).expect("valid client");
    let err = client
        .get_finalized_head()
        .expect_err("must reject inconsistent providers");

    match err {
        EvmLedgerError::ProviderInconsistency { reason } => {
            assert!(reason.contains("block hash mismatch"));
            assert!(reason.contains("0xaaaa"));
            assert!(reason.contains("0xbbbb"));
        }
        other => panic!("expected ProviderInconsistency, got {other:?}"),
    }
}

#[test]
fn test_provider_inconsistency_parent_hash_mismatch() {
    // Verifies: REQ-LEDG-006, ADR-0004 §53
    let transport = Arc::new(MockRpcTransport::new());
    let ep1 = "https://rpc-1.example.com";
    let ep2 = "https://rpc-2.example.com";

    transport.set_response(
        ep1,
        "eth_getBlockByNumber",
        json!({
            "number": "0x64",
            "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "parentHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "timestamp": "0x60000000"
        }),
    );

    // Mismo hash de bloque pero parentHash distinto (divergencia histórica)
    transport.set_response(
        ep2,
        "eth_getBlockByNumber",
        json!({
            "number": "0x64",
            "hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "parentHash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "timestamp": "0x60000000"
        }),
    );

    let config = MultiRpcConfig {
        endpoints: vec![ep1.to_string(), ep2.to_string()],
        require_quorum_consistency: true,
        min_consistent_endpoints: 2,
        ..MultiRpcConfig::new(vec![ep1.to_string(), ep2.to_string()])
    };

    let client = MultiRpcClient::new(config, transport).expect("valid client");
    let err = client
        .get_finalized_head()
        .expect_err("must reject parent hash mismatch");

    match err {
        EvmLedgerError::ProviderInconsistency { reason } => {
            assert!(reason.contains("parent hash mismatch"));
        }
        other => panic!("expected ProviderInconsistency, got {other:?}"),
    }
}

#[test]
fn test_transient_failure_exponential_backoff_and_recovery() {
    // Verifies: REQ-SYNC-003, REQ-LEDG-006
    let transport = Arc::new(MockRpcTransport::new());
    let ep = "https://rpc.example.com";

    // Simular que eth_chainId falla 2 veces con error 429 / Rate Limited y luego tiene éxito
    transport.set_transient_failure(
        ep,
        "eth_chainId",
        2,
        EvmLedgerError::Transport("429 Too Many Requests (Rate limited)".to_string()),
        json!("0xa4b1"),
    );

    let config = MultiRpcConfig {
        endpoints: vec![ep.to_string()],
        max_retries_per_endpoint: 3,
        initial_backoff_ms: 10,
        max_backoff_ms: 50,
        ..MultiRpcConfig::new(vec![ep.to_string()])
    };

    let client = MultiRpcClient::new(config, transport.clone()).expect("valid client");
    let chain_id = client
        .get_chain_id()
        .expect("should succeed on 3rd attempt after backoff");
    assert_eq!(chain_id, 42161);

    // Debe haberse invocado exactamente 3 veces (2 fallos + 1 éxito)
    assert_eq!(transport.call_count(ep, "eth_chainId"), 3);
}

#[test]
fn test_all_endpoints_failed_error() {
    // Verifies: REQ-LEDG-006
    let transport = Arc::new(MockRpcTransport::new());
    let ep1 = "https://rpc-1.example.com";
    let ep2 = "https://rpc-2.example.com";

    transport.set_endpoint_error(ep1, EvmLedgerError::Transport("ep1 timeout".to_string()));
    transport.set_endpoint_error(ep2, EvmLedgerError::Transport("ep2 refused".to_string()));

    let config = MultiRpcConfig {
        endpoints: vec![ep1.to_string(), ep2.to_string()],
        max_retries_per_endpoint: 1,
        ..MultiRpcConfig::new(vec![ep1.to_string(), ep2.to_string()])
    };

    let client = MultiRpcClient::new(config, transport).expect("valid client");
    let err = client
        .get_chain_id()
        .expect_err("must return AllEndpointsFailed");

    match err {
        EvmLedgerError::AllEndpointsFailed {
            endpoints_count,
            last_error,
        } => {
            assert_eq!(endpoints_count, 2);
            assert!(last_error.contains("ep2 refused"));
        }
        other => panic!("expected AllEndpointsFailed, got {other:?}"),
    }
}

#[test]
fn test_duplicate_events_across_queries_are_deduplicated_and_sorted() {
    // Verifies: REQ-LEDG-005
    let transport = Arc::new(MockRpcTransport::new());
    let ep = "https://rpc.example.com";

    transport.set_response(
        ep,
        "eth_getBlockByNumber",
        json!({
            "number": "0x1f4",
            "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "timestamp": "0x60000000"
        }),
    );

    let issuer_id = [0x55u8; 32];
    let kid = [0x66u8; 32];
    let data = encode_uint64_word(1700000000); // state_since

    let make_log = |tx_idx: u32, log_idx: u32| {
        json!({
            "address": "0x1111111111111111111111111111111111111111",
            "topics": [
                format!("0x{}", hex_encode(&TOPIC_KEY_RETIRED)),
                format!("0x{}", hex_encode(&issuer_id)),
                format!("0x{}", hex_encode(&kid)),
            ],
            "data": format!("0x{}", hex_encode(&data)),
            "blockNumber": "0x64",
            "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "transactionIndex": format!("0x{tx_idx:x}"),
            "logIndex": format!("0x{log_idx:x}"),
            "removed": false
        })
    };

    // Devolver logs duplicados y desordenados: (tx 1, log 0), (tx 0, log 0), (tx 1, log 0) duplicado
    let logs_resp = json!([make_log(1, 0), make_log(0, 0), make_log(1, 0)]);

    transport.set_response(ep, "eth_getLogs", logs_resp);

    let config = MultiRpcConfig {
        endpoints: vec![ep.to_string()],
        require_quorum_consistency: false,
        ..MultiRpcConfig::new(vec![ep.to_string()])
    };

    let client = MultiRpcClient::new(config, transport).expect("valid client");
    let adapter = EvmLedgerAdapter::new_with_chain_id(
        client,
        1,
        EvmContractAddresses::new(
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ),
    );

    let events = adapter
        .fetch_events(100, 100)
        .expect("events fetched and deduplicated");

    // Debe contener exactamente 2 eventos únicos ordenados por tx_index (0 luego 1)
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].coordinate.tx_index, 0);
    assert_eq!(events[1].coordinate.tx_index, 1);
}
