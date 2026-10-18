//! Pruebas de integración del adaptador EVM de Gravital ID (F6.T09, REQ-LEDG-002, REQ-LEDG-005, REQ-LEDG-006).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Abstracción del ledger con `LedgerAdapter`.
//! - **REQ-LEDG-005:** Lectura por rangos acotada a bloques finalizados.
//! - **REQ-LEDG-006:** Múltiples proveedores RPC y tolerancia a fallos.
//! - **REQ-TRUST-008:** Reconstrucción determinista a partir de logs del ledger.
//! - **INV-01:** Verificación determinista sans-I/O en pruebas mediante `MockRpcTransport`.
//! - **INV-02 / REQ-LEDG-001:** Cero datos personales en eventos y parámetros.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::Arc;

use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_ledger::{LedgerAdapter, LedgerEvent, LedgerState};
use gravital_id_ledger_evm::abi::{
    TOPIC_BUNDLE_SIGNER_UPDATED, TOPIC_ISSUER_REGISTERED, TOPIC_KEY_ADDED,
    TOPIC_STATUS_MANIFEST_ANCHORED, TOPIC_TRUST_ROOT_UPDATED,
};
use gravital_id_ledger_evm::{
    hex_encode, EvmContractAddresses, EvmLedgerAdapter, MockRpcTransport, MultiRpcClient,
    MultiRpcConfig,
};
use gravital_id_testkit::SeededRng;
use serde_json::json;

// =============================================================================
// HELPERS DE CODIFICACIÓN ABI Y CLAVES PARA LOGS DE PRUEBA
// =============================================================================

fn sample_p256_key(seed: u64) -> (Vec<u8>, [u8; 32]) {
    let rng = SeededRng::new(seed);
    let sk = generate_p256_secret_key(&rng).expect("valid secret key");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");

    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(jwk.x());
    uncompressed.extend_from_slice(jwk.y());

    let mut kid = [0u8; 32];
    kid.copy_from_slice(jwk.thumbprint_sha256().as_slice());

    (uncompressed, kid)
}

fn pad_to_word(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let rem = out.len() % 32;
    if rem != 0 {
        out.extend(vec![0u8; 32 - rem]);
    }
    out
}

fn encode_uint64_word(val: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&val.to_be_bytes());
    word
}

fn encode_address_word(addr: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(&addr);
    word
}

fn encode_bool_word(val: bool) -> [u8; 32] {
    let mut word = [0u8; 32];
    if val {
        word[31] = 1;
    }
    word
}

fn encode_dynamic_bytes(data: &[u8], offset: usize) -> (Vec<u8>, Vec<u8>) {
    let offset_word = encode_uint64_word(offset as u64);
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_uint64_word(data.len() as u64));
    payload.extend_from_slice(&pad_to_word(data));
    (offset_word.to_vec(), payload)
}

fn make_log_json(
    address: &str,
    topics: Vec<[u8; 32]>,
    data: &[u8],
    block_number: u64,
    tx_index: u32,
    log_index: u32,
) -> serde_json::Value {
    let topics_json: Vec<serde_json::Value> = topics
        .into_iter()
        .map(|t| json!(format!("0x{}", hex_encode(&t))))
        .collect();

    json!({
        "address": address,
        "topics": topics_json,
        "data": format!("0x{}", hex_encode(data)),
        "blockNumber": format!("0x{block_number:x}"),
        "blockHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "transactionIndex": format!("0x{tx_index:x}"),
        "logIndex": format!("0x{log_index:x}"),
        "removed": false
    })
}

// =============================================================================
// PRUEBAS DE INTEGRACIÓN
// =============================================================================

#[test]
fn test_evm_adapter_lifecycle_and_pure_state_reconstruction() {
    // Verifies: REQ-LEDG-002, REQ-LEDG-005, REQ-LEDG-006, REQ-TRUST-008
    let transport = Arc::new(MockRpcTransport::new());
    let ep1 = "https://rpc-1.example.com";
    let ep2 = "https://rpc-2.example.com";

    // 1. eth_chainId
    transport.set_response(ep1, "eth_chainId", json!("0xa4b1")); // 42161 (Arbitrum One)

    // 2. eth_getBlockByNumber para finalized head (bloque 200)
    let finalized_block_json = json!({
        "number": "0xc8", // 200
        "hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "parentHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "timestamp": "0x66000000"
    });
    transport.set_response_for_params(
        ep1,
        "eth_getBlockByNumber",
        json!(["finalized", false]),
        finalized_block_json.clone(),
    );
    transport.set_response_for_params(
        ep2,
        "eth_getBlockByNumber",
        json!(["finalized", false]),
        finalized_block_json,
    );

    // Configurar timestamps de bloques específicos consultados (bloque 100)
    let block_100_json = json!({
        "number": "0x64", // 100
        "hash": "0x1001001001001001001001001001001001001001001001001001001001001001",
        "parentHash": "0x0990990990990990990990990990990990990990990990990990990990990990",
        "timestamp": "0x65000010"
    });
    transport.set_response_for_params(
        ep1,
        "eth_getBlockByNumber",
        json!(["0x64", false]),
        block_100_json.clone(),
    );
    transport.set_response_for_params(
        ep2,
        "eth_getBlockByNumber",
        json!(["0x64", false]),
        block_100_json,
    );

    let config = MultiRpcConfig {
        endpoints: vec![ep1.to_string(), ep2.to_string()],
        max_block_range: 50,
        ..MultiRpcConfig::new(vec![ep1.to_string(), ep2.to_string()])
    };

    let client = MultiRpcClient::new(config, transport.clone()).expect("valid client");
    let contracts = EvmContractAddresses::new(
        "0x1111111111111111111111111111111111111111".to_string(),
        "0x2222222222222222222222222222222222222222".to_string(),
    );

    let adapter = EvmLedgerAdapter::new(client, contracts.clone()).expect("adapter initialized");
    assert_eq!(adapter.chain_id(), 42161);

    let head = adapter.finalized_head().expect("head fetched");
    assert_eq!(head.block_number, 200);

    // Claves P-256 criptográficamente válidas
    let (signer_pk, signer_kid) = sample_p256_key(1001);
    let (issuer_pk, issuer_kid) = sample_p256_key(1002);

    // Preparar eventos en bloque 100:
    // Evento A: TrustRootUpdated
    let root_hash = [0x55u8; 32];
    let mut trust_root_data = Vec::new();
    trust_root_data.extend_from_slice(&encode_uint64_word(1700000000)); // updated_at
    let log_trust_root = make_log_json(
        &contracts.trust_registry,
        vec![
            TOPIC_TRUST_ROOT_UPDATED,
            root_hash,
            encode_uint64_word(1), // root_version = 1
        ],
        &trust_root_data,
        100,
        0,
        0,
    );

    // Evento B: BundleSignerUpdated
    let signer_addr = [0xaa; 20];
    let (offset_b, payload_b) = encode_dynamic_bytes(&signer_pk, 64);
    let mut signer_data = Vec::new();
    signer_data.extend_from_slice(&offset_b);
    signer_data.extend_from_slice(&encode_bool_word(true)); // authorized = true
    signer_data.extend_from_slice(&payload_b);
    let log_signer = make_log_json(
        &contracts.trust_registry,
        vec![
            TOPIC_BUNDLE_SIGNER_UPDATED,
            encode_address_word(signer_addr),
            signer_kid,
        ],
        &signer_data,
        100,
        0,
        1,
    );

    // Evento C: IssuerRegistered
    let issuer_id = [0x33u8; 32];
    let uri = "https://issuer.example.com";
    let (offset_c, payload_c) = encode_dynamic_bytes(uri.as_bytes(), 96);
    let mut issuer_data = Vec::new();
    issuer_data.extend_from_slice(&offset_c);
    issuer_data.extend_from_slice(&encode_uint64_word(1600000000)); // valid_from
    issuer_data.extend_from_slice(&encode_uint64_word(1900000000)); // valid_until
    issuer_data.extend_from_slice(&payload_c);
    let log_issuer = make_log_json(
        &contracts.trust_registry,
        vec![TOPIC_ISSUER_REGISTERED, issuer_id],
        &issuer_data,
        100,
        1,
        0,
    );

    // Evento D: KeyAdded
    let (offset_d, payload_d) = encode_dynamic_bytes(&issuer_pk, 32);
    let mut key_data = Vec::new();
    key_data.extend_from_slice(&offset_d);
    key_data.extend_from_slice(&payload_d);
    let log_key = make_log_json(
        &contracts.trust_registry,
        vec![TOPIC_KEY_ADDED, issuer_id, issuer_kid],
        &key_data,
        100,
        1,
        1,
    );

    // Evento E: StatusManifestAnchored
    let manifest_hash = [0x77u8; 32];
    let manifest_uri = "https://status.example.com/manifest.json";
    let (offset_e, payload_e) = encode_dynamic_bytes(manifest_uri.as_bytes(), 64);
    let mut anchor_data = Vec::new();
    anchor_data.extend_from_slice(&manifest_hash);
    anchor_data.extend_from_slice(&offset_e);
    anchor_data.extend_from_slice(&payload_e);
    let log_anchor = make_log_json(
        &contracts.status_anchor,
        vec![
            TOPIC_STATUS_MANIFEST_ANCHORED,
            issuer_id,
            encode_uint64_word(1), // manifest_version = 1
        ],
        &anchor_data,
        100,
        2,
        0,
    );

    // Simular respuesta de eth_getLogs con los 5 eventos
    transport.set_response(
        ep1,
        "eth_getLogs",
        json!([log_trust_root, log_signer, log_issuer, log_key, log_anchor]),
    );

    // Consultar eventos en rango [100, 100]
    let events = adapter
        .fetch_events(100, 100)
        .expect("events fetched and decoded");
    assert_eq!(events.len(), 5);

    // Verificar orden de coordenadas (bloque 100, tx 0..2, log 0..1)
    for i in 1..events.len() {
        assert!(events[i - 1].coordinate < events[i].coordinate);
    }

    // Comprobar que los tipos decodificados corresponden
    match &events[0].event {
        LedgerEvent::TrustRootUpdated(e) => {
            assert_eq!(e.root_hash, root_hash);
            assert_eq!(e.root_version, 1);
        }
        other => panic!("expected TrustRootUpdated, got {other:?}"),
    }

    match &events[1].event {
        LedgerEvent::BundleSignerUpdated(e) => {
            assert_eq!(e.signer_address, signer_addr);
            assert_eq!(e.kid, signer_kid);
            assert!(e.authorized);
        }
        other => panic!("expected BundleSignerUpdated, got {other:?}"),
    }

    match &events[2].event {
        LedgerEvent::IssuerRegistered(e) => {
            assert_eq!(e.issuer_id, issuer_id);
            assert_eq!(e.uri, uri);
        }
        other => panic!("expected IssuerRegistered, got {other:?}"),
    }

    match &events[3].event {
        LedgerEvent::KeyAdded(e) => {
            assert_eq!(e.issuer_id, issuer_id);
            assert_eq!(e.kid, issuer_kid);
            assert_eq!(e.public_key, issuer_pk);
        }
        other => panic!("expected KeyAdded, got {other:?}"),
    }

    match &events[4].event {
        LedgerEvent::StatusManifestAnchored(e) => {
            assert_eq!(e.issuer_id, issuer_id);
            assert_eq!(e.manifest_version, 1);
            assert_eq!(e.manifest_hash, manifest_hash);
            assert_eq!(e.uri_hint, manifest_uri);
        }
        other => panic!("expected StatusManifestAnchored, got {other:?}"),
    }

    // REQ-TRUST-008: Verificar que los eventos decodificados reconstruyen estado puro sin error
    let mut state = LedgerState::new(42161, contracts.trust_registry);
    let applied_count = state
        .apply_events(&events)
        .expect("pure state reconstructed");
    assert_eq!(applied_count, 5);

    let root_rec = state.trust_root().expect("trust root present");
    assert_eq!(root_rec.root_version, 1);
    assert_eq!(root_rec.root_hash, root_hash);
    assert!(state.issuers().contains_key(&issuer_id));
    assert!(state.bundle_signers().contains_key(&signer_addr));
}

#[test]
fn test_evm_adapter_chunking_across_block_ranges() {
    // Verifies: REQ-LEDG-005
    let transport = Arc::new(MockRpcTransport::new());
    let ep = "https://rpc.example.com";

    transport.set_response(
        ep,
        "eth_getBlockByNumber",
        json!({
            "number": "0x1f4", // 500
            "hash": "0x5555555555555555555555555555555555555555555555555555555555555555",
            "parentHash": "0x4444444444444444444444444444444444444444444444444444444444444444",
            "timestamp": "0x67000000"
        }),
    );

    // max_block_range = 10 -> rango [100, 125] requiere 3 queries: [100, 109], [110, 119], [120, 125]
    let config = MultiRpcConfig {
        endpoints: vec![ep.to_string()],
        max_block_range: 10,
        require_quorum_consistency: false,
        ..MultiRpcConfig::new(vec![ep.to_string()])
    };

    let client = MultiRpcClient::new(config, transport.clone()).expect("valid client");
    let adapter = EvmLedgerAdapter::new_with_chain_id(
        client,
        1,
        EvmContractAddresses::new(
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ),
    );

    transport.set_response(ep, "eth_getLogs", json!([]));

    let events = adapter
        .fetch_events(100, 125)
        .expect("chunked query succeeds");
    assert_eq!(events.len(), 0);

    // Verificar que se realizaron exactamente 3 llamadas eth_getLogs
    assert_eq!(transport.call_count(ep, "eth_getLogs"), 3);

    let recorded = transport.recorded_calls();
    let get_logs_calls: Vec<_> = recorded
        .iter()
        .filter(|c| c.method == "eth_getLogs")
        .collect();
    assert_eq!(get_logs_calls.len(), 3);

    // Primer chunk: 100 (0x64) a 109 (0x6d)
    let p0 = &get_logs_calls[0].params[0];
    assert_eq!(p0["fromBlock"], "0x64");
    assert_eq!(p0["toBlock"], "0x6d");

    // Segundo chunk: 110 (0x6e) a 119 (0x77)
    let p1 = &get_logs_calls[1].params[0];
    assert_eq!(p1["fromBlock"], "0x6e");
    assert_eq!(p1["toBlock"], "0x77");

    // Tercer chunk: 120 (0x78) a 125 (0x7d)
    let p2 = &get_logs_calls[2].params[0];
    assert_eq!(p2["fromBlock"], "0x78");
    assert_eq!(p2["toBlock"], "0x7d");
}

#[test]
fn test_evm_adapter_status_commitment_queries() {
    // Verifies: REQ-LEDG-002, REQ-STAT-006
    let transport = Arc::new(MockRpcTransport::new());
    let ep = "https://rpc.example.com";

    let issuer_id = [0x88u8; 32];
    let manifest_hash = [0x99u8; 32];
    let manifest_version = 42u64;
    let anchored_at = 1710000000u64;
    let block_number = 1500u64;

    // Codificar retorno ABI de getLatestCommitment:
    // (bytes32 manifestHash, uint64 manifestVersion, uint64 anchoredAt, uint64 blockNumber)
    let mut return_bytes = Vec::new();
    return_bytes.extend_from_slice(&manifest_hash);
    return_bytes.extend_from_slice(&encode_uint64_word(manifest_version));
    return_bytes.extend_from_slice(&encode_uint64_word(anchored_at));
    return_bytes.extend_from_slice(&encode_uint64_word(block_number));

    transport.set_response(
        ep,
        "eth_call",
        json!(format!("0x{}", hex_encode(&return_bytes))),
    );

    let config = MultiRpcConfig {
        endpoints: vec![ep.to_string()],
        require_quorum_consistency: false,
        ..MultiRpcConfig::new(vec![ep.to_string()])
    };

    let client = MultiRpcClient::new(config, transport.clone()).expect("valid client");
    let adapter = EvmLedgerAdapter::new_with_chain_id(
        client,
        1,
        EvmContractAddresses::new(
            "0x1111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222".to_string(),
        ),
    );

    // Consulta con compromiso existente
    let record = adapter
        .get_status_commitment(&issuer_id)
        .expect("commitment fetched")
        .expect("commitment should be Some");

    assert_eq!(record.issuer_id, issuer_id);
    assert_eq!(record.manifest_version, 42);
    assert_eq!(record.manifest_hash, manifest_hash);
    assert_eq!(record.anchored_at, anchored_at);
    assert_eq!(record.block_number, block_number);

    // Consulta con versión 0 (emisor sin compromiso anclado) -> retorna None
    let mut empty_return = Vec::new();
    empty_return.extend_from_slice(&[0u8; 32]);
    empty_return.extend_from_slice(&encode_uint64_word(0)); // version = 0
    empty_return.extend_from_slice(&encode_uint64_word(0));
    empty_return.extend_from_slice(&encode_uint64_word(0));

    transport.set_response(
        ep,
        "eth_call",
        json!(format!("0x{}", hex_encode(&empty_return))),
    );

    let none_record = adapter
        .get_status_commitment(&issuer_id)
        .expect("query succeeds");
    assert!(none_record.is_none());
}
