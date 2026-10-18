//! Pruebas de configuración y validación tipada para pip-indexer (F7.T03, REQ-LEDG-005, REQ-REL-001).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pip_indexer::config::IndexerConfig;
use std::env;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn default_configuration_is_valid() {
    let cfg = IndexerConfig::default();
    assert!(cfg.validate().is_ok());
    assert_eq!(cfg.chain_id, 31337);
    assert_eq!(cfg.chunk_size_blocks, 500);
    assert_eq!(cfg.poll_interval_millis, 2000);
    assert_eq!(cfg.max_allowed_lag, 100);
}

#[test]
fn from_env_parses_all_fields_correctly() {
    let _lock = ENV_LOCK.lock().unwrap();

    let prefix = "PIP_INDEXER_TEST_1_";
    env::set_var(
        format!("{prefix}RPC_ENDPOINTS"),
        "http://node1:8545, https://node2:8545",
    );
    env::set_var(format!("{prefix}CHAIN_ID"), "421614");
    env::set_var(
        format!("{prefix}TRUST_REGISTRY"),
        "0x1111111111111111111111111111111111111111",
    );
    env::set_var(
        format!("{prefix}STATUS_ANCHOR"),
        "0x2222222222222222222222222222222222222222",
    );
    env::set_var(format!("{prefix}DATABASE_URL"), "sqlite://test.db");
    env::set_var(format!("{prefix}CHUNK_SIZE"), "1000");
    env::set_var(format!("{prefix}POLL_INTERVAL_MS"), "500");
    env::set_var(format!("{prefix}START_BLOCK"), "100");
    env::set_var(format!("{prefix}MAX_ALLOWED_LAG"), "50");

    let cfg = IndexerConfig::from_env_with_prefix(prefix).unwrap();

    assert_eq!(cfg.chain_id, 421614);
    assert_eq!(
        cfg.rpc_endpoints.first().map(|s| s.as_str()),
        Some("http://node1:8545")
    );
    assert_eq!(
        cfg.rpc_endpoints.get(1).map(|s| s.as_str()),
        Some("https://node2:8545")
    );
    assert_eq!(
        cfg.trust_registry_address,
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(
        cfg.status_anchor_address,
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(cfg.database_url, "sqlite://test.db");
    assert_eq!(cfg.chunk_size_blocks, 1000);
    assert_eq!(cfg.poll_interval_millis, 500);
    assert_eq!(cfg.start_block, 100);
    assert_eq!(cfg.max_allowed_lag, 50);

    // Cleanup
    env::remove_var(format!("{prefix}RPC_ENDPOINTS"));
    env::remove_var(format!("{prefix}CHAIN_ID"));
    env::remove_var(format!("{prefix}TRUST_REGISTRY"));
    env::remove_var(format!("{prefix}STATUS_ANCHOR"));
    env::remove_var(format!("{prefix}DATABASE_URL"));
    env::remove_var(format!("{prefix}CHUNK_SIZE"));
    env::remove_var(format!("{prefix}POLL_INTERVAL_MS"));
    env::remove_var(format!("{prefix}START_BLOCK"));
    env::remove_var(format!("{prefix}MAX_ALLOWED_LAG"));
}

#[test]
fn invalid_configuration_fails_closed() {
    let _lock = ENV_LOCK.lock().unwrap();

    // 1. Endpoint inválido (sin protocolo http/https/ws)
    let cfg = IndexerConfig {
        rpc_endpoints: vec!["invalid_node_without_scheme".to_string()],
        ..Default::default()
    };
    assert!(cfg.validate().is_err());

    // 2. Lista vacía de endpoints
    let cfg_empty = IndexerConfig {
        rpc_endpoints: vec![],
        ..Default::default()
    };
    assert!(cfg_empty.validate().is_err());

    // 3. Chain ID 0
    let cfg2 = IndexerConfig {
        chain_id: 0,
        ..Default::default()
    };
    assert!(cfg2.validate().is_err());

    // 4. Dirección Ethereum malformada (longitud o caracteres)
    let cfg3 = IndexerConfig {
        trust_registry_address: "0x123".to_string(),
        ..Default::default()
    };
    assert!(cfg3.validate().is_err());

    let cfg4 = IndexerConfig {
        status_anchor_address: "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        ..Default::default()
    };
    assert!(cfg4.validate().is_err());

    // 5. Chunk size 0 o excesivo
    let cfg5 = IndexerConfig {
        chunk_size_blocks: 0,
        ..Default::default()
    };
    assert!(cfg5.validate().is_err());

    let cfg5_large = IndexerConfig {
        chunk_size_blocks: 20_000,
        ..Default::default()
    };
    assert!(cfg5_large.validate().is_err());

    // 6. Intervalo de sondeo fuera de límites
    let cfg6 = IndexerConfig {
        poll_interval_millis: 10,
        ..Default::default()
    };
    assert!(cfg6.validate().is_err());

    let cfg6_large = IndexerConfig {
        poll_interval_millis: 1_000_000,
        ..Default::default()
    };
    assert!(cfg6_large.validate().is_err());

    // 7. Base de datos vacía
    let cfg7 = IndexerConfig {
        database_url: "   ".to_string(),
        ..Default::default()
    };
    assert!(cfg7.validate().is_err());
}

#[test]
fn system_clock_provides_sensible_unix_timestamp() {
    use gravital_id_types::Clock;
    let clock = pip_indexer::clock::SystemClock;
    assert!(clock.now_seconds() > 1_700_000_000);
    assert_eq!(clock.monotonic_elapsed_millis(), None);
}

#[test]
fn postgres_schema_constants_and_sql_embedded() {
    assert!(pip_indexer::postgres::POSTGRES_SCHEMA_V1_SQL
        .contains("CREATE TABLE IF NOT EXISTS indexed_events"));
    assert!(pip_indexer::postgres::POSTGRES_SCHEMA_V1_SQL
        .contains("CREATE TABLE IF NOT EXISTS indexer_checkpoints"));
    assert_eq!(
        pip_indexer::postgres::TABLE_INDEXED_EVENTS,
        "indexed_events"
    );
    assert_eq!(
        pip_indexer::postgres::TABLE_INDEXER_CHECKPOINTS,
        "indexer_checkpoints"
    );
    assert_eq!(
        pip_indexer::postgres::TABLE_ISSUERS_PROJECTION,
        "issuers_projection"
    );
    assert_eq!(
        pip_indexer::postgres::TABLE_KEYS_PROJECTION,
        "keys_projection"
    );
    assert_eq!(
        pip_indexer::postgres::TABLE_STATUS_ANCHORS_PROJECTION,
        "status_anchors_projection"
    );
    assert_eq!(
        pip_indexer::postgres::TABLE_BUNDLE_SIGNERS_PROJECTION,
        "bundle_signers_projection"
    );
    assert!(pip_indexer::postgres::SQL_POSTGRES_INSERT_EVENT_IDEMPOTENT.contains("ON CONFLICT"));
    assert!(pip_indexer::postgres::SQL_POSTGRES_UPSERT_CHECKPOINT.contains("ON CONFLICT"));
    assert!(pip_indexer::postgres::SQL_POSTGRES_SELECT_CHECKPOINT.contains("SELECT"));
    assert!(pip_indexer::postgres::SQL_POSTGRES_REWIND_EVENTS.contains("DELETE"));
}

#[test]
fn from_env_handles_invalid_port_and_empty_endpoints() {
    let _lock = ENV_LOCK.lock().unwrap();

    let prefix = "PIP_INDEXER_TEST_ERR_";

    // Puerto inválido
    env::set_var("PIP_SERVER_PORT", "not_a_number");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var("PIP_SERVER_PORT");

    // Endpoint vacío
    env::set_var(format!("{prefix}RPC_ENDPOINTS"), " ,   ");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var(format!("{prefix}RPC_ENDPOINTS"));

    // Chain ID no numérico
    env::set_var(format!("{prefix}CHAIN_ID"), "xyz");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var(format!("{prefix}CHAIN_ID"));

    // Chunk size no numérico
    env::set_var(format!("{prefix}CHUNK_SIZE"), "abc");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var(format!("{prefix}CHUNK_SIZE"));

    // Poll interval no numérico
    env::set_var(format!("{prefix}POLL_INTERVAL_MS"), "def");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var(format!("{prefix}POLL_INTERVAL_MS"));

    // Start block no numérico
    env::set_var(format!("{prefix}START_BLOCK"), "ghi");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var(format!("{prefix}START_BLOCK"));

    // Max allowed lag no numérico
    env::set_var(format!("{prefix}MAX_ALLOWED_LAG"), "jkl");
    assert!(IndexerConfig::from_env_with_prefix(prefix).is_err());
    env::remove_var(format!("{prefix}MAX_ALLOWED_LAG"));

    // from_env usa prefijo por defecto y funciona con default
    let cfg = IndexerConfig::from_env().unwrap();
    assert_eq!(cfg.chain_id, 31337);
}
