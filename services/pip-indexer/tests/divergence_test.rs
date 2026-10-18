//! Pruebas de detección de divergencias y split-views entre proveedores RPC (REQ-LEDG-005, REQ-LEDG-006).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pip_indexer::divergence::{BlockHeaderSample, RpcDivergenceDetector};

#[test]
fn consistent_rpc_samples_pass_and_return_block_hash() {
    let samples = vec![
        BlockHeaderSample {
            provider: "https://rpc1.arbitrum.io".to_string(),
            block_number: 1000,
            block_hash: "0xaaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
                .to_string(),
            parent_hash: "0xbbbb111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
                .to_string(),
        },
        BlockHeaderSample {
            provider: "https://rpc2.arbitrum.io".to_string(),
            block_number: 1000,
            block_hash: "0xaaaa111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
                .to_string(),
            parent_hash: "0xbbbb111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
                .to_string(),
        },
    ];

    let agreed_hash = RpcDivergenceDetector::check_samples(&samples).unwrap();
    assert_eq!(agreed_hash, samples.first().unwrap().block_hash);
}

#[test]
fn divergence_in_block_hash_fails_closed() {
    let samples = vec![
        BlockHeaderSample {
            provider: "rpc1".to_string(),
            block_number: 500,
            block_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        },
        BlockHeaderSample {
            provider: "rpc2".to_string(),
            block_number: 500,
            block_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        },
    ];

    let res = RpcDivergenceDetector::check_samples(&samples);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Divergencia crítica en block_hash"));
}

#[test]
fn divergence_in_parent_hash_fails_closed() {
    let samples = vec![
        BlockHeaderSample {
            provider: "rpc1".to_string(),
            block_number: 500,
            block_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            parent_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        },
        BlockHeaderSample {
            provider: "rpc2".to_string(),
            block_number: 500,
            block_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            parent_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
        },
    ];

    let res = RpcDivergenceDetector::check_samples(&samples);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Divergencia crítica en parent_hash"));
}

#[test]
fn divergence_in_heights_fails_closed() {
    let samples = vec![
        BlockHeaderSample {
            provider: "rpc1".to_string(),
            block_number: 500,
            block_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        },
        BlockHeaderSample {
            provider: "rpc2".to_string(),
            block_number: 501,
            block_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            parent_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        },
    ];

    let res = RpcDivergenceDetector::check_samples(&samples);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Inconsistencia en alturas de bloque"));
}

#[test]
fn empty_samples_fail_gracefully() {
    let res = RpcDivergenceDetector::check_samples(&[]);
    assert!(res.is_err());
}

#[test]
fn safe_finalized_head_resolves_minimum_and_rejects_excessive_skew() {
    let heads = vec![
        ("rpc1".to_string(), 1000),
        ("rpc2".to_string(), 1002),
        ("rpc3".to_string(), 1001),
    ];

    // Con tolerancia de 5 bloques, la altura segura es el mínimo (1000)
    let safe_head = RpcDivergenceDetector::safe_finalized_head(&heads, 5).unwrap();
    assert_eq!(safe_head, 1000);

    // Con tolerancia de 1 bloque, un desfase de 2 bloques (1002 - 1000) dispara alerta
    let res_err = RpcDivergenceDetector::safe_finalized_head(&heads, 1);
    assert!(res_err.is_err());
    assert!(res_err
        .unwrap_err()
        .to_string()
        .contains("Desfase excesivo"));

    // Lista vacía
    assert!(RpcDivergenceDetector::safe_finalized_head(&[], 5).is_err());
}
