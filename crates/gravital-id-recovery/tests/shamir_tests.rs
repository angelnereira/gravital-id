//! Pruebas de integración, propiedades, umbral y forenses para Shamir Secret Sharing (`F8.T02`).
//!
//! Trazabilidad:
//! - `REQ-REC-003`: Recuperación social con Shamir (k-de-n).
//! - `P-10`: Resiliencia y descentralización de confianza sin custodio único.
//! - `INV-01`: Sans-I/O y compatibilidad `no_std`.
//! - `INV-02`: Ausencia absoluta de datos personales o secretos en claro.
//! - `INV-05`: Fail-closed ante fragmentos insuficientes, alterados o duplicados.
//! - `INV-10`: Sin panics o excepciones ante datos malformados.
//! - `INV-11`: Determinismo e inyección de RNG.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).

use gravital_id_crypto::Rng;
use gravital_id_recovery::{
    RecoveryCode, RecoveryError, ShamirSecretSharing, ShamirShare, SHAMIR_HEADER_LEN,
};
use gravital_id_testkit::SeededRng;

// // Verifies: REQ-REC-003 (Pruebas de umbral exacto para múltiples configuraciones k-de-n)
#[test]
fn test_shamir_threshold_matrix_various_k_and_n() {
    let rng = SeededRng::new(0xABCD);

    let configurations = [
        (2, 3),  // 2 de 3
        (3, 5),  // 3 de 5
        (4, 7),  // 4 de 7
        (5, 10), // 5 de 10
        (8, 12), // 8 de 12
    ];

    for &(k, n) in &configurations {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret).expect("rng fill");

        let shares = ShamirSecretSharing::split(&secret, k, n, &rng)
            .unwrap_or_else(|e| panic!("split failed for k={k}, n={n}: {e:?}"));
        assert_eq!(shares.len(), n as usize);

        // 1. Reconstruir con los primeros k fragmentos: [0..k]
        let sub_first_k: Vec<ShamirShare> = shares.iter().take(k as usize).cloned().collect();
        let rec1 = ShamirSecretSharing::combine(&sub_first_k).expect("rec first k");
        assert_eq!(
            &rec1, &secret,
            "Fallo al reconstruir con primeros k para ({k}, {n})"
        );

        // 2. Reconstruir con los últimos k fragmentos: [(n-k)..n]
        let sub_last_k: Vec<ShamirShare> = shares
            .iter()
            .skip((n as usize).saturating_sub(k as usize))
            .take(k as usize)
            .cloned()
            .collect();
        let rec2 = ShamirSecretSharing::combine(&sub_last_k).expect("rec last k");
        assert_eq!(
            &rec2, &secret,
            "Fallo al reconstruir con últimos k para ({k}, {n})"
        );

        // 3. Reconstruir con selección alternada
        let sub_alt_k: Vec<ShamirShare> =
            shares.iter().step_by(2).take(k as usize).cloned().collect();
        if sub_alt_k.len() == k as usize {
            let rec3 = ShamirSecretSharing::combine(&sub_alt_k).expect("rec alt k");
            assert_eq!(
                &rec3, &secret,
                "Fallo al reconstruir con alternados para ({k}, {n})"
            );
        }
    }
}

// // Verifies: REQ-REC-003, INV-05 (Fragmentos insuficientes fallan cerrado sin revelar secreto)
#[test]
fn test_shamir_insufficient_shares_fails_closed() {
    let rng = SeededRng::new(0x1234);
    let secret = b"my_super_secret_payload_12345678";
    let k = 4;
    let n = 6;

    let shares = ShamirSecretSharing::split(secret, k, n, &rng).expect("split");

    // 0 fragmentos
    assert!(matches!(
        ShamirSecretSharing::combine(&[]),
        Err(RecoveryError::InsufficientShares)
    ));

    // 1 fragmento
    assert!(matches!(
        ShamirSecretSharing::combine(&[shares[0].clone()]),
        Err(RecoveryError::InsufficientShares)
    ));

    // k - 1 fragmentos (3 fragmentos de 4 requeridos)
    let sub_k_minus_1 = &[shares[0].clone(), shares[1].clone(), shares[2].clone()];
    assert!(matches!(
        ShamirSecretSharing::combine(sub_k_minus_1),
        Err(RecoveryError::InsufficientShares)
    ));
}

// // Verifies: INV-05 (Rechazo de índices duplicados)
#[test]
fn test_shamir_duplicate_share_index_rejected() {
    let rng = SeededRng::new(0x2345);
    let secret = b"duplicate_index_mitigation_test!";
    let shares = ShamirSecretSharing::split(secret, 3, 5, &rng).expect("split");

    // k fragmentos provistos, pero con índice duplicado (ej. share[1] repetido)
    let duplicate_set = &[shares[0].clone(), shares[1].clone(), shares[1].clone()];
    let res = ShamirSecretSharing::combine(duplicate_set);
    assert!(
        matches!(res, Err(RecoveryError::DuplicateShareIndex)),
        "Fragmentos con índice duplicado deben ser rechazados fail-closed"
    );
}

// // Verifies: INV-05 (Rechazo de mezcla de fragmentos de distintos secretos)
#[test]
fn test_shamir_mismatched_secret_id_rejected() {
    let rng = SeededRng::new(0x3456);
    let secret_a = b"first_secret_for_splitting_session_a";
    let secret_b = b"second_secret_for_splitting_session_b";

    let shares_a = ShamirSecretSharing::split(secret_a, 3, 5, &rng).expect("split a");
    let shares_b = ShamirSecretSharing::split(secret_b, 3, 5, &rng).expect("split b");

    // Mezclar fragmentos de A y B
    let mixed_set = &[
        shares_a[0].clone(),
        shares_a[1].clone(),
        shares_b[2].clone(),
    ];
    let res = ShamirSecretSharing::combine(mixed_set);
    assert!(
        matches!(res, Err(RecoveryError::SecretIdMismatch)),
        "Mezcla de fragmentos con distinto secret_id debe fallar fail-closed"
    );
}

// // Verifies: INV-05 (Alteración de un solo bit en un fragmento falla autenticación)
#[test]
fn test_shamir_tampered_shares_fail_checksum() {
    let rng = SeededRng::new(0x4567);
    let secret = b"integrity_tampering_check_secret";
    let shares = ShamirSecretSharing::split(secret, 3, 5, &rng).expect("split");

    // Probar corrupción de 1 bit en el valor de share[0]
    let corrupted_share = shares[0].clone();
    let binary = corrupted_share.to_bytes();
    let mut tampered_bytes = binary.clone();

    // Mutar el último byte del valor del fragmento
    let val_offset = SHAMIR_HEADER_LEN + corrupted_share.value().len() - 1;
    tampered_bytes[val_offset] ^= 0x01;

    // Deserializar fragmento corrupto debe fallar en el checksum interno
    let parse_res = ShamirShare::from_bytes(&tampered_bytes);
    assert!(
        matches!(parse_res, Err(RecoveryError::InvalidChecksum)),
        "Fragmento con byte alterado debe fallar al deserializarse con InvalidChecksum"
    );

    // Mutar directamente en memoria el valor de un fragmento y forzar reconstrucción
    let mut modified_shares = shares.clone();
    // Reemplazar el valor con bytes fraudulentos
    let fraudulent_share = ShamirShare::new(
        corrupted_share.threshold,
        corrupted_share.total_shares,
        corrupted_share.share_index,
        corrupted_share.secret_id,
        vec![0xAA; corrupted_share.value().len()],
    );
    modified_shares[0] = fraudulent_share;

    // Al reconstruir con el fragmento fraudulento, el secret_id no coincidirá con sha256(reconstructed)
    let combine_res = ShamirSecretSharing::combine(&modified_shares[..3]);
    assert!(
        matches!(combine_res, Err(RecoveryError::InvalidChecksum)),
        "Reconstrucción con fragmento fraudulento debe fallar con InvalidChecksum"
    );
}

// // Verifies: INV-02 (Auditoría forense de cero PII y secretos en claro)
#[test]
fn test_shamir_zero_pii_forensic_scan() {
    let rng = SeededRng::new(0x5678);
    let pii_samples = [
        "8-765-4321",
        "Juan Perez Rodriguez",
        "juan.perez@example.pa",
    ];

    let mut secret_payload = Vec::new();
    for pii in &pii_samples {
        secret_payload.extend_from_slice(pii.as_bytes());
    }

    let shares = ShamirSecretSharing::split(&secret_payload, 2, 4, &rng).expect("split");

    for (idx, share) in shares.iter().enumerate() {
        let binary = share.to_bytes();
        let compact = share.to_compact_code();
        let debug = format!("{share:?}");

        // 1. Debug redactado
        assert!(debug.contains("***REDACTED***"));

        // 2. Ninguna cadena confidencial en claro en los bytes binarios del fragmento individual
        for pii in &pii_samples {
            let needle = pii.as_bytes();
            let found_bin = binary.windows(needle.len()).any(|w| w == needle);
            assert!(
                !found_bin,
                "VIOLACIÓN INV-02: PII en claro encontrado en fragmento {idx} binario"
            );
            assert!(
                !compact.contains(pii),
                "VIOLACIÓN INV-02: PII en claro encontrado en fragmento {idx} compacto"
            );
            assert!(
                !debug.contains(pii),
                "VIOLACIÓN INV-02: PII en claro encontrado en debug de fragmento {idx}"
            );
        }
    }
}

// // Verifies: REQ-REC-003 (Roundtrip de código de recuperación completo con mnemónico)
#[test]
fn test_shamir_full_recovery_code_journey() {
    let rng = SeededRng::new(0x6789);
    let original_code = RecoveryCode::generate(&rng).expect("generate original code");
    let original_mnemonic = original_code.to_mnemonic();

    // 1. Dividir en esquema 3 de 5
    let shares = ShamirSecretSharing::split_recovery_code(&original_code, 3, 5, &rng)
        .expect("split recovery code");
    assert_eq!(shares.len(), 5);

    // 2. Serializar a Crockford Base32 compacto para cada guardián
    let mut guardian_cards = Vec::new();
    for share in &shares {
        let card = share.to_compact_code();
        assert!(!card.is_empty());
        guardian_cards.push(card);
    }

    // 3. Simular reunión de los guardianes 2, 4 y 5
    let guardian_indices = [1, 3, 4]; // 0-indexed: guardianes 2, 4 y 5
    let mut recovered_shares = Vec::new();
    for &idx in &guardian_indices {
        let parsed_share = ShamirShare::from_compact_code(&guardian_cards[idx])
            .expect("parse guardian compact card");
        recovered_shares.push(parsed_share);
    }

    // 4. Reconstruir el código de recuperación
    let restored_code = ShamirSecretSharing::combine_recovery_code(&recovered_shares)
        .expect("combine recovery code");

    assert_eq!(original_code.entropy(), restored_code.entropy());
    assert_eq!(original_mnemonic, restored_code.to_mnemonic());
}

// // Verifies: INV-10 (Ausencia de pánicos ante entradas hostiles y malformadas)
#[test]
fn test_shamir_hostile_inputs_no_panics() {
    let hostile_binaries: &[&[u8]] = &[
        b"",
        b"GID",
        b"GIDS",
        &[0u8; 12],
        &[0xFFu8; 20],
        b"GIDS\x01\x05\x03\x01\x00\x00\x00\x00\x10", // k=5 > n=3
        b"GIDS\x01\x01\x05\x01\x00\x00\x00\x00\x10", // k=1 < 2
    ];

    for &hostile in hostile_binaries {
        let res = ShamirShare::from_bytes(hostile);
        assert!(res.is_err(), "Entrada binaria hostil debe fallar");
    }

    let hostile_compacts = ["", "-", "XXXX", "GIDS-0000", "INVALID-BASE32-CHARS-!@#$%"];

    for hostile in &hostile_compacts {
        let res = ShamirShare::from_compact_code(hostile);
        assert!(res.is_err(), "Cadena compacta hostil debe fallar");
    }
}
