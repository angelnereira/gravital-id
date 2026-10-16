//! Pruebas basadas en propiedades (proptest) para gravital-id-ledger (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-TRUST-008:** Determinismo estricto e invariante de bytes idénticos.
//! - **REQ-LEDG-002:** Ordenación monotónica de eventos.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_ledger::{
    derive_trust_bundle, BlockHeader, BundleDerivationParams, EventCoordinate,
    IssuerRegisteredEvent, KeyAddedEvent, LedgerError, LedgerEvent, LedgerState,
    SequencedLedgerEvent,
};
use gravital_id_testkit::SeededRng;
use proptest::prelude::*;

fn test_key(seed: u64) -> (Vec<u8>, [u8; 32]) {
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

proptest! {
    #[test]
    // Verifies: REQ-LEDG-002, REQ-TRUST-008
    fn prop_monotonic_coordinates_always_succeed_and_non_monotonic_fail(
        start_block in 1u64..10_000,
        step1 in 1u32..10,
        step2 in 1u32..10,
    ) {
        let mut state = LedgerState::new(1, "0x1234567890123456789012345678901234567890".into());
        let issuer_id = [0x42; 32];

        let c1 = EventCoordinate::new(start_block, 0, 0, 1_000);
        let c2 = EventCoordinate::new(start_block, step1, 0, 1_000);
        let c3 = EventCoordinate::new(start_block.saturating_add(1), 0, step2, 1_012);

        // c1 < c2 < c3
        prop_assert!(c1 < c2);
        prop_assert!(c2 < c3);

        // Registro de emisor en c1
        let ev1 = SequencedLedgerEvent::new(
            c1,
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://issuer.example.com".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_000,
                valid_until: 10_000,
            }),
        );
        prop_assert!(state.apply_event(&ev1).is_ok());
        prop_assert_eq!(state.last_coordinate(), Some(c1));

        // Evento con coordenada duplicada (c1) falla
        let is_dup_err = matches!(
            state.apply_event(&ev1),
            Err(LedgerError::NonMonotonicEventCoordinate { .. })
        );
        prop_assert!(is_dup_err);

        // Evento con coordenada anterior a c1 falla
        let c_older = EventCoordinate::new(start_block.saturating_sub(1), 0, 0, 999);
        if c_older < c1 {
            let ev_older = SequencedLedgerEvent::new(
                c_older,
                LedgerEvent::IssuerReinstated(gravital_id_ledger::IssuerReinstatedEvent { issuer_id }),
            );
            let is_older_err = matches!(
                state.apply_event(&ev_older),
                Err(LedgerError::NonMonotonicEventCoordinate { .. })
            );
            prop_assert!(is_older_err);
        }

        // Evento con coordenada superior (c2) tiene éxito
        let (key_bytes, kid) = test_key(1);
        let ev2 = SequencedLedgerEvent::new(
            c2,
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        );
        prop_assert!(state.apply_event(&ev2).is_ok());
        prop_assert_eq!(state.last_coordinate(), Some(c2));
    }

    #[test]
    // Verifies: REQ-TRUST-008
    fn prop_deterministic_derivation_invariant(
        block_num in 100u64..1_000,
        timestamp in 1_700_000_000u64..1_800_000_000,
        epoch in 1u64..10,
        version in 1u64..500,
    ) {
        let mut state = LedgerState::new(1, "0x1234567890123456789012345678901234567890".into());
        let issuer_id = [0x77; 32];
        let (key_bytes, kid) = test_key(42);

        let c1 = EventCoordinate::new(block_num.saturating_sub(10), 0, 0, timestamp.saturating_sub(120));
        let c2 = EventCoordinate::new(block_num.saturating_sub(5), 0, 0, timestamp.saturating_sub(60));

        let _ = state.apply_event(&SequencedLedgerEvent::new(
            c1,
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://proptest-issuer.org".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec!["https://vct.example.com/id".into()],
                valid_from: timestamp.saturating_sub(1_000),
                valid_until: timestamp.saturating_add(100_000),
            }),
        ));

        let _ = state.apply_event(&SequencedLedgerEvent::new(
            c2,
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ));

        let block = BlockHeader::new(block_num, [0xbb; 32], [0xaa; 32], timestamp);
        let params = BundleDerivationParams::new(
            "pip-global-mainnet",
            epoch,
            version,
            block,
            7 * 86_400,
            vec![],
        );

        let d1 = derive_trust_bundle(&state, &params).expect("derivation 1");
        let d2 = derive_trust_bundle(&state, &params).expect("derivation 2");

        // Bytes canónicos y hash idénticos
        prop_assert_eq!(d1.canonical_json_bytes, d2.canonical_json_bytes);
        prop_assert_eq!(d1.sha256_digest, d2.sha256_digest);
    }
}
