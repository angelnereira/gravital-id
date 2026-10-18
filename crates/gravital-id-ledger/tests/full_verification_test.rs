//! Pruebas exhaustivas del modo de verificación completa multi-fuente de TrustBundle (F7.T08).
//!
//! Trazabilidad:
//! - **REQ-TRUST-004:** El modo de verificación completa DEBE contrastar el bundle con $\ge 2$ fuentes de ledger independientes.
//! - **P-10:** Resiliencia y descentralización de confianza.
//! - **INV-01:** Verificación sans-I/O determinista en memoria.
//! - **INV-02:** Cero datos personales en alarmas o diagnósticos.
//! - **INV-04:** Modelo estructurado con evidencia y diagnósticos.
//! - **INV-05:** Fail-closed ante cualquier discrepancia o caída de fuentes.
//! - **INV-11:** Trazabilidad determinista con tiempo inyectado.
//! - **INV-16:** Prohibición absoluta de confiar en menos de 2 fuentes en verificación completa.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_ledger::{
    derive_trust_bundle, BlockHeader, BundleDerivationParams, BundleStateDivergence,
    EventCoordinate, FullVerificationEngine, FullVerificationOutcome, FullVerificationPolicy,
    InMemoryLedgerAdapter, IssuerRegisteredEvent, IssuerSuspendedEvent, KeyAddedEvent,
    KeyCompromisedEvent, LedgerAdapter, LedgerError, LedgerEvent, LedgerResult, LedgerState,
    SequencedLedgerEvent, StatusCommitmentRecord,
};
use gravital_id_testkit::SeededRng;
use proptest::prelude::*;

const TEST_CHAIN_ID: u64 = 11155111;
const TEST_REGISTRY_ADDR: &str = "0x1111111111111111111111111111111111111111";

fn sample_keys(seed: u64) -> (Vec<u8>, [u8; 32]) {
    let rng = SeededRng::new(seed);
    let sk = generate_p256_secret_key(&rng).expect("valid secret key");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");

    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(jwk.x());
    uncompressed.extend_from_slice(jwk.y());

    let mut kid = [0u8; 32];
    kid[0..8].copy_from_slice(&seed.to_be_bytes());
    (uncompressed, kid)
}

fn build_test_source(
    chain_id: u64,
    finalized_block: u64,
    events: Vec<SequencedLedgerEvent>,
) -> InMemoryLedgerAdapter {
    let head = BlockHeader::new(
        finalized_block,
        [0xAA; 32],
        [0x99; 32],
        1_700_000_000u64.saturating_add(finalized_block),
    );
    let mut adapter = InMemoryLedgerAdapter::new(chain_id, head);
    for ev in events {
        adapter.add_event(ev);
    }
    adapter
}

struct FailingAdapter;

impl LedgerAdapter for FailingAdapter {
    fn chain_id(&self) -> u64 {
        TEST_CHAIN_ID
    }
    fn finalized_head(&self) -> LedgerResult<BlockHeader> {
        Err(LedgerError::Adapter(
            "simulated network connection timeout".into(),
        ))
    }
    fn fetch_events(&self, _from: u64, _to: u64) -> LedgerResult<Vec<SequencedLedgerEvent>> {
        Err(LedgerError::Adapter("simulated RPC failure".into()))
    }
    fn get_status_commitment(
        &self,
        _issuer_id: &[u8; 32],
    ) -> LedgerResult<Option<StatusCommitmentRecord>> {
        Err(LedgerError::Adapter(
            "simulated status query failure".into(),
        ))
    }
}

// Verifies: REQ-TRUST-004, INV-16
#[test]
fn policy_rejects_fewer_than_two_sources_at_construction() {
    assert!(FullVerificationPolicy::new(0, 100).is_err());
    assert!(FullVerificationPolicy::new(1, 100).is_err());

    let err = FullVerificationPolicy::new(1, 100).expect_err("should reject 1 source");
    match err {
        LedgerError::InvalidPolicy(msg) => {
            assert!(msg.contains("min_sources must be >= 2"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    assert!(FullVerificationPolicy::new(2, 100).is_ok());
    assert!(FullVerificationPolicy::new(5, 50).is_ok());
}

// Verifies: REQ-TRUST-004, INV-05
#[test]
fn insufficient_sources_fails_closed_when_less_than_two_provided() {
    let engine = FullVerificationEngine::standard();
    let (key_bytes, kid) = sample_keys(1);
    let issuer_id = [0x01; 32];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    let src1 = build_test_source(TEST_CHAIN_ID, 50, events.clone());

    // Derivar un bundle canónico en bloque 50
    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], 1_700_000_050),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    // 1. Caso con 0 fuentes
    let outcome_zero = engine.verify_bundle(&derived.bundle, &[], 1_700_000_050);
    assert!(!outcome_zero.is_verified());
    match outcome_zero {
        FullVerificationOutcome::InsufficientSources {
            required,
            available,
            ..
        } => {
            assert_eq!(required, 2);
            assert_eq!(available, 0);
        }
        other => panic!("expected InsufficientSources, got: {other:?}"),
    }

    // 2. Caso con solo 1 fuente (INV-16: nunca confiar en 1 sola fuente en modo completo)
    let outcome_one = engine.verify_bundle(
        &derived.bundle,
        &[("source-alpha", &src1 as &dyn LedgerAdapter)],
        1_700_000_050,
    );
    assert!(!outcome_one.is_verified());
    match outcome_one {
        FullVerificationOutcome::InsufficientSources {
            required,
            available,
            ..
        } => {
            assert_eq!(required, 2);
            assert_eq!(available, 1);
        }
        other => panic!("expected InsufficientSources, got: {other:?}"),
    }
}

// Verifies: REQ-TRUST-004, INV-05
#[test]
fn insufficient_sources_fails_closed_when_a_source_adapter_fails() {
    let engine = FullVerificationEngine::standard();
    let (key_bytes, kid) = sample_keys(2);
    let issuer_id = [0x02; 32];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    let src_healthy = build_test_source(TEST_CHAIN_ID, 50, events.clone());
    let src_failing = FailingAdapter;

    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], 1_700_000_050),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    let outcome = engine.verify_bundle(
        &derived.bundle,
        &[
            ("rpc-primary", &src_healthy as &dyn LedgerAdapter),
            ("rpc-failing", &src_failing as &dyn LedgerAdapter),
        ],
        1_700_000_050,
    );

    assert!(!outcome.is_verified());
    match outcome {
        FullVerificationOutcome::InsufficientSources {
            required,
            available,
            failed_sources,
        } => {
            assert_eq!(required, 2);
            assert_eq!(available, 1);
            assert_eq!(failed_sources.len(), 1);
            assert_eq!(failed_sources[0].0, "rpc-failing");
        }
        other => panic!("expected InsufficientSources, got: {other:?}"),
    }
}

// Verifies: REQ-TRUST-004
#[test]
fn nominal_full_verification_succeeds_with_two_and_three_concordant_sources() {
    let engine = FullVerificationEngine::standard();
    let (key_bytes, kid) = sample_keys(3);
    let issuer_id = [0x03; 32];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(50, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    let src1 = build_test_source(TEST_CHAIN_ID, 50, events.clone());
    let src2 = build_test_source(TEST_CHAIN_ID, 52, events.clone());
    let src3 = build_test_source(TEST_CHAIN_ID, 55, events.clone());

    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], 1_700_000_050),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    // 1. Verificación exitosa con 2 fuentes
    let outcome_two = engine.verify_bundle(
        &derived.bundle,
        &[
            ("rpc-infura", &src1 as &dyn LedgerAdapter),
            ("rpc-alchemy", &src2 as &dyn LedgerAdapter),
        ],
        1_700_000_050,
    );
    assert!(outcome_two.is_verified());
    match outcome_two {
        FullVerificationOutcome::Verified {
            sources_verified,
            checkpoints,
            ..
        } => {
            assert_eq!(sources_verified.len(), 2);
            assert_eq!(checkpoints.len(), 2);
            assert_eq!(sources_verified[0], "rpc-infura");
            assert_eq!(sources_verified[1], "rpc-alchemy");
        }
        other => panic!("expected Verified, got: {other:?}"),
    }

    // 2. Verificación exitosa con 3 fuentes
    let outcome_three = engine.verify_bundle(
        &derived.bundle,
        &[
            ("node-us", &src1 as &dyn LedgerAdapter),
            ("node-eu", &src2 as &dyn LedgerAdapter),
            ("node-ap", &src3 as &dyn LedgerAdapter),
        ],
        1_700_000_050,
    );
    assert!(outcome_three.is_verified());
    if let FullVerificationOutcome::Verified {
        sources_verified, ..
    } = outcome_three
    {
        assert_eq!(sources_verified.len(), 3);
    }
}

// Verifies: REQ-TRUST-004, INV-05
#[test]
fn divergence_alarm_emitted_when_bundle_misses_compromised_key() {
    let engine = FullVerificationEngine::standard();
    let (key_bytes, kid) = sample_keys(4);
    let issuer_id = [0x04; 32];

    let events_nominal = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(30, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    // El bundle se derivó con la clave nominal activa
    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events_nominal {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(30, [0xAA; 32], [0x99; 32], 1_700_000_030),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    // Ambos nodos del ledger registran un evento de clave comprometida en bloque 35
    let mut events_compromised = events_nominal;
    events_compromised.push(SequencedLedgerEvent::new(
        EventCoordinate::new(35, 0, 0, 1_700_000_035),
        LedgerEvent::KeyCompromised(KeyCompromisedEvent {
            issuer_id,
            kid,
            state_since: 1_700_000_035,
        }),
    ));

    let src1 = build_test_source(TEST_CHAIN_ID, 50, events_compromised.clone());
    let src2 = build_test_source(TEST_CHAIN_ID, 50, events_compromised);

    let outcome = engine.verify_bundle(
        &derived.bundle,
        &[
            ("ledger-node-1", &src1 as &dyn LedgerAdapter),
            ("ledger-node-2", &src2 as &dyn LedgerAdapter),
        ],
        1_700_000_060,
    );

    assert!(!outcome.is_verified());
    match outcome {
        FullVerificationOutcome::BundleDivergence(alarm) => {
            assert!(alarm.has_critical_security_divergence);
            assert_eq!(alarm.divergences_by_source.len(), 2);
            for divs in alarm.divergences_by_source.values() {
                assert!(divs.iter().any(|d| matches!(
                    d,
                    BundleStateDivergence::CompromisedKeyNotReflected { .. }
                )));
            }
        }
        other => panic!("expected BundleDivergence alarm, got: {other:?}"),
    }
}

// Verifies: REQ-TRUST-004, INV-05
#[test]
fn divergence_alarm_emitted_when_bundle_misses_suspended_or_deregistered_issuer() {
    let engine = FullVerificationEngine::standard();
    let (key_bytes, kid) = sample_keys(5);
    let issuer_id = [0x05; 32];

    let events_nominal = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(30, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events_nominal {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(30, [0xAA; 32], [0x99; 32], 1_700_000_030),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    // En el ledger el emisor fue suspendido preventivamente
    let mut events_suspended = events_nominal;
    events_suspended.push(SequencedLedgerEvent::new(
        EventCoordinate::new(35, 0, 0, 1_700_000_035),
        LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
            issuer_id,
            expires_at: 1_700_086_400,
            initiated_by: [0xEE; 20],
        }),
    ));

    let src1 = build_test_source(TEST_CHAIN_ID, 50, events_suspended.clone());
    let src2 = build_test_source(TEST_CHAIN_ID, 50, events_suspended);

    let outcome = engine.verify_bundle(
        &derived.bundle,
        &[
            ("source-a", &src1 as &dyn LedgerAdapter),
            ("source-b", &src2 as &dyn LedgerAdapter),
        ],
        1_700_000_050,
    );

    assert!(!outcome.is_verified());
    match outcome {
        FullVerificationOutcome::BundleDivergence(alarm) => {
            for divs in alarm.divergences_by_source.values() {
                assert!(divs
                    .iter()
                    .any(|d| matches!(d, BundleStateDivergence::IssuerStateMismatch { .. })));
            }
        }
        other => panic!("expected BundleDivergence, got: {other:?}"),
    }
}

// Verifies: REQ-TRUST-004, INV-05
#[test]
fn cross_ledger_divergence_alarm_emitted_when_sources_disagree_on_chain_id() {
    let engine = FullVerificationEngine::standard();
    let (key_bytes, kid) = sample_keys(6);
    let issuer_id = [0x06; 32];

    let events = vec![
        SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 1_700_000_010),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "did:web:te.gob.pa".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_700_000_000,
                valid_until: 1_800_000_000,
            }),
        ),
        SequencedLedgerEvent::new(
            EventCoordinate::new(20, 0, 0, 1_700_000_020),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid,
                public_key: key_bytes,
            }),
        ),
    ];

    // Source 1 es Sepolia (11155111), Source 2 es Mainnet (1)
    let src1 = build_test_source(11155111, 50, events.clone());
    let src2 = build_test_source(1, 50, events.clone());

    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(50, [0xAA; 32], [0x99; 32], 1_700_000_050),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    let outcome = engine.verify_bundle(
        &derived.bundle,
        &[
            ("sepolia-node", &src1 as &dyn LedgerAdapter),
            ("mainnet-node", &src2 as &dyn LedgerAdapter),
        ],
        1_700_000_050,
    );

    assert!(!outcome.is_verified());
    match outcome {
        FullVerificationOutcome::CrossLedgerDivergence(alarm) => {
            assert!(alarm.reason.contains("chain_id"));
            assert_eq!(alarm.sources_involved.len(), 2);
        }
        other => panic!("expected CrossLedgerDivergence, got: {other:?}"),
    }
}

// Verifies: REQ-TRUST-004, INV-05
#[test]
fn cross_ledger_divergence_alarm_emitted_when_block_drift_exceeds_threshold() {
    let policy = FullVerificationPolicy::new(2, 50).expect("valid policy");
    let engine = FullVerificationEngine::new(policy);
    let issuer_id = [0x07; 32];

    let events = vec![SequencedLedgerEvent::new(
        EventCoordinate::new(10, 0, 0, 1_700_000_010),
        LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id,
            uri: "did:web:te.gob.pa".into(),
            profiles: vec!["pip-personal-v1".into()],
            vcts: vec![],
            valid_from: 1_700_000_000,
            valid_until: 1_800_000_000,
        }),
    )];

    // Source 1 en bloque 100, Source 2 en bloque 200 (drift = 100 > max 50)
    let src1 = build_test_source(TEST_CHAIN_ID, 100, events.clone());
    let src2 = build_test_source(TEST_CHAIN_ID, 200, events.clone());

    let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
    for ev in &events {
        state.apply_event(ev).expect("apply event");
    }
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        BlockHeader::new(100, [0xAA; 32], [0x99; 32], 1_700_000_100),
        604_800,
        vec![],
    );
    let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

    let outcome = engine.verify_bundle(
        &derived.bundle,
        &[
            ("lagging-node", &src1 as &dyn LedgerAdapter),
            ("leading-node", &src2 as &dyn LedgerAdapter),
        ],
        1_700_000_200,
    );

    assert!(!outcome.is_verified());
    match outcome {
        FullVerificationOutcome::CrossLedgerDivergence(alarm) => {
            assert!(alarm.reason.contains("drift"));
        }
        other => panic!("expected CrossLedgerDivergence, got: {other:?}"),
    }
}

// Verifies: REQ-TRUST-004
proptest! {
    #[test]
    fn prop_full_verification_agreement_iff_verified(
        seed in 100u64..200u64,
        drift in 0u64..30u64,
        mutate_compromise in any::<bool>(),
    ) {
        let engine = FullVerificationEngine::standard();
        let (key_bytes, kid) = sample_keys(seed);
        let issuer_id = [0x42; 32];

        let mut events = vec![
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 0, 1_700_000_010),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id,
                    uri: "did:web:te.gob.pa".into(),
                    profiles: vec!["pip-personal-v1".into()],
                    vcts: vec![],
                    valid_from: 1_700_000_000,
                    valid_until: 1_800_000_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(50, 0, 0, 1_700_000_020),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id,
                    kid,
                    public_key: key_bytes,
                }),
            ),
        ];

        let mut state = LedgerState::new(TEST_CHAIN_ID, TEST_REGISTRY_ADDR.into());
        for ev in &events {
            state.apply_event(ev).expect("apply event");
        }

        let params = BundleDerivationParams::new(
            "pip-global-mainnet",
            1,
            1,
            BlockHeader::new(50, [0xAA; 32], [0x99; 32], 1_700_000_050),
            604_800,
            vec![],
        );
        let derived = derive_trust_bundle(&state, &params).expect("derive bundle");

        if mutate_compromise {
            events.push(SequencedLedgerEvent::new(
                EventCoordinate::new(55, 0, 0, 1_700_000_055),
                LedgerEvent::KeyCompromised(KeyCompromisedEvent {
                    issuer_id,
                    kid,
                    state_since: 1_700_000_055,
                }),
            ));
        }

        let src1 = build_test_source(TEST_CHAIN_ID, 60, events.clone());
        let src2 = build_test_source(TEST_CHAIN_ID, 60u64.saturating_add(drift), events);

        let outcome = engine.verify_bundle(
            &derived.bundle,
            &[
                ("src-1", &src1 as &dyn LedgerAdapter),
                ("src-2", &src2 as &dyn LedgerAdapter),
            ],
            1_700_000_060,
        );

        if mutate_compromise {
            prop_assert!(!outcome.is_verified(), "must fail closed when key is compromised in ledger");
            prop_assert!(matches!(outcome, FullVerificationOutcome::BundleDivergence(_)));
        } else {
            prop_assert!(outcome.is_verified(), "must verify successfully when all sources agree");
        }
    }
}
