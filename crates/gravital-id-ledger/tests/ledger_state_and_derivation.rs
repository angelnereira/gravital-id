//! Pruebas unitarias y de integración para gravital-id-ledger (F6.T08).
//!
//! Trazabilidad:
//! - **REQ-LEDG-002:** Abstracción del ledger con `LedgerAdapter`.
//! - **REQ-TRUST-008:** Derivación determinista del bundle y contraste estado ↔ bundle.
//! - **REQ-LEDG-004:** Invariantes de gobernanza, máquina de estados y TTL de emergencia.
//! - **REQ-LEDG-001 / REQ-LEDG-007 / INV-02:** Cero datos personales en el ledger.
//! - **INV-01:** Verificación y lógica de núcleo sans-I/O sin red.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_ledger::{
    compare_bundle_with_state, derive_trust_bundle, BlockHeader, BundleDerivationParams,
    BundleSignerUpdatedEvent, BundleStateDivergence, EventCoordinate, InMemoryLedgerAdapter,
    IssuerDeregisteredEvent, IssuerRegisteredEvent, IssuerReinstatedEvent, IssuerSuspendedEvent,
    KeyAddedEvent, KeyCompromisedEvent, KeyRetiredEvent, KeySuspendedEvent, LedgerAdapter,
    LedgerError, LedgerEvent, LedgerState, SequencedLedgerEvent, StatusCommitmentRecord,
    StatusManifestAnchoredEvent, TrustRootUpdatedEvent, VerifierDeregisteredEvent,
    VerifierRegisteredEvent,
};
use gravital_id_testkit::SeededRng;
use gravital_id_trust::{IssuerState, KeyState, PolicyEntry};

fn sample_keys(seed: u64) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let rng = SeededRng::new(seed);
    let sk = generate_p256_secret_key(&rng).expect("valid secret key");
    let jwk = public_key_from_secret_key(&sk).expect("valid jwk");

    // Clave no comprimida (65 bytes: 0x04 || x || y)
    let mut uncompressed = vec![0x04];
    uncompressed.extend_from_slice(jwk.x());
    uncompressed.extend_from_slice(jwk.y());

    // Clave comprimida (33 bytes: (0x02/0x03) || x)
    let prefix = if jwk.y()[31].is_multiple_of(2) {
        0x02
    } else {
        0x03
    };
    let mut compressed = vec![prefix];
    compressed.extend_from_slice(jwk.x());

    // kid como bytes de thumbprint
    let mut kid = [0u8; 32];
    kid.copy_from_slice(jwk.thumbprint_sha256().as_slice());

    (uncompressed, compressed, kid)
}

#[test]
// Verifies: REQ-LEDG-002, REQ-TRUST-008
fn test_event_coordinate_ordering_and_display() {
    let c1 = EventCoordinate::new(100, 0, 1, 1_700_000_000);
    let c2 = EventCoordinate::new(100, 0, 2, 1_700_000_000);
    let c3 = EventCoordinate::new(100, 1, 0, 1_700_000_000);
    let c4 = EventCoordinate::new(101, 0, 0, 1_700_000_012);

    assert!(c1 < c2);
    assert!(c2 < c3);
    assert!(c3 < c4);
    assert_eq!(c1, c1);
    assert_eq!(format!("{c1}"), "b100:tx0:log1@1700000000");
}

#[test]
// Verifies: REQ-LEDG-002, REQ-TRUST-008, INV-01
fn test_in_memory_ledger_adapter_operations() {
    let initial_head = BlockHeader::new(100, [0x11; 32], [0x00; 32], 1_700_000_000);
    let mut adapter = InMemoryLedgerAdapter::new(1, initial_head.clone());

    assert_eq!(adapter.chain_id(), 1);
    assert_eq!(adapter.finalized_head().unwrap(), initial_head);

    let coord = EventCoordinate::new(101, 0, 0, 1_700_000_012);
    let (uncompressed, _, kid) = sample_keys(1);
    let ev = SequencedLedgerEvent::new(
        coord,
        LedgerEvent::KeyAdded(KeyAddedEvent {
            issuer_id: [0xaa; 32],
            kid,
            public_key: uncompressed,
        }),
    );
    adapter.add_event(ev.clone());

    let fetched = adapter.fetch_events(100, 102).unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0], ev);

    let empty = adapter.fetch_events(102, 105).unwrap();
    assert!(empty.is_empty());

    let commitment = StatusCommitmentRecord {
        issuer_id: [0xaa; 32],
        manifest_version: 1,
        manifest_hash: [0x55; 32],
        uri_hint: "https://status.example.com".into(),
        anchored_at: 1_700_000_012,
        block_number: 101,
    };
    adapter.set_status_commitment(commitment.clone());
    assert_eq!(
        adapter.get_status_commitment(&[0xaa; 32]).unwrap(),
        Some(commitment)
    );
    assert_eq!(adapter.get_status_commitment(&[0xbb; 32]).unwrap(), None);
}

#[test]
// Verifies: REQ-LEDG-002, REQ-TRUST-008, REQ-LEDG-004
fn test_ledger_state_issuer_lifecycle_and_invariants() {
    let mut state = LedgerState::new(1, "0x1234567890123456789012345678901234567890".into());
    let issuer_id = [0x01; 32];

    // 1. Registro con timestamps inválidos falla
    let bad_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(10, 0, 0, 1_000),
        LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id,
            uri: "https://issuer.example.com".into(),
            profiles: vec!["pip-personal-v1".into()],
            vcts: vec!["https://vct.example.com/id".into()],
            valid_from: 2_000,
            valid_until: 1_000, // Invalid: from >= until
        }),
    );
    assert!(matches!(
        state.apply_event(&bad_ev),
        Err(LedgerError::InvalidTimestamps { .. })
    ));

    // 2. Registro exitoso
    let reg_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(11, 0, 0, 1_100),
        LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id,
            uri: "https://issuer.example.com".into(),
            profiles: vec!["pip-personal-v1".into()],
            vcts: vec!["https://vct.example.com/id".into()],
            valid_from: 1_000,
            valid_until: 5_000,
        }),
    );
    state.apply_event(&reg_ev).unwrap();
    assert_eq!(
        state.effective_issuer_state(&issuer_id, 1_200),
        Some(IssuerState::Active)
    );

    // 3. Intento de coordenada no monótona o duplicada falla
    assert!(matches!(
        state.apply_event(&reg_ev),
        Err(LedgerError::NonMonotonicEventCoordinate { .. })
    ));

    // 4. Intento de registrar emisor duplicado falla
    let dup_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(12, 0, 0, 1_200),
        LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
            issuer_id,
            uri: "https://issuer.example.com".into(),
            profiles: vec![],
            vcts: vec![],
            valid_from: 1_000,
            valid_until: 5_000,
        }),
    );
    assert!(matches!(
        state.apply_event(&dup_ev),
        Err(LedgerError::IssuerAlreadyExists(_))
    ));

    // 5. Suspensión preventiva de emisor con TTL de emergencia (14 días = 1.209.600 s)
    let susp_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(13, 0, 0, 1_300),
        LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
            issuer_id,
            expires_at: 1_300 + 1_209_600,
            initiated_by: [0xee; 20], // Rol de emergencia
        }),
    );
    state.apply_event(&susp_ev).unwrap();
    // Durante la suspensión:
    assert_eq!(
        state.effective_issuer_state(&issuer_id, 1_500),
        Some(IssuerState::Suspended)
    );
    // Tras expirar automáticamente el TTL:
    assert_eq!(
        state.effective_issuer_state(&issuer_id, 1_300 + 1_209_601),
        Some(IssuerState::Active)
    );

    // 6. Prohibición de renovación por rol de emergencia mientras está activa (REQ-LEDG-004)
    let renew_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(14, 0, 0, 1_400),
        LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
            issuer_id,
            expires_at: 1_400 + 1_209_600,
            initiated_by: [0xee; 20], // Mismo rol de emergencia
        }),
    );
    assert!(matches!(
        state.apply_event(&renew_ev),
        Err(LedgerError::EmergencyRenewalForbidden { .. })
    ));

    // 7. Levantamiento o reactivación explícita
    let reinstate_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(15, 0, 0, 1_500),
        LedgerEvent::IssuerReinstated(IssuerReinstatedEvent { issuer_id }),
    );
    state.apply_event(&reinstate_ev).unwrap();
    assert_eq!(
        state.effective_issuer_state(&issuer_id, 1_501),
        Some(IssuerState::Active)
    );

    // 8. Baja definitiva (deregister)
    let dereg_ev = SequencedLedgerEvent::new(
        EventCoordinate::new(16, 0, 0, 1_600),
        LedgerEvent::IssuerDeregistered(IssuerDeregisteredEvent { issuer_id }),
    );
    state.apply_event(&dereg_ev).unwrap();
    assert_eq!(state.effective_issuer_state(&issuer_id, 1_601), None);
}

#[test]
// Verifies: REQ-LEDG-002, REQ-LEDG-004, REQ-TRUST-008
fn test_ledger_state_key_transitions_and_irreversibility() {
    let mut state = LedgerState::new(1, "0x1234567890123456789012345678901234567890".into());
    let issuer_id = [0x02; 32];

    // Registrar emisor
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(1, 0, 0, 1_000),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://issuer.example.com".into(),
                profiles: vec!["pip-personal-v1".into()],
                vcts: vec![],
                valid_from: 1_000,
                valid_until: 10_000,
            }),
        ))
        .unwrap();

    let (uncompressed_sec1, compressed_sec1, kid1) = sample_keys(10);
    let (uncompressed_sec2, _, kid2) = sample_keys(20);

    // 1. Agregar clave P-256 no comprimida (65 B)
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(2, 0, 0, 2_000),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: kid1,
                public_key: uncompressed_sec1,
            }),
        ))
        .unwrap();

    assert_eq!(
        state.effective_key_state(&issuer_id, &kid1, 2_100),
        Some(KeyState::Active)
    );

    // 2. Agregar segunda clave P-256 no comprimida (65 B)
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(3, 0, 0, 3_000),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: kid2,
                public_key: uncompressed_sec2,
            }),
        ))
        .unwrap();

    // 3. Intento de clave comprimida (33 B) o malformada falla
    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(4, 0, 0, 4_000),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: [0x99; 32],
                public_key: compressed_sec1, // 33-byte compressed is rejected (must be 65-byte uncompressed)
            }),
        )),
        Err(LedgerError::InvalidPublicKey(_))
    ));

    // 4. Clave duplicada falla
    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(5, 0, 0, 5_000),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: kid1,
                public_key: vec![0x04; 65],
            }),
        )),
        Err(LedgerError::KeyAlreadyExists { .. })
    ));

    // 5. Retiro ordenado de kid1
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(6, 0, 0, 6_000),
            LedgerEvent::KeyRetired(KeyRetiredEvent {
                issuer_id,
                kid: kid1,
                state_since: 6_000,
            }),
        ))
        .unwrap();

    assert_eq!(
        state.effective_key_state(&issuer_id, &kid1, 6_100),
        Some(KeyState::Retired)
    );

    // 6. Invariante: Una clave retirada NO puede suspenderse
    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(7, 0, 0, 7_000),
            LedgerEvent::KeySuspended(KeySuspendedEvent {
                issuer_id,
                kid: kid1,
                expires_at: 8_000,
                initiated_by: [0xee; 20],
            }),
        )),
        Err(LedgerError::InvalidKeyTransition { .. })
    ));

    // 7. Marcar kid2 como suspendida preventivamente
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(8, 0, 0, 8_000),
            LedgerEvent::KeySuspended(KeySuspendedEvent {
                issuer_id,
                kid: kid2,
                expires_at: 8_000 + 14 * 86_400,
                initiated_by: [0xee; 20],
            }),
        ))
        .unwrap();

    assert_eq!(
        state.effective_key_state(&issuer_id, &kid2, 8_500),
        Some(KeyState::Suspended)
    );

    // 8. Marcar kid1 y kid2 como Compromised (estado terminal absoluto)
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(9, 0, 0, 9_000),
            LedgerEvent::KeyCompromised(KeyCompromisedEvent {
                issuer_id,
                kid: kid1,
                state_since: 9_000,
            }),
        ))
        .unwrap();

    assert_eq!(
        state.effective_key_state(&issuer_id, &kid1, 9_100),
        Some(KeyState::Compromised)
    );

    // 9. Invariante: Una clave comprometida jamás puede ser retirada ni suspendida
    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(10, 0, 0, 10_000),
            LedgerEvent::KeyRetired(KeyRetiredEvent {
                issuer_id,
                kid: kid1,
                state_since: 10_000,
            }),
        )),
        Err(LedgerError::KeyAlreadyCompromised { .. })
    ));

    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(11, 0, 0, 11_000),
            LedgerEvent::KeySuspended(KeySuspendedEvent {
                issuer_id,
                kid: kid1,
                expires_at: 12_000,
                initiated_by: [0xee; 20],
            }),
        )),
        Err(LedgerError::KeyAlreadyCompromised { .. })
    ));
}

#[test]
// Verifies: REQ-LEDG-002, REQ-TRUST-007, REQ-STAT-006
fn test_ledger_state_verifiers_root_and_status_anchors() {
    let mut state = LedgerState::new(
        11155111,
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".into(),
    );
    let (pubkey, _, _) = sample_keys(42);

    // 1. Verificador registrado y dado de baja
    let v_id = [0x55; 32];
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(1, 0, 0, 100),
            LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
                verifier_id: v_id,
                uri: "https://verifier.org".into(),
                profiles: vec!["pip-personal-v1".into()],
                public_key: pubkey.clone(),
                valid_from: 100,
                valid_until: 1_000,
            }),
        ))
        .unwrap();

    assert_eq!(state.verifiers().len(), 1);
    assert!(state.verifiers()[&v_id].active);

    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(2, 0, 0, 200),
            LedgerEvent::VerifierDeregistered(VerifierDeregisteredEvent { verifier_id: v_id }),
        ))
        .unwrap();
    assert!(!state.verifiers()[&v_id].active);

    // 2. Raíz de confianza y monotonicidad de versión
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(3, 0, 0, 300),
            LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash: [0xaa; 32],
                root_version: 1,
                updated_at: 300,
            }),
        ))
        .unwrap();

    assert_eq!(state.trust_root().unwrap().root_version, 1);

    // Versión igual o decreciente falla
    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(4, 0, 0, 400),
            LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash: [0xbb; 32],
                root_version: 1, // Decreciente / igual
                updated_at: 400,
            }),
        )),
        Err(LedgerError::NonMonotonicRootVersion { .. })
    ));

    // 3. Operador firmante de bundle
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(5, 0, 0, 500),
            LedgerEvent::BundleSignerUpdated(BundleSignerUpdatedEvent {
                signer_address: [0x33; 20],
                kid: [0x44; 32],
                public_key: pubkey,
                authorized: true,
            }),
        ))
        .unwrap();
    assert!(state.bundle_signers()[&[0x33; 20]].authorized);

    // 4. Anclaje de manifiesto de estado en StatusAnchor (REQ-STAT-006)
    let iss_id = [0x77; 32];
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(6, 0, 0, 600),
            LedgerEvent::StatusManifestAnchored(StatusManifestAnchoredEvent {
                issuer_id: iss_id,
                manifest_version: 1,
                manifest_hash: [0x88; 32],
                uri_hint: "https://status.example.com/v1.jwt".into(),
            }),
        ))
        .unwrap();

    assert_eq!(state.status_commitments()[&iss_id].manifest_version, 1);

    // Versión no monótona o hash cero falla
    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(7, 0, 0, 700),
            LedgerEvent::StatusManifestAnchored(StatusManifestAnchoredEvent {
                issuer_id: iss_id,
                manifest_version: 1,
                manifest_hash: [0x88; 32],
                uri_hint: "".into(),
            }),
        )),
        Err(LedgerError::NonMonotonicManifestVersion { .. })
    ));

    assert!(matches!(
        state.apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(8, 0, 0, 800),
            LedgerEvent::StatusManifestAnchored(StatusManifestAnchoredEvent {
                issuer_id: iss_id,
                manifest_version: 2,
                manifest_hash: [0x00; 32], // Zero hash
                uri_hint: "".into(),
            }),
        )),
        Err(LedgerError::InvalidManifestHash(_))
    ));
}

#[test]
// Verifies: REQ-TRUST-008, REQ-LEDG-002, INV-01
fn test_deterministic_trust_bundle_derivation_byte_for_byte() {
    let mut state = LedgerState::new(1, "0x1111111111111111111111111111111111111111".into());

    let (uncomp_key1, _, kid1) = sample_keys(101);
    let (uncomp_key2, _, kid2) = sample_keys(102);

    let iss1 = [0x10; 32];
    let iss2 = [0x20; 32];

    state
        .apply_events(&[
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 0, 1_000),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id: iss1,
                    uri: "https://issuer-alpha.example.com".into(),
                    profiles: vec!["pip-personal-v1".into()],
                    vcts: vec!["https://vct.example.com/id".into()],
                    valid_from: 1_000,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 1, 1_000),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id: iss1,
                    kid: kid1,
                    public_key: uncomp_key1,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(11, 0, 0, 1_100),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id: iss2,
                    uri: "https://issuer-beta.example.com".into(),
                    profiles: vec!["pip-financial-v1".into(), "pip-personal-v1".into()],
                    vcts: vec!["https://vct.example.com/kyc".into()],
                    valid_from: 1_100,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(11, 0, 1, 1_100),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id: iss2,
                    kid: kid2,
                    public_key: uncomp_key2,
                }),
            ),
        ])
        .unwrap();

    let block_header = BlockHeader::new(100, [0xaa; 32], [0x99; 32], 2_000);
    let policy = PolicyEntry {
        profile_id: "pip-personal-v1".into(),
        version: "1.0.0".into(),
        policy_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
    };

    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        100,
        block_header.clone(),
        7 * 86_400,
        vec![policy],
    );

    // Derivación 1
    let derived1 = derive_trust_bundle(&state, &params).expect("derivation 1 succeeds");
    // Derivación 2 (independiente)
    let derived2 = derive_trust_bundle(&state, &params).expect("derivation 2 succeeds");

    // REQ-TRUST-008: Garantía de bytes 100% idénticos entre ejecuciones
    assert_eq!(derived1.canonical_json_bytes, derived2.canonical_json_bytes);
    assert_eq!(derived1.sha256_digest, derived2.sha256_digest);
    assert_eq!(derived1.bundle.bundle_version(), 100);
    assert_eq!(derived1.bundle.framework_id(), "pip-global-mainnet");
    assert_eq!(derived1.bundle.issuers().len(), 2);
}

#[test]
// Verifies: REQ-TRUST-008, REQ-TRUST-004, REQ-LEDG-002
fn test_compare_bundle_with_state_reconciliation_and_critical_compromise() {
    let mut state = LedgerState::new(1, "0x1111111111111111111111111111111111111111".into());
    let (key_bytes, _, kid) = sample_keys(200);
    let issuer_id = [0x50; 32];

    state
        .apply_events(&[
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 0, 1_000),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id,
                    uri: "https://issuer-sec.example.com".into(),
                    profiles: vec!["pip-personal-v1".into()],
                    vcts: vec![],
                    valid_from: 1_000,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 1, 1_000),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id,
                    kid,
                    public_key: key_bytes,
                }),
            ),
        ])
        .unwrap();

    let block_header = BlockHeader::new(10, [0xaa; 32], [0x00; 32], 1_500);
    let params =
        BundleDerivationParams::new("pip-global-mainnet", 1, 1, block_header, 86_400, vec![]);

    // 1. Bundle derivado consistente con el estado
    let derived = derive_trust_bundle(&state, &params).unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state, 1_500);
    assert!(diff.is_consistent());
    assert!(!diff.has_critical_security_divergence());

    // 2. Ocurre un compromiso de clave en el ledger en el bloque 11
    state
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(11, 0, 0, 2_000),
            LedgerEvent::KeyCompromised(KeyCompromisedEvent {
                issuer_id,
                kid,
                state_since: 2_000,
            }),
        ))
        .unwrap();

    // 3. El bundle anterior ahora discrepa críticamente respecto al estado actual
    let stale_diff = compare_bundle_with_state(&derived.bundle, &state, 2_500);
    assert!(!stale_diff.is_consistent());
    assert!(stale_diff.has_critical_security_divergence());
    assert!(stale_diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::CompromisedKeyNotReflected { .. })));
}

#[test]
// Verifies: REQ-LEDG-002, REQ-TRUST-008
fn test_ledger_errors_display_and_conversion() {
    use gravital_id_types::GidError;

    let errors = vec![
        LedgerError::NonMonotonicEventCoordinate {
            last: EventCoordinate::new(10, 0, 0, 100),
            received: EventCoordinate::new(9, 0, 0, 90),
        },
        LedgerError::IssuerAlreadyExists([0x01; 32]),
        LedgerError::IssuerNotFound([0x02; 32]),
        LedgerError::IssuerNotActive([0x03; 32]),
        LedgerError::KeyAlreadyExists {
            issuer_id: [0x01; 32],
            kid: [0x02; 32],
        },
        LedgerError::KeyNotFound {
            issuer_id: [0x01; 32],
            kid: [0x02; 32],
        },
        LedgerError::KeyAlreadyCompromised {
            issuer_id: [0x01; 32],
            kid: [0x02; 32],
        },
        LedgerError::InvalidKeyTransition {
            from: "active",
            to: "retired",
            reason: "invalid transition",
        },
        LedgerError::InvalidPublicKey("bad key".into()),
        LedgerError::InvalidTimestamps {
            valid_from: 100,
            valid_until: 50,
        },
        LedgerError::EmergencyRenewalForbidden {
            target_id: [0x05; 32],
        },
        LedgerError::NonMonotonicRootVersion {
            current: 2,
            proposed: 1,
        },
        LedgerError::NonMonotonicManifestVersion {
            issuer_id: [0x06; 32],
            current: 5,
            proposed: 4,
        },
        LedgerError::InvalidManifestHash([0x00; 32]),
        LedgerError::VerifierAlreadyExists([0x07; 32]),
        LedgerError::VerifierNotFound([0x08; 32]),
        LedgerError::Serialization("json err".into()),
        LedgerError::BundleError("bundle err".into()),
        LedgerError::Adapter("rpc failure".into()),
    ];

    for err in errors {
        let msg = format!("{err}");
        assert!(!msg.is_empty());
        let gid_err: GidError = err.into();
        assert!(!gid_err.message.is_empty());
    }
}

#[test]
// Verifies: REQ-TRUST-008, REQ-LEDG-002
fn test_diff_all_divergence_variants_and_report_helpers() {
    let mut state = LedgerState::new(1, "0x1111111111111111111111111111111111111111".into());
    let (key_bytes, _, kid) = sample_keys(300);
    let issuer_id = [0x50; 32];

    state
        .apply_events(&[
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 0, 1_000),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id,
                    uri: "https://issuer-sec.example.com".into(),
                    profiles: vec!["pip-personal-v1".into()],
                    vcts: vec![],
                    valid_from: 1_000,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(10, 0, 1, 1_000),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id,
                    kid,
                    public_key: key_bytes,
                }),
            ),
        ])
        .unwrap();

    let block_header = BlockHeader::new(10, [0xaa; 32], [0x00; 32], 1_500);
    let params =
        BundleDerivationParams::new("pip-global-mainnet", 1, 1, block_header, 86_400, vec![]);
    let derived = derive_trust_bundle(&state, &params).unwrap();

    // 1. ChainIdMismatch
    let state_diff_chain = LedgerState::new(2, "0x1111111111111111111111111111111111111111".into());
    let diff = compare_bundle_with_state(&derived.bundle, &state_diff_chain, 1_500);
    assert!(diff.has_critical_security_divergence());
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::ChainIdMismatch { .. })));

    // 2. RegistryAddressMismatch
    let state_diff_reg = LedgerState::new(1, "0x2222222222222222222222222222222222222222".into());
    let diff = compare_bundle_with_state(&derived.bundle, &state_diff_reg, 1_500);
    assert!(diff.has_critical_security_divergence());
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::RegistryAddressMismatch { .. })));

    // 3. FinalizedBlockAheadOfLedger
    let mut state_behind = LedgerState::new(1, "0x1111111111111111111111111111111111111111".into());
    state_behind
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(5, 0, 0, 500),
            LedgerEvent::TrustRootUpdated(TrustRootUpdatedEvent {
                root_hash: [0x99; 32],
                root_version: 1,
                updated_at: 500,
            }),
        ))
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_behind, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::FinalizedBlockAheadOfLedger { .. })));

    // 4. IssuerMissingInLedger
    let state_empty = LedgerState::new(1, "0x1111111111111111111111111111111111111111".into());
    let diff = compare_bundle_with_state(&derived.bundle, &state_empty, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::IssuerMissingInLedger(_))));

    // 5. ActiveIssuerMissingInBundle
    let mut state_extra_iss = state.clone();
    let (key_bytes2, _, kid2) = sample_keys(301);
    let extra_iss_id = [0x60; 32];
    state_extra_iss
        .apply_events(&[
            SequencedLedgerEvent::new(
                EventCoordinate::new(11, 0, 0, 1_200),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id: extra_iss_id,
                    uri: "https://extra-iss.example.com".into(),
                    profiles: vec![],
                    vcts: vec![],
                    valid_from: 1_200,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(11, 0, 1, 1_200),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id: extra_iss_id,
                    kid: kid2,
                    public_key: key_bytes2,
                }),
            ),
        ])
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_extra_iss, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::ActiveIssuerMissingInBundle(_))));

    // 6. ActiveKeyMissingInBundle
    let mut state_extra_key = state.clone();
    let (key_bytes3, _, kid3) = sample_keys(302);
    state_extra_key
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(11, 0, 0, 1_200),
            LedgerEvent::KeyAdded(KeyAddedEvent {
                issuer_id,
                kid: kid3,
                public_key: key_bytes3,
            }),
        ))
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_extra_key, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::ActiveKeyMissingInBundle { .. })));

    // 7. IssuerStateMismatch & KeyStateMismatch
    let mut state_suspended = state.clone();
    state_suspended
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(11, 0, 0, 1_200),
            LedgerEvent::IssuerSuspended(IssuerSuspendedEvent {
                issuer_id,
                expires_at: 2_000,
                initiated_by: [0xee; 20],
            }),
        ))
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_suspended, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::IssuerStateMismatch { .. })));

    let mut state_key_retired = state.clone();
    state_key_retired
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(11, 0, 0, 1_200),
            LedgerEvent::KeyRetired(KeyRetiredEvent {
                issuer_id,
                kid,
                state_since: 1_200,
            }),
        ))
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_key_retired, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::KeyStateMismatch { .. })));

    // 8. KeyMissingInLedger
    let mut state_without_key = state.clone();
    state_without_key
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(11, 0, 0, 1_200),
            LedgerEvent::IssuerDeregistered(IssuerDeregisteredEvent { issuer_id }),
        ))
        .unwrap();
    state_without_key
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(12, 0, 0, 1_300),
            LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                issuer_id,
                uri: "https://issuer-sec.example.com".into(),
                profiles: vec![],
                vcts: vec![],
                valid_from: 1_300,
                valid_until: 10_000,
            }),
        ))
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_without_key, 1_500);
    assert!(diff
        .divergences
        .iter()
        .any(|d| matches!(d, BundleStateDivergence::KeyMissingInLedger { .. })));
}

#[test]
// Verifies: REQ-LEDG-002, REQ-TRUST-008
fn test_in_memory_adapter_set_head() {
    let initial_head = BlockHeader::new(100, [0x11; 32], [0x00; 32], 1_700_000_000);
    let mut adapter = InMemoryLedgerAdapter::new(1, initial_head);
    let new_head = BlockHeader::new(105, [0x22; 32], [0x11; 32], 1_700_000_060);
    adapter.set_head(new_head.clone());
    assert_eq!(adapter.finalized_head().unwrap(), new_head);
}

#[test]
// Verifies: REQ-TRUST-008
fn test_derivation_omits_issuer_without_active_keys_and_includes_verifiers_with_jwk() {
    let mut state = LedgerState::new(1, "0x1111111111111111111111111111111111111111".into());
    let (key_bytes, _, _kid) = sample_keys(400);
    let iss_with_keys = [0x70; 32];
    let iss_without_keys = [0x71; 32];
    let verifier_id = [0x80; 32];

    state
        .apply_events(&[
            SequencedLedgerEvent::new(
                EventCoordinate::new(1, 0, 0, 1_000),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id: iss_with_keys,
                    uri: "https://iss-with-keys.example.com".into(),
                    profiles: vec!["pip-personal-v1".into()],
                    vcts: vec![],
                    valid_from: 1_000,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(1, 0, 1, 1_000),
                LedgerEvent::KeyAdded(KeyAddedEvent {
                    issuer_id: iss_with_keys,
                    kid: [0x01; 32],
                    public_key: key_bytes.clone(),
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(1, 0, 2, 1_000),
                LedgerEvent::IssuerRegistered(IssuerRegisteredEvent {
                    issuer_id: iss_without_keys,
                    uri: "https://iss-without-keys.example.com".into(),
                    profiles: vec![],
                    vcts: vec![],
                    valid_from: 1_000,
                    valid_until: 10_000,
                }),
            ),
            SequencedLedgerEvent::new(
                EventCoordinate::new(1, 0, 3, 1_000),
                LedgerEvent::VerifierRegistered(VerifierRegisteredEvent {
                    verifier_id,
                    uri: "https://verifier-public.example.com".into(),
                    public_key: key_bytes,
                    profiles: vec!["pip-financial-v1".into()],
                    valid_from: 1_000,
                    valid_until: 10_000,
                }),
            ),
        ])
        .unwrap();

    let block_header = BlockHeader::new(1, [0xaa; 32], [0x00; 32], 1_500);
    let params = BundleDerivationParams::new(
        "pip-global-mainnet",
        1,
        1,
        block_header,
        86_400,
        vec![PolicyEntry {
            profile_id: "pip-financial-v1".into(),
            version: "v1".into(),
            policy_hash: "0x1234567890abcdef".into(),
        }],
    );

    let derived = derive_trust_bundle(&state, &params).unwrap();
    // iss_without_keys debe omitirse porque no tiene claves vigentes
    assert_eq!(derived.bundle.issuers().len(), 1);
    assert_eq!(
        derived.bundle.issuers()[0].issuer_id,
        "https://iss-with-keys.example.com"
    );
    // verifier debe incluirse con clave pública
    assert_eq!(derived.bundle.verifiers().len(), 1);
    assert_eq!(
        derived.bundle.verifiers()[0].verifier_id,
        "https://verifier-public.example.com"
    );
    assert!(derived.bundle.verifiers()[0].public_key.is_some());
    assert_eq!(derived.bundle.policies().len(), 1);

    // Comparar bundle con verificador
    let diff = compare_bundle_with_state(&derived.bundle, &state, 1_500);
    assert!(diff.is_consistent());

    // Si damos de baja al verificador, debe saltar VerifierMissingOrInactiveInLedger
    let mut state_dereg_ver = state.clone();
    state_dereg_ver
        .apply_event(&SequencedLedgerEvent::new(
            EventCoordinate::new(2, 0, 0, 1_600),
            LedgerEvent::VerifierDeregistered(VerifierDeregisteredEvent { verifier_id }),
        ))
        .unwrap();
    let diff = compare_bundle_with_state(&derived.bundle, &state_dereg_ver, 1_700);
    assert!(diff.divergences.iter().any(|d| matches!(
        d,
        BundleStateDivergence::VerifierMissingOrInactiveInLedger(_)
    )));
}
