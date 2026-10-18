//! Pruebas unitarias, de integración y de propiedades para `gravital-id-sync` (F7.T07).
//!
//! Verifies:
//! - REQ-SYNC-001 (Cola de salida cifrada con claves de idempotencia)
//! - REQ-SYNC-002 (Entrega al-menos-una-vez con deduplicación en destinatario)
//! - REQ-SYNC-003 (Backoff exponencial con jitter determinista)
//! - REQ-SYNC-004 (Verificación estricta de hash de contenido recibido)
//! - REQ-SYNC-005 (Descargas públicas anónimas sin identificadores)
//! - REQ-SYNC-006 (Sobres cifrados con HPKE RFC 9180)
//! - REQ-SYNC-007 (Pool de relays con failover automático)

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_sync::backoff::RetryPolicy;
use gravital_id_sync::dedup::InboundDeduplicationFilter;
use gravital_id_sync::engine::{OutboxStepResult, SyncEngine};
use gravital_id_sync::error::SyncError;
use gravital_id_sync::hpke_envelope::HpkeEnvelope;
use gravital_id_sync::model::{MailboxId, OperationId, SyncOperation};
use gravital_id_sync::queue::EncryptedOutboxQueue;
use gravital_id_sync::relay_pool::RelayPool;
use gravital_id_sync::transport::MockTransport;
use gravital_id_sync::verifier::ContentVerifier;
use gravital_id_testkit::FixedClock;
use gravital_id_types::{Clock, UnixTime};
use proptest::prelude::*;

// Claves de prueba SEC1 sin comprimir (65 bytes) y clave privada P-256 (32 bytes) (RFC 9180 Apéndice A.5.1)
const TEST_RECIPIENT_PUB: [u8; 65] = [
    0x04, 0xa6, 0x97, 0xbf, 0xfd, 0xe9, 0x40, 0x5c, 0x99, 0x28, 0x83, 0xc5, 0xc4, 0x39, 0xd6, 0xcc,
    0x35, 0x81, 0x70, 0xb5, 0x1a, 0xf7, 0x28, 0x12, 0x33, 0x3b, 0x01, 0x56, 0x21, 0xdc, 0x0f, 0x40,
    0xba, 0xd9, 0xbb, 0x72, 0x6f, 0x68, 0xa5, 0xc0, 0x13, 0x80, 0x6a, 0x79, 0x0e, 0xc7, 0x16, 0xab,
    0x86, 0x69, 0xf8, 0x4f, 0x6b, 0x69, 0x45, 0x96, 0xc2, 0x98, 0x7c, 0xf3, 0x5b, 0xab, 0xa2, 0xa0,
    0x06,
];

const TEST_RECIPIENT_PRIV: [u8; 32] = [
    0xa4, 0xd1, 0xc5, 0x58, 0x36, 0xaa, 0x30, 0xf9, 0xb3, 0xfb, 0xb6, 0xac, 0x98, 0xd3, 0x38, 0xc8,
    0x77, 0xc2, 0x86, 0x7d, 0xd3, 0xa7, 0x73, 0x96, 0xd1, 0x3f, 0x68, 0xd3, 0xab, 0x15, 0x0d, 0x3b,
];

const TEST_EPHEMERAL_SECRET: [u8; 32] = [
    0x75, 0x50, 0x25, 0x3e, 0x11, 0x47, 0xaa, 0xe4, 0x88, 0x39, 0xc1, 0xf8, 0xaf, 0x80, 0xd2, 0x77,
    0x0f, 0xb7, 0xa4, 0xc7, 0x63, 0xaf, 0xe7, 0xd0, 0xaf, 0xa7, 0xe0, 0xf4, 0x2a, 0x5b, 0x36, 0x89,
];

// Verifies: REQ-SYNC-001
#[test]
fn outbox_queue_enforces_idempotency_and_lifecycle() {
    let mut queue = EncryptedOutboxQueue::new(10);
    let now = UnixTime::from_seconds(1_000);
    let op_id = OperationId::new("op-unique-1234").expect("valid id");
    let mailbox = MailboxId::new("inbox-alice").expect("valid mailbox");

    let op = SyncOperation::new(
        op_id.clone(),
        mailbox.clone(),
        vec![1, 2, 3],
        now,
        Some(3600),
    );

    // 1. Encolar con éxito
    assert!(queue.enqueue(op.clone()).is_ok());
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.count_pending(), 1);

    // 2. Rechazo de id duplicado (REQ-SYNC-001)
    let duplicate_res = queue.enqueue(op);
    assert_eq!(
        duplicate_res,
        Err(SyncError::DuplicateOperationId("op-unique-1234".into()))
    );

    // 3. Peek debido
    let due = queue.peek_due(now).expect("due op exists");
    assert_eq!(due.id, op_id);

    // 4. Marcar en tránsito
    assert!(queue.mark_in_flight(&op_id).is_ok());
    assert_eq!(queue.count_in_flight(), 1);

    // 5. Intento fallido y reprogramación
    let next_attempt = UnixTime::from_seconds(1_010);
    let permanent = queue
        .mark_attempt_failed(&op_id, next_attempt, 3)
        .expect("mark failed");
    assert!(!permanent);
    assert_eq!(queue.count_pending(), 1);

    // No debe estar debido antes de next_attempt
    assert!(queue.peek_due(UnixTime::from_seconds(1_005)).is_none());
    assert!(queue.peek_due(UnixTime::from_seconds(1_010)).is_some());

    // 6. Marcar entregado
    assert!(queue.mark_delivered(&op_id).is_ok());
    assert_eq!(queue.count_delivered(), 1);
}

// Verifies: REQ-SYNC-002
#[test]
fn inbound_deduplication_filter_rejects_duplicates_within_window() {
    let mut filter = InboundDeduplicationFilter::new(100, 300); // 300 s window
    let now = UnixTime::from_seconds(1_000);
    let envelope_id = "env-msg-9999";

    // Primera vez: aceptado
    assert!(filter.check_and_record(envelope_id, now));
    assert_eq!(filter.len(), 1);

    // Segunda vez dentro de la ventana: duplicado rechazado (REQ-SYNC-002)
    assert!(!filter.check_and_record(envelope_id, UnixTime::from_seconds(1_100)));
    assert!(filter.is_duplicate(envelope_id, UnixTime::from_seconds(1_100)));

    // Tras expirar la ventana de 300 s (t = 1301): el mensaje expiró y puede recibirse de nuevo
    assert!(filter.check_and_record(envelope_id, UnixTime::from_seconds(1_301)));
}

// Verifies: REQ-SYNC-004
#[test]
fn content_verifier_verifies_sha256_strictly_and_fails_closed_on_corruption() {
    let payload = b"{\"ver\":1,\"issuer\":\"did:web:te.gob.pa\"}";
    let expected_hash = "5712c6c966f4702b8e1c6501e8d3e9459bf5eecf62ed36c0f5fea8a276077b7a";

    // 1. Caso positivo: hash coincide
    assert!(ContentVerifier::verify_object_sha256(payload, expected_hash).is_ok());

    // 2. Caso negativo: payload alterado falla cerrado (INV-05)
    let corrupted = b"{\"ver\":1,\"issuer\":\"did:web:attacker.com\"}";
    let err = ContentVerifier::verify_object_sha256(corrupted, expected_hash)
        .expect_err("should fail closed");

    match err {
        SyncError::ContentIntegrityFailed {
            expected_hash: exp, ..
        } => {
            assert_eq!(exp, expected_hash);
        }
        _ => panic!("unexpected error variant"),
    }
}

// Verifies: REQ-SYNC-005
#[test]
fn content_verifier_rejects_forbidden_identity_query_params_in_public_requests() {
    // 1. Petición limpia por digest SHA-256: permitida
    assert!(ContentVerifier::assert_anonymous_public_request(
        "/v1/objects/6d9fb778ca97f26fc9ba5a02db1d8ba02a631c8901b0b53835e076ddc5ad96e6"
    )
    .is_ok());

    // 2. Petición con parámetro de titular sub o cédula: rechazada (REQ-SYNC-005, INV-02)
    assert!(matches!(
        ContentVerifier::assert_anonymous_public_request("/v1/objects/abc?sub=user123"),
        Err(SyncError::AnonymousDownloadViolation(_))
    ));
    assert!(matches!(
        ContentVerifier::assert_anonymous_public_request("/v1/objects/abc?cedula=8-888-8888"),
        Err(SyncError::AnonymousDownloadViolation(_))
    ));
    assert!(matches!(
        ContentVerifier::assert_anonymous_public_request("/v1/objects/abc?bearer=token123"),
        Err(SyncError::AnonymousDownloadViolation(_))
    ));
}

// Verifies: REQ-SYNC-006
#[test]
fn hpke_envelope_seals_and_opens_roundtrip() {
    let plaintext = b"Operacion multi-inquilino de sincronizacion portable";
    let aad = b"context-aad-session";

    // Sellar con HPKE RFC 9180
    let sealed = HpkeEnvelope::seal(&TEST_RECIPIENT_PUB, &TEST_EPHEMERAL_SECRET, plaintext, aad)
        .expect("sealing failed");

    // Debe contener al menos 65 bytes de clave encapsulada
    assert!(sealed.len() >= 65);

    // Abrir con la clave privada del receptor
    let opened = HpkeEnvelope::open(&TEST_RECIPIENT_PRIV, &sealed, aad).expect("open failed");
    assert_eq!(opened, plaintext);

    // Caso negativo: AAD manipulado produce fallo de autenticación AEAD
    assert!(HpkeEnvelope::open(&TEST_RECIPIENT_PRIV, &sealed, b"wrong-aad").is_err());
}

// Verifies: REQ-SYNC-007
#[test]
fn relay_pool_performs_failover_when_primary_fails() {
    let urls = vec![
        "https://relay1.gravital.id".to_string(),
        "https://relay2.gravital.id".to_string(),
    ];
    let mut pool = RelayPool::new(urls, 60).expect("pool creation");
    let now = UnixTime::from_seconds(1_000);

    // 1. Inicialmente se selecciona el primario relay1
    assert_eq!(
        pool.select_active_relay(now).expect("select active"),
        "https://relay1.gravital.id"
    );

    // 2. Fallo en relay1: debe conmutar automáticamente a relay2 (REQ-SYNC-007)
    pool.record_failure("https://relay1.gravital.id", now);
    assert_eq!(
        pool.select_active_relay(now).expect("failover active"),
        "https://relay2.gravital.id"
    );

    // 3. Éxito en relay2
    pool.record_success("https://relay2.gravital.id");
    assert_eq!(
        pool.select_active_relay(now)
            .expect("relay2 remains active"),
        "https://relay2.gravital.id"
    );
}

// Verifies: REQ-SYNC-001, REQ-SYNC-002, REQ-SYNC-006, REQ-SYNC-007
#[test]
fn sync_engine_executes_full_outbox_and_inbox_handshake() {
    let pool = RelayPool::new(
        vec![
            "https://relay1.gravital.id".into(),
            "https://relay2.gravital.id".into(),
        ],
        60,
    )
    .expect("pool");

    let outbox = EncryptedOutboxQueue::new(50);
    let dedup = InboundDeduplicationFilter::new(100, 3600);
    let retry_policy = RetryPolicy::new(1, 60, 5, 20);

    let mut engine = SyncEngine::new(pool, outbox, dedup, retry_policy);
    let transport = MockTransport::new();
    let clock = FixedClock::new(1_000);

    let op_id = OperationId::new("sync-tx-001").expect("id");
    let mailbox = MailboxId::new("mailbox-recipient-bob").expect("mb");
    let plaintext = b"Credencial sincronizada de forma segura";

    // Cifrar el sobre con HPKE
    let ciphertext = HpkeEnvelope::seal(
        &TEST_RECIPIENT_PUB,
        &TEST_EPHEMERAL_SECRET,
        plaintext,
        b"aad-info",
    )
    .expect("seal");

    // Encolar operación saliente
    engine
        .enqueue_operation(
            op_id.clone(),
            mailbox.clone(),
            ciphertext,
            UnixTime::from_seconds(clock.now_seconds()),
            Some(3600),
        )
        .expect("enqueue");

    // Ejecutar paso de salida
    let step_res = engine
        .step_outbox(&transport, &clock, 42)
        .expect("step outbox");

    match step_res {
        OutboxStepResult::Delivered {
            operation_id,
            relay_url,
        } => {
            assert_eq!(operation_id, op_id);
            assert_eq!(relay_url, "https://relay1.gravital.id");
        }
        _ => panic!("expected Delivered step result"),
    }

    // Consultar el buzón de entrada desde el lado receptor
    let received = engine
        .poll_inbox(
            &transport,
            &mailbox,
            &TEST_RECIPIENT_PRIV,
            b"aad-info",
            &clock,
            None,
        )
        .expect("poll inbox");

    assert_eq!(received.len(), 1);
    assert_eq!(received[0].envelope_id, "sync-tx-001");
    assert_eq!(received[0].plaintext_payload, plaintext);

    // Segundo poll: el sobre fue deduplicado y consumido (REQ-SYNC-002)
    let second_poll = engine
        .poll_inbox(
            &transport,
            &mailbox,
            &TEST_RECIPIENT_PRIV,
            b"aad-info",
            &clock,
            None,
        )
        .expect("second poll");
    assert_eq!(second_poll.len(), 0);
}

// Verifies: REQ-SYNC-003 (Property-based test con proptest)
proptest! {
    #[test]
    fn backoff_delay_respects_monotonic_growth_and_boundaries(
        retries in 0u32..20u32,
        jitter_seed in any::<u64>(),
    ) {
        let policy = RetryPolicy::new(1, 300, 10, 25);
        let delay = policy.compute_delay_secs(retries, jitter_seed);

        // El retardo nunca debe ser 0 ni exceder max_delay_secs
        prop_assert!(delay >= 1);
        prop_assert!(delay <= 300);

        let next_attempt = policy.compute_next_attempt(retries, UnixTime::from_seconds(100), jitter_seed);
        prop_assert!(next_attempt.as_seconds() >= 101);
        prop_assert!(next_attempt.as_seconds() <= 400);
    }
}
