//! Pruebas unitarias y de integración para el almacenamiento de `pip-relay`.
//!
//! Verifies: REQ-SYNC-004, REQ-SYNC-006, REQ-CODE-001, REQ-CODE-002, REQ-CODE-003, REQ-CODE-004

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gravital_id_crypto::sha256;
use gravital_id_types::Clock;
use pip_relay::config::RelayConfig;
use pip_relay::error::RelayError;
use pip_relay::store::{
    compute_damm_check_digit, compute_session_hash_hex, hex_encode, validate_session_code,
    InMemoryRelayStore,
};

#[derive(Debug, Clone)]
struct TestSyncClock {
    now: Arc<AtomicU64>,
}

impl TestSyncClock {
    fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for TestSyncClock {
    fn now_seconds(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }

    fn monotonic_elapsed_millis(&self) -> Option<u64> {
        None
    }
}

fn default_test_config() -> RelayConfig {
    let mut config = RelayConfig::default();
    config.max_payload_bytes = 1024;
    config.default_object_ttl_secs = 3600;
    config.max_object_ttl_secs = 86400;
    config.default_envelope_ttl_secs = 600;
    config.max_envelope_ttl_secs = 3600;
    config.session_code_ttl_secs = 180;
    config.max_objects_capacity = 5;
    config.max_envelopes_per_mailbox = 3;
    config.max_rendezvous_capacity = 5;
    config.rate_limit_requests_per_minute = 60;
    config.rate_limit_burst = 10;
    config
}

// =============================================================================
// DAMM ALGORITHM & SESSION CODE TESTS (REQ-CODE-001..004, ADR-0025, PROTOCOL.md §7.7)
// =============================================================================

#[test]
fn test_damm_check_digit_computation_and_validation() {
    // Código de 9 dígitos base: "123456789"
    let check_digit = compute_damm_check_digit("123456789").expect("valid 9 digits");
    let full_10_digits = format!("123456789{check_digit}");
    let validated = validate_session_code(&full_10_digits).expect("valid code");
    assert_eq!(validated, full_10_digits);

    // Formato con separadores (espacios o guiones)
    let formatted = format!("123 456 789{check_digit}");
    let validated_fmt = validate_session_code(&formatted).expect("valid formatted code");
    assert_eq!(validated_fmt, full_10_digits);

    let formatted_dashes = format!("123-456-789-{check_digit}");
    let validated_dashes = validate_session_code(&formatted_dashes).expect("valid dashed code");
    assert_eq!(validated_dashes, full_10_digits);
}

#[test]
fn test_damm_detects_all_single_digit_errors() {
    let base_9 = "572391480";
    let check = compute_damm_check_digit(base_9).expect("check digit");
    let valid_code = format!("{base_9}{check}");
    assert!(validate_session_code(&valid_code).is_ok());

    let bytes = valid_code.as_bytes();
    for i in 0..10 {
        let original_digit = bytes[i];
        for mutated_char in b'0'..=b'9' {
            if mutated_char != original_digit {
                let mut mutated_bytes = bytes.to_vec();
                mutated_bytes[i] = mutated_char;
                let mutated_str = std::str::from_utf8(&mutated_bytes).unwrap();
                let res = validate_session_code(mutated_str);
                assert!(
                    res.is_err(),
                    "Damm must detect single digit error at pos {i}: mutated {mutated_str}"
                );
            }
        }
    }
}

#[test]
fn test_damm_detects_adjacent_transpositions() {
    let base_9 = "481516234";
    let check = compute_damm_check_digit(base_9).expect("check digit");
    let valid_code = format!("{base_9}{check}");
    let chars: Vec<char> = valid_code.chars().collect();

    for i in 0..9 {
        if chars[i] != chars[i + 1] {
            let mut transposed = chars.clone();
            transposed.swap(i, i + 1);
            let transposed_str: String = transposed.into_iter().collect();
            let res = validate_session_code(&transposed_str);
            assert!(
                res.is_err(),
                "Damm must detect transposition between pos {i} and {}: {transposed_str}",
                i + 1
            );
        }
    }
}

#[test]
fn test_validate_session_code_invalid_lengths_and_chars() {
    // Menos de 10 dígitos
    assert!(matches!(
        validate_session_code("12345678"),
        Err(RelayError::InvalidSessionCode(_))
    ));
    // Más de 10 dígitos
    assert!(matches!(
        validate_session_code("12345678901"),
        Err(RelayError::InvalidSessionCode(_))
    ));
    // Caracteres alfabéticos
    assert!(matches!(
        validate_session_code("123456789a"),
        Err(RelayError::InvalidSessionCode(_))
    ));
    // 9 dígitos con caracteres no numéricos
    assert!(matches!(
        compute_damm_check_digit("12345678x"),
        Err(RelayError::InvalidSessionCode(_))
    ));
    // Longitud incorrecta en compute_damm_check_digit
    assert!(matches!(
        compute_damm_check_digit("12345678"),
        Err(RelayError::InvalidSessionCode(_))
    ));
}

#[test]
fn test_session_hash_hex_computation() {
    let code = "1234567890";
    let hash = compute_session_hash_hex(code);
    assert_eq!(hash.len(), 64);
    // Verificar que sea determinista
    assert_eq!(hash, compute_session_hash_hex(code));
    // Preimagen esperada: "gid-session-code-v1" + "1234567890"
    let mut expected_preimage = b"gid-session-code-v1".to_vec();
    expected_preimage.extend_from_slice(code.as_bytes());
    let expected_hash = hex_encode(&sha256(&expected_preimage));
    assert_eq!(hash, expected_hash);
}

// =============================================================================
// CONTENT-ADDRESSED OBJECTS TESTS (REQ-SYNC-004)
// =============================================================================

#[test]
fn test_objects_put_and_get_roundtrip() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock);

    let data = b"payload test content".to_vec();
    let expected_digest = hex_encode(&sha256(&data));

    // Put object
    let computed_digest = store
        .put_object(data.clone(), Some(&expected_digest), Some(300))
        .expect("put object success");
    assert_eq!(computed_digest, expected_digest);

    // Get object
    let fetched = store
        .get_object(&expected_digest)
        .expect("get object success");
    assert_eq!(fetched, data);
    assert_eq!(store.object_count(), 1);
}

#[test]
fn test_objects_sha256_mismatch_rejected() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock);

    let data = b"some data".to_vec();
    let fake_digest = "00".repeat(32);

    let err = store
        .put_object(data, Some(&fake_digest), None)
        .unwrap_err();
    assert!(matches!(err, RelayError::ObjectHashMismatch { .. }));
}

#[test]
fn test_objects_payload_too_large_rejected() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock);

    // Config max_payload_bytes is 1024
    let oversized = vec![0x42u8; 1025];
    let err = store.put_object(oversized, None, None).unwrap_err();
    assert!(matches!(
        err,
        RelayError::PayloadTooLarge {
            max: 1024,
            actual: 1025
        }
    ));
}

#[test]
fn test_objects_expiration_and_cleanup() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock.clone());

    let data = b"expiring object".to_vec();
    let digest = store.put_object(data, None, Some(60)).expect("put ok");
    assert_eq!(store.object_count(), 1);

    // Advance clock past expiration
    clock.set(1061);
    // get_object returns not found because it has expired
    assert!(matches!(
        store.get_object(&digest),
        Err(RelayError::ObjectNotFound(_))
    ));

    // Cleanup expired entries
    store.cleanup_expired();
    assert_eq!(store.object_count(), 0);
}

#[test]
fn test_objects_capacity_eviction() {
    let clock = TestSyncClock::new(1000);
    let mut config = default_test_config();
    config.max_objects_capacity = 3;
    let store = InMemoryRelayStore::new(config, clock.clone());

    for i in 0..3 {
        let data = format!("object {i}").into_bytes();
        // El objeto 0 expira en 50s, los demás en 200s
        let ttl = if i == 0 { 50 } else { 200 };
        store.put_object(data, None, Some(ttl)).expect("put ok");
    }
    assert_eq!(store.object_count(), 3);

    // Intentar insertar un 4º objeto mientras los 3 siguen vigentes es rechazado con CapacityExceeded
    let data_fail = b"object fail".to_vec();
    let err = store.put_object(data_fail, None, Some(200)).unwrap_err();
    assert!(matches!(err, RelayError::CapacityExceeded(_)));

    // Avanzamos el reloj para que expire el objeto 0
    clock.set(1051);

    // Ahora insertar un nuevo objeto purga el expirado y se acepta
    let data4 = b"object 4".to_vec();
    store.put_object(data4, None, Some(200)).expect("put ok");
    assert_eq!(store.object_count(), 3);
}

// =============================================================================
// HPKE MAILBOXES ENVELOPES TESTS (REQ-SYNC-006)
// =============================================================================

#[test]
fn test_mailbox_post_and_get_with_idempotency() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock);

    let inbox_id = "inbox-alice";
    let envelope_id = "env-001";
    let payload = b"hpke-encrypted-envelope-bytes".to_vec();

    // Primer post: nuevo
    let is_new = store
        .post_envelope(inbox_id, envelope_id, payload.clone(), Some(300))
        .expect("post ok");
    assert!(is_new, "First post must return true");

    // Segundo post idéntico: idempotencia -> retorna false sin error
    let is_new_dup = store
        .post_envelope(inbox_id, envelope_id, payload.clone(), Some(300))
        .expect("post ok");
    assert!(!is_new_dup, "Duplicate post must return false");

    // Get envelopes
    let envelopes = store.get_envelopes(inbox_id, None).expect("get ok");
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].envelope_id, envelope_id);
    assert_eq!(envelopes[0].payload, payload);

    // Filtrado por `since`
    let envelopes_future = store
        .get_envelopes(
            inbox_id,
            Some(gravital_id_types::UnixTime::from_seconds(1000)),
        )
        .expect("get ok");
    assert_eq!(envelopes_future.len(), 1);

    let envelopes_past = store
        .get_envelopes(
            inbox_id,
            Some(gravital_id_types::UnixTime::from_seconds(1001)),
        )
        .expect("get ok");
    assert_eq!(envelopes_past.len(), 0);

    // Delete envelope (ACK)
    let deleted = store
        .delete_envelope(inbox_id, envelope_id)
        .expect("delete ok");
    assert!(deleted);
    let envelopes_after_del = store.get_envelopes(inbox_id, None).expect("get ok");
    assert_eq!(envelopes_after_del.len(), 0);
}

#[test]
fn test_mailbox_expiration_and_capacity() {
    let clock = TestSyncClock::new(1000);
    let mut config = default_test_config();
    config.max_envelopes_per_mailbox = 2;
    let store = InMemoryRelayStore::new(config, clock.clone());

    let inbox_id = "inbox-bob";
    store
        .post_envelope(inbox_id, "env-1", b"data1".to_vec(), Some(60))
        .expect("post ok");
    store
        .post_envelope(inbox_id, "env-2", b"data2".to_vec(), Some(120))
        .expect("post ok");

    // Inserción de un 3º sobre cuando la capacidad está llena y no hay expirados es rechazada
    let err = store
        .post_envelope(inbox_id, "env-3", b"data3".to_vec(), Some(180))
        .unwrap_err();
    assert!(matches!(err, RelayError::CapacityExceeded(_)));

    // Avanzamos el reloj para que expire env-1
    clock.set(1061);

    // Ahora insertar env-3 purga env-1 y tiene éxito
    store
        .post_envelope(inbox_id, "env-3", b"data3".to_vec(), Some(180))
        .expect("post ok");
    let envs = store.get_envelopes(inbox_id, None).expect("get ok");
    assert_eq!(envs.len(), 2);
    assert!(envs.iter().any(|e| e.envelope_id == "env-3"));
    assert!(!envs.iter().any(|e| e.envelope_id == "env-1"));

    store.cleanup_expired();
}

// =============================================================================
// EPHEMERAL RENDEZVOUS WORKFLOW (REQ-CODE-001..004, PROTOCOL.md §7.7)
// =============================================================================

#[test]
fn test_rendezvous_request_response_single_use_atomic_consumption() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock);

    let code_9 = "987654321";
    let check = compute_damm_check_digit(code_9).expect("check");
    let session_code = format!("{code_9}{check}");
    let session_hash = compute_session_hash_hex(&session_code);

    let req_payload = b"proximity-verifier-request-jwt".to_vec();
    let resp_payload = b"proximity-holder-response-vp".to_vec();

    // 1. Verificador registra request con TTL de 120s
    store
        .register_session_request(&session_hash, req_payload.clone(), Some(120))
        .expect("put req ok");

    // 2. Prover / Holder obtiene el request
    let fetched_req = store
        .get_session_request(&session_hash)
        .expect("get req ok");
    assert_eq!(fetched_req, req_payload);

    // 3. Prover / Holder envía el response
    store
        .submit_session_response(&session_hash, resp_payload.clone())
        .expect("put resp ok");

    // 4. Verificador consume el response atómicamente (consumo de un solo uso)
    let fetched_resp = store
        .get_session_response(&session_hash)
        .expect("get resp ok");
    assert_eq!(fetched_resp, resp_payload);

    // 5. Intentos posteriores deben fallar con SessionAlreadyConsumed (INV-05, REQ-CODE-004)
    let second_get_resp = store.get_session_response(&session_hash);
    assert!(matches!(
        second_get_resp,
        Err(RelayError::SessionAlreadyConsumed)
    ));

    let second_submit_resp = store.submit_session_response(&session_hash, b"other".to_vec());
    assert!(matches!(
        second_submit_resp,
        Err(RelayError::SessionAlreadyConsumed)
    ));
}

#[test]
fn test_rendezvous_ttl_max_180s_and_expiration() {
    let clock = TestSyncClock::new(1000);
    let store = InMemoryRelayStore::new(default_test_config(), clock.clone());

    let session_hash = "11".repeat(32);
    // Solicitamos TTL de 300s, pero la configuración fija max_rendezvous_ttl_secs = 180s
    store
        .register_session_request(&session_hash, b"req".to_vec(), Some(300))
        .expect("put req ok");

    // A los 179s aún existe
    clock.set(1179);
    assert!(store.get_session_request(&session_hash).is_ok());

    // A los 181s ha caducado
    clock.set(1181);
    assert!(matches!(
        store.get_session_request(&session_hash),
        Err(RelayError::SessionExpired)
    ));

    store.cleanup_expired();
}

#[test]
fn test_store_edge_cases_and_error_paths() {
    let clock = TestSyncClock::new(1000);
    let mut config = default_test_config();
    config.max_mailboxes_capacity = 2;
    config.max_rendezvous_capacity = 2;
    let store = InMemoryRelayStore::new(config, clock.clone());

    // clock()
    assert_eq!(store.clock().now_seconds(), 1000);

    // Empty identifiers in mailbox
    assert!(matches!(
        store.post_envelope("", "env1", vec![1], None),
        Err(RelayError::InvalidIdentifier(_))
    ));
    assert!(matches!(
        store.post_envelope("inbox1", "", vec![1], None),
        Err(RelayError::InvalidIdentifier(_))
    ));

    // Envelope payload too large
    let big = vec![0u8; 2000];
    assert!(matches!(
        store.post_envelope("inbox1", "env1", big, None),
        Err(RelayError::PayloadTooLarge { .. })
    ));

    // Non-existent mailbox get & delete
    assert_eq!(store.get_envelopes("non_existent", None).unwrap().len(), 0);
    assert!(!store.delete_envelope("non_existent", "env1").unwrap());

    // Mailboxes capacity exceeded
    store
        .post_envelope("box1", "e1", vec![1], Some(100))
        .unwrap();
    store
        .post_envelope("box2", "e1", vec![1], Some(100))
        .unwrap();
    let err = store
        .post_envelope("box3", "e1", vec![1], Some(100))
        .unwrap_err();
    assert!(matches!(err, RelayError::CapacityExceeded(_)));

    // Rendezvous invalid session hash
    assert!(matches!(
        store.register_session_request("invalid_len", vec![1], None),
        Err(RelayError::InvalidIdentifier(_))
    ));
    assert!(matches!(
        store.register_session_request(&"zz".repeat(32), vec![1], None),
        Err(RelayError::InvalidIdentifier(_))
    ));

    // Rendezvous payload too large
    let session_hash = "ab".repeat(32);
    let big = vec![0u8; 2000];
    assert!(matches!(
        store.register_session_request(&session_hash, big.clone(), None),
        Err(RelayError::PayloadTooLarge { .. })
    ));

    // Register session ok
    store
        .register_session_request(&session_hash, vec![1, 2, 3], Some(60))
        .unwrap();

    // Submit response payload too large
    assert!(matches!(
        store.submit_session_response(&session_hash, big),
        Err(RelayError::PayloadTooLarge { .. })
    ));

    // Rendezvous capacity exceeded
    let session_hash2 = "cd".repeat(32);
    store
        .register_session_request(&session_hash2, vec![1], Some(60))
        .unwrap();
    let session_hash3 = "ef".repeat(32);
    let cap_err = store
        .register_session_request(&session_hash3, vec![1], Some(60))
        .unwrap_err();
    assert!(matches!(cap_err, RelayError::CapacityExceeded(_)));

    // Expiration checks on submit_session_response and get_session_response
    clock.set(1061);
    assert!(matches!(
        store.submit_session_response(&session_hash, vec![4, 5, 6]),
        Err(RelayError::SessionExpired)
    ));
    assert!(matches!(
        store.get_session_response(&session_hash),
        Err(RelayError::SessionExpired)
    ));
}
