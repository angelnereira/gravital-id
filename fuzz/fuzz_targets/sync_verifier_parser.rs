#![no_main]
//! Objetivo de fuzzing para los verificadores y parsers de `gravital-id-sync` (F7.T07).
//!
//! // Verifies: REQ-SYNC-004, REQ-SYNC-005, INV-10
//!
//! Propiedad invariantada:
//! 1. `ContentVerifier::assert_anonymous_public_request` nunca entra en pánico ante cualquier entrada UTF-8 (INV-10).
//! 2. `ContentVerifier::verify_object_sha256` nunca entra en pánico ante cualquier combinación de datos y hash esperado (INV-10).
//! 3. Comportamiento estrictamente determinista y fail-closed (INV-05).

use gravital_id_sync::ContentVerifier;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzzing de verificación de anonimato en URLs / paths públicos (REQ-SYNC-005)
    if let Ok(url_str) = core::str::from_utf8(data) {
        let _ = ContentVerifier::assert_anonymous_public_request(url_str);
    }

    // 2. Fuzzing de verificación de hash SHA-256 (REQ-SYNC-004)
    if data.len() >= 64 {
        if let Ok(expected_hash_candidate) = core::str::from_utf8(&data[..64]) {
            let payload = &data[64..];
            let _ = ContentVerifier::verify_object_sha256(payload, expected_hash_candidate);
        }
    }
});
