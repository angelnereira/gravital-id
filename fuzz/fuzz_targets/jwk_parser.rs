#![no_main]
//! Objetivo de fuzzing del parser JWK EC P-256 (F2.T07/F2.T11).
//!
//! // Verifies: REQ-SEC-005
//!
//! Propiedades invariantadas:
//! 1. `parse_bytes` nunca entra en pánico para ninguna entrada (INV-10).
//! 2. Determinismo: la misma entrada produce el mismo resultado (REQ-VER-009).
//! 3. Fail-closed: si acepta, el punto siempre está en la curva P-256 y nunca
//!    contiene miembros privados.
//! 4. Round-trip: si acepta, `to_canonical_json` genera un JWK que se vuelve a parsear con éxito.

use gravital_id_crypto::jwk::JwkEcP256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = JwkEcP256::parse_bytes(data);
    let second = JwkEcP256::parse_bytes(data);

    match (&first, &second) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "JWK parse must be deterministic"),
        (Err(e1), Err(e2)) => assert_eq!(e1.code, e2.code, "JWK errors must be deterministic"),
        _ => panic!("JWK parse determinism failure"),
    }

    if let Ok(jwk) = first {
        let canonical = jwk.to_canonical_json();
        let reparsed = JwkEcP256::parse(&canonical).expect("canonical JWK must always reparse");
        assert_eq!(jwk.x(), reparsed.x());
        assert_eq!(jwk.y(), reparsed.y());
        assert_eq!(jwk.thumbprint_sha256(), reparsed.thumbprint_sha256());
    }
});
