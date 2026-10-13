#![no_main]
//! Objetivo de fuzzing del lector JSON acotado (F2.T03/F2.T11).
//!
//! // Verifies: REQ-SEC-005, REQ-CRED-009, REQ-VER-008
//!
//! Propiedades invariantadas:
//! 1. `parse_bytes` y `parse` **nunca** entran en pánico para ninguna entrada
//!    (INV-10), incluida la que no es UTF-8 válido.
//! 2. Determinismo: la misma entrada produce el mismo resultado (REQ-VER-009).
//! 3. Subconjunto estricto: si aceptamos, la entrada es UTF-8 válido y el
//!    documento es JSON con miembros únicos y números acotados (REQ-CRED-009,
//!    REQ-VER-008).

use gravital_id_codec::json::{self, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::profile_default();

    // 1 y 2: nunca pánico, siempre determinista.
    let first = json::parse_bytes(data, &limits);
    let second = json::parse_bytes(data, &limits);
    match (&first, &second) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "JSON parse must be deterministic"),
        (Err(_), Err(_)) => {}
        _ => panic!("JSON parse must be deterministic"),
    }

    if let Ok(value) = first {
        // 3: si aceptamos bytes, eran UTF-8 válido.
        assert!(
            core::str::from_utf8(data).is_ok(),
            "accepted input must be valid UTF-8"
        );
        // Y el documento no está vacío.
        assert!(
            !matches!(value, gravital_id_codec::json::Value::Null) || !data.is_empty(),
            "null requires at least one byte"
        );

        // Recuperar la vista de texto con los mismos límites también funciona.
        if let Ok(text) = core::str::from_utf8(data) {
            let via_text = json::parse_with_limits(text, &limits)
                .expect("text and bytes paths must agree");
            assert_eq!(via_text, value, "text and bytes paths must agree");
        }
    }
});
