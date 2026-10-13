#![no_main]
//! Objetivo de fuzzing de Base45 (F2.T05/F2.T11).
//!
//! Propiedades invariantadas:
//! 1. `decode` nunca entra en pánico para ninguna entrada (INV-10).
//! 2. Round-trip: `decode(encode(bytes)) == bytes` para bytes arbitrarios.
//! 3. Validación estricta RFC 9285 §6: solo se aceptan caracteres del alfabeto,
//!    longitudes válidas y tríos ≤ 65535.

use gravital_id_codec::{decode_base45, encode_base45};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (Vec<u8>, String)| {
    let (bytes, text) = data;

    // 1 y round-trip: la codificación es total y la decodificación es su inversa.
    let encoded = encode_base45(&bytes);
    let decoded = decode_base45(&encoded)
        .expect("anything encoded by us must decode back");
    assert_eq!(decoded, bytes, "base45 round-trip must preserve bytes");

    // La salida solo contiene caracteres del alfabeto.
    assert!(
        encoded
            .chars()
            .all(|c| c.is_ascii_digit()
                || c.is_ascii_uppercase()
                || matches!(c, ' ' | '$' | '%' | '*' | '+' | '-' | '.' | '/' | ':')),
        "base45 output left the RFC 9285 alphabet"
    );

    // 2: cualquier texto arbitrario se procesa sin pánico; si se acepta, la
    //    recodificación debe reproduirlo exactamente (canonicalidad).
    if let Ok(values) = decode_base45(&text) {
        assert_eq!(
            encode_base45(&values),
            text,
            "accepted base45 input must be canonical"
        );
    }
});
