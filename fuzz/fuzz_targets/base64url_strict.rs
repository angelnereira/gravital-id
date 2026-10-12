#![no_main]
//! Objetivo de fuzzing del decoder base64url estricto (F2.T02/F2.T11).
//!
//! Propiedad invariantada: si `decode` acepta una entrada, esa entrada **es** la
//! codificación canónica de sus bytes (sin relleno y con bits sobrantes cero),
//! de modo que `encode(decode(s)) == s`. Además, `decode` nunca entra en pánico
//! para ninguna entrada (INV-10).

use gravital_id_codec::{decode, decode_bounded, encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(bytes) = decode(input) {
        // Canonicalidad: la entrada aceptada se recodifica sin cambios.
        let re_encoded = encode(&bytes);
        assert_eq!(re_encoded, input, "decoded input must be canonical");
        // Y la recodificación vuelve a decodificar a los mismos bytes.
        assert_eq!(decode(&re_encoded).expect("canonical re-encode decodes"), bytes);
    }

    // La variante acotada coincide con la acotación por defecto.
    if let Ok(bytes) = decode_bounded(input, usize::MAX) {
        assert_eq!(decode_bounded(input, bytes.len()).expect("exact bound accepts"), bytes);
    }
});
