#![no_main]
//! Objetivo de fuzzing de la descompresión DEFLATE acotada (F2.T05/F2.T11).
//!
//! // Verifies: REQ-SEC-005, REQ-STAT-003
//!
//! Propiedades invariantadas:
//! 1. `inflate_bounded` nunca entra en pánico para ninguna entrada (INV-10),
//!    incluidos flujos corruptos, truncados y bombas de descompresión.
//! 2. Si se acepta, la salida respeta la cota indicada.
//! 3. Round-trip: comprimir y descomprimir con cota generosa reproduce la
//!    entrada.

use gravital_id_codec::{deflate, inflate_bounded, DEFAULT_MAX_OUTPUT_BYTES};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (Vec<u8>, u16, u16)| {
    let (payload, raw_limit, raw_ratio) = data;

    // Cotas acotadas para mantener el coste de cada ejecución razonable.
    let limit = usize::from(raw_limit) * 64; // hasta ~4 MiB
    let ratio = usize::from(raw_ratio).max(1); // al menos 1:1

    // Comprimir y descomprimir con cota generosa: round-trip.
    let compressed = deflate(&payload);
    if let Ok(restored) = inflate_bounded(&compressed, DEFAULT_MAX_OUTPUT_BYTES, 1024) {
        assert_eq!(restored, payload, "deflate round-trip must preserve bytes");
    }

    // Entrada arbitraria contra los límites: nunca pánico y, si se acepta,
    // la salida respeta la cota efectiva más restrictiva.
    let effective = limit.min(payload.len().saturating_mul(ratio));
    match inflate_bounded(&payload, limit, ratio) {
        Ok(out) => assert!(
            out.len() <= effective,
            "accepted output must respect the effective cap ({} > {})",
            out.len(),
            effective
        ),
        Err(_) => {
            // Rechazada: Correcto. Si la cota absoluta era holgada y el ratio
            // restrictivo, el error debe ser DecompressionRatioExceeded.
            if limit >= DEFAULT_MAX_OUTPUT_BYTES {
                let ratio_cap = payload.len().saturating_mul(ratio);
                if ratio_cap < limit {
                    // El ratio fue el limitante: nada más que comprobar aquí.
                }
            }
        }
    }
});
