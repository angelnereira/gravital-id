#![no_main]
#![allow(clippy::disallowed_types)]
//! Objetivo de fuzzing para el parser de SD-JWT compacto y la capa SD-JWT VC (F3.T03, F3.T05).
//!
//! // Verifies: REQ-SEC-005, REQ-CRED-001, REQ-CRED-008, REQ-CRED-009, REQ-VER-003, REQ-VER-008
//!
//! Invariantes bajo fuzzing:
//! 1. `ParsedSdJwt::parse`, `parse_with_limits` y `verify_vc` nunca entran en pánico para
//!    ninguna entrada (INV-10).
//! 2. Determinismo: la misma entrada produce el mismo resultado (REQ-VER-009).
//! 3. Fail-closed: ante cualquier malformación o ambigüedad, el resultado es `Err`
//!    (REQ-VER-003); `alg: none` y algoritmos fuera del perfil nunca se aceptan
//!    (REQ-CRED-008, INV-08).

use core::str;

use gravital_id_credential::{ParsedSdJwt, SdJwtLimits, VcValidityPolicy};
use gravital_id_types::UnixTime;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(compact_str) = str::from_utf8(data) else {
        return;
    };

    let limits = SdJwtLimits::default();

    // 1 y 2: nunca pánico, siempre determinista
    let first = ParsedSdJwt::parse_with_limits(compact_str, &limits);
    let second = ParsedSdJwt::parse_with_limits(compact_str, &limits);

    match (&first, &second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.raw_issuer_jwt(), b.raw_issuer_jwt());
            assert_eq!(a.reconstructed_claims(), b.reconstructed_claims());
            assert_eq!(a.disclosures().len(), b.disclosures().len());
            assert_eq!(a.kb_jwt(), b.kb_jwt());
        }
        (Err(e1), Err(e2)) => {
            assert_eq!(e1.code, e2.code);
        }
        _ => panic!("ParsedSdJwt::parse must be deterministic"),
    }

    // Capa SD-JWT VC: la verificación nunca acepta una entrada malformada y es determinista.
    if let Ok(parsed) = &first {
        let policy = VcValidityPolicy::default();
        let now = UnixTime::from_seconds(1_700_000_000);
        let vc_first = parsed.verify_vc(now, &policy);
        let vc_second = parsed.verify_vc(now, &policy);

        match (&vc_first, &vc_second) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(e1), Err(e2)) => assert_eq!(e1.code, e2.code),
            _ => panic!("ParsedSdJwt::verify_vc must be deterministic"),
        }
    }
});
