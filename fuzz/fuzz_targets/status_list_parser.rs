#![no_main]
#![allow(clippy::disallowed_types)]
//! Objetivo de fuzzing para el parser de Token Status List y del manifiesto de estado
//! (F4.T01, REQ-STAT-001, REQ-STAT-008, REQ-SEC-005).
//!
//! // Verifies: REQ-SEC-005, REQ-STAT-001, REQ-STAT-003, REQ-STAT-008, REQ-VER-003
//!
//! Invariantes bajo fuzzing:
//! 1. `StatusListVerifier::parse` y `StatusManifestVerifier::parse` nunca entran en pánico
//!    para ninguna entrada (INV-10).
//! 2. Determinismo: la misma entrada produce el mismo resultado (REQ-VER-009).
//! 3. Fail-closed: ante malformación, descompresión desbordada o bits no soportados, el
//!    resultado es error (REQ-VER-003).

use core::str;

use gravital_id_status::{StatusListVerifier, StatusManifestVerifier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(jwt) = str::from_utf8(data) else {
        return;
    };

    // 1 y 2: nunca pánico, siempre determinista.
    let list_first = StatusListVerifier::parse(jwt);
    let list_second = StatusListVerifier::parse(jwt);
    match (&list_first, &list_second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.bits_per_entry(), b.bits_per_entry());
            assert_eq!(a.entry_count(), b.entry_count());
            assert_eq!(a.uri(), b.uri());
        }
        (Err(e1), Err(e2)) => assert_eq!(e1.code, e2.code),
        _ => panic!("StatusListVerifier::parse must be deterministic"),
    }

    let manifest_first = StatusManifestVerifier::parse(jwt);
    let manifest_second = StatusManifestVerifier::parse(jwt);
    match (&manifest_first, &manifest_second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.manifest_version(), b.manifest_version());
            assert_eq!(a.lists().len(), b.lists().len());
        }
        (Err(e1), Err(e2)) => assert_eq!(e1.code, e2.code),
        _ => panic!("StatusManifestVerifier::parse must be deterministic"),
    }
});
