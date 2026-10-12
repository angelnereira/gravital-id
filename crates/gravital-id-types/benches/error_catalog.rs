//! Benchmarks de ejemplo (F1.T11: criterion configurado).
//!
//! Miden el formateo del catálogo canónico de errores, la única superficie
//! medible de F1. Los benchmarks de firma, verificación, hash y AEAD se añaden
//! en F2.T12 (`ROADMAP.md §7`) y se publican en `docs/STATUS.md`.

// Andamiaje de benchmarks (F1.T11): `criterion_group!` genera funciones que el
// lint `missing_docs` del workspace exige documentar; excepción local
// documentada (PROJECT_STRUCTURE.md §5.1).
#![allow(missing_docs)]

use criterion::{criterion_group, criterion_main, Criterion};
use gravital_id_types::{ErrorCode, GidError};
use std::hint::black_box;

fn bench_error_rendering(c: &mut Criterion) {
    let err = GidError::new(
        ErrorCode::NonceReused,
        "Session nonce was reused in the verifier state store",
    )
    .with_details("nonce domain: presentation");

    c.bench_function("gid_error_display_with_details", |b| {
        b.iter(|| black_box(&err).to_string())
    });

    c.bench_function("error_code_code_str", |b| {
        b.iter(|| black_box(ErrorCode::ClockRollbackDetected).code_str())
    });

    c.bench_function("error_code_identifier_name", |b| {
        b.iter(|| black_box(ErrorCode::ClockRollbackDetected).identifier_name())
    });
}

criterion_group!(benches, bench_error_rendering);
criterion_main!(benches);
