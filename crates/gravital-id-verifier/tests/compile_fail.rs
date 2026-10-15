//! Pruebas de compilación fallida con trybuild (REQ-VER-012, ADR-0020).
//!
//! Verifica que el sistema de tipos de Rust impida en tiempo de compilación construir
//! directamente un `VerificationResult` con estado `Valid` eludiendo el typestate del pipeline.

// Verifies: REQ-VER-012
#[test]
fn test_compile_fail_cannot_construct_valid_directly() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
