//! Pruebas de compilación fallida con trybuild (REQ-KEY-001, REQ-KEY-009).
//!
//! Verifica que el sistema de tipos de Rust impida en tiempo de compilación utilizar
//! una clave para un propósito distinto al autorizado.

// Verifies: REQ-KEY-001, REQ-KEY-009
#[test]
fn test_compile_fail_cross_purpose() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
