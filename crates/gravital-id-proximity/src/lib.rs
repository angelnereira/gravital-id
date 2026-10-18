//! # `gravital-id-proximity`
//!
//! Núcleo de proximidad: máquinas de estado sans-I/O, cifrado de sesión HPKE y
//! vinculación al transcrito, reutilizable sobre NFC y BLE (F20, `ROADMAP.md §27`).
//!
//! - **Capa arquitectónica:** L4 (sans-I/O; sin I/O de red ni de disco).
//! - **Garantía no_std:** No (usa `alloc`); compatible con WASM.
//!
//! ## Estado en F20.T01
//!
//! Andamiaje inicial: crate creado con lints estrictos y dependencias acotadas a
//! L1. Los mensajes CBOR, el cifrado de sesión, el transcrito y las máquinas de
//! estado se añaden en F20.T02–T06.

#![forbid(unsafe_code)]

extern crate alloc;

use gravital_id_types::GidError;

/// Versión semántica del crate en compilación.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Error canónico re-exportado para los consumidores.
pub type ProximityError = GidError;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    // Verifies: REQ-MAINT-002 (el crate compila con lints estrictos)
    #[test]
    fn crate_compiles_with_strict_lints() {
        let _ = VERSION;
    }
}
