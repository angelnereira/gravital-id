//! Binding WASM del SDK de Gravital ID (`bindings/wasm`).
//!
//! Superficie de humo de F1.T13: demuestra que la fachada del SDK compila a
//! `wasm32-unknown-unknown` y que sus tipos cruzan la frontera FFI. Será
//! sustituida por la API completa en F9.T01/F9.T06 (`ROADMAP.md §14`).

use wasm_bindgen::prelude::*;
use gravital_id_sdk::{ErrorCode, GidError};

/// Versión semántica del SDK en uso.
#[wasm_bindgen]
pub fn sdk_version() -> String {
    match std::panic::catch_unwind(|| gravital_id_sdk::VERSION.to_string()) {
        Ok(v) => v,
        Err(_) => "GID-E9999".to_string(),
    }
}

/// Construye el error canónico para `message` y devuelve su identificador
/// (`GID-Exxxx`). Andamiaje de F1: valida el catálogo de errores a través de
/// la frontera FFI. Captura pánicos y los mapea a `GID-E9999` (INV-10).
#[wasm_bindgen]
pub fn error_identifier(message: &str) -> String {
    match std::panic::catch_unwind(|| {
        GidError::new(ErrorCode::MalformedMessage, message)
            .code_str()
            .to_string()
    }) {
        Ok(v) => v,
        Err(_) => "GID-E9999".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // // Verifies: REQ-PORT-001 (el binding compila y ejecuta en wasm32)
    #[wasm_bindgen_test]
    fn sdk_version_is_exposed_across_ffi() {
        // La versión expuesta es la del SDK, no la del crate binding.
        assert_eq!(sdk_version(), gravital_id_sdk::VERSION);
    }

    // // Verifies: REQ-SDK-003 (el catálogo canónico cruza la frontera FFI)
    #[wasm_bindgen_test]
    fn error_catalog_crosses_ffi_boundary() {
        assert_eq!(error_identifier("malformed payload"), "GID-E1001");
    }
}
