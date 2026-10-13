//! UI test: intento de firmar con clave HPKE debe fallar en compilación.
//!
//! Trazabilidad: REQ-KEY-001, REQ-KEY-009.

use gravital_id_keys::purpose::HpkeKeyAgreement;
use gravital_id_keys::{KeyHandle, KeyStore};

fn attempt_signing_with_hpke_key(keystore: &impl KeyStore, handle: &KeyHandle<HpkeKeyAgreement>) {
    let digest = [0u8; 32];
    let _ = keystore.sign(handle, &digest);
}

fn main() {}
