//! UI test: intento de acuerdo Diffie-Hellman con clave de firma debe fallar en compilación.
//!
//! Trazabilidad: REQ-KEY-001, REQ-KEY-009.

use gravital_id_crypto::JwkEcP256;
use gravital_id_keys::purpose::HolderBinding;
use gravital_id_keys::{KeyHandle, KeyStore};

fn attempt_agree_with_signing_key(
    keystore: &impl KeyStore,
    handle: &KeyHandle<HolderBinding>,
    peer_pub: &JwkEcP256,
) {
    let _ = keystore.agree_key(handle, peer_pub);
}

fn main() {}
