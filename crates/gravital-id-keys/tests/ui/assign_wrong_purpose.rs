//! UI test: intento de asignar KeyHandle de acuerdo a variable de KeyHandle de firma debe fallar.
//!
//! Trazabilidad: REQ-KEY-001.

use gravital_id_keys::purpose::{HolderBinding, HpkeKeyAgreement};
use gravital_id_keys::KeyHandle;

fn attempt_assign_wrong_purpose(hpke_key: KeyHandle<HpkeKeyAgreement>) {
    let _signing_key: KeyHandle<HolderBinding> = hpke_key;
}

fn main() {}
