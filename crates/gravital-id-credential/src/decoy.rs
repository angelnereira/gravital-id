//! Soporte para digests señuelo (decoys) en objetos y arrays (REQ-CRED-003, RFC 9901 §5.1.2).
//!
//! Los digests señuelo permiten ofuscar el número real de claims o elementos divulgables
//! en una credencial o presentación SD-JWT, mitigando ataques de inferencia por cardinalidad
//! y previniendo la correlación del titular.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_crypto::Rng;
use gravital_id_types::GidError;

use crate::disclosure::DisclosureDigest;

/// Genera un digest señuelo aleatorio de 32 bytes con la misma apariencia que un digest real.
///
/// // Verifies: REQ-CRED-003
pub fn generate_decoy_digest(rng: &impl Rng) -> Result<DisclosureDigest, GidError> {
    let bytes = rng.fill_32_bytes()?;
    Ok(DisclosureDigest::from_hash_bytes(&bytes))
}

/// Genera un lote de `count` digests señuelo aleatorios e independientes.
///
/// // Verifies: REQ-CRED-003
pub fn generate_decoy_digests(
    rng: &impl Rng,
    count: usize,
) -> Result<Vec<DisclosureDigest>, GidError> {
    let mut digests = Vec::with_capacity(count);
    for _ in 0..count {
        digests.push(generate_decoy_digest(rng)?);
    }
    Ok(digests)
}

/// Crea un elemento de array señuelo de la forma `{"...": "<decoy_digest>"}` (RFC 9901 §5.1.2).
///
/// // Verifies: REQ-CRED-003
#[must_use]
pub fn create_array_decoy_element(digest: &DisclosureDigest) -> Value {
    Value::Object(vec![(
        "...".to_string(),
        Value::String(digest.as_str().to_string()),
    )])
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use gravital_id_testkit::SeededRng;

    #[test]
    fn decoy_digest_has_same_format_as_real_digest() {
        let rng = SeededRng::new(404);
        let decoy = generate_decoy_digest(&rng).expect("generate decoy");
        assert_eq!(decoy.as_str().len(), 43);

        // Can be parsed by DisclosureDigest
        let parsed = DisclosureDigest::from_base64url(decoy.as_str()).expect("valid decoy");
        assert_eq!(parsed, decoy);
    }

    #[test]
    fn batch_decoy_digests_are_distinct() {
        let rng = SeededRng::new(505);
        let decoys = generate_decoy_digests(&rng, 5).expect("generate decoys");
        assert_eq!(decoys.len(), 5);
        for i in 0..4 {
            for j in (i + 1)..5 {
                assert_ne!(decoys[i], decoys[j]);
            }
        }
    }

    #[test]
    fn array_decoy_element_structure() {
        let rng = SeededRng::new(606);
        let decoy = generate_decoy_digest(&rng).expect("generate decoy");
        let element = create_array_decoy_element(&decoy);

        match element {
            Value::Object(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "...");
                assert_eq!(entries[0].1, Value::String(decoy.as_str().to_string()));
            }
            _ => panic!("expected Value::Object"),
        }
    }
}
