use gravital_id_verifier::{AllMandatoryPassed, VerificationResult};

fn main() {
    // Intento inválido: AllMandatoryPassed tiene campos privados e impide
    // forjar un resultado `Valid` fuera del pipeline de verificación (REQ-VER-012, ADR-0020).
    let witness = AllMandatoryPassed { _private: () };
    let _ = VerificationResult::new_valid(
        witness,
        vec![],
        "iss".into(),
        "kid".into(),
        "vct".into(),
        gravital_id_codec::json::Value::Null,
        None,
    );
}
