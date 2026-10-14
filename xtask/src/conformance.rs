//! Runner de vectores de conformidad SD-JWT VC (F3.T09, `cargo xtask conformance`).
//!
//! Ejecuta todos los vectores publicados en `conformance/vectors/sd-jwt-vc/` contra la
//! implementación y falla ante cualquier discrepancia entre el resultado esperado y el
//! obtenido.
//!
//! Trazabilidad:
//! - **REQ-MAINT-003:** Cada comprobación de verificación DEBE tener al menos un vector
//!   negativo.
//! - **INV-12:** Los vectores publicados son inmutables: el runner solo los lee.
//! - **INV-05:** Un vector «invalid» no puede pasar por una aceptación.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use gravital_id_codec::json::{self, Limits as JsonLimits, Value};
use gravital_id_credential::{
    to_canonical_json, KbVerificationPolicy, ParsedSdJwt, VcValidityPolicy,
};
use gravital_id_crypto::JwkEcP256;
use gravital_id_types::{GidError, ProfileId, UnixTime};

/// Directorio de los vectores, relativo a la raíz del workspace.
pub const VECTOR_DIR: &str = "conformance/vectors/sd-jwt-vc";

/// Lee un campo de texto obligatorio de un objeto JSON.
fn str_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .member(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing or invalid string field '{name}'"))
}

/// Lee un campo entero sin signo obligatorio.
fn u64_field(value: &Value, name: &str) -> Result<u64> {
    match value.member(name) {
        Some(Value::Number(json::Number::PosInt(n))) => Ok(*n),
        _ => Err(anyhow!("missing or invalid integer field '{name}'")),
    }
}

/// Lee un campo booleano con valor por defecto.
fn bool_field(value: &Value, name: &str, default: bool) -> bool {
    match value.member(name) {
        Some(Value::Bool(b)) => *b,
        _ => default,
    }
}

/// Interpreta la política de verificación declarada por el vector.
fn parse_policy(value: &Value) -> Result<VcValidityPolicy> {
    let mut policy = VcValidityPolicy::default();
    policy.require_status = bool_field(value, "require_status", policy.require_status);
    policy.require_exp = bool_field(value, "require_exp", policy.require_exp);
    policy.require_cnf = bool_field(value, "require_cnf", policy.require_cnf);
    if value.member("clock_skew_seconds").is_some() {
        policy.clock_skew_seconds = u64_field(value, "clock_skew_seconds")?;
    }
    if let Some(profile) = value.member("profile").and_then(Value::as_str) {
        let profile_id =
            ProfileId::parse(profile).map_err(|e| anyhow!("invalid profile '{profile}': {e}"))?;
        policy.profile = Some(profile_id);
    }
    if let Some(Value::Array(algs)) = value.member("allowed_algorithms") {
        let mut allowed = Vec::with_capacity(algs.len());
        for alg in algs {
            let alg = alg
                .as_str()
                .ok_or_else(|| anyhow!("'allowed_algorithms' must contain strings"))?;
            allowed.push(alg.to_string());
        }
        policy.allowed_algorithms = allowed;
    }
    Ok(policy)
}

/// Interpreta una JWK pública declarada por el vector (actúa como entrada del trust bundle).
fn parse_jwk(value: &Value) -> Result<JwkEcP256> {
    let canonical = to_canonical_json(value);
    JwkEcP256::parse(&canonical).map_err(|e| anyhow!("invalid JWK: {e}"))
}

/// Ejecuta un vector y devuelve el error observado si no coincide con lo esperado.
pub fn run_vector(vector: &Value) -> Result<()> {
    let name = str_field(vector, "name")?;
    let kind = str_field(vector, "kind")?;
    let sd_jwt = str_field(vector, "sd_jwt")?;
    let now = UnixTime::from_seconds(u64_field(vector, "now")?);
    let policy = parse_policy(vector.member("policy").unwrap_or(&Value::Null))?;
    let expected = vector
        .member("expected")
        .ok_or_else(|| anyhow!("vector '{name}' has no 'expected' block"))?;
    let expected_result = str_field(expected, "result")?;

    let parsed = match ParsedSdJwt::parse(sd_jwt) {
        Ok(parsed) => parsed,
        Err(error) => {
            // El rechazo puede llegar desde el propio parseo (p. ej. `alg: none`).
            return match expected_result {
                "invalid" => expect_error(expected, &error),
                _ => Err(anyhow!(
                    "vector '{name}' expected {expected_result} but parsing failed: {error}"
                )),
            };
        }
    };

    // Firma del emisor, cuando el vector aporta la clave (rol del trust bundle local).
    if let Some(issuer_jwk) = vector.member("issuer_jwk") {
        let jwk = parse_jwk(issuer_jwk)?;
        match parsed.verify_issuer_signature(&jwk) {
            Ok(()) => {}
            Err(error) => {
                return match expected_result {
                    "invalid" => expect_error(expected, &error),
                    _ => Err(anyhow!(
                        "vector '{name}' expected {expected_result} but the issuer signature failed: {error}"
                    )),
                };
            }
        }
    }

    match expected_result {
        "valid" => {
            let claims = parsed
                .verify_vc(now, &policy)
                .map_err(|e| anyhow!("vector '{name}' expected valid, got error: {e}"))?;
            check_expected_claims(name, expected, &claims)?;
            check_expected_predicates(name, vector, &parsed)?;

            // Presentaciones con Key Binding.
            if kind == "presentation" {
                let aud = str_field(vector, "aud")?;
                let nonce = str_field(vector, "nonce")?;
                let holder = parse_jwk(vector.member("holder_jwk").ok_or_else(|| {
                    anyhow!("vector '{name}' is a presentation without 'holder_jwk'")
                })?)?;
                parsed
                    .verify_key_binding(aud, nonce, &holder, now, &KbVerificationPolicy::default())
                    .map_err(|e| anyhow!("vector '{name}': key binding failed: {e}"))?;
            }
            Ok(())
        }
        "invalid" => match parsed.verify_vc(now, &policy) {
            Ok(_) => Err(anyhow!(
                "vector '{name}' expected a rejection but verification succeeded"
            )),
            Err(error) => expect_error(expected, &error),
        },
        other => Err(anyhow!("vector '{name}' has unknown result '{other}'")),
    }
}

/// Compara el código de error observado con el esperado por el vector.
fn expect_error(expected: &Value, error: &GidError) -> Result<()> {
    let expected_code = str_field(expected, "error_code")?;
    if error.code_str() == expected_code {
        return Ok(());
    }
    // Se admite tambiÃ©n la comparaciÃ³n por cÃ³digo numÃ©rico (p. ej. "3005").
    if let Ok(expected_numeric) = expected_code.parse::<u32>() {
        if error.numeric_code() == expected_numeric {
            return Ok(());
        }
    }
    Err(anyhow!(
        "expected error {expected_code}, got {} ({error})",
        error.code_str()
    ))
}

/// Comprueba los claims que el vector declara como esperados.
fn check_expected_claims(
    name: &str,
    expected: &Value,
    claims: &gravital_id_credential::SdJwtVcClaims,
) -> Result<()> {
    if let Some(iss) = expected.member("iss").and_then(Value::as_str) {
        if claims.iss != iss {
            return Err(anyhow!(
                "vector '{name}': expected iss '{iss}', got '{}'",
                claims.iss
            ));
        }
    }
    if let Some(vct) = expected.member("vct").and_then(Value::as_str) {
        if claims.vct.as_str() != vct {
            return Err(anyhow!(
                "vector '{name}': expected vct '{vct}', got '{}'",
                claims.vct
            ));
        }
    }
    if let Some(iat) = expected.member("iat") {
        let expected_iat = match iat {
            Value::Number(json::Number::PosInt(n)) => *n,
            _ => return Err(anyhow!("vector '{name}': 'iat' must be a positive integer")),
        };
        if claims.iat.as_seconds() != expected_iat {
            return Err(anyhow!(
                "vector '{name}': expected iat {expected_iat}, got {}",
                claims.iat.as_seconds()
            ));
        }
    }
    if let Some(Value::Bool(expected_cnf)) = expected.member("cnf") {
        if claims.cnf.is_some() != *expected_cnf {
            return Err(anyhow!(
                "vector '{name}': expected cnf presence {expected_cnf}, got {}",
                claims.cnf.is_some()
            ));
        }
    }
    if let Some(Value::Bool(expected_status)) = expected.member("status") {
        if claims.status.is_some() != *expected_status {
            return Err(anyhow!(
                "vector '{name}': expected status presence {expected_status}, got {}",
                claims.status.is_some()
            ));
        }
    }
    Ok(())
}

/// Comprueba los predicados divulgados que el vector declara como esperados.
fn check_expected_predicates(name: &str, vector: &Value, parsed: &ParsedSdJwt) -> Result<()> {
    let Some(Value::Object(expected)) = vector.member("expected_predicates") else {
        return Ok(());
    };

    let Some(profile) = vector
        .member("policy")
        .and_then(|p| p.member("profile"))
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let profile_id = ProfileId::parse(profile).map_err(|e| anyhow!("invalid profile: {e}"))?;
    let schema = gravital_id_credential::ProfileSchema::lookup(&profile_id)
        .ok_or_else(|| anyhow!("no schema registered for profile '{profile}'"))?;

    let disclosed =
        gravital_id_credential::disclosed_predicates(schema, parsed.reconstructed_claims());
    for (claim, expected_value) in expected {
        let Value::Bool(expected_value) = expected_value else {
            return Err(anyhow!(
                "vector '{name}': predicate '{claim}' must be a boolean"
            ));
        };
        let found = disclosed
            .iter()
            .find(|predicate| predicate.name == claim.as_str())
            .ok_or_else(|| anyhow!("vector '{name}': predicate '{claim}' was not disclosed"))?;
        if found.value != *expected_value {
            return Err(anyhow!(
                "vector '{name}': predicate '{claim}' expected {expected_value}, got {}",
                found.value
            ));
        }
    }
    Ok(())
}

/// Ejecuta todos los vectores publicados e informa del resultado.
pub fn run_conformance(workspace_root: &Path) -> Result<()> {
    let dir = workspace_root.join(VECTOR_DIR);
    if !dir.exists() {
        return Err(anyhow!(
            "no se encontró el directorio de vectores {}",
            dir.display()
        ));
    }

    let mut vectors = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("no se pudo leer {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            vectors.push(path);
        }
    }
    vectors.sort();

    if vectors.is_empty() {
        return Err(anyhow!(
            "no hay vectores de conformidad en {}",
            dir.display()
        ));
    }

    let mut passed = 0usize;
    let mut failures = Vec::new();
    for path in &vectors {
        let text = fs::read_to_string(path)
            .with_context(|| format!("no se pudo leer {}", path.display()))?;
        let value = json::parse_bytes(text.as_bytes(), &JsonLimits::profile_default())
            .map_err(|e| anyhow!("{}: JSON inválido: {e}", path.display()))?;

        match run_vector(&value) {
            Ok(()) => {
                passed = passed.saturating_add(1);
                println!(
                    "  ok   {} ({})",
                    str_field(&value, "name").unwrap_or("<sin nombre>"),
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
                );
            }
            Err(error) => {
                println!("  FAIL {}", path.display());
                failures.push(format!("{}: {error}", path.display()));
            }
        }
    }

    println!(
        "xtask: conformidad SD-JWT VC — {passed}/{} vectores correctos",
        vectors.len()
    );

    if failures.is_empty() {
        Ok(())
    } else {
        for failure in &failures {
            println!("  - {failure}");
        }
        Err(anyhow!(
            "{} vector(es) de conformidad fallan (INV-12: los vectores no se editan; se corrige la implementación)",
            failures.len()
        ))
    }
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
    use std::fs;

    fn workspace_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("la raíz del workspace es el padre de xtask")
    }

    /// Carga un vector publicado por su nombre.
    fn load_vector(name: &str) -> Value {
        let path = workspace_root()
            .join(VECTOR_DIR)
            .join(format!("{name}.json"));
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", path.display()));
        json::parse_bytes(text.as_bytes(), &JsonLimits::profile_default())
            .unwrap_or_else(|e| panic!("JSON inválido en {}: {e}", path.display()))
    }

    /// Reemplaza (o añade) un miembro de primer nivel de un objeto JSON.
    fn set_member(value: Value, name: &str, new_value: Value) -> Value {
        match value {
            Value::Object(entries) => {
                let mut entries: Vec<(String, Value)> = entries;
                let mut replaced = false;
                for (key, slot) in entries.iter_mut() {
                    if key == name {
                        *slot = new_value.clone();
                        replaced = true;
                    }
                }
                if !replaced {
                    entries.push((name.to_string(), new_value));
                }
                Value::Object(entries)
            }
            other => other,
        }
    }

    fn invalid_expectation(code: &str) -> Value {
        Value::Object(vec![
            ("result".to_string(), Value::String("invalid".to_string())),
            ("error_code".to_string(), Value::String(code.to_string())),
        ])
    }

    fn valid_expectation() -> Value {
        Value::Object(vec![(
            "result".to_string(),
            Value::String("valid".to_string()),
        )])
    }

    #[test]
    fn every_published_vector_passes() {
        let dir = workspace_root().join(VECTOR_DIR);
        let mut checked = 0usize;
        for entry in fs::read_dir(&dir).expect("directorio de vectores") {
            let path = entry.expect("entrada").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("lectura");
            let value = json::parse_bytes(text.as_bytes(), &JsonLimits::profile_default())
                .expect("json válido");
            let name = value
                .member("name")
                .and_then(Value::as_str)
                .unwrap_or("<sin nombre>")
                .to_string();
            run_vector(&value).unwrap_or_else(|e| panic!("el vector {name} falla: {e}"));
            checked = checked.saturating_add(1);
        }
        assert!(
            checked >= 20,
            "se esperaban al menos 20 vectores publicados, hay {checked}"
        );
    }

    #[test]
    fn runner_detects_a_vector_whose_expectation_is_wrong() {
        let mut vector = load_vector("sd-jwt-vc-personal-nominal");
        vector = set_member(vector, "expected", invalid_expectation("GID-E2001"));

        let error = run_vector(&vector).expect_err("el runner debe fallar");
        assert!(
            error.to_string().contains("expected a rejection")
                || error.to_string().contains("GID-E2001"),
            "el error debería describir la discrepancia: {error}"
        );
    }

    #[test]
    fn runner_detects_a_valid_credential_declared_as_invalid() {
        let mut vector = load_vector("sd-jwt-vc-personal-nominal");
        vector = set_member(vector, "expected", invalid_expectation("GID-E3005"));

        let error = run_vector(&vector).expect_err("el runner debe fallar");
        assert!(
            error.to_string().contains("expected error GID-E3005")
                || error.to_string().contains("expected a rejection"),
            "el error debería describir la discrepancia: {error}"
        );
    }

    #[test]
    fn runner_detects_a_rejected_credential_declared_as_valid() {
        let mut vector = load_vector("sd-jwt-vc-alg-none-rejected");
        vector = set_member(vector, "expected", valid_expectation());

        let error = run_vector(&vector).expect_err("el runner debe fallar");
        assert!(
            error.to_string().contains("expected valid"),
            "el error debería indicar que se esperaba válido: {error}"
        );
    }

    #[test]
    fn run_conformance_reports_all_vectors() {
        run_conformance(workspace_root()).expect("todos los vectores deben pasar");
    }
}
