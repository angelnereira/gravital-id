//! Verificación del catálogo de errores (`cargo xtask check-error-codes`).
//!
//! Garantiza que los códigos definidos en `gravital-id-types` sean únicos y que
//! coincidan exactamente con los documentados en `docs/specs/ERROR_CODES.md`
//! (`REQ-SDK-003`).

use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Extrae los sufijos numéricos de tokens `<prefix>E<4 dígitos>` presentes en `text`.
///
/// Devuelve todas las apariciones (con repeticiones) para poder detectar duplicados.
pub fn extract_codes(text: &str, prefix: &str) -> Vec<u32> {
    let needle = format!("{prefix}-E");
    let mut result = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.len() == 4 {
            if let Ok(n) = digits.parse::<u32>() {
                result.push(n);
            }
        }
        rest = after;
    }
    result
}

/// Extrae los códigos **definidos** en `text`: solo las líneas de brazo de `match`
/// con la forma `=> "<prefix>E<4 dígitos>"`.
///
/// Evita falsos positivos por menciones del código en documentación, ejemplos o
/// pruebas (p. ej. `/// ... con prefijo \`GID-E\` (ej. "GID-E1001")`).
/// Regression: #6 (`check-error-codes` reportaba duplicados inexistentes).
pub fn extract_definition_codes(text: &str, prefix: &str) -> Vec<u32> {
    let arm_prefix = format!("=> \"{prefix}-E");
    text.lines()
        .filter(|line| line.contains(&arm_prefix))
        .flat_map(|line| extract_codes(line, prefix))
        .collect()
}

/// Extrae los discriminantes numéricos de las variantes del enum de la forma
/// `Identificador = <dígitos>,` (ignora `#[repr(u32)]` y otros `= u32`).
pub fn extract_enum_discriminants(text: &str) -> Vec<u32> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            // Una variante de enum: comienza con un identificador en mayúsculas.
            let mut chars = line.chars();
            let first = chars.next()?;
            if !first.is_ascii_uppercase() {
                return None;
            }
            let (name, rest) = line.split_once(' ')?;
            if name.chars().any(|c| !c.is_ascii_alphanumeric() && c != '_') {
                return None;
            }
            let value = rest.trim().strip_prefix("= ")?.strip_suffix(',')?;
            value.parse::<u32>().ok()
        })
        .collect()
}

/// Valida unicidad de un conjunto de códigos y devuelve el conjunto ordenado.
pub fn ensure_unique(codes: &[u32], origin: &str) -> Result<BTreeSet<u32>> {
    let mut set = BTreeSet::new();
    let mut duplicates = Vec::new();
    for code in codes {
        if !set.insert(*code) {
            duplicates.push(*code);
        }
    }
    if !duplicates.is_empty() {
        bail!("Códigos duplicados en {origin}: {duplicates:?}");
    }
    Ok(set)
}

/// Compara los códigos del código fuente contra los documentados.
pub fn compare_sets(source: &BTreeSet<u32>, documented: &BTreeSet<u32>) -> Result<()> {
    let undocumented: Vec<_> = source.difference(documented).collect();
    let unimplemented: Vec<_> = documented.difference(source).collect();
    if undocumented.is_empty() && unimplemented.is_empty() {
        return Ok(());
    }
    bail!(
        "Catálogo de errores inconsistente. En código pero no documentados: {undocumented:?}. \
         Documentados pero no implementados: {unimplemented:?}"
    );
}

/// Ejecuta el comando `cargo xtask check-error-codes`.
pub fn run_check_error_codes(workspace_root: &Path) -> Result<()> {
    let source_path = workspace_root
        .join("crates")
        .join("gravital-id-types")
        .join("src")
        .join("error.rs");
    let doc_path = workspace_root
        .join("docs")
        .join("specs")
        .join("ERROR_CODES.md");

    let source = fs::read_to_string(&source_path)
        .with_context(|| format!("No se pudo leer {}", source_path.display()))?;
    let doc = fs::read_to_string(&doc_path)
        .with_context(|| format!("No se pudo leer {}", doc_path.display()))?;

    // Cada código aparece exactamente una vez como definición `=> "GID-Exxxx"`.
    let source_codes = ensure_unique(
        &extract_definition_codes(&source, "GID"),
        "error.rs (GID-E)",
    )?;
    // Y exactamente una vez como definición `=> "PIP-Exxxx"` en legacy_code_str();
    // ambos catálogos deben coincidir.
    let legacy_codes = ensure_unique(
        &extract_definition_codes(&source, "PIP"),
        "error.rs (PIP-E)",
    )?;
    compare_sets(&source_codes, &legacy_codes)?;

    // Los discriminantes del enum deben coincidir con los códigos documentados:
    // un código publicado nunca cambia de significado (PROJECT_STRUCTURE §7).
    let discriminants = ensure_unique(
        &extract_enum_discriminants(&source),
        "error.rs (discriminantes del enum)",
    )?;
    compare_sets(&source_codes, &discriminants)?;

    // En la documentación, cada código figura exactamente una vez en la tabla de
    // su familia como `PIP-Exxxx`. Se extraen solo filas de tabla para ignorar
    // los rangos de los encabezados (p. ej. `PIP-E1000..E1999`) y los ejemplos
    // de bloques de código.
    let documented: Vec<u32> = doc
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .flat_map(|line| extract_codes(line, "PIP"))
        .collect();
    let documented_set: BTreeSet<u32> = documented.iter().copied().collect();
    compare_sets(&source_codes, &documented_set)?;

    println!(
        "xtask: {} códigos de error únicos y documentados correctamente.",
        source_codes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // // Verifies: REQ-SDK-003
    #[test]
    fn test_extract_codes_finds_four_digit_codes() {
        let codes = extract_codes("`PIP-E1001` y PIP-E2002, no PIP-E12", "PIP");
        assert_eq!(codes, vec![1001, 2002]);
    }

    // // Verifies: REQ-SDK-003 (Regresión #6: menciones en docs no son duplicados)
    #[test]
    fn test_extract_definition_codes_ignores_doc_mentions() {
        let source = r#"
/// Devuelve el código con prefijo `GID-E` (ej. "GID-E1001").
/// Otro comentario que menciona GID-E1003.
pub const fn code_str(self) -> &'static str {
    match self {
        Self::MalformedMessage => "GID-E1001",
        Self::NonceReused => "GID-E1003",
    }
}
"#;
        assert_eq!(extract_definition_codes(source, "GID"), vec![1001, 1003]);
    }

    // // Verifies: REQ-SDK-003 (Regresión #6: caso negativo real, dos definiciones)
    #[test]
    fn test_negative_duplicate_definition_codes_are_detected() {
        let source = r#"
match self {
    Self::A => "GID-E1001",
    Self::B => "GID-E1001",
}
"#;
        let res = ensure_unique(&extract_definition_codes(source, "GID"), "test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("1001"));
    }

    // // Verifies: REQ-SDK-003 (discriminantes del enum)
    #[test]
    fn test_extract_enum_discriminants() {
        let source = r#"
#[derive(Debug)]
#[repr(u32)]
pub enum ErrorCode {
    MalformedMessage = 1001,
    InvalidSignature = 2001,
    other_not_variant = 3,
    _Phantom(u32),
}
"#;
        assert_eq!(extract_enum_discriminants(source), vec![1001, 2001]);
    }

    // // Verifies: REQ-SDK-003 (caso negativo: duplicados)
    #[test]
    fn test_negative_duplicate_codes_are_rejected() {
        let res = ensure_unique(&[1001, 1002, 1001], "test");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("1001"));
    }

    // // Verifies: REQ-SDK-003 (caso negativo: código sin documentar)
    #[test]
    fn test_negative_undocumented_code_is_rejected() {
        let source: BTreeSet<u32> = [1001, 1002].into_iter().collect();
        let documented: BTreeSet<u32> = [1001].into_iter().collect();
        let res = compare_sets(&source, &documented);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("1002"));
    }

    // // Verifies: REQ-SDK-003 (caso negativo: código documentado pero no implementado)
    #[test]
    fn test_negative_unimplemented_documented_code_is_rejected() {
        let source: BTreeSet<u32> = [1001].into_iter().collect();
        let documented: BTreeSet<u32> = [1001, 1002].into_iter().collect();
        assert!(compare_sets(&source, &documented).is_err());
    }

    // // Verifies: REQ-SDK-003 (caso positivo)
    #[test]
    fn test_matching_sets_pass() {
        let a: BTreeSet<u32> = [1001, 1002].into_iter().collect();
        assert!(compare_sets(&a, &a.clone()).is_ok());
    }
}
