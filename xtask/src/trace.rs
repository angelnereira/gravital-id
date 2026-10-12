//! Trazabilidad requisito -> prueba (`cargo xtask trace`).
//!
//! Implementa la verificación normativa de `REQ-DOC-003` y `AGENTS.md §5.2`.

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Representa un requisito del sistema extraído de `docs/REQUIREMENTS.md`.
#[derive(Debug, Clone)]
pub struct Requirement {
    /// Identificador canónico (ej. `REQ-KEY-001`).
    pub id: String,
    /// Texto del requisito.
    #[allow(dead_code)]
    pub description: String,
    /// Nivel normativo: "DEBE", "DEBERÍA", "PUEDE".
    pub level: String,
    /// Método de verificación: T (test), F (fuzz), I (inspección), A (auditoría), D (demo).
    pub verification: String,
    /// Fase asignada (ej. "F0", "F1", "F2", etc.).
    pub phase: String,
    /// Principio arquitectónico asociado.
    pub principle: String,
}

/// Extrae todos los requisitos definidos en `docs/REQUIREMENTS.md`.
pub fn parse_requirements(req_path: &Path) -> Result<Vec<Requirement>> {
    let content = fs::read_to_string(req_path)
        .with_context(|| format!("No se pudo leer {}", req_path.display()))?;

    let mut requirements = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('|') && trimmed.contains("REQ-") {
            let cols: Vec<&str> = trimmed
                .split('|')
                .map(|c| c.trim())
                .filter(|c| !c.is_empty())
                .collect();

            // Esperamos al menos 6 columnas: ID, Requisito, Nivel, Verif., Fase, P
            if cols.len() >= 6 && cols[0].starts_with("REQ-") {
                requirements.push(Requirement {
                    id: cols[0].to_string(),
                    description: cols[1].to_string(),
                    level: cols[2].to_string(),
                    verification: cols[3].to_string(),
                    phase: cols[4].to_string(),
                    principle: cols[5].to_string(),
                });
            }
        }
    }

    Ok(requirements)
}

/// Escanea recursivamente archivos `.rs` buscando etiquetas `// Verifies: REQ-...` o citas de REQ en pruebas.
pub fn scan_test_verifications(root_dir: &Path) -> Result<HashMap<String, Vec<PathBuf>>> {
    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();

    fn visit_dir(dir: &Path, map: &mut HashMap<String, Vec<PathBuf>>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name != "target" && name != ".git" && name != "node_modules" {
                    visit_dir(&path, map)?;
                }
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let content = fs::read_to_string(&path)?;
                for line in content.lines() {
                    if line.contains("REQ-") {
                        // Buscar tokens que comiencen con REQ-
                        for word in
                            line.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
                        {
                            if word.starts_with("REQ-") {
                                let id = word.trim().to_string();
                                map.entry(id).or_default().push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    visit_dir(root_dir, &mut map)?;

    // Deduplicar rutas por requisito
    for paths in map.values_mut() {
        paths.sort();
        paths.dedup();
    }

    Ok(map)
}

/// Valida que todo requisito DEBE con verificación T/F de fases cerradas tenga pruebas asociadas.
pub fn validate_traceability(
    requirements: &[Requirement],
    verifications: &HashMap<String, Vec<PathBuf>>,
    closed_phases: &HashSet<&str>,
) -> Result<String> {
    let mut missing = Vec::new();
    let mut report =
        String::from("# Matriz de Trazabilidad Requisitos -> Pruebas (REQ-DOC-003)\n\n");
    report.push_str(
        "| ID | Fase | Nivel | Verificación | Principio | Pruebas / Archivos | Estado |\n",
    );
    report.push_str("|---|---|---|---|---|---|---|\n");

    for req in requirements {
        let paths = verifications.get(&req.id);
        let has_tests = paths.is_some() && !paths.unwrap().is_empty();

        let requires_test = req.level == "DEBE"
            && (req.verification.contains('T') || req.verification.contains('F'));
        let is_phase_closed = closed_phases.contains(req.phase.as_str());

        let status = if has_tests {
            "Cubierto"
        } else if is_phase_closed && requires_test {
            missing.push(format!(
                "{} (Fase {}, DEBE, {}) no tiene pruebas en el código",
                req.id, req.phase, req.verification
            ));
            "FALTANTE (Bloqueante)"
        } else if requires_test {
            "Pendiente (Fase futura)"
        } else {
            "Inspección / Auditoría"
        };

        let paths_str = match paths {
            Some(p) => p
                .iter()
                .map(|pb| {
                    pb.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join(", "),
            None => "—".to_string(),
        };

        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            req.id, req.phase, req.level, req.verification, req.principle, paths_str, status
        ));
    }

    if !missing.is_empty() {
        bail!(
            "Violación de REQ-DOC-003: Requisitos DEBE de fases cerradas sin pruebas:\n- {}",
            missing.join("\n- ")
        );
    }

    Ok(report)
}

/// Ejecuta el comando `cargo xtask trace`.
pub fn run_trace(workspace_root: &Path) -> Result<()> {
    let req_path = workspace_root.join("docs").join("REQUIREMENTS.md");
    let requirements = parse_requirements(&req_path)?;
    println!(
        "xtask: cargados {} requisitos desde REQUIREMENTS.md",
        requirements.len()
    );

    let verifications = scan_test_verifications(workspace_root)?;
    println!(
        "xtask: escaneadas referencias en código Rust ({} requisitos referenciados)",
        verifications.len()
    );

    // Fases cerradas actualmente (F0 está cerrada según STATUS.md)
    let mut closed_phases = HashSet::new();
    closed_phases.insert("F0");

    let report = validate_traceability(&requirements, &verifications, &closed_phases)?;

    let out_path = workspace_root.join("docs").join("TRACEABILITY.md");
    fs::write(&out_path, report)?;
    println!(
        "xtask: matriz de trazabilidad actualizada en {}",
        out_path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // // Verifies: REQ-DOC-003
    #[test]
    fn test_traceability_passes_when_all_covered() {
        let reqs = vec![Requirement {
            id: "REQ-MAINT-002".into(),
            description: "Reglas de capas verificadas".into(),
            level: "DEBE".into(),
            verification: "T".into(),
            phase: "F1".into(),
            principle: "P-01".into(),
        }];

        let mut verifications = HashMap::new();
        verifications.insert(
            "REQ-MAINT-002".into(),
            vec![PathBuf::from("xtask/src/layers.rs")],
        );

        let mut closed = HashSet::new();
        closed.insert("F1");

        let res = validate_traceability(&reqs, &verifications, &closed);
        assert!(res.is_ok());
    }

    // // Verifies: REQ-DOC-003 (caso negativo: falta prueba en fase cerrada)
    #[test]
    fn test_negative_traceability_fails_for_missing_test_in_closed_phase() {
        let reqs = vec![Requirement {
            id: "REQ-MAINT-002".into(),
            description: "Reglas de capas".into(),
            level: "DEBE".into(),
            verification: "T".into(),
            phase: "F1".into(),
            principle: "P-01".into(),
        }];

        let verifications = HashMap::new();
        let mut closed = HashSet::new();
        closed.insert("F1"); // Fase F1 declarada cerrada sin prueba -> debe fallar

        let res = validate_traceability(&reqs, &verifications, &closed);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("REQ-MAINT-002"));
    }
}
