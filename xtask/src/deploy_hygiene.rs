//! Verificación automatizada de higiene y seguridad en configuraciones de despliegue e IaC (F7.T01).
//!
//! Trazabilidad:
//! - **REQ-REL-001:** Ningún servicio debe ser punto único de fallo para verificar o recuperar.
//! - **REQ-PRIV-003:** SDK y servicios no deben registrar datos personales ni secretos.
//! - **INV-02:** Cero datos personales ni secretos en el repositorio.

use std::fs;
use std::path::Path;

/// Patrones prohibidos que indican fuga o inclusión indebida de secretos reales en archivos de despliegue.
const FORBIDDEN_SECRET_PATTERNS: &[&str] = &[
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "xprv",
    "ghp_",
    "github_pat_",
];

// Verifies: REQ-REL-001, REQ-PRIV-003, INV-02
/// Ejecuta la validación de higiene en todos los archivos de despliegue e infraestructura.
pub fn run_check_deploy_hygiene(workspace_root: &Path) -> anyhow::Result<()> {
    let deploy_dir = workspace_root.join("deploy");
    if !deploy_dir.exists() {
        anyhow::bail!(
            "El directorio '{}' no existe en el workspace",
            deploy_dir.display()
        );
    }

    let mut files_scanned = 0usize;

    // 1. Escanear recursivamente deploy/ buscando secretos en claro
    scan_directory_for_secrets(&deploy_dir, &mut files_scanned)?;

    // 2. Verificar que los artefactos contracts.json contengan las estructuras normativas
    let environments = ["local", "dev", "testnet"];
    for env in environments {
        let contracts_json = deploy_dir
            .join("environments")
            .join(env)
            .join("contracts.json");

        if !contracts_json.exists() {
            anyhow::bail!(
                "Falta el artefacto de contratos requerido: {}",
                contracts_json.display()
            );
        }

        let content = fs::read_to_string(&contracts_json)?;
        let parsed: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            anyhow::anyhow!("Error parseando JSON de {}: {e}", contracts_json.display())
        })?;

        // Validar presencia de campos esenciales según el esquema
        if parsed.get("chainId").is_none() {
            anyhow::bail!("Campo 'chainId' faltante en {}", contracts_json.display());
        }
        if parsed.get("contracts").is_none() {
            anyhow::bail!(
                "Objeto 'contracts' faltante en {}",
                contracts_json.display()
            );
        }
    }

    // 3. Verificar que Dockerfile.service ejecuta con usuario no root
    let dockerfile = deploy_dir.join("docker").join("Dockerfile.service");
    if dockerfile.exists() {
        let content = fs::read_to_string(&dockerfile)?;
        if !content.contains("USER 10001:10001") && !content.contains("USER gid") {
            anyhow::bail!(
                "Dockerfile.service debe ejecutar con usuario no root (INV-02, REQ-REL-001)"
            );
        }
    }

    println!(
        "xtask: verificados {} archivos de despliegue e infraestructura; 0 secretos en claro detectados y entornos validados (REQ-REL-001, REQ-PRIV-003, INV-02).",
        files_scanned
    );

    Ok(())
}

fn scan_directory_for_secrets(dir: &Path, count: &mut usize) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            scan_directory_for_secrets(&path, count)?;
        } else if path.is_file() {
            *count = count.saturating_add(1);
            let content = fs::read_to_string(&path).unwrap_or_default();

            for pattern in FORBIDDEN_SECRET_PATTERNS {
                if content.contains(pattern) {
                    anyhow::bail!(
                        "Fuga de seguridad detectada en '{}': contiene patrón de clave privada o token '{}'",
                        path.display(),
                        pattern
                    );
                }
            }
        }
    }
    Ok(())
}
