//! Verificación de reglas de capas e invariantes arquitectónicas (`cargo xtask check-layers`).
//!
//! Implementa la verificación normativa de `PROJECT_STRUCTURE.md §4`, `ADR-0019` y `REQ-MAINT-002`.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuración cargada desde `xtask/layers.toml`.
#[derive(Debug, Deserialize)]
pub struct LayersConfig {
    /// Capas del sistema L1..L6.
    pub layers: HashMap<String, Vec<String>>,
    /// Reglas de validación.
    pub rules: RulesConfig,
}

/// Reglas configuradas en `layers.toml`.
#[derive(Debug, Deserialize)]
pub struct RulesConfig {
    /// Dependencias prohibidas para capas L1–L4.
    pub forbidden_deps_l1_l4: Vec<String>,
    /// Capas que deben ser no_std.
    pub no_std_layers: Vec<String>,
    /// Crates prohibidos para gravital-id-verifier.
    pub verifier_disallowed: Vec<String>,
    /// Prefijos de rutas prohibidas para crates/.
    pub forbidden_root_prefixes_for_crates: Vec<String>,
}

/// Información extraída de un crate del workspace.
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// Nombre del crate.
    pub name: String,
    /// Ruta al directorio del crate.
    pub dir: PathBuf,
    /// Capa asignada (ej. "L1", "L2", "L5", o None).
    pub layer: Option<String>,
    /// `true` si el crate vive en `bindings/`.
    pub is_binding: bool,
    /// Dependencias normales (excluyendo dev-dependencies).
    pub dependencies: Vec<String>,
    /// Dev-dependencies.
    #[allow(dead_code)]
    pub dev_dependencies: Vec<String>,
    /// Contenido de lib.rs o main.rs raíz.
    pub root_source: String,
}

/// Mapeo numérico de capas para comparaciones de orden.
pub fn layer_rank(layer: &str) -> Option<u32> {
    match layer {
        "L1" => Some(1),
        "L2" => Some(2),
        "L3" => Some(3),
        "L4" => Some(4),
        "L5" => Some(5),
        "L6" => Some(6),
        _ => None,
    }
}

/// Ejecuta las validaciones de capas sobre el conjunto de crates dado.
pub fn validate_layers(config: &LayersConfig, crates: &[CrateInfo]) -> Result<()> {
    let mut errors = Vec::new();

    // Mapear cada nombre de crate a su capa
    let mut crate_to_layer: HashMap<String, String> = HashMap::new();
    for (layer_name, members) in &config.layers {
        for member in members {
            crate_to_layer.insert(member.clone(), layer_name.clone());
        }
    }

    let no_std_layers_set: HashSet<&str> = config
        .rules
        .no_std_layers
        .iter()
        .map(|s| s.as_str())
        .collect();

    for c in crates {
        let is_in_crates_dir =
            c.dir.starts_with("crates") || c.dir.to_string_lossy().contains("/crates/");

        // Regla 1: forbid(unsafe_code) obligatorio fuera de bindings/ (REQ-SEC-001, INV-09)
        let is_in_bindings = c.dir.to_string_lossy().contains("bindings");
        if !is_in_bindings && !c.root_source.contains("#![forbid(unsafe_code)]") {
            errors.push(format!(
                "[{}] REQ-SEC-001 / INV-09: Falta '#![forbid(unsafe_code)]' en el archivo raíz",
                c.name
            ));
        }

        // Si el crate pertenece a una capa normada
        if let Some(layer) = c
            .layer
            .as_deref()
            .or_else(|| crate_to_layer.get(&c.name).map(|s| s.as_str()))
        {
            let rank_current = layer_rank(layer);

            // Regla 2: L1–L3 deben ser estrictamente no_std (ADR-0019, REQ-PORT-004)
            if no_std_layers_set.contains(layer) && !c.root_source.contains("#![no_std]") {
                errors.push(format!(
                    "[{}] REQ-PORT-004 / ADR-0019: Crate en capa {} debe declarar '#![no_std]'",
                    c.name, layer
                ));
            }

            // Regla 3: Dependencias prohibidas en L1–L4 (INV-01, sans-I/O)
            if let Some(r) = rank_current {
                if r <= 4 {
                    for dep in &c.dependencies {
                        for forbidden in &config.rules.forbidden_deps_l1_l4 {
                            if dep == forbidden {
                                errors.push(format!(
                                    "[{}] INV-01: Dependencia prohibida '{}' en capa {} (L1–L4 son sans-I/O y sin async runtimes)",
                                    c.name, forbidden, layer
                                ));
                            }
                        }
                    }
                }
            }

            // Regla 4: Orden de capas: Un crate solo puede depender de su capa o capas inferiores
            if let Some(r_cur) = rank_current {
                for dep in &c.dependencies {
                    if let Some(dep_layer) = crate_to_layer.get(dep) {
                        if let Some(r_dep) = layer_rank(dep_layer) {
                            if r_dep > r_cur {
                                errors.push(format!(
                                    "[{}] REQ-MAINT-002: Violación de capa: '{}' en {} no puede depender de '{}' en capa superior {}",
                                    c.name, c.name, layer, dep, dep_layer
                                ));
                            }
                        }
                    }
                }
            }

            // Regla 5: Verifier isolation: gravital-id-verifier no puede depender de sync, ledger, storage o transport
            if c.name == "gravital-id-verifier" {
                for dep in &c.dependencies {
                    for disallowed in &config.rules.verifier_disallowed {
                        if dep == disallowed {
                            errors.push(format!(
                                "[gravital-id-verifier] Violación de aislamiento: verifier no puede depender de '{}'",
                                disallowed
                            ));
                        }
                    }
                }
            }
        }

        // Regla 6: Crates en crates/ no pueden depender de bindings/, services/, apps/ o spikes/
        if is_in_crates_dir {
            for dep in &c.dependencies {
                for prefix in &config.rules.forbidden_root_prefixes_for_crates {
                    if dep.starts_with(prefix) {
                        errors.push(format!(
                            "[{}] Violación de frontera: un crate del núcleo no puede depender de '{}'",
                            c.name, dep
                        ));
                    }
                }
            }
        }

        // Regla 7: testkit solo puede ser dev-dependency (INV-01, PROJECT_STRUCTURE §4)
        for dep in &c.dependencies {
            if dep == "gravital-id-testkit" {
                errors.push(format!(
                    "[{}] 'gravital-id-testkit' solo está permitido en [dev-dependencies], encontrado en dependencias normales",
                    c.name
                ));
            }
        }
        // Regla 8: Los bindings solo pueden depender de gravital-id-sdk
        // (PROJECT_STRUCTURE §4 regla 6, INV-15).
        if c.is_binding {
            for dep in &c.dependencies {
                if dep.starts_with("gravital-id-") && dep != "gravital-id-sdk" {
                    errors.push(format!(
                        "[{}] PROJECT_STRUCTURE §4 regla 6: un binding solo puede depender de 'gravital-id-sdk', no de '{}'",
                        c.name, dep
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "Se detectaron {} violaciones de capas:\n- {}",
            errors.len(),
            errors.join("\n- ")
        );
    }
}

/// Carga los crates del workspace desde el sistema de ficheros (núcleo y bindings).
pub fn load_workspace_crates(
    workspace_root: &Path,
    config: &LayersConfig,
) -> Result<Vec<CrateInfo>> {
    let mut crate_to_layer: HashMap<String, String> = HashMap::new();
    for (layer_name, members) in &config.layers {
        for member in members {
            crate_to_layer.insert(member.clone(), layer_name.clone());
        }
    }

    let mut result = Vec::new();
    let crates_dir = workspace_root.join("crates");

    if crates_dir.exists() {
        for entry in fs::read_dir(&crates_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let cargo_toml_path = path.join("Cargo.toml");
                if cargo_toml_path.exists() {
                    let toml_str = fs::read_to_string(&cargo_toml_path)?;
                    let parsed: toml::Value = toml::from_str(&toml_str).with_context(|| {
                        format!("Error parseando {}", cargo_toml_path.display())
                    })?;

                    let package_name = parsed
                        .get("package")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();

                    let mut dependencies = Vec::new();
                    if let Some(deps_table) = parsed.get("dependencies").and_then(|d| d.as_table())
                    {
                        for (dep_name, _) in deps_table {
                            dependencies.push(dep_name.clone());
                        }
                    }

                    let mut dev_dependencies = Vec::new();
                    if let Some(dev_deps) =
                        parsed.get("dev-dependencies").and_then(|d| d.as_table())
                    {
                        for (dep_name, _) in dev_deps {
                            dev_dependencies.push(dep_name.clone());
                        }
                    }

                    let lib_rs = path.join("src").join("lib.rs");
                    let root_source = if lib_rs.exists() {
                        fs::read_to_string(&lib_rs)?
                    } else {
                        let main_rs = path.join("src").join("main.rs");
                        if main_rs.exists() {
                            fs::read_to_string(&main_rs)?
                        } else {
                            String::new()
                        }
                    };

                    let layer = crate_to_layer.get(&package_name).cloned();

                    result.push(CrateInfo {
                        name: package_name,
                        dir: path,
                        layer,
                        is_binding: false,
                        dependencies,
                        dev_dependencies,
                        root_source,
                    });
                }
            }
        }
    }

    // Bindings (PROJECT_STRUCTURE.md §4 regla 6): crates excluidos del workspace
    // de Cargo porque solo compilan para su plataforma destino.
    let bindings_dir = workspace_root.join("bindings");
    if bindings_dir.exists() {
        for entry in fs::read_dir(&bindings_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let cargo_toml_path = path.join("Cargo.toml");
            if !cargo_toml_path.exists() {
                continue;
            }
            let toml_str = fs::read_to_string(&cargo_toml_path)?;
            let parsed: toml::Value = toml::from_str(&toml_str)
                .with_context(|| format!("Error parseando {}", cargo_toml_path.display()))?;

            let package_name = parsed
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();

            let mut dependencies = Vec::new();
            if let Some(deps_table) = parsed.get("dependencies").and_then(|d| d.as_table()) {
                for (dep_name, _) in deps_table {
                    dependencies.push(dep_name.clone());
                }
            }

            let mut dev_dependencies = Vec::new();
            if let Some(dev_deps) = parsed.get("dev-dependencies").and_then(|d| d.as_table()) {
                for (dep_name, _) in dev_deps {
                    dev_dependencies.push(dep_name.clone());
                }
            }

            let lib_rs = path.join("src").join("lib.rs");
            let root_source = if lib_rs.exists() {
                fs::read_to_string(&lib_rs)?
            } else {
                String::new()
            };

            result.push(CrateInfo {
                name: package_name,
                dir: path,
                layer: None,
                is_binding: true,
                dependencies,
                dev_dependencies,
                root_source,
            });
        }
    }

    Ok(result)
}

/// Comando principal `cargo xtask check-layers`.
pub fn run_check_layers(workspace_root: &Path) -> Result<()> {
    let config_path = workspace_root.join("xtask").join("layers.toml");
    let config_str = fs::read_to_string(&config_path)
        .with_context(|| format!("No se pudo leer {}", config_path.display()))?;
    let config: LayersConfig =
        toml::from_str(&config_str).with_context(|| "Error deserializando layers.toml")?;

    let crates = load_workspace_crates(workspace_root, &config)?;
    println!(
        "xtask: verificando reglas de capas en {} crates...",
        crates.len()
    );

    validate_layers(&config, &crates)?;

    println!("xtask: todas las reglas de capas e invariantes pasaron satisfactoriamente.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> LayersConfig {
        let mut layers = HashMap::new();
        layers.insert("L1".into(), vec!["crate-l1".into()]);
        layers.insert("L2".into(), vec!["crate-l2".into()]);
        layers.insert(
            "L3".into(),
            vec!["gravital-id-verifier".into(), "crate-l3".into()],
        );
        layers.insert("L4".into(), vec!["crate-l4".into()]);
        layers.insert("L5".into(), vec!["crate-l5".into()]);

        let rules = RulesConfig {
            forbidden_deps_l1_l4: vec!["tokio".into(), "rusqlite".into()],
            no_std_layers: vec!["L1".into(), "L2".into(), "L3".into()],
            verifier_disallowed: vec!["gravital-id-sync".into(), "crate-l5".into()],
            forbidden_root_prefixes_for_crates: vec!["services/".into(), "bindings/".into()],
        };

        LayersConfig { layers, rules }
    }

    // // Verifies: REQ-MAINT-002 (caso positivo)
    #[test]
    fn test_valid_layers_pass() {
        let config = sample_config();
        let crates = vec![
            CrateInfo {
                name: "crate-l1".into(),
                dir: PathBuf::from("crates/crate-l1"),
                layer: Some("L1".into()),
                is_binding: false,
                dependencies: vec![],
                dev_dependencies: vec!["gravital-id-testkit".into()],
                root_source: "#![no_std]\n#![forbid(unsafe_code)]\n".into(),
            },
            CrateInfo {
                name: "crate-l2".into(),
                dir: PathBuf::from("crates/crate-l2"),
                layer: Some("L2".into()),
                is_binding: false,
                dependencies: vec!["crate-l1".into()],
                dev_dependencies: vec![],
                root_source: "#![no_std]\n#![forbid(unsafe_code)]\n".into(),
            },
        ];

        assert!(validate_layers(&config, &crates).is_ok());
    }

    // // Verifies: REQ-MAINT-002 (caso negativo: orden de capas)
    #[test]
    fn test_negative_layer_order_violation() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "crate-l1".into(),
            dir: PathBuf::from("crates/crate-l1"),
            layer: Some("L1".into()),
            is_binding: false,
            dependencies: vec!["crate-l2".into()], // L1 depende de L2 -> Ilegal
            dev_dependencies: vec![],
            root_source: "#![no_std]\n#![forbid(unsafe_code)]\n".into(),
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Violación de capa"));
    }

    // // Verifies: INV-01, REQ-PORT-003 (caso negativo: async runtime o cliente en L1-L4)
    #[test]
    fn test_negative_forbidden_dep_in_l1_l4() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "crate-l4".into(),
            dir: PathBuf::from("crates/crate-l4"),
            layer: Some("L4".into()),
            is_binding: false,
            dependencies: vec!["tokio".into()], // Ilegal en L4
            dev_dependencies: vec![],
            root_source: "#![forbid(unsafe_code)]\n".into(),
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Dependencia prohibida 'tokio'"));
    }

    // // Verifies: REQ-PORT-004, ADR-0019 (caso negativo: falta no_std en L1-L3)
    #[test]
    fn test_negative_missing_no_std_in_l1_l3() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "crate-l2".into(),
            dir: PathBuf::from("crates/crate-l2"),
            layer: Some("L2".into()),
            is_binding: false,
            dependencies: vec![],
            dev_dependencies: vec![],
            root_source: "#![forbid(unsafe_code)]\n".into(), // Falta #![no_std]
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("debe declarar '#![no_std]'"));
    }

    // // Verifies: REQ-SEC-001, INV-09 (caso negativo: falta forbid(unsafe_code))
    #[test]
    fn test_negative_missing_forbid_unsafe() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "crate-l5".into(),
            dir: PathBuf::from("crates/crate-l5"),
            layer: Some("L5".into()),
            is_binding: false,
            dependencies: vec![],
            dev_dependencies: vec![],
            root_source: "// sin forbid unsafe\n".into(),
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Falta '#![forbid(unsafe_code)]'"));
    }

    // // Verifies: INV-01, PROJECT_STRUCTURE §4 (caso negativo: verifier isolation)
    #[test]
    fn test_negative_verifier_isolation() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "gravital-id-verifier".into(),
            dir: PathBuf::from("crates/gravital-id-verifier"),
            layer: Some("L3".into()),
            is_binding: false,
            dependencies: vec!["gravital-id-sync".into()], // Verifier no puede depender de sync
            dev_dependencies: vec![],
            root_source: "#![no_std]\n#![forbid(unsafe_code)]\n".into(),
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Violación de aislamiento"));
    }

    // // Verifies: PROJECT_STRUCTURE §4 regla 6 (caso positivo: binding solo depende del sdk)
    #[test]
    fn test_binding_may_depend_only_on_sdk() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "gravital-id-wasm".into(),
            dir: PathBuf::from("bindings/wasm"),
            layer: None,
            is_binding: true,
            dependencies: vec!["gravital-id-sdk".into(), "wasm-bindgen".into()],
            dev_dependencies: vec![],
            root_source: "#![forbid(unsafe_code)]\n".into(),
        }];

        assert!(validate_layers(&config, &crates).is_ok());
    }

    // // Verifies: PROJECT_STRUCTURE §4 regla 6 (caso negativo: binding usa crate interno)
    #[test]
    fn test_negative_binding_depending_on_internal_crate() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "gravital-id-wasm".into(),
            dir: PathBuf::from("bindings/wasm"),
            layer: None,
            is_binding: true,
            dependencies: vec!["gravital-id-verifier".into()], // Ilegal: saltarse la fachada
            dev_dependencies: vec![],
            root_source: "#![forbid(unsafe_code)]\n".into(),
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("regla 6"));
    }

    // // Verifies: INV-01, PROJECT_STRUCTURE §4 (caso negativo: testkit en dependencias normales)
    #[test]
    fn test_negative_testkit_in_regular_dependencies() {
        let config = sample_config();
        let crates = vec![CrateInfo {
            name: "crate-l1".into(),
            dir: PathBuf::from("crates/crate-l1"),
            layer: Some("L1".into()),
            is_binding: false,
            dependencies: vec!["gravital-id-testkit".into()], // Solo dev-dependencies
            dev_dependencies: vec![],
            root_source: "#![no_std]\n#![forbid(unsafe_code)]\n".into(),
        }];

        let res = validate_layers(&config, &crates);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("solo está permitido en [dev-dependencies]"));
    }
}
