//! Automatización y tareas de mantenimiento del repositorio Gravital ID (`xtask`).

#![forbid(unsafe_code)]
// SAFETY/CLI: xtask es una herramienta de línea de comandos que se comunica con el desarrollador por stdout.
#![allow(clippy::print_stdout)]

mod conformance;
mod error_codes;
mod generate_vectors;
mod layers;
mod trace;

use std::path::Path;

fn main() -> anyhow::Result<()> {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No se pudo determinar la raíz del workspace"))?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("check-layers") => {
            layers::run_check_layers(workspace_root)?;
            Ok(())
        }
        Some("trace") => {
            trace::run_trace(workspace_root)?;
            Ok(())
        }
        Some("gen-conformance-vectors") => {
            generate_vectors::generate_vectors(workspace_root)?;
            Ok(())
        }
        Some("conformance") => {
            conformance::run_conformance(workspace_root)?;
            Ok(())
        }
        Some("check-error-codes") => {
            error_codes::run_check_error_codes(workspace_root)?;
            Ok(())
        }
        Some(cmd) => {
            anyhow::bail!("Comando desconocido en xtask: {cmd}");
        }
        None => {
            println!("Uso: cargo xtask <check-layers|trace|check-error-codes|conformance|gen-conformance-vectors>");
            Ok(())
        }
    }
}
