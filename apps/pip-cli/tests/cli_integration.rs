#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de la CLI `pip-cli` / `gid-cli` (F4.T12).
//!
//! Trazabilidad:
//! - **REQ-VER-001:** Verificación offline completa mediante subcomandos de CLI.
//! - **REQ-SDK-008:** Sans-I/O orquestado por la CLI.
//! - **INV-01:** Verificación sin red.
//! - **INV-04:** Cuatro estados normativos.
//! - **INV-05:** Fail-closed determinista.

use std::fs;
use std::process::Command;

// Verifies: REQ-VER-001, INV-01, INV-04, INV-05
#[test]
fn cli_demo_offline_reproduces_all_four_states() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .arg("demo-offline")
        .output()
        .expect("ejecutar pip-cli demo-offline");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CASO 1: Presentación válida con estado fresco"));
    assert!(stdout.contains("CASO 2: Presentación válida pero snapshot de estado antiguo"));
    assert!(stdout.contains("CASO 3: Verificación offline sin snapshot de estado disponible"));
    assert!(stdout.contains("CASO 4: Credencial revocada en la lista de estado"));
    assert!(stdout.contains("Demostración finalizada con ÉXITO"));
}

// Verifies: REQ-VER-001
#[test]
fn cli_subcommands_e2e_dev_issuer_bundle_status_issue_and_verify() {
    let temp_dir = std::env::temp_dir().join(format!("pip_cli_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let jwk_path = temp_dir.join("issuer.jwk.json");
    let bundle_path = temp_dir.join("bundle.json");
    let status_path = temp_dir.join("status.jwt");
    let pres_path = temp_dir.join("presentation.txt");

    // 1. dev-issuer
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "dev-issuer",
            "--out-jwk",
            jwk_path.to_str().unwrap(),
            "--seed",
            "12345",
        ])
        .output()
        .expect("dev-issuer");
    assert!(out.status.success());
    assert!(jwk_path.exists());

    // 2. dev-bundle
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "dev-bundle",
            "--issuer-uri",
            "https://issuer.cedula.example.gov",
            "--kid",
            "key-2026-issuer-01",
            "--jwk",
            jwk_path.to_str().unwrap(),
            "--out",
            bundle_path.to_str().unwrap(),
        ])
        .output()
        .expect("dev-bundle");
    assert!(out.status.success());
    assert!(bundle_path.exists());

    // 3. dev-status
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "dev-status",
            "--issuer-uri",
            "https://issuer.cedula.example.gov",
            "--uri",
            "https://status.cedula.example.gov/lists/2026-10",
            "--bits",
            "2",
            "--values",
            "0,0,0,0",
            "--out",
            status_path.to_str().unwrap(),
        ])
        .output()
        .expect("dev-status");
    assert!(out.status.success());
    assert!(status_path.exists());

    // 4. issue
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "issue",
            "--issuer-uri",
            "https://issuer.cedula.example.gov",
            "--vct",
            "https://credentials.gravital.io/vct/personal/id-v1",
            "--status-uri",
            "https://status.cedula.example.gov/lists/2026-10",
            "--status-idx",
            "0",
            "--seed",
            "12345",
            "--out",
            pres_path.to_str().unwrap(),
        ])
        .output()
        .expect("issue");
    assert!(out.status.success());
    assert!(pres_path.exists());

    // 5. verify offline
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "verify",
            "--presentation",
            pres_path.to_str().unwrap(),
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--status-snapshot",
            status_path.to_str().unwrap(),
            "--now",
            "1770000000",
        ])
        .output()
        .expect("verify");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Estado resultante: Valid"));

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
