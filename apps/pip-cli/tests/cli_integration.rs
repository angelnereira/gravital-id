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

// Verifies: REQ-PRES-005, REQ-PRES-007, REQ-PERF-003, INV-01, INV-04, INV-05, INV-11
#[test]
fn cli_demo_flow_offline_e2e_full_journey() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .arg("demo-flow-offline")
        .output()
        .expect("ejecutar pip-cli demo-flow-offline");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASO 1: Generación de claves"));
    assert!(stdout.contains("PASO 2: Construcción de TrustBundle"));
    assert!(stdout.contains("PASO 3: Emisión de credencial SD-JWT"));
    assert!(stdout.contains("PASO 4: Importación en la wallet"));
    assert!(stdout.contains("PASO 5: Verificador emite solicitud firmada"));
    assert!(stdout.contains("PASO 6: Wallet valida solicitud y claims sensibles"));
    assert!(stdout.contains("PASO 7: Wallet prepara presentación con divulgación selectiva"));
    assert!(stdout.contains("PASO 8: Transcodificación binaria sin pérdidas a payload QR Base45"));
    assert!(
        stdout.contains("PASO 9: Verificador procesa payload QR y ejecuta pipeline 100% offline")
    );
    assert!(stdout.contains("Estado de Verificación: Valid"));
    assert!(stdout.contains("Flujo Offline E2E Completado con ÉXITO"));
}

// Verifies: REQ-PRES-005, REQ-PRES-007, REQ-VER-001, INV-01, INV-05, INV-11
#[test]
fn cli_subcommands_offline_flow_individual_steps() {
    let temp_dir = std::env::temp_dir().join(format!("pip_cli_flow_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let issuer_jwk = temp_dir.join("issuer.jwk.json");
    let verifier_jwk = temp_dir.join("verifier.jwk.json");
    let bundle_path = temp_dir.join("bundle.json");
    let status_path = temp_dir.join("status.jwt");
    let cred_path = temp_dir.join("credential.txt");
    let wallet_db = temp_dir.join("wallet.db");
    let cred_id_path = temp_dir.join("cred_id.txt");
    let req_path = temp_dir.join("request.b45");
    let pres_path = temp_dir.join("presentation.b45");

    // 1. dev-issuer
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "dev-issuer",
            "--out-jwk",
            issuer_jwk.to_str().unwrap(),
            "--seed",
            "11111",
        ])
        .output()
        .expect("dev-issuer");
    assert!(out.status.success());

    // 2. dev-verifier
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "dev-verifier",
            "--out-jwk",
            verifier_jwk.to_str().unwrap(),
            "--seed",
            "22222",
        ])
        .output()
        .expect("dev-verifier");
    assert!(out.status.success());

    // 3. dev-bundle with registered verifier
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "dev-bundle",
            "--issuer-uri",
            "https://issuer.cedula.example.gov",
            "--jwk",
            issuer_jwk.to_str().unwrap(),
            "--verifier-id",
            "https://verifier.example.com",
            "--verifier-jwk",
            verifier_jwk.to_str().unwrap(),
            "--out",
            bundle_path.to_str().unwrap(),
        ])
        .output()
        .expect("dev-bundle");
    assert!(out.status.success());

    // 4. dev-status
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

    // 5. issue credential with disclosures
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
            "11111",
            "--holder-seed",
            "33333",
            "--with-disclosures",
            "--out",
            cred_path.to_str().unwrap(),
        ])
        .output()
        .expect("issue");
    assert!(out.status.success());

    // 6. wallet-import into encrypted SQLite wallet
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "wallet-import",
            "--credential",
            cred_path.to_str().unwrap(),
            "--holder-seed",
            "33333",
            "--db",
            wallet_db.to_str().unwrap(),
            "--out-id",
            cred_id_path.to_str().unwrap(),
        ])
        .output()
        .expect("wallet-import");
    assert!(out.status.success());
    assert!(cred_id_path.exists());

    // 7. verify-request: generate signed verification request asking for sensitive claim
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "verify-request",
            "--verifier-id",
            "https://verifier.example.com",
            "--claims",
            "given_name,document_number",
            "--sign-seed",
            "22222",
            "--format",
            "base45",
            "--out",
            req_path.to_str().unwrap(),
        ])
        .output()
        .expect("verify-request");
    assert!(out.status.success());
    assert!(req_path.exists());

    // 8. wallet-present: wallet validates request against bundle and produces QR Base45 presentation
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "wallet-present",
            "--request",
            req_path.to_str().unwrap(),
            "--credential",
            cred_path.to_str().unwrap(),
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--holder-seed",
            "33333",
            "--format",
            "base45",
            "--out",
            pres_path.to_str().unwrap(),
        ])
        .output()
        .expect("wallet-present");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(pres_path.exists());
    let pres_content = fs::read_to_string(&pres_path).unwrap();
    assert!(pres_content.starts_with("GID1:"));

    // 9. verify: verifier decodes Base45 QR payload and verifies offline
    let out = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "verify",
            "--presentation",
            pres_path.to_str().unwrap(),
            "--request",
            req_path.to_str().unwrap(),
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
    assert!(stdout.contains("Detectado payload QR Base45"));
    assert!(stdout.contains("Estado resultante: Valid"));

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
