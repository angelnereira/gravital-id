#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración para la Demostración del Hito M1 y Legibilidad QR (F5.T13, F5.T14).
//!
//! Trazabilidad:
//! - **REQ-PRES-005:** Transporte QR Base45 y visualización de códigos QR.
//! - **REQ-PERF-003:** Presupuesto de presentación offline y rendimiento de verificación.
//! - **REQ-STOR-001:** Almacenamiento cifrado en reposo (DEK/KEK).
//! - **REQ-STOR-004:** Consistencia atómica en SQLite.
//! - **REQ-PRIV-005:** Ausencia estricta de PII en almacenamiento persistente.
//! - **INV-01:** Verificación sin red.
//! - **INV-02:** Cero datos personales o hashes en almacenamiento.
//! - **INV-04:** Cuatro estados normativos en el pipeline.
//! - **INV-05:** Fail-closed determinista.
//! - **INV-11:** Inyección explícita de tiempo y aleatoriedad determinista.

use std::process::Command;

// Verifies: REQ-PRES-005, REQ-PERF-003, REQ-STOR-001, REQ-STOR-004, REQ-PRIV-005, INV-01, INV-02, INV-04, INV-05, INV-11
#[test]
fn cli_demo_m1_completes_all_three_scenarios_and_forensic_audit() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .arg("demo-m1")
        .output()
        .expect("ejecutar pip-cli demo-m1");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verificación de los tres escenarios MVP normativos
    assert!(
        stdout.contains("[ESCENARIO MVP-01] Verificación 100% offline y sans-I/O"),
        "Debe contener encabezado de MVP-01"
    );
    assert!(
        stdout.contains("MVP-01 Aprobado: Resultado 'Valid' verificado sin acceso a la red"),
        "MVP-01 debe concluir como Valid"
    );

    assert!(
        stdout.contains("[ESCENARIO MVP-02] Rechazo determinista de manipulaciones"),
        "Debe contener encabezado de MVP-02"
    );
    assert!(
        stdout.contains("Caso 2A: Firma de emisor manipulada rechazada deterministamente"),
        "Debe probar Caso 2A"
    );
    assert!(
        stdout.contains("Caso 2B: Emisor no autorizado rechazado deterministamente"),
        "Debe probar Caso 2B"
    );
    assert!(
        stdout.contains("Caso 2C: Credencial revocada rechazada deterministamente"),
        "Debe probar Caso 2C"
    );
    assert!(
        stdout.contains("Caso 2D: Divulgación manipulada rechazada deterministamente"),
        "Debe probar Caso 2D"
    );

    assert!(
        stdout.contains("[ESCENARIO MVP-03] Rechazo de replay con estado persistente SQLite"),
        "Debe contener encabezado de MVP-03"
    );
    assert!(
        stdout.contains("Intento 2 (Replay idéntico): Invalid determinista"),
        "MVP-03 debe rechazar el replay"
    );

    // Auditoría forense de almacenamiento
    assert!(
        stdout.contains("AUDITORÍA FORENSE"),
        "Debe realizar auditoría forense"
    );
    assert!(
        stdout.contains("Inspección forense superada: 0 strings de PII o presentaciones en claro"),
        "Cero datos personales en SQLite verificado"
    );

    // Conclusión final
    assert!(
        stdout.contains("HITO M1 & GATE G5: DEMOSTRACIÓN COMPLETADA CON ÉXITO"),
        "Demostración M1 aprobada"
    );
}

// Verifies: REQ-PRES-005
#[test]
fn cli_qr_render_produces_valid_terminal_blocks() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "qr-render",
            "--data",
            "GID1:254-TEST-PAYLOAD-OFFLINE-REPRESENTATION",
        ])
        .output()
        .expect("ejecutar pip-cli qr-render");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains('█') || stdout.contains('▀') || stdout.contains('▄'));
}

// Verifies: REQ-PRES-005
#[test]
fn cli_qr_render_with_invert_produces_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args([
            "qr-render",
            "--data",
            "GID1:254-TEST-PAYLOAD-OFFLINE-INVERTED",
            "--invert",
        ])
        .output()
        .expect("ejecutar pip-cli qr-render --invert");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains('█') || stdout.contains('▀') || stdout.contains('▄'));
}

// Verifies: REQ-PRES-005
#[test]
fn cli_qr_render_missing_data_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .arg("qr-render")
        .output()
        .expect("ejecutar pip-cli qr-render sin args");

    assert!(!output.status.success());
}

// Verifies: REQ-PRES-005, REQ-PERF-003, INV-01
#[test]
fn cli_demo_flow_offline_with_qr_renders_qr() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .args(["demo-flow-offline", "--qr"])
        .output()
        .expect("ejecutar pip-cli demo-flow-offline --qr");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Visualización de código QR listo para escaneo"));
    assert!(stdout.contains("Flujo Offline E2E Completado con ÉXITO"));
}
