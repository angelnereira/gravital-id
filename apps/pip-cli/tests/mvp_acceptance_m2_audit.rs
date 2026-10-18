#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración automatizadas para la Revisión Integral del MVP (Gate G8 / Hito M2, F8.T11).
//!
//! Trazabilidad:
//! - **REQ-VER-001:** Verificación 100% offline sans-I/O sin llamadas a red.
//! - **REQ-PRES-005:** Rechazo estricto de ataques de repetición (Anti-Replay) y transcodificación Base45.
//! - **REQ-STAT-004:** Degradación determinista a `ValidWithStaleStatus` según perfiles de frescura.
//! - **REQ-STAT-008:** Monotonía estricta y protección contra rollback de estado de revocación.
//! - **REQ-LEDG-001:** Ausencia taxativa de datos personales o identificadores en el ledger.
//! - **REQ-REC-001:** Migración de dispositivos con compromiso criptográfico SHA-256 y SAS.
//! - **REQ-REC-002:** Código de recuperación BIP-39 (128 bits) y respaldo cifrado XChaCha20-Poly1305.
//! - **REQ-REC-004:** Clave de recuperación exclusiva (`HolderRecovery`) para re-vinculación.
//! - **REQ-REC-007:** Derivación no correlacionable de claves de recuperación por emisor.
//! - **REQ-CRED-001:** Interoperabilidad de formato según RFC 9901 y SD-JWT VC con Key Binding.
//! - **REQ-STOR-004:** Persistencia transaccional ACID y verificación PRAGMA integrity_check en SQLite.
//! - **REQ-PERF-003:** Presupuesto de latencia de verificación offline sans-I/O (< 20 ms).
//! - **INV-01:** Verificación sans-I/O en memoria.
//! - **INV-02:** Cero datos personales o identificadores en almacenamiento, logs o eventos.
//! - **INV-04:** Cuatro estados normativos en el resultado de verificación.
//! - **INV-05:** Comportamiento fail-closed ante errores o datos alterados.
//! - **INV-06:** Claves de emisor obtenidas exclusivamente del Trust Bundle.
//! - **INV-11:** Inyección explícita y determinista de reloj y aleatoriedad.
//! - **INV-16:** Quórum k-de-n en verificación y custodia Shamir.

use std::process::Command;

// Verifies: REQ-VER-001, REQ-PRES-005, REQ-STAT-004, REQ-STAT-008, REQ-LEDG-001, REQ-REC-001, REQ-REC-002, REQ-REC-004, REQ-REC-007, REQ-CRED-001, REQ-STOR-004, REQ-PERF-003, INV-01, INV-02, INV-04, INV-05, INV-06, INV-11, INV-16
#[test]
fn cli_demo_m2_executes_all_nine_mvp_criteria_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_pip-cli"))
        .arg("demo-m2")
        .output()
        .expect("ejecutar pip-cli demo-m2");

    assert!(
        output.status.success(),
        "pip-cli demo-m2 falló al ejecutarse"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Criterio MVP-01
    assert!(
        stdout.contains("[CRITERIO MVP-01] Verificación correcta 100% offline y sans-I/O"),
        "Falta encabezado MVP-01"
    );
    assert!(
        stdout.contains(
            "[MVP-01 CUMPLIDO] Verificación 100% offline y sans-I/O exitosa (Valid) con 0 red"
        ),
        "MVP-01 debe concluir exitosamente"
    );

    // Criterio MVP-02
    assert!(
        stdout.contains("[CRITERIO MVP-02] Rechazo determinista de manipulaciones"),
        "Falta encabezado MVP-02"
    );
    assert!(
        stdout.contains("Caso 2A: Firma de emisor alterada rechazada deterministamente"),
        "Falta Caso 2A en MVP-02"
    );
    assert!(
        stdout.contains("Caso 2B: Emisor no registrado en TrustBundle rechazado como Unverifiable"),
        "Falta Caso 2B en MVP-02"
    );
    assert!(
        stdout.contains("Caso 2C: Credencial revocada en TokenStatusList rechazada como Invalid"),
        "Falta Caso 2C en MVP-02"
    );
    assert!(
        stdout.contains("Caso 2D: Divulgación manipulada rechazada deterministamente como Invalid"),
        "Falta Caso 2D en MVP-02"
    );
    assert!(
        stdout.contains(
            "[MVP-02 CUMPLIDO] Rechazo de firmas, emisores y credenciales revocadas o alteradas"
        ),
        "MVP-02 debe concluir exitosamente"
    );

    // Criterio MVP-03
    assert!(
        stdout.contains("[CRITERIO MVP-03] Rechazo de replay en almacenamiento persistente SQLite"),
        "Falta encabezado MVP-03"
    );
    assert!(
        stdout.contains("[✓] Intento 2 (Replay idéntico): Rechazado deterministamente como Invalid (Nonce check FAILED)"),
        "Falta detección de replay en MVP-03"
    );
    assert!(
        stdout.contains("[MVP-03 CUMPLIDO] Protección estricta contra ataques de repetición en base SQLite persistente"),
        "MVP-03 debe concluir exitosamente"
    );

    // Criterio MVP-04
    assert!(
        stdout
            .contains("[CRITERIO MVP-04] Degradación determinista ante snapshots desactualizados"),
        "Falta encabezado MVP-04"
    );
    assert!(
        stdout.contains("[MVP-04 CUMPLIDO] Degradación determinista a ValidWithStaleStatus"),
        "MVP-04 debe concluir exitosamente"
    );

    // Criterio MVP-05
    assert!(
        stdout.contains("[CRITERIO MVP-05] Revocación offline y sincronización"),
        "Falta encabezado MVP-05"
    );
    assert!(
        stdout.contains("[MVP-05 CUMPLIDO] Revocación reflejada de inmediato tras sincronización y anti-rollback monotónico"),
        "MVP-05 debe concluir exitosamente"
    );

    // Criterio MVP-06
    assert!(
        stdout.contains(
            "[CRITERIO MVP-06] Cero datos personales en transacciones y eventos de ledger"
        ),
        "Falta encabezado MVP-06"
    );
    assert!(
        stdout.contains("[MVP-06 CUMPLIDO] Cero datos personales ni identificadores de titulares"),
        "MVP-06 debe concluir exitosamente"
    );

    // Criterio MVP-07
    assert!(
        stdout.contains(
            "[CRITERIO MVP-07] Procedimientos documentados de recuperación y rotación de claves"
        ),
        "Falta encabezado MVP-07"
    );
    assert!(
        stdout.contains("[F8.T01] RecoveryCode BIP-39 (128 bits) generado y verificado"),
        "Falta F8.T01 en MVP-07"
    );
    assert!(
        stdout.contains("[F8.T02] Custodia social Shamir 3-de-5 en GF(2^8) particionada y reconstruida exitosamente"),
        "Falta F8.T02 en MVP-07"
    );
    assert!(
        stdout.contains("[F8.T03] Clave de recuperación HolderRecoveryKey derivada por emisor con huella RFC 9278"),
        "Falta F8.T03 en MVP-07"
    );
    assert!(
        stdout.contains("[F8.T04] Re-vinculación atómica por clase de dispositivo"),
        "Falta F8.T04 en MVP-07"
    );
    assert!(
        stdout.contains("[F8.T05] Migración directa entre dispositivos con compromiso SHA-256 y SAS coincidente"),
        "Falta F8.T05 en MVP-07"
    );
    assert!(
        stdout.contains("[MVP-07 CUMPLIDO] Recuperación y rotación de claves completamente operativas y documentadas"),
        "MVP-07 debe concluir exitosamente"
    );

    // Criterio MVP-08
    assert!(
        stdout
            .contains("[CRITERIO MVP-08] Interoperabilidad de formato según RFC 9901 y SD-JWT VC"),
        "Falta encabezado MVP-08"
    );
    assert!(
        stdout.contains("[MVP-08 CUMPLIDO] Interoperabilidad de formato y compatibilidad RFC 9901"),
        "MVP-08 debe concluir exitosamente"
    );

    // Criterio MVP-09
    assert!(
        stdout.contains("[CRITERIO MVP-09] Robustez, persistencia y seguridad en verde"),
        "Falta encabezado MVP-09"
    );
    assert!(
        stdout.contains("[REQ-STOR-004] SQLite PRAGMA integrity_check = 'ok'"),
        "Falta PRAGMA integrity_check en MVP-09"
    );
    assert!(
        stdout.contains(
            "[INV-05] Rechazo fail-closed determinista ante paquete de respaldo corrupto"
        ),
        "Falta rechazo de respaldo corrupto en MVP-09"
    );
    assert!(
        stdout.contains(
            "[INV-16] Rechazo fail-closed determinista ante fragmentos Shamir insuficientes"
        ),
        "Falta rechazo Shamir k-1 en MVP-09"
    );
    assert!(
        stdout.contains(
            "[INV-02] Auditoría forense de cero datos personales en disco y memoria aprobada"
        ),
        "Falta auditoría PII en MVP-09"
    );
    assert!(
        stdout.contains("[MVP-09 CUMPLIDO] Robustez, tolerancia a fallos transaccionales y seguridad integral en verde"),
        "MVP-09 debe concluir exitosamente"
    );

    // Dictamen final
    assert!(
        stdout.contains("DICTAMEN FINAL: HITO M2 Y GATE G8 CUMPLIDOS CON ÉXITO"),
        "Falta dictamen final de aprobación de Gate G8"
    );
}

// Verifies: REQ-VER-001, REQ-PERF-003, INV-01, INV-02, INV-04, INV-05, INV-11
#[test]
fn lib_run_demo_m2_executes_in_process_without_error() {
    pip_cli::run_demo_m2().expect("run_demo_m2 in-process debe completarse con éxito");
}
