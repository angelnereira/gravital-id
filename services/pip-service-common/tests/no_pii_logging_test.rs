//! Pruebas rigurosas de no-PII en la capa de redacción de logs (F7.T02, REQ-PRIV-003, INV-02).
//!
//! Trazabilidad:
//! - **REQ-PRIV-003:** SDK y servicios NO DEBEN registrar datos personales ni secretos.
//! - **INV-02:** Cero datos personales, ni hashes de datos personales, ni secretos en logs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use pip_service_common::redaction::{redact_text, RedactingWriter};
use std::io::Write;

#[test]
fn redact_text_removes_jwt_tokens() {
    let raw_jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let input = format!("Recibida solicitud con credencial: {raw_jwt} para validacion");
    let redacted = redact_text(&input);

    assert!(!redacted.contains(raw_jwt));
    assert!(redacted.contains("[REDACTED_TOKEN]"));
    assert_eq!(
        redacted,
        "Recibida solicitud con credencial: [REDACTED_TOKEN] para validacion"
    );
}

#[test]
fn redact_text_removes_pem_private_keys() {
    let pem =
        "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIB3z2q6H0vN8kP...\n-----END EC PRIVATE KEY-----";
    let input = format!("Error al cargar clave: {pem}");
    let redacted = redact_text(&input);

    assert!(!redacted.contains("MHQCAQEEIB3z2q6H0vN8kP"));
    assert!(redacted.contains("[REDACTED_SECRET]"));
}

#[test]
fn redact_text_removes_email_addresses() {
    let input = "Notificacion enviada a alice.smith@example.org y a bob+tax@empresa.gob.pa";
    let redacted = redact_text(input);

    assert!(!redacted.contains("alice.smith@example.org"));
    assert!(!redacted.contains("bob+tax@empresa.gob.pa"));
    assert_eq!(
        redacted,
        "Notificacion enviada a [REDACTED_EMAIL] y a [REDACTED_EMAIL]"
    );
}

#[test]
fn redact_text_removes_phone_numbers() {
    let input = "Telefono de contacto: +507 6123-4567 o al (507) 222-3344";
    let redacted = redact_text(input);

    assert!(!redacted.contains("6123-4567"));
    assert!(!redacted.contains("222-3344"));
    assert!(redacted.contains("[REDACTED_PHONE]"));
}

#[test]
fn redact_text_removes_sensitive_json_claims_and_credentials() {
    let json_payload = r#"{"user_id": 101, "given_name": "Maria", "family_name": "Perez", "national_id": "8-123-456", "password": "MySuperSecretPassword!", "salary": "75000", "status": "ACTIVE"}"#;
    let redacted = redact_text(json_payload);

    assert!(
        !redacted.contains("Maria"),
        "given_name no debe aparecer en claro"
    );
    assert!(
        !redacted.contains("Perez"),
        "family_name no debe aparecer en claro"
    );
    assert!(
        !redacted.contains("8-123-456"),
        "national_id no debe aparecer en claro"
    );
    assert!(
        !redacted.contains("MySuperSecretPassword!"),
        "password no debe aparecer"
    );
    assert!(!redacted.contains("75000"), "salary no debe aparecer");

    // Los metadatos no sensibles de operación deben conservarse intactos
    assert!(redacted.contains("\"user_id\": 101"));
    assert!(redacted.contains("\"status\": \"ACTIVE\""));
    assert!(redacted.contains("\"given_name\": \"[REDACTED_PII]\""));
    assert!(redacted.contains("\"family_name\": \"[REDACTED_PII]\""));
    assert!(redacted.contains("\"national_id\": \"[REDACTED_PII]\""));
}

#[test]
fn redacting_writer_sanitizes_stream_without_leaks() {
    let mut sink = Vec::new();
    {
        let mut writer = RedactingWriter::new(&mut sink);
        writeln!(
            writer,
            "INFO event: user login from test@domain.com with phone +1-555-123-4567"
        )
        .unwrap();
        writeln!(
            writer,
            "DEBUG token verification: eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjMifQ.XYZ1234567890abc"
        )
        .unwrap();
        writer.flush().unwrap();
    }

    let output = String::from_utf8(sink).unwrap();
    assert!(!output.contains("test@domain.com"));
    assert!(!output.contains("+1-555-123-4567"));
    assert!(!output.contains("eyJhbGciOiJFUzI1NiJ9"));
    assert!(output.contains("[REDACTED_EMAIL]"));
    assert!(output.contains("[REDACTED_PHONE]"));
    assert!(output.contains("[REDACTED_TOKEN]"));
}

#[test]
fn non_sensitive_operational_logs_are_preserved() {
    let input = "Block 12345 finalized on chain 421614 with root 0x89d227b04381014e41e9d70fe1df49b99971d2ac; latency=45ms";
    let redacted = redact_text(input);

    assert_eq!(
        redacted, input,
        "Logs operativos no sensibles no deben alterarse"
    );
}

#[test]
fn compile_safe_regex_handles_invalid_patterns_gracefully() {
    let regex = pip_service_common::redaction::compile_safe_regex("[invalid(regex");
    assert!(!regex.is_match("hello world"));
}
