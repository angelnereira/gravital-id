//! Capa de redacción de logs para protección de datos personales y secretos (F7.T02, REQ-PRIV-003, INV-02).
//!
//! Trazabilidad:
//! - **REQ-PRIV-003:** SDK y servicios NO DEBEN registrar datos personales ni secretos.
//! - **INV-02:** Cero datos personales, ni hashes de datos personales, ni secretos en logs.

use regex::Regex;
use std::io::{self, Write};
use std::sync::OnceLock;

/// Compila una expresión regular de manera robusta sin pánicos ni unwraps, usando un fallback inocuo ante errores.
#[must_use]
pub fn compile_safe_regex(pattern: &str) -> Regex {
    if let Ok(r) = Regex::new(pattern) {
        r
    } else if let Ok(fallback) = Regex::new(r"\b\B") {
        fallback
    } else if let Ok(empty) = Regex::new("") {
        empty
    } else {
        // En el caso inalcanzable de fallo en regex vacía, dormir para no desperdiciar ciclos
        #[allow(clippy::empty_loop)]
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

fn compile_regex(pattern: &str) -> Regex {
    compile_safe_regex(pattern)
}

/// Expresión regular compilada para detectar tokens JWS/JWT en serialización compacta (Base64URL con 2 puntos).
fn jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX
        .get_or_init(|| compile_regex(r"ey[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}"))
}

/// Expresión regular para detectar bloques de clave privada PEM.
fn pem_private_key_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        compile_regex(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
    })
}

/// Expresión regular para detectar direcciones de correo electrónico.
fn email_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| compile_regex(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"))
}

/// Expresión regular para detectar números de teléfono con formatos estándar acotados por límites de palabra.
fn phone_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        compile_regex(
            r"(?:(?:\b|\+)[0-9]{1,3}[-.\s]?)?(?:\([0-9]{2,4}\)[-.\s]?)?\b[0-9]{3,4}[-.\s]?[0-9]{4}\b",
        )
    })
}

/// Expresión regular para detectar campos sensibles en JSON o pares clave-valor.
fn sensitive_json_field_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        compile_regex(
            r#"(?i)("?(?:password|secret|private_key|privatekey|seed|given_name|family_name|fullname|national_id|tax_id|ssn|document_number|birth_date|salary|income|portrait|photo|fingerprint)"?\s*[:=]\s*)"(?:[^"\\]|\\.)*""#,
        )
    })
}

// Verifies: REQ-PRIV-003, INV-02
/// Sanitiza y redacta cualquier dato personal, credencial o secreto presente en el texto.
#[must_use]
pub fn redact_text(input: &str) -> String {
    // 1. Redactar claves privadas PEM
    let s = pem_private_key_regex().replace_all(input, "[REDACTED_SECRET]");

    // 2. Redactar tokens JWS/JWT completos
    let s = jwt_regex().replace_all(&s, "[REDACTED_TOKEN]");

    // 3. Redactar campos sensibles estructurados en JSON o formato clave=valor
    let s = sensitive_json_field_regex().replace_all(&s, "${1}\"[REDACTED_PII]\"");

    // 4. Redactar correos electrónicos
    let s = email_regex().replace_all(&s, "[REDACTED_EMAIL]");

    // 5. Redactar números de teléfono (solo si tienen longitud adecuada)
    let s = phone_regex().replace_all(&s, "[REDACTED_PHONE]");

    s.into_owned()
}

/// Adaptador `io::Write` que intercepta cualquier flujo de bytes de logging y aplica redacción antes de escribir.
#[derive(Debug)]
pub struct RedactingWriter<W: Write> {
    inner: W,
}

impl<W: Write> RedactingWriter<W> {
    /// Crea un nuevo escritor redactor sobre el escritor subyacente.
    pub const fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let redacted = redact_text(&text);
        self.inner.write_all(redacted.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
