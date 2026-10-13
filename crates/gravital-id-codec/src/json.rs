//! Lector JSON acotado y estricto (F2.T03, REQ-CRED-009, REQ-VER-008).
//!
//! Implementa un subconjunto de RFC 8259 con las restricciones del perfil:
//! - **Acotado**: tamaño de entrada, profundidad, elementos por contenedor y
//!   longitud de cadena (REQ-VER-008).
//! - **Sin miembros duplicados**: cada objeto rechaza claves repetidas
//!   (REQ-CRED-009).
//! - **UTF-8 estricto**: la entrada de bytes se valida con
//!   `core::str::from_utf8`; las cadenas rechazan caracteres de control sin
//!   escapar y suplentes `\uD800`–`\uDFFF` huérfanos.
//! - **Números acotados**: enteros fuera de `i64`/`u64` y flotantes no finitos
//!   se rechazan (nada de `Infinity`/`NaN`, nada de desbordamientos silenciosos).
//!
//! El parser es descendente recursivo con profundidad acotada por [`Limits`], de
//! modo que no hay desbordamiento de pila (INV-10), y no usa indexaciones ni
//! aritmética que puedan entrar en pánico.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use gravital_id_types::{ErrorCode, GidError};

/// Tamaño máximo de entrada por defecto (64 KiB).
///
/// Alineado con el tamaño máximo de credencial SD-JWT en línea
/// (`CRYPTO_PROFILES.md §5.2`).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024;

/// Profundidad máxima de anidamiento por defecto.
///
/// Cota de implementación del perfil (REQ-VER-008): los documentos del
/// protocolo (cabeceras JWS, claims SD-JWT, bundles) son llanos o tienen pocos
/// niveles; el valor se revisará con las mediciones de F3.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Elementos máximos por contenedor (array u objeto) por defecto.
pub const DEFAULT_MAX_ELEMENTS: usize = 10_000;

/// Longitud máxima de cadena (en bytes UTF-8) por defecto.
pub const DEFAULT_MAX_STRING_BYTES: usize = 8 * 1024;

/// Límites de parseo aplicables a un documento JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Tamaño máximo de la entrada en bytes.
    pub max_input_bytes: usize,
    /// Profundidad máxima de anidamiento (arrays y objetos).
    pub max_depth: usize,
    /// Número máximo de elementos por contenedor.
    pub max_elements: usize,
    /// Longitud máxima de cada cadena en bytes UTF-8.
    pub max_string_bytes: usize,
}

impl Limits {
    /// Límites por defecto del perfil.
    #[must_use]
    pub const fn profile_default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_elements: DEFAULT_MAX_ELEMENTS,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::profile_default()
    }
}

/// Número JSON con rango acotado.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Number {
    /// Entero sin signo que cabe en `u64`.
    PosInt(u64),
    /// Entero negativo que cabe en `i64`.
    NegInt(i64),
    /// Flotante finito (literales con fracción o exponente).
    Float(f64),
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PosInt(v) => write!(f, "{v}"),
            Self::NegInt(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
        }
    }
}

/// Valor JSON parseado.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` o `false`.
    Bool(bool),
    /// Número acotado (ver [`Number`]).
    Number(Number),
    /// Cadena UTF-8 ya decodificada (escapes resueltos).
    String(String),
    /// Array de valores, en orden de aparición.
    Array(Vec<Value>),
    /// Objeto como lista ordenada de pares clave/valor.
    ///
    /// Las claves son únicas: el parser rechaza duplicados (REQ-CRED-009).
    Object(Vec<(String, Value)>),
}

impl Value {
    /// Tipo del valor, para mensajes de error y para las capas superiores (F3).
    #[allow(dead_code)] // Se consumirá desde pip-credential en F3; se mantiene probado aquí.
    fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }

    /// Vista de cadena si el valor es una cadena.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Busca un miembro por nombre en un objeto.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Object(entries) => entries
                .iter()
                .find(|(key, _)| key.as_str() == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

/// Error interno de parseo (motivo estable).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseError {
    /// Entrada por encima del límite de bytes.
    InputTooLarge,
    /// Fin de entrada inesperado.
    UnexpectedEof,
    /// Token inesperado en la posición indicada.
    UnexpectedToken(String),
    /// Carácter de control sin escapar en una cadena.
    UnescapedControlChar,
    /// Secuencia de escape inválida.
    InvalidEscape,
    /// Par suplente `\uD800`–`\uDFFF` huérfano o mal formado.
    InvalidUnicodeEscape,
    /// Literal inválido (`true`, `false`, `null`, número).
    InvalidLiteral,
    /// Número entero fuera del rango `i64`/`u64`.
    IntegerOutOfRange,
    /// Número flotante no finito (desbordamiento de `f64`).
    NumberNotFinite,
    /// Objeto con miembros duplicados.
    DuplicateMember(String),
    /// Estructura desbalanceada (falta `}` o `]`).
    UnbalancedStructure,
    /// Contenedor con más elementos que el límite.
    TooManyElements,
    /// Anidamiento más profundo que el límite.
    TooDeep,
    /// Cadena más larga que el límite.
    StringTooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("JSON input exceeds the size limit"),
            Self::UnexpectedEof => f.write_str("unexpected end of JSON input"),
            Self::UnexpectedToken(token) => write!(f, "unexpected token: {token}"),
            Self::UnescapedControlChar => f.write_str("unescaped control character in JSON string"),
            Self::InvalidEscape => f.write_str("invalid escape sequence in JSON string"),
            Self::InvalidUnicodeEscape => {
                f.write_str("invalid or unpaired unicode escape in JSON string")
            }
            Self::InvalidLiteral => f.write_str("invalid JSON literal"),
            Self::IntegerOutOfRange => f.write_str("JSON integer outside i64/u64 range"),
            Self::NumberNotFinite => f.write_str("JSON number is not finite"),
            Self::DuplicateMember(key) => write!(f, "duplicate object member: {key}"),
            Self::UnbalancedStructure => f.write_str("unbalanced JSON structure"),
            Self::TooManyElements => f.write_str("too many elements in JSON container"),
            Self::TooDeep => f.write_str("JSON nesting exceeds the depth limit"),
            Self::StringTooLong => f.write_str("JSON string exceeds the length limit"),
        }
    }
}

/// Convierte el motivo interno en el error canónico del protocolo.
fn to_gid_error(reason: ParseError) -> GidError {
    GidError::new(ErrorCode::MalformedMessage, reason.to_string())
}

/// Parser descendente recursivo con estado de posición y límites.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    limits: &'a Limits,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: &'a Limits) -> Self {
        Self {
            bytes,
            pos: 0,
            limits,
        }
    }

    /// Byte en la posición actual, sin avanzar.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Byte en `offset` desde la posición actual.
    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos.saturating_add(offset)).copied()
    }

    /// Consume un byte y avanza.
    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(byte)
    }

    /// Consume un byte concreto o falla.
    fn expect(&mut self, expected: u8) -> Result<(), GidError> {
        match self.peek() {
            Some(found) if found == expected => {
                self.pos = self.pos.saturating_add(1);
                Ok(())
            }
            Some(found) => {
                let token = (found as char).to_string();
                Err(to_gid_error(ParseError::UnexpectedToken(token)))
            }
            None => Err(to_gid_error(ParseError::UnexpectedEof)),
        }
    }

    /// Espacios en blanco RFC 8259.
    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            match byte {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos = self.pos.saturating_add(1),
                _ => break,
            }
        }
    }

    /// Punto de entrada: un valor JSON seguido solo de espacios en blanco.
    fn parse_document(&mut self) -> Result<Value, GidError> {
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        if self.pos != self.bytes.len() {
            let token = self
                .peek()
                .map(|b| (b as char).to_string())
                .unwrap_or_else(|| "end of input".to_string());
            return Err(to_gid_error(ParseError::UnexpectedToken(token)));
        }
        Ok(value)
    }

    /// Valor JSON en la posición actual.
    fn parse_value(&mut self, depth: usize) -> Result<Value, GidError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => self.parse_literal("true", Value::Bool(true)),
            Some(b'f') => self.parse_literal("false", Value::Bool(false)),
            Some(b'n') => self.parse_literal("null", Value::Null),
            Some(b'-') | Some(b'0'..=b'9') => Ok(Value::Number(self.parse_number()?)),
            Some(other) => {
                let token = (other as char).to_string();
                Err(to_gid_error(ParseError::UnexpectedToken(token)))
            }
            None => Err(to_gid_error(ParseError::UnexpectedEof)),
        }
    }

    /// Literal exacto (`true`, `false`, `null`).
    fn parse_literal(&mut self, literal: &str, value: Value) -> Result<Value, GidError> {
        let bytes = literal.as_bytes();
        for (index, expected) in bytes.iter().enumerate() {
            match self.peek_at(index) {
                Some(found) if found == *expected => {}
                _ => return Err(to_gid_error(ParseError::InvalidLiteral)),
            }
        }
        self.pos = self.pos.saturating_add(bytes.len());
        Ok(value)
    }

    /// Objeto `{ ... }` con claves únicas.
    fn parse_object(&mut self, depth: usize) -> Result<Value, GidError> {
        self.expect(b'{')?;
        let depth_now = depth.saturating_add(1);
        if depth_now > self.limits.max_depth {
            return Err(to_gid_error(ParseError::TooDeep));
        }

        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        self.skip_whitespace();

        if self.peek() == Some(b'}') {
            self.pos = self.pos.saturating_add(1);
            return Ok(Value::Object(entries));
        }

        loop {
            if entries.len() >= self.limits.max_elements {
                return Err(to_gid_error(ParseError::TooManyElements));
            }
            self.skip_whitespace();
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                return Err(to_gid_error(ParseError::DuplicateMember(key)));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.parse_value(depth_now)?;
            entries.push((key, value));

            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                Some(other) => {
                    let token = (other as char).to_string();
                    return Err(to_gid_error(ParseError::UnexpectedToken(token)));
                }
                None => return Err(to_gid_error(ParseError::UnbalancedStructure)),
            }
        }

        Ok(Value::Object(entries))
    }

    /// Array `[ ... ]`.
    fn parse_array(&mut self, depth: usize) -> Result<Value, GidError> {
        self.expect(b'[')?;
        let depth_now = depth.saturating_add(1);
        if depth_now > self.limits.max_depth {
            return Err(to_gid_error(ParseError::TooDeep));
        }

        let mut items: Vec<Value> = Vec::new();
        self.skip_whitespace();

        if self.peek() == Some(b']') {
            self.pos = self.pos.saturating_add(1);
            return Ok(Value::Array(items));
        }

        loop {
            if items.len() >= self.limits.max_elements {
                return Err(to_gid_error(ParseError::TooManyElements));
            }
            let value = self.parse_value(depth_now)?;
            items.push(value);

            self.skip_whitespace();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                Some(other) => {
                    let token = (other as char).to_string();
                    return Err(to_gid_error(ParseError::UnexpectedToken(token)));
                }
                None => return Err(to_gid_error(ParseError::UnbalancedStructure)),
            }
        }

        Ok(Value::Array(items))
    }

    /// Cadena JSON con escapes resueltos.
    fn parse_string(&mut self) -> Result<String, GidError> {
        self.expect(b'"')?;
        let mut out = String::new();

        loop {
            let byte = match self.peek() {
                Some(byte) => byte,
                None => return Err(to_gid_error(ParseError::UnexpectedEof)),
            };

            match byte {
                b'"' => {
                    self.pos = self.pos.saturating_add(1);
                    if out.len() > self.limits.max_string_bytes {
                        return Err(to_gid_error(ParseError::StringTooLong));
                    }
                    return Ok(out);
                }
                0x00..=0x1F => {
                    return Err(to_gid_error(ParseError::UnescapedControlChar));
                }
                b'\\' => {
                    self.pos = self.pos.saturating_add(1);
                    self.parse_escape(&mut out)?;
                }
                0x20..=0x7F => {
                    self.pos = self.pos.saturating_add(1);
                    out.push(byte as char);
                }
                // Bytes UTF-8 multibyte: se copian tal cual (la entrada completa
                // ya se validó como UTF-8 estricta en parse_bytes/parse).
                _ => {
                    // La secuencia UTF-8 completa ocupa `char_len` bytes: se
                    // consumen todos de una vez para no reprocesar las
                    // continuaciones.
                    let char_len = utf8_len(byte)?;
                    let start = self.pos;
                    let end = start.saturating_add(char_len);
                    let slice = self
                        .bytes
                        .get(start..end)
                        .ok_or_else(|| to_gid_error(ParseError::InvalidLiteral))?;
                    let text = core::str::from_utf8(slice)
                        .map_err(|_| to_gid_error(ParseError::InvalidLiteral))?;
                    self.pos = end;
                    out.push_str(text);
                }
            }

            if out.len() > self.limits.max_string_bytes {
                return Err(to_gid_error(ParseError::StringTooLong));
            }
        }
    }

    /// Secuencia de escape (el `\` ya se consumió).
    fn parse_escape(&mut self, out: &mut String) -> Result<(), GidError> {
        let byte = match self.peek() {
            Some(byte) => byte,
            None => return Err(to_gid_error(ParseError::UnexpectedEof)),
        };
        self.pos = self.pos.saturating_add(1);

        let simple = match byte {
            b'"' => Some('"'),
            b'\\' => Some('\\'),
            b'/' => Some('/'),
            b'b' => Some('\u{0008}'),
            b'f' => Some('\u{000C}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            _ => None,
        };
        if let Some(ch) = simple {
            out.push(ch);
            return Ok(());
        }

        if byte != b'u' {
            return Err(to_gid_error(ParseError::InvalidEscape));
        }

        let first = self.parse_hex4()?;
        // Pares surrogados: \uD800-\uDBFF seguido de \uDC00-\uDFFF.
        if (0xD800..=0xDBFF).contains(&first) {
            self.expect(b'\\')?;
            match self.peek() {
                Some(b'u') => {
                    self.pos = self.pos.saturating_add(1);
                }
                _ => return Err(to_gid_error(ParseError::InvalidUnicodeEscape)),
            }
            let second = self.parse_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(to_gid_error(ParseError::InvalidUnicodeEscape));
            }
            let high = u32::from(first).saturating_sub(0xD800);
            let low = u32::from(second).saturating_sub(0xDC00);
            let combined = high
                .wrapping_shl(10)
                .saturating_add(low)
                .saturating_add(0x1_0000);
            let ch = char::from_u32(combined)
                .ok_or_else(|| to_gid_error(ParseError::InvalidUnicodeEscape))?;
            out.push(ch);
            return Ok(());
        }

        if (0xDC00..=0xDFFF).contains(&first) {
            // Suplente bajo huérfano.
            return Err(to_gid_error(ParseError::InvalidUnicodeEscape));
        }

        let ch = char::from_u32(u32::from(first))
            .ok_or_else(|| to_gid_error(ParseError::InvalidUnicodeEscape))?;
        out.push(ch);
        Ok(())
    }

    /// Cuatro dígitos hexadecimales.
    fn parse_hex4(&mut self) -> Result<u16, GidError> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let byte = match self.peek() {
                Some(byte) => byte,
                None => return Err(to_gid_error(ParseError::UnexpectedEof)),
            };
            let digit = match byte {
                b'0'..=b'9' => Some(u16::from(byte).saturating_sub(u16::from(b'0'))),
                b'a'..=b'f' => Some(
                    u16::from(byte)
                        .saturating_sub(u16::from(b'a'))
                        .saturating_add(10),
                ),
                b'A'..=b'F' => Some(
                    u16::from(byte)
                        .saturating_sub(u16::from(b'A'))
                        .saturating_add(10),
                ),
                _ => None,
            };
            let digit = digit.ok_or_else(|| to_gid_error(ParseError::InvalidUnicodeEscape))?;
            value = value
                .checked_shl(4)
                .map(|v| v | digit)
                .ok_or_else(|| to_gid_error(ParseError::InvalidUnicodeEscape))?;
            self.pos = self.pos.saturating_add(1);
        }
        Ok(value)
    }

    /// Número JSON con rango acotado.
    fn parse_number(&mut self) -> Result<Number, GidError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.pos = self.pos.saturating_add(1);
        }

        // Parte entera.
        let mut magnitude: u64 = 0;
        let mut integer_digits = 0usize;
        let mut overflow = false;
        let first_digit_pos = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            let digit = u64::from(self.peek().unwrap_or(b'0')).saturating_sub(u64::from(b'0'));
            self.pos = self.pos.saturating_add(1);
            integer_digits = integer_digits.saturating_add(1);
            match magnitude.checked_mul(10).and_then(|m| m.checked_add(digit)) {
                Some(next) => magnitude = next,
                None => overflow = true,
            }
        }

        // RFC 8259: ni ceros a la izquierda ni parte entera vacía.
        let first_is_zero = self.bytes.get(first_digit_pos) == Some(&b'0');
        if integer_digits == 0 || (first_is_zero && integer_digits > 1) {
            return Err(to_gid_error(ParseError::InvalidLiteral));
        }

        let mut is_float = false;

        // Fracción.
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos = self.pos.saturating_add(1);
            let mut frac_digits = 0usize;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos = self.pos.saturating_add(1);
                frac_digits = frac_digits.saturating_add(1);
            }
            if frac_digits == 0 {
                return Err(to_gid_error(ParseError::InvalidLiteral));
            }
        }

        // Exponente.
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos = self.pos.saturating_add(1);
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos = self.pos.saturating_add(1);
            }
            let mut exp_digits = 0usize;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos = self.pos.saturating_add(1);
                exp_digits = exp_digits.saturating_add(1);
            }
            if exp_digits == 0 {
                return Err(to_gid_error(ParseError::InvalidLiteral));
            }
        }

        if is_float {
            let literal = self
                .bytes
                .get(start..self.pos)
                .and_then(|slice| core::str::from_utf8(slice).ok())
                .ok_or_else(|| to_gid_error(ParseError::InvalidLiteral))?;
            let value: f64 = literal
                .parse()
                .map_err(|_| to_gid_error(ParseError::InvalidLiteral))?;
            if !value.is_finite() {
                return Err(to_gid_error(ParseError::NumberNotFinite));
            }
            return Ok(Number::Float(value));
        }

        if overflow {
            return Err(to_gid_error(ParseError::IntegerOutOfRange));
        }

        if negative {
            // i64::MIN (-9223372036854775808) es representable: su magnitud es
            // exactamente i64::MAX + 1.
            const I64_MAX_MAGNITUDE: u64 = i64::MAX as u64;
            if magnitude <= I64_MAX_MAGNITUDE {
                let value = 0i64.wrapping_sub(i64::try_from(magnitude).unwrap_or(i64::MIN));
                return Ok(Number::NegInt(value));
            }
            if magnitude == I64_MAX_MAGNITUDE.saturating_add(1) {
                return Ok(Number::NegInt(i64::MIN));
            }
            return Err(to_gid_error(ParseError::IntegerOutOfRange));
        }

        Ok(Number::PosInt(magnitude))
    }
}

/// Longitud en bytes de un carácter UTF-8 a partir de su byte inicial.
fn utf8_len(first: u8) -> Result<usize, GidError> {
    match first {
        0x00..=0x7F => Ok(1),
        0xC2..=0xDF => Ok(2),
        0xE0..=0xEF => Ok(3),
        0xF0..=0xF4 => Ok(4),
        _ => Err(to_gid_error(ParseError::InvalidLiteral)),
    }
}

/// Parsea JSON con los límites por defecto.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si el documento excede los límites, no es
/// JSON válido, tiene miembros duplicados o números fuera de rango.
pub fn parse(input: &str) -> Result<Value, GidError> {
    parse_with_limits(input, &Limits::profile_default())
}

/// Parsea JSON con límites explícitos.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] en las mismas condiciones que [`parse`].
pub fn parse_with_limits(input: &str, limits: &Limits) -> Result<Value, GidError> {
    if input.len() > limits.max_input_bytes {
        return Err(to_gid_error(ParseError::InputTooLarge));
    }
    let mut parser = Parser::new(input.as_bytes(), limits);
    parser.parse_document()
}

/// Parsea bytes como JSON con límites explícitos, validando UTF-8 estricto.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si los bytes no son UTF-8 válido (incluidas
/// secuencias sobrelargadas y suplentes) o si el documento incumple las reglas
/// de [`parse_with_limits`].
pub fn parse_bytes(bytes: &[u8], limits: &Limits) -> Result<Value, GidError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(to_gid_error(ParseError::InputTooLarge));
    }
    // La validación UTF-8 estricta es el punto: rechaza sobrelongitudes,
    // suplentos CESU-8 y secuencias truncadas antes de parsear.
    let _validated =
        core::str::from_utf8(bytes).map_err(|_| to_gid_error(ParseError::InvalidLiteral))?;
    let mut parser = Parser::new(bytes, limits);
    parser.parse_document()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    // ---------- Casos positivos ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn parses_documents_of_every_shape() {
        assert_eq!(parse("null").expect("null"), Value::Null);
        assert_eq!(parse("true").expect("true"), Value::Bool(true));
        assert_eq!(parse(" false ").expect("false with ws"), Value::Bool(false));
        assert_eq!(parse("0").expect("zero"), Value::Number(Number::PosInt(0)));
        assert_eq!(
            parse("-0").expect("negative zero"),
            Value::Number(Number::NegInt(0))
        );
        assert_eq!(
            parse(r#""hola""#).expect("string"),
            Value::String("hola".to_string())
        );
        assert_eq!(parse("[]").expect("empty array"), Value::Array(vec![]));
        assert_eq!(parse("{}").expect("empty object"), Value::Object(vec![]));
        assert_eq!(
            parse(r#"{"a":1}"#).expect("object"),
            Value::Object(vec![("a".to_string(), Value::Number(Number::PosInt(1)))])
        );
        assert_eq!(
            parse("[1,[2,[3]]]").expect("nested arrays"),
            Value::Array(vec![
                Value::Number(Number::PosInt(1)),
                Value::Array(vec![
                    Value::Number(Number::PosInt(2)),
                    Value::Array(vec![Value::Number(Number::PosInt(3))]),
                ]),
            ])
        );
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn resolves_string_escapes_and_unicode() {
        assert_eq!(
            parse(r#""a\"b\\c\/d""#).expect("simple escapes").as_str(),
            Some("a\"b\\c/d")
        );
        assert_eq!(
            parse(r#""\b\f\n\r\t""#).expect("control escapes").as_str(),
            Some("\u{0008}\u{000C}\n\r\t")
        );
        assert_eq!(
            parse(r#""\u00e9""#).expect("BMP escape").as_str(),
            Some("é")
        );
        // Par suplente: U+1F600 (😀) = \uD83D\uDE00.
        assert_eq!(
            parse(r#""\uD83D\uDE00""#).expect("surrogate pair").as_str(),
            Some("😀")
        );
        // UTF-8 multibyte directo.
        assert_eq!(parse(r#""ñ😀""#).expect("raw utf8").as_str(), Some("ñ😀"));
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn parses_numbers_with_bounded_range() {
        assert_eq!(
            parse("9223372036854775807").expect("i64::MAX"),
            Value::Number(Number::PosInt(i64::MAX as u64))
        );
        assert_eq!(
            parse("18446744073709551615").expect("u64::MAX"),
            Value::Number(Number::PosInt(u64::MAX))
        );
        assert_eq!(
            parse("-9223372036854775808").expect("i64::MIN"),
            Value::Number(Number::NegInt(i64::MIN))
        );
        assert_eq!(
            parse("-42").expect("negative"),
            Value::Number(Number::NegInt(-42))
        );
        assert_eq!(
            parse("1.5").expect("fraction"),
            Value::Number(Number::Float(1.5))
        );
        assert_eq!(
            parse("1e3").expect("exponent"),
            Value::Number(Number::Float(1000.0))
        );
        assert_eq!(
            parse("-2.5E-1").expect("signed exponent"),
            Value::Number(Number::Float(-0.25))
        );
    }

    // ---------- Casos negativos: duplicados (REQ-CRED-009) ----------

    // // Verifies: REQ-CRED-009
    #[test]
    fn rejects_duplicate_object_members() {
        let err = parse(r#"{"a":1,"a":2}"#).expect_err("duplicate member");
        assert_eq!(err.code, ErrorCode::MalformedMessage);
        assert_eq!(format!("{err}"), "[GID-E1001] duplicate object member: a");

        // Duplicados anidados también se rechazan.
        assert!(parse(r#"{"x":{"b":1,"b":2}}"#).is_err());
        // Claves distintas con escapes equivalentes son el mismo miembro.
        assert!(parse(r#"{"a":1,"\u0061":2}"#).is_err());
    }

    // ---------- Casos negativos: límites (REQ-VER-008) ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_documents_above_limits() {
        let small = Limits {
            max_input_bytes: 16,
            max_depth: 2,
            max_elements: 2,
            max_string_bytes: 4,
        };

        assert!(parse_with_limits(r#"{"a":1,"b":2}"#, &small).is_ok());
        // Elementos por encima del límite.
        assert!(parse_with_limits(r#"{"a":1,"b":2,"c":3}"#, &small).is_err());
        assert!(parse_with_limits(r#"[1,2,3]"#, &small).is_err());
        // Profundidad por encima del límite.
        assert!(parse_with_limits("[[[1]]]", &small).is_err());
        // Cadena por encima del límite.
        assert!(parse_with_limits(r#""demasiado-larga""#, &small).is_err());
        // Entrada por encima del límite de bytes.
        // 17 bytes > 16.
        assert!(parse_with_limits(r#"{"a":12345678901}"#, &small).is_err());
    }

    // ---------- Casos negativos: sintaxis ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_malformed_syntax() {
        // Estructura.
        for bad in [
            "",
            " ",
            "{",
            "}",
            "[",
            "]",
            "[1,",
            "{\"a\":}",
            "{\"a\":1,}",
            "[1,]",
            "{\"a\" 1}",
            "{a:1}",
            "{'a':1}",
            "nul",
            "tru",
            "fals",
            "nulll",
        ] {
            assert!(parse(bad).is_err(), "expected rejection for {bad:?}");
        }
        // Números (RFC 8259).
        for bad in [
            "01",
            "-01",
            "1.",
            ".5",
            "+1",
            "1e",
            "1e+",
            "-",
            "1e++5",
            "0x1",
            "Infinity",
            "NaN",
            "-Infinity",
        ] {
            assert!(parse(bad).is_err(), "expected rejection for {bad:?}");
        }
        // Cadenas.
        for bad in [
            r#""unterminated"#,
            "\"tab\tinside\"",
            "\"newline\ninside\"",
            "\"bad\\escape\"",
            "\"\\uXX00\"",
            "\"\\uD800\"",
            "\"\\uDC00\"",
            "\"\\uD83D\"",
            "\"\\uD83Dx\"",
        ] {
            assert!(parse(bad).is_err(), "expected rejection for {bad:?}");
        }
        // Basura tras el documento.
        assert!(parse("1 2").is_err());
        assert!(parse("{}{}").is_err());
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_out_of_range_numbers() {
        // entero por encima de u64::MAX
        assert!(parse("18446744073709551616").is_err());
        // entero negativo por debajo de i64::MIN
        assert!(parse("-9223372036854775809").is_err());
        // flotante que desborda f64 (infinito)
        assert!(parse("1e400").is_err());
        assert!(parse("-1e400").is_err());
    }

    // // Verifies: REQ-VER-008 (UTF-8 estricto a nivel de bytes)
    #[test]
    fn parse_bytes_rejects_invalid_utf8() {
        // Bytes continuos sin byte de inicio.
        assert!(parse_bytes(&[0x80, 0x80], &Limits::profile_default()).is_err());
        // Secuencia sobrelarga (overlong) de '/'.
        assert!(parse_bytes(&[0xC0, 0xAF], &Limits::profile_default()).is_err());
        // Suplento UTF-16 codificado en UTF-8 (CESU-8): prohibido.
        assert!(parse_bytes(&[0xED, 0xA0, 0x80], &Limits::profile_default()).is_err());
        // UTF-8 válido: el documento parsea.
        let mut doc = Vec::new();
        doc.extend_from_slice(br#""a":""#);
        doc.extend_from_slice(&[0xC3, 0xB1]); // ñ
        doc.push(b'"');
        let full = {
            let mut v = Vec::new();
            v.push(b'{');
            v.extend_from_slice(&doc);
            v.push(b'}');
            v
        };
        assert!(parse_bytes(&full, &Limits::profile_default()).is_ok());
    }

    // // Verifies: REQ-VER-008 (límite de entrada antes de asignar)
    #[test]
    fn input_size_is_checked_before_parsing() {
        let limits = Limits {
            max_input_bytes: 6,
            ..Limits::profile_default()
        };
        // `"hola"` ocupa 6 bytes con las comillas.
        assert!(parse_with_limits(r#""hola""#, &limits).is_ok());
        assert!(parse_with_limits(r#""holaa""#, &limits).is_err());
    }

    // ---------- Casos negativos: determinismo y validación de acceso ----------

    // // Verifies: REQ-VER-009
    #[test]
    fn parsing_is_deterministic() {
        let input = r#"{"b":[1,2,{"c":"d"}],"a":true}"#;
        let first = parse(input).expect("valid");
        let second = parse(input).expect("valid");
        assert_eq!(first, second);
    }

    // // Verifies: REQ-VER-008 (API de acceso)
    #[test]
    fn value_accessors_work() {
        let value = parse(r#"{"kid":"te-2026-01","nested":{"x":1}}"#).expect("valid");
        assert_eq!(
            value.member("kid").and_then(Value::as_str),
            Some("te-2026-01")
        );
        assert_eq!(
            value.member("nested").and_then(|v| v.member("x")),
            Some(&Value::Number(Number::PosInt(1)))
        );
        assert!(value.member("missing").is_none());
    }

    // // Verifies: REQ-VER-008 (mensajes estables)
    #[test]
    fn error_messages_are_stable() {
        assert_eq!(
            format!("{}", parse("").expect_err("empty")),
            "[GID-E1001] unexpected end of JSON input"
        );
        // Tras la coma falta un valor: fin de entrada inesperado.
        assert_eq!(
            format!("{}", parse("[1,").expect_err("dangling")),
            "[GID-E1001] unexpected end of JSON input"
        );
        // Separador ausente entre valores.
        assert_eq!(
            format!("{}", parse("[1 2").expect_err("missing comma")),
            "[GID-E1001] unexpected token: 2"
        );
    }

    // ---------- Caso negativo: nunca entra en pánico ----------

    // // Verifies: REQ-VER-008 (INV-10: el parser no entra en pánico nunca)
    #[test]
    fn parser_never_panics_on_arbitrary_input() {
        // Mutaciones de un documento válido: ninguna debe provocar pánico.
        let base = r#"{"a":[1,2.5,"x",true,null],"b":{"c":"d"},"e":-3,"f":1e2}"#;
        for index in 0..base.len() {
            let mut mutated: Vec<u8> = base.as_bytes().to_vec();
            if let Some(slot) = mutated.get_mut(index) {
                *slot = slot.wrapping_add(1);
            }
            let _ = core::str::from_utf8(&mutated).map(parse);
            let _ = parse_bytes(&mutated, &Limits::profile_default());
        }
        // Truncaciones.
        for len in 0..base.len() {
            let _ = base.get(..len).map(parse);
        }
    }
}
