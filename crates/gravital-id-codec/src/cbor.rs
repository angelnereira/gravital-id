//! Lector CBOR acotado (F2.T04, REQ-VER-008).
//!
//! Implementa el subconjunto de RFC 8949 que necesita el protocolo:
//! - **Acotado**: tamaño de entrada, profundidad, elementos y longitud de
//!   cadenas (REQ-VER-008).
//! - **Determinismo opcional** ([`Strictness::deterministic`]): entradas más
//!   cortas para enteros y longitudes (RFC 8949 §4.2.1), prohibición de
//!   longitudes indefinidas, claves de mapa únicas y ordenadas por
//!   *(longitud, bytes)* y rechazo de NaN/Infinity (§4.2.2). El empaquetado de
//!   presentaciones del perfil offline (`PROTOCOL.md §3.2`) exige esta forma.
//! - **Entero sin pérdida**: los negativos se representan como `-(1 + n)` con
//!   `n` en `u64`, de modo que todo el rango de CBOR es representable sin
//!   desbordamientos.
//!
//! Igual que el lector JSON, el módulo no usa indexaciones ni aritmética que
//! puedan entrar en pánico (INV-10).

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use gravital_id_types::{ErrorCode, GidError};

/// Tamaño máximo de entrada por defecto (64 KiB).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024;

/// Profundidad máxima de anidamiento por defecto (32).
///
/// Cota deliberadamente conservadora (REQ-VER-008, INV-10): el lector es
/// descendente recursivo y, con instrumentación (ASAN), cada nivel consume
/// varios frames anchos. Con 32 niveles el peor caso cabe con margen en la pila
/// de 8 MiB incluso bajo instrumentación; los documentos del protocolo
/// (empaquetado de presentaciones, `PROTOCOL.md §3.2`) nunca se acercan a este
/// límite.
pub const DEFAULT_MAX_DEPTH: usize = 32;

/// Elementos máximos por array o mapa por defecto.
pub const DEFAULT_MAX_ELEMENTS: usize = 10_000;

/// Longitud máxima de cadena de texto por defecto (bytes UTF-8).
pub const DEFAULT_MAX_TEXT_BYTES: usize = 8 * 1024;

/// Límites de parseo aplicables a un documento CBOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Tamaño máximo de la entrada en bytes.
    pub max_input_bytes: usize,
    /// Profundidad máxima de anidamiento (arrays, mapas y etiquetas).
    pub max_depth: usize,
    /// Número máximo de elementos por contenedor.
    pub max_elements: usize,
    /// Longitud máxima de cada cadena de texto en bytes UTF-8.
    pub max_text_bytes: usize,
}

impl Limits {
    /// Límites por defecto del perfil.
    #[must_use]
    pub const fn profile_default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_elements: DEFAULT_MAX_ELEMENTS,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::profile_default()
    }
}

/// Nivel de exigencia de codificación determinista (RFC 8949 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strictness {
    /// Enteros y longitudes deben usar la forma más corta posible.
    pub require_shortest_arguments: bool,
    /// Se rechazan las longitudes indefinidas (`_ ... FF`).
    pub forbid_indefinite_lengths: bool,
    /// Las claves de mapa deben ser únicas y estar ordenadas por
    /// *(longitud codificada, bytes)*.
    pub require_sorted_unique_keys: bool,
    /// Se rechazan NaN e infinitos.
    pub forbid_special_floats: bool,
    /// Los flotantes deben usar la forma más corta que preserva el valor.
    pub require_shortest_floats: bool,
}

impl Strictness {
    /// Exigencia determinista del perfil (valor por defecto de `parse`).
    #[must_use]
    pub const fn deterministic() -> Self {
        Self {
            require_shortest_arguments: true,
            forbid_indefinite_lengths: true,
            require_sorted_unique_keys: true,
            forbid_special_floats: true,
            require_shortest_floats: true,
        }
    }

    /// Exigencia permisiva: CBOR válido, sin comprobaciones deterministas.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            require_shortest_arguments: false,
            forbid_indefinite_lengths: false,
            require_sorted_unique_keys: false,
            forbid_special_floats: false,
            require_shortest_floats: false,
        }
    }
}

impl Default for Strictness {
    fn default() -> Self {
        Self::deterministic()
    }
}

/// Valor CBOR parseado.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `null` (0xf6).
    Null,
    /// `undefined` (0xf7).
    Undefined,
    /// Booleano (0xf4 / 0xf5).
    Bool(bool),
    /// Entero sin signo (major 0).
    UInt(u64),
    /// Entero negativo: el valor es `-(1 + n)` (major 1).
    NInt(u64),
    /// Flotante (major 7, f16/f32/f64).
    Float(f64),
    /// Cadena de bytes (major 2).
    Bytes(Vec<u8>),
    /// Cadena de texto UTF-8 (major 3).
    Text(String),
    /// Array (major 4).
    Array(Vec<Value>),
    /// Mapa (major 5) como lista ordenada de pares.
    Map(Vec<(Value, Value)>),
    /// Etiqueta (major 6) con su contenido.
    Tag(u64, Box<Value>),
    /// Valor simple (major 7, p. ej. 0xf0).
    Simple(u8),
}

/// Error interno de parseo (motivo estable).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseError {
    InputTooLarge,
    UnexpectedEof,
    ReservedAdditionalInfo,
    /// Argumento entero codificado en una forma más larga de la necesaria.
    NonShortestArgument,
    /// Longitud indefinida rechazada por la exigencia determinista.
    IndefiniteLength,
    /// Contenedor sin código de ruptura (`0xff`).
    MissingBreak,
    /// Texto que no es UTF-8 válido.
    InvalidUtf8,
    /// Claves de mapa desordenadas según RFC 8949 §4.2.1.
    UnsortedMapKey,
    /// Claves de mapa duplicadas.
    DuplicateMapKey,
    /// NaN o infinito rechazado por la exigencia determinista.
    SpecialFloat,
    /// Flotante codificado en una forma más larga que la necesaria.
    NonShortestFloat,
    /// Etiqueta sin contenido o con estructura inválida.
    InvalidTag,
    TooManyElements,
    TooDeep,
    TextTooLong,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("CBOR input exceeds the size limit"),
            Self::UnexpectedEof => f.write_str("unexpected end of CBOR input"),
            Self::ReservedAdditionalInfo => f.write_str("reserved CBOR additional information"),
            Self::NonShortestArgument => {
                f.write_str("CBOR argument is not encoded in its shortest form")
            }
            Self::IndefiniteLength => f.write_str("indefinite-length CBOR item is not allowed"),
            Self::MissingBreak => f.write_str("indefinite-length CBOR item without break code"),
            Self::InvalidUtf8 => f.write_str("CBOR text string is not valid UTF-8"),
            Self::UnsortedMapKey => f.write_str("CBOR map keys are not sorted"),
            Self::DuplicateMapKey => f.write_str("CBOR map has duplicate keys"),
            Self::SpecialFloat => f.write_str("CBOR special float (NaN/Infinity) is not allowed"),
            Self::NonShortestFloat => f.write_str("CBOR float is not encoded in its shortest form"),
            Self::InvalidTag => f.write_str("invalid CBOR tag structure"),
            Self::TooManyElements => f.write_str("too many elements in CBOR container"),
            Self::TooDeep => f.write_str("CBOR nesting exceeds the depth limit"),
            Self::TextTooLong => f.write_str("CBOR text string exceeds the length limit"),
        }
    }
}

/// Convierte el motivo interno en el error canónico del protocolo.
fn to_gid_error(reason: ParseError) -> GidError {
    GidError::new(ErrorCode::MalformedMessage, reason.to_string())
}

/// Parser CBOR con posición, límites y exigencia determinista.
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    limits: &'a Limits,
    strictness: &'a Strictness,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: &'a Limits, strictness: &'a Strictness) -> Self {
        Self {
            bytes,
            pos: 0,
            limits,
            strictness,
        }
    }

    /// Byte en la posición actual.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consume un byte.
    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(byte)
    }

    /// Lee `n` bytes como entero big-endian.
    fn read_uint(&mut self, n: usize) -> Result<u64, GidError> {
        let mut value: u64 = 0;
        let mut remaining = n;
        while remaining > 0 {
            remaining = remaining.saturating_sub(1);
            let byte = self
                .bump()
                .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
            value = value
                .checked_shl(8)
                .map(|v| v | u64::from(byte))
                .ok_or_else(|| to_gid_error(ParseError::ReservedAdditionalInfo))?;
        }
        Ok(value)
    }

    /// Lee el argumento de un ítem a partir de la información adicional.
    ///
    /// Devuelve `None` si la longitud es indefinida (`additional == 31`).
    fn read_argument(&mut self, additional: u8) -> Result<Option<u64>, GidError> {
        let (value, used_bytes) = match additional {
            0..=23 => (u64::from(additional), 0),
            24 => (self.read_uint(1)?, 1),
            25 => (self.read_uint(2)?, 2),
            26 => (self.read_uint(4)?, 4),
            27 => (self.read_uint(8)?, 8),
            28..=30 => {
                return Err(to_gid_error(ParseError::ReservedAdditionalInfo));
            }
            _ => return Ok(None), // 31: indefinido
        };

        if self.strictness.require_shortest_arguments {
            // La forma mínima exige que el argumento quepa en `used_bytes` bytes.
            let minimal = match value {
                0..=23 => 0,
                24..=0xFF => 1,
                0x100..=0xFFFF => 2,
                0x1_0000..=0xFFFF_FFFF => 4,
                _ => 8,
            };
            if minimal < used_bytes {
                return Err(to_gid_error(ParseError::NonShortestArgument));
            }
        }

        Ok(Some(value))
    }

    /// Documento completo: un ítem que consume toda la entrada.
    fn parse_document(&mut self) -> Result<Value, GidError> {
        let value = self.parse_value(0)?;
        if self.pos != self.bytes.len() {
            return Err(to_gid_error(ParseError::ReservedAdditionalInfo));
        }
        Ok(value)
    }

    /// Ítem CBOR en la posición actual.
    fn parse_value(&mut self, depth: usize) -> Result<Value, GidError> {
        let initial = self
            .bump()
            .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        match major {
            0 => Ok(Value::UInt(self.require_argument(additional)?)),
            1 => Ok(Value::NInt(self.require_argument(additional)?)),
            2 => self.parse_bytes(additional, depth),
            3 => self.parse_text(additional, depth),
            4 => self.parse_array(additional, depth),
            5 => self.parse_map(additional, depth),
            6 => self.parse_tag(additional, depth),
            7 => self.parse_simple_or_float(additional),
            _ => Err(to_gid_error(ParseError::ReservedAdditionalInfo)),
        }
    }

    /// Argumento obligatorio (rechaza indefinido donde no aplica).
    fn require_argument(&mut self, additional: u8) -> Result<u64, GidError> {
        self.read_argument(additional)?
            .ok_or_else(|| to_gid_error(ParseError::IndefiniteLength))
    }

    /// Cadena de bytes (major 2), definida o indefinida.
    ///
    /// El `depth` recibido es el del ítem contenedor: los fragmentos de una
    /// cadena indefinida se parsean a esa profundidad, de modo que el
    /// anidamiento seguimos acotado por [`Limits::max_depth`] (INV-10).
    fn parse_bytes(&mut self, additional: u8, depth: usize) -> Result<Value, GidError> {
        match self.read_argument(additional)? {
            Some(len) => {
                let len =
                    usize::try_from(len).map_err(|_| to_gid_error(ParseError::InputTooLarge))?;
                let start = self.pos;
                let end = start
                    .checked_add(len)
                    .ok_or_else(|| to_gid_error(ParseError::InputTooLarge))?;
                let slice = self
                    .bytes
                    .get(start..end)
                    .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
                self.pos = end;
                Ok(Value::Bytes(slice.to_vec()))
            }
            None => {
                if self.strictness.forbid_indefinite_lengths {
                    return Err(to_gid_error(ParseError::IndefiniteLength));
                }
                // Cada fragmento se parsea un nivel más abajo: el presupuesto de
                // profundidad se consume aquí para que ni siquiera una cadena
                // indefinida anidada ilegalmente pueda desbordar la pila
                // (INV-10; hallazgo del fuzzing #27).
                if depth.saturating_add(1) > self.limits.max_depth {
                    return Err(to_gid_error(ParseError::TooDeep));
                }
                let mut chunks: Vec<Vec<u8>> = Vec::new();
                loop {
                    match self.peek() {
                        Some(0xFF) => {
                            self.pos = self.pos.saturating_add(1);
                            break;
                        }
                        Some(_) => {
                            if chunks.len() >= self.limits.max_elements {
                                return Err(to_gid_error(ParseError::TooManyElements));
                            }
                            let item = self.parse_value(depth.saturating_add(1))?;
                            match item {
                                Value::Bytes(chunk) => chunks.push(chunk),
                                _ => return Err(to_gid_error(ParseError::InvalidTag)),
                            }
                        }
                        None => return Err(to_gid_error(ParseError::MissingBreak)),
                    }
                }
                let mut out = Vec::new();
                for chunk in &chunks {
                    out.extend_from_slice(chunk);
                }
                Ok(Value::Bytes(out))
            }
        }
    }

    /// Cadena de texto (major 3), definida o indefinida.
    ///
    /// Igual que [`Self::parse_bytes`]: los fragmentos se parsean a la
    /// profundidad del contenedor.
    fn parse_text(&mut self, additional: u8, depth: usize) -> Result<Value, GidError> {
        match self.read_argument(additional)? {
            Some(len) => {
                let len =
                    usize::try_from(len).map_err(|_| to_gid_error(ParseError::InputTooLarge))?;
                if len > self.limits.max_text_bytes {
                    return Err(to_gid_error(ParseError::TextTooLong));
                }
                let start = self.pos;
                let end = start
                    .checked_add(len)
                    .ok_or_else(|| to_gid_error(ParseError::InputTooLarge))?;
                let slice = self
                    .bytes
                    .get(start..end)
                    .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
                let text = core::str::from_utf8(slice)
                    .map_err(|_| to_gid_error(ParseError::InvalidUtf8))?;
                self.pos = end;
                Ok(Value::Text(text.to_string()))
            }
            None => {
                if self.strictness.forbid_indefinite_lengths {
                    return Err(to_gid_error(ParseError::IndefiniteLength));
                }
                // Ídem parse_bytes: el presupuesto de profundidad se consume
                // antes de parsear cada fragmento (INV-10; hallazgo #27).
                if depth.saturating_add(1) > self.limits.max_depth {
                    return Err(to_gid_error(ParseError::TooDeep));
                }
                let mut out = String::new();
                loop {
                    match self.peek() {
                        Some(0xFF) => {
                            self.pos = self.pos.saturating_add(1);
                            break;
                        }
                        Some(_) => {
                            if out.len() >= self.limits.max_text_bytes {
                                return Err(to_gid_error(ParseError::TextTooLong));
                            }
                            let item = self.parse_value(depth.saturating_add(1))?;
                            match item {
                                Value::Text(chunk) => out.push_str(&chunk),
                                _ => return Err(to_gid_error(ParseError::InvalidTag)),
                            }
                        }
                        None => return Err(to_gid_error(ParseError::MissingBreak)),
                    }
                }
                Ok(Value::Text(out))
            }
        }
    }

    /// Array (major 4).
    fn parse_array(&mut self, additional: u8, depth: usize) -> Result<Value, GidError> {
        let depth_now = depth.saturating_add(1);
        if depth_now > self.limits.max_depth {
            return Err(to_gid_error(ParseError::TooDeep));
        }

        let mut items: Vec<Value> = Vec::new();
        match self.read_argument(additional)? {
            Some(len) => {
                let len =
                    usize::try_from(len).map_err(|_| to_gid_error(ParseError::InputTooLarge))?;
                if len > self.limits.max_elements {
                    return Err(to_gid_error(ParseError::TooManyElements));
                }
                for _ in 0..len {
                    let item = self.parse_value(depth_now)?;
                    items.push(item);
                }
            }
            None => {
                if self.strictness.forbid_indefinite_lengths {
                    return Err(to_gid_error(ParseError::IndefiniteLength));
                }
                loop {
                    match self.peek() {
                        Some(0xFF) => {
                            self.pos = self.pos.saturating_add(1);
                            break;
                        }
                        Some(_) => {
                            if items.len() >= self.limits.max_elements {
                                return Err(to_gid_error(ParseError::TooManyElements));
                            }
                            let item = self.parse_value(depth_now)?;
                            items.push(item);
                        }
                        None => return Err(to_gid_error(ParseError::MissingBreak)),
                    }
                }
            }
        }

        Ok(Value::Array(items))
    }

    /// Mapa (major 5) con claves únicas y ordenadas en modo determinista.
    fn parse_map(&mut self, additional: u8, depth: usize) -> Result<Value, GidError> {
        let depth_now = depth.saturating_add(1);
        if depth_now > self.limits.max_depth {
            return Err(to_gid_error(ParseError::TooDeep));
        }

        let mut entries: Vec<(Value, Value)> = Vec::new();
        let mut previous_key_slice: Option<(usize, usize)> = None;

        let mut parse_entry = |parser: &mut Parser<'a>| -> Result<(), GidError> {
            if entries.len() >= parser.limits.max_elements {
                return Err(to_gid_error(ParseError::TooManyElements));
            }
            let key_start = parser.pos;
            let key = parser.parse_value(depth_now)?;
            let key_end = parser.pos;

            if parser.strictness.require_sorted_unique_keys {
                // Orden RFC 8949 §4.2.1: primero por longitud codificada, luego
                // bytewise. Duplicados quedan detectados por la misma regla.
                if let Some((prev_start, prev_end)) = previous_key_slice {
                    let previous = parser
                        .bytes
                        .get(prev_start..prev_end)
                        .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
                    let current = parser
                        .bytes
                        .get(key_start..key_end)
                        .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
                    match previous.len().cmp(&current.len()) {
                        core::cmp::Ordering::Greater => {
                            return Err(to_gid_error(ParseError::UnsortedMapKey));
                        }
                        core::cmp::Ordering::Equal => match previous.cmp(current) {
                            core::cmp::Ordering::Greater => {
                                return Err(to_gid_error(ParseError::UnsortedMapKey));
                            }
                            core::cmp::Ordering::Equal => {
                                return Err(to_gid_error(ParseError::DuplicateMapKey));
                            }
                            core::cmp::Ordering::Less => {}
                        },
                        core::cmp::Ordering::Less => {}
                    }
                }
                previous_key_slice = Some((key_start, key_end));
            }

            let value = parser.parse_value(depth_now)?;
            entries.push((key, value));
            Ok(())
        };

        match self.read_argument(additional)? {
            Some(len) => {
                let len =
                    usize::try_from(len).map_err(|_| to_gid_error(ParseError::InputTooLarge))?;
                if len > self.limits.max_elements {
                    return Err(to_gid_error(ParseError::TooManyElements));
                }
                for _ in 0..len {
                    parse_entry(self)?;
                }
            }
            None => {
                if self.strictness.forbid_indefinite_lengths {
                    return Err(to_gid_error(ParseError::IndefiniteLength));
                }
                loop {
                    match self.peek() {
                        Some(0xFF) => {
                            self.pos = self.pos.saturating_add(1);
                            break;
                        }
                        Some(_) => parse_entry(self)?,
                        None => return Err(to_gid_error(ParseError::MissingBreak)),
                    }
                }
            }
        }

        Ok(Value::Map(entries))
    }

    /// Etiqueta (major 6).
    fn parse_tag(&mut self, additional: u8, depth: usize) -> Result<Value, GidError> {
        let tag = self.require_argument(additional)?;
        let depth_now = depth.saturating_add(1);
        if depth_now > self.limits.max_depth {
            return Err(to_gid_error(ParseError::TooDeep));
        }
        let item = self.parse_value(depth_now)?;
        Ok(Value::Tag(tag, Box::new(item)))
    }

    /// Valores simples, break y flotantes (major 7).
    fn parse_simple_or_float(&mut self, additional: u8) -> Result<Value, GidError> {
        match additional {
            0..=19 => Ok(Value::Simple(additional)),
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Ok(Value::Undefined),
            24 => {
                let value = self
                    .bump()
                    .ok_or_else(|| to_gid_error(ParseError::UnexpectedEof))?;
                if value < 32 {
                    // Los valores < 32 deben ir en el byte inicial.
                    return Err(to_gid_error(ParseError::NonShortestArgument));
                }
                Ok(Value::Simple(value))
            }
            25 => {
                let half = self.read_uint(2)? as u16;
                self.float_from_f16(half)
            }
            26 => {
                let bits = self.read_uint(4)? as u32;
                self.float_from_f32(bits)
            }
            27 => {
                let bits = self.read_uint(8)?;
                self.float_from_f64(bits)
            }
            28..=30 => Err(to_gid_error(ParseError::ReservedAdditionalInfo)),
            _ => {
                // 31: código de ruptura fuera de un contenedor indefinido.
                Err(to_gid_error(ParseError::MissingBreak))
            }
        }
    }

    /// Flotante desde medio precisión (16 bits).
    fn float_from_f16(&self, bits: u16) -> Result<Value, GidError> {
        if bits & 0x7C00 == 0x7C00 {
            // Exponente todo unos: NaN o infinito.
            if self.strictness.forbid_special_floats {
                return Err(to_gid_error(ParseError::SpecialFloat));
            }
            let sign = u64::from(bits & 0x8000) << 63;
            let exponent = if bits & 0x0200 == 0 { 0x7FFu64 } else { 0 };
            let raw = sign | (exponent << 52);
            return Ok(Value::Float(f64::from_bits(raw)));
        }
        // 16 bits ya es la forma más corta posible para cualquier valor finito.
        Ok(Value::Float(f16_to_f64(bits)))
    }

    /// Flotante desde precisión simple (32 bits).
    fn float_from_f32(&self, bits: u32) -> Result<Value, GidError> {
        if bits & 0x7F80_0000 == 0x7F80_0000 {
            if self.strictness.forbid_special_floats {
                return Err(to_gid_error(ParseError::SpecialFloat));
            }
            return Ok(Value::Float(f64::from_bits(u64::from(bits) << 32)));
        }
        let value = f64::from(f32::from_bits(bits));
        if self.strictness.require_shortest_floats && f32_bits_fit_f16(bits) {
            return Err(to_gid_error(ParseError::NonShortestFloat));
        }
        Ok(Value::Float(value))
    }

    /// Flotante desde precisión doble (64 bits).
    fn float_from_f64(&self, bits: u64) -> Result<Value, GidError> {
        if bits & 0x7FF0_0000_0000_0000 == 0x7FF0_0000_0000_0000
            && self.strictness.forbid_special_floats
        {
            return Err(to_gid_error(ParseError::SpecialFloat));
        }
        let value = f64::from_bits(bits);
        if self.strictness.require_shortest_floats && f64_bits_fit_f32(bits) {
            return Err(to_gid_error(ParseError::NonShortestFloat));
        }
        Ok(Value::Float(value))
    }
}

/// Convierte un medio flotante IEEE 754 binary16 a `f64` (exacto).
///
/// Solo aritmética de enteros: los subnormales se normalizan por
/// desplazamientos antes de recomponer los bits de `f32`.
fn f16_to_f64(bits: u16) -> f64 {
    let sign = u32::from(bits & 0x8000) << 16;
    let exponent = u32::from((bits >> 10) & 0x1F);
    let fraction = u32::from(bits & 0x03FF);

    let (exp32, frac23) = if exponent == 0 {
        if fraction == 0 {
            (0u32, 0u32) // ±0
        } else {
            // Subnormal f16 (valor = fraction × 2^-24): se normaliza llevando el
            // bit significativo más alto a la posición del bit implícito de f32
            // (bit 22). Con la fracción alineada a 23 bits, su bit más alto
            // parte de la posición 13 + p (p = posición en `fraction`).
            let mut aligned = fraction << 13;
            let mut shifts = 0u32;
            while aligned & 0x0040_0000 == 0 {
                aligned = aligned.wrapping_shl(1);
                shifts = shifts.saturating_add(1);
            }
            // La fracción de f32 son los 23 bits bajo el bit implícito.
            let mantissa = (aligned & 0x003F_FFFF).wrapping_shl(1);
            // Exponente sesgado: p - 24 + 127 = p + 103, con p = 9 - shifts.
            let exponent32 = 9u32.saturating_sub(shifts).saturating_add(103);
            (exponent32, mantissa)
        }
    } else {
        (exponent.saturating_add(112), fraction << 13)
    };

    f64::from(f32::from_bits(sign | (exp32 << 23) | frac23))
}

/// `true` si el valor `f32` dado por sus bits es representable exactamente en
/// binary16 (RFC 8949 §4.2: la codificación más corta que preserva el valor).
fn f32_bits_fit_f16(bits: u32) -> bool {
    let exponent = (bits >> 23) & 0xFF;
    let mantissa = bits & 0x7F_FF_FF;
    if exponent == 0 {
        return mantissa == 0; // ±0 sí; subnormales f32 no caben salvo el cero
    }
    let unbalanced = i64::from(exponent).saturating_sub(127);
    if !(-24..=15).contains(&unbalanced) {
        return false;
    }
    if unbalanced >= -14 {
        // Rango normal f16: los 13 bits bajos de la mantisa deben ser cero.
        mantissa % (1u32 << 13) == 0
    } else {
        // Rango subnormal f16: el valor debe ser múltiplo de 2^-24.
        let modulus_shift = unbalanced
            .checked_neg()
            .and_then(|v| v.checked_sub(1))
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(23);
        let modulus = 1u32.checked_shl(modulus_shift).unwrap_or(0);
        modulus != 0 && mantissa.checked_rem(modulus) == Some(0)
    }
}

/// `true` si el valor `f64` dado por sus bits es representable exactamente en
/// `f32` (misma regla, un nivel más abajo).
fn f64_bits_fit_f32(bits: u64) -> bool {
    let exponent = (bits >> 52) & 0x7FF;
    let mantissa = bits & 0xF_FFFF_FFFF_FFFF;
    if exponent == 0 {
        return mantissa == 0;
    }
    let exponent32 = u32::try_from(exponent.min(0x7FF)).unwrap_or(0x7FF);
    let unbalanced = i64::from(exponent32).saturating_sub(1023);
    if !(-149..=127).contains(&unbalanced) {
        return false;
    }
    if unbalanced >= -126 {
        // Rango normal f32: los 29 bits bajos de la mantisa deben ser cero.
        mantissa % (1u64 << 29) == 0
    } else {
        // Rango subnormal f32: el valor debe ser múltiplo de 2^-149.
        let modulus_shift = unbalanced
            .checked_neg()
            .and_then(|v| v.checked_sub(97))
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(52);
        let modulus = 1u64.checked_shl(modulus_shift).unwrap_or(0);
        modulus != 0 && mantissa.checked_rem(modulus) == Some(0)
    }
}

/// Parsea CBOR con los límites y la exigencia determinista por defecto.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si el documento excede los límites, no es
/// CBOR válido o incumple la exigencia determinista del perfil.
pub fn parse(input: &[u8]) -> Result<Value, GidError> {
    let limits = Limits::profile_default();
    let strictness = Strictness::deterministic();
    parse_with_options(input, &limits, &strictness)
}

/// Parsea CBOR con límites explícitos y exigencia determinista.
pub fn parse_with_limits(input: &[u8], limits: &Limits) -> Result<Value, GidError> {
    let strictness = Strictness::deterministic();
    parse_with_options(input, limits, &strictness)
}

/// Parsea CBOR con límites y exigencia explícitos.
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] en las mismas condiciones que [`parse`],
/// más las que imponga `strictness`.
pub fn parse_with_options(
    input: &[u8],
    limits: &Limits,
    strictness: &Strictness,
) -> Result<Value, GidError> {
    if input.len() > limits.max_input_bytes {
        return Err(to_gid_error(ParseError::InputTooLarge));
    }
    let mut parser = Parser::new(input, limits, strictness);
    parser.parse_document()
}

#[cfg(test)]
// Pruebas locales deterministas: excepciones de lints documentadas
// (PROJECT_STRUCTURE.md §5.1). Los helpers usan panic para señalizar una
// expectativa incumplida.
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Vector positivo del apéndice A de RFC 8949.
    fn ok(bytes: &[u8]) -> Value {
        match parse(bytes) {
            Ok(value) => value,
            Err(error) => panic!("expected {bytes:02x?} to parse: {error}"),
        }
    }

    /// Vector negativo: debe fallar en modo determinista.
    fn err(bytes: &[u8]) -> GidError {
        match parse(bytes) {
            Ok(value) => panic!("expected {bytes:02x?} to be rejected, got {value:?}"),
            Err(error) => error,
        }
    }

    // ---------- Enteros ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn parses_integers_from_rfc8949_appendix_a() {
        assert_eq!(ok(&[0x00]), Value::UInt(0));
        assert_eq!(ok(&[0x01]), Value::UInt(1));
        assert_eq!(ok(&[0x0a]), Value::UInt(10));
        assert_eq!(ok(&[0x17]), Value::UInt(23));
        assert_eq!(ok(&[0x18, 0x18]), Value::UInt(24));
        assert_eq!(ok(&[0x18, 0x19]), Value::UInt(25));
        assert_eq!(ok(&[0x18, 0x64]), Value::UInt(100));
        assert_eq!(ok(&[0x19, 0x03, 0xe8]), Value::UInt(1000));
        assert_eq!(ok(&[0x1a, 0x00, 0x0f, 0x42, 0x40]), Value::UInt(1_000_000));
        assert_eq!(
            ok(&[0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]),
            Value::UInt(1_000_000_000_000)
        );
        assert_eq!(
            ok(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Value::UInt(u64::MAX)
        );
        assert_eq!(ok(&[0x20]), Value::NInt(0)); // -1
        assert_eq!(ok(&[0x29]), Value::NInt(9)); // -10
        assert_eq!(ok(&[0x38, 0x63]), Value::NInt(99)); // -100
        assert_eq!(ok(&[0x39, 0x03, 0xe7]), Value::NInt(999)); // -1000
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn negative_integers_are_lossless() {
        // -(1 + n) con n en u64 cubre todo el rango de CBOR.
        match ok(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]) {
            Value::NInt(n) => assert_eq!(n, u64::MAX), // -18446744073709551616
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---------- Cadenas, arrays, mapas ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn parses_strings_arrays_and_maps_from_rfc8949() {
        assert_eq!(ok(&[0x40]), Value::Bytes(Vec::new()));
        assert_eq!(ok(&[0x60]), Value::Text(String::new()));
        assert_eq!(
            ok(&[0x44, 0x01, 0x02, 0x03, 0x04]),
            Value::Bytes(vec![1, 2, 3, 4])
        );
        assert_eq!(ok(&[0x61, 0x61]), Value::Text("a".to_string()));
        assert_eq!(
            ok(&[0x64, 0x49, 0x45, 0x54, 0x46]),
            Value::Text("IETF".to_string())
        );
        assert_eq!(ok(&[0x62, 0x22, 0x5c]), Value::Text("\"\\".to_string()));
        assert_eq!(ok(&[0x80]), Value::Array(Vec::new()));
        assert_eq!(
            ok(&[0x83, 0x01, 0x02, 0x03]),
            Value::Array(vec![Value::UInt(1), Value::UInt(2), Value::UInt(3)])
        );
        assert_eq!(
            ok(&[0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05]),
            Value::Array(vec![
                Value::UInt(1),
                Value::Array(vec![Value::UInt(2), Value::UInt(3)]),
                Value::Array(vec![Value::UInt(4), Value::UInt(5)]),
            ])
        );
        assert_eq!(ok(&[0xa0]), Value::Map(Vec::new()));
        assert_eq!(
            ok(&[0xa2, 0x01, 0x02, 0x03, 0x04]),
            Value::Map(vec![
                (Value::UInt(1), Value::UInt(2)),
                (Value::UInt(3), Value::UInt(4))
            ])
        );
        // {"a": 1, "b": [2, 3]}
        assert_eq!(
            ok(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03]),
            Value::Map(vec![
                (Value::Text("a".to_string()), Value::UInt(1)),
                (
                    Value::Text("b".to_string()),
                    Value::Array(vec![Value::UInt(2), Value::UInt(3)])
                ),
            ])
        );
    }

    // ---------- Flotantes ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn parses_floats_from_rfc8949() {
        assert_eq!(ok(&[0xf9, 0x3c, 0x00]), Value::Float(1.0));
        assert_eq!(ok(&[0xfa, 0x47, 0xc3, 0x50, 0x00]), Value::Float(100000.0));
        assert_eq!(
            ok(&[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]),
            Value::Float(1.1)
        );
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn f16_conversion_is_exact_including_subnormals() {
        // Subnormal f16 más pequeño: 0x0001 = 2^-24.
        assert_eq!(
            ok(&[0xf9, 0x00, 0x01]),
            Value::Float(5.960_464_477_539_063e-8)
        );
        // Subnormal con varios bits: 0x0201 = 513 × 2^-24.
        assert_eq!(
            ok(&[0xf9, 0x02, 0x01]),
            Value::Float(3.057_718_276_977_539e-5)
        );
        // Cero negativo: 0x8000 = -0.0.
        match ok(&[0xf9, 0x80, 0x00]) {
            Value::Float(v) => assert!(v.is_sign_negative() && v == 0.0),
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ---------- Etiquetas y simples ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn parses_tags_and_simple_values() {
        // 0("2013-03-21T20:04:00Z")
        assert_eq!(
            ok(&[
                0xc0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x33, 0x2d, 0x32, 0x31, 0x54, 0x32,
                0x30, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x30, 0x5a
            ]),
            Value::Tag(0, Box::new(Value::Text("2013-03-21T20:04:00Z".to_string())))
        );
        assert_eq!(ok(&[0xf4]), Value::Bool(false));
        assert_eq!(ok(&[0xf5]), Value::Bool(true));
        assert_eq!(ok(&[0xf6]), Value::Null);
        assert_eq!(ok(&[0xf7]), Value::Undefined);
        assert_eq!(ok(&[0xf0]), Value::Simple(16));
        assert_eq!(ok(&[0xf8, 0xff]), Value::Simple(255));
    }

    // ---------- Determinismo (RFC 8949 §4.2) ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_non_shortest_arguments_in_deterministic_mode() {
        // 24 codificado en 2 bytes (0x190018) en lugar de 0x1818.
        err(&[0x19, 0x00, 0x18]);
        // 0 codificado con additional 24.
        err(&[0x18, 0x00]);
        // Longitud de cadena en 8 bytes.
        err(&[0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x61]);
        // Simple value < 32 con additional 24.
        err(&[0xf8, 0x10]);
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_special_floats_in_deterministic_mode() {
        err(&[0xf9, 0x7c, 0x00]); // +Infinity
        err(&[0xf9, 0xfc, 0x00]); // -Infinity
        err(&[0xf9, 0x7e, 0x00]); // NaN
        err(&[0xfa, 0x7f, 0x80, 0x00, 0x00]); // +Infinity f32
        err(&[0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0]); // +Infinity f64
        err(&[0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0]); // NaN f64
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_non_shortest_floats_in_deterministic_mode() {
        // 1.0 en f32 (0xfa...) cuando cabe en f16 (0xf93c00).
        err(&[0xfa, 0x3f, 0x80, 0x00, 0x00]);
        // 1.0 en f64 cuando cabe en f16.
        err(&[0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // 2.0 cabe en f16 (0xf94000).
        err(&[0xfa, 0x40, 0x00, 0x00, 0x00]);
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_unsorted_and_duplicate_map_keys() {
        // {1: 1, 0: 0}: claves descendentes.
        err(&[0xa2, 0x01, 0x01, 0x00, 0x00]);
        // {"b": 1, "a": 2}: fuera de orden bytewise.
        err(&[0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02]);
        // {1: 1, 1: 2}: duplicado.
        err(&[0xa2, 0x01, 0x01, 0x01, 0x02]);
        // Orden correcto por longitud primero: "a" (3 bytes codificados) antes
        // que [1] (4 bytes codificados) — el mapa {1: .., "a": ..} sería
        // inválido; {"a":.., 1:..} también (por longitud). El orden canónico es
        // por longitud: "a" (0x6161, 2 bytes) antes que 0x01 (1 byte)? No:
        // 0x01 tiene longitud 1 y "a" longitud 2, así que 0x01 va primero.
        assert_eq!(
            ok(&[0xa2, 0x01, 0x01, 0x61, 0x61, 0x02]),
            Value::Map(vec![
                (Value::UInt(1), Value::UInt(1)),
                (Value::Text("a".to_string()), Value::UInt(2)),
            ])
        );
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_indefinite_lengths_in_deterministic_mode() {
        err(&[0x5f, 0x42, 0x01, 0x02, 0x43, 0x03, 0x04, 0x05, 0xff]); // bytes indefinidas
        err(&[0x7f, 0x61, 0x61, 0xff]); // texto indefinido
        err(&[0x9f, 0x01, 0x02, 0xff]); // array indefinido
        err(&[0xbf, 0x01, 0x02, 0xff]); // mapa indefinido
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn permissive_mode_accepts_indefinite_lengths() {
        let limits = Limits::profile_default();
        let strictness = Strictness::permissive();
        // (_ h'0102', h'030405')
        assert_eq!(
            parse_with_options(
                &[0x5f, 0x42, 0x01, 0x02, 0x43, 0x03, 0x04, 0x05, 0xff],
                &limits,
                &strictness
            )
            .expect("permissive accepts indefinite bytes"),
            Value::Bytes(vec![1, 2, 3, 4, 5])
        );
        // (_ "strea", "ming")
        assert_eq!(
            parse_with_options(
                &[0x7f, 0x65, 0x73, 0x74, 0x72, 0x65, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x67, 0xff],
                &limits,
                &strictness
            )
            .expect("permissive accepts indefinite text"),
            Value::Text("streaming".to_string())
        );
    }

    // ---------- Límites y errores estructurales ----------

    // // Verifies: REQ-VER-008
    #[test]
    fn rejects_resource_violations() {
        err(&[]); // vacío
        err(&[0x1b, 0x00]); // truncado
        err(&[0x42, 0x01]); // 2 bytes declarados, solo 1 presente
        err(&[0x62, 0x61]); // 2 bytes de texto declarados, solo 1 presente
        err(&[0x83, 0x01, 0x02]); // array truncado
        err(&[0xa1, 0x01]); // mapa sin valor
        err(&[0x1c]); // additional info reservada
        err(&[0xff]); // break suelto
        err(&[0x00, 0x00]); // basura tras el documento
        err(&[0x62, 0xc3]); // texto no UTF-8
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn enforces_limits() {
        let small = Limits {
            max_input_bytes: 4,
            max_depth: 2,
            max_elements: 2,
            max_text_bytes: 4,
        };
        // Entrada por encima del límite de bytes.
        assert!(parse_with_limits(&[0x84, 0x01, 0x02, 0x03, 0x04], &small).is_err());
        // Profundidad: [[[1]]] excede 2.
        assert!(parse_with_limits(&[0x81, 0x81, 0x81, 0x01], &small).is_err());
        // Elementos: [1,2,3] excede 2.
        assert!(parse_with_limits(&[0x83, 0x01, 0x02, 0x03], &small).is_err());
        // Texto largo.
        assert!(parse_with_limits(&[0x65, 0x61, 0x61, 0x61, 0x61, 0x61], &small).is_err());
    }

    // ---------- Nunca pánico ----------

    // // Verifies: REQ-VER-008 (INV-10)
    #[test]
    fn parser_never_panics_on_arbitrary_input() {
        let base = [
            0xa2u8, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03, 0xf9, 0x3c, 0x00,
        ];
        for index in 0..base.len() {
            let mut mutated = base;
            if let Some(slot) = mutated.get_mut(index) {
                *slot = slot.wrapping_add(1);
            }
            let _ = parse(&mutated);
        }
        for len in 0..base.len() {
            if let Some(prefix) = base.get(..len) {
                let _ = parse(prefix);
            }
        }
        // Byte aleatorio repetido.
        for byte in 0..=255u8 {
            let _ = parse(&[byte; 16]);
        }
    }

    // // Verifies: REQ-VER-008 (INV-10: anidamiento acotado, sin desbordamiento de pila)
    #[test]
    fn deep_nesting_is_bounded_not_stack_overflowing() {
        // Hallazgo del fuzzing (#27): arrays indefinidos anidados recursaban
        // sin acotar porque los fragmentos se parseaban a profundidad 0.
        let depth = 5_000usize;
        let mut input = vec![0x9fu8; depth];
        input.extend(core::iter::repeat(0xff).take(depth));

        let limits = Limits::profile_default();
        let permissive = parse_with_options(&input, &limits, &Strictness::permissive());
        assert!(
            permissive.is_err(),
            "deep nesting must be rejected, not overflow"
        );

        let deterministic = parse(&input);
        assert!(deterministic.is_err());

        // También con anidamiento definido muy profundo.
        let mut defined = vec![0x81u8; depth];
        defined.push(0x01);
        assert!(parse(&defined).is_err());
    }

    // // Verifies: REQ-VER-008 (INV-10: cadenas indefinidas anidadas, hallazgo #27)
    #[test]
    fn nested_indefinite_strings_consume_depth_budget() {
        // El presupuesto de profundidad debe consumirse también en los
        // fragmentos de cadenas indefinidas: sin el check, `7f 7f 7f ...`
        // recursaba sin cota (desbordamiento de pila bajo ASAN).
        let depth = 5_000usize;
        let mut input = vec![0x7fu8; depth];
        input.extend(core::iter::repeat(0xff).take(depth));

        let limits = Limits::profile_default();
        let permissive = parse_with_options(&input, &limits, &Strictness::permissive());
        assert!(
            permissive.is_err(),
            "nested indefinite strings must be bounded"
        );
        assert!(parse(&input).is_err());

        // Mezcla: array indefinido con cadenas indefinidas anidadas dentro.
        let mut mixed = vec![0x9fu8; 64];
        mixed.extend(core::iter::repeat(0x7f).take(64));
        mixed.extend(core::iter::repeat(0xff).take(128));
        mixed.push(0xff);
        assert!(parse_with_options(&mixed, &limits, &Strictness::permissive()).is_err());
    }

    // ---------- Determinismo del resultado ----------

    // // Verifies: REQ-VER-009
    #[test]
    fn parsing_is_deterministic() {
        let input = [0xa2u8, 0x01, 0x02, 0x61, 0x63, 0x82, 0x04, 0x05];
        assert_eq!(parse(&input).ok(), parse(&input).ok());
    }
}
