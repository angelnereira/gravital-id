//! Serializador JSON canónico y compacto (RFC 8785 / RFC 8259).
//!
//! Genera representaciones JSON deterministas sin espacios en blanco superfluos y con
//! claves de objeto ordenadas lexicográficamente, garantizando la reproducibilidad
//! requerida para el cálculo de digests en SD-JWT (RFC 9901 §5.2).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use gravital_id_codec::json::{Number, Value};

/// Serializa un [`Value`] a una cadena JSON canónica y compacta.
#[must_use]
pub fn to_canonical_json(value: &Value) -> String {
    let mut out = String::new();
    serialize_value(value, &mut out);
    out
}

/// Serializa un [`Value`] acumulando en un buffer `out`.
pub fn serialize_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(Number::PosInt(n)) => {
            let _ = write!(out, "{n}");
        }
        Value::Number(Number::NegInt(n)) => {
            let _ = write!(out, "{n}");
        }
        Value::Number(Number::Float(f)) => {
            // Nota: Number en gravital-id-codec solo almacena números finitos.
            let _ = write!(out, "{f}");
        }
        Value::String(s) => {
            serialize_string(s, out);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_value(item, out);
            }
            out.push(']');
        }
        Value::Object(entries) => {
            out.push('{');
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            // RFC 8785: Claves ordenadas por unidades de código UTF-16 / lexicográficamente
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (i, (key, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                serialize_string(key, out);
                out.push(':');
                serialize_value(val, out);
            }
            out.push('}');
        }
    }
}

/// Serializa una cadena con escapes RFC 8259 / RFC 8785.
fn serialize_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use gravital_id_codec::json::parse;

    #[test]
    fn canonical_json_primitives() {
        assert_eq!(to_canonical_json(&Value::Null), "null");
        assert_eq!(to_canonical_json(&Value::Bool(true)), "true");
        assert_eq!(to_canonical_json(&Value::Bool(false)), "false");
        assert_eq!(to_canonical_json(&Value::Number(Number::PosInt(42))), "42");
        assert_eq!(
            to_canonical_json(&Value::Number(Number::NegInt(-17))),
            "-17"
        );
        assert_eq!(
            to_canonical_json(&Value::String("hello world".to_string())),
            "\"hello world\""
        );
    }

    #[test]
    fn canonical_json_escapes_special_characters() {
        let val = Value::String("quote: \", backslash: \\, newline: \n".to_string());
        assert_eq!(
            to_canonical_json(&val),
            "\"quote: \\\", backslash: \\\\, newline: \\n\""
        );
    }

    #[test]
    fn canonical_json_sorts_object_keys_lexicographically() {
        let obj = Value::Object(vec![
            ("z".to_string(), Value::Number(Number::PosInt(3))),
            ("a".to_string(), Value::Number(Number::PosInt(1))),
            ("m".to_string(), Value::Number(Number::PosInt(2))),
        ]);
        assert_eq!(to_canonical_json(&obj), "{\"a\":1,\"m\":2,\"z\":3}");
    }

    #[test]
    fn canonical_json_preserves_array_order() {
        let arr = Value::Array(vec![
            Value::String("first".to_string()),
            Value::String("second".to_string()),
        ]);
        assert_eq!(to_canonical_json(&arr), "[\"first\",\"second\"]");
    }

    #[test]
    fn canonical_json_roundtrip_with_parser() {
        let input = "{\"age\":30,\"name\":\"Alice\",\"verified\":true}";
        let parsed = parse(input).expect("parse input");
        let serialized = to_canonical_json(&parsed);
        assert_eq!(
            serialized,
            "{\"age\":30,\"name\":\"Alice\",\"verified\":true}"
        );
    }
}
