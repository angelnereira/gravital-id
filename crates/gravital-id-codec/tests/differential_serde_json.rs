//! Prueba diferencial del lector JSON frente a `serde_json` (F2.T03, REQ-VER-008).
//!
//! `serde_json` es la referencia independiente **solo en pruebas**: el lector de
//! producción (`gravital-id-codec::json`) es `no_std` y no depende de ella
//! (INV-01). La propiedad comprobada: nuestro lenguaje es un subconjunto estricto
//! del de `serde_json` —todo lo que aceptamos, ella lo acepta con el mismo valor—
//! y todo JSON que genere la estrategia (respetando nuestros límites) lo
//! aceptamos con el valor exacto.

// Pruebas de integración con condiciones locales y deterministas: excepción de
// lints documentada (PROJECT_STRUCTURE.md §5.1).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use gravital_id_codec::json::{self, Limits, Number, Value};
use proptest::prelude::*;

/// Estrategia de JSON acotado que respeta los límites del perfil.
fn bounded_json() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        Just("null".to_string()),
        any::<bool>().prop_map(|b| b.to_string()),
        any::<i64>().prop_map(|v| v.to_string()),
        // Sin notación científica: el literal debe seguir siendo entero.
        r#"[a-z]{1,8}"#.prop_map(|s| format!("\"{s}\"")),
    ];

    leaf.prop_recursive(4, 32, 3, |inner| {
        prop_oneof![
            // Arrays de hasta 3 elementos.
            prop::collection::vec(inner.clone(), 0..=3)
                .prop_map(|items| format!("[{}]", items.join(","))),
            // Objetos con claves únicas de hasta 3 miembros.
            prop::collection::hash_map(r#"key[0-9]{1,2}"#, inner, 0..=3).prop_map(|map| {
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                let body: Vec<String> = keys
                    .into_iter()
                    .map(|k| format!("\"{k}\":{}", map.get(&k).cloned().unwrap_or_default()))
                    .collect();
                format!("{{{}}}", body.join(","))
            }),
        ]
    })
}

proptest! {
    // // Verifies: REQ-VER-008 (nuestro parseo acepta lo generado, con el valor exacto)
    #[test]
    fn generated_json_round_trips_through_our_parser(doc in bounded_json()) {
        // La referencia independiente debe parsearlo también.
        let reference = serde_json::from_str::<serde_json::Value>(&doc)
            .expect("serde_json accepts generated documents");
        let ours = json::parse(&doc).expect("our parser accepts generated documents");

        // Comparación estructural contra serde_json::Value.
        prop_assert_eq!(describe(&ours), describe_json(&reference));
    }

    // // Verifies: REQ-VER-008 (subconjunto estricto: lo que aceptamos lo acepta serde_json)
    #[test]
    fn anything_we_accept_serde_json_accepts(data in "\\PC{0,120}") {
        if let Ok(ours) = json::parse(&data) {
            let reference = serde_json::from_str::<serde_json::Value>(&data)
                .expect("serde_json must accept what our parser accepts");
            prop_assert_eq!(describe(&ours), describe_json(&reference));
        }
    }

    // // Verifies: REQ-VER-009 (determinismo)
    #[test]
    fn parsing_is_deterministic(data in "\\PC{0,120}") {
        let first = json::parse(&data);
        let second = json::parse(&data);
        prop_assert_eq!(first.is_ok(), second.is_ok());
        if let (Ok(a), Ok(b)) = (first, second) {
            prop_assert_eq!(a, b);
        }
    }

    // // Verifies: REQ-VER-008 (nunca entra en pánico, tampoco por bytes)
    #[test]
    fn parse_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..160)) {
        let _ = json::parse_bytes(&data, &Limits::profile_default());
    }
}

/// Descripción textual estable de un valor nuestro (para comparar).
fn describe(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(Number::PosInt(v)) => format!("i{v}"),
        Value::Number(Number::NegInt(v)) => format!("i{v}"),
        Value::Number(Number::Float(v)) => format!("f{v}"),
        Value::String(s) => format!("s:{s}"),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(describe).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(entries) => {
            // Orden normalizado (igual que en el lado de serde_json): la
            // comparación es de contenido, no de orden de documento.
            let mut parts: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("{k}={}", describe(v)))
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
    }
}

/// Descripción equivalente de un valor de serde_json.
fn describe_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => {
            if let Some(v) = n.as_i64() {
                format!("i{v}")
            } else if let Some(v) = n.as_u64() {
                format!("i{v}")
            } else {
                format!("f{}", n.as_f64().unwrap_or_default())
            }
        }
        serde_json::Value::String(s) => format!("s:{s}"),
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(describe_json).collect();
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::Object(map) => {
            // serde_json::Map preserva el orden de inserción solo con la feature
            // "preserve_order"; sin ella es BTreeMap (ordenado). Nuestro parser
            // preserva el orden del documento, así que normalizamos ordenando.
            let mut parts: Vec<String> = map
                .iter()
                .map(|(k, v)| format!("{k}={}", describe_json(v)))
                .collect();
            parts.sort();
            format!("{{{}}}", parts.join(","))
        }
    }
}
