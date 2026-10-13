//! Propiedades de los newtypes validados (F2.T01, REQ-VER-008).
//!
//! La propiedad central: `parse` acepta **exactamente** las cadenas que
//! satisfacen la regla de formato documentada, y todo valor aceptado se
//! conserva byte a byte (round-trip), de modo que no existe un estado inválido
//! representable.

use gravital_id_types::{
    BundleVersion, IssuerId, Kid, ProfileId, UnixTime, Vct, MAX_ID_LEN, MAX_VCT_LEN,
};
use proptest::prelude::*;

/// Referencia independiente de la regla kebab-case usada por `validate_kebab`.
fn is_valid_kebab(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

proptest! {
    // // Verifies: REQ-VER-008 (IssuerId acepta exactamente la regla documentada)
    #[test]
    fn issuer_id_parse_matches_reference_rule(value in "\\PC{0,80}") {
        let expected = is_valid_kebab(&value, MAX_ID_LEN);
        let parsed = IssuerId::parse(&value);
        prop_assert_eq!(parsed.is_ok(), expected);
        if let Ok(id) = parsed {
            prop_assert_eq!(id.as_str(), value.as_str());
            // Round-trip: el valor validado se vuelve a parsear sin cambios.
            prop_assert_eq!(IssuerId::parse(id.as_str()).ok(), Some(id));
        }
    }

    // // Verifies: REQ-VER-008 (Kid comparte la misma regla)
    #[test]
    fn kid_parse_matches_reference_rule(value in "\\PC{0,80}") {
        let expected = is_valid_kebab(&value, MAX_ID_LEN);
        prop_assert_eq!(Kid::parse(&value).is_ok(), expected);
    }

    // // Verifies: REQ-VER-008 (ProfileId comparte la misma regla)
    #[test]
    fn profile_id_parse_matches_reference_rule(value in "\\PC{0,80}") {
        let expected = is_valid_kebab(&value, MAX_ID_LEN);
        prop_assert_eq!(ProfileId::parse(&value).is_ok(), expected);
    }

    // // Verifies: REQ-VER-008 (Vct: acotado, sin espacios ni controles)
    #[test]
    fn vct_parse_matches_reference_rule(value in "\\PC{0,300}") {
        let expected = !value.is_empty()
            && value.len() <= MAX_VCT_LEN
            && !value.chars().any(|c| c.is_ascii_whitespace() || c.is_control());
        let parsed = Vct::parse(&value);
        prop_assert_eq!(parsed.is_ok(), expected);
        if let Ok(vct) = parsed {
            prop_assert_eq!(vct.as_str(), value.as_str());
        }
    }

    // // Verifies: REQ-VER-008 (UnixTime conserva el valor y ordena)
    #[test]
    fn unix_time_preserves_value_and_order(a in any::<u64>(), b in any::<u64>()) {
        let (ta, tb) = (UnixTime::from_seconds(a), UnixTime::from_seconds(b));
        prop_assert_eq!(ta.as_seconds(), a);
        prop_assert_eq!(ta.is_before(tb), a < b);
        prop_assert_eq!(ta.is_at_or_after(tb), a >= b);
        // Aritmética saturada: nunca desborda.
        let sum = ta.saturating_add_seconds(b);
        prop_assert!(sum.as_seconds() >= a);
        prop_assert_eq!(sum.as_seconds(), a.saturating_add(b));
    }

    // // Verifies: REQ-VER-008 (BundleVersion es monótona y saturada)
    #[test]
    fn bundle_version_is_monotonic_and_saturating(a in any::<u64>(), b in any::<u64>()) {
        let (va, vb) = (BundleVersion::new(a), BundleVersion::new(b));
        prop_assert_eq!(va.next().is_newer_than(va), true);
        prop_assert_eq!(va.is_newer_than(vb), a > b);
        prop_assert_eq!(va.next().as_u64(), a.saturating_add(1));
    }
}
