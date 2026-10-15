//! Claims de predicado precomputados por el perfil (F3.T07, REQ-CRED-005).
//!
//! Un predicado es un claim booleano que el emisor calcula **en el momento de la
//! emisión** a partir de un dato sensible (p. ej. `age_over_18` derivado de
//! `birth_date`) para que el titular pueda demostrarlo sin divulgar el dato.
//!
//! Trazabilidad:
//! - **REQ-CRED-005:** Los perfiles PUEDEN definir claims de predicado precomputados.
//!
//! El SDK no decide: expone los predicados divulgados y sus valores; la `Policy` del
//! integrador es quien acepta o rechaza (principio P-05).
//! - **INV-11:** La edad se calcula contra el instante que pasa el llamador; el núcleo
//!   nunca lee el reloj.
//!
//! **Semántica deliberada (F3.T07):** el verificador NUNCA recalcula un predicado a
//! partir del atributo divulgado. El valor vigente es el que firmó el emisor cuando
//! emitió la credencial; si un titular presenta `age_over_21 = false` emitido a los 20
//! años, eso sigue siendo lo que el emisor afirmó, y la decisión de aceptarlo
//! corresponde a la política del integrador, no al núcleo.

use alloc::format;
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::profile::ClaimKind;

use crate::profile::{parse_iso_date, ProfileSchema};

/// Segundos de un día solar (usado solo para proyectar `UnixTime` a fecha de calendario).
const SECONDS_PER_DAY: u64 = 86_400;

/// Edad en años cumplidos (0..=150).
///
/// Valor determinista derivado únicamente de la fecha de nacimiento y del instante
/// de referencia que recibe el llamador.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AgeYears(u8);

impl AgeYears {
    /// Edad máxima admitida.
    pub const MAX: u8 = 150;

    /// Construye una edad validada.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si supera [`AgeYears::MAX`].
    pub fn new(years: u8) -> Result<Self, GidError> {
        if years > Self::MAX {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!("age {years} exceeds the supported maximum of {}", Self::MAX),
            ));
        }
        Ok(Self(years))
    }

    /// Edad en años.
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// Convierte un número de días desde el epoch Unix en fecha de calendario (año, mes, día).
///
/// Algoritmo de calendario civil estándar ( Howard Hinnant, dominio público).
/// Determinista y sin acceso a reloj.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days.saturating_add(719_468);
    let era = if shifted >= 0 {
        shifted.saturating_div(146_097)
    } else {
        shifted.saturating_sub(146_096).saturating_div(146_097)
    };
    let day_of_era = shifted.saturating_sub(era.saturating_mul(146_097));
    let year_of_era = day_of_era
        .saturating_sub(day_of_era.saturating_div(1_460))
        .saturating_add(day_of_era.saturating_div(36_524))
        .saturating_sub(day_of_era.saturating_div(146_096))
        .saturating_div(365);
    let year = year_of_era.saturating_add(era.saturating_mul(400));
    let day_of_year = day_of_era.saturating_sub(
        year_of_era
            .saturating_mul(365)
            .saturating_add(year_of_era.saturating_div(4))
            .saturating_sub(year_of_era.saturating_div(100)),
    );
    let month_pos = day_of_year
        .saturating_mul(5)
        .saturating_add(2)
        .saturating_div(153);
    let day = day_of_year
        .saturating_sub(
            month_pos
                .saturating_mul(153)
                .saturating_add(2)
                .saturating_div(5),
        )
        .saturating_add(1);
    let month = if month_pos < 10 {
        month_pos.saturating_add(3)
    } else {
        month_pos.saturating_sub(9)
    };
    let year = year.saturating_add(i64::from(month <= 2));
    (year, month as u32, day as u32)
}

/// Fecha de calendario (`año`, `mes`, `día`) de un instante Unix, en UTC.
///
/// # Errores
/// [`ErrorCode::MalformedSdJwt`] si el instante no cabe en un día de calendario.
fn calendar_date(at: UnixTime) -> Result<(i64, u32, u32), GidError> {
    let days = i64::try_from(at.as_seconds().saturating_div(SECONDS_PER_DAY)).map_err(|_| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            "reference time is outside the supported calendar range",
        )
    })?;
    Ok(civil_from_days(days))
}

/// Calcula la edad en años cumplidos en el instante de referencia.
///
/// La edad se mide por fecha de calendario, no por días transcurridos: quien nace el
/// 29 de febrero cumple años el 1 de marzo en los años comunes.
///
/// # Errores
/// - [`ErrorCode::MalformedSdJwt`] si `birth_date` no es una fecha ISO 8601 válida
///   con calendario real, o si el instante de referencia no es representable.
/// - [`ErrorCode::CredentialNotYetValid`] si la fecha de nacimiento es posterior al
///   instante de referencia (fail-closed: no se calcula sobre datos incoherentes).
pub fn age_years(birth_date: &str, at: UnixTime) -> Result<AgeYears, GidError> {
    let (birth_year, birth_month, birth_day) = parse_iso_date(birth_date).ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            format!("'{birth_date}' is not an ISO 8601 date (YYYY-MM-DD)"),
        )
    })?;

    let (at_year, at_month, at_day) = calendar_date(at)?;

    let birth_year_i64 = i64::from(birth_year);
    let birth_month_i64 = i64::from(birth_month);
    let birth_day_i64 = i64::from(birth_day);
    let at_month_i64 = i64::from(at_month);
    let at_day_i64 = i64::from(at_day);

    // ¿Ya se cumplió años en el instante de referencia?
    let birthday_reached = (at_month_i64, at_day_i64) >= (birth_month_i64, birth_day_i64);
    let mut age = at_year.saturating_sub(birth_year_i64);
    if !birthday_reached {
        age = age.saturating_sub(1);
    }
    if age < 0 {
        return Err(GidError::new(
            ErrorCode::CredentialNotYetValid,
            format!("birth date '{birth_date}' is after the reference time"),
        ));
    }
    let age_u8 = u8::try_from(age).map_err(|_| {
        GidError::new(
            ErrorCode::MalformedSdJwt,
            "calculated age is outside the supported range",
        )
    })?;
    AgeYears::new(age_u8)
}

/// Predicado de edad del perfil, listo para añadir como claim a la credencial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePredicate {
    /// Nombre del claim de predicado declarado por el esquema (p. ej. `age_over_18`).
    pub name: &'static str,
    /// Valor que el emisor firma.
    pub value: bool,
}

impl ProfilePredicate {
    /// Convierte el predicado en un par `(nombre, valor JSON)` para el constructor de credenciales.
    #[must_use]
    pub fn to_claim(&self) -> (&'static str, Value) {
        (self.name, Value::Bool(self.value))
    }
}

/// Calcula los predicados de edad que el perfil declara, evaluados en el instante dado.
///
/// Es lo que usa el emisor para precomputar los claims de predicado **en el momento de
/// la emisión** (REQ-CRED-005). El resultado mantiene el orden del esquema.
///
/// # Errores
/// Los de [`age_years`], más [`ErrorCode::MalformedSdJwt`] si `birth_date` no es válida.
pub fn profile_age_predicates(
    schema: &ProfileSchema,
    birth_date: &str,
    at: UnixTime,
) -> Result<Vec<ProfilePredicate>, GidError> {
    let age = age_years(birth_date, at)?.as_u8();
    let mut predicates = Vec::new();
    for spec in schema.claims {
        if let ClaimKind::Predicate { min_age_years } = spec.kind {
            predicates.push(ProfilePredicate {
                name: spec.name,
                value: age >= min_age_years,
            });
        }
    }
    Ok(predicates)
}

/// Predicado divulgado en una presentación, con su valor tal y como lo firmó el emisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisclosedPredicate {
    /// Nombre del claim de predicado (p. ej. `age_over_18`).
    pub name: &'static str,
    /// Valor divulgado.
    pub value: bool,
    /// Umbbral declarado por el esquema del perfil.
    pub min_age_years: u8,
}

impl DisclosedPredicate {
    /// Indica si el predicado divulgado satisface su umbral.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        self.value
    }
}

/// Extrae los predicados divulgados en una presentación (REQ-CRED-005).
///
/// El núcleo **no** acepta ni rechaza por el valor del predicado: devuelve los hechos
/// y la `Policy` del integrador decide (por ejemplo, exigir `age_over_18 == true`).
/// Un predicado ausente simplemente no aparece en la lista: no se infiere `false` ni
/// `true` por la ausencia.
///
/// Si la credencial declara un predicado con un valor que no es booleano, la
/// validación de esquema ya lo habrá rechazado antes de llegar aquí.
#[must_use]
pub fn disclosed_predicates(schema: &ProfileSchema, claims: &Value) -> Vec<DisclosedPredicate> {
    let Value::Object(entries) = claims else {
        return Vec::new();
    };

    let mut disclosed = Vec::new();
    for spec in schema.claims {
        let ClaimKind::Predicate { min_age_years } = spec.kind else {
            continue;
        };
        if let Some(Value::Bool(value)) =
            entries.iter().find(|(k, _)| k == spec.name).map(|(_, v)| v)
        {
            disclosed.push(DisclosedPredicate {
                name: spec.name,
                value: *value,
                min_age_years,
            });
        }
    }
    disclosed
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
    use gravital_id_types::ProfileId;

    use alloc::{string::ToString, vec};

    fn personal_schema() -> &'static ProfileSchema {
        ProfileSchema::lookup(&ProfileId::parse(ProfileId::PERSONAL_V1).unwrap()).unwrap()
    }

    #[test]
    fn calendar_projection_matches_known_dates() {
        // 1970-01-01, 2000-02-29 (bisiesto), 2026-10-13.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_097), (2000, 5, 20));
        let days = i64::try_from(1_791_849_600u64 / 86_400).unwrap();
        assert_eq!(civil_from_days(days), (2026, 10, 13));
    }

    #[test]
    fn age_is_measured_by_calendar_anniversary() {
        let birth = "2000-10-13";

        // El día exacto del cumpleaños ya se cumplen años.
        let birthday = UnixTime::from_seconds(1_791_849_600); // 2026-10-13 UTC
        assert_eq!(age_years(birth, birthday).unwrap().as_u8(), 26);

        // Un día antes, todavía no.
        let day_before = UnixTime::from_seconds(1_791_763_200); // 2026-10-12 UTC
        assert_eq!(age_years(birth, day_before).unwrap().as_u8(), 25);
    }

    #[test]
    fn leap_day_birthdays_turn_on_march_first() {
        let birth = "2004-02-29";

        let feb_28 = UnixTime::from_seconds(1_740_700_800); // 2025-02-28 UTC
        assert_eq!(age_years(birth, feb_28).unwrap().as_u8(), 20);

        let mar_01 = UnixTime::from_seconds(1_740_787_200); // 2025-03-01 UTC
        assert_eq!(age_years(birth, mar_01).unwrap().as_u8(), 21);
    }

    #[test]
    fn birth_date_in_the_future_fails_closed() {
        let err = age_years("2030-01-01", UnixTime::from_seconds(1_700_000_000)).unwrap_err();
        assert_eq!(err.code, ErrorCode::CredentialNotYetValid);
    }

    #[test]
    fn malformed_birth_date_is_rejected() {
        let err = age_years("2000-13-01", UnixTime::from_seconds(1_700_000_000)).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
        let err = age_years("01/01/2000", UnixTime::from_seconds(1_700_000_000)).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn profile_predicates_follow_the_schema_thresholds() {
        let schema = personal_schema();

        // Nacido el 2006-10-13: en 2026-10-13 cumple 20 años.
        let predicates =
            profile_age_predicates(schema, "2006-10-13", UnixTime::from_seconds(1_791_849_600))
                .unwrap();
        let values: Vec<bool> = predicates.iter().map(|p| p.value).collect();
        assert_eq!(values, vec![true, false]); // age_over_18 = true, age_over_21 = false

        // A los 21 años y un día, ambos son ciertos.
        let predicates =
            profile_age_predicates(schema, "2005-10-12", UnixTime::from_seconds(1_791_849_600))
                .unwrap();
        assert!(predicates.iter().all(|p| p.value));
    }

    #[test]
    fn disclosed_predicates_are_reported_without_deciding() {
        let schema = personal_schema();
        let claims = Value::Object(vec![
            ("age_over_18".to_string(), Value::Bool(true)),
            ("given_name".to_string(), Value::String("Ana".to_string())),
        ]);

        let disclosed = disclosed_predicates(schema, &claims);
        assert_eq!(disclosed.len(), 1);
        assert_eq!(disclosed.first().unwrap().name, "age_over_18");
        assert!(disclosed.first().unwrap().is_satisfied());

        // La ausencia de un predicado no implica ningún valor.
        let empty = disclosed_predicates(
            schema,
            &Value::Object(vec![(
                "given_name".to_string(),
                Value::String("Ana".to_string()),
            )]),
        );
        assert!(empty.is_empty());
    }
}
