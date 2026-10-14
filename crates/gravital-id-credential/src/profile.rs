//! Esquemas de perfil incorporados en compilación (F3.T06, REQ-CRED-004).
//!
//! Los esquemas son la traducción literal de `docs/specs/profiles/<id>.md` §3
//! ("Esquema JSON Canónico de Referencia") a constantes del crate, de modo que la
//! validación no depende de leer archivos en tiempo de ejecución (INV-01, L1–L4
//! sin I/O) ni de un motor JSON Schema completo.
//!
//! Trazabilidad:
//! - **REQ-CRED-004:** Los claims DEBEN validarse contra el esquema del perfil y del
//!   `vct` en emisión y verificación.
//! - **REQ-VER-003:** Fail-closed: cualquier claim fuera del esquema detiene la emisión
//!   o la verificación con [`ErrorCode::SchemaValidationFailed`] (`PIP-E3004`).
//! - **INV-05:** Nunca se omite una validación por desconocimiento: si un perfil no
//!   tiene esquema registrado, la operación falla en lugar de aceptar sin comprobar.

use alloc::format;
use alloc::vec::Vec;

use gravital_id_codec::json::{Number, Value};
use gravital_id_types::{ErrorCode, GidError, ProfileId, Vct};

/// Tipo admitido por los esquemas normativos de `docs/specs/profiles/`.
///
/// Cubre exactamente las palabras clave JSON Schema que usan las especificaciones
/// (`type`, `enum`, `pattern`, `format`, `items`). Cualquier palabra clave no
/// representable aquí obliga a ampliar este `enum`; nunca se ignora en silencio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// `{"type": "string"}`.
    String,
    /// `{"type": "string", "format": "date"}` → ISO 8601 `YYYY-MM-DD`.
    StringDate,
    /// `{"type": "string", "format": "date-time"}` → RFC 3339.
    StringDateTime,
    /// `{"type": "string", "enum": [...]}`.
    StringEnum(&'static [&'static str]),
    /// `{"type": "string", "pattern": "^[A-Z]{3}$"}` (código de país ISO 3166-1 alfa-3).
    CountryCode,
    /// `{"type": "boolean"}`.
    Boolean,
    /// `{"type": "number"}` restringido a enteros sin signo (`u64`).
    Uint,
    /// `{"type": "array", "items": {"type": "string"}}`.
    StringArray,
}

impl ClaimKind {
    /// Nombre del tipo tal como aparece en el esquema JSON (para mensajes de error).
    #[must_use]
    pub fn json_type_name(&self) -> &'static str {
        match self {
            Self::String | Self::StringDate | Self::StringDateTime | Self::CountryCode => "string",
            Self::StringEnum(_) => "string",
            Self::Boolean => "boolean",
            Self::Uint => "number",
            Self::StringArray => "array",
        }
    }

    /// Comprueba que un valor JSON satisface el tipo del esquema (fail-closed).
    fn validate_value(&self, name: &str, value: &Value) -> Result<(), GidError> {
        match self {
            Self::String => match value {
                Value::String(s) if !s.is_empty() => Ok(()),
                Value::String(_) => Err(schema_error(name, "string value must not be empty")),
                _ => Err(self.type_error(name, value)),
            },
            Self::StringDate => match value {
                Value::String(s) if is_iso_date(s) => Ok(()),
                Value::String(_) => Err(schema_error(
                    name,
                    "value is not an ISO 8601 date (YYYY-MM-DD)",
                )),
                _ => Err(self.type_error(name, value)),
            },
            Self::StringDateTime => match value {
                Value::String(s) if is_date_time(s) => Ok(()),
                Value::String(_) => Err(schema_error(name, "value is not an RFC 3339 date-time")),
                _ => Err(self.type_error(name, value)),
            },
            Self::StringEnum(allowed) => match value {
                Value::String(s) if allowed.contains(&s.as_str()) => Ok(()),
                Value::String(s) => Err(schema_error(
                    name,
                    &format!("value '{s}' is not one of the values allowed by the profile schema"),
                )),
                _ => Err(self.type_error(name, value)),
            },
            Self::CountryCode => match value {
                Value::String(s) if is_country_code(s) => Ok(()),
                Value::String(s) => Err(schema_error(
                    name,
                    &format!("value '{s}' does not match the pattern '^[A-Z]{{3}}$'"),
                )),
                _ => Err(self.type_error(name, value)),
            },
            Self::Boolean => match value {
                Value::Bool(_) => Ok(()),
                _ => Err(self.type_error(name, value)),
            },
            Self::Uint => match value {
                Value::Number(Number::PosInt(_)) => Ok(()),
                Value::Number(_) => {
                    Err(schema_error(name, "number must be a non-negative integer"))
                }
                _ => Err(self.type_error(name, value)),
            },
            Self::StringArray => match value {
                Value::Array(items) => {
                    for item in items {
                        match item {
                            Value::String(s) if !s.is_empty() => {}
                            _ => return Err(self.type_error(name, item)),
                        }
                    }
                    Ok(())
                }
                _ => Err(self.type_error(name, value)),
            },
        }
    }

    /// Error tipado para un valor que no cumple el tipo del esquema.
    fn type_error(&self, name: &str, value: &Value) -> GidError {
        schema_error(
            name,
            &format!(
                "expected {} per profile schema, got JSON {}",
                self.json_type_name(),
                json_type_of(value)
            ),
        )
    }
}

/// Especificación de un claim del esquema de un perfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimSpec {
    /// Nombre del claim (atributo divulgable).
    pub name: &'static str,
    /// Tipo admitido por el esquema.
    pub kind: ClaimKind,
    /// `true` si el esquema lo declara en `required`.
    pub required: bool,
}

impl ClaimSpec {
    /// Crea la especificación de un claim del esquema.
    #[must_use]
    pub const fn new(name: &'static str, kind: ClaimKind, required: bool) -> Self {
        Self {
            name,
            kind,
            required,
        }
    }
}

/// Esquema normativo de un perfil de credencial (`docs/specs/profiles/<id>.md` §3).
///
/// Los valores `profile` y `vct` son literales de la especificación; la búsqueda se
/// hace por cadena para poder declarar los esquemas como constantes (`ProfileId` y
/// `Vct` tienen constructores de validación no constantes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSchema {
    /// Identificador del perfil (`pip-personal-v1`, …).
    pub profile: &'static str,
    /// Tipo de credencial verificable asociado al perfil.
    pub vct: &'static str,
    /// Claims declarados por el esquema.
    pub claims: &'static [ClaimSpec],
}

impl ProfileSchema {
    /// Busca el esquema de un perfil por su identificador.
    #[must_use]
    pub fn lookup(profile_id: &ProfileId) -> Option<&'static ProfileSchema> {
        PROFILE_SCHEMAS
            .iter()
            .find(|schema| schema.profile == profile_id.as_str())
    }

    /// Busca el esquema de un perfil por el `vct` de la credencial.
    #[must_use]
    pub fn lookup_by_vct(vct: &Vct) -> Option<&'static ProfileSchema> {
        Self::lookup_by_vct_str(vct.as_str())
    }

    /// Busca el esquema de un perfil por la cadena del `vct`.
    #[must_use]
    pub fn lookup_by_vct_str(vct: &str) -> Option<&'static ProfileSchema> {
        PROFILE_SCHEMAS.iter().find(|schema| schema.vct == vct)
    }

    /// Todos los esquemas registrados en compilación.
    #[must_use]
    pub fn all() -> &'static [ProfileSchema] {
        PROFILE_SCHEMAS
    }

    /// Especificación de un claim del esquema, si está declarado.
    #[must_use]
    pub fn claim(&self, name: &str) -> Option<&'static ClaimSpec> {
        self.claims.iter().find(|spec| spec.name == name)
    }

    /// Claims que el esquema declara obligatorios.
    #[must_use]
    pub fn required_claims(&self) -> Vec<&'static str> {
        self.claims
            .iter()
            .filter(|spec| spec.required)
            .map(|spec| spec.name)
            .collect()
    }

    /// Valida un objeto de atributos contra el esquema (REQ-CRED-004, REQ-VER-003).
    ///
    /// Reglas:
    /// - Todo claim declarado en `required` DEBE estar presente.
    /// - Todo claim presente DEBE cumplir el tipo declarado (`enum`, patrones y formatos incluidos).
    ///
    /// Es la comprobación que aplica el **emisor** sobre los atributos que incluye en la
    /// credencial antes de firmarla.
    ///
    /// # Errores
    /// [`ErrorCode::SchemaValidationFailed`] (`PIP-E3004`) ante cualquier incumplimiento.
    pub fn validate(&self, attributes: &Value) -> Result<(), GidError> {
        self.validate_with_required(attributes, true)
    }

    /// Valida los atributos **divulgados en una presentación** contra el esquema.
    ///
    /// Comprueba únicamente los tipos de los claims presentes (`enum`, patrones y
    /// formatos incluidos). No exige los claims `required`: el titular puede divulgar
    /// cualquier subconjunto de atributos (la minimización de presentaciones se exige en
    /// la fase F5) y el verificador
    /// no puede distinguir un atributo no divulgado de un digest señuelo. La obligación
    /// de incluir los claims `required` recae en el emisor y se comprueba con
    /// [`ProfileSchema::validate`] en el momento de la emisión.
    ///
    /// # Errores
    /// [`ErrorCode::SchemaValidationFailed`] (`PIP-E3004`) si algún claim divulgado
    /// incumple el tipo declarado por el esquema.
    pub fn validate_disclosed(&self, attributes: &Value) -> Result<(), GidError> {
        self.validate_with_required(attributes, false)
    }

    /// Implementación común de [`ProfileSchema::validate`] y
    /// [`ProfileSchema::validate_disclosed`].
    ///
    /// Los atributos no declarados en el esquema se admiten: las especificaciones no
    /// fijan `additionalProperties: false` y los perfiles pueden añadir claims sin
    /// romper la interoperabilidad. Los metadatos siempre visibles de la capa VC
    /// (`iss`, `vct`, …) se validan en `verify_vc`, no aquí.
    fn validate_with_required(
        &self,
        attributes: &Value,
        enforce_required: bool,
    ) -> Result<(), GidError> {
        let entries = match attributes {
            Value::Object(entries) => entries,
            _ => {
                return Err(GidError::new(
                    ErrorCode::SchemaValidationFailed,
                    "credential attributes must be a JSON object",
                ));
            }
        };

        for spec in self.claims {
            let value = entries.iter().find(|(k, _)| k == spec.name).map(|(_, v)| v);
            match value {
                Some(value) => spec.kind.validate_value(spec.name, value)?,
                None if enforce_required && spec.required => {
                    return Err(GidError::new(
                        ErrorCode::SchemaValidationFailed,
                        format!(
                            "missing required attribute '{}' for profile '{}'",
                            spec.name, self.profile
                        ),
                    ));
                }
                None => {}
            }
        }

        Ok(())
    }
}

/// Error de validación de esquema con el nombre del claim en el mensaje.
fn schema_error(name: &str, detail: &str) -> GidError {
    GidError::new(
        ErrorCode::SchemaValidationFailed,
        format!("claim '{name}' violates the profile schema: {detail}"),
    )
}

/// Nombre del tipo JSON de un valor (para mensajes de error legibles).
fn json_type_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(Number::PosInt(_)) | Value::Number(Number::NegInt(_)) => "integer",
        Value::Number(Number::Float(_)) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Comprueba el patrón `^[A-Z]{3}$`.
fn is_country_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 3 && bytes.iter().all(u8::is_ascii_uppercase)
}

/// Convierte una porción de bytes ASCII en un entero sin signo.
fn ascii_digits_to_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = u32::from(byte.wrapping_sub(b'0'));
        value = value.saturating_mul(10).saturating_add(digit);
    }
    Some(value)
}

/// Valida una fecha de calendario (con años bisiestos).
fn is_valid_calendar_date(year: u32, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= max_day
}

/// Analiza una fecha ISO 8601 (`YYYY-MM-DD`) y valida el calendario.
fn parse_iso_date(value: &str) -> Option<(u32, u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 {
        return None;
    }
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let year = ascii_digits_to_u32(bytes.get(0..4)?)?;
    let month = ascii_digits_to_u32(bytes.get(5..7)?)?;
    let day = ascii_digits_to_u32(bytes.get(8..10)?)?;
    if !is_valid_calendar_date(year, month, day) {
        return None;
    }
    Some((year, month, day))
}

/// Comprueba el formato `date` de JSON Schema (`YYYY-MM-DD` con fecha válida).
fn is_iso_date(value: &str) -> bool {
    parse_iso_date(value).is_some()
}

/// Comprueba una hora `HH:MM:SS` válida.
fn is_valid_time(hour: u32, minute: u32, second: u32) -> bool {
    hour <= 23 && minute <= 59 && second <= 60
}

/// Comprueba el formato `date-time` de JSON Schema (subconjunto RFC 3339 usado por
/// los perfiles: `YYYY-MM-DDTHH:MM:SS[.frac][Z|±HH:MM]`).
fn is_date_time(value: &str) -> bool {
    let Some(date_part) = value.get(..10) else {
        return false;
    };
    let Some(_) = parse_iso_date(date_part) else {
        return false;
    };
    if value.as_bytes().get(10) != Some(&b'T') {
        return false;
    }
    let Some(time_part) = value.get(11..19) else {
        return false;
    };
    let time_bytes = time_part.as_bytes();
    if time_bytes.get(2) != Some(&b':') || time_bytes.get(5) != Some(&b':') {
        return false;
    }
    let Some(hour) = ascii_digits_to_u32(time_bytes.get(0..2).unwrap_or(&[])) else {
        return false;
    };
    let Some(minute) = ascii_digits_to_u32(time_bytes.get(3..5).unwrap_or(&[])) else {
        return false;
    };
    let Some(second) = ascii_digits_to_u32(time_bytes.get(6..8).unwrap_or(&[])) else {
        return false;
    };
    if !is_valid_time(hour, minute, second) {
        return false;
    }

    let suffix = value.get(19..).unwrap_or("");
    if suffix.is_empty() {
        return false;
    }
    let mut rest = suffix;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits_len = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        let digits = fraction.get(..digits_len).unwrap_or("");
        if digits.is_empty() {
            return false;
        }
        rest = fraction.get(digits_len..).unwrap_or("");
    }
    match rest.as_bytes().first() {
        Some(b'Z') => rest.len() == 1,
        Some(b'+') | Some(b'-') => is_utc_offset(&rest[1..]),
        _ => false,
    }
}

/// Comprueba un desplazamiento horario `HH:MM`.
fn is_utc_offset(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 5 || bytes.get(2) != Some(&b':') {
        return false;
    }
    let Some(hour) = ascii_digits_to_u32(bytes.get(0..2).unwrap_or(&[])) else {
        return false;
    };
    let Some(minute) = ascii_digits_to_u32(bytes.get(3..5).unwrap_or(&[])) else {
        return false;
    };
    hour <= 23 && minute <= 59
}

/// Esquemas normativos en compilación (`docs/specs/profiles/*.md` §3).
///
/// Toda modificación de un esquema aquí DEBE acompañarse del cambio en la
/// especificación del perfil (spec-first, `AGENTS.md` §12) y de un vector de
/// conformidad en `conformance/vectors/` (F3.T09).
pub const PROFILE_SCHEMAS: &[ProfileSchema] = &[
    ProfileSchema {
        profile: ProfileId::PERSONAL_V1,
        vct: "https://credentials.gravital.io/vct/personal/id-v1",
        claims: &[
            ClaimSpec::new("given_name", ClaimKind::String, true),
            ClaimSpec::new("family_name", ClaimKind::String, true),
            ClaimSpec::new("birth_date", ClaimKind::StringDate, false),
            ClaimSpec::new("age_over_18", ClaimKind::Boolean, true),
            ClaimSpec::new("age_over_21", ClaimKind::Boolean, false),
            ClaimSpec::new("nationality", ClaimKind::CountryCode, false),
            ClaimSpec::new("document_number", ClaimKind::String, false),
        ],
    },
    ProfileSchema {
        profile: ProfileId::FINANCIAL_V1,
        vct: "https://credentials.gravital.io/vct/financial/kyc-v1",
        claims: &[
            ClaimSpec::new("legal_name", ClaimKind::String, true),
            ClaimSpec::new("tax_id", ClaimKind::String, true),
            ClaimSpec::new(
                "id_document_type",
                ClaimKind::StringEnum(&["passport", "national_id"]),
                false,
            ),
            ClaimSpec::new("id_document_number", ClaimKind::String, false),
            ClaimSpec::new(
                "kyc_tier",
                ClaimKind::StringEnum(&["tier1", "tier2", "tier3"]),
                true,
            ),
            ClaimSpec::new("aml_cleared", ClaimKind::Boolean, true),
            ClaimSpec::new("aml_cleared_at", ClaimKind::StringDateTime, false),
            ClaimSpec::new("pep_status", ClaimKind::Boolean, false),
            ClaimSpec::new("country_of_residence", ClaimKind::CountryCode, false),
        ],
    },
    ProfileSchema {
        profile: ProfileId::ENTERPRISE_V1,
        vct: "https://credentials.gravital.io/vct/enterprise/employee-v1",
        claims: &[
            ClaimSpec::new("employee_id", ClaimKind::String, true),
            ClaimSpec::new("organization_id", ClaimKind::String, true),
            ClaimSpec::new("department", ClaimKind::String, false),
            ClaimSpec::new("job_title", ClaimKind::String, false),
            ClaimSpec::new(
                "security_clearance",
                ClaimKind::StringEnum(&["confidential", "secret", "top_secret"]),
                true,
            ),
            ClaimSpec::new("authorized_zones", ClaimKind::StringArray, true),
            ClaimSpec::new("valid_until", ClaimKind::StringDateTime, false),
        ],
    },
];

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

    fn personal_schema() -> &'static ProfileSchema {
        ProfileSchema::lookup(&ProfileId::parse(ProfileId::PERSONAL_V1).expect("profile"))
            .expect("personal schema")
    }

    fn attributes(entries: Vec<(&str, Value)>) -> Value {
        Value::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    #[test]
    fn schemas_registered_for_the_three_normative_profiles() {
        assert_eq!(PROFILE_SCHEMAS.len(), 3);
        for profile_id in [
            ProfileId::PERSONAL_V1,
            ProfileId::FINANCIAL_V1,
            ProfileId::ENTERPRISE_V1,
        ] {
            let schema = ProfileSchema::lookup(&ProfileId::parse(profile_id).expect("profile"))
                .expect("schema registered");
            assert!(!schema.claims.is_empty());
        }
        assert!(!personal_schema().required_claims().is_empty());
    }

    #[test]
    fn nominal_personal_attributes_pass_validation() {
        let schema = personal_schema();
        let value = attributes(vec![
            ("given_name", Value::String("Ana".to_string())),
            ("family_name", Value::String("Perez".to_string())),
            ("age_over_18", Value::Bool(true)),
            ("birth_date", Value::String("1990-04-12".to_string())),
            ("nationality", Value::String("PAN".to_string())),
        ]);
        schema.validate(&value).expect("valid attributes");
    }

    #[test]
    fn rejection_of_missing_required_attribute() {
        let schema = personal_schema();
        let value = attributes(vec![("given_name", Value::String("Ana".to_string()))]);
        let err = schema.validate(&value).expect_err("missing required");
        assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
        assert!(err.message.contains("family_name"));
    }

    #[test]
    fn rejection_of_wrong_type_and_enum_values() {
        // Booleano donde el esquema pide cadena.
        let schema = personal_schema();
        let value = attributes(vec![
            ("given_name", Value::Bool(true)),
            ("family_name", Value::String("Perez".to_string())),
            ("age_over_18", Value::Bool(true)),
        ]);
        let err = schema.validate(&value).expect_err("tipo incorrecto");
        assert_eq!(err.code, ErrorCode::SchemaValidationFailed);

        // Fuera del enum del perfil financiero.
        let financial = ProfileSchema::lookup_by_vct_str(
            "https://credentials.gravital.io/vct/financial/kyc-v1",
        )
        .expect("financial schema");
        let value = attributes(vec![
            ("legal_name", Value::String("Ana Perez".to_string())),
            ("tax_id", Value::String("8-123-456".to_string())),
            ("kyc_tier", Value::String("tier9".to_string())),
            ("aml_cleared", Value::Bool(false)),
        ]);
        let err = financial.validate(&value).expect_err("valor fuera de enum");
        assert_eq!(err.code, ErrorCode::SchemaValidationFailed);
        assert!(err.message.contains("kyc_tier"));
    }

    #[test]
    fn rejection_of_invalid_dates_country_codes_and_arrays() {
        let schema = personal_schema();

        let bad_date = attributes(vec![
            ("given_name", Value::String("Ana".to_string())),
            ("family_name", Value::String("Perez".to_string())),
            ("age_over_18", Value::Bool(true)),
            ("birth_date", Value::String("1990-02-30".to_string())),
        ]);
        assert_eq!(
            schema.validate(&bad_date).expect_err("fecha inválida").code,
            ErrorCode::SchemaValidationFailed
        );

        let bad_country = attributes(vec![
            ("given_name", Value::String("Ana".to_string())),
            ("family_name", Value::String("Perez".to_string())),
            ("age_over_18", Value::Bool(true)),
            ("nationality", Value::String("pan".to_string())),
        ]);
        assert_eq!(
            schema
                .validate(&bad_country)
                .expect_err("país inválido")
                .code,
            ErrorCode::SchemaValidationFailed
        );

        let enterprise =
            ProfileSchema::lookup(&ProfileId::parse(ProfileId::ENTERPRISE_V1).unwrap())
                .expect("enterprise schema");
        let bad_array = attributes(vec![
            ("employee_id", Value::String("E-1".to_string())),
            ("organization_id", Value::String("O-1".to_string())),
            ("security_clearance", Value::String("secret".to_string())),
            (
                "authorized_zones",
                Value::Array(vec![Value::Number(Number::PosInt(1))]),
            ),
        ]);
        assert_eq!(
            enterprise
                .validate(&bad_array)
                .expect_err("array inválido")
                .code,
            ErrorCode::SchemaValidationFailed
        );
    }

    #[test]
    fn undeclared_attributes_are_admitted() {
        let schema = personal_schema();
        let value = attributes(vec![
            ("given_name", Value::String("Ana".to_string())),
            ("family_name", Value::String("Perez".to_string())),
            ("age_over_18", Value::Bool(true)),
            ("future_claim", Value::String("value".to_string())),
        ]);
        schema
            .validate(&value)
            .expect("additional properties admitidos");
    }

    #[test]
    fn lookup_by_vct_matches_the_reference_schema() {
        let vct =
            Vct::parse("https://credentials.gravital.io/vct/enterprise/employee-v1").expect("vct");
        let schema = ProfileSchema::lookup_by_vct(&vct).expect("schema");
        assert_eq!(schema.profile, ProfileId::ENTERPRISE_V1);
        assert!(ProfileSchema::lookup_by_vct_str("https://unknown.example/vct").is_none());
    }

    #[test]
    fn date_time_validation_accepts_rfc3339_subset() {
        assert!(is_date_time("2026-10-13T09:30:00Z"));
        assert!(is_date_time("2026-10-13T09:30:00.500Z"));
        assert!(is_date_time("2026-10-13T09:30:00-05:00"));
        assert!(!is_date_time("2026-10-13 09:30:00Z"));
        assert!(!is_date_time("2026-10-13T09:30:00"));
        assert!(!is_date_time("2026-10-13T09:30:00+25:00"));
        assert!(is_iso_date("2024-02-29"));
        assert!(!is_iso_date("2023-02-29"));
    }
}
