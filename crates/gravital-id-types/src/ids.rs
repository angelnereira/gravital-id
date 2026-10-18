//! Identificadores validados del protocolo (`ids.rs`, F2.T01).
//!
//! Reglas de formato tomadas de las especificaciones normativas:
//! - `IssuerId`: `TRUST_BUNDLE.md §3.1` (p. ej. `iss-panama-tribunal-electoral`).
//! - `Kid`: `TRUST_BUNDLE.md §2.3`/`§3.1` (p. ej. `te-iss-2026-ecdsa-01`).
//! - `Vct`: perfiles de credencial (`docs/specs/profiles/`, p. ej.
//!   `https://credentials.gravital.io/vct/personal/id-v1`).
//! - `ProfileId`: identificadores de perfil (`pip-personal-v1`, `pip-financial-v1`,
//!   `pip-enterprise-v1`).
//!
//! Los identificadores de organización y de clave no son datos personales
//! (INV-02), pero **nunca** se usan como clave de deduplicación de firmas
//! (REQ-KEY-010).

use alloc::string::String;
use core::fmt;

use crate::error::{ErrorCode, GidError};

/// Longitud máxima de `IssuerId` y `Kid`.
///
/// `TRUST_BUNDLE.md §2.2` fija 64 caracteres como cota de identificador canónico
/// (`framework_id`); se aplica la misma cota al resto de identificadores de
/// organizaciones y claves (REQ-VER-008).
pub const MAX_ID_LEN: usize = 64;

/// Longitud máxima de `Vct`.
///
/// Cota de transporte: las credenciales viajan por QR con presupuesto de
/// presentación (`CRYPTO_PROFILES.md §5.2`), de modo que el identificador de
/// tipo se acota por debajo del tamaño máximo de credencial (64 KiB).
pub const MAX_VCT_LEN: usize = 256;

/// Construye el error canónico para un identificador inválido.
fn invalid_id(kind: &str, value: &str, reason: &str) -> GidError {
    // El valor rechazado no se incluye en el mensaje: podría contener material
    // sensible en ciertos contextos y los mensajes de error son estables.
    let _ = value;
    GidError::new(
        ErrorCode::MalformedMessage,
        alloc::format!("invalid {kind} identifier: {reason}"),
    )
}

/// Valida la forma común de `IssuerId`/`Kid`/`ProfileId`: ASCII en kebab-case
/// con segmentos no vacíos y cota de longitud.
fn validate_kebab(kind: &str, value: &str, max_len: usize) -> Result<(), GidError> {
    if value.is_empty() {
        return Err(invalid_id(kind, value, "must not be empty"));
    }
    if value.len() > max_len {
        return Err(invalid_id(kind, value, "exceeds maximum length"));
    }
    if value.starts_with('-') {
        return Err(invalid_id(kind, value, "leading hyphen"));
    }
    let mut prev_hyphen = false;
    for ch in value.chars() {
        match ch {
            'a'..='z' | '0'..='9' => prev_hyphen = false,
            '-' => {
                if prev_hyphen {
                    return Err(invalid_id(kind, value, "empty segment"));
                }
                prev_hyphen = true;
            }
            _ => return Err(invalid_id(kind, value, "unsupported character")),
        }
    }
    if prev_hyphen {
        return Err(invalid_id(kind, value, "trailing hyphen"));
    }
    Ok(())
}

/// Identificador de emisor (organización), p. ej. `iss-panama-tribunal-electoral`.
///
/// No confundir con el titular: es un identificador de organización y no es un
/// dato personal (INV-02).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IssuerId(String);

impl IssuerId {
    /// Analiza y valida un identificador de emisor.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si está vacío, supera [`MAX_ID_LEN`] o
    /// contiene caracteres fuera de `[a-z0-9-]` con segmentos no vacíos.
    pub fn parse(value: &str) -> Result<Self, GidError> {
        validate_kebab("issuer id", value, MAX_ID_LEN)?;
        Ok(Self(String::from(value)))
    }

    /// Vista del identificador validado.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for IssuerId {
    type Error = GidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Identificador de clave (`kid` de JWS), p. ej. `te-iss-2026-ecdsa-01`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid(String);

impl Kid {
    /// Analiza y valida un identificador de clave.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si está vacío, supera [`MAX_ID_LEN`] o
    /// contiene caracteres fuera de `[a-z0-9-]` con segmentos no vacíos.
    pub fn parse(value: &str) -> Result<Self, GidError> {
        validate_kebab("key id", value, MAX_ID_LEN)?;
        Ok(Self(String::from(value)))
    }

    /// Vista del identificador validado.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Kid {
    type Error = GidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Identificador de tipo de credencial (`vct`), p. ej.
/// `https://credentials.gravital.io/vct/personal/id-v1`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Vct(String);

impl Vct {
    /// Analiza y valida un identificador de tipo de credencial.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si está vacío, supera [`MAX_VCT_LEN`] o
    /// contiene espacios o caracteres de control.
    pub fn parse(value: &str) -> Result<Self, GidError> {
        if value.is_empty() {
            return Err(invalid_id("vct", value, "must not be empty"));
        }
        if value.len() > MAX_VCT_LEN {
            return Err(invalid_id("vct", value, "exceeds maximum length"));
        }
        for ch in value.chars() {
            if ch.is_ascii_whitespace() || ch.is_control() {
                return Err(invalid_id("vct", value, "unsupported character"));
            }
        }
        Ok(Self(String::from(value)))
    }

    /// Vista del identificador validado.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Vct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Vct {
    type Error = GidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Identificador de perfil, p. ej. `pip-personal-v1`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileId(String);

impl ProfileId {
    /// Identificador del perfil personal (`docs/specs/profiles/pip-personal-v1.md`).
    pub const PERSONAL_V1: &'static str = "pip-personal-v1";
    /// Identificador del perfil financiero (`docs/specs/profiles/pip-financial-v1.md`).
    pub const FINANCIAL_V1: &'static str = "pip-financial-v1";
    /// Identificador del perfil empresarial (`docs/specs/profiles/pip-enterprise-v1.md`).
    pub const ENTERPRISE_V1: &'static str = "pip-enterprise-v1";

    /// Analiza y valida un identificador de perfil.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si está vacío, supera [`MAX_ID_LEN`] o
    /// contiene caracteres fuera de `[a-z0-9-]` con segmentos no vacíos.
    pub fn parse(value: &str) -> Result<Self, GidError> {
        validate_kebab("profile id", value, MAX_ID_LEN)?;
        Ok(Self(String::from(value)))
    }

    /// Vista del identificador validado.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for ProfileId {
    type Error = GidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Marca de tiempo Unix en segundos.
///
/// El núcleo **nunca** lee el reloj del sistema (INV-11): los instantes llegan
/// desde el `Clock` inyectado por el host o desde documentos firmados.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// Crea una marca de tiempo a partir de segundos Unix.
    ///
    /// Cualquier `u64` es un instante representable; la validez semántica
    /// (vigencia, expiración) la comprueban las capas superiores.
    #[must_use]
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Segundos Unix de la marca de tiempo.
    #[must_use]
    pub const fn as_seconds(self) -> u64 {
        self.0
    }

    /// Suma saturada de segundos (nunca desborda; AGENTS.md §9.1).
    #[must_use]
    pub const fn saturating_add_seconds(self, seconds: u64) -> Self {
        Self(self.0.saturating_add(seconds))
    }

    /// `true` si este instante es anterior a `other`.
    #[must_use]
    pub const fn is_before(self, other: Self) -> bool {
        self.0 < other.0
    }

    /// `true` si este instante es posterior o igual a `other`.
    #[must_use]
    pub const fn is_at_or_after(self, other: Self) -> bool {
        self.0 >= other.0
    }
}

impl From<u64> for UnixTime {
    fn from(seconds: u64) -> Self {
        Self::from_seconds(seconds)
    }
}

/// Versión de trust bundle, estrictamente monótona dentro de una época
/// (`TRUST_BUNDLE.md §3`: `bundle_epoch` + `bundle_version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BundleVersion(u64);

impl BundleVersion {
    /// Crea una versión de bundle.
    #[must_use]
    pub const fn new(version: u64) -> Self {
        Self(version)
    }

    /// Vista numérica de la versión.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Siguiente versión (saturada; nunca desborda).
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// `true` si esta versión es posterior a `other` (anti-rollback, F4.T03).
    #[must_use]
    pub const fn is_newer_than(self, other: Self) -> bool {
        self.0 > other.0
    }
}

impl From<u64> for BundleVersion {
    fn from(version: u64) -> Self {
        Self::new(version)
    }
}

/// Clase de factor de dispositivo para la política de ranura única (`ADR-0029`, `REQ-DEVSLOT-001`).
///
/// Un titular puede portar su identidad simultáneamente en diferentes clases de soporte
/// (p. ej. un móvil y una tarjeta inteligente física), pero nunca en dos dispositivos
/// de la misma clase simultáneamente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DeviceFactorClass {
    /// Teléfono móvil (`"mobile"`). Clave en StrongBox/TEE o Secure Enclave.
    Mobile,
    /// Tarjeta física inteligente tipo Visa (`"card"`). Clave en chip Java Card con serial CPLC.
    Card,
    /// Dispositivo auxiliar compatible (`"other"`, p. ej. llave de seguridad FIDO2 o quiosco).
    Other,
}

impl DeviceFactorClass {
    /// Valor textual normativo para claims y metadatos (`"mobile"`, `"card"`, `"other"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::Card => "card",
            Self::Other => "other",
        }
    }

    /// Parsea una clase de factor de dispositivo a partir de su cadena normativa.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedMessage`] si la cadena no es `"mobile"`, `"card"` ni `"other"`.
    pub fn parse(s: &str) -> Result<Self, GidError> {
        match s {
            "mobile" => Ok(Self::Mobile),
            "card" => Ok(Self::Card),
            "other" => Ok(Self::Other),
            _ => Err(GidError::new(
                ErrorCode::MalformedMessage,
                alloc::format!(
                    "invalid device factor class '{s}': expected 'mobile', 'card', or 'other'"
                ),
            )),
        }
    }
}

impl fmt::Display for DeviceFactorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&str> for DeviceFactorClass {
    type Error = GidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)] // Pruebas locales deterministas (PROJECT_STRUCTURE.md §5.1).
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    // // Verifies: REQ-VER-008
    #[test]
    fn issuer_id_accepts_spec_examples() {
        let id = IssuerId::parse("iss-panama-tribunal-electoral").expect("spec example is valid");
        assert_eq!(id.as_str(), "iss-panama-tribunal-electoral");
        assert_eq!(format!("{id}"), "iss-panama-tribunal-electoral");
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn kid_and_profile_accept_spec_examples() {
        assert_eq!(
            Kid::parse("te-iss-2026-ecdsa-01")
                .expect("valid kid")
                .as_str(),
            "te-iss-2026-ecdsa-01"
        );
        assert_eq!(
            ProfileId::parse(ProfileId::PERSONAL_V1)
                .expect("valid profile")
                .as_str(),
            "pip-personal-v1"
        );
    }

    // // Verifies: REQ-VER-008
    #[test]
    fn vct_accepts_spec_example() {
        let vct = Vct::parse("https://credentials.gravital.io/vct/personal/id-v1")
            .expect("spec example is valid");
        assert_eq!(
            vct.as_str(),
            "https://credentials.gravital.io/vct/personal/id-v1"
        );
    }

    // // Verifies: REQ-VER-008 (caso negativo: identificador vacío)
    #[test]
    fn parse_empty_identifier_returns_malformed_message() {
        for err in [
            IssuerId::parse("").expect_err("empty"),
            Kid::parse("").expect_err("empty"),
            ProfileId::parse("").expect_err("empty"),
            Vct::parse("").expect_err("empty"),
        ] {
            assert_eq!(err.code, ErrorCode::MalformedMessage);
        }
    }

    // // Verifies: REQ-VER-008 (caso negativo: longitud y caracteres)
    #[test]
    fn parse_identifier_rejects_invalid_shapes() {
        let too_long = alloc::string::String::from_utf8(vec![b'a'; MAX_ID_LEN + 1])
            .expect("ascii vector is valid utf8");
        assert!(IssuerId::parse(&too_long).is_err());
        assert!(Kid::parse("kid_with_underscore").is_err());
        assert!(Kid::parse("-leading-hyphen").is_err());
        assert!(Kid::parse("trailing-hyphen-").is_err());
        assert!(Kid::parse("double--hyphen").is_err());
        assert!(Kid::parse("kid with space").is_err());
        assert!(Vct::parse("https://example.com/vct with space").is_err());
    }

    // // Verifies: REQ-VER-008 (TryFrom coherente con parse)
    #[test]
    fn try_from_matches_parse() {
        let via_parse = IssuerId::parse("iss-example");
        let via_try: Result<IssuerId, _> = "iss-example".try_into();
        assert_eq!(via_parse.ok(), via_try.ok());
    }

    // // Verifies: REQ-VER-008 (tiempo y versión: aritmética saturada)
    #[test]
    fn unix_time_and_bundle_version_arithmetic_is_saturating() {
        let t = UnixTime::from_seconds(10);
        assert!(t.is_before(UnixTime::from_seconds(11)));
        assert!(t.is_at_or_after(UnixTime::from_seconds(10)));
        assert_eq!(
            UnixTime::from_seconds(u64::MAX)
                .saturating_add_seconds(5)
                .as_seconds(),
            u64::MAX
        );

        let v = BundleVersion::new(41);
        assert!(v.next().is_newer_than(v));
        assert!(!v.is_newer_than(v));
        assert_eq!(BundleVersion::new(u64::MAX).next().as_u64(), u64::MAX);
    }

    // // Verifies: REQ-DEVSLOT-001 (ADR-0029)
    #[test]
    fn device_factor_class_parse_and_display() {
        assert_eq!(
            DeviceFactorClass::parse("mobile").unwrap(),
            DeviceFactorClass::Mobile
        );
        assert_eq!(
            DeviceFactorClass::parse("card").unwrap(),
            DeviceFactorClass::Card
        );
        assert_eq!(
            DeviceFactorClass::parse("other").unwrap(),
            DeviceFactorClass::Other
        );

        assert_eq!(DeviceFactorClass::Mobile.as_str(), "mobile");
        assert_eq!(DeviceFactorClass::Card.as_str(), "card");
        assert_eq!(DeviceFactorClass::Other.as_str(), "other");

        assert_eq!(format!("{}", DeviceFactorClass::Mobile), "mobile");
        assert_eq!(format!("{}", DeviceFactorClass::Card), "card");
        assert_eq!(format!("{}", DeviceFactorClass::Other), "other");

        assert!(DeviceFactorClass::parse("tablet").is_err());
        assert!(DeviceFactorClass::parse("").is_err());
    }
}
