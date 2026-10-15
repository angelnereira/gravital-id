//! Política de verificación del integrador (F4.T05, REQ-VER-005, REQ-VER-007).
//!
//! La `Policy` es **datos que el integrador configura**, no lógica incrustada en el
//! núcleo. El núcleo la aplica de forma mecánica y devuelve evidencia; la decisión de
//! aceptar o rechazar una credencial concreta sigue siendo del integrador (P-05).
//!
//! Trazabilidad:
//! - **REQ-VER-005:** la tolerancia de reloj es configurable y está acotada por el perfil.
//! - **REQ-VER-007:** el núcleo no toma decisiones de negocio; la `Policy` sí las expresa.
//! - **REQ-STAT-004:** la frescura máxima de estado se define por perfil y clase de
//!   operación.
//! - **REQ-CRED-008:** algoritmos admitidos, con `none` siempre rechazado (INV-08).
//! - **INV-05:** una política mal formada se rechaza en lugar de interpretarse laxa.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};

use gravital_id_types::{ErrorCode, GidError, ProfileId, Vct};

/// Clase de operación para la que se fija la frescura del estado.
///
/// Los valores orientativos de cada perfil están en `docs/specs/profiles/*.md` §2: por
/// ejemplo, el perfil financiero exige 30 minutos para transacciones y 4 horas para
/// consultas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationClass {
    /// Operación de alta criticidad (pago, autorización).
    Transaction,
    /// Consulta de baja criticidad.
    Query,
    /// Operación interna sin límite declarado por el perfil.
    Default,
}

impl OperationClass {
    /// Nombre canónico de la clase.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::Query => "query",
            Self::Default => "default",
        }
    }
}

/// Cota dura del sesgo de reloj admitido por el perfil.
///
/// `CRYPTO_PROFILES.md` no fija un valor único; se toma el límite operativo de 5 minutos
/// para operaciones interactivas, configurable por el integrador por debajo de él.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;

/// Frescura máxima de estado por clase de operación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFreshness {
    /// Antigúcedad máxima del snapshot de estado, en segundos.
    pub max_age_seconds: u64,
}

impl StatusFreshness {
    /// Frescura sin límite (solo válida si el perfil lo permite).
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_age_seconds: u64::MAX,
        }
    }

    /// Frescura con una antigúcedad máxima dada.
    #[must_use]
    pub const fn new(max_age_seconds: u64) -> Self {
        Self { max_age_seconds }
    }

    /// Indica si una antigúcedad cumple esta frescura.
    #[must_use]
    pub fn admits(&self, age_seconds: u64) -> bool {
        age_seconds <= self.max_age_seconds
    }
}

/// Conjunto de emisores admitidos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerSelection {
    /// Se admite cualquier emisor del bundle activo.
    AnyFromBundle,
    /// Solo los identificadores listados.
    AllowList(Vec<String>),
    /// Todos excepto los listados.
    DenyList(Vec<String>),
}

impl IssuerSelection {
    /// Indica si un emisor está admitido.
    #[must_use]
    pub fn admits(&self, issuer_uri: &str) -> bool {
        match self {
            Self::AnyFromBundle => true,
            Self::AllowList(list) => list.iter().any(|entry| entry == issuer_uri),
            Self::DenyList(list) => !list.iter().any(|entry| entry == issuer_uri),
        }
    }
}

/// Conjunto de `vct` admitidos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VctSelection {
    /// Se admite cualquier `vct`.
    Any,
    /// Solo los listados.
    AllowList(Vec<String>),
    /// Todos excepto los listados.
    DenyList(Vec<String>),
}

impl VctSelection {
    /// Indica si un `vct` está admitido.
    #[must_use]
    pub fn admits(&self, vct: &Vct) -> bool {
        match self {
            Self::Any => true,
            Self::AllowList(list) => list.iter().any(|entry| entry == vct.as_str()),
            Self::DenyList(list) => !list.iter().any(|entry| entry == vct.as_str()),
        }
    }
}

/// Política de verificación configurada por el integrador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPolicy {
    clock_skew_seconds: u64,
    max_clock_skew_seconds: u64,
    status_freshness: [StatusFreshness; 3],
    issuers: IssuerSelection,
    vcts: VctSelection,
    profiles: Vec<ProfileId>,
    require_status: bool,
    require_cnf: bool,
    require_exp: bool,
    allowed_algorithms: Vec<String>,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            clock_skew_seconds: 60,
            max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
            status_freshness: [
                StatusFreshness::new(30 * 60),
                StatusFreshness::new(4 * 60 * 60),
                StatusFreshness::new(7 * 24 * 60 * 60),
            ],
            issuers: IssuerSelection::AnyFromBundle,
            vcts: VctSelection::Any,
            profiles: Vec::new(),
            require_status: true,
            require_cnf: false,
            require_exp: false,
            allowed_algorithms: vec!["ES256".to_string()],
        }
    }
}

impl VerificationPolicy {
    /// Política con los valores por defecto (los más habituales de los perfiles).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sesgo de reloj configurado, en segundos.
    #[must_use]
    pub fn clock_skew_seconds(&self) -> u64 {
        self.clock_skew_seconds
    }

    /// Cota dura del sesgo de reloj para esta política.
    #[must_use]
    pub fn max_clock_skew_seconds(&self) -> u64 {
        self.max_clock_skew_seconds
    }

    /// Frescura de estado exigida para una clase de operación.
    #[must_use]
    pub fn status_freshness(&self, class: OperationClass) -> StatusFreshness {
        self.status_freshness
            .get(Self::index_of(class))
            .copied()
            .unwrap_or(StatusFreshness::unlimited())
    }

    /// Índice de una clase dentro del array de frescura.
    const fn index_of(class: OperationClass) -> usize {
        match class {
            OperationClass::Transaction => 0,
            OperationClass::Query => 1,
            OperationClass::Default => 2,
        }
    }

    /// Emisores admitidos.
    #[must_use]
    pub fn issuers(&self) -> &IssuerSelection {
        &self.issuers
    }

    /// `vct` admitidos.
    #[must_use]
    pub fn vcts(&self) -> &VctSelection {
        &self.vcts
    }

    /// Perfiles exigidos (vacío = sin requisito de perfil).
    #[must_use]
    pub fn profiles(&self) -> &[ProfileId] {
        &self.profiles
    }

    /// Si se exige referencia de estado (REQ-CRED-007).
    #[must_use]
    pub fn requires_status(&self) -> bool {
        self.require_status
    }

    /// Si se exige `cnf` para vinculación de titular.
    #[must_use]
    pub fn requires_cnf(&self) -> bool {
        self.require_cnf
    }

    /// Si se exige `exp`.
    #[must_use]
    pub fn requires_exp(&self) -> bool {
        self.require_exp
    }

    /// Algoritmos admitidos (nunca incluye `none`: INV-08).
    #[must_use]
    pub fn allowed_algorithms(&self) -> &[String] {
        &self.allowed_algorithms
    }

    /// Configura el sesgo de reloj, sin superar la cota (REQ-VER-005).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si el sesgo supera `max_clock_skew_seconds`.
    pub fn with_clock_skew_seconds(mut self, seconds: u64) -> Result<Self, GidError> {
        if seconds > self.max_clock_skew_seconds {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "clock skew {seconds}s exceeds the profile bound of {}s",
                    self.max_clock_skew_seconds
                ),
            ));
        }
        self.clock_skew_seconds = seconds;
        Ok(self)
    }

    /// Configura la cota dura del sesgo de reloj (debe ser \u2265 0 y coherente).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedSdJwt`] si la cota es menor que el sesgo ya configurado o
    /// supera [`MAX_CLOCK_SKEW_SECONDS`].
    pub fn with_max_clock_skew_seconds(mut self, seconds: u64) -> Result<Self, GidError> {
        if seconds > MAX_CLOCK_SKEW_SECONDS {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "max clock skew {seconds}s exceeds the hard bound of {MAX_CLOCK_SKEW_SECONDS}s"
                ),
            ));
        }
        if seconds < self.clock_skew_seconds {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                "max clock skew cannot be lower than the configured skew",
            ));
        }
        self.max_clock_skew_seconds = seconds;
        Ok(self)
    }

    /// Configura la frescura de estado para una clase de operación (REQ-STAT-004).
    #[must_use]
    pub fn with_status_freshness(
        mut self,
        class: OperationClass,
        freshness: StatusFreshness,
    ) -> Self {
        if let Some(slot) = self.status_freshness.get_mut(Self::index_of(class)) {
            *slot = freshness;
        }
        self
    }

    /// Configura los emisores admitidos.
    #[must_use]
    pub fn with_issuers(mut self, issuers: IssuerSelection) -> Self {
        self.issuers = issuers;
        self
    }

    /// Configura los `vct` admitidos.
    #[must_use]
    pub fn with_vcts(mut self, vcts: VctSelection) -> Self {
        self.vcts = vcts;
        self
    }

    /// Configura los perfiles exigidos.
    #[must_use]
    pub fn with_profiles(mut self, profiles: Vec<ProfileId>) -> Self {
        self.profiles = profiles;
        self
    }

    /// Exige (o no) la referencia de estado.
    #[must_use]
    pub fn with_require_status(mut self, require: bool) -> Self {
        self.require_status = require;
        self
    }

    /// Exige (o no) el claim `cnf`.
    #[must_use]
    pub fn with_require_cnf(mut self, require: bool) -> Self {
        self.require_cnf = require;
        self
    }

    /// Exige (o no) el claim `exp`.
    #[must_use]
    pub fn with_require_exp(mut self, require: bool) -> Self {
        self.require_exp = require;
        self
    }

    /// Configura los algoritmos admitidos.
    ///
    /// # Errores
    /// [`ErrorCode::UnsupportedAlgorithm`] si la lista está vacía o incluye `none`
    /// (INV-08: `none` nunca se admite, ni configurándolo).
    pub fn with_allowed_algorithms(mut self, algorithms: Vec<String>) -> Result<Self, GidError> {
        if algorithms.is_empty() {
            return Err(GidError::new(
                ErrorCode::UnsupportedAlgorithm,
                "a policy must allow at least one algorithm",
            ));
        }
        for algorithm in &algorithms {
            if algorithm.eq_ignore_ascii_case("none") {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    "algorithm 'none' cannot be allowed by any policy (INV-08)",
                ));
            }
        }
        self.allowed_algorithms = algorithms;
        Ok(self)
    }

    /// Comprueba la coherencia interna de la política (fail-closed, INV-05).
    ///
    /// # Errores
    /// - [`ErrorCode::MalformedSdJwt`]: sesgo de reloj fuera de su cota.
    /// - [`ErrorCode::UnsupportedAlgorithm`]: sin algoritmos o con `none`.
    pub fn validate(&self) -> Result<(), GidError> {
        if self.clock_skew_seconds > self.max_clock_skew_seconds {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "clock skew {}s exceeds the profile bound of {}s",
                    self.clock_skew_seconds, self.max_clock_skew_seconds
                ),
            ));
        }
        if self.max_clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS {
            return Err(GidError::new(
                ErrorCode::MalformedSdJwt,
                format!(
                    "max clock skew {}s exceeds the hard bound of {MAX_CLOCK_SKEW_SECONDS}s",
                    self.max_clock_skew_seconds
                ),
            ));
        }
        if self.allowed_algorithms.is_empty() {
            return Err(GidError::new(
                ErrorCode::UnsupportedAlgorithm,
                "a policy must allow at least one algorithm",
            ));
        }
        for algorithm in &self.allowed_algorithms {
            if algorithm.eq_ignore_ascii_case("none") {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    "algorithm 'none' cannot be allowed by any policy (INV-08)",
                ));
            }
        }
        Ok(())
    }

    /// Comprueba si un emisor está admitido.
    #[must_use]
    pub fn admits_issuer(&self, issuer_uri: &str) -> bool {
        self.issuers.admits(issuer_uri)
    }

    /// Comprueba si un `vct` está admitido.
    #[must_use]
    pub fn admits_vct(&self, vct: &Vct) -> bool {
        self.vcts.admits(vct)
    }

    /// Comprueba si un algoritmo está admitido.
    #[must_use]
    pub fn admits_algorithm(&self, algorithm: &str) -> bool {
        self.allowed_algorithms
            .iter()
            .any(|entry| entry == algorithm)
    }

    /// Comprueba si una antigúcedad de estado cumple la frescura de la clase dada.
    #[must_use]
    pub fn admits_status_age(&self, class: OperationClass, age_seconds: u64) -> bool {
        self.status_freshness(class).admits(age_seconds)
    }
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

    #[test]
    fn default_policy_is_coherent() {
        let policy = VerificationPolicy::default();
        policy.validate().expect("política por defecto válida");
        assert_eq!(policy.clock_skew_seconds(), 60);
        assert!(policy.requires_status());
        assert!(policy.admits_algorithm("ES256"));
        assert!(!policy.admits_algorithm("none"));
        assert!(policy.admits_issuer("https://cualquiera.example.gov"));
        assert_eq!(
            policy
                .status_freshness(OperationClass::Transaction)
                .max_age_seconds,
            1_800
        );
        assert_eq!(
            policy
                .status_freshness(OperationClass::Query)
                .max_age_seconds,
            14_400
        );
        assert_eq!(
            policy
                .status_freshness(OperationClass::Default)
                .max_age_seconds,
            604_800
        );
    }

    #[test]
    fn clock_skew_is_bounded_by_the_profile() {
        let policy = VerificationPolicy::default();
        // Sesgo enorme: se rechaza.
        let error = policy.clone().with_clock_skew_seconds(10_000).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
        // Dentro de la cota: se acepta.
        let policy = policy.with_clock_skew_seconds(120).expect("sesgo válido");
        assert_eq!(policy.clock_skew_seconds(), 120);

        // La cota no puede bajar por debajo del sesgo ya fijado.
        let error = policy.clone().with_max_clock_skew_seconds(60).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);

        // Tampoco puede superar el límite duro.
        let error = policy.with_max_clock_skew_seconds(10_000).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn alg_none_can_never_be_allowed() {
        let error = VerificationPolicy::default()
            .with_allowed_algorithms(vec!["none".to_string()])
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);

        let error = VerificationPolicy::default()
            .with_allowed_algorithms(Vec::new())
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);
    }

    #[test]
    fn issuer_and_vct_selections() {
        let allow = IssuerSelection::AllowList(vec!["https://a.example.gov".to_string()]);
        assert!(allow.admits("https://a.example.gov"));
        assert!(!allow.admits("https://b.example.gov"));

        let deny = IssuerSelection::DenyList(vec!["https://b.example.gov".to_string()]);
        assert!(deny.admits("https://a.example.gov"));
        assert!(!deny.admits("https://b.example.gov"));

        let vct_allow = VctSelection::AllowList(vec!["https://v.example/1".to_string()]);
        let admitted = Vct::parse("https://v.example/1").unwrap();
        let rejected = Vct::parse("https://v.example/2").unwrap();
        assert!(vct_allow.admits(&admitted));
        assert!(!vct_allow.admits(&rejected));
    }

    #[test]
    fn freshness_by_operation_class() {
        let policy = VerificationPolicy::default()
            .with_status_freshness(OperationClass::Transaction, StatusFreshness::new(60))
            .with_status_freshness(OperationClass::Query, StatusFreshness::unlimited());

        assert!(policy.admits_status_age(OperationClass::Transaction, 60));
        assert!(!policy.admits_status_age(OperationClass::Transaction, 61));
        assert!(policy.admits_status_age(OperationClass::Query, u64::MAX));
    }

    #[test]
    fn profiles_are_configured_without_deciding_in_the_core() {
        let profile = ProfileId::parse(ProfileId::PERSONAL_V1).unwrap();
        let policy = VerificationPolicy::default().with_profiles(vec![profile.clone()]);
        assert_eq!(policy.profiles(), &[profile]);

        // El núcleo solo informa: la decisión de aceptar es del integrador.
        assert!(!policy.profiles().is_empty());
        let _ = OperationClass::Transaction.as_str().to_string();
    }
}
