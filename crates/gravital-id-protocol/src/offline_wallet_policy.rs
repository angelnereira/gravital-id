//! Validación de solicitudes de verificación en la wallet (REQ-PRES-007, PROTOCOL.md §3.1).
//!
//! Trazabilidad:
//! - `REQ-PRES-007`: Perfiles y claims sensibles exigen solicitudes firmadas con clave registrada.
//! - `REQ-PRES-001` / `REQ-PRIV-001`: Minimización y comprobación de claims solicitados permitidos.
//! - `INV-01`: Validación sans-I/O 100% offline sin llamadas de red.
//! - `INV-05`: Rechazo fail-closed ante cualquier violación de política o expiración.
//! - `INV-11`: Reloj inyectado (`UnixTime`), determinismo estricto.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_trust::bundle::{TrustBundle, VerifierEntry};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::offline_request::VerificationRequest;
use crate::offline_signed_request::parse_and_verify_signed_request;

/// Tolerancia temporal de sesgo de reloj por defecto (60 segundos).
pub const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS: u64 = 60;

/// Duración máxima de validez de una solicitud (300 segundos / 5 minutos).
pub const DEFAULT_MAX_REQUEST_VALIDITY_SECONDS: u64 = 300;

/// Claims normativos de Nivel 1 que exigen solicitud firmada de verificador registrado (`REQ-PRES-007`, `pip-identity-v1.md §Nivel 1`).
pub const DEFAULT_SENSITIVE_CLAIMS: &[&str] = &["document_number", "birth_date", "portrait"];

/// Política de validación de solicitudes del verificador en la wallet (`REQ-PRES-007`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRequestPolicy {
    /// Tolerancia máxima de sesgo de reloj en segundos (`INV-11`).
    pub clock_skew_tolerance_seconds: u64,
    /// Duración máxima permitida de la ventana de validez (`expires_at - issued_at`).
    pub max_request_validity_seconds: u64,
    /// Si es `true`, todas las solicitudes deben provenir de un verificador registrado.
    pub require_registered_verifier: bool,
    /// Lista de claims sensibles que exigen un verificador registrado y solicitud firmada.
    pub sensitive_claims: Vec<String>,
    /// Lista de claims expresamente denegados por la política de la wallet.
    pub disallowed_claims: Vec<String>,
    /// Lista blanca opcional de `verifier_id` permitidos.
    pub allowed_verifier_ids: Option<Vec<String>>,
}

impl Default for WalletRequestPolicy {
    fn default() -> Self {
        Self {
            clock_skew_tolerance_seconds: DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
            max_request_validity_seconds: DEFAULT_MAX_REQUEST_VALIDITY_SECONDS,
            require_registered_verifier: false,
            sensitive_claims: DEFAULT_SENSITIVE_CLAIMS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            disallowed_claims: Vec::new(),
            allowed_verifier_ids: None,
        }
    }
}

/// Resultado de la validación exitosa de una solicitud de verificación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWalletRequest {
    /// Solicitud de verificación validada.
    pub request: VerificationRequest,
    /// Indica si el verificador está formalmente registrado en el `TrustBundle`.
    pub is_registered_verifier: bool,
    /// Registro del verificador en el bundle (si está registrado).
    pub verifier_entry: Option<VerifierEntry>,
    /// Indica si la solicitud fue recibida como JWS firmado con clave criptográfica válida.
    pub is_signed: bool,
}

/// Validador de solicitudes de verificación para la wallet del titular (`REQ-PRES-007`).
#[derive(Debug, Clone, Default)]
pub struct WalletRequestValidator {
    policy: WalletRequestPolicy,
}

impl WalletRequestValidator {
    /// Crea un nuevo validador con la política especificada.
    #[must_use]
    pub fn new(policy: WalletRequestPolicy) -> Self {
        Self { policy }
    }

    /// Retorna una referencia a la política de validación activa.
    #[must_use]
    pub fn policy(&self) -> &WalletRequestPolicy {
        &self.policy
    }

    /// Valida una solicitud de verificación no firmada (`VerificationRequest`) (`REQ-PRES-007`).
    ///
    /// # Errores
    /// - [`ErrorCode::ExpiredRequest`] si la solicitud ha caducado.
    /// - [`ErrorCode::MalformedMessage`] si la solicitud viola restricciones de política,
    ///   solicita claims sensibles sin solicitud firmada, o excede los límites temporales.
    pub fn validate_request(
        &self,
        request: &VerificationRequest,
        current_time: UnixTime,
        trust_bundle: Option<&TrustBundle>,
    ) -> Result<ValidatedWalletRequest, GidError> {
        // 1. Validación de vigencia y sesgo temporal
        request.validate_timing(current_time, self.policy.clock_skew_tolerance_seconds)?;

        // 2. Validación de duración máxima de la solicitud
        let duration = request
            .expires_at
            .as_seconds()
            .saturating_sub(request.issued_at.as_seconds());
        if duration > self.policy.max_request_validity_seconds {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "verification request validity window exceeds maximum policy threshold",
            ));
        }

        // 3. Verificación de lista blanca de verificadores si está configurada
        if let Some(allowed) = &self.policy.allowed_verifier_ids {
            if !allowed.iter().any(|v| v == &request.verifier_id) {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "verifier_id is not in the wallet allowed verifiers list",
                ));
            }
        }

        // 4. Recolección e inspección de claims solicitados
        let requested_claims = extract_requested_claims(request);

        // Comprobar claims denegados
        for disallowed in &self.policy.disallowed_claims {
            if requested_claims.iter().any(|c| c == disallowed) {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "request asks for claims disallowed by wallet policy",
                ));
            }
        }

        // Comprobar si se solicitan claims sensibles
        let requests_sensitive = self
            .policy
            .sensitive_claims
            .iter()
            .any(|sens| requested_claims.iter().any(|c| c == sens));

        // En caso de claims sensibles: REQ-PRES-007 exige estrictamente solicitud firmada
        if requests_sensitive {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "sensitive claims require a cryptographically signed verification request (REQ-PRES-007)",
            ));
        }

        // 5. Comprobar si la política general exige verificador registrado
        let mut verifier_entry = None;
        let mut is_registered = false;

        if let Some(bundle) = trust_bundle {
            if let Some(entry) = bundle.find_verifier(&request.verifier_id) {
                if !entry.is_valid_at(current_time) {
                    return Err(GidError::new(
                        ErrorCode::ExpiredRequest,
                        "verifier registration in trust bundle has expired",
                    ));
                }
                verifier_entry = Some(entry.clone());
                is_registered = true;
            }
        }

        if self.policy.require_registered_verifier && !is_registered {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "wallet policy strictly requires requests from registered verifiers",
            ));
        }

        Ok(ValidatedWalletRequest {
            request: request.clone(),
            is_registered_verifier: is_registered,
            verifier_entry,
            is_signed: false,
        })
    }

    /// Valida una solicitud de verificación firmada en formato JWS compacto (`REQ-PRES-007`).
    ///
    /// Valida la firma criptográfica contra la clave pública del verificador registrada en el `TrustBundle`,
    /// su vigencia, autorización de perfiles y restricciones de claims.
    ///
    /// # Errores
    /// - [`ErrorCode::InvalidSignature`] si la firma criptográfica del verificador es incorrecta.
    /// - [`ErrorCode::ExpiredRequest`] si la solicitud o el registro del verificador ha expirado.
    /// - [`ErrorCode::MalformedMessage`] si el verificador no está registrado o la política se infringe.
    pub fn validate_signed_request(
        &self,
        signed_jws: &str,
        current_time: UnixTime,
        trust_bundle: &TrustBundle,
    ) -> Result<ValidatedWalletRequest, GidError> {
        // 1. Parsear JWS y verificar firma criptográfica contra el TrustBundle
        let (request, verifier_entry) = parse_and_verify_signed_request(signed_jws, trust_bundle)?;

        // 2. Validar vigencia temporal de la solicitud
        request.validate_timing(current_time, self.policy.clock_skew_tolerance_seconds)?;

        // 3. Validar duración máxima de la solicitud
        let duration = request
            .expires_at
            .as_seconds()
            .saturating_sub(request.issued_at.as_seconds());
        if duration > self.policy.max_request_validity_seconds {
            return Err(GidError::new(
                ErrorCode::MalformedMessage,
                "signed verification request validity window exceeds maximum policy threshold",
            ));
        }

        // 4. Validar vigencia de la entrada del verificador en el bundle
        if !verifier_entry.is_valid_at(current_time) {
            return Err(GidError::new(
                ErrorCode::ExpiredRequest,
                "verifier registration in trust bundle has expired",
            ));
        }

        // 5. Verificación de lista blanca si está configurada
        if let Some(allowed) = &self.policy.allowed_verifier_ids {
            if !allowed.iter().any(|v| v == &request.verifier_id) {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "signed verifier_id is not in the wallet allowed verifiers list",
                ));
            }
        }

        // 6. Validar que el verificador esté autorizado para los perfiles / VCTs solicitados
        for cred_query in &request.query.credentials {
            for vct in &cred_query.vct_values {
                if !verifier_entry.allows_profile(vct.as_str()) {
                    return Err(GidError::new(
                        ErrorCode::MalformedMessage,
                        "verifier is not authorized in trust bundle for requested credential profile",
                    ));
                }
            }
        }

        // 7. Recolección e inspección de claims solicitados
        let requested_claims = extract_requested_claims(&request);
        for disallowed in &self.policy.disallowed_claims {
            if requested_claims.iter().any(|c| c == disallowed) {
                return Err(GidError::new(
                    ErrorCode::MalformedMessage,
                    "signed request asks for claims disallowed by wallet policy",
                ));
            }
        }

        Ok(ValidatedWalletRequest {
            request,
            is_registered_verifier: true,
            verifier_entry: Some(verifier_entry),
            is_signed: true,
        })
    }
}

/// Extrae todos los nombres de claims solicitados en la consulta DCQL.
fn extract_requested_claims(request: &VerificationRequest) -> Vec<String> {
    let mut claims = Vec::new();
    for cred in &request.query.credentials {
        for c in &cred.claims {
            claims.push(c.name.clone());
        }
    }
    claims
}
