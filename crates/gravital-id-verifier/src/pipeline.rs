//! Pipeline de verificación offline con typestate (F4.T06, ADR-0020, REQ-VER-002, REQ-VER-012).
//!
//! Trazabilidad:
//! - **REQ-VER-002:** El resultado DEBE ser uno de `Valid`, `ValidWithStaleStatus`,
//!   `Unverifiable`, `Invalid`, con lista de comprobaciones y evidencia.
//! - **REQ-VER-004:** Las claves de emisor se obtienen exclusivamente del trust bundle (INV-06).
//! - **REQ-VER-010:** Precedencia de estados: `Invalid` > `Unverifiable` > `ValidWithStaleStatus` > `Valid`.
//! - **REQ-VER-012:** Las comprobaciones sobre datos no autenticados quedan `Skipped`;
//!   `Valid` es inconstruible sin que todas las comprobaciones obligatorias hayan pasado.
//! - **REQ-PRES-004:** Caché de nonces anti-replay integrada con `VerifierStateStore`.
//! - **REQ-STAT-004:** Frescura de estado por perfil y clase de operación.
//! - **REQ-CRED-007:** Verificación de referencia de estado.
//! - **REQ-CRED-008:** Rechazo de algoritmos fuera de la lista y de `none`.
//! - **INV-01:** Verificación 100 % desconectada sin llamadas de red.
//! - **INV-04:** Modelo cerrado de cuatro estados con evidencia exhaustiva.
//! - **INV-05:** Fail-closed ante cualquier error o ambigüedad.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::json::Value;
use gravital_id_credential::kb::KbVerificationPolicy;
use gravital_id_credential::profile::ProfileSchema;
use gravital_id_credential::vc::{ConfirmationClaim, SD_JWT_VC_TYP};
use gravital_id_credential::ParsedSdJwt;
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::status_list::TokenStatus;
use gravital_id_trust::bundle::{IssuerKey, KeyState, TrustBundle};
use gravital_id_types::{ErrorCode, UnixTime, Vct};

use crate::policy::{OperationClass, VerificationPolicy};
use crate::result::{AllMandatoryPassed, CheckEvidence, CheckKind, VerificationResult};
use crate::state::{TimeFloorCheck, TimeFloorGuard, VerifierStateStore};

/// Solicitud de verificación con desafío de sesión contra replay (REQ-PRES-002, REQ-PRES-004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    /// Desafío aleatorio fresco de $\ge 128$ bits generado por el verificador.
    pub nonce: String,
    /// Identificador de audiencia esperado (URI o identificador del verificador).
    pub audience: String,
    /// Instante de expiración de la solicitud/sesión.
    pub expires_at: UnixTime,
    /// Clase de operación para evaluar la frescura del estado.
    pub operation_class: OperationClass,
}

impl VerificationRequest {
    /// Crea una nueva solicitud de verificación.
    #[must_use]
    pub fn new(
        nonce: impl Into<String>,
        audience: impl Into<String>,
        expires_at: UnixTime,
        operation_class: OperationClass,
    ) -> Self {
        Self {
            nonce: nonce.into(),
            audience: audience.into(),
            expires_at,
            operation_class,
        }
    }
}

/// Marcador typestate: La presentación aún no ha sido analizada sintácticamente.
pub struct StageUnchecked;

/// Marcador typestate: La estructura y cabeceras sintácticas han sido comprobadas.
pub struct StageStructureChecked;

/// Marcador typestate: El emisor y la clave de firma han sido resueltos en el TrustBundle.
pub struct StageIssuerResolved;

/// Marcador typestate: La firma criptográfica ha sido verificada (datos autenticados, REQ-VER-012).
pub struct StageAuthenticated;

/// Pipeline de verificación de credenciales con comprobaciones ordenadas y typestate (F4.T06).
pub struct VerifierPipeline;

impl VerifierPipeline {
    /// Ejecuta de forma exhaustiva y determinista el pipeline completo de verificación offline.
    ///
    /// Evalúa en orden riguroso las 11 comprobaciones normativas:
    /// 1. Estructura (`Structure`)
    /// 2. Emisor autorizado (`IssuerAuthorized`)
    /// 3. Estado de clave (`KeyState`)
    /// 4. Firma criptográfica (`Signature`)
    /// 5. Vigencia temporal (`Validity`)
    /// 6. Divulgaciones (`Disclosures`)
    /// 7. Esquema (`Schema`)
    /// 8. Vinculación de titular (`KeyBinding`)
    /// 9. Nonce anti-replay (`Nonce`)
    /// 10. Estado de revocación (`Status`)
    /// 11. Política del integrador (`Policy`)
    ///
    /// Comprobación exhaustiva del pipeline de verificación offline.
    ///
    /// Justificación: El pipeline sans-I/O exige la inyección determinista de
    /// presentación, solicitud, bundle, snapshot, almacén de estado, política y
    /// reloj (INV-01, INV-11, REQ-VER-002).
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        presentation_compact: &str,
        expected_request: Option<&VerificationRequest>,
        trust_bundle: &TrustBundle,
        status_snapshot: Option<&StatusSnapshot>,
        state_store: &mut impl VerifierStateStore,
        policy: &VerificationPolicy,
        now: UnixTime,
        monotonic_elapsed_millis: Option<u64>,
    ) -> VerificationResult {
        let mut checks = Vec::with_capacity(11);

        // 0. Comprobación del piso de tiempo confiable (REQ-VER-006, REQ-VER-011)
        let mut guard = TimeFloorGuard::new(state_store);
        match guard.check(now, monotonic_elapsed_millis) {
            Ok(TimeFloorCheck::Ok) | Ok(TimeFloorCheck::FirstRun) => {}
            Err(e) if e.code == ErrorCode::ClockRollbackDetected => {
                checks.push(CheckEvidence::indeterminate(
                    CheckKind::Structure,
                    ErrorCode::ClockRollbackDetected,
                    "clock rollback detected by trusted time floor",
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_unverifiable(checks, None, None, None);
            }
            Err(e) if e.code == ErrorCode::VerifierStateCorrupted => {
                checks.push(CheckEvidence::indeterminate(
                    CheckKind::Structure,
                    ErrorCode::VerifierStateCorrupted,
                    "verifier state store is missing or corrupted",
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_unverifiable(checks, None, None, None);
            }
            Err(e) => {
                checks.push(CheckEvidence::indeterminate(
                    CheckKind::Structure,
                    e.code,
                    e.message,
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_unverifiable(checks, None, None, None);
            }
        }

        // 1. Estructura sintáctica (Structure)
        let parsed = match ParsedSdJwt::parse(presentation_compact) {
            Ok(p) => p,
            Err(e) => {
                checks.push(CheckEvidence::failed(
                    CheckKind::Structure,
                    e.code,
                    format!("malformed compact SD-JWT presentation: {}", e.message),
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_invalid(checks, None, None, None);
            }
        };

        // Comprobación de cabecera JWS: typ == "dc+sd-jwt", alg != "none" y en allowed_algorithms
        let typ_opt = parsed.header().member("typ").and_then(Value::as_str);
        if typ_opt != Some(SD_JWT_VC_TYP) {
            let actual = typ_opt.unwrap_or("missing");
            checks.push(CheckEvidence::failed(
                CheckKind::Structure,
                ErrorCode::MalformedSdJwt,
                format!("unsupported typ header '{actual}', expected '{SD_JWT_VC_TYP}'"),
            ));
            Self::fill_skipped_from(&mut checks, 1);
            return VerificationResult::new_invalid(checks, None, None, None);
        }

        let alg_opt = parsed.header().member("alg").and_then(Value::as_str);
        match alg_opt {
            Some(alg) if alg.eq_ignore_ascii_case("none") => {
                checks.push(CheckEvidence::failed(
                    CheckKind::Structure,
                    ErrorCode::UnsupportedAlgorithm,
                    "algorithm 'none' is strictly prohibited (INV-08, REQ-CRED-008)",
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_invalid(checks, None, None, None);
            }
            Some(alg) if !policy.allowed_algorithms().iter().any(|a| a == alg) => {
                checks.push(CheckEvidence::failed(
                    CheckKind::Structure,
                    ErrorCode::UnsupportedAlgorithm,
                    format!("algorithm '{alg}' is not in policy allowed_algorithms (REQ-CRED-008)"),
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_invalid(checks, None, None, None);
            }
            None => {
                checks.push(CheckEvidence::failed(
                    CheckKind::Structure,
                    ErrorCode::UnsupportedAlgorithm,
                    "missing alg header in SD-JWT VC",
                ));
                Self::fill_skipped_from(&mut checks, 1);
                return VerificationResult::new_invalid(checks, None, None, None);
            }
            _ => {}
        }
        checks.push(CheckEvidence::passed(
            CheckKind::Structure,
            "valid SD-JWT VC compact structure and JWS headers",
        ));

        // 2. Emisor autorizado (IssuerAuthorized)
        let iss_str = match parsed.raw_payload().member("iss").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s,
            _ => {
                checks.push(CheckEvidence::failed(
                    CheckKind::IssuerAuthorized,
                    ErrorCode::MissingRequiredClaim,
                    "missing or empty 'iss' claim in presentation payload",
                ));
                Self::fill_skipped_from(&mut checks, 2);
                return VerificationResult::new_invalid(checks, None, None, None);
            }
        };

        if !policy.issuers().admits(iss_str) {
            checks.push(CheckEvidence::failed(
                CheckKind::IssuerAuthorized,
                ErrorCode::UntrustedIssuer,
                format!("issuer '{iss_str}' is denied by verification policy"),
            ));
            Self::fill_skipped_from(&mut checks, 2);
            return VerificationResult::new_invalid(checks, Some(iss_str.to_string()), None, None);
        }

        let issuer_entry = match trust_bundle.issuer(iss_str) {
            Some(entry) => entry,
            None => {
                checks.push(CheckEvidence::indeterminate(
                    CheckKind::IssuerAuthorized,
                    ErrorCode::UntrustedIssuer,
                    format!("issuer '{iss_str}' not found in active trust bundle"),
                ));
                Self::fill_skipped_from(&mut checks, 2);
                return VerificationResult::new_unverifiable(
                    checks,
                    Some(iss_str.to_string()),
                    None,
                    None,
                );
            }
        };

        if issuer_entry.state == gravital_id_trust::bundle::IssuerState::Suspended {
            checks.push(CheckEvidence::indeterminate(
                CheckKind::IssuerAuthorized,
                ErrorCode::IssuerSuspended,
                format!("issuer '{iss_str}' is suspended in active trust bundle"),
            ));
            Self::fill_skipped_from(&mut checks, 2);
            return VerificationResult::new_unverifiable(
                checks,
                Some(iss_str.to_string()),
                None,
                None,
            );
        }
        checks.push(CheckEvidence::passed(
            CheckKind::IssuerAuthorized,
            format!("issuer '{iss_str}' is authorized in active trust bundle"),
        ));

        // 3. Estado de clave del emisor (KeyState)
        let kid_header = parsed.header().member("kid").and_then(Value::as_str);
        let key_entry: &IssuerKey = match kid_header {
            Some(kid) => match issuer_entry.keys.iter().find(|k| k.kid.as_str() == kid) {
                Some(k) => k,
                None => {
                    checks.push(CheckEvidence::indeterminate(
                        CheckKind::KeyState,
                        ErrorCode::UntrustedIssuer,
                        format!("kid '{kid}' not registered for issuer in trust bundle"),
                    ));
                    Self::fill_skipped_from(&mut checks, 3);
                    return VerificationResult::new_unverifiable(
                        checks,
                        Some(iss_str.to_string()),
                        Some(kid.to_string()),
                        None,
                    );
                }
            },
            None => {
                if issuer_entry.keys.is_empty() {
                    checks.push(CheckEvidence::indeterminate(
                        CheckKind::KeyState,
                        ErrorCode::UntrustedIssuer,
                        format!("no signing keys registered for issuer '{iss_str}' in bundle"),
                    ));
                    Self::fill_skipped_from(&mut checks, 3);
                    return VerificationResult::new_unverifiable(
                        checks,
                        Some(iss_str.to_string()),
                        None,
                        None,
                    );
                }

                match issuer_entry
                    .keys
                    .iter()
                    .find(|k| k.state == KeyState::Active)
                {
                    Some(k) => k,
                    None => {
                        match issuer_entry.keys.first() {
                            Some(k) => k,
                            None => {
                                checks.push(CheckEvidence::indeterminate(
                                CheckKind::KeyState,
                                ErrorCode::UntrustedIssuer,
                                format!("no signing keys registered for issuer '{iss_str}' in bundle"),
                            ));
                                Self::fill_skipped_from(&mut checks, 3);
                                return VerificationResult::new_unverifiable(
                                    checks,
                                    Some(iss_str.to_string()),
                                    None,
                                    None,
                                );
                            }
                        }
                    }
                }
            }
        };

        let kid_used = key_entry.kid.as_str().to_string();

        match key_entry.state {
            KeyState::Compromised => {
                checks.push(CheckEvidence::failed(
                    CheckKind::KeyState,
                    ErrorCode::IssuerKeyCompromised,
                    format!("issuer key '{kid_used}' is permanently compromised (INV-05)"),
                ));
                Self::fill_skipped_from(&mut checks, 3);
                return VerificationResult::new_invalid(
                    checks,
                    Some(iss_str.to_string()),
                    Some(kid_used),
                    None,
                );
            }
            KeyState::Suspended => {
                checks.push(CheckEvidence::indeterminate(
                    CheckKind::KeyState,
                    ErrorCode::IssuerSuspended,
                    format!("issuer key '{kid_used}' is currently suspended in trust bundle"),
                ));
                Self::fill_skipped_from(&mut checks, 3);
                return VerificationResult::new_unverifiable(
                    checks,
                    Some(iss_str.to_string()),
                    Some(kid_used),
                    None,
                );
            }
            KeyState::Active | KeyState::Retired => {
                checks.push(CheckEvidence::passed(
                    CheckKind::KeyState,
                    format!(
                        "issuer key '{kid_used}' is in valid state '{}'",
                        key_entry.state.as_str()
                    ),
                ));
            }
        }

        // 4. Firma criptográfica del emisor (Signature) - INV-06: solo con clave del TrustBundle
        if let Err(e) = parsed.verify_issuer_signature(&key_entry.jwk) {
            checks.push(CheckEvidence::failed(
                CheckKind::Signature,
                ErrorCode::InvalidSignature,
                format!("issuer JWS signature verification failed: {}", e.message),
            ));
            // REQ-VER-012: Comprobaciones que dependen de datos no autenticados quedan Skipped
            Self::fill_skipped_from(&mut checks, 4);
            return VerificationResult::new_invalid(
                checks,
                Some(iss_str.to_string()),
                Some(kid_used),
                None,
            );
        }
        checks.push(CheckEvidence::passed(
            CheckKind::Signature,
            "issuer JWS signature is cryptographically valid against trust bundle key",
        ));

        // ─────────────────────────────────────────────────────────────────────
        // ESTADO AUTENTICADO: A partir de este punto, el contenido está firmado
        // ─────────────────────────────────────────────────────────────────────

        let mut overall_invalid = false;
        let mut overall_unverifiable = false;

        // 5. Vigencia temporal (Validity)
        let iat_opt = parsed.raw_payload().member("iat").and_then(|v| match v {
            gravital_id_codec::json::Value::Number(gravital_id_codec::json::Number::PosInt(n)) => {
                Some(*n)
            }
            _ => None,
        });

        let mut validity_failed = false;
        match iat_opt {
            Some(iat_sec) => {
                let skew = policy.clock_skew_seconds();
                let now_sec = now.as_seconds();

                // Si la clave estaba retirada, comprobar que la emisión precedió al retiro (REQ-KEY-006)
                if key_entry.state == KeyState::Retired
                    && iat_sec >= key_entry.state_since.as_seconds()
                {
                    checks.push(CheckEvidence::failed(
                        CheckKind::Validity,
                        ErrorCode::IssuerKeyRetired,
                        format!(
                            "credential iat ({iat_sec}) is after key retirement ({})",
                            key_entry.state_since.as_seconds()
                        ),
                    ));
                    validity_failed = true;
                    overall_invalid = true;
                } else if iat_sec > now_sec.saturating_add(skew) {
                    checks.push(CheckEvidence::failed(
                        CheckKind::Validity,
                        ErrorCode::CredentialNotYetValid,
                        format!("credential iat ({iat_sec}) is in the future compared to now ({now_sec} + {skew})"),
                    ));
                    validity_failed = true;
                    overall_invalid = true;
                }

                // nbf (si está presente)
                if let Some(gravital_id_codec::json::Value::Number(
                    gravital_id_codec::json::Number::PosInt(nbf_sec),
                )) = parsed.raw_payload().member("nbf")
                {
                    if now_sec.saturating_add(skew) < *nbf_sec {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Validity,
                            ErrorCode::CredentialNotYetValid,
                            format!("credential nbf ({nbf_sec}) is in the future"),
                        ));
                        validity_failed = true;
                        overall_invalid = true;
                    } else if *nbf_sec < iat_sec {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Validity,
                            ErrorCode::MalformedSdJwt,
                            "credential nbf is before iat",
                        ));
                        validity_failed = true;
                        overall_invalid = true;
                    }
                }

                // exp (si está presente o exigido por la política)
                let exp_opt = parsed.raw_payload().member("exp").and_then(|v| match v {
                    gravital_id_codec::json::Value::Number(
                        gravital_id_codec::json::Number::PosInt(n),
                    ) => Some(*n),
                    _ => None,
                });

                if let Some(exp_sec) = exp_opt {
                    if now_sec > exp_sec.saturating_add(skew) {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Validity,
                            ErrorCode::CredentialExpired,
                            format!("credential exp ({exp_sec} + {skew}) is expired compared to now ({now_sec})"),
                        ));
                        validity_failed = true;
                        overall_invalid = true;
                    } else if exp_sec < iat_sec {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Validity,
                            ErrorCode::MalformedSdJwt,
                            "credential exp is before iat",
                        ));
                        validity_failed = true;
                        overall_invalid = true;
                    }
                } else if policy.requires_exp() {
                    checks.push(CheckEvidence::failed(
                        CheckKind::Validity,
                        ErrorCode::MissingRequiredClaim,
                        "missing required 'exp' claim as required by policy",
                    ));
                    validity_failed = true;
                    overall_invalid = true;
                }

                if !validity_failed {
                    checks.push(CheckEvidence::passed(
                        CheckKind::Validity,
                        "credential timestamps (iat/nbf/exp) are within valid temporal range",
                    ));
                }
            }
            None => {
                checks.push(CheckEvidence::failed(
                    CheckKind::Validity,
                    ErrorCode::MissingRequiredClaim,
                    "missing required 'iat' claim",
                ));
                overall_invalid = true;
            }
        }

        // 6. Divulgaciones (Disclosures)
        // La integridad criptográfica de cada divulgación contra sus digests ya se validó
        // al parsear el SD-JWT en L2.
        checks.push(CheckEvidence::passed(
            CheckKind::Disclosures,
            format!(
                "{} selective disclosures verified against authenticated digests",
                parsed.disclosures().len()
            ),
        ));

        // 7. Esquema y Tipo de Credencial (Schema)
        let vct_opt = parsed.raw_payload().member("vct").and_then(Value::as_str);
        let mut vct_str_used = None;
        match vct_opt {
            Some(vct_raw) => match Vct::parse(vct_raw) {
                Ok(vct) => {
                    vct_str_used = Some(vct.as_str().to_string());
                    if !policy.vcts().admits(&vct) {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Schema,
                            ErrorCode::SchemaValidationFailed,
                            format!(
                                "vct '{}' is not admitted by policy vcts selection",
                                vct.as_str()
                            ),
                        ));
                        overall_invalid = true;
                    } else if !issuer_entry.vcts.is_empty()
                        && !issuer_entry.vcts.iter().any(|v| v == vct.as_str())
                    {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Schema,
                            ErrorCode::UntrustedIssuer,
                            format!("issuer '{iss_str}' is not authorized in trust bundle to issue vct '{}'", vct.as_str()),
                        ));
                        overall_invalid = true;
                    } else {
                        // Validación de esquema de perfil si existe
                        let schema_opt = ProfileSchema::lookup_by_vct(&vct);
                        if let Some(schema) = schema_opt {
                            if let Err(e) = schema.validate_disclosed(parsed.reconstructed_claims())
                            {
                                checks.push(CheckEvidence::failed(
                                    CheckKind::Schema,
                                    e.code,
                                    format!(
                                        "reconstructed claims violate profile schema: {}",
                                        e.message
                                    ),
                                ));
                                overall_invalid = true;
                            } else {
                                checks.push(CheckEvidence::passed(
                                    CheckKind::Schema,
                                    format!(
                                        "vct '{}' adheres to normative profile schema",
                                        vct.as_str()
                                    ),
                                ));
                            }
                        } else {
                            checks.push(CheckEvidence::passed(
                                CheckKind::Schema,
                                format!("vct '{}' authorized and valid", vct.as_str()),
                            ));
                        }
                    }
                }
                Err(e) => {
                    checks.push(CheckEvidence::failed(
                        CheckKind::Schema,
                        ErrorCode::MalformedSdJwt,
                        format!("invalid vct identifier format: {}", e.message),
                    ));
                    overall_invalid = true;
                }
            },
            None => {
                checks.push(CheckEvidence::failed(
                    CheckKind::Schema,
                    ErrorCode::MissingRequiredClaim,
                    "missing required 'vct' claim in presentation payload",
                ));
                overall_invalid = true;
            }
        }

        // 8. Vinculación de titular (KeyBinding)
        let require_kb = policy.requires_cnf() || expected_request.is_some() || parsed.has_kb_jwt();
        if require_kb {
            let cnf_val_opt = parsed.raw_payload().member("cnf");
            match cnf_val_opt {
                Some(cnf_val) => match ConfirmationClaim::from_value(cnf_val) {
                    Ok(cnf) => {
                        let expected_aud =
                            expected_request.map(|r| r.audience.as_str()).unwrap_or("");
                        let expected_nonce =
                            expected_request.map(|r| r.nonce.as_str()).unwrap_or("");
                        let kb_policy = KbVerificationPolicy {
                            clock_skew_seconds: policy.clock_skew_seconds(),
                            max_age_seconds: Some(300),
                        };

                        match parsed.verify_key_binding(
                            expected_aud,
                            expected_nonce,
                            &cnf.jwk,
                            now,
                            &kb_policy,
                        ) {
                            Ok(_) => {
                                checks.push(CheckEvidence::passed(
                                    CheckKind::KeyBinding,
                                    "holder Key Binding JWT verified successfully against cnf.jwk",
                                ));
                            }
                            Err(e) => {
                                checks.push(CheckEvidence::failed(
                                    CheckKind::KeyBinding,
                                    ErrorCode::KeyBindingFailed,
                                    format!(
                                        "holder Key Binding JWT verification failed: {}",
                                        e.message
                                    ),
                                ));
                                overall_invalid = true;
                            }
                        }
                    }
                    Err(e) => {
                        checks.push(CheckEvidence::failed(
                            CheckKind::KeyBinding,
                            e.code,
                            format!("malformed cnf claim in credential: {}", e.message),
                        ));
                        overall_invalid = true;
                    }
                },
                None => {
                    checks.push(CheckEvidence::failed(
                        CheckKind::KeyBinding,
                        ErrorCode::MissingRequiredClaim,
                        "credential lacks 'cnf' confirmation claim required for key binding",
                    ));
                    overall_invalid = true;
                }
            }
        } else {
            checks.push(CheckEvidence::passed(
                CheckKind::KeyBinding,
                "key binding not required by request or policy",
            ));
        }

        // 9. Comprobación de Nonce (Nonce)
        if let Some(req) = expected_request {
            match state_store.nonce_seen(&req.nonce, now) {
                Ok(true) => {
                    checks.push(CheckEvidence::failed(
                        CheckKind::Nonce,
                        ErrorCode::NonceReused,
                        format!(
                            "nonce '{}' has already been used (replay detected)",
                            req.nonce
                        ),
                    ));
                    overall_invalid = true;
                }
                Ok(false) => {
                    if let Err(e) = state_store.remember_nonce(&req.nonce, req.expires_at) {
                        checks.push(CheckEvidence::indeterminate(
                            CheckKind::Nonce,
                            e.code,
                            format!("failed to record nonce in state store: {}", e.message),
                        ));
                        overall_unverifiable = true;
                    } else {
                        checks.push(CheckEvidence::passed(
                            CheckKind::Nonce,
                            "nonce is fresh and recorded into state store against replay",
                        ));
                    }
                }
                Err(e) => {
                    checks.push(CheckEvidence::indeterminate(
                        CheckKind::Nonce,
                        e.code,
                        format!("error checking nonce in state store: {}", e.message),
                    ));
                    overall_unverifiable = true;
                }
            }
        } else {
            checks.push(CheckEvidence::passed(
                CheckKind::Nonce,
                "no verification request provided; nonce check passed",
            ));
        }

        // 10. Estado de revocación (Status)
        let mut status_age_seconds = None;
        let mut status_is_stale = false;
        let status_member_opt = parsed.raw_payload().member("status");

        match status_member_opt {
            Some(status_val) => {
                let sl_ref_opt = status_val.member("status_list");
                match sl_ref_opt {
                    Some(sl_ref) => {
                        let idx_opt = sl_ref.member("idx").and_then(|v| match v {
                            gravital_id_codec::json::Value::Number(
                                gravital_id_codec::json::Number::PosInt(n),
                            ) => Some(*n),
                            _ => None,
                        });
                        let uri_opt = sl_ref.member("uri").and_then(Value::as_str);

                        match (idx_opt, uri_opt) {
                            (Some(idx), Some(uri)) => match status_snapshot {
                                Some(snapshot) if snapshot.uri() == uri => {
                                    match snapshot.list().status_of(idx) {
                                        Ok(TokenStatus::Valid) => {
                                            let op_class = expected_request
                                                .map(|r| r.operation_class)
                                                .unwrap_or(OperationClass::Default);
                                            let freshness = policy.status_freshness(op_class);
                                            let age = snapshot.age_seconds(now);
                                            status_age_seconds = Some(age);

                                            if freshness.admits(age) {
                                                checks.push(CheckEvidence::passed(
                                                        CheckKind::Status,
                                                        format!("status bit is valid at index {idx} and fresh ({age}s)"),
                                                    ));
                                            } else {
                                                status_is_stale = true;
                                                checks.push(CheckEvidence::passed(
                                                        CheckKind::Status,
                                                        format!("status bit is valid at index {idx} but exceeds freshness ({age}s > {}s)", freshness.max_age_seconds),
                                                    ));
                                            }
                                        }
                                        Ok(TokenStatus::Revoked) => {
                                            checks.push(CheckEvidence::failed(
                                                    CheckKind::Status,
                                                    ErrorCode::CredentialRevoked,
                                                    format!("credential is revoked at status list index {idx}"),
                                                ));
                                            overall_invalid = true;
                                        }
                                        Ok(TokenStatus::Suspended) => {
                                            checks.push(CheckEvidence::indeterminate(
                                                    CheckKind::Status,
                                                    ErrorCode::CredentialSuspended,
                                                    format!("credential is suspended at status list index {idx}"),
                                                ));
                                            overall_unverifiable = true;
                                        }
                                        Err(e) => {
                                            checks.push(CheckEvidence::failed(
                                                CheckKind::Status,
                                                e.code,
                                                format!("status list lookup error: {}", e.message),
                                            ));
                                            overall_invalid = true;
                                        }
                                    }
                                }
                                _ => {
                                    checks.push(CheckEvidence::indeterminate(
                                            CheckKind::Status,
                                            ErrorCode::StatusIndexOutOfRange,
                                            format!("status list snapshot for URI '{uri}' not provided or missing"),
                                        ));
                                    overall_unverifiable = true;
                                }
                            },
                            _ => {
                                checks.push(CheckEvidence::failed(
                                    CheckKind::Status,
                                    ErrorCode::MalformedStatusList,
                                    "status_list reference missing valid idx or uri",
                                ));
                                overall_invalid = true;
                            }
                        }
                    }
                    None => {
                        checks.push(CheckEvidence::failed(
                            CheckKind::Status,
                            ErrorCode::MalformedStatusList,
                            "status claim missing status_list object",
                        ));
                        overall_invalid = true;
                    }
                }
            }
            None => {
                if policy.requires_status() {
                    checks.push(CheckEvidence::failed(
                        CheckKind::Status,
                        ErrorCode::MissingRequiredClaim,
                        "missing required 'status' claim in credential payload (REQ-CRED-007)",
                    ));
                    overall_invalid = true;
                } else {
                    checks.push(CheckEvidence::passed(
                        CheckKind::Status,
                        "status claim omitted and not required by policy for short-lived credential",
                    ));
                }
            }
        }

        // 11. Política del integrador (Policy)
        if !policy.profiles().is_empty() {
            let mut profile_matched = false;
            if let Some(vct_str) = &vct_str_used {
                if let Ok(vct) = Vct::parse(vct_str) {
                    if let Some(schema) = ProfileSchema::lookup_by_vct(&vct) {
                        if policy
                            .profiles()
                            .iter()
                            .any(|p| p.as_str() == schema.profile)
                        {
                            profile_matched = true;
                        }
                    }
                }
            }
            if !profile_matched {
                checks.push(CheckEvidence::failed(
                    CheckKind::Policy,
                    ErrorCode::SchemaValidationFailed,
                    "credential does not satisfy required policy profiles",
                ));
                overall_invalid = true;
            } else {
                checks.push(CheckEvidence::passed(
                    CheckKind::Policy,
                    "credential satisfies all policy profile constraints",
                ));
            }
        } else {
            checks.push(CheckEvidence::passed(
                CheckKind::Policy,
                "verification policy constraints satisfied",
            ));
        }

        // Resolución de estado final según precedencia (REQ-VER-010):
        // Invalid > Unverifiable > ValidWithStaleStatus > Valid
        if overall_invalid {
            VerificationResult::new_invalid(
                checks,
                Some(iss_str.to_string()),
                Some(kid_used),
                vct_str_used,
            )
        } else if overall_unverifiable {
            VerificationResult::new_unverifiable(
                checks,
                Some(iss_str.to_string()),
                Some(kid_used),
                vct_str_used,
            )
        } else if status_is_stale {
            VerificationResult::new_valid_with_stale_status(
                checks,
                iss_str.to_string(),
                kid_used,
                vct_str_used.unwrap_or_default(),
                parsed.reconstructed_claims().clone(),
                status_age_seconds.unwrap_or(0),
            )
        } else {
            let witness = AllMandatoryPassed::new();
            VerificationResult::new_valid(
                witness,
                checks,
                iss_str.to_string(),
                kid_used,
                vct_str_used.unwrap_or_default(),
                parsed.reconstructed_claims().clone(),
                status_age_seconds,
            )
        }
    }

    /// Rellena las comprobaciones restantes con `Skipped` ante fallo prematuro (REQ-VER-012).
    fn fill_skipped_from(checks: &mut Vec<CheckEvidence>, from_index: usize) {
        let all_kinds = [
            CheckKind::Structure,
            CheckKind::IssuerAuthorized,
            CheckKind::KeyState,
            CheckKind::Signature,
            CheckKind::Validity,
            CheckKind::Disclosures,
            CheckKind::Schema,
            CheckKind::KeyBinding,
            CheckKind::Nonce,
            CheckKind::Status,
            CheckKind::Policy,
        ];

        for &kind in all_kinds.iter().skip(from_index) {
            checks.push(CheckEvidence::skipped(
                kind,
                "check skipped due to prior verification stage failure (REQ-VER-012)",
            ));
        }
    }
}
