//! Solicitudes de verificación offline firmadas (REQ-PRES-007, PROTOCOL.md §3.1).
//!
//! Trazabilidad:
//! - `REQ-PRES-007`: Solicitudes firmadas con clave registrada obligatorias según perfil.
//! - `PROTOCOL.md §3.1`: Encapsulación JWS compacta (RFC 7515) con ES256 verificado contra el `TrustBundle`.
//! - `INV-01`: Cero dependencias de red durante la verificación.
//! - `INV-05`: Rechazo fail-closed si la firma es inválida o la clave no está en el bundle.
//! - `INV-08`: Algoritmo estrictamente fijado a ES256 (RFC 6979 / P-256).

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits, Value};
use gravital_id_crypto::{sha256, verify_es256_jwk};
use gravital_id_keys::{IssuerSigning, KeyHandle, KeyStore};
use gravital_id_trust::bundle::{TrustBundle, VerifierEntry};
use gravital_id_types::{ErrorCode, GidError, Kid};

use crate::offline_request::{VerificationRequest, VERIFICATION_REQUEST_TYPE};

/// Tipo de token normativo en la cabecera JWS de la solicitud firmada.
pub const SIGNED_REQUEST_TYP: &str = "pip-verification-request-v1";

/// Cabecera JWS canónica para ES256.
const SIGNED_REQUEST_HEADER_BYTES: &[u8] =
    br#"{"alg":"ES256","typ":"pip-verification-request-v1"}"#;

/// Firma una solicitud de verificación offline produciendo un token JWS compacto (`PROTOCOL.md §3.1`, `REQ-PRES-007`).
///
/// # Errores
/// [`ErrorCode::KeyNotFound`] o [`ErrorCode::HardwareKeystoreFailed`] si la clave de firma no está disponible.
pub fn sign_verification_request<K: KeyStore>(
    request: &VerificationRequest,
    keystore: &K,
    key_handle: &KeyHandle<IssuerSigning>,
    kid: Option<&Kid>,
) -> Result<String, GidError> {
    let header_bytes = match kid {
        Some(k) => format!(
            r#"{{"alg":"ES256","kid":"{}","typ":"{SIGNED_REQUEST_TYP}"}}"#,
            k.as_str()
        )
        .into_bytes(),
        None => SIGNED_REQUEST_HEADER_BYTES.to_vec(),
    };

    let header_b64 = base64url::encode(&header_bytes);
    let payload_bytes = request.to_json_bytes()?;
    let payload_b64 = base64url::encode(&payload_bytes);

    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = sha256(signing_input.as_bytes());
    let signature_p1363 = keystore.sign(key_handle, &digest)?;
    let sig_b64 = base64url::encode(&signature_p1363);

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Parsea y verifica criptográficamente una solicitud de verificación firmada contra el `TrustBundle` (`REQ-PRES-007`).
///
/// # Errores
/// [`ErrorCode::MalformedMessage`] si la estructura JWS o el payload es inválido.
/// [`ErrorCode::InvalidSignature`] si la firma criptográfica no es válida.
/// [`ErrorCode::UnsupportedAlgorithm`] si el algoritmo declarado no es ES256.
pub fn parse_and_verify_signed_request(
    jws_token: &str,
    trust_bundle: &TrustBundle,
) -> Result<(VerificationRequest, VerifierEntry), GidError> {
    let mut parts = jws_token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing JWS header part"))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing JWS payload part"))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing JWS signature part"))?;
    if parts.next().is_some() {
        return Err(GidError::new(
            ErrorCode::MalformedMessage,
            "signed verification request must have exactly 3 parts",
        ));
    }

    let header_bytes = base64url::decode(header_b64)?;
    let header_val = parse_bytes(&header_bytes, &Limits::profile_default()).map_err(|e| {
        GidError::new(
            ErrorCode::MalformedMessage,
            format!("failed to parse JWS header: {e}"),
        )
    })?;

    // Validar algoritmo
    let alg = header_val
        .member("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| GidError::new(ErrorCode::MalformedMessage, "missing 'alg' in header"))?;
    if alg != "ES256" {
        return Err(GidError::new(
            ErrorCode::UnsupportedAlgorithm,
            format!("unsupported signature algorithm '{alg}', expected 'ES256'"),
        ));
    }

    // Validar typ (debe ser SIGNED_REQUEST_TYP, VERIFICATION_REQUEST_TYPE o "jwt")
    if let Some(typ) = header_val.member("typ").and_then(Value::as_str) {
        if typ != SIGNED_REQUEST_TYP && typ != VERIFICATION_REQUEST_TYPE && typ != "jwt" {
            return Err(GidError::new(
                ErrorCode::UnsupportedProtocolVersion,
                format!("unsupported JWS typ '{typ}'"),
            ));
        }
    }

    // Decodificar y parsear payload
    let payload_bytes = base64url::decode(payload_b64)?;
    let request = VerificationRequest::from_json_bytes(&payload_bytes)?;

    // Decodificar firma
    let sig_bytes = base64url::decode(sig_b64)?;
    if sig_bytes.len() != 64 {
        return Err(GidError::new(
            ErrorCode::InvalidSignature,
            format!(
                "signature length must be exactly 64 bytes (got {})",
                sig_bytes.len()
            ),
        ));
    }

    // Localizar verificador en el TrustBundle
    let verifier = trust_bundle
        .find_verifier(&request.verifier_id)
        .ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedMessage,
                format!(
                    "verifier '{}' is not registered in the active trust bundle",
                    request.verifier_id
                ),
            )
        })?;

    let public_key = verifier.public_key.as_ref().ok_or_else(|| {
        GidError::new(
            ErrorCode::MalformedMessage,
            format!(
                "registered verifier '{}' has no public key configured in trust bundle",
                request.verifier_id
            ),
        )
    })?;

    // Verificar firma criptográfica ES256
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_es256_jwk(public_key, signing_input.as_bytes(), &sig_bytes)?;

    Ok((request, verifier.clone()))
}
