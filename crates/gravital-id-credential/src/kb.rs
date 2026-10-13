//! Key Binding JWT (KB-JWT) para presentaciones SD-JWT (F3.T04, RFC 9901 §6).
//!
//! Trazabilidad:
//! - **REQ-PRES-002:** Toda presentación interactiva DEBE incluir KB-JWT con
//!   `nonce`, `aud`, `iat` y `sd_hash`.
//! - **REQ-CRED-001:** Formato de Key Binding según RFC 9901 §6.
//! - **REQ-VER-003:** Fail-closed ante cualquier discrepancia o error en el KB-JWT (`ErrorCode::KeyBindingFailed`).
//! - **INV-03:** Sin custodia de claves privadas del titular; firma delegada al `KeyStore`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::json::{parse_bytes, Limits as JsonLimits, Number, Value};
use gravital_id_crypto::{sha256, verify_es256_jwk, JwkEcP256, ES256_SIGNATURE_LEN};
use gravital_id_keys::{HolderBinding, KeyHandle, KeyStore};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::json_canonical::to_canonical_json;

/// Tipo de token fijado para la cabecera del Key Binding JWT (RFC 9901 §6).
pub const KB_JWT_TYP: &str = "kb+jwt";

/// Algoritmo criptográfico normativo para KB-JWT (INV-08: ES256).
pub const KB_JWT_ALG: &str = "ES256";

/// Tolerancia por defecto de sesgo de reloj para KB-JWT en segundos.
pub const DEFAULT_KB_CLOCK_SKEW_SECONDS: u64 = 60;

/// Antigüedad máxima por defecto para la validez de un KB-JWT (5 minutos).
pub const DEFAULT_KB_MAX_AGE_SECONDS: u64 = 300;

/// Claims normativos de un Key Binding JWT (RFC 9901 §6, REQ-PRES-002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KbJwtClaims {
    /// Momento de emisión del KB-JWT.
    pub iat: UnixTime,
    /// Identificador del verificador destinatario.
    pub aud: String,
    /// Desafío aleatorio fresco generado por el verificador (≥ 128 bits).
    pub nonce: String,
    /// Resumen SHA-256 en base64url de la presentación SD-JWT precedente finalizada en `~`.
    pub sd_hash: String,
}

impl KbJwtClaims {
    /// Crea un conjunto de claims para KB-JWT.
    #[must_use]
    pub fn new(
        iat: UnixTime,
        aud: impl Into<String>,
        nonce: impl Into<String>,
        sd_hash: impl Into<String>,
    ) -> Self {
        Self {
            iat,
            aud: aud.into(),
            nonce: nonce.into(),
            sd_hash: sd_hash.into(),
        }
    }

    /// Serializa los claims a JSON canónico ordenado (RFC 8785).
    #[must_use]
    pub fn to_canonical_value(&self) -> Value {
        Value::Object(vec![
            ("aud".to_string(), Value::String(self.aud.clone())),
            (
                "iat".to_string(),
                Value::Number(Number::PosInt(self.iat.as_seconds())),
            ),
            ("nonce".to_string(), Value::String(self.nonce.clone())),
            ("sd_hash".to_string(), Value::String(self.sd_hash.clone())),
        ])
    }
}

/// Política de validación temporal para el Key Binding JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KbVerificationPolicy {
    /// Tolerancia máxima de sesgo de reloj en segundos.
    pub clock_skew_seconds: u64,
    /// Antigüedad máxima permitida para `iat` en segundos (opcional).
    pub max_age_seconds: Option<u64>,
}

impl Default for KbVerificationPolicy {
    fn default() -> Self {
        Self {
            clock_skew_seconds: DEFAULT_KB_CLOCK_SKEW_SECONDS,
            max_age_seconds: Some(DEFAULT_KB_MAX_AGE_SECONDS),
        }
    }
}

/// Calcula el digest `sd_hash` normativo para una presentación SD-JWT (RFC 9901 §6.2).
///
/// La entrada DEBE ser la representación exacta de la presentación SD-JWT hasta
/// e incluyendo el carácter delimitador `~` final:
/// `<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~`
pub fn calculate_sd_hash(sd_jwt_prefix: &str) -> Result<String, GidError> {
    if !sd_jwt_prefix.ends_with('~') {
        return Err(GidError::new(
            ErrorCode::MalformedSdJwt,
            "SD-JWT prefix for sd_hash computation must end with '~'",
        ));
    }

    let hash = sha256(sd_jwt_prefix.as_bytes());
    Ok(base64url::encode(&hash))
}

/// Emisor de Key Binding JWTs para presentaciones de titulares (RFC 9901 §6).
pub struct KbIssuer;

impl KbIssuer {
    /// Emite y firma un Key Binding JWT delegando la firma al `KeyStore` del dispositivo (INV-03).
    pub fn issue(
        claims: &KbJwtClaims,
        key_store: &impl KeyStore,
        handle: &KeyHandle<HolderBinding>,
    ) -> Result<String, GidError> {
        // Cabecera JWS canónica
        let header_val = Value::Object(vec![
            ("alg".to_string(), Value::String(KB_JWT_ALG.to_string())),
            ("typ".to_string(), Value::String(KB_JWT_TYP.to_string())),
        ]);
        let header_json = to_canonical_json(&header_val);
        let header_b64 = base64url::encode(header_json.as_bytes());

        // Payload canónico ordenado
        let payload_val = claims.to_canonical_value();
        let payload_json = to_canonical_json(&payload_val);
        let payload_b64 = base64url::encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let digest = sha256(signing_input.as_bytes());

        // Firma delegada al hardware o módulo seguro del titular (INV-03)
        let signature_bytes = key_store.sign(handle, &digest)?;
        let sig_b64 = base64url::encode(&signature_bytes);

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    /// Crea una presentación completa SD-JWT con Key Binding: `<prefix><kb_jwt>`.
    ///
    /// Calcula automáticamente el `sd_hash` a partir del prefijo SD-JWT presentado.
    pub fn create_presentation(
        sd_jwt_prefix: &str,
        aud: impl Into<String>,
        nonce: impl Into<String>,
        iat: UnixTime,
        key_store: &impl KeyStore,
        handle: &KeyHandle<HolderBinding>,
    ) -> Result<String, GidError> {
        let sd_hash = calculate_sd_hash(sd_jwt_prefix)?;
        let claims = KbJwtClaims::new(iat, aud, nonce, sd_hash);
        let kb_jwt = Self::issue(&claims, key_store, handle)?;
        Ok(format!("{sd_jwt_prefix}{kb_jwt}"))
    }
}

/// Verificador estricto de Key Binding JWTs (RFC 9901 §6, REQ-PRES-002, REQ-VER-003).
pub struct KbJwtVerifier;

impl KbJwtVerifier {
    /// Parsea y verifica exhaustivamente un Key Binding JWT contra la presentación y la política.
    ///
    /// Valida:
    /// - Sintaxis de 3 partes JWS.
    /// - `typ == "kb+jwt"` y `alg == "ES256"`.
    /// - Coincidencia exacta de `aud` y `nonce`.
    /// - Coincidencia exacta de `sd_hash` con el hash SHA-256 del `sd_jwt_prefix`.
    /// - Validación temporal de `iat` (futuro y frescura).
    /// - Verificación criptográfica de firma ES256 contra la clave pública JWK del titular.
    pub fn verify(
        kb_jwt: &str,
        sd_jwt_prefix: &str,
        expected_aud: &str,
        expected_nonce: &str,
        holder_jwk: &JwkEcP256,
        current_time: UnixTime,
        policy: &KbVerificationPolicy,
    ) -> Result<KbJwtClaims, GidError> {
        let segments: Vec<&str> = kb_jwt.split('.').collect();
        if segments.len() != 3 {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                format!(
                    "Key Binding JWT must contain 3 dot-separated segments, got {}",
                    segments.len()
                ),
            ));
        }

        let Some(&header_b64) = segments.first() else {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                "missing KB-JWT header",
            ));
        };
        let Some(&payload_b64) = segments.get(1) else {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                "missing KB-JWT payload",
            ));
        };
        let Some(&sig_b64) = segments.get(2) else {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                "missing KB-JWT signature",
            ));
        };

        let signing_input = format!("{header_b64}.{payload_b64}");
        let json_limits = JsonLimits::profile_default();

        // 1. Decodificación y validación de cabecera
        let header_bytes = base64url::decode(header_b64).map_err(|e| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                format!("invalid base64url in KB-JWT header: {e}"),
            )
        })?;
        let header_val = parse_bytes(&header_bytes, &json_limits).map_err(|e| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                format!("failed to parse KB-JWT header JSON: {e}"),
            )
        })?;

        match header_val.member("typ") {
            Some(Value::String(typ)) if typ == KB_JWT_TYP => {}
            _ => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    format!("KB-JWT header typ must be '{KB_JWT_TYP}'"),
                ));
            }
        }

        match header_val.member("alg") {
            Some(Value::String(alg)) if alg == KB_JWT_ALG => {}
            Some(Value::String(alg)) => {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    format!("unsupported KB-JWT algorithm '{alg}': only ES256 is supported"),
                ));
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT header must contain string 'alg' claim with 'ES256'",
                ));
            }
        }

        // 2. Decodificación y validación de payload
        let payload_bytes = base64url::decode(payload_b64).map_err(|e| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                format!("invalid base64url in KB-JWT payload: {e}"),
            )
        })?;
        let payload_val = parse_bytes(&payload_bytes, &json_limits).map_err(|e| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                format!("failed to parse KB-JWT payload JSON: {e}"),
            )
        })?;

        // Validación de aud
        let aud = match payload_val.member("aud") {
            Some(Value::String(a)) if a == expected_aud => a.clone(),
            Some(Value::String(a)) => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    format!("KB-JWT aud mismatch: expected '{expected_aud}', got '{a}'"),
                ));
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT payload missing string 'aud' claim",
                ));
            }
        };

        // Validación de nonce
        let nonce = match payload_val.member("nonce") {
            Some(Value::String(n)) if n == expected_nonce => n.clone(),
            Some(Value::String(_)) => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT nonce mismatch",
                ));
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT payload missing string 'nonce' claim",
                ));
            }
        };

        // Validación de sd_hash
        let expected_sd_hash = calculate_sd_hash(sd_jwt_prefix)?;
        let sd_hash = match payload_val.member("sd_hash") {
            Some(Value::String(h)) if h == &expected_sd_hash => h.clone(),
            Some(Value::String(_)) => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT sd_hash does not match SD-JWT presentation digest",
                ));
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT payload missing string 'sd_hash' claim",
                ));
            }
        };

        // Validación de iat y límites de frescura
        let iat_seconds = match payload_val.member("iat") {
            Some(Value::Number(Number::PosInt(n))) => *n,
            _ => {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    "KB-JWT payload missing positive integer 'iat' claim",
                ));
            }
        };
        let iat = UnixTime::from_seconds(iat_seconds);

        // Rechazo de timestamp futuro más allá de la tolerancia de sesgo de reloj
        let max_future_allowed = current_time.saturating_add_seconds(policy.clock_skew_seconds);
        if iat.as_seconds() > max_future_allowed.as_seconds() {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                format!(
                    "KB-JWT iat ({}) is in the future beyond clock skew tolerance (now: {})",
                    iat.as_seconds(),
                    current_time.as_seconds()
                ),
            ));
        }

        // Rechazo de presentación expirada si se especifica max_age
        if let Some(max_age) = policy.max_age_seconds {
            let expiration_time = iat
                .saturating_add_seconds(max_age)
                .saturating_add_seconds(policy.clock_skew_seconds);
            if current_time.as_seconds() > expiration_time.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::KeyBindingFailed,
                    format!(
                        "KB-JWT presentation expired: issued at {}, now {}, max age {}s",
                        iat.as_seconds(),
                        current_time.as_seconds(),
                        max_age
                    ),
                ));
            }
        }

        // 3. Validación de firma ES256 del titular
        let sig_bytes = base64url::decode(sig_b64).map_err(|e| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                format!("invalid base64url in KB-JWT signature: {e}"),
            )
        })?;

        if sig_bytes.len() != ES256_SIGNATURE_LEN {
            return Err(GidError::new(
                ErrorCode::KeyBindingFailed,
                format!(
                    "KB-JWT signature must be 64 bytes (got {})",
                    sig_bytes.len()
                ),
            ));
        }

        let mut signature = [0u8; ES256_SIGNATURE_LEN];
        if let Some(slot) = signature.get_mut(..sig_bytes.len()) {
            slot.copy_from_slice(&sig_bytes);
        }

        verify_es256_jwk(holder_jwk, signing_input.as_bytes(), &signature).map_err(|e| {
            GidError::new(
                ErrorCode::KeyBindingFailed,
                format!("KB-JWT signature verification failed: {e}"),
            )
        })?;

        Ok(KbJwtClaims {
            iat,
            aud,
            nonce,
            sd_hash,
        })
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
    use gravital_id_keys::{HolderBinding, SoftwareKeyStore};
    use gravital_id_testkit::SeededRng;

    #[test]
    fn calculate_sd_hash_nominal() {
        let sd_jwt_prefix = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJleGFtcGxlIn0.sig~disclosure1~";
        let sd_hash = calculate_sd_hash(sd_jwt_prefix).expect("calculate sd_hash");
        assert_eq!(sd_hash.len(), 43); // 32 bytes en base64url sin padding
    }

    #[test]
    fn calculate_sd_hash_rejects_missing_trailing_tilde() {
        let prefix_no_tilde = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJleGFtcGxlIn0.sig~disclosure1";
        let err = calculate_sd_hash(prefix_no_tilde).unwrap_err();
        assert_eq!(err.code, ErrorCode::MalformedSdJwt);
    }

    #[test]
    fn issue_and_verify_kb_jwt_roundtrip() {
        let rng = SeededRng::new(10101);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<HolderBinding>()
            .expect("generate holder binding key");
        let holder_jwk = key_store.public_key(&handle).expect("public key");

        let sd_jwt_prefix = "header.payload.sig~disc1~disc2~";
        let now = UnixTime::from_seconds(1_700_000_000);
        let aud = "https://verifier.example.com";
        let nonce = "random_nonce_128_bits_entropy";

        let full_presentation =
            KbIssuer::create_presentation(sd_jwt_prefix, aud, nonce, now, &key_store, &handle)
                .expect("create presentation");

        assert!(full_presentation.starts_with(sd_jwt_prefix));
        let kb_jwt = &full_presentation[sd_jwt_prefix.len()..];

        let policy = KbVerificationPolicy::default();
        let verified_claims =
            KbJwtVerifier::verify(kb_jwt, sd_jwt_prefix, aud, nonce, &holder_jwk, now, &policy)
                .expect("verify kb-jwt");

        assert_eq!(verified_claims.aud, aud);
        assert_eq!(verified_claims.nonce, nonce);
        assert_eq!(verified_claims.iat, now);
        assert_eq!(
            verified_claims.sd_hash,
            calculate_sd_hash(sd_jwt_prefix).expect("sd_hash")
        );
    }

    #[test]
    fn verify_rejects_tampered_sd_hash() {
        let rng = SeededRng::new(20202);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<HolderBinding>()
            .expect("generate key");
        let holder_jwk = key_store.public_key(&handle).expect("public key");

        let prefix_a = "header.payload.sig~disc1~";
        let now = UnixTime::from_seconds(1_700_000_000);
        let aud = "https://verifier.example.com";
        let nonce = "nonce123";

        let presentation =
            KbIssuer::create_presentation(prefix_a, aud, nonce, now, &key_store, &handle)
                .expect("create");
        let kb_jwt = &presentation[prefix_a.len()..];

        // Se intenta verificar contra un prefijo diferente (alterado)
        let prefix_b = "header.payload.sig~disc1~tampered~";
        let policy = KbVerificationPolicy::default();

        let err = KbJwtVerifier::verify(kb_jwt, prefix_b, aud, nonce, &holder_jwk, now, &policy)
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::KeyBindingFailed);
        assert!(err.message.contains("sd_hash does not match"));
    }

    #[test]
    fn verify_rejects_wrong_holder_key() {
        let rng = SeededRng::new(30303);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle_real = key_store
            .generate_key::<HolderBinding>()
            .expect("generate key");

        let wrong_rng = SeededRng::new(40404);
        let mut wrong_store = SoftwareKeyStore::new(wrong_rng);
        let handle_wrong = wrong_store
            .generate_key::<HolderBinding>()
            .expect("generate wrong key");
        let wrong_jwk = wrong_store.public_key(&handle_wrong).expect("wrong jwk");

        let prefix = "header.payload.sig~disc1~";
        let now = UnixTime::from_seconds(1_700_000_000);
        let presentation =
            KbIssuer::create_presentation(prefix, "aud", "nonce", now, &key_store, &handle_real)
                .expect("create");
        let kb_jwt = &presentation[prefix.len()..];

        let policy = KbVerificationPolicy::default();
        let err = KbJwtVerifier::verify(kb_jwt, prefix, "aud", "nonce", &wrong_jwk, now, &policy)
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::KeyBindingFailed);
        assert!(err.message.contains("signature verification failed"));
    }

    #[test]
    fn verify_rejects_future_iat() {
        let rng = SeededRng::new(50505);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<HolderBinding>()
            .expect("generate key");
        let holder_jwk = key_store.public_key(&handle).expect("public key");

        let prefix = "header.payload.sig~";
        let future_time = UnixTime::from_seconds(1_700_001_000); // 1000s en el futuro
        let current_time = UnixTime::from_seconds(1_700_000_000);

        let presentation =
            KbIssuer::create_presentation(prefix, "aud", "nonce", future_time, &key_store, &handle)
                .expect("create");
        let kb_jwt = &presentation[prefix.len()..];

        let policy = KbVerificationPolicy {
            clock_skew_seconds: 60,
            max_age_seconds: Some(300),
        };

        let err = KbJwtVerifier::verify(
            kb_jwt,
            prefix,
            "aud",
            "nonce",
            &holder_jwk,
            current_time,
            &policy,
        )
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::KeyBindingFailed);
        assert!(err.message.contains("in the future"));
    }

    #[test]
    fn verify_rejects_expired_iat() {
        let rng = SeededRng::new(60606);
        let mut key_store = SoftwareKeyStore::new(rng);
        let handle = key_store
            .generate_key::<HolderBinding>()
            .expect("generate key");
        let holder_jwk = key_store.public_key(&handle).expect("public key");

        let prefix = "header.payload.sig~";
        let old_time = UnixTime::from_seconds(1_700_000_000);
        let current_time = UnixTime::from_seconds(1_700_001_000); // 1000s después (> 300s + 60s)

        let presentation =
            KbIssuer::create_presentation(prefix, "aud", "nonce", old_time, &key_store, &handle)
                .expect("create");
        let kb_jwt = &presentation[prefix.len()..];

        let policy = KbVerificationPolicy {
            clock_skew_seconds: 60,
            max_age_seconds: Some(300),
        };

        let err = KbJwtVerifier::verify(
            kb_jwt,
            prefix,
            "aud",
            "nonce",
            &holder_jwk,
            current_time,
            &policy,
        )
        .unwrap_err();

        assert_eq!(err.code, ErrorCode::KeyBindingFailed);
        assert!(err.message.contains("expired"));
    }
}
