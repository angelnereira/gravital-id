//! Token Status List en formato JWT (F4.T01, REQ-STAT-001, REQ-STAT-003, REQ-STAT-007).
//!
//! Una *Token Status List* es un JWT cuyo payload contiene el claim `status_list`:
//!
//! ```json
//! {
//!   "alg": "ES256", "typ": "statuslist+jwt"
//! }
//! {
//!   "status_list": {
//!     "bits": 2,
//!     "lst": "<base64url del contenido comprimido>",
//!     "uri": "https://example.gov/status/2026.jwt",
//!     "exp": 1791720000
//!   },
//!   "iat": 1791633600,
//!   "iss": "https://issuer.example.gov"
//! }
//! ```
//!
//! El contenido de `lst` es una secuencia de bits empaquetada (1 bit por entrada para
//! perfiles generales, 2 bits para perfiles con suspensión reversible), comprimida con
//! ZLIB/DEFLATE y codificada en base64url sin relleno.
//!
//! Trazabilidad:
//! - **REQ-STAT-001:** estado mediante Token Status List (formato JWT), versión fijada en
//!   `CRYPTO_PROFILES.md` (`draft-ietf-oauth-status-list-21`, `typ: statuslist+jwt`).
//! - **REQ-STAT-003:** la descompresión tiene límite de salida (2 MiB) y de ratio (10:1).
//! - **REQ-STAT-007:** estados válido, revocado y suspendido (2 bits).
//! - **INV-01 / INV-09 / INV-10:** sin I/O, sin `unsafe` y sin pánicos en biblioteca.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::deflate::inflate_bounded;
use gravital_id_codec::json::{parse_bytes, Limits as JsonLimits, Number, Value};
use gravital_id_crypto::{verify_es256_jwk, JwkEcP256, ES256_SIGNATURE_LEN};
use gravital_id_types::{ErrorCode, GidError, UnixTime};

/// Tipo de token normativo de una Token Status List (CRYPTO_PROFILES §2).
pub const STATUS_LIST_TYP: &str = "statuslist+jwt";

/// Algoritmo normativo de firma (INV-08: solo ES256).
pub const STATUS_LIST_ALG: &str = "ES256";

/// Límite absoluto de descompresión por lista (CRYPTO_PROFILES §5.1, REQ-STAT-003).
pub const MAX_DECOMPRESSED_BYTES: usize = 2 * 1024 * 1024;

/// Ratio máximo de expansión admitido (CRYPTO_PROFILES §5.1, REQ-STAT-003).
pub const MAX_EXPANSION_RATIO: usize = 10;

/// Bits por entrada admitidos por el perfil v1 (CRYPTO_PROFILES §5.1).
pub const SUPPORTED_BITS_PER_ENTRY: [u8; 2] = [1, 2];

/// Estado de una credencial según su entrada en la lista (REQ-STAT-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenStatus {
    /// `00` (2 bits) o `0` (1 bit): la credencial es válida.
    Valid,
    /// `01` (2 bits) o `1` (1 bit): la credencial está revocada.
    Revoked,
    /// `10` (2 bits): la credencial está suspendida temporalmente.
    Suspended,
}

impl TokenStatus {
    /// Indica si el estado bloquea la aceptación de la credencial.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Contenido de una Token Status List ya descomprimido y validado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenStatusList {
    bits_per_entry: u8,
    /// Bytes del contenido desempaquetado.
    entries: Vec<u8>,
    /// URI de la lista, si el payload la declara.
    uri: Option<String>,
    /// Instante de expiración (`exp`), si se declaró.
    expires_at: Option<UnixTime>,
    /// Instante de emisión (`iat`), si se declaró.
    issued_at: Option<UnixTime>,
}

impl TokenStatusList {
    /// Bits por entrada declarados por la lista (1 o 2).
    #[must_use]
    pub fn bits_per_entry(&self) -> u8 {
        self.bits_per_entry
    }

    /// URI declarada por la lista.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        self.uri.as_deref()
    }

    /// Instante de expiración declarado.
    #[must_use]
    pub fn expires_at(&self) -> Option<UnixTime> {
        self.expires_at
    }

    /// Instante de emisión declarado.
    #[must_use]
    pub fn issued_at(&self) -> Option<UnixTime> {
        self.issued_at
    }

    /// Número de entradas que caben en el contenido recibido.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        let bits = usize::from(self.bits_per_entry);
        if bits == 0 {
            return 0;
        }
        self.entries
            .len()
            .saturating_mul(8)
            .checked_div(bits)
            .unwrap_or(0)
    }

    /// Lee el estado de la entrada indicada.
    ///
    /// # Errores
    /// - [`ErrorCode::StatusIndexOutOfRange`] si el índice cae fuera de la lista.
    /// - [`ErrorCode::MalformedStatusList`] si el valor leído no corresponde a un estado
    ///   válido para el número de bits declarado (fail-closed).
    pub fn status_of(&self, index: u64) -> Result<TokenStatus, GidError> {
        let bits = u32::from(self.bits_per_entry);
        if bits == 0 {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "status list declares zero bits per entry",
            ));
        }

        let entry_count = u64::try_from(self.entry_count()).unwrap_or(u64::MAX);
        if index >= entry_count {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                format!("status index {index} is out of range for a list of {entry_count} entries"),
            ));
        }

        let bit_offset = index.saturating_mul(u64::from(bits));
        let byte_index = (bit_offset / 8) as usize;
        let bit_index_in_byte = (bit_offset % 8) as u32;

        // Los bits se empaquan de izquierda a derecha (MSB primero), igual que en el
        // borrador de Token Status List.
        let Some(byte) = self.entries.get(byte_index).copied() else {
            return Err(GidError::new(
                ErrorCode::StatusIndexOutOfRange,
                "status list content is shorter than the requested index",
            ));
        };

        let raw = match bits {
            1 => u32::from((byte >> (7u32.saturating_sub(bit_index_in_byte))) & 0b1),
            2 => {
                // Una entrada de 2 bits nunca cruza dos bytes cuando el desplazamiento es par.
                let shift = 6u32.saturating_sub(bit_index_in_byte);
                u32::from((byte >> shift) & 0b11)
            }
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("unsupported {bits} bits per entry"),
                ));
            }
        };

        match (bits, raw) {
            (1, 0) => Ok(TokenStatus::Valid),
            (1, 1) => Ok(TokenStatus::Revoked),
            (2, 0) => Ok(TokenStatus::Valid),
            (2, 1) => Ok(TokenStatus::Revoked),
            (2, 2) => Ok(TokenStatus::Suspended),
            _ => Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!("status value {raw} is not defined for {bits} bits per entry"),
            )),
        }
    }

    /// Comprueba la coincidencia de URI con la que declara la credencial.
    ///
    /// Si la lista no declara URI, la comprobación se omite (no hay con qué comparar).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si las URI no coinciden exactamente.
    pub fn check_uri(&self, expected_uri: &str) -> Result<(), GidError> {
        if let Some(uri) = self.uri.as_deref() {
            if uri != expected_uri {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status list uri does not match the uri referenced by the credential",
                ));
            }
        }
        Ok(())
    }

    /// Comprueba vigencia temporal de la lista contra el reloj inyectado (INV-11).
    ///
    /// # Errores
    /// - [`ErrorCode::CredentialNotYetValid`] si `iat` es posterior al instante dado.
    /// - [`ErrorCode::StatusListExpired`] si `exp` ya venció.
    pub fn check_freshness(&self, now: UnixTime) -> Result<(), GidError> {
        if let Some(issued_at) = self.issued_at {
            if issued_at.as_seconds() > now.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::CredentialNotYetValid,
                    "status list 'iat' is in the future",
                ));
            }
        }
        if let Some(expires_at) = self.expires_at {
            if now.as_seconds() > expires_at.as_seconds() {
                return Err(GidError::new(
                    ErrorCode::StatusListExpired,
                    "status list has expired",
                ));
            }
        }
        Ok(())
    }
}

/// Verificador de Token Status List (JWT).
pub struct StatusListVerifier;

impl StatusListVerifier {
    /// Parsea y verifica un Token Status List JWT completo.
    ///
    /// Comprueba, en orden: sintaxis JWS, cabecera (`typ` y `alg`, rechazando `none`),
    /// algoritmo de digest, claim `status_list`, descompresión acotada y coherencia de
    /// `bits`. La verificación de firma y la temporal se delegan a quien corresponda
    /// (el verificador con el trust bundle en F4.T03).
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] ante cualquier incumplimiento de formato;
    /// [`ErrorCode::UnsupportedAlgorithm`] para `alg`/`typ` prohibidos.
    pub fn parse(jwt: &str) -> Result<TokenStatusList, GidError> {
        let segments: Vec<&str> = jwt.split('.').collect();
        if segments.len() != 3 {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "Token Status List must have 3 dot-separated segments, got {}",
                    segments.len()
                ),
            ));
        }

        let Some(&header_b64) = segments.first() else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing Token Status List header",
            ));
        };
        let Some(&payload_b64) = segments.get(1) else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing Token Status List payload",
            ));
        };

        let limits = JsonLimits::profile_default();
        let header_bytes = base64url::decode(header_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("invalid base64url in status list header: {e}"),
            )
        })?;
        let header_val = parse_bytes(&header_bytes, &limits).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("failed to parse status list header: {e}"),
            )
        })?;

        match header_val.member("typ").and_then(Value::as_str) {
            Some(typ) if typ == STATUS_LIST_TYP => {}
            Some(typ) => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("unsupported 'typ' header '{typ}', expected '{STATUS_LIST_TYP}'"),
                ));
            }
            None => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "missing 'typ' header in Token Status List",
                ));
            }
        }

        match header_val.member("alg").and_then(Value::as_str) {
            Some(alg) if alg == STATUS_LIST_ALG => {}
            Some(alg) if alg.eq_ignore_ascii_case("none") => {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    "algorithm 'none' is strictly prohibited (INV-08)",
                ));
            }
            Some(alg) => {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    format!("unsupported algorithm '{alg}': only {STATUS_LIST_ALG} is supported"),
                ));
            }
            None => {
                return Err(GidError::new(
                    ErrorCode::UnsupportedAlgorithm,
                    "missing 'alg' header in Token Status List",
                ));
            }
        }

        let payload_bytes = base64url::decode(payload_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("invalid base64url in status list payload: {e}"),
            )
        })?;
        let payload_limits = JsonLimits {
            max_string_bytes: 64 * 1024,
            ..JsonLimits::profile_default()
        };
        let payload_val = parse_bytes(&payload_bytes, &payload_limits).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("failed to parse status list payload: {e}"),
            )
        })?;

        Self::from_payload(&payload_val)
    }

    /// Construye la lista a partir del payload ya decodificado.
    ///
    /// Separado de [`StatusListVerifier::parse`] para poder probar el tratamiento del
    /// claim `status_list` sin firmar.
    pub fn from_payload(payload: &Value) -> Result<TokenStatusList, GidError> {
        let status_list = payload.member("status_list").ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                "Token Status List payload missing 'status_list' claim",
            )
        })?;

        let bits = match status_list.member("bits") {
            Some(Value::Number(Number::PosInt(bits))) => u8::try_from(*bits).map_err(|_| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("'bits' value {bits} is out of the supported range"),
                )
            })?,
            _ => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status_list claim must declare an integer 'bits' member",
                ));
            }
        };
        if !SUPPORTED_BITS_PER_ENTRY.contains(&bits) {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "unsupported {bits} bits per entry: only {SUPPORTED_BITS_PER_ENTRY:?} are allowed"
                ),
            ));
        }

        let lst_b64 = status_list
            .member("lst")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    "status_list claim missing the compressed 'lst' member",
                )
            })?;

        let compressed = base64url::decode(lst_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("invalid base64url in 'lst': {e}"),
            )
        })?;

        // REQ-STAT-003: descompresión acotada (límite absoluto y ratio).
        let entries = inflate_bounded(&compressed, MAX_DECOMPRESSED_BYTES, MAX_EXPANSION_RATIO)
            .map_err(|e| {
                GidError::new(
                    ErrorCode::MalformedStatusList,
                    format!("status list 'lst' decompression failed: {e}"),
                )
            })?;

        let uri = status_list
            .member("uri")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let expires_at = match payload.member("exp") {
            Some(Value::Number(Number::PosInt(exp))) => Some(UnixTime::from_seconds(*exp)),
            Some(_) => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "payload 'exp' must be a positive integer",
                ));
            }
            None => None,
        };

        let issued_at = match payload.member("iat") {
            Some(Value::Number(Number::PosInt(iat))) => Some(UnixTime::from_seconds(*iat)),
            Some(_) => {
                return Err(GidError::new(
                    ErrorCode::MalformedStatusList,
                    "payload 'iat' must be a positive integer",
                ));
            }
            None => None,
        };

        Ok(TokenStatusList {
            bits_per_entry: bits,
            entries,
            uri,
            expires_at,
            issued_at,
        })
    }

    /// Verifica la firma JWS de la lista contra la clave de estado del emisor.
    ///
    /// La clave se obtiene del trust bundle (INV-06); esta función solo la usa.
    ///
    /// # Errores
    /// [`ErrorCode::InvalidSignature`] si la firma no verifica o tiene longitud inválida.
    pub fn verify_signature(jwt: &str, signing_key: &JwkEcP256) -> Result<(), GidError> {
        let segments: Vec<&str> = jwt.split('.').collect();
        if segments.len() != 3 {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                format!(
                    "Token Status List must have 3 dot-separated segments, got {}",
                    segments.len()
                ),
            ));
        }
        let Some(&header_b64) = segments.first() else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing Token Status List header",
            ));
        };
        let Some(&payload_b64) = segments.get(1) else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing Token Status List payload",
            ));
        };
        let Some(&sig_b64) = segments.get(2) else {
            return Err(GidError::new(
                ErrorCode::MalformedStatusList,
                "missing Token Status List signature",
            ));
        };

        let signature = base64url::decode(sig_b64).map_err(|e| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("invalid base64url in status list signature: {e}"),
            )
        })?;
        if signature.len() != ES256_SIGNATURE_LEN {
            return Err(GidError::new(
                ErrorCode::InvalidSignature,
                format!(
                    "status list signature must be {} bytes, got {}",
                    ES256_SIGNATURE_LEN,
                    signature.len()
                ),
            ));
        }

        let mut signature_bytes = [0u8; ES256_SIGNATURE_LEN];
        if let Some(slot) = signature_bytes.get_mut(..signature.len()) {
            slot.copy_from_slice(&signature);
        }

        verify_es256_jwk(
            signing_key,
            format!("{header_b64}.{payload_b64}").as_bytes(),
            &signature_bytes,
        )
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
    use alloc::vec;
    use gravital_id_codec::deflate::deflate;

    /// Empaqueta una secuencia de estados en una `lst` comprimida y codificada.
    fn pack_lst(bits: u8, values: &[u32]) -> String {
        let mut bytes = Vec::new();
        let mut current: u8 = 0;
        let mut used = 0u32;
        for value in values {
            for shift in (0..bits).rev() {
                let bit = (value >> shift) & 0b1;
                current = (current << 1) | (bit as u8);
                used = used.saturating_add(1);
                if used.is_multiple_of(8) {
                    bytes.push(current);
                    current = 0;
                }
            }
        }
        if !used.is_multiple_of(8) {
            current <<= 8u32.saturating_sub(used % 8);
            bytes.push(current);
        }
        base64url::encode(&deflate(&bytes))
    }

    /// Payload de prueba: `list_extra` va dentro de `status_list` (p. ej. `uri`) y
    /// `root_extra` en la raíz del payload (p. ej. `exp`, `iat`).
    fn payload(
        bits: u8,
        values: &[u32],
        list_extra: &[(&str, Value)],
        root_extra: &[(&str, Value)],
    ) -> Value {
        let mut entries = vec![
            (
                "bits".to_string(),
                Value::Number(Number::PosInt(u64::from(bits))),
            ),
            ("lst".to_string(), Value::String(pack_lst(bits, values))),
        ];
        for (key, value) in list_extra {
            entries.push(((*key).to_string(), value.clone()));
        }
        let mut root = vec![("status_list".to_string(), Value::Object(entries))];
        for (key, value) in root_extra {
            root.push(((*key).to_string(), value.clone()));
        }
        Value::Object(root)
    }

    #[test]
    fn one_bit_lists_report_valid_and_revoked() {
        let list = StatusListVerifier::from_payload(&payload(1, &[0, 1, 0], &[], &[]))
            .expect("one bit list");
        assert_eq!(list.bits_per_entry(), 1);
        // El número de entradas se deriva de los bytes recibidos (3 bits => 1 byte => 8
        // ranuras de 1 bit); el resto es relleno.
        assert_eq!(list.entry_count(), 8);
        assert_eq!(list.status_of(0).unwrap(), TokenStatus::Valid);
        assert_eq!(list.status_of(1).unwrap(), TokenStatus::Revoked);
        assert_eq!(list.status_of(2).unwrap(), TokenStatus::Valid);
    }

    #[test]
    fn two_bit_lists_report_suspended() {
        let list = StatusListVerifier::from_payload(&payload(2, &[0, 1, 2, 0], &[], &[]))
            .expect("two bit list");
        assert_eq!(list.entry_count(), 4);
        assert_eq!(list.status_of(0).unwrap(), TokenStatus::Valid);
        assert_eq!(list.status_of(1).unwrap(), TokenStatus::Revoked);
        assert_eq!(list.status_of(2).unwrap(), TokenStatus::Suspended);
        assert_eq!(list.status_of(3).unwrap(), TokenStatus::Valid);
    }

    #[test]
    fn index_out_of_range_is_rejected() {
        let list = StatusListVerifier::from_payload(&payload(1, &[0, 1], &[], &[])).expect("list");
        let error = list.status_of(9).unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusIndexOutOfRange);
    }

    #[test]
    fn undefined_status_value_fails_closed() {
        // Con 2 bits por entrada, el valor 3 (11b) no corresponde a ningún estado.
        let list = StatusListVerifier::from_payload(&payload(2, &[3], &[], &[])).expect("list");
        let error = list.status_of(0).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
        assert!(error.message.contains("not defined"));
    }

    #[test]
    fn unsupported_bits_per_entry_is_rejected() {
        let error = StatusListVerifier::from_payload(&payload(4, &[0], &[], &[])).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
    }

    #[test]
    fn uri_and_freshness_checks() {
        let list = StatusListVerifier::from_payload(&payload(
            1,
            &[0, 1],
            &[(
                "uri",
                Value::String("https://status.example.gov/l".to_string()),
            )],
            &[
                ("exp", Value::Number(Number::PosInt(1_800_000_000))),
                ("iat", Value::Number(Number::PosInt(1_700_000_000))),
            ],
        ))
        .expect("list");

        list.check_uri("https://status.example.gov/l")
            .expect("uri coincide");
        let error = list.check_uri("https://other.example.gov/l").unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);

        list.check_freshness(UnixTime::from_seconds(1_700_000_100))
            .expect("vigente");

        let error = list
            .check_freshness(UnixTime::from_seconds(1_800_000_100))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusListExpired);

        let error = list
            .check_freshness(UnixTime::from_seconds(1_699_999_000))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::CredentialNotYetValid);
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        // Contenido altamente comprimible que supera el ratio admitido.
        let bomb = alloc::vec![0u8; 4096];
        let compressed = deflate(&bomb);
        let lst = base64url::encode(&compressed);
        let payload = Value::Object(vec![(
            "status_list".to_string(),
            Value::Object(vec![
                ("bits".to_string(), Value::Number(Number::PosInt(1))),
                ("lst".to_string(), Value::String(lst)),
            ]),
        )]);
        let error = StatusListVerifier::from_payload(&payload).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
        assert!(error.message.contains("decompression"));
    }

    #[test]
    fn parse_rejects_forbidden_headers() {
        let header = r#"{"alg":"none","typ":"statuslist+jwt"}"#;
        let payload = r#"{"status_list":{"bits":1,"lst":"eJw"}}"#;
        let jwt = format!(
            "{}.{}.{}",
            base64url::encode(header.as_bytes()),
            base64url::encode(payload.as_bytes()),
            base64url::encode(&[0u8; 64])
        );
        let error = StatusListVerifier::parse(&jwt).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);

        let header = r#"{"alg":"ES256","typ":"jwt"}"#;
        let jwt = format!(
            "{}.{}.{}",
            base64url::encode(header.as_bytes()),
            base64url::encode(payload.as_bytes()),
            base64url::encode(&[0u8; 64])
        );
        let error = StatusListVerifier::parse(&jwt).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
    }
}
