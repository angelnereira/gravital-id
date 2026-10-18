//! Almacenamiento en memoria con límites y TTL estricto para pip-relay (F7.T06).
//!
//! Implementa:
//! - Distribución de objetos por hash SHA-256 (`REQ-SYNC-004`).
//! - Buzones de sobres de operación cifrados con HPKE (`REQ-SYNC-006`).
//! - Punto de encuentro efímero (`SessionCode`, `ADR-0025`, `PROTOCOL.md §7.7`).
//!
//! Trazabilidad:
//! - **INV-01:** Sin I/O de red en la lógica interna del motor.
//! - **INV-02:** Cero datos personales ni payloads cifrados registrados en logs.
//! - **INV-11:** Inyección de reloj [`Clock`] para determinismo estricto en pruebas.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use gravital_id_crypto::sha256;
use gravital_id_types::{Clock, UnixTime};

use crate::config::RelayConfig;
use crate::error::RelayError;

/// Matriz canónica del cuasigrupo antisimétrico de Damm (2004) de orden 10.
const DAMM_TABLE: [[u8; 10]; 10] = [
    [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
    [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
    [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
    [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
    [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
    [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
    [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
    [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
    [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
    [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
];

/// Prefijo de dominio normativo para el hash de sesión (`PROTOCOL.md §7.7`).
pub const SESSION_CODE_HASH_PREFIX: &[u8] = b"gid-session-code-v1";

/// Valida un `SessionCode` de 10 dígitos mediante el algoritmo de Damm (ADR-0025).
///
/// Ignora guiones y espacios en blanco. Retorna la cadena canónica de 10 dígitos.
///
/// # Errores
/// [`RelayError::InvalidSessionCode`] si no tiene exactamente 10 dígitos o falla la suma de Damm.
pub fn validate_session_code(code: &str) -> Result<String, RelayError> {
    let digits: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    if digits.len() != 10 {
        return Err(RelayError::InvalidSessionCode(format!(
            "session code must have exactly 10 digits (got {})",
            digits.len()
        )));
    }

    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(RelayError::InvalidSessionCode(
            "session code must contain only decimal digits".to_string(),
        ));
    }

    let mut interim = 0usize;
    for ch in digits.chars() {
        let digit = (ch as u8).saturating_sub(b'0') as usize;
        let row = DAMM_TABLE
            .get(interim)
            .ok_or_else(|| RelayError::InvalidSessionCode("damm lookup row out of range".into()))?;
        let next = row
            .get(digit)
            .ok_or_else(|| RelayError::InvalidSessionCode("damm lookup col out of range".into()))?;
        interim = *next as usize;
    }

    if interim != 0 {
        return Err(RelayError::InvalidSessionCode(
            "damm check digit validation failed".to_string(),
        ));
    }

    Ok(digits)
}

/// Calcula el dígito de control de Damm para una secuencia de 9 dígitos numéricos.
///
/// # Errores
/// [`RelayError::InvalidSessionCode`] si no tiene exactamente 9 dígitos decimales.
pub fn compute_damm_check_digit(nine_digits: &str) -> Result<u8, RelayError> {
    let digits: String = nine_digits
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    if digits.len() != 9 {
        return Err(RelayError::InvalidSessionCode(format!(
            "expected 9 digits to compute check digit (got {})",
            digits.len()
        )));
    }

    let mut interim = 0usize;
    for ch in digits.chars() {
        if !ch.is_ascii_digit() {
            return Err(RelayError::InvalidSessionCode(
                "session code must contain only decimal digits".to_string(),
            ));
        }
        let digit = (ch as u8).saturating_sub(b'0') as usize;
        let row = DAMM_TABLE
            .get(interim)
            .ok_or_else(|| RelayError::InvalidSessionCode("damm lookup row out of range".into()))?;
        let next = row
            .get(digit)
            .ok_or_else(|| RelayError::InvalidSessionCode("damm lookup col out of range".into()))?;
        interim = *next as usize;
    }

    u8::try_from(interim)
        .map_err(|_| RelayError::InvalidSessionCode("check digit exceeds u8".into()))
}

/// Computa el hash de sesión a partir de los 10 dígitos validados (`PROTOCOL.md §7.7`).
#[must_use]
pub fn compute_session_hash_hex(session_code_10_digits: &str) -> String {
    let mut preimage = Vec::with_capacity(SESSION_CODE_HASH_PREFIX.len().saturating_add(10));
    preimage.extend_from_slice(SESSION_CODE_HASH_PREFIX);
    preimage.extend_from_slice(session_code_10_digits.as_bytes());

    let digest = sha256(&preimage);
    hex_encode(&digest)
}

/// Registro de objeto direccionado por contenido (REQ-SYNC-004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRecord {
    /// Hash SHA-256 en formato hexadecimal en minúsculas (64 caracteres).
    pub sha256_hex: String,
    /// Contenido binario del objeto.
    pub data: Vec<u8>,
    /// Instante de creación.
    pub created_at: UnixTime,
    /// Instante de caducidad.
    pub expires_at: UnixTime,
}

/// Sobre de operación cifrado con HPKE en un buzón (REQ-SYNC-006).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeRecord {
    /// Identificador único del sobre (clave de idempotencia).
    pub envelope_id: String,
    /// Carga cifrada opaca (HPKE ciphertext).
    pub payload: Vec<u8>,
    /// Instante de recepción.
    pub created_at: UnixTime,
    /// Instante de caducidad.
    pub expires_at: UnixTime,
}

/// Sesión efímera de punto de encuentro numérico (`SessionCode`, PROTOCOL.md §7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousSession {
    /// Hash de sesión de 64 caracteres hex (`sha256("gid-session-code-v1" || code)`).
    pub session_hash: String,
    /// Solicitud de verificación (`ProximityRequest`) opcional.
    pub request_payload: Option<Vec<u8>>,
    /// Respuesta de presentación (`ProximityResponse`) opcional.
    pub response_payload: Option<Vec<u8>>,
    /// Instante de creación.
    pub created_at: UnixTime,
    /// Instante de caducidad (máx. 180 segundos).
    pub expires_at: UnixTime,
    /// Marca de consumo atómico de un solo uso.
    pub consumed: bool,
}

/// Estado interno en memoria del relay.
#[derive(Default)]
struct StoreState {
    objects: HashMap<String, ObjectRecord>,
    mailboxes: HashMap<String, BTreeMap<String, EnvelopeRecord>>,
    rendezvous: HashMap<String, RendezvousSession>,
}

/// Almacén en memoria concurrente y con límite de recursos para `pip-relay`.
pub struct InMemoryRelayStore<C: Clock + Send + Sync + 'static> {
    config: RelayConfig,
    clock: C,
    state: RwLock<StoreState>,
}

impl<C: Clock + Send + Sync + 'static> InMemoryRelayStore<C> {
    /// Construye una nueva instancia de almacenamiento en memoria con la configuración y reloj inyectados.
    pub fn new(config: RelayConfig, clock: C) -> Self {
        Self {
            config,
            clock,
            state: RwLock::new(StoreState::default()),
        }
    }

    /// Retorna una referencia a la configuración activa.
    #[must_use]
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// Retorna una referencia al reloj inyectado.
    #[must_use]
    pub fn clock(&self) -> &C {
        &self.clock
    }

    #[inline]
    fn now(&self) -> UnixTime {
        UnixTime::from_seconds(self.clock.now_seconds())
    }

    // =========================================================================
    // OBJETOS POR HASH (REQ-SYNC-004)
    // =========================================================================

    /// Almacena un objeto direccionado por su hash SHA-256.
    ///
    /// # Errores
    /// - [`RelayError::PayloadTooLarge`] si el tamaño supera `max_payload_bytes`.
    /// - [`RelayError::ObjectHashMismatch`] si `expected_sha256` no coincide con el digest real.
    /// - [`RelayError::CapacityExceeded`] si la capacidad máxima de objetos se ha alcanzado.
    pub fn put_object(
        &self,
        data: Vec<u8>,
        expected_sha256: Option<&str>,
        custom_ttl_secs: Option<u64>,
    ) -> Result<String, RelayError> {
        if data.len() > self.config.max_payload_bytes {
            return Err(RelayError::PayloadTooLarge {
                max: self.config.max_payload_bytes,
                actual: data.len(),
            });
        }

        let computed_digest = sha256(&data);
        let computed_hex = hex_encode(&computed_digest);

        if let Some(expected) = expected_sha256 {
            let normalized_expected = expected.trim().to_ascii_lowercase();
            if normalized_expected != computed_hex {
                return Err(RelayError::ObjectHashMismatch {
                    expected: normalized_expected,
                    actual: computed_hex,
                });
            }
        }

        let now = self.now();
        let ttl = custom_ttl_secs
            .unwrap_or(self.config.default_object_ttl_secs)
            .min(self.config.max_object_ttl_secs);
        let expires_at = UnixTime::from_seconds(now.as_seconds().saturating_add(ttl));

        let mut lock = self
            .state
            .write()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        // Evicción oportuna si está al límite
        if lock.objects.len() >= self.config.max_objects_capacity
            && !lock.objects.contains_key(&computed_hex)
        {
            lock.objects.retain(|_, v| v.expires_at > now);
            if lock.objects.len() >= self.config.max_objects_capacity {
                return Err(RelayError::CapacityExceeded(
                    "maximum object capacity reached".into(),
                ));
            }
        }

        lock.objects.insert(
            computed_hex.clone(),
            ObjectRecord {
                sha256_hex: computed_hex.clone(),
                data,
                created_at: now,
                expires_at,
            },
        );

        Ok(computed_hex)
    }

    /// Obtiene un objeto por su hash SHA-256.
    ///
    /// # Errores
    /// [`RelayError::ObjectNotFound`] si el objeto no existe o ha expirado.
    pub fn get_object(&self, sha256_hex: &str) -> Result<Vec<u8>, RelayError> {
        let key = sha256_hex.trim().to_ascii_lowercase();
        let now = self.now();

        let lock = self
            .state
            .read()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        let record = lock
            .objects
            .get(&key)
            .ok_or_else(|| RelayError::ObjectNotFound(key.clone()))?;

        if record.expires_at <= now {
            return Err(RelayError::ObjectNotFound(key));
        }

        Ok(record.data.clone())
    }

    /// Retorna el número de objetos actualmente almacenados.
    pub fn object_count(&self) -> usize {
        self.state.read().map(|s| s.objects.len()).unwrap_or(0)
    }

    // =========================================================================
    // BUZÓN DE SOBRES DE OPERACIÓN (REQ-SYNC-006)
    // =========================================================================

    /// Publica un sobre cifrado en el buzón indicado.
    ///
    /// Retorna `Ok(true)` si se insertó un sobre nuevo, o `Ok(false)` si el sobre ya
    /// existía con la misma clave de idempotencia (operación idempotente).
    ///
    /// # Errores
    /// - [`RelayError::PayloadTooLarge`] si el payload excede el tamaño máximo.
    /// - [`RelayError::InvalidIdentifier`] si el `inbox_id` o `envelope_id` están vacíos.
    /// - [`RelayError::CapacityExceeded`] si se supera el número máximo de buzones o sobres.
    pub fn post_envelope(
        &self,
        inbox_id: &str,
        envelope_id: &str,
        payload: Vec<u8>,
        custom_ttl_secs: Option<u64>,
    ) -> Result<bool, RelayError> {
        let clean_inbox = inbox_id.trim();
        if clean_inbox.is_empty() {
            return Err(RelayError::InvalidIdentifier(
                "inbox_id must not be empty".into(),
            ));
        }

        let clean_id = envelope_id.trim();
        if clean_id.is_empty() {
            return Err(RelayError::InvalidIdentifier(
                "envelope_id must not be empty".into(),
            ));
        }

        if payload.len() > self.config.max_payload_bytes {
            return Err(RelayError::PayloadTooLarge {
                max: self.config.max_payload_bytes,
                actual: payload.len(),
            });
        }

        let now = self.now();
        let ttl = custom_ttl_secs
            .unwrap_or(self.config.default_envelope_ttl_secs)
            .min(self.config.max_envelope_ttl_secs);
        let expires_at = UnixTime::from_seconds(now.as_seconds().saturating_add(ttl));

        let mut lock = self
            .state
            .write()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        // Evicción y control de capacidad de buzones
        if !lock.mailboxes.contains_key(clean_inbox)
            && lock.mailboxes.len() >= self.config.max_mailboxes_capacity
        {
            lock.mailboxes.retain(|_, box_envelopes| {
                box_envelopes.retain(|_, env| env.expires_at > now);
                !box_envelopes.is_empty()
            });

            if lock.mailboxes.len() >= self.config.max_mailboxes_capacity {
                return Err(RelayError::CapacityExceeded(
                    "maximum mailboxes capacity reached".into(),
                ));
            }
        }

        let inbox = lock.mailboxes.entry(clean_inbox.to_string()).or_default();

        // Idempotencia estricta: si ya existe el envelope_id, retornar Ok(false)
        if inbox.contains_key(clean_id) {
            return Ok(false);
        }

        // Limpiar expirados en este buzón si está lleno
        if inbox.len() >= self.config.max_envelopes_per_mailbox {
            inbox.retain(|_, env| env.expires_at > now);
            if inbox.len() >= self.config.max_envelopes_per_mailbox {
                return Err(RelayError::CapacityExceeded(
                    "maximum envelopes per mailbox reached".into(),
                ));
            }
        }

        inbox.insert(
            clean_id.to_string(),
            EnvelopeRecord {
                envelope_id: clean_id.to_string(),
                payload,
                created_at: now,
                expires_at,
            },
        );

        Ok(true)
    }

    /// Consulta los sobres vigentes en un buzón, opcionalmente filtrados a partir de `since_time`.
    pub fn get_envelopes(
        &self,
        inbox_id: &str,
        since_time: Option<UnixTime>,
    ) -> Result<Vec<EnvelopeRecord>, RelayError> {
        let clean_inbox = inbox_id.trim();
        let now = self.now();

        let lock = self
            .state
            .read()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        let Some(inbox) = lock.mailboxes.get(clean_inbox) else {
            return Ok(Vec::new());
        };

        let envelopes = inbox
            .values()
            .filter(|env| {
                if env.expires_at <= now {
                    return false;
                }
                if let Some(since) = since_time {
                    env.created_at >= since
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        Ok(envelopes)
    }

    /// Borra un sobre de un buzón (acuse de entrega / ACK).
    pub fn delete_envelope(&self, inbox_id: &str, envelope_id: &str) -> Result<bool, RelayError> {
        let clean_inbox = inbox_id.trim();
        let clean_id = envelope_id.trim();

        let mut lock = self
            .state
            .write()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        let Some(inbox) = lock.mailboxes.get_mut(clean_inbox) else {
            return Ok(false);
        };

        let removed = inbox.remove(clean_id).is_some();
        Ok(removed)
    }

    // =========================================================================
    // PUNTO DE ENCUENTRO EFÍMERO (SessionCode, PROTOCOL.md §7.7)
    // =========================================================================

    /// Registra la solicitud de verificación (`ProximityRequest`) para una sesión efímera.
    ///
    /// # Errores
    /// - [`RelayError::InvalidIdentifier`] si `session_hash_hex` no tiene 64 caracteres hex.
    /// - [`RelayError::PayloadTooLarge`] si el tamaño supera `max_payload_bytes`.
    /// - [`RelayError::CapacityExceeded`] si se supera `max_rendezvous_capacity`.
    pub fn register_session_request(
        &self,
        session_hash_hex: &str,
        request_bytes: Vec<u8>,
        ttl_secs: Option<u64>,
    ) -> Result<(), RelayError> {
        let clean_hash = session_hash_hex.trim().to_ascii_lowercase();
        if clean_hash.len() != 64 || !clean_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RelayError::InvalidIdentifier(
                "session_hash must be a 64-character hexadecimal SHA-256 digest".into(),
            ));
        }

        if request_bytes.len() > self.config.max_payload_bytes {
            return Err(RelayError::PayloadTooLarge {
                max: self.config.max_payload_bytes,
                actual: request_bytes.len(),
            });
        }

        let now = self.now();
        let ttl = ttl_secs
            .unwrap_or(self.config.session_code_ttl_secs)
            .min(self.config.session_code_ttl_secs); // Norma: máximo 180 s
        let expires_at = UnixTime::from_seconds(now.as_seconds().saturating_add(ttl));

        let mut lock = self
            .state
            .write()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        if !lock.rendezvous.contains_key(&clean_hash)
            && lock.rendezvous.len() >= self.config.max_rendezvous_capacity
        {
            lock.rendezvous
                .retain(|_, s| s.expires_at > now && !s.consumed);
            if lock.rendezvous.len() >= self.config.max_rendezvous_capacity {
                return Err(RelayError::CapacityExceeded(
                    "maximum rendezvous sessions capacity reached".into(),
                ));
            }
        }

        lock.rendezvous.insert(
            clean_hash.clone(),
            RendezvousSession {
                session_hash: clean_hash,
                request_payload: Some(request_bytes),
                response_payload: None,
                created_at: now,
                expires_at,
                consumed: false,
            },
        );

        Ok(())
    }

    /// Obtiene la solicitud de verificación pendiente para una sesión efímera.
    ///
    /// # Errores
    /// - [`RelayError::SessionNotFound`] si no existe la sesión.
    /// - [`RelayError::SessionExpired`] si la sesión ha superado su TTL.
    /// - [`RelayError::SessionAlreadyConsumed`] si ya fue consumida.
    pub fn get_session_request(&self, session_hash_hex: &str) -> Result<Vec<u8>, RelayError> {
        let clean_hash = session_hash_hex.trim().to_ascii_lowercase();
        let now = self.now();

        let lock = self
            .state
            .read()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        let session = lock
            .rendezvous
            .get(&clean_hash)
            .ok_or(RelayError::SessionNotFound)?;

        if session.expires_at <= now {
            return Err(RelayError::SessionExpired);
        }

        if session.consumed {
            return Err(RelayError::SessionAlreadyConsumed);
        }

        let request = session
            .request_payload
            .as_ref()
            .ok_or(RelayError::SessionNotFound)?;

        Ok(request.clone())
    }

    /// Envía la respuesta de presentación a la sesión efímera.
    ///
    /// **Garantía de un solo uso:** Si la respuesta ya fue enviada o la sesión fue consumida,
    /// rechaza atómicamente con [`RelayError::SessionAlreadyConsumed`] (`REQ-CODE-001`).
    ///
    /// # Errores
    /// - [`RelayError::SessionNotFound`] si la sesión no existe.
    /// - [`RelayError::SessionExpired`] si la sesión ha expirado.
    /// - [`RelayError::SessionAlreadyConsumed`] si ya existe una respuesta o ya fue consumida.
    /// - [`RelayError::PayloadTooLarge`] si el tamaño supera `max_payload_bytes`.
    pub fn submit_session_response(
        &self,
        session_hash_hex: &str,
        response_bytes: Vec<u8>,
    ) -> Result<(), RelayError> {
        let clean_hash = session_hash_hex.trim().to_ascii_lowercase();

        if response_bytes.len() > self.config.max_payload_bytes {
            return Err(RelayError::PayloadTooLarge {
                max: self.config.max_payload_bytes,
                actual: response_bytes.len(),
            });
        }

        let now = self.now();

        let mut lock = self
            .state
            .write()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        let session = lock
            .rendezvous
            .get_mut(&clean_hash)
            .ok_or(RelayError::SessionNotFound)?;

        if session.expires_at <= now {
            return Err(RelayError::SessionExpired);
        }

        if session.consumed || session.response_payload.is_some() {
            return Err(RelayError::SessionAlreadyConsumed);
        }

        session.response_payload = Some(response_bytes);
        Ok(())
    }

    /// Obtiene la respuesta de presentación y marca la sesión como consumida atómicamente.
    ///
    /// # Errores
    /// - [`RelayError::SessionNotFound`] si la sesión o la respuesta no existen aún.
    /// - [`RelayError::SessionExpired`] si la sesión ha expirado.
    /// - [`RelayError::SessionAlreadyConsumed`] si ya fue consumida previamente.
    pub fn get_session_response(&self, session_hash_hex: &str) -> Result<Vec<u8>, RelayError> {
        let clean_hash = session_hash_hex.trim().to_ascii_lowercase();
        let now = self.now();

        let mut lock = self
            .state
            .write()
            .map_err(|_| RelayError::Internal("poisoned store lock".into()))?;

        let session = lock
            .rendezvous
            .get_mut(&clean_hash)
            .ok_or(RelayError::SessionNotFound)?;

        if session.expires_at <= now {
            return Err(RelayError::SessionExpired);
        }

        if session.consumed {
            return Err(RelayError::SessionAlreadyConsumed);
        }

        let response = session
            .response_payload
            .take()
            .ok_or(RelayError::SessionNotFound)?;

        session.consumed = true;
        Ok(response)
    }

    /// Realiza limpieza global de registros caducados (mantenimiento periódico).
    pub fn cleanup_expired(&self) {
        let now = self.now();
        if let Ok(mut lock) = self.state.write() {
            lock.objects.retain(|_, v| v.expires_at > now);
            lock.mailboxes.retain(|_, box_envelopes| {
                box_envelopes.retain(|_, env| env.expires_at > now);
                !box_envelopes.is_empty()
            });
            lock.rendezvous
                .retain(|_, s| s.expires_at > now && !s.consumed);
        }
    }
}

/// Codifica bytes a string hexadecimal en minúsculas sin unwraps ni indexación insegura.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let cap = bytes.len().saturating_mul(2);
    let mut hex = Vec::with_capacity(cap);
    for &b in bytes {
        let high = (b >> 4) as usize;
        let low = (b & 0x0f) as usize;
        if let Some(&h) = HEX_CHARS.get(high) {
            hex.push(h);
        }
        if let Some(&l) = HEX_CHARS.get(low) {
            hex.push(l);
        }
    }
    String::from_utf8(hex).unwrap_or_default()
}
