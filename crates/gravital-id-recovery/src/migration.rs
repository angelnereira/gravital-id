//! Protocolo normativo de migración directa entre dispositivos con compromiso previo y SAS (`REQ-REC-001`, `ADR-0009`, `SPEC-PIP-MIGRATE-001`).
//!
//! Trazabilidad:
//! - **REQ-REC-001:** La migración entre dispositivos DEBE usar canal efímero ECDH con compromiso previo de claves y verificación SAS.
//! - **ADR-0009:** Modelo de recuperación Nivel 1 (migración voluntaria entre dispositivos).
//! - **INV-01:** Sans-I/O en capas L1–L4 (`no_std` + `alloc`).
//! - **INV-02:** Cero datos personales o identificadores de hardware en tránsito no cifrado, logs o transcritos.
//! - **INV-03:** Claves privadas del titular protegidas; no se exportan claves ligadas a hardware, se encolan re-vinculaciones.
//! - **INV-05:** Fail-closed estricto ante manipulación de compromiso, transcript o tag AEAD.
//! - **INV-10:** Cero pánicos, unwraps o estados indefinidos.
//! - **INV-11:** Relojes y generadores criptográficos CSPRNG inyectados por el llamador.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use gravital_id_crypto::aead::{open as aead_open, seal as aead_seal, AEAD_NONCE_LEN};
use gravital_id_crypto::ecdh::ecdh_agree_keys;
use gravital_id_crypto::jwk::JwkEcP256;
use gravital_id_crypto::kdf::{hkdf_expand_sha256, hkdf_extract_sha256};
use gravital_id_crypto::mac::constant_time_eq;
use gravital_id_crypto::rng::Rng;
use gravital_id_crypto::secret::{SecretBytes, SecretKeyBytes};
use gravital_id_crypto::sha::sha256;
use gravital_id_crypto::sign::{generate_p256_secret_key, public_key_from_secret_key};
use gravital_id_types::{Clock, UnixTime};

use crate::error::RecoveryError;
use crate::payload::BackupPayload;

/// Prefijo normativo para el código QR de enganche de migración.
pub const MIGRATION_QR_PREFIX: &str = "pip-migrate-v1";

/// Prefijo canónico para el compromiso previo de clave efímera.
pub const MIGRATION_COMMITMENT_PREFIX: &str = "pip-migrate-commit-v1:";

/// Prefijo canónico para el transcrito SAS.
pub const MIGRATION_SAS_PREFIX: &str = "pip-migrate-sas-v1:";

/// Longitud del identificador de sesión de migración en bytes.
pub const SESSION_ID_LEN: usize = 16;

/// Longitud de los nonces criptográficos de migración en bytes.
pub const NONCE_LEN: usize = 16;

/// Longitud del resumen de compromiso SHA-256 en bytes.
pub const COMMITMENT_LEN: usize = 32;

/// Longitud de la clave pública SEC1 sin comprimir en bytes (`0x04 || x || y`).
pub const SEC1_PUBKEY_LEN: usize = 65;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

const HKDF_INFO_SAS_CODE: &[u8] = b"pip-sas-code";
const HKDF_INFO_SESSION_KEY: &[u8] = b"pip-migrate-session-key";
const HKDF_INFO_SESSION_NONCE: &[u8] = b"pip-migrate-session-nonce";

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        if let Some(&h) = HEX_CHARS.get((b >> 4) as usize) {
            out.push(h);
        }
        if let Some(&l) = HEX_CHARS.get((b & 0x0f) as usize) {
            out.push(l);
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

fn decode_hex_nibble(byte: u8) -> Result<u8, RecoveryError> {
    match byte {
        b'0'..=b'9' => Ok(byte.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(byte.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Ok(byte.saturating_sub(b'A').saturating_add(10)),
        _ => Err(RecoveryError::InvalidMigrationMessage(
            "carácter hexadecimal no válido",
        )),
    }
}

fn decode_hex_exact<const N: usize>(s: &str) -> Result<[u8; N], RecoveryError> {
    if s.len() != N.saturating_mul(2) {
        return Err(RecoveryError::InvalidMigrationMessage(
            "longitud de cadena hexadecimal incorrecta",
        ));
    }
    let mut out = [0u8; N];
    let bytes = s.as_bytes();
    for i in 0..N {
        let hi_idx = i.saturating_mul(2);
        let lo_idx = hi_idx.saturating_add(1);
        let hi = *bytes
            .get(hi_idx)
            .ok_or(RecoveryError::InvalidMigrationMessage(
                "error de límites hex",
            ))?;
        let lo = *bytes
            .get(lo_idx)
            .ok_or(RecoveryError::InvalidMigrationMessage(
                "error de límites hex",
            ))?;
        let val = (decode_hex_nibble(hi)? << 4) | decode_hex_nibble(lo)?;
        if let Some(slot) = out.get_mut(i) {
            *slot = val;
        }
    }
    Ok(out)
}

/// Código numérico corto de autenticación (Short Authentication String, SAS) de 6 dígitos decimales.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SasCode(u32);

impl SasCode {
    /// Construye una nueva instancia a partir de un valor entero, asegurando 6 dígitos (0..999_999).
    #[must_use]
    pub const fn new(val: u32) -> Self {
        Self(val % 1_000_000)
    }

    /// Devuelve el valor numérico entero del código SAS.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Devuelve la representación legible formateada como dos grupos de tres dígitos separados por guion (`xxx-xxx`).
    #[must_use]
    pub fn formatted(self) -> String {
        format!("{:03}-{:03}", self.0 / 1000, self.0 % 1000)
    }
}

impl fmt::Display for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.formatted())
    }
}

impl fmt::Debug for SasCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SasCode({})", self.formatted())
    }
}

/// Mensaje inicial de enganche de migración generado por el dispositivo nuevo (Destino), presentado en QR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationEngagement {
    /// Identificador único pseudoaleatorio de la sesión de migración (16 bytes).
    pub target_id: [u8; SESSION_ID_LEN],
    /// Clave pública efímera P-256 SEC1 del dispositivo nuevo (65 bytes).
    pub target_pub: [u8; SEC1_PUBKEY_LEN],
    /// Nonce aleatorio del dispositivo nuevo (16 bytes).
    pub target_nonce: [u8; NONCE_LEN],
    /// Instante UNIX de creación de la solicitud de enganche.
    pub created_at: UnixTime,
}

impl MigrationEngagement {
    /// Codifica el enganche en una cadena URI compacta para visualización en código QR.
    ///
    /// Formato: `pip-migrate-v1:<target_id_hex>:<target_pub_hex>:<target_nonce_hex>:<created_at_secs>`
    #[must_use]
    pub fn to_qr_string(&self) -> String {
        format!(
            "{MIGRATION_QR_PREFIX}:{}:{}:{}:{}",
            encode_hex(&self.target_id),
            encode_hex(&self.target_pub),
            encode_hex(&self.target_nonce),
            self.created_at.as_seconds()
        )
    }

    /// Parsea y valida una cadena URI de enganche escaneada de un código QR.
    ///
    /// # Errores
    /// [`RecoveryError::InvalidMigrationMessage`] si el prefijo, formato o longitudes son incorrectos.
    pub fn from_qr_string(s: &str) -> Result<Self, RecoveryError> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 5 {
            return Err(RecoveryError::InvalidMigrationMessage(
                "formato de QR de migración inválido",
            ));
        }

        let prefix = *parts
            .first()
            .ok_or(RecoveryError::InvalidMigrationMessage("prefijo faltante"))?;
        if prefix != MIGRATION_QR_PREFIX {
            return Err(RecoveryError::InvalidMigrationMessage(
                "prefijo de QR de migración desconocido",
            ));
        }

        let id_str = *parts
            .get(1)
            .ok_or(RecoveryError::InvalidMigrationMessage("target_id faltante"))?;
        let pub_str = *parts.get(2).ok_or(RecoveryError::InvalidMigrationMessage(
            "target_pub faltante",
        ))?;
        let nonce_str = *parts.get(3).ok_or(RecoveryError::InvalidMigrationMessage(
            "target_nonce faltante",
        ))?;
        let time_str = *parts.get(4).ok_or(RecoveryError::InvalidMigrationMessage(
            "created_at faltante",
        ))?;

        let target_id = decode_hex_exact::<SESSION_ID_LEN>(id_str)?;
        let target_pub = decode_hex_exact::<SEC1_PUBKEY_LEN>(pub_str)?;
        if target_pub.first() != Some(&0x04) {
            return Err(RecoveryError::InvalidMigrationMessage(
                "clave pública SEC1 debe tener prefijo 0x04",
            ));
        }
        // Validar punto elíptico en P-256
        let _ = JwkEcP256::from_sec1_bytes(&target_pub).map_err(|_| {
            RecoveryError::InvalidMigrationMessage("punto de curva elíptica P-256 inválido")
        })?;

        let target_nonce = decode_hex_exact::<NONCE_LEN>(nonce_str)?;
        let secs = time_str.parse::<u64>().map_err(|_| {
            RecoveryError::InvalidMigrationMessage("tiempo UNIX inválido en QR de migración")
        })?;
        let created_at = UnixTime::from_seconds(secs);

        Ok(Self {
            target_id,
            target_pub,
            target_nonce,
            created_at,
        })
    }
}

/// Mensaje de compromiso criptográfico previo enviado por el dispositivo origen (Viejo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommitment {
    /// Identificador de sesión correspondiente al enganche.
    pub target_id: [u8; SESSION_ID_LEN],
    /// Resumen SHA-256 del compromiso previo sobre la clave efímera del origen y nonces.
    pub commitment: [u8; COMMITMENT_LEN],
}

/// Acuse de recibo del compromiso previo emitido por el dispositivo nuevo (Destino).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCommitmentAck {
    /// Identificador de sesión confirmado.
    pub target_id: [u8; SESSION_ID_LEN],
    /// Estado de aceptación del compromiso.
    pub accepted: bool,
}

/// Mensaje de revelación de clave efímera enviado por el dispositivo origen tras el acuse del compromiso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRevelation {
    /// Identificador de sesión.
    pub target_id: [u8; SESSION_ID_LEN],
    /// Clave pública efímera P-256 SEC1 del dispositivo origen (65 bytes).
    pub source_pub: [u8; SEC1_PUBKEY_LEN],
    /// Nonce aleatorio del dispositivo origen (16 bytes).
    pub source_nonce: [u8; NONCE_LEN],
}

/// Paquete cifrado con AEAD conteniendo los datos migrados de la wallet del titular.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationEncryptedPackage {
    /// Identificador de sesión.
    pub target_id: [u8; SESSION_ID_LEN],
    /// Contenido cifrado y autenticado (`ciphertext || tag` de Poly1305).
    pub encrypted_data: Vec<u8>,
}

/// Acuse final de migración exitosa emitido por el nuevo dispositivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCompleteAck {
    /// Identificador de sesión completado.
    pub target_id: [u8; SESSION_ID_LEN],
    /// Indicador de éxito.
    pub accepted: bool,
}

/// Registro de una re-vinculación encolada para ser ejecutada ante un emisor en el nuevo hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRebinding {
    /// Identificador URI del emisor de la credencial.
    pub issuer_uri: String,
    /// Identificador local único de la credencial en la wallet.
    pub credential_id: String,
    /// Tipo de credencial verificable (`vct`).
    pub vct: String,
}

/// Resultado entregado al nuevo dispositivo tras descifrar con éxito la migración.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCompletedResult {
    /// Bóveda de respaldo restaurada con el secreto maestro de recuperación y credenciales.
    pub restored_payload: BackupPayload,
    /// Solicitudes de re-vinculación encoladas para el nuevo hardware ante cada emisor (`REQ-REC-001`, `ADR-0029`).
    pub queued_rebindings: Vec<PendingRebinding>,
}

/// Calcula el compromiso canónico previo según `SPEC-PIP-MIGRATE-001`.
///
/// Preimagen: `"pip-migrate-commit-v1:" || target_id_hex || ":" || target_nonce_hex || ":" || source_nonce_hex || ":" || source_pub_hex`
#[must_use]
pub fn compute_commitment(
    target_id: &[u8; SESSION_ID_LEN],
    target_nonce: &[u8; NONCE_LEN],
    source_nonce: &[u8; NONCE_LEN],
    source_pub: &[u8; SEC1_PUBKEY_LEN],
) -> [u8; COMMITMENT_LEN] {
    let preimage = format!(
        "{MIGRATION_COMMITMENT_PREFIX}{}:{}:{}:{}",
        encode_hex(target_id),
        encode_hex(target_nonce),
        encode_hex(source_nonce),
        encode_hex(source_pub)
    );
    sha256(preimage.as_bytes())
}

/// Calcula la cadena canónica del transcrito SAS según `SPEC-PIP-MIGRATE-001`.
///
/// Transcrito: `"pip-migrate-sas-v1:" || target_id_hex || ":" || source_pub_hex || ":" || target_pub_hex || ":" || source_nonce_hex || ":" || target_nonce_hex`
#[must_use]
pub fn compute_transcript(
    target_id: &[u8; SESSION_ID_LEN],
    source_pub: &[u8; SEC1_PUBKEY_LEN],
    target_pub: &[u8; SEC1_PUBKEY_LEN],
    source_nonce: &[u8; NONCE_LEN],
    target_nonce: &[u8; NONCE_LEN],
) -> String {
    format!(
        "{MIGRATION_SAS_PREFIX}{}:{}:{}:{}:{}",
        encode_hex(target_id),
        encode_hex(source_pub),
        encode_hex(target_pub),
        encode_hex(source_nonce),
        encode_hex(target_nonce)
    )
}

fn derive_sas_and_session_keys(
    shared_secret: &[u8; 32],
    transcript: &str,
) -> Result<(SasCode, [u8; 32], [u8; AEAD_NONCE_LEN]), RecoveryError> {
    let prk = hkdf_extract_sha256(shared_secret, transcript.as_bytes())
        .map_err(|_| RecoveryError::KeyDerivationFailed("HKDF extract falló en migración"))?;

    let sas_bytes_vec = hkdf_expand_sha256(&prk, HKDF_INFO_SAS_CODE, 4)
        .map_err(|_| RecoveryError::KeyDerivationFailed("HKDF expand de SAS falló"))?;
    if sas_bytes_vec.len() != 4 {
        return Err(RecoveryError::KeyDerivationFailed(
            "longitud de SAS errónea",
        ));
    }
    let mut sas_raw = [0u8; 4];
    if let Some(src) = sas_bytes_vec.get(..4) {
        sas_raw.copy_from_slice(src);
    }
    let sas_num = u32::from_be_bytes(sas_raw) % 1_000_000;
    let sas = SasCode::new(sas_num);

    let key_vec = hkdf_expand_sha256(&prk, HKDF_INFO_SESSION_KEY, 32)
        .map_err(|_| RecoveryError::KeyDerivationFailed("HKDF expand de session key falló"))?;
    if key_vec.len() != 32 {
        return Err(RecoveryError::KeyDerivationFailed(
            "longitud de clave de sesión errónea",
        ));
    }
    let mut session_key = [0u8; 32];
    if let Some(src) = key_vec.get(..32) {
        session_key.copy_from_slice(src);
    }

    let nonce_vec = hkdf_expand_sha256(&prk, HKDF_INFO_SESSION_NONCE, AEAD_NONCE_LEN)
        .map_err(|_| RecoveryError::KeyDerivationFailed("HKDF expand de session nonce falló"))?;
    if nonce_vec.len() != AEAD_NONCE_LEN {
        return Err(RecoveryError::KeyDerivationFailed(
            "longitud de nonce de sesión errónea",
        ));
    }
    let mut session_nonce = [0u8; AEAD_NONCE_LEN];
    if let Some(src) = nonce_vec.get(..AEAD_NONCE_LEN) {
        session_nonce.copy_from_slice(src);
    }

    Ok((sas, session_key, session_nonce))
}

enum TargetStage {
    WaitingForCommitment,
    WaitingForRevelation {
        commitment: [u8; COMMITMENT_LEN],
    },
    SasVerification {
        sas: SasCode,
        session_key: SecretBytes<32>,
        session_nonce: [u8; AEAD_NONCE_LEN],
        transcript_hash: [u8; 32],
    },
    ReadyForData {
        sas: SasCode,
        session_key: SecretBytes<32>,
        session_nonce: [u8; AEAD_NONCE_LEN],
        transcript_hash: [u8; 32],
    },
    Completed,
}

/// Máquina de estados sans-I/O para el dispositivo nuevo (Destino de la migración).
pub struct TargetMigrationMachine {
    target_id: [u8; SESSION_ID_LEN],
    secret_key: SecretKeyBytes,
    public_key: [u8; SEC1_PUBKEY_LEN],
    nonce: [u8; NONCE_LEN],
    stage: TargetStage,
}

impl TargetMigrationMachine {
    /// Devuelve el código SAS si la máquina se encuentra en la etapa de verificación o posterior.
    #[must_use]
    pub fn sas(&self) -> Option<SasCode> {
        match &self.stage {
            TargetStage::SasVerification { sas, .. } | TargetStage::ReadyForData { sas, .. } => {
                Some(*sas)
            }
            _ => None,
        }
    }

    /// Identificador de la sesión de migración.
    #[must_use]
    pub fn target_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.target_id
    }

    /// Clave pública efímera P-256 SEC1 del dispositivo nuevo.
    #[must_use]
    pub fn public_key(&self) -> &[u8; SEC1_PUBKEY_LEN] {
        &self.public_key
    }

    /// Nonce aleatorio del dispositivo nuevo.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }
    /// Inicia la sesión de migración en el nuevo dispositivo generando par efímero P-256 y enganche QR.
    ///
    /// # Errores
    /// [`RecoveryError::InsufficientEntropy`] si la fuente aleatoria no provee suficiente entropía.
    pub fn new(
        rng: &impl Rng,
        clock: &impl Clock,
    ) -> Result<(Self, MigrationEngagement), RecoveryError> {
        let mut target_id = [0u8; SESSION_ID_LEN];
        let id_entropy = rng
            .fill_32_bytes()
            .map_err(|_| RecoveryError::InsufficientEntropy)?;
        if let Some(src) = id_entropy.get(..SESSION_ID_LEN) {
            target_id.copy_from_slice(src);
        }

        let mut nonce = [0u8; NONCE_LEN];
        let nonce_entropy = rng
            .fill_32_bytes()
            .map_err(|_| RecoveryError::InsufficientEntropy)?;
        if let Some(src) = nonce_entropy.get(..NONCE_LEN) {
            nonce.copy_from_slice(src);
        }

        let secret_key = generate_p256_secret_key(rng)
            .map_err(|_| RecoveryError::KeyDerivationFailed("fallo al generar escalar P-256"))?;
        let jwk = public_key_from_secret_key(&secret_key)
            .map_err(|_| RecoveryError::KeyDerivationFailed("fallo al derivar JWK P-256"))?;
        let public_key = jwk.to_sec1_bytes();

        let created_at = UnixTime::from_seconds(clock.now_seconds());

        let engagement = MigrationEngagement {
            target_id,
            target_pub: public_key,
            target_nonce: nonce,
            created_at,
        };

        let machine = Self {
            target_id,
            secret_key,
            public_key,
            nonce,
            stage: TargetStage::WaitingForCommitment,
        };

        Ok((machine, engagement))
    }

    /// Procesa el mensaje de compromiso previo enviado por el dispositivo origen.
    ///
    /// # Errores
    /// - [`RecoveryError::InvalidSessionId`] si el identificador de sesión no coincide.
    /// - [`RecoveryError::InvalidMigrationMessage`] si la máquina no está en estado `WaitingForCommitment`.
    pub fn process_commitment(
        &mut self,
        msg: MigrationCommitment,
    ) -> Result<TargetCommitmentAck, RecoveryError> {
        if msg.target_id != self.target_id {
            return Err(RecoveryError::InvalidSessionId);
        }
        match self.stage {
            TargetStage::WaitingForCommitment => {
                self.stage = TargetStage::WaitingForRevelation {
                    commitment: msg.commitment,
                };
                Ok(TargetCommitmentAck {
                    target_id: self.target_id,
                    accepted: true,
                })
            }
            _ => Err(RecoveryError::InvalidMigrationMessage(
                "mensaje de compromiso recibido en estado inválido",
            )),
        }
    }

    /// Procesa la revelación de la clave efímera del origen, valida el compromiso previo y calcula el código SAS.
    ///
    /// # Errores
    /// - [`RecoveryError::InvalidSessionId`] si `target_id` no coincide.
    /// - [`RecoveryError::CommitmentMismatch`] si el hash de la clave revelada no coincide con el compromiso (fail-closed).
    /// - [`RecoveryError::InvalidMigrationMessage`] si la clave efímera no es un punto válido en P-256.
    pub fn process_revelation(
        &mut self,
        msg: MigrationRevelation,
    ) -> Result<SasCode, RecoveryError> {
        if msg.target_id != self.target_id {
            return Err(RecoveryError::InvalidSessionId);
        }

        let stored_commitment = match self.stage {
            TargetStage::WaitingForRevelation { commitment } => commitment,
            _ => {
                return Err(RecoveryError::InvalidMigrationMessage(
                    "revelación recibida antes del compromiso previo",
                ))
            }
        };

        let expected_commitment = compute_commitment(
            &self.target_id,
            &self.nonce,
            &msg.source_nonce,
            &msg.source_pub,
        );

        if !constant_time_eq(&stored_commitment, &expected_commitment) {
            return Err(RecoveryError::CommitmentMismatch);
        }

        let source_jwk = JwkEcP256::from_sec1_bytes(&msg.source_pub).map_err(|_| {
            RecoveryError::InvalidMigrationMessage("punto de curva elíptica origen inválido")
        })?;

        let shared_secret = ecdh_agree_keys(&self.secret_key, &source_jwk).map_err(|_| {
            RecoveryError::KeyDerivationFailed("acuerdo Diffie-Hellman P-256 falló")
        })?;

        let transcript = compute_transcript(
            &self.target_id,
            &msg.source_pub,
            &self.public_key,
            &msg.source_nonce,
            &self.nonce,
        );

        let (sas, session_key_bytes, session_nonce) =
            derive_sas_and_session_keys(shared_secret.expose_secret(), &transcript)?;
        let transcript_hash = sha256(transcript.as_bytes());

        self.stage = TargetStage::SasVerification {
            sas,
            session_key: SecretBytes::new(session_key_bytes),
            session_nonce,
            transcript_hash,
        };

        Ok(sas)
    }

    /// Confirma interactivamente la verificación visual del código SAS en pantalla.
    ///
    /// # Errores
    /// [`RecoveryError::InvalidMigrationMessage`] si no se encuentra en estado de verificación SAS.
    pub fn confirm_sas(&mut self) -> Result<(), RecoveryError> {
        let (sas, key, nonce, t_hash) = match &self.stage {
            TargetStage::SasVerification {
                sas,
                session_key,
                session_nonce,
                transcript_hash,
            } => (*sas, session_key.clone(), *session_nonce, *transcript_hash),
            _ => {
                return Err(RecoveryError::InvalidMigrationMessage(
                    "no se puede confirmar SAS en la fase actual",
                ))
            }
        };

        self.stage = TargetStage::ReadyForData {
            sas,
            session_key: key,
            session_nonce: nonce,
            transcript_hash: t_hash,
        };

        Ok(())
    }

    /// Recibe y descifra el paquete de datos de migración, restaurando la bóveda y encolando las re-vinculaciones.
    ///
    /// # Errores
    /// - [`RecoveryError::SasNotConfirmed`] si el titular no confirmó interactivamente el código SAS.
    /// - [`RecoveryError::MigrationAeadFailed`] si el tag de autenticación Poly1305 o AAD no coincide.
    /// - [`RecoveryError::DeserializationFailed`] si el contenido no se ajusta al esquema de `BackupPayload`.
    pub fn receive_and_decrypt(
        &mut self,
        package: MigrationEncryptedPackage,
    ) -> Result<(MigrationCompletedResult, MigrationCompleteAck), RecoveryError> {
        if package.target_id != self.target_id {
            return Err(RecoveryError::InvalidSessionId);
        }

        let (session_key, session_nonce, transcript_hash) = match &self.stage {
            TargetStage::ReadyForData {
                session_key,
                session_nonce,
                transcript_hash,
                ..
            } => (session_key.clone(), *session_nonce, *transcript_hash),
            TargetStage::SasVerification { .. } => return Err(RecoveryError::SasNotConfirmed),
            _ => {
                return Err(RecoveryError::InvalidMigrationMessage(
                    "paquete de datos recibido fuera de secuencia",
                ))
            }
        };

        let plaintext = aead_open(
            session_key.expose_secret(),
            &session_nonce,
            &package.encrypted_data,
            &transcript_hash,
        )
        .map_err(|_| RecoveryError::MigrationAeadFailed)?;

        let restored_payload = BackupPayload::from_canonical_json(&plaintext)?;

        let mut queued_rebindings = Vec::with_capacity(restored_payload.credentials.len());
        for cred in &restored_payload.credentials {
            queued_rebindings.push(PendingRebinding {
                issuer_uri: cred.issuer.clone(),
                credential_id: cred.id.clone(),
                vct: cred.vct.clone(),
            });
        }

        self.stage = TargetStage::Completed;

        let result = MigrationCompletedResult {
            restored_payload,
            queued_rebindings,
        };

        let ack = MigrationCompleteAck {
            target_id: self.target_id,
            accepted: true,
        };

        Ok((result, ack))
    }

    /// Indica si el proceso de migración concluyó exitosamente en el nuevo dispositivo.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self.stage, TargetStage::Completed)
    }
}

enum SourceStage {
    WaitingForAck {
        sas: SasCode,
        session_key: SecretBytes<32>,
        session_nonce: [u8; AEAD_NONCE_LEN],
        transcript_hash: [u8; 32],
        revelation: MigrationRevelation,
    },
    SasVerification {
        sas: SasCode,
        session_key: SecretBytes<32>,
        session_nonce: [u8; AEAD_NONCE_LEN],
        transcript_hash: [u8; 32],
    },
    ReadyToTransmit {
        sas: SasCode,
        session_key: SecretBytes<32>,
        session_nonce: [u8; AEAD_NONCE_LEN],
        transcript_hash: [u8; 32],
    },
    WaitingForCompletion,
    Completed,
}

/// Máquina de estados sans-I/O para el dispositivo antiguo (Origen de la migración).
pub struct SourceMigrationMachine {
    target_id: [u8; SESSION_ID_LEN],
    public_key: [u8; SEC1_PUBKEY_LEN],
    nonce: [u8; NONCE_LEN],
    stage: SourceStage,
}

impl SourceMigrationMachine {
    /// Devuelve el código SAS si la máquina se encuentra en la etapa de verificación o posterior.
    #[must_use]
    pub fn sas(&self) -> Option<SasCode> {
        match &self.stage {
            SourceStage::WaitingForAck { sas, .. }
            | SourceStage::SasVerification { sas, .. }
            | SourceStage::ReadyToTransmit { sas, .. } => Some(*sas),
            _ => None,
        }
    }

    /// Identificador de la sesión de migración.
    #[must_use]
    pub fn target_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.target_id
    }

    /// Clave pública efímera P-256 SEC1 del dispositivo origen.
    #[must_use]
    pub fn public_key(&self) -> &[u8; SEC1_PUBKEY_LEN] {
        &self.public_key
    }

    /// Nonce aleatorio del dispositivo origen.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Inicia el proceso de migración desde el enganche escaneado del nuevo dispositivo, emitiendo el compromiso previo.
    ///
    /// # Errores
    /// - [`RecoveryError::InsufficientEntropy`] si la fuente aleatoria falla.
    /// - [`RecoveryError::InvalidMigrationMessage`] si la clave del nuevo dispositivo no es válida en P-256.
    pub fn from_engagement(
        engagement: MigrationEngagement,
        rng: &impl Rng,
    ) -> Result<(Self, MigrationCommitment), RecoveryError> {
        let mut nonce = [0u8; NONCE_LEN];
        let nonce_entropy = rng
            .fill_32_bytes()
            .map_err(|_| RecoveryError::InsufficientEntropy)?;
        if let Some(src) = nonce_entropy.get(..NONCE_LEN) {
            nonce.copy_from_slice(src);
        }

        let secret_key = generate_p256_secret_key(rng)
            .map_err(|_| RecoveryError::KeyDerivationFailed("fallo al generar escalar P-256"))?;
        let jwk = public_key_from_secret_key(&secret_key)
            .map_err(|_| RecoveryError::KeyDerivationFailed("fallo al derivar JWK P-256"))?;
        let public_key = jwk.to_sec1_bytes();

        let commitment_hash = compute_commitment(
            &engagement.target_id,
            &engagement.target_nonce,
            &nonce,
            &public_key,
        );

        let target_jwk = JwkEcP256::from_sec1_bytes(&engagement.target_pub).map_err(|_| {
            RecoveryError::InvalidMigrationMessage("clave pública del nuevo dispositivo no válida")
        })?;

        let shared_secret = ecdh_agree_keys(&secret_key, &target_jwk).map_err(|_| {
            RecoveryError::KeyDerivationFailed("acuerdo Diffie-Hellman P-256 falló")
        })?;

        let transcript = compute_transcript(
            &engagement.target_id,
            &public_key,
            &engagement.target_pub,
            &nonce,
            &engagement.target_nonce,
        );

        let (sas, session_key_bytes, session_nonce) =
            derive_sas_and_session_keys(shared_secret.expose_secret(), &transcript)?;
        let transcript_hash = sha256(transcript.as_bytes());

        let revelation = MigrationRevelation {
            target_id: engagement.target_id,
            source_pub: public_key,
            source_nonce: nonce,
        };

        let machine = Self {
            target_id: engagement.target_id,
            public_key,
            nonce,
            stage: SourceStage::WaitingForAck {
                sas,
                session_key: SecretBytes::new(session_key_bytes),
                session_nonce,
                transcript_hash,
                revelation,
            },
        };

        let commitment_msg = MigrationCommitment {
            target_id: engagement.target_id,
            commitment: commitment_hash,
        };

        Ok((machine, commitment_msg))
    }

    /// Procesa el acuse del compromiso enviado por el nuevo dispositivo y emite la revelación de la clave efímera junto con el SAS.
    ///
    /// # Errores
    /// - [`RecoveryError::InvalidSessionId`] si el `target_id` no coincide.
    /// - [`RecoveryError::InvalidMigrationMessage`] si el nuevo dispositivo rechazó el compromiso o estado inválido.
    pub fn process_ack(
        &mut self,
        ack: TargetCommitmentAck,
    ) -> Result<(MigrationRevelation, SasCode), RecoveryError> {
        if ack.target_id != self.target_id {
            return Err(RecoveryError::InvalidSessionId);
        }
        if !ack.accepted {
            return Err(RecoveryError::InvalidMigrationMessage(
                "el nuevo dispositivo rechazó el compromiso previo",
            ));
        }

        match &self.stage {
            SourceStage::WaitingForAck {
                sas,
                session_key,
                session_nonce,
                transcript_hash,
                revelation,
            } => {
                let rev = revelation.clone();
                let code = *sas;
                self.stage = SourceStage::SasVerification {
                    sas: code,
                    session_key: session_key.clone(),
                    session_nonce: *session_nonce,
                    transcript_hash: *transcript_hash,
                };
                Ok((rev, code))
            }
            _ => Err(RecoveryError::InvalidMigrationMessage(
                "acuse recibido fuera de secuencia",
            )),
        }
    }

    /// Confirma interactivamente la verificación visual del código SAS en pantalla.
    ///
    /// # Errores
    /// [`RecoveryError::InvalidMigrationMessage`] si no se encuentra en estado de verificación SAS.
    pub fn confirm_sas(&mut self) -> Result<(), RecoveryError> {
        let (sas, key, nonce, t_hash) = match &self.stage {
            SourceStage::SasVerification {
                sas,
                session_key,
                session_nonce,
                transcript_hash,
            } => (*sas, session_key.clone(), *session_nonce, *transcript_hash),
            _ => {
                return Err(RecoveryError::InvalidMigrationMessage(
                    "no se puede confirmar SAS en la fase actual",
                ))
            }
        };

        self.stage = SourceStage::ReadyToTransmit {
            sas,
            session_key: key,
            session_nonce: nonce,
            transcript_hash: t_hash,
        };

        Ok(())
    }

    /// Cifra el contenido de la bóveda del titular utilizando la clave derivada autenticada contra el transcrito.
    ///
    /// # Errores
    /// - [`RecoveryError::SasNotConfirmed`] si el titular no confirmó interactivamente el SAS antes de transmitir.
    /// - [`RecoveryError::MigrationAeadFailed`] si el sellado AEAD falla.
    pub fn encrypt_payload(
        &mut self,
        payload: &BackupPayload,
    ) -> Result<MigrationEncryptedPackage, RecoveryError> {
        let (session_key, session_nonce, transcript_hash) = match &self.stage {
            SourceStage::ReadyToTransmit {
                session_key,
                session_nonce,
                transcript_hash,
                ..
            } => (session_key.clone(), *session_nonce, *transcript_hash),
            SourceStage::SasVerification { .. } => return Err(RecoveryError::SasNotConfirmed),
            _ => {
                return Err(RecoveryError::InvalidMigrationMessage(
                    "intento de cifrar en estado no preparado",
                ))
            }
        };

        let plaintext = payload.to_canonical_json()?;
        let encrypted_data = aead_seal(
            session_key.expose_secret(),
            &session_nonce,
            &plaintext,
            &transcript_hash,
        )
        .map_err(|_| RecoveryError::MigrationAeadFailed)?;

        self.stage = SourceStage::WaitingForCompletion;

        Ok(MigrationEncryptedPackage {
            target_id: self.target_id,
            encrypted_data,
        })
    }

    /// Procesa el acuse final de migración exitosa emitido por el nuevo dispositivo y finaliza el proceso.
    ///
    /// # Errores
    /// - [`RecoveryError::InvalidSessionId`] si el identificador de sesión no coincide.
    /// - [`RecoveryError::InvalidMigrationMessage`] si el nuevo dispositivo reportó fallo en la migración.
    pub fn process_complete_ack(&mut self, ack: MigrationCompleteAck) -> Result<(), RecoveryError> {
        if ack.target_id != self.target_id {
            return Err(RecoveryError::InvalidSessionId);
        }
        if !ack.accepted {
            return Err(RecoveryError::InvalidMigrationMessage(
                "el nuevo dispositivo reportó fallo al completar la migración",
            ));
        }

        match self.stage {
            SourceStage::WaitingForCompletion => {
                self.stage = SourceStage::Completed;
                Ok(())
            }
            _ => Err(RecoveryError::InvalidMigrationMessage(
                "acuse final recibido fuera de secuencia",
            )),
        }
    }

    /// Indica si el proceso de migración concluyó exitosamente en el dispositivo antiguo.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self.stage, SourceStage::Completed)
    }
}
