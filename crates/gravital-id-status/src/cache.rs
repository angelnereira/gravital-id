//! Caché y frescura de listas de estado (F4.T02, REQ-STAT-004).
//!
//! El verificador offline no descarga listas en cada comprobación: mantiene un *snapshot*
//! de cada lista con el instante en que la obtuvo y decide la frescura con el `Clock`
//! inyectado. La antigüedad se calcula siempre contra el reloj que pasa el llamador
//! (INV-11), nunca contra el reloj del sistema.
//!
//! Trazabilidad:
//! - **REQ-STAT-004:** la frescura máxima se define por perfil y por clase de operación.
//! - **REQ-STAT-007:** el snapshot preserva la semántica de estados (válido, revocado,
//!   suspendido).
//! - **REQ-VER-003:** un snapshot caducado o incoherente nunca produce aceptación.
//! - **REQ-VER-011:** el estado persistente del verificador se lee y escribe mediante una
//!   interfaz propia; aquí solo vive en memoria (la persistencia llega con
//!   `VerifierStateStore`).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use gravital_id_types::{ErrorCode, GidError, UnixTime};

use crate::status_list::TokenStatusList;

/// Frescura máxima admitida para un snapshot, según perfil y clase de operación.
///
/// Los valores normativos de cada perfil están en `docs/specs/profiles/*.md` §2; el
/// integrador los traslada a esta política.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessPolicy {
    /// Antigüedad máxima del snapshot en segundos.
    pub max_age_seconds: u64,
}

impl FreshnessPolicy {
    /// Política con una antigüedad máxima dada.
    #[must_use]
    pub const fn new(max_age_seconds: u64) -> Self {
        Self { max_age_seconds }
    }

    /// Perfil personal: 7 días (`pip-personal-v1` §2, REQ-STAT-004).
    pub const PERSONAL_V1: Self = Self::new(7 * 24 * 60 * 60);

    /// Perfil financiero, transacciones: 30 minutos (`pip-financial-v1` §2).
    pub const FINANCIAL_TRANSACTION: Self = Self::new(30 * 60);

    /// Perfil financiero, consultas: 4 horas (`pip-financial-v1` §2).
    pub const FINANCIAL_QUERY: Self = Self::new(4 * 60 * 60);

    /// Perfil empresarial: 8 horas (`pip-enterprise-v1` §2).
    pub const ENTERPRISE_V1: Self = Self::new(8 * 60 * 60);

    /// Indica si una antigüedad supera la política.
    #[must_use]
    pub fn is_within(&self, age_seconds: u64) -> bool {
        age_seconds <= self.max_age_seconds
    }
}

/// Snapshot de una lista de estado con el instante en que se obtuvo.
///
/// El instante de obtención lo aporta el `Clock` del host en el momento de almacenar; la
/// antigüedad se recalcula contra el reloj inyectado en cada consulta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    list: TokenStatusList,
    uri: String,
    acquired_at: UnixTime,
}

impl StatusSnapshot {
    /// Crea un snapshot a partir de una lista ya verificada y del instante de obtención.
    #[must_use]
    pub fn new(list: TokenStatusList, uri: impl Into<String>, acquired_at: UnixTime) -> Self {
        Self {
            list,
            uri: uri.into(),
            acquired_at,
        }
    }

    /// Lista de estado contenida en el snapshot.
    #[must_use]
    pub fn list(&self) -> &TokenStatusList {
        &self.list
    }

    /// URI de la lista.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Instante en que se obtuvo la lista (del reloj del host).
    #[must_use]
    pub fn acquired_at(&self) -> UnixTime {
        self.acquired_at
    }

    /// Antigíad del snapshot en segundos respecto al instante dado.
    ///
    /// Un instante anterior al de obtención (reloj atrasado o snapshot restaurado)
    /// devuelve antigíad 0: la comprobación de frescura no puede endurecerse con un
    /// reloj que retrocede, y quien detecta el retroceso es el piso de tiempo confiable
    /// (F4.T04, REQ-VER-006).
    #[must_use]
    pub fn age_seconds(&self, now: UnixTime) -> u64 {
        now.as_seconds()
            .saturating_sub(self.acquired_at.as_seconds())
    }

    /// Indica si el snapshot cumple la política de frescura.
    #[must_use]
    pub fn is_fresh(&self, now: UnixTime, policy: &FreshnessPolicy) -> bool {
        policy.is_within(self.age_seconds(now))
    }

    /// Comprueba la frescura del snapshot y de la lista que contiene.
    ///
    /// # Errores
    /// - [`ErrorCode::StatusListExpired`] si la antigíad supera la política o si la
    ///   propia lista está fuera de su ventana de vigencia.
    /// - [`ErrorCode::CredentialNotYetValid`] si la lista se obtuvo en el futuro.
    pub fn check_freshness(&self, now: UnixTime, policy: &FreshnessPolicy) -> Result<(), GidError> {
        self.list.check_freshness(now)?;

        if now.as_seconds() < self.acquired_at.as_seconds() {
            return Err(GidError::new(
                ErrorCode::CredentialNotYetValid,
                "status snapshot was acquired in the future",
            ));
        }

        let age = self.age_seconds(now);
        if !policy.is_within(age) {
            return Err(GidError::new(
                ErrorCode::StatusListExpired,
                format!(
                    "status snapshot is {age}s old, beyond the {max}s freshness policy",
                    max = policy.max_age_seconds
                ),
            ));
        }
        Ok(())
    }
}

/// Caché en memoria de snapshots de listas de estado (F4.T02).
///
/// Sin red, sin reloj propio y acotada en número de entradas: el verificador offline la
/// usa para no revalidar lo que ya comprobó en esta sesión.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusCache {
    entries: BTreeMap<String, StatusSnapshot>,
    max_entries: usize,
}

/// Número máximo por defecto de listas en caché.
pub const DEFAULT_MAX_CACHED_LISTS: usize = 64;

impl Default for StatusCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CACHED_LISTS)
    }
}

impl StatusCache {
    /// Caché con un número máximo de entradas.
    #[must_use]
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries,
        }
    }

    /// Número máximo de entradas configurado.
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Número de snapshots almacenados.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Indica si la caché está vacía.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Almacena (o reemplaza) el snapshot de una lista.
    ///
    /// Si la caché está llena y la URI es nueva, se expulsa la entrada más antigua
    /// para mantener la cota (REQ-VER-008).
    pub fn insert(&mut self, snapshot: StatusSnapshot) {
        let uri = snapshot.uri().to_string();
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&uri) {
            self.evict_oldest();
        }
        self.entries.insert(uri, snapshot);
    }

    /// Expulsa la entrada con el instante de obtención más antiguo.
    fn evict_oldest(&mut self) {
        if self.max_entries == 0 {
            return;
        }
        let mut oldest: Option<(UnixTime, String)> = None;
        for (uri, snapshot) in self.entries.iter() {
            let candidate = (snapshot.acquired_at(), uri.clone());
            match oldest {
                Some((current, _)) if current <= candidate.0 => {}
                _ => oldest = Some(candidate),
            }
        }
        if let Some((_, uri)) = oldest {
            self.entries.remove(&uri);
        }
    }

    /// Snapshot almacenado para una URI.
    #[must_use]
    pub fn get(&self, uri: &str) -> Option<&StatusSnapshot> {
        self.entries.get(uri)
    }

    /// Snapshot que cumple la política de frescura.
    ///
    /// # Errores
    /// [`ErrorCode::MalformedStatusList`] si no hay snapshot para la URI;
    /// [`ErrorCode::StatusListExpired`] si está caducado.
    pub fn fresh(
        &self,
        uri: &str,
        now: UnixTime,
        policy: &FreshnessPolicy,
    ) -> Result<&StatusSnapshot, GidError> {
        let snapshot = self.get(uri).ok_or_else(|| {
            GidError::new(
                ErrorCode::MalformedStatusList,
                format!("no cached status list for uri '{uri}'"),
            )
        })?;
        snapshot.check_freshness(now, policy)?;
        Ok(snapshot)
    }

    /// URI almacenadas.
    #[must_use]
    pub fn uris(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Elimina el snapshot de una URI.
    pub fn remove(&mut self, uri: &str) -> Option<StatusSnapshot> {
        self.entries.remove(uri)
    }

    /// Vacía la caché.
    pub fn clear(&mut self) {
        self.entries.clear();
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
    use crate::status_list::StatusListVerifier;
    use alloc::vec;
    use gravital_id_codec::base64url;
    use gravital_id_codec::deflate::deflate;
    use gravital_id_codec::json::{Number, Value};

    fn list_with(uri: &str, exp: Option<u64>) -> TokenStatusList {
        let values: [u32; 8] = [0, 1, 0, 0, 0, 0, 0, 0];
        let mut bytes = Vec::new();
        let mut current: u8 = 0;
        let mut used = 0u32;
        for value in values {
            for shift in (0..1u32).rev() {
                current = (current << 1) | ((value >> shift) & 0b1) as u8;
                used = used.saturating_add(1);
                if used % 8 == 0 {
                    bytes.push(current);
                    current = 0;
                }
            }
        }
        if used % 8 != 0 {
            current <<= 8u32.saturating_sub(used % 8);
            bytes.push(current);
        }

        let entries = vec![
            ("bits".to_string(), Value::Number(Number::PosInt(1))),
            (
                "lst".to_string(),
                Value::String(base64url::encode(&deflate(&bytes))),
            ),
            ("uri".to_string(), Value::String(uri.to_string())),
        ];
        // `exp` vive en la raíz del payload, no dentro de `status_list`.
        let mut root = vec![("status_list".to_string(), Value::Object(entries))];
        if let Some(exp) = exp {
            root.push(("exp".to_string(), Value::Number(Number::PosInt(exp))));
        }
        let payload = Value::Object(root);
        StatusListVerifier::from_payload(&payload).expect("list")
    }

    #[test]
    fn snapshot_age_is_computed_with_the_injected_clock() {
        let snapshot = StatusSnapshot::new(
            list_with("https://s.example/l", None),
            "https://s.example/l",
            UnixTime::from_seconds(1_000),
        );
        assert_eq!(snapshot.age_seconds(UnixTime::from_seconds(1_500)), 500);
        // Un reloj atrasado no produce antigíad negativa.
        assert_eq!(snapshot.age_seconds(UnixTime::from_seconds(900)), 0);
    }

    #[test]
    fn freshness_policies_match_the_profile_specifications() {
        assert_eq!(FreshnessPolicy::PERSONAL_V1.max_age_seconds, 604_800);
        assert_eq!(
            FreshnessPolicy::FINANCIAL_TRANSACTION.max_age_seconds,
            1_800
        );
        assert_eq!(FreshnessPolicy::FINANCIAL_QUERY.max_age_seconds, 14_400);
        assert_eq!(FreshnessPolicy::ENTERPRISE_V1.max_age_seconds, 28_800);

        let snapshot = StatusSnapshot::new(
            list_with("https://s.example/l", None),
            "https://s.example/l",
            UnixTime::from_seconds(1_000),
        );
        let now = UnixTime::from_seconds(1_000).saturating_add_seconds(604_801);
        assert!(!snapshot.is_fresh(now, &FreshnessPolicy::PERSONAL_V1));
        let earlier = UnixTime::from_seconds(1_000).saturating_add_seconds(604_800);
        assert!(snapshot.is_fresh(earlier, &FreshnessPolicy::PERSONAL_V1));
    }

    #[test]
    fn expired_list_inside_a_fresh_snapshot_is_rejected() {
        let acquired = UnixTime::from_seconds(1_000);
        let snapshot = StatusSnapshot::new(
            list_with("https://s.example/l", Some(1_500)),
            "https://s.example/l",
            acquired,
        );
        // El snapshot es joven pero la lista ya caducó.
        let error = snapshot
            .check_freshness(UnixTime::from_seconds(1_600), &FreshnessPolicy::PERSONAL_V1)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusListExpired);
    }

    #[test]
    fn cache_evicts_the_oldest_entry_when_full() {
        let mut cache = StatusCache::new(2);
        cache.insert(StatusSnapshot::new(
            list_with("https://a.example/l", None),
            "https://a.example/l",
            UnixTime::from_seconds(10),
        ));
        cache.insert(StatusSnapshot::new(
            list_with("https://b.example/l", None),
            "https://b.example/l",
            UnixTime::from_seconds(20),
        ));
        cache.insert(StatusSnapshot::new(
            list_with("https://c.example/l", None),
            "https://c.example/l",
            UnixTime::from_seconds(30),
        ));

        assert_eq!(cache.len(), 2);
        assert!(
            cache.get("https://a.example/l").is_none(),
            "la más antigua se expulsa"
        );
        assert!(cache.get("https://c.example/l").is_some());
        assert_eq!(cache.uris().len(), 2);
    }

    #[test]
    fn cache_returns_fresh_snapshots_only() {
        let mut cache = StatusCache::default();
        cache.insert(StatusSnapshot::new(
            list_with("https://s.example/l", None),
            "https://s.example/l",
            UnixTime::from_seconds(1_000),
        ));

        let policy = FreshnessPolicy::new(60);
        cache
            .fresh(
                "https://s.example/l",
                UnixTime::from_seconds(1_030),
                &policy,
            )
            .expect("snapshot fresco");
        let error = cache
            .fresh(
                "https://s.example/l",
                UnixTime::from_seconds(1_200),
                &policy,
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StatusListExpired);

        let error = cache
            .fresh(
                "https://desconocida.example/l",
                UnixTime::from_seconds(1_030),
                &policy,
            )
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedStatusList);
    }

    #[test]
    fn snapshot_without_uri_in_list_still_tracks_its_own_uri() {
        let snapshot = StatusSnapshot::new(
            list_with("https://s.example/l", None),
            "https://s.example/l",
            UnixTime::from_seconds(0),
        );
        assert_eq!(snapshot.uri(), "https://s.example/l");
        assert_eq!(snapshot.list().uri(), Some("https://s.example/l"));
    }
}
