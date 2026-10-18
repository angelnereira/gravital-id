//! Publicación de trust bundles en almacenamiento de objetos y CDN (F7.T04, REQ-REL-001, ADR-0013).

use crate::error::TrustServiceError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Registro con las claves y metadatos de un bundle publicado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedBundleRecord {
    /// Clave canónica del bundle vigente (ej. "bundles/current.json").
    pub current_key: String,
    /// Clave versionada inmutable (ej. "bundles/1/42.json").
    pub versioned_key: String,
    /// Clave del digest SHA-256 (ej. "bundles/latest_digest.txt").
    pub digest_key: String,
    /// Timestamp Unix en que se completó la publicación.
    pub published_at: u64,
}

/// Trait abstracto de publicación de artefactos de confianza en almacenamiento de objetos o CDN.
pub trait BundlePublisher: Send + Sync {
    /// Publica el bundle multi-firmado tanto en la ubicación canónica actual como en el archivo versionado.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Storage`] ante fallos de I/O o red.
    fn publish_bundle(
        &self,
        epoch: u64,
        version: u64,
        jws_json: &str,
        digest: &[u8; 32],
        timestamp: u64,
    ) -> Result<PublishedBundleRecord, TrustServiceError>;

    /// Obtiene el contenido de un objeto publicado a partir de su clave/ruta relativa.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Storage`] si la lectura falla.
    fn get_object(&self, key: &str) -> Result<Option<String>, TrustServiceError>;

    /// Obtiene el bundle vigente canónico actual (`bundles/current.json`).
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Storage`] si no existe o la lectura falla.
    fn get_current_bundle(&self) -> Result<String, TrustServiceError> {
        match self.get_object("bundles/current.json")? {
            Some(content) => Ok(content),
            None => Err(TrustServiceError::Storage(
                "Bundle canónico actual no encontrado".to_string(),
            )),
        }
    }

    /// Obtiene una versión específica de un bundle (`bundles/{epoch}/{version}.json`).
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Storage`] si no existe o la lectura falla.
    fn get_bundle_version(&self, epoch: u64, version: u64) -> Result<String, TrustServiceError> {
        let key = format!("bundles/{epoch}/{version}.json");
        match self.get_object(&key)? {
            Some(content) => Ok(content),
            None => Err(TrustServiceError::Storage(format!(
                "Bundle versionado {epoch}/{version} no encontrado"
            ))),
        }
    }

    /// Obtiene el último digest hexadecimal publicado (`bundles/latest_digest.txt`).
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Storage`] si no existe o la lectura falla.
    fn get_latest_digest(&self) -> Result<String, TrustServiceError> {
        match self.get_object("bundles/latest_digest.txt")? {
            Some(content) => Ok(content),
            None => Err(TrustServiceError::Storage(
                "Digest de bundle no encontrado".to_string(),
            )),
        }
    }
}

/// Publicador en memoria sin I/O para pruebas unitarias y de integración.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBundlePublisher {
    objects: Arc<Mutex<BTreeMap<String, String>>>,
}

impl InMemoryBundlePublisher {
    /// Crea una nueva instancia de publicador en memoria.
    #[must_use]
    pub fn new() -> Self {
        Self {
            objects: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Limpia todos los objetos almacenados en memoria.
    pub fn clear(&self) {
        if let Ok(mut g) = self.objects.lock() {
            g.clear();
        }
    }

    /// Retorna una copia de todas las claves almacenadas.
    #[must_use]
    pub fn list_keys(&self) -> Vec<String> {
        self.objects
            .lock()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl BundlePublisher for InMemoryBundlePublisher {
    fn publish_bundle(
        &self,
        epoch: u64,
        version: u64,
        jws_json: &str,
        digest: &[u8; 32],
        timestamp: u64,
    ) -> Result<PublishedBundleRecord, TrustServiceError> {
        let current_key = "bundles/current.json".to_string();
        let versioned_key = format!("bundles/{epoch}/{version}.json");
        let digest_key = "bundles/latest_digest.txt".to_string();
        let digest_hex = pip_indexer::storage::hex_encode(digest);

        let mut lock = self
            .objects
            .lock()
            .map_err(|e| TrustServiceError::Storage(format!("Mutex poisoned: {e}")))?;

        lock.insert(current_key.clone(), jws_json.to_string());
        lock.insert(versioned_key.clone(), jws_json.to_string());
        lock.insert(digest_key.clone(), digest_hex);

        Ok(PublishedBundleRecord {
            current_key,
            versioned_key,
            digest_key,
            published_at: timestamp,
        })
    }

    fn get_object(&self, key: &str) -> Result<Option<String>, TrustServiceError> {
        let lock = self
            .objects
            .lock()
            .map_err(|e| TrustServiceError::Storage(format!("Mutex poisoned: {e}")))?;
        Ok(lock.get(key).cloned())
    }
}

/// Publicador en sistema de archivos local para desarrollo y contenedores de staging.
#[derive(Debug, Clone)]
pub struct FileSystemBundlePublisher {
    root_dir: PathBuf,
}

impl FileSystemBundlePublisher {
    /// Crea un publicador basado en un directorio raíz en disco.
    ///
    /// # Errores
    /// Devuelve [`TrustServiceError::Storage`] si el directorio no puede ser creado.
    pub fn new(root_dir: impl AsRef<Path>) -> Result<Self, TrustServiceError> {
        let path = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&path).map_err(|e| {
            TrustServiceError::Storage(format!("No se pudo crear directorio {path:?}: {e}"))
        })?;
        Ok(Self { root_dir: path })
    }
}

impl BundlePublisher for FileSystemBundlePublisher {
    fn publish_bundle(
        &self,
        epoch: u64,
        version: u64,
        jws_json: &str,
        digest: &[u8; 32],
        timestamp: u64,
    ) -> Result<PublishedBundleRecord, TrustServiceError> {
        let current_rel = "bundles/current.json";
        let versioned_rel = format!("bundles/{epoch}/{version}.json");
        let digest_rel = "bundles/latest_digest.txt";
        let digest_hex = pip_indexer::storage::hex_encode(digest);

        let current_path = self.root_dir.join(current_rel);
        let versioned_path = self.root_dir.join(&versioned_rel);
        let digest_path = self.root_dir.join(digest_rel);

        if let Some(parent) = versioned_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                TrustServiceError::Storage(format!("Error creando subdirectorio de bundle: {e}"))
            })?;
        }

        fs::write(&current_path, jws_json).map_err(|e| {
            TrustServiceError::Storage(format!("Error escribiendo {current_path:?}: {e}"))
        })?;

        fs::write(&versioned_path, jws_json).map_err(|e| {
            TrustServiceError::Storage(format!("Error escribiendo {versioned_path:?}: {e}"))
        })?;

        fs::write(&digest_path, digest_hex).map_err(|e| {
            TrustServiceError::Storage(format!("Error escribiendo {digest_path:?}: {e}"))
        })?;

        Ok(PublishedBundleRecord {
            current_key: current_rel.to_string(),
            versioned_key: versioned_rel,
            digest_key: digest_rel.to_string(),
            published_at: timestamp,
        })
    }

    fn get_object(&self, key: &str) -> Result<Option<String>, TrustServiceError> {
        let path = self.root_dir.join(key);
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)
            .map_err(|e| TrustServiceError::Storage(format!("Error leyendo {path:?}: {e}")))?;
        Ok(Some(content))
    }
}
