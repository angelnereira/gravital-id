//! Pruebas unitarias de almacenamiento y publicación de trust bundles (F7.T04, REQ-TRUST-005).

#![forbid(unsafe_code)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use pip_trust_service::publisher::{
    BundlePublisher, FileSystemBundlePublisher, InMemoryBundlePublisher,
};

#[test]
fn test_in_memory_publisher_lifecycle() {
    let publisher = InMemoryBundlePublisher::new();

    // Sin publicaciones previas
    assert!(publisher.get_current_bundle().is_err());
    assert!(publisher.get_latest_digest().is_err());
    assert!(publisher.get_bundle_version(1, 1).is_err());
    assert!(publisher.list_keys().is_empty());

    let jws_v1 = r#"{"payload":"eyJ0ZXN0IjoxfQ","signatures":[]}"#;
    let digest_v1 = [1u8; 32];
    let timestamp = 1700000000;

    let rec1 = publisher
        .publish_bundle(1, 1, jws_v1, &digest_v1, timestamp)
        .expect("publish v1 ok");
    assert_eq!(rec1.current_key, "bundles/current.json");
    assert_eq!(rec1.versioned_key, "bundles/1/1.json");
    assert_eq!(rec1.digest_key, "bundles/latest_digest.txt");
    assert_eq!(rec1.published_at, timestamp);

    // Serde roundtrip
    let json_rec = serde_json::to_string(&rec1).expect("serialize record");
    let rec_back: pip_trust_service::publisher::PublishedBundleRecord =
        serde_json::from_str(&json_rec).expect("deserialize record");
    assert_eq!(rec1, rec_back);

    // Comprobar lecturas
    let current = publisher.get_current_bundle().expect("get current");
    assert_eq!(current, jws_v1);

    let v1 = publisher.get_bundle_version(1, 1).expect("get v1");
    assert_eq!(v1, jws_v1);

    let digest_str = publisher.get_latest_digest().expect("get digest");
    assert_eq!(digest_str, pip_indexer::storage::hex_encode(&digest_v1));

    let keys = publisher.list_keys();
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&"bundles/current.json".to_string()));
    assert!(keys.contains(&"bundles/1/1.json".to_string()));
    assert!(keys.contains(&"bundles/latest_digest.txt".to_string()));

    // Publicar versión 2
    let jws_v2 = r#"{"payload":"eyJ0ZXN0IjoyfQ","signatures":[]}"#;
    let digest_v2 = [2u8; 32];
    publisher
        .publish_bundle(1, 2, jws_v2, &digest_v2, timestamp + 60)
        .expect("publish v2 ok");

    assert_eq!(publisher.get_current_bundle().unwrap(), jws_v2);
    assert_eq!(publisher.get_bundle_version(1, 1).unwrap(), jws_v1);
    assert_eq!(publisher.get_bundle_version(1, 2).unwrap(), jws_v2);

    // Limpiar
    publisher.clear();
    assert!(publisher.get_current_bundle().is_err());
    assert!(publisher.list_keys().is_empty());
}

#[test]
fn test_filesystem_publisher_lifecycle() {
    let rand_suffix: u64 = 987654321;
    let temp_dir = std::env::temp_dir().join(format!("pip_trust_test_{rand_suffix}"));
    let _ = std::fs::remove_dir_all(&temp_dir);

    let publisher = FileSystemBundlePublisher::new(&temp_dir).expect("create fs publisher");

    let jws = r#"{"payload":"eyJmb3JtYXQiOiJqd3MifQ","signatures":[]}"#;
    let digest = [0xabu8; 32];
    let timestamp = 1710000000;

    let rec = publisher
        .publish_bundle(2, 5, jws, &digest, timestamp)
        .expect("publish ok");
    assert_eq!(rec.current_key, "bundles/current.json");
    assert_eq!(rec.versioned_key, "bundles/2/5.json");
    assert_eq!(rec.digest_key, "bundles/latest_digest.txt");
    assert_eq!(rec.published_at, timestamp);

    // Verificar archivos físicos en disco
    assert!(temp_dir.join("bundles/current.json").exists());
    assert!(temp_dir.join("bundles/2/5.json").exists());
    assert!(temp_dir.join("bundles/latest_digest.txt").exists());

    let current = publisher.get_current_bundle().expect("read current");
    assert_eq!(current, jws);

    let v = publisher
        .get_bundle_version(2, 5)
        .expect("read version 2/5");
    assert_eq!(v, jws);

    let digest_read = publisher.get_latest_digest().expect("read digest");
    assert_eq!(digest_read, pip_indexer::storage::hex_encode(&digest));

    // Version no existente
    assert!(publisher.get_bundle_version(2, 99).is_err());

    // Limpieza
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_filesystem_publisher_errors() {
    assert!(FileSystemBundlePublisher::new("/dev/null/impossible_dir_456").is_err());
}
