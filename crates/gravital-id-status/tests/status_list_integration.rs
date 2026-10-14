#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de `gravital-id-status` (F4.T01).
//!
//! Trazabilidad:
//! - **REQ-STAT-001:** Token Status List en formato JWT con `typ: statuslist+jwt`.
//! - **REQ-STAT-003:** descompresión acotada (2 MiB / ratio 10:1) y `adler32`.
//! - **REQ-STAT-007:** estados válido, revocado y suspendido.
//! - **REQ-STAT-008:** manifiesto firmado con versión monotónica por emisor (ADR-0017).
//! - **REQ-VER-003:** fail-closed ante cualquier incoherencia.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use gravital_id_codec::base64url;
use gravital_id_codec::deflate::deflate;
use gravital_id_codec::json::{Number, Value};
use gravital_id_crypto::sha256;
use gravital_id_keys::{IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_status::{
    IssuerStatusManifest, StatusListVerifier, StatusManifestVerifier, TokenStatus,
};
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime};

const NOW: UnixTime = UnixTime::from_seconds(1_769_849_600); // 2026-01-01
const LIST_URI: &str = "https://status.cedula.example.gov/lists/2026.jwt";

/// Empaqueta estados en el contenido comprimido de una `lst`.
fn pack_lst(bits: u8, values: &[u32]) -> String {
    let mut bytes = Vec::new();
    let mut current: u8 = 0;
    let mut used = 0u32;
    for value in values {
        for shift in (0..bits).rev() {
            let bit = (value >> shift) & 0b1;
            current = (current << 1) | (bit as u8);
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
    base64url::encode(&deflate(&bytes))
}

/// Firma un JWT ES256 con la clave del emisor y devuelve la serialización compacta.
fn sign_jwt<S: KeyStore>(
    store: &S,
    handle: &gravital_id_keys::KeyHandle<IssuerSigning>,
    header_json: &str,
    payload_json: &str,
) -> String {
    let signing_input = format!(
        "{}.{}",
        base64url::encode(header_json.as_bytes()),
        base64url::encode(payload_json.as_bytes())
    );
    let digest = sha256(signing_input.as_bytes());
    let signature = store.sign(handle, &digest).expect("sign");
    format!("{signing_input}.{}", base64url::encode(&signature))
}

fn status_list_header() -> &'static str {
    r#"{"alg":"ES256","typ":"statuslist+jwt"}"#
}

fn manifest_header() -> &'static str {
    r#"{"alg":"ES256","typ":"status-manifest+jwt"}"#
}

/// Construye el payload JSON de una lista de estado.
fn status_list_payload(bits: u8, values: &[u32], extra_root: &str) -> String {
    format!(
        r#"{{"exp":{},"iat":{},"iss":"https://issuer.cedula.example.gov","status_list":{{"bits":{},"lst":"{}","uri":"{}"}}{}}}"#,
        NOW.as_seconds().saturating_add(86_400),
        NOW.as_seconds(),
        bits,
        pack_lst(bits, values),
        LIST_URI,
        extra_root
    )
}

/// Construye el payload JSON de un manifiesto de estado.
fn manifest_payload(version: u64, uri: &str, sha256_hex: &str) -> String {
    format!(
        r#"{{"issuer_id":"iss-cedula","issued_at":{},"manifest_version":{},"status_lists":[{{"sha256":"{}","status_list_id":"sl-2026-1","type":"TokenStatusList","uri":"{}","valid_until":{}}}],"valid_until":{}}}"#,
        NOW.as_seconds(),
        version,
        sha256_hex,
        uri,
        NOW.as_seconds().saturating_add(86_400),
        NOW.as_seconds().saturating_add(86_400)
    )
}

/// Suite: emisor con su clave de firma y su clave de estado.
struct Fixture {
    store: SoftwareKeyStore<SeededRng>,
}

impl Fixture {
    fn new(seed: u64) -> Self {
        Self {
            store: SoftwareKeyStore::new(SeededRng::new(seed)),
        }
    }
}

// Verifies: REQ-STAT-001, REQ-STAT-007
#[test]
fn one_bit_status_list_round_trip() {
    let mut fixture = Fixture::new(8_001);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");
    let jwk = fixture.store.public_key(&handle).expect("jwk");

    let jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(1, &[0, 1, 0, 0], ""),
    );

    let list = StatusListVerifier::parse(&jwt).expect("parse");
    assert_eq!(list.bits_per_entry(), 1);
    assert_eq!(list.uri(), Some(LIST_URI));
    assert_eq!(list.status_of(0).unwrap(), TokenStatus::Valid);
    assert_eq!(list.status_of(1).unwrap(), TokenStatus::Revoked);
    assert_eq!(list.status_of(2).unwrap(), TokenStatus::Valid);

    StatusListVerifier::verify_signature(&jwt, &jwk).expect("firma válida");
    list.check_uri(LIST_URI).expect("uri coincide");
    list.check_freshness(NOW).expect("lista vigente");
}

// Verifies: REQ-STAT-001, REQ-STAT-007
#[test]
fn two_bit_status_list_reports_suspended() {
    let mut fixture = Fixture::new(8_002);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");
    let jwk = fixture.store.public_key(&handle).expect("jwk");

    let jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(2, &[0, 1, 2, 0, 2], ""),
    );

    let list = StatusListVerifier::parse(&jwt).expect("parse");
    assert_eq!(list.bits_per_entry(), 2);
    assert_eq!(list.status_of(0).unwrap(), TokenStatus::Valid);
    assert_eq!(list.status_of(1).unwrap(), TokenStatus::Revoked);
    assert_eq!(list.status_of(2).unwrap(), TokenStatus::Suspended);
    assert_eq!(list.status_of(4).unwrap(), TokenStatus::Suspended);

    StatusListVerifier::verify_signature(&jwt, &jwk).expect("firma válida");
}

// Verifies: REQ-STAT-003, REQ-VER-003
#[test]
fn decompression_bomb_and_tampered_digest_are_rejected() {
    let mut fixture = Fixture::new(8_003);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");

    // Bomba de descompresión: 8 KiB de ceros comprimen muy por debajo del ratio admitido.
    let bomb = alloc::vec![0u8; 8 * 1024];
    let payload = format!(
        r#"{{"status_list":{{"bits":1,"lst":"{}"}}}}"#,
        base64url::encode(&deflate(&bomb))
    );
    let jwt = sign_jwt(&fixture.store, &handle, status_list_header(), &payload);
    let error = StatusListVerifier::parse(&jwt).expect_err("bomba rechazada");
    assert_eq!(error.code, ErrorCode::MalformedStatusList);
    assert!(error.message.contains("decompression"));

    // Una lista válida firmada con otra clave no verifica.
    let good = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(1, &[0, 1], ""),
    );
    let mut other = Fixture::new(8_004);
    let other_handle = other.store.generate_key::<IssuerSigning>().expect("key");
    let other_jwk = other.store.public_key(&other_handle).expect("jwk");
    let _ = other_handle;

    let error =
        StatusListVerifier::verify_signature(&good, &other_jwk).expect_err("clave distinta");
    assert_eq!(error.code, ErrorCode::InvalidSignature);
}

// Verifies: REQ-STAT-008
#[test]
fn issuer_status_manifest_round_trip_and_anti_rollback() {
    let mut fixture = Fixture::new(8_005);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");
    let jwk = fixture.store.public_key(&handle).expect("jwk");

    // El hash de la lista que publica el emisor.
    let list_jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(1, &[0, 1, 1], ""),
    );
    let digest: String = sha256(list_jwt.as_bytes())
        .iter()
        .fold(String::new(), |mut acc, byte| {
            use core::fmt::Write;
            let _ = write!(acc, "{byte:02x}");
            acc
        });

    let manifest = sign_jwt(
        &fixture.store,
        &handle,
        manifest_header(),
        &manifest_payload(845, LIST_URI, &digest),
    );

    let parsed: IssuerStatusManifest = StatusManifestVerifier::parse(&manifest).expect("parse");
    assert_eq!(parsed.issuer_id(), "iss-cedula");
    assert_eq!(parsed.manifest_version(), 845);
    assert_eq!(parsed.lists().len(), 1);

    // Firma, frescura y anti-rollback.
    StatusManifestVerifier::verify_signature(&manifest, &jwk).expect("firma válida");
    parsed.check_freshness(NOW).expect("manifiesto vigente");
    parsed
        .check_monotonic_version(Some(844))
        .expect("versión nueva");

    // Integridad de lista: el hash descargado debe coincidir con el firmado.
    StatusManifestVerifier::check_list_digest(&parsed, LIST_URI, &digest).expect("hash coincide");
    let error = StatusManifestVerifier::check_list_digest(&parsed, LIST_URI, &"0".repeat(64))
        .expect_err("hash distinto");
    assert_eq!(error.code, ErrorCode::StatusManifestMismatch);

    // Un manifiesto con la misma versión se rechaza (INV-05).
    let stale = sign_jwt(
        &fixture.store,
        &handle,
        manifest_header(),
        &manifest_payload(845, LIST_URI, &digest),
    );
    let stale_parsed = StatusManifestVerifier::parse(&stale).expect("parse");
    let error = stale_parsed
        .check_monotonic_version(Some(845))
        .expect_err("versión repetida");
    assert_eq!(error.code, ErrorCode::MalformedStatusList);
}

// Verifies: REQ-STAT-003, REQ-VER-008
#[test]
fn out_of_range_index_and_uri_mismatch_are_rejected() {
    let mut fixture = Fixture::new(8_006);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");

    let list_jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(1, &[0, 1], ""),
    );
    let list = StatusListVerifier::parse(&list_jwt).expect("parse");

    // Índice más allá de la capacidad de la lista.
    let error = list.status_of(1_000).expect_err("fuera de rango");
    assert_eq!(error.code, ErrorCode::StatusIndexOutOfRange);

    // La URI de la credencial no coincide con la de la lista.
    let error = list
        .check_uri("https://status.otro.example.gov/lists/2026.jwt")
        .expect_err("uri distinta");
    assert_eq!(error.code, ErrorCode::MalformedStatusList);
}

// Verifies: REQ-STAT-004, REQ-STAT-008
#[test]
fn expired_list_and_manifest_are_rejected() {
    let mut fixture = Fixture::new(8_007);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");

    // Lista ya caducada.
    let payload = r#"{"exp":1700000000,"iat":1699990000,"iss":"https://issuer.cedula.example.gov","status_list":{"bits":1,"lst":"eN7"}}"#.replace(
        "eN7",
        &pack_lst(1, &[0]),
    );
    let jwt = sign_jwt(&fixture.store, &handle, status_list_header(), &payload);
    let list = StatusListVerifier::parse(&jwt).expect("parse");
    let error = list.check_freshness(NOW).expect_err("lista caducada");
    assert_eq!(error.code, ErrorCode::StatusListExpired);

    // Manifiesto caducado.
    let manifest_payload = format!(
        r#"{{"issuer_id":"iss-cedula","issued_at":1699990000,"manifest_version":1,"status_lists":[{{"sha256":"{}","status_list_id":"sl-1","type":"TokenStatusList","uri":"{}"}}],"valid_until":1700000000}}"#,
        "a".repeat(64),
        LIST_URI
    );
    let manifest = sign_jwt(
        &fixture.store,
        &handle,
        manifest_header(),
        &manifest_payload,
    );
    let parsed = StatusManifestVerifier::parse(&manifest).expect("parse");
    let error = parsed
        .check_freshness(NOW)
        .expect_err("manifiesto caducado");
    assert_eq!(error.code, ErrorCode::StatusListExpired);
}

// Verifies: REQ-STAT-001
#[test]
fn forbidden_status_list_headers_are_rejected() {
    let mut fixture = Fixture::new(8_008);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");

    // typ incorrecto.
    let jwt = sign_jwt(
        &fixture.store,
        &handle,
        r#"{"alg":"ES256","typ":"jwt"}"#,
        &status_list_payload(1, &[0], ""),
    );
    let error = StatusListVerifier::parse(&jwt).expect_err("typ inválido");
    assert_eq!(error.code, ErrorCode::MalformedStatusList);

    // alg: none.
    let jwt = sign_jwt(
        &fixture.store,
        &handle,
        r#"{"alg":"none","typ":"statuslist+jwt"}"#,
        &status_list_payload(1, &[0], ""),
    );
    let error = StatusListVerifier::parse(&jwt).expect_err("alg none");
    assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);

    // Sin el claim status_list.
    let jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        r#"{"iss":"https://issuer.example.gov"}"#,
    );
    let error = StatusListVerifier::parse(&jwt).expect_err("sin status_list");
    assert_eq!(error.code, ErrorCode::MalformedStatusList);
}

// Verifies: REQ-VER-009
#[test]
fn status_list_parsing_is_deterministic() {
    let mut fixture = Fixture::new(8_009);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");
    let jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(2, &[0, 1, 2], ""),
    );

    let first = StatusListVerifier::parse(&jwt).expect("parse");
    let second = StatusListVerifier::parse(&jwt).expect("parse");
    assert_eq!(first.status_of(1).unwrap(), second.status_of(1).unwrap());
    assert_eq!(first.entry_count(), second.entry_count());
    assert_eq!(first.status_of(2).unwrap(), TokenStatus::Suspended);
    let _ = Value::Number(Number::PosInt(0));
}

// Verifies: REQ-STAT-004, INV-11
#[test]
fn cache_and_snapshot_use_the_injected_clock() {
    use gravital_id_status::{FreshnessPolicy, StatusCache, StatusSnapshot};
    use gravital_id_types::Clock;

    // Reloj inyectado por el host: el núcleo nunca lee el reloj del sistema.
    struct TestClock(u64);
    impl Clock for TestClock {
        fn now_seconds(&self) -> u64 {
            self.0
        }
        fn monotonic_elapsed_millis(&self) -> Option<u64> {
            None
        }
    }

    let mut fixture = Fixture::new(8_100);
    let handle = fixture.store.generate_key::<IssuerSigning>().expect("key");
    let list_jwt = sign_jwt(
        &fixture.store,
        &handle,
        status_list_header(),
        &status_list_payload(2, &[0, 1, 2], ""),
    );
    let list = gravital_id_status::StatusListVerifier::parse(&list_jwt).expect("parse");

    let clock = TestClock(NOW.as_seconds());
    let snapshot = StatusSnapshot::new(
        list.clone(),
        LIST_URI,
        UnixTime::from_seconds(clock.now_seconds()),
    );

    // Antigüedad calculada contra el reloj inyectado.
    let later = TestClock(NOW.as_seconds().saturating_add(4 * 60 * 60));
    assert_eq!(
        snapshot.age_seconds(UnixTime::from_seconds(later.now_seconds())),
        4 * 60 * 60
    );

    // Política de consulta del perfil financiero: 4 horas exactas.
    snapshot
        .check_freshness(
            UnixTime::from_seconds(later.now_seconds()),
            &FreshnessPolicy::FINANCIAL_QUERY,
        )
        .expect("consulta dentro de la frescura");

    // Política de transacción: 30 minutos, así que caduca.
    let error = snapshot
        .check_freshness(
            UnixTime::from_seconds(later.now_seconds()),
            &FreshnessPolicy::FINANCIAL_TRANSACTION,
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::StatusListExpired);

    // La caché solo devuelve el snapshot fresco y conserva la semántica de estados.
    let mut cache = StatusCache::default();
    cache.insert(snapshot);
    let fresh = cache
        .fresh(
            LIST_URI,
            UnixTime::from_seconds(later.now_seconds()),
            &FreshnessPolicy::FINANCIAL_QUERY,
        )
        .expect("snapshot fresco");
    assert_eq!(
        fresh.list().status_of(2).unwrap(),
        gravital_id_status::TokenStatus::Suspended
    );

    // Tras refrescar la lista (nuevo snapshot con el reloj actual), vuelve a estar fresca
    // incluso con la política de transacción.
    let refreshed =
        StatusSnapshot::new(list, LIST_URI, UnixTime::from_seconds(later.now_seconds()));
    cache.insert(refreshed);
    cache
        .fresh(
            LIST_URI,
            UnixTime::from_seconds(later.now_seconds()),
            &FreshnessPolicy::FINANCIAL_TRANSACTION,
        )
        .expect("snapshot recién refrescado");
}
