//! Pruebas complementarias de cobertura para gravital-id-holder (F5.T07, F5.T08).
//!
//! Cubre ramas de error, límites de validación, roundtrips JSON y variantes de auditoría.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use gravital_id_crypto::secret::SecretBytes;
use gravital_id_holder::{
    AuditEventType, CredentialId, CredentialQuery, DcqlQuery, HolderWallet, RequestedClaim,
    WalletAuditEvent, WalletCredential,
};
use gravital_id_storage::InMemoryStorageBackend;
use gravital_id_testkit::SeededRng;
use gravital_id_types::{ErrorCode, UnixTime, Vct};

#[test]
fn credential_id_validation_and_display() {
    assert!(CredentialId::new("").is_err());
    let too_long = "a".repeat(129);
    assert!(CredentialId::new(too_long).is_err());
    assert!(CredentialId::new("id with spaces").is_err());
    assert!(CredentialId::new("id/with/slashes").is_err());

    let valid = CredentialId::new("cred-123_abc.xyz:42").expect("valid id");
    assert_eq!(valid.as_str(), "cred-123_abc.xyz:42");
    assert_eq!(format!("{valid}"), "cred-123_abc.xyz:42");
    assert_eq!(
        format!("{valid:?}"),
        "CredentialId(\"cred-123_abc.xyz:42\")"
    );
    assert!(valid.to_record_id().is_ok());
}

#[test]
fn credential_query_validation_bounds() {
    let vct = Vct::parse("https://credentials.example.com/v1").expect("vct");

    // ID vacío o demasiado largo
    assert!(CredentialQuery::new("", vec![vct.clone()], vec![]).is_err());
    let long_id = "a".repeat(33);
    assert!(CredentialQuery::new(long_id, vec![vct.clone()], vec![]).is_err());

    // vct_values vacío o > 4
    assert!(CredentialQuery::new("q1", vec![], vec![]).is_err());
    let many_vcts = vec![
        vct.clone(),
        vct.clone(),
        vct.clone(),
        vct.clone(),
        vct.clone(),
    ];
    assert!(CredentialQuery::new("q1", many_vcts, vec![]).is_err());

    // claims > 32
    let mut many_claims = Vec::new();
    for i in 0..33 {
        many_claims.push(RequestedClaim::optional(format!("claim_{i}")));
    }
    assert!(CredentialQuery::new("q1", vec![vct.clone()], many_claims).is_err());

    // matches_vct
    let q = CredentialQuery::new("q1", vec![vct.clone()], vec![]).expect("valid query");
    assert!(q.matches_vct(&vct));
    let other_vct = Vct::parse("https://credentials.other.com/v2").expect("other vct");
    assert!(!q.matches_vct(&other_vct));
}

#[test]
fn dcql_query_validation_and_malformed_json() {
    let vct = Vct::parse("https://credentials.example.com/v1").expect("vct");
    let cq = CredentialQuery::new("q1", vec![vct], vec![]).expect("cq");

    // new con credenciales vacías o > 4
    assert!(DcqlQuery::new(vec![]).is_err());
    let too_many = vec![cq.clone(), cq.clone(), cq.clone(), cq.clone(), cq];
    assert!(DcqlQuery::new(too_many).is_err());

    // JSON no objeto
    assert!(DcqlQuery::from_json_bytes(b"[]").is_err());
    assert!(DcqlQuery::from_json_bytes(b"\"not object\"").is_err());

    // JSON sin array credentials
    assert!(DcqlQuery::from_json_bytes(b"{}").is_err());
    assert!(DcqlQuery::from_json_bytes(b"{\"credentials\": 123}").is_err());

    // credentials vacío o > 4
    assert!(DcqlQuery::from_json_bytes(b"{\"credentials\": []}").is_err());

    // elemento dentro de credentials no objeto
    assert!(DcqlQuery::from_json_bytes(b"{\"credentials\": [123]}").is_err());

    // falta id en consulta de credencial
    assert!(DcqlQuery::from_json_bytes(br#"{"credentials": [{"format": "dc+sd-jwt"}]}"#).is_err());
}

#[test]
fn wallet_audit_events_roundtrip_all_variants() {
    let t = UnixTime::from_seconds(1700000000);
    let vct = Vct::parse("https://credentials.example.com/id").expect("vct");

    let events = vec![
        WalletAuditEvent::new(
            "evt-1",
            t,
            AuditEventType::CredentialImported { vct: vct.clone() },
        ),
        WalletAuditEvent::new(
            "evt-2",
            t,
            AuditEventType::CredentialDeleted {
                credential_id: "cred-42".to_string(),
            },
        ),
        WalletAuditEvent::new(
            "evt-3",
            t,
            AuditEventType::PresentationCreated {
                vct,
                query_id: "query-abc".to_string(),
            },
        ),
        WalletAuditEvent::new(
            "evt-4",
            t,
            AuditEventType::AuditLogPurged {
                records_removed: 99,
            },
        ),
        WalletAuditEvent::new("evt-5", t, AuditEventType::BatchDeleted { count: 3 }),
        WalletAuditEvent::new(
            "evt-6",
            t,
            AuditEventType::KeyRotated {
                key_id: "key-1".to_string(),
            },
        ),
        WalletAuditEvent::new("evt-7", t, AuditEventType::SyncCompleted),
    ];

    for ev in events {
        let json = ev.to_canonical_json();
        let parsed = WalletAuditEvent::from_json_bytes(json.as_bytes()).expect("reparse event");
        assert_eq!(ev, parsed);
    }

    // Errores al parsear auditoría malformada
    assert!(WalletAuditEvent::from_json_bytes(b"not json").is_err());
    assert!(WalletAuditEvent::from_json_bytes(b"{}").is_err());
    assert!(WalletAuditEvent::from_json_bytes(br#"{"sequence":1,"timestamp":100}"#).is_err());
    assert!(WalletAuditEvent::from_json_bytes(
        br#"{"event_id":"e1","timestamp":100,"event_type":"UnknownType"}"#
    )
    .is_err());
}

#[test]
fn wallet_credential_from_json_bytes_errors() {
    assert!(WalletCredential::from_json_bytes(b"not json").is_err());
    assert!(WalletCredential::from_json_bytes(b"{}").is_err());

    // JSON faltando id
    assert!(WalletCredential::from_json_bytes(br#"{"raw_sd_jwt":"jwt"}"#).is_err());

    // JSON faltando raw_sd_jwt
    assert!(WalletCredential::from_json_bytes(br#"{"id":"c1"}"#).is_err());

    // JSON faltando vct
    assert!(WalletCredential::from_json_bytes(br#"{"id":"c1","raw_sd_jwt":"jwt"}"#).is_err());

    // JSON faltando issuer
    assert!(WalletCredential::from_json_bytes(
        br#"{"id":"c1","raw_sd_jwt":"jwt","vct":"https://example.com/v1"}"#
    )
    .is_err());

    // JSON faltando holder_binding_key_id
    assert!(WalletCredential::from_json_bytes(
        br#"{"id":"c1","raw_sd_jwt":"jwt","vct":"https://example.com/v1","issuer":"https://iss"}"#
    )
    .is_err());

    // JSON faltando holder_jwk
    assert!(WalletCredential::from_json_bytes(
        br#"{"id":"c1","raw_sd_jwt":"jwt","vct":"https://example.com/v1","issuer":"https://iss","holder_binding_key_id":"k1"}"#
    )
    .is_err());

    // JSON faltando issued_at
    assert!(WalletCredential::from_json_bytes(
        br#"{"id":"c1","raw_sd_jwt":"jwt","vct":"https://example.com/v1","issuer":"https://iss","holder_binding_key_id":"k1","holder_jwk":"{}"}"#
    )
    .is_err());
}

#[test]
fn wallet_lookup_and_delete_edge_cases() {
    let storage = InMemoryStorageBackend::new();
    let kek = SecretBytes::new([0x55u8; 32]);
    let rng = SeededRng::new(5555);
    let mut wallet = HolderWallet::new(storage, kek, rng).expect("wallet");

    // Buscar credencial inexistente
    let missing_id = CredentialId::new("cred-non-existent").expect("id");
    assert!(wallet.get_credential(&missing_id).expect("get").is_none());

    // Eliminar credencial inexistente retorna Ok(false)
    let now = UnixTime::from_seconds(1700000000);
    let deleted = wallet
        .delete_credential(&missing_id, now)
        .expect("idempotent delete");
    assert!(!deleted);

    // Listar credenciales cuando está vacía
    let empty_list = wallet.list_credentials().expect("list");
    assert!(empty_list.is_empty());

    // Buscar por VCT en wallet vacía
    let vct = Vct::parse("https://example.com/vct").expect("vct");
    let by_vct = wallet.find_credentials_by_vct(&vct).expect("find by vct");
    assert!(by_vct.is_empty());

    // Preparar disclosure plan en wallet vacía
    let q = CredentialQuery::new("q1", vec![vct], vec![]).expect("query");
    let err_plan = wallet
        .prepare_disclosure_plan(&q, None)
        .expect_err("no credential in wallet");
    assert_eq!(err_plan.code, ErrorCode::RecordNotFound);
}

#[test]
fn dcql_query_direct_vct_values_and_claims_objects() {
    let raw = br#"{
        "credentials": [
            {
                "id": "c1",
                "vct_values": ["https://example.com/id"],
                "claims": [
                    "simple_claim",
                    {"name": "complex_claim", "required": false},
                    {"path": "nested_claim", "required": true}
                ]
            }
        ]
    }"#;
    let dcql = DcqlQuery::from_json_bytes(raw).expect("parse");
    assert_eq!(dcql.credentials.len(), 1);
    assert_eq!(dcql.credentials[0].claims.len(), 3);
    assert_eq!(dcql.credentials[0].claims[0].name, "simple_claim");
    assert!(dcql.credentials[0].claims[0].required);
    assert_eq!(dcql.credentials[0].claims[1].name, "complex_claim");
    assert!(!dcql.credentials[0].claims[1].required);
    assert_eq!(dcql.credentials[0].claims[2].name, "nested_claim");
    assert!(dcql.credentials[0].claims[2].required);
}
