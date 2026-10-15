#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Pruebas de integración de la política de verificación (F4.T05).
//!
//! Trazabilidad:
//! - **REQ-VER-005:** la tolerancia de reloj es configurable y está acotada por el perfil.
//! - **REQ-VER-007:** el núcleo no decide la aceptación; la `Policy` la expresa y el
//!   integrador la configura.
//! - **REQ-STAT-004:** frescura máxima de estado por perfil y clase de operación.
//! - **INV-08:** `none` nunca es admitido, ni por configuración.

extern crate alloc;

use gravital_id_types::{ErrorCode, ProfileId, Vct};
use gravital_id_verifier::{
    IssuerSelection, OperationClass, StatusFreshness, VctSelection, VerificationPolicy,
};

// Verifies: REQ-VER-005
#[test]
fn clock_skew_is_configurable_but_bounded_by_the_profile() {
    // Configuración válida dentro de la cota por defecto (300 s).
    let policy = VerificationPolicy::default()
        .with_clock_skew_seconds(180)
        .expect("sesgo configurable");
    assert_eq!(policy.clock_skew_seconds(), 180);

    // El integrador puede endurecer la cota para su operación, pero no por debajo del
    // sesgo que ya tiene configurado.
    let error = policy
        .clone()
        .with_max_clock_skew_seconds(120)
        .expect_err("la cota no puede bajar del sesgo ya fijado");
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);

    // Con un sesgo pequeño sí caben cotas más estrictas.
    let strict = VerificationPolicy::default()
        .with_clock_skew_seconds(20)
        .expect("sesgo pequeño")
        .with_max_clock_skew_seconds(30)
        .expect("cota más estricta");
    let error = strict.clone().with_clock_skew_seconds(60).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);
    assert!(strict.admits_status_age(OperationClass::Transaction, 0));
}

// Verifies: REQ-STAT-004
#[test]
fn status_freshness_follows_the_operation_class() {
    let policy = VerificationPolicy::default()
        .with_status_freshness(OperationClass::Transaction, StatusFreshness::new(300))
        .with_status_freshness(OperationClass::Query, StatusFreshness::new(86_400));

    // Una transacción con estado de 10 minutos se rechaza; una consulta lo admite.
    assert!(!policy.admits_status_age(OperationClass::Transaction, 600));
    assert!(policy.admits_status_age(OperationClass::Query, 600));
    assert!(policy.admits_status_age(OperationClass::Transaction, 299));
}

// Verifies: REQ-VER-007
#[test]
fn policy_expresses_acceptance_without_the_core_deciding() {
    let policy = VerificationPolicy::default()
        .with_issuers(IssuerSelection::AllowList(vec![
            "https://issuer.cedula.example.gov".to_string(),
        ]))
        .with_vcts(VctSelection::AllowList(vec![
            "https://credentials.gravital.io/vct/personal/id-v1".to_string(),
        ]))
        .with_profiles(vec![ProfileId::parse(ProfileId::PERSONAL_V1).unwrap()]);

    // El núcleo solo informa de lo configurado; la decisión es del integrador.
    assert!(policy.admits_issuer("https://issuer.cedula.example.gov"));
    assert!(!policy.admits_issuer("https://otro.example.gov"));
    assert!(policy
        .admits_vct(&Vct::parse("https://credentials.gravital.io/vct/personal/id-v1").unwrap()));
    assert!(!policy
        .admits_vct(&Vct::parse("https://credentials.gravital.io/vct/financial/kyc-v1").unwrap()));
    assert_eq!(policy.profiles().len(), 1);
    policy.validate().expect("política coherente");
}

// Verifies: INV-08, REQ-CRED-008
#[test]
fn alg_none_is_never_admitted_even_if_configured() {
    let error = VerificationPolicy::default()
        .with_allowed_algorithms(vec!["ES256".to_string(), "none".to_string()])
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedAlgorithm);
    assert!(error.message.contains("none"));
}

// Verifies: REQ-VER-005, INV-05
#[test]
fn incoherent_policies_are_rejected() {
    // Sesgo por encima del límite duro del perfil.
    let mut policy = VerificationPolicy::default();
    policy = policy.with_max_clock_skew_seconds(300).unwrap();
    let error = policy.clone().with_clock_skew_seconds(301).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);

    // Cota dura por encima del límite duro global.
    let error = VerificationPolicy::default()
        .with_max_clock_skew_seconds(600)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedSdJwt);
}

// Verifies: REQ-STAT-004
#[test]
fn per_profile_freshness_defaults_match_the_specifications() {
    let policy = VerificationPolicy::default();
    assert_eq!(
        policy
            .status_freshness(OperationClass::Transaction)
            .max_age_seconds,
        30 * 60,
        "el perfil financiero exige 30 minutos para transacciones"
    );
    assert_eq!(
        policy
            .status_freshness(OperationClass::Query)
            .max_age_seconds,
        4 * 60 * 60,
        "y 4 horas para consultas"
    );
    assert_eq!(
        policy
            .status_freshness(OperationClass::Default)
            .max_age_seconds,
        7 * 24 * 60 * 60,
        "el perfil personal admite 7 días"
    );
}
