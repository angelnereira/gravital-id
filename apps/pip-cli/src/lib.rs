#![forbid(unsafe_code)]
// SAFETY/CLI: Herramienta de línea de comandos de desarrollo que interactúa con el usuario mediante stdout/stderr.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::indexing_slicing
)]

//! `pip-cli` / `gid-cli`: Biblioteca y CLI de desarrollo y verificación offline de Gravital ID (F4.T12).
//!
//! Trazabilidad:
//! - **REQ-VER-001:** La verificación opera completamente offline con bundle y snapshot locales.
//! - **REQ-SDK-008:** Sans-I/O: la CLI orquesta la inyección de datos en memoria para el pipeline.
//! - **INV-01:** Verificación sin red.
//! - **INV-04:** Cuatro estados normativos (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
//! - **INV-05:** Fail-closed determinista.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use gravital_id_codec::base64url;
use gravital_id_codec::deflate::deflate;
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::to_canonical_json;
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::bundle::TrustBundle;
use gravital_id_types::{ErrorCode, GidError, UnixTime};
use gravital_id_verifier::pipeline::{VerificationRequest, VerifierPipeline};
use gravital_id_verifier::policy::{OperationClass, VerificationPolicy};
use gravital_id_verifier::result::{CheckKind, CheckStatus, VerificationStatus};
use gravital_id_verifier::state::{InMemoryStateStore, StateIntegrityKey};

const DEV_INSECURE_WARNING: &str =
    "[DEV-INSECURE] Clave de desarrollo generada con fines de prueba. NO USAR EN PRODUCCIÓN.";

fn gid_err<T>(res: Result<T, GidError>, ctx: &str) -> Result<T> {
    res.map_err(|e| anyhow!("{ctx}: {e}"))
}

/// Muestra la ayuda de uso de la CLI.
pub fn print_usage() {
    println!(
        r#"pip-cli / gid-cli — Herramienta de desarrollo y verificación offline de Gravital ID (F4.T12)

USO:
    pip-cli <SUBCOMANDO> [OPCIONES]

SUBCOMANDOS:
    demo-offline
        Ejecuta una demostración completa y determinista de los 4 estados canónicos de
        verificación (Valid, ValidWithStaleStatus, Unverifiable, Invalid) de forma totalmente
        offline sin I/O de red.

    dev-issuer [--out-jwk <FICHERO>] [--seed <NUM>]
        Genera un par de claves de emisor para desarrollo marcado explícitamente como inseguro.

    dev-bundle --issuer-uri <URI> --jwk <FICHERO> [--kid <KID>] [--out <FICHERO>]
        Construye un trust bundle JSON canónico local conteniendo al emisor de desarrollo.

    dev-status --issuer-uri <URI> --uri <URI> [--bits <1|2>] [--values <V1,V2,...>] [--out <FICHERO>]
        Genera un JWT de StatusList y su snapshot local.

    issue --issuer-uri <URI> --vct <VCT> [--status-uri <URI>] [--status-idx <IDX>] [--exp-seconds <S>] [--out <FICHERO>]
        Emite una credencial SD-JWT VC de prueba.

    verify --presentation <CADENA|FICHERO> --bundle <FICHERO> [--status-snapshot <FICHERO>] [--nonce <NONCE>] [--audience <AUD>] [--now <UNIX_TIME>]
        Verifica una presentación de forma 100% offline contra un trust bundle y snapshot locales.

    help | -h | --help
        Muestra este mensaje de ayuda.
"#
    );
}

/// Punto de entrada principal para `pip-cli` y `gid-cli`.
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args.first().map(|s| s.as_str()) {
        Some("demo-offline") => run_demo_offline()?,
        Some("dev-issuer") => run_dev_issuer(&args[1..])?,
        Some("dev-bundle") => run_dev_bundle(&args[1..])?,
        Some("dev-status") => run_dev_status(&args[1..])?,
        Some("issue") => run_issue(&args[1..])?,
        Some("verify") => run_verify(&args[1..])?,
        Some("help") | Some("-h") | Some("--help") => print_usage(),
        Some(unknown) => {
            eprintln!("Error: Subcomando desconocido '{unknown}'.");
            print_usage();
            std::process::exit(1);
        }
        None => print_usage(),
    }

    Ok(())
}

fn get_arg_val(args: &[String], flag: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(i.saturating_add(1)).cloned();
        }
    }
    None
}

fn run_dev_issuer(args: &[String]) -> Result<()> {
    println!("{DEV_INSECURE_WARNING}");
    let seed: u64 = get_arg_val(args, "--seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xDEAD_BEEF);
    let out_jwk = get_arg_val(args, "--out-jwk");

    let mut store = SoftwareKeyStore::new(SeededRng::new(seed));
    let handle = gid_err(
        store.generate_key::<IssuerSigning>(),
        "error generando clave de emisor",
    )?;
    let jwk = gid_err(
        store.public_key(&handle),
        "error obteniendo clave pública JWK",
    )?;
    let jwk_json = jwk.to_canonical_json();

    if let Some(path) = out_jwk {
        fs::write(&path, jwk_json.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Clave pública JWK guardada en: {path}");
    } else {
        println!("Clave pública JWK del emisor:");
        println!("{jwk_json}");
    }

    Ok(())
}

fn run_dev_bundle(args: &[String]) -> Result<()> {
    let issuer_uri = get_arg_val(args, "--issuer-uri")
        .unwrap_or_else(|| "https://issuer.cedula.example.gov".to_string());
    let kid = get_arg_val(args, "--kid").unwrap_or_else(|| "key-2026-issuer-01".to_string());
    let jwk_file = get_arg_val(args, "--jwk")
        .ok_or_else(|| anyhow!("Falta argumento obligatorio --jwk <FICHERO>"))?;
    let out_path = get_arg_val(args, "--out");

    let jwk_content =
        fs::read_to_string(&jwk_file).with_context(|| format!("error leyendo {jwk_file}"))?;
    let jwk_val = gid_err(
        gravital_id_codec::json::parse(&jwk_content),
        "error parseando JSON de JWK",
    )?;

    let now = get_arg_val(args, "--now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_770_000_000u64);

    let bundle_payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String("pip-global".to_string()),
        ),
        ("bundle_epoch".to_string(), Value::Number(Number::PosInt(1))),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(1)),
        ),
        ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
        (
            "registry_address".to_string(),
            Value::String("0x1234".to_string()),
        ),
        (
            "finalized_block_number".to_string(),
            Value::Number(Number::PosInt(100)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdeadbeef".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(now.saturating_sub(86_400))),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(now.saturating_add(86_400 * 30))),
        ),
        (
            "issuers".to_string(),
            Value::Array(vec![Value::Object(vec![
                ("issuer_id".to_string(), Value::String(issuer_uri)),
                (
                    "profiles".to_string(),
                    Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
                ),
                (
                    "vcts".to_string(),
                    Value::Array(vec![
                        Value::String(
                            "https://credentials.gravital.io/vct/personal/id-v1".to_string(),
                        ),
                        Value::String("https://credentials.gravital.io/vct/custom-v1".to_string()),
                    ]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(now.saturating_sub(86_400))),
                ),
                ("state".to_string(), Value::String("active".to_string())),
                (
                    "keys".to_string(),
                    Value::Array(vec![Value::Object(vec![
                        ("kid".to_string(), Value::String(kid)),
                        ("jwk".to_string(), jwk_val),
                        ("state".to_string(), Value::String("active".to_string())),
                        (
                            "state_since".to_string(),
                            Value::Number(Number::PosInt(now.saturating_sub(86_400))),
                        ),
                    ])]),
                ),
            ])]),
        ),
    ]);

    let bundle_json = to_canonical_json(&bundle_payload);
    if let Some(path) = out_path {
        fs::write(&path, bundle_json.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Trust bundle guardado en: {path}");
    } else {
        println!("{bundle_json}");
    }

    Ok(())
}

fn pack_status_lst(bits: u8, values: &[u32]) -> String {
    let mut bytes = Vec::new();
    let mut current = 0u8;
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

fn run_dev_status(args: &[String]) -> Result<()> {
    let issuer_uri = get_arg_val(args, "--issuer-uri")
        .unwrap_or_else(|| "https://issuer.cedula.example.gov".to_string());
    let list_uri = get_arg_val(args, "--uri")
        .unwrap_or_else(|| "https://status.cedula.example.gov/lists/2026-10".to_string());
    let bits: u8 = get_arg_val(args, "--bits")
        .and_then(|b| b.parse().ok())
        .unwrap_or(2);
    let values_str = get_arg_val(args, "--values").unwrap_or_else(|| "0,0,0,0".to_string());
    let out_path = get_arg_val(args, "--out");

    let values: Vec<u32> = values_str
        .split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .collect();

    let now = 1_770_000_000u64;
    let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
    let payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":{},"lst":"{}","uri":"{}"}}}}"#,
        now.saturating_add(86_400),
        now.saturating_sub(3_600),
        issuer_uri,
        bits,
        pack_status_lst(bits, &values),
        list_uri
    );
    let jwt = format!(
        "{}.{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(payload.as_bytes()),
        base64url::encode(&[0u8; 64])
    );

    if let Some(path) = out_path {
        fs::write(&path, jwt.as_bytes()).with_context(|| format!("error escribiendo {path}"))?;
        println!("JWT de StatusList guardado en: {path}");
    } else {
        println!("{jwt}");
    }

    Ok(())
}

fn run_issue(args: &[String]) -> Result<()> {
    println!("{DEV_INSECURE_WARNING}");
    let issuer_uri = get_arg_val(args, "--issuer-uri")
        .unwrap_or_else(|| "https://issuer.cedula.example.gov".to_string());
    let vct = get_arg_val(args, "--vct")
        .unwrap_or_else(|| "https://credentials.gravital.io/vct/personal/id-v1".to_string());
    let exp_sec: u64 = get_arg_val(args, "--exp-seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(86_400 * 365);
    let status_uri = get_arg_val(args, "--status-uri");
    let status_idx: Option<u32> = get_arg_val(args, "--status-idx").and_then(|s| s.parse().ok());
    let out_path = get_arg_val(args, "--out");

    let now = 1_770_000_000u64;
    let seed: u64 = get_arg_val(args, "--seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xDEAD_BEEF);
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(seed));
    let issuer_handle = gid_err(issuer_store.generate_key::<IssuerSigning>(), "gen issuer")?;

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0x5678));
    let holder_handle = gid_err(holder_store.generate_key::<HolderBinding>(), "gen holder")?;
    let holder_jwk = gid_err(holder_store.public_key(&holder_handle), "holder jwk")?;

    let header = r#"{"alg":"ES256","typ":"dc+sd-jwt","kid":"key-2026-issuer-01"}"#;
    let status_claim = if let (Some(uri), Some(idx)) = (status_uri, status_idx) {
        format!(r#","status":{{"status_list":{{"idx":{idx},"uri":"{uri}"}}}}"#)
    } else {
        String::new()
    };

    let payload = format!(
        r#"{{"iss":"{issuer_uri}","vct":"{vct}","iat":{},"exp":{},"cnf":{{"jwk":{}}}{status_claim}}}"#,
        now,
        now.saturating_add(exp_sec),
        holder_jwk.to_canonical_json()
    );

    let h_b64 = base64url::encode(header.as_bytes());
    let p_b64 = base64url::encode(payload.as_bytes());
    let signing_input = format!("{h_b64}.{p_b64}");
    let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
    let sig = gid_err(issuer_store.sign(&issuer_handle, &digest), "sign")?;
    let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
    let presentation = format!("{issuer_jwt}~");

    if let Some(path) = out_path {
        fs::write(&path, presentation.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Presentación emitida en: {path}");
    } else {
        println!("{presentation}");
    }

    Ok(())
}

fn run_verify(args: &[String]) -> Result<()> {
    let pres_arg = get_arg_val(args, "--presentation")
        .ok_or_else(|| anyhow!("Falta --presentation <CADENA|FICHERO>"))?;
    let bundle_path =
        get_arg_val(args, "--bundle").ok_or_else(|| anyhow!("Falta --bundle <FICHERO>"))?;
    let snap_path = get_arg_val(args, "--status-snapshot");
    let nonce = get_arg_val(args, "--nonce");
    let aud = get_arg_val(args, "--audience");
    let now_sec: u64 = get_arg_val(args, "--now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_770_000_000);

    let presentation_str = if Path::new(&pres_arg).exists() {
        fs::read_to_string(&pres_arg)
            .with_context(|| format!("error leyendo presentación de {pres_arg}"))?
    } else {
        pres_arg
    };

    let bundle_content =
        fs::read_to_string(&bundle_path).with_context(|| format!("error leyendo {bundle_path}"))?;
    let bundle_val = gid_err(
        gravital_id_codec::json::parse(&bundle_content),
        "error parseando JSON de bundle",
    )?;
    let bundle = gid_err(
        TrustBundle::from_payload(&bundle_val),
        "error instanciando TrustBundle",
    )?;

    let snapshot_opt = if let Some(path) = snap_path {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("error leyendo snapshot de {path}"))?;
        let list = gid_err(
            StatusListVerifier::parse(content.trim()),
            "error parseando snapshot JWT",
        )?;
        let uri = list.uri().unwrap_or("").to_string();
        Some(StatusSnapshot::new(
            list,
            &uri,
            UnixTime::from_seconds(now_sec),
        ))
    } else {
        None
    };

    let mut state_store = InMemoryStateStore::new(StateIntegrityKey::new([0x99; 32]));
    let policy = VerificationPolicy::default();
    let now = UnixTime::from_seconds(now_sec);

    let req_opt = if let (Some(n), Some(a)) = (nonce, aud) {
        Some(VerificationRequest::new(
            &n,
            &a,
            UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
            OperationClass::Default,
        ))
    } else {
        None
    };

    println!("--------------------------------------------------");
    println!("Gravital ID — Verificación Offline (Sans-I/O)");
    println!("--------------------------------------------------");

    let result = VerifierPipeline::verify(
        presentation_str.trim(),
        req_opt.as_ref(),
        &bundle,
        snapshot_opt.as_ref(),
        &mut state_store,
        &policy,
        now,
        None,
    );

    println!("Estado resultante: {}", result.status().as_str());
    if let Some(age) = result.status_age_seconds() {
        println!("Antigüedad del estado: {age} segundos");
    }
    println!("\nDetalle de comprobaciones (11 etapas):");
    for check in result.checks() {
        let status_symbol = match check.status {
            CheckStatus::Passed => "[✓] PASSED       ",
            CheckStatus::Failed => "[✗] FAILED       ",
            CheckStatus::Indeterminate => "[?] INDETERMINATE",
            CheckStatus::Skipped => "[-] SKIPPED      ",
        };
        let err = check
            .error_code
            .map(|c| format!(" (Error: GID-E{})", c as u16))
            .unwrap_or_default();
        println!(
            "  {status_symbol} {:<18} : {}{err}",
            check.kind.as_str(),
            check.message
        );
    }
    println!("--------------------------------------------------");

    match result.status() {
        VerificationStatus::Valid | VerificationStatus::ValidWithStaleStatus => Ok(()),
        VerificationStatus::Unverifiable => bail!("Verificación resultó Unverifiable"),
        VerificationStatus::Invalid => bail!("Verificación resultó Invalid"),
    }
}

// Verifies: REQ-VER-001, REQ-SDK-008, INV-01, INV-04, INV-05
fn run_demo_offline() -> Result<()> {
    println!("================================================================================");
    println!(" Gravital ID (PIP) — Demostración Determinista de Verificación Offline (F4.T12)");
    println!(" Invariantes: INV-01 (cero red), INV-04 (4 estados), INV-05 (fail-closed)");
    println!("================================================================================\n");

    let now = UnixTime::from_seconds(1_770_000_000);

    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0xCAFE_0001));
    let issuer_handle = gid_err(issuer_store.generate_key::<IssuerSigning>(), "gen issuer")?;
    let issuer_jwk = gid_err(issuer_store.public_key(&issuer_handle), "jwk issuer")?;

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0xCAFE_0002));
    let holder_handle = gid_err(holder_store.generate_key::<HolderBinding>(), "gen holder")?;
    let holder_jwk = gid_err(holder_store.public_key(&holder_handle), "jwk holder")?;

    let issuer_uri = "https://issuer.cedula.example.gov";
    let status_list_uri = "https://status.cedula.example.gov/lists/2026-10";
    let vct = "https://credentials.gravital.io/vct/personal/id-v1";
    let audience = "https://verifier.example.com";
    let nonce = "session-nonce-offline-demo-128bit";
    let kid = "key-2026-issuer-01";

    let jwk_parsed = gid_err(
        gravital_id_codec::json::parse(issuer_jwk.to_canonical_json().as_str()),
        "jwk",
    )?;
    let bundle_payload = Value::Object(vec![
        (
            "framework_id".to_string(),
            Value::String("pip-global".to_string()),
        ),
        ("bundle_epoch".to_string(), Value::Number(Number::PosInt(1))),
        (
            "bundle_version".to_string(),
            Value::Number(Number::PosInt(1)),
        ),
        ("chain_id".to_string(), Value::Number(Number::PosInt(1))),
        (
            "registry_address".to_string(),
            Value::String("0x1234".to_string()),
        ),
        (
            "finalized_block_number".to_string(),
            Value::Number(Number::PosInt(100)),
        ),
        (
            "finalized_block_hash".to_string(),
            Value::String("0xdeadbeef".to_string()),
        ),
        (
            "issued_at".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
        ),
        (
            "valid_until".to_string(),
            Value::Number(Number::PosInt(now.as_seconds().saturating_add(86_400))),
        ),
        (
            "issuers".to_string(),
            Value::Array(vec![Value::Object(vec![
                (
                    "issuer_id".to_string(),
                    Value::String(issuer_uri.to_string()),
                ),
                (
                    "profiles".to_string(),
                    Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
                ),
                (
                    "vcts".to_string(),
                    Value::Array(vec![Value::String(vct.to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
                ),
                ("state".to_string(), Value::String("active".to_string())),
                (
                    "keys".to_string(),
                    Value::Array(vec![Value::Object(vec![
                        ("kid".to_string(), Value::String(kid.to_string())),
                        ("jwk".to_string(), jwk_parsed),
                        ("state".to_string(), Value::String("active".to_string())),
                        (
                            "state_since".to_string(),
                            Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
                        ),
                    ])]),
                ),
            ])]),
        ),
    ]);
    let bundle = gid_err(TrustBundle::from_payload(&bundle_payload), "bundle")?;

    let make_pres = |exp_sec: u64, idx: u32| -> String {
        let header = format!(r#"{{"alg":"ES256","typ":"dc+sd-jwt","kid":"{kid}"}}"#);
        let payload = format!(
            r#"{{"iss":"{issuer_uri}","vct":"{vct}","iat":{},"exp":{},"cnf":{{"jwk":{}}},"status":{{"status_list":{{"idx":{idx},"uri":"{status_list_uri}"}}}}}}"#,
            now.as_seconds(),
            exp_sec,
            holder_jwk.to_canonical_json()
        );
        let h_b64 = base64url::encode(header.as_bytes());
        let p_b64 = base64url::encode(payload.as_bytes());
        let signing_input = format!("{h_b64}.{p_b64}");
        let digest = gravital_id_crypto::sha256(signing_input.as_bytes());
        let sig = issuer_store.sign(&issuer_handle, &digest).expect("sign");
        let issuer_jwt = format!("{signing_input}.{}", base64url::encode(&sig));
        let prefix = format!("{issuer_jwt}~");

        gravital_id_credential::KbIssuer::create_presentation(
            &prefix,
            audience,
            nonce,
            now,
            &holder_store,
            &holder_handle,
        )
        .expect("kb-jwt")
    };

    let build_snap = |values: &[u32], acquired_at: UnixTime| -> StatusSnapshot {
        let header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
        let payload = format!(
            r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":2,"lst":"{}","uri":"{}"}}}}"#,
            now.as_seconds().saturating_add(86_400),
            now.as_seconds().saturating_sub(3_600),
            issuer_uri,
            pack_status_lst(2, values),
            status_list_uri
        );
        let jwt = format!(
            "{}.{}.{}",
            base64url::encode(header.as_bytes()),
            base64url::encode(payload.as_bytes()),
            base64url::encode(&[0u8; 64])
        );
        let list = StatusListVerifier::parse(&jwt).expect("status list parse");
        StatusSnapshot::new(list, status_list_uri, acquired_at)
    };

    let req = VerificationRequest::new(
        nonce,
        audience,
        UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
        OperationClass::Transaction,
    );
    let policy = VerificationPolicy::default();

    // -------------------------------------------------------------------------
    // CASO 1: Valid
    // -------------------------------------------------------------------------
    println!(">>> CASO 1: Presentación válida con estado fresco");
    let pres_valid = make_pres(now.as_seconds().saturating_add(3600), 0);
    let fresh_snap = build_snap(&[0, 0, 0, 0], now);
    let mut store1 = InMemoryStateStore::new(StateIntegrityKey::new([0x11; 32]));
    let res1 = VerifierPipeline::verify(
        &pres_valid,
        Some(&req),
        &bundle,
        Some(&fresh_snap),
        &mut store1,
        &policy,
        now,
        None,
    );
    println!("    Resultado obtenido: {}", res1.status().as_str());
    assert_eq!(res1.status(), VerificationStatus::Valid);
    println!("    [OK] Estado 'Valid' verificado deterministamente.\n");

    // -------------------------------------------------------------------------
    // CASO 2: ValidWithStaleStatus
    // -------------------------------------------------------------------------
    println!(
        ">>> CASO 2: Presentación válida pero snapshot de estado antiguo (> 30 min en Transaction)"
    );
    let stale_time = UnixTime::from_seconds(now.as_seconds().saturating_sub(3_600));
    let stale_snap = build_snap(&[0, 0, 0, 0], stale_time);
    let mut store2 = InMemoryStateStore::new(StateIntegrityKey::new([0x22; 32]));
    let res2 = VerifierPipeline::verify(
        &pres_valid,
        Some(&req),
        &bundle,
        Some(&stale_snap),
        &mut store2,
        &policy,
        now,
        None,
    );
    println!("    Resultado obtenido: {}", res2.status().as_str());
    assert_eq!(res2.status(), VerificationStatus::ValidWithStaleStatus);
    println!("    [OK] Estado 'ValidWithStaleStatus' verificado deterministamente.\n");

    // -------------------------------------------------------------------------
    // CASO 3: Unverifiable
    // -------------------------------------------------------------------------
    println!(">>> CASO 3: Verificación offline sin snapshot de estado disponible");
    let mut store3 = InMemoryStateStore::new(StateIntegrityKey::new([0x33; 32]));
    let res3 = VerifierPipeline::verify(
        &pres_valid,
        Some(&req),
        &bundle,
        None, // Ausente offline
        &mut store3,
        &policy,
        now,
        None,
    );
    println!("    Resultado obtenido: {}", res3.status().as_str());
    assert_eq!(res3.status(), VerificationStatus::Unverifiable);
    println!("    [OK] Estado 'Unverifiable' verificado deterministamente.\n");

    // -------------------------------------------------------------------------
    // CASO 4: Invalid
    // -------------------------------------------------------------------------
    println!(">>> CASO 4: Credencial revocada en la lista de estado (bit = 1)");
    let pres_revoked = make_pres(now.as_seconds().saturating_add(3600), 1);
    let revoked_snap = build_snap(&[0, 1, 0, 0], now);
    let mut store4 = InMemoryStateStore::new(StateIntegrityKey::new([0x44; 32]));
    let res4 = VerifierPipeline::verify(
        &pres_revoked,
        Some(&req),
        &bundle,
        Some(&revoked_snap),
        &mut store4,
        &policy,
        now,
        None,
    );
    println!("    Resultado obtenido: {}", res4.status().as_str());
    assert_eq!(res4.status(), VerificationStatus::Invalid);
    assert_eq!(
        res4.check(CheckKind::Status).map(|c| c.error_code),
        Some(Some(ErrorCode::CredentialRevoked))
    );
    println!("    [OK] Estado 'Invalid' verificado deterministamente.\n");

    println!("================================================================================");
    println!(" Demostración finalizada con ÉXITO: Los 4 estados fueron reproducidos 100% offline.");
    println!("================================================================================");

    Ok(())
}
