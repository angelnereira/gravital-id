#![forbid(unsafe_code)]
// SAFETY/CLI: Herramienta de línea de comandos de desarrollo que interactúa con el usuario mediante stdout/stderr.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::indexing_slicing
)]

//! `pip-cli` / `gid-cli`: Biblioteca y CLI de desarrollo y verificación offline de Gravital ID (F4.T12, F5.T12).
//!
//! Trazabilidad:
//! - **REQ-VER-001:** La verificación opera completamente offline con bundle y snapshot locales.
//! - **REQ-PRES-005:** Soporte de transporte bidireccional offline con código QR Base45.
//! - **REQ-PRES-007:** Validación de solicitudes de verificación en la wallet contra TrustBundle.
//! - **REQ-PERF-003:** Presupuesto de latencia de verificación offline.
//! - **REQ-SDK-008:** Sans-I/O: la CLI orquesta la inyección de datos en memoria para el pipeline.
//! - **INV-01:** Verificación sin red.
//! - **INV-04:** Cuatro estados normativos (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`).
//! - **INV-05:** Fail-closed determinista.
//! - **INV-11:** Reloj inyectado determinísticamente.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use gravital_id_codec::base45::{decode as decode_base45, encode as encode_base45};
use gravital_id_codec::base64url;
use gravital_id_codec::deflate::{deflate, inflate};
use gravital_id_codec::json::{Number, Value};
use gravital_id_credential::{to_canonical_json, KbIssuer, ParsedSdJwt, SdIssuer, SdObjectBuilder};
use gravital_id_crypto::secret::SecretBytes;
use gravital_id_holder::{CredentialQuery, DcqlQuery, HolderWallet, RequestedClaim};
use gravital_id_keys::{HolderBinding, IssuerSigning, KeyStore, SoftwareKeyStore};
use gravital_id_protocol::offline_signed_request::sign_verification_request;
use gravital_id_protocol::offline_wallet_policy::WalletRequestValidator;
use gravital_id_protocol::{
    decode_presentation_from_base45, encode_presentation_to_base45,
    VerificationRequest as ProtocolVerificationRequest,
};
use gravital_id_status::cache::StatusSnapshot;
use gravital_id_status::status_list::StatusListVerifier;
use gravital_id_storage_sqlite::SqliteStorage;
use gravital_id_testkit::SeededRng;
use gravital_id_trust::bundle::TrustBundle;
use gravital_id_types::{ErrorCode, GidError, UnixTime, Vct};
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
        r#"pip-cli / gid-cli — Herramienta de desarrollo y verificación offline de Gravital ID (F4.T12, F5.T12)

USO:
    pip-cli <SUBCOMANDO> [OPCIONES]

SUBCOMANDOS:
    demo-offline
        Ejecuta una demostración completa y determinista de los 4 estados canónicos de
        verificación (Valid, ValidWithStaleStatus, Unverifiable, Invalid) de forma totalmente
        offline sin I/O de red.

    demo-flow-offline
        Ejecuta el flujo completo de extremo a extremo offline (F5.T12):
        emisor -> wallet cifrada -> solicitud firmada -> presentación QR Base45 -> verificación.

    dev-issuer [--out-jwk <FICHERO>] [--seed <NUM>]
        Genera un par de claves de emisor para desarrollo marcado explícitamente como inseguro.

    dev-verifier [--out-jwk <FICHERO>] [--seed <NUM>]
        Genera un par de claves de verificador para desarrollo marcado explícitamente como inseguro.

    dev-bundle --issuer-uri <URI> --jwk <FICHERO> [--kid <KID>] [--verifier-id <URI>] [--verifier-jwk <FICHERO>] [--out <FICHERO>]
        Construye un trust bundle JSON canónico local conteniendo emisor y verificador registrados.

    dev-status --issuer-uri <URI> --uri <URI> [--bits <1|2>] [--values <V1,V2,...>] [--out <FICHERO>]
        Genera un JWT de StatusList y su snapshot local.

    issue --issuer-uri <URI> --vct <VCT> [--status-uri <URI>] [--status-idx <IDX>] [--exp-seconds <S>] [--holder-seed <NUM>] [--with-disclosures] [--out <FICHERO>]
        Emite una credencial SD-JWT VC de prueba con soporte de divulgación selectiva.

    wallet-import --credential <CADENA|FICHERO> [--holder-seed <NUM>] [--db <FICHERO>] [--out-id <FICHERO>]
        Importa una credencial emitida en la wallet del titular cifrada localmente (REQ-KEY-008).

    verify-request --verifier-id <ID> [--audience <AUD>] [--nonce <NONCE>] [--claims <C1,C2>] [--sign-seed <NUM>] [--format <json|base45>] [--out <FICHERO>]
        Genera una solicitud de verificación offline (opcionalmente firmada con ES256).

    wallet-present --request <CADENA|FICHERO> --credential <CADENA|FICHERO> [--bundle <FICHERO>] [--holder-seed <NUM>] [--claims <C1,C2>] [--format <base45|sd-jwt>] [--out <FICHERO>]
        Valida la solicitud en la wallet y genera una presentación divulgando solo los atributos permitidos con KB-JWT y QR Base45.

    verify --presentation <CADENA|FICHERO> --bundle <FICHERO> [--request <CADENA|FICHERO>] [--status-snapshot <FICHERO>] [--nonce <NONCE>] [--audience <AUD>] [--now <UNIX_TIME>]
        Verifica una presentación SD-JWT o payload QR Base45 de forma 100% offline contra bundle y snapshot locales.

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
        Some("demo-flow-offline") => run_demo_flow_offline()?,
        Some("dev-issuer") => run_dev_issuer(&args[1..])?,
        Some("dev-verifier") => run_dev_verifier(&args[1..])?,
        Some("dev-bundle") => run_dev_bundle(&args[1..])?,
        Some("dev-status") => run_dev_status(&args[1..])?,
        Some("issue") => run_issue(&args[1..])?,
        Some("wallet-import") => run_wallet_import(&args[1..])?,
        Some("verify-request") => run_verify_request(&args[1..])?,
        Some("wallet-present") => run_wallet_present(&args[1..])?,
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

fn run_dev_verifier(args: &[String]) -> Result<()> {
    println!("{DEV_INSECURE_WARNING}");
    let seed: u64 = get_arg_val(args, "--seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xCAFE_BEEF);
    let out_jwk = get_arg_val(args, "--out-jwk");

    let mut store = SoftwareKeyStore::new(SeededRng::new(seed));
    let handle = gid_err(
        store.generate_key::<IssuerSigning>(),
        "error generando clave de verificador",
    )?;
    let jwk = gid_err(
        store.public_key(&handle),
        "error obteniendo clave pública JWK",
    )?;
    let jwk_json = jwk.to_canonical_json();

    if let Some(path) = out_jwk {
        fs::write(&path, jwk_json.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Clave pública JWK del verificador guardada en: {path}");
    } else {
        println!("Clave pública JWK del verificador:");
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
    let verifier_id_opt = get_arg_val(args, "--verifier-id");
    let verifier_jwk_file = get_arg_val(args, "--verifier-jwk");
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

    let mut verifiers_array = Vec::new();
    if let Some(v_id) = verifier_id_opt {
        let v_jwk_val = if let Some(v_file) = verifier_jwk_file {
            let content =
                fs::read_to_string(&v_file).with_context(|| format!("error leyendo {v_file}"))?;
            gid_err(
                gravital_id_codec::json::parse(&content),
                "error parseando JWK de verificador",
            )?
        } else {
            let mut v_store = SoftwareKeyStore::new(SeededRng::new(0xCAFE_BEEF));
            let v_handle = gid_err(v_store.generate_key::<IssuerSigning>(), "gen verifier key")?;
            let v_jwk = gid_err(v_store.public_key(&v_handle), "verifier jwk")?;
            gid_err(
                gravital_id_codec::json::parse(&v_jwk.to_canonical_json()),
                "parse verifier jwk",
            )?
        };

        verifiers_array.push(Value::Object(vec![
            ("verifier_id".to_string(), Value::String(v_id)),
            (
                "profiles".to_string(),
                Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
            ),
            (
                "valid_from".to_string(),
                Value::Number(Number::PosInt(now.saturating_sub(86_400))),
            ),
            (
                "valid_until".to_string(),
                Value::Number(Number::PosInt(now.saturating_add(86_400 * 30))),
            ),
            ("jwk".to_string(), v_jwk_val),
        ]));
    }

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
        ("verifiers".to_string(), Value::Array(verifiers_array)),
        ("policies".to_string(), Value::Array(vec![])),
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
    let holder_seed: u64 = get_arg_val(args, "--holder-seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5678);
    let with_disclosures = args
        .iter()
        .any(|a| a == "--with-disclosures" || a == "--with-claims");
    let out_path = get_arg_val(args, "--out");

    let now = 1_770_000_000u64;
    let seed: u64 = get_arg_val(args, "--seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xDEAD_BEEF);
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(seed));
    let issuer_handle = gid_err(issuer_store.generate_key::<IssuerSigning>(), "gen issuer")?;

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(holder_seed));
    let holder_handle = gid_err(holder_store.generate_key::<HolderBinding>(), "gen holder")?;
    let holder_jwk = gid_err(holder_store.public_key(&holder_handle), "holder jwk")?;

    let presentation = if with_disclosures {
        let mut builder = SdObjectBuilder::new();
        builder = builder.add_plain_claim("iss", Value::String(issuer_uri));
        builder = builder.add_plain_claim("vct", Value::String(vct));
        builder = builder.add_plain_claim("iat", Value::Number(Number::PosInt(now)));
        builder = builder.add_plain_claim(
            "exp",
            Value::Number(Number::PosInt(now.saturating_add(exp_sec))),
        );
        let holder_jwk_val = gid_err(
            gravital_id_codec::json::parse(&holder_jwk.to_canonical_json()),
            "parse holder jwk",
        )?;
        builder = builder.add_plain_claim(
            "cnf",
            Value::Object(vec![("jwk".to_string(), holder_jwk_val)]),
        );

        if let (Some(uri), Some(idx)) = (status_uri, status_idx) {
            let status_val = Value::Object(vec![(
                "status_list".to_string(),
                Value::Object(vec![
                    ("idx".to_string(), Value::Number(Number::PosInt(idx as u64))),
                    ("uri".to_string(), Value::String(uri)),
                ]),
            )]);
            builder = builder.add_plain_claim("status", status_val);
        }

        // Add standard claims as selective disclosures
        builder = builder.add_sd_claim("given_name", Value::String("Alice".to_string()));
        builder = builder.add_sd_claim("family_name", Value::String("Smith".to_string()));
        builder = builder.add_sd_claim("document_number", Value::String("ID-12345678".to_string()));
        builder = builder.add_sd_claim("birth_date", Value::String("1990-01-01".to_string()));
        builder = builder.add_sd_claim("age_over_18", Value::Bool(true));

        let rng = SeededRng::new(seed.wrapping_add(1));
        let header = gravital_id_credential::JwsHeader {
            alg: "ES256".to_string(),
            typ: "dc+sd-jwt".to_string(),
            kid: Some(
                gravital_id_types::Kid::parse("key-2026-issuer-01").map_err(|e| anyhow!("{e}"))?,
            ),
        };

        let issued = gid_err(
            SdIssuer::issue_signed(builder, &issuer_store, &issuer_handle, header, &rng),
            "error emitiendo SD-JWT con divulgaciones",
        )?;
        issued.to_compact_serialization().to_string()
    } else {
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
        format!("{issuer_jwt}~")
    };

    if let Some(path) = out_path {
        fs::write(&path, presentation.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Presentación emitida en: {path}");
    } else {
        println!("{presentation}");
    }

    Ok(())
}

fn run_wallet_import(args: &[String]) -> Result<()> {
    let cred_arg = get_arg_val(args, "--credential")
        .ok_or_else(|| anyhow!("Falta argumento obligatorio --credential <CADENA|FICHERO>"))?;
    let holder_seed: u64 = get_arg_val(args, "--holder-seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5678);
    let db_path = get_arg_val(args, "--db");
    let out_id = get_arg_val(args, "--out-id");
    let now_sec: u64 = get_arg_val(args, "--now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_770_000_000);

    let cred_str = if Path::new(&cred_arg).exists() {
        fs::read_to_string(&cred_arg)
            .with_context(|| format!("error leyendo credencial de {cred_arg}"))?
    } else {
        cred_arg
    };

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(holder_seed));
    let holder_handle = gid_err(
        holder_store.generate_key::<HolderBinding>(),
        "error generando clave de titular",
    )?;
    let holder_key_id = holder_handle.id().to_string();

    let storage = if let Some(path) = db_path {
        gid_err(
            SqliteStorage::open(&path),
            &format!("error abriendo SQLite en {path}"),
        )?
    } else {
        gid_err(
            SqliteStorage::open_in_memory(),
            "error abriendo SQLite en memoria",
        )?
    };

    let kek = SecretBytes::new([0x5A; 32]);
    let mut wallet = gid_err(
        HolderWallet::new(storage, kek, SeededRng::new(0x1122_3344)),
        "error inicializando HolderWallet",
    )?;

    let now = UnixTime::from_seconds(now_sec);
    let cred_id = gid_err(
        wallet.import_credential(
            cred_str.trim(),
            &holder_key_id,
            now,
            &holder_store,
            &holder_handle,
        ),
        "error importando credencial en la wallet",
    )?;

    println!("--------------------------------------------------");
    println!("Gravital ID — Wallet del Titular (F5.T12)");
    println!("--------------------------------------------------");
    println!("[✓] Credencial importada y cifrada con éxito (REQ-KEY-008, REQ-STOR-001).");
    println!("    ID de Credencial: {}", cred_id.as_str());
    println!("    Holder Key ID:    {}", holder_key_id);
    println!("--------------------------------------------------");

    if let Some(path) = out_id {
        fs::write(&path, cred_id.as_str().as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("ID de credencial guardado en: {path}");
    }

    Ok(())
}

fn run_verify_request(args: &[String]) -> Result<()> {
    let verifier_id = get_arg_val(args, "--verifier-id")
        .unwrap_or_else(|| "https://verifier.example.com".to_string());
    let audience = get_arg_val(args, "--audience").unwrap_or_else(|| verifier_id.clone());
    let nonce = get_arg_val(args, "--nonce")
        .unwrap_or_else(|| "session-nonce-offline-demo-128bit".to_string());
    let vct = get_arg_val(args, "--vct")
        .unwrap_or_else(|| "https://credentials.gravital.io/vct/personal/id-v1".to_string());
    let claims_str =
        get_arg_val(args, "--claims").unwrap_or_else(|| "given_name,family_name".to_string());
    let exp_sec: u64 = get_arg_val(args, "--expires-seconds")
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let now_sec: u64 = get_arg_val(args, "--now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_770_000_000);
    let sign_seed_opt: Option<u64> = get_arg_val(args, "--sign-seed").and_then(|s| s.parse().ok());
    let format_opt = get_arg_val(args, "--format").unwrap_or_else(|| "json".to_string());
    let out_path = get_arg_val(args, "--out");

    let req_claims: Vec<RequestedClaim> = claims_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(RequestedClaim::required)
        .collect();

    let vct_parsed = gid_err(Vct::parse(&vct), "error parseando VCT")?;
    let cred_query = gid_err(
        CredentialQuery::new("cred1", vec![vct_parsed], req_claims),
        "error construyendo CredentialQuery",
    )?;
    let dcql = gid_err(
        DcqlQuery::new(vec![cred_query]),
        "error construyendo DcqlQuery",
    )?;

    let issued_at = UnixTime::from_seconds(now_sec);
    let expires_at = UnixTime::from_seconds(now_sec.saturating_add(exp_sec));

    let offline_req = gid_err(
        ProtocolVerificationRequest::new(
            verifier_id,
            nonce,
            audience,
            issued_at,
            expires_at,
            dcql,
            None,
        ),
        "error creando ProtocolVerificationRequest",
    )?;

    let output_str = if let Some(seed) = sign_seed_opt {
        let mut store = SoftwareKeyStore::new(SeededRng::new(seed));
        let handle = gid_err(store.generate_key::<IssuerSigning>(), "gen verifier key")?;
        let signed_jws = gid_err(
            sign_verification_request(&offline_req, &store, &handle, None),
            "error firmando solicitud de verificación",
        )?;
        if format_opt == "base45" {
            let compressed = deflate(signed_jws.as_bytes());
            format!("REQ1:{}", encode_base45(&compressed))
        } else {
            signed_jws
        }
    } else {
        let json_bytes = gid_err(offline_req.to_json_bytes(), "error serializando solicitud")?;
        let json_str = String::from_utf8(json_bytes)?;
        if format_opt == "base45" {
            let compressed = deflate(json_str.as_bytes());
            format!("REQ1:{}", encode_base45(&compressed))
        } else {
            json_str
        }
    };

    if let Some(path) = out_path {
        fs::write(&path, output_str.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Solicitud de verificación guardada en: {path}");
    } else {
        println!("{output_str}");
    }

    Ok(())
}

fn run_wallet_present(args: &[String]) -> Result<()> {
    let req_arg = get_arg_val(args, "--request")
        .ok_or_else(|| anyhow!("Falta argumento obligatorio --request <CADENA|FICHERO>"))?;
    let cred_arg = get_arg_val(args, "--credential")
        .ok_or_else(|| anyhow!("Falta argumento obligatorio --credential <CADENA|FICHERO>"))?;
    let bundle_path = get_arg_val(args, "--bundle");
    let holder_seed: u64 = get_arg_val(args, "--holder-seed")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5678);
    let claims_override = get_arg_val(args, "--claims");
    let now_sec: u64 = get_arg_val(args, "--now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_770_000_000);
    let format_opt = get_arg_val(args, "--format").unwrap_or_else(|| "base45".to_string());
    let out_path = get_arg_val(args, "--out");

    let req_str = if Path::new(&req_arg).exists() {
        fs::read_to_string(&req_arg)
            .with_context(|| format!("error leyendo solicitud de {req_arg}"))?
    } else {
        req_arg
    };

    let cred_str = if Path::new(&cred_arg).exists() {
        fs::read_to_string(&cred_arg)
            .with_context(|| format!("error leyendo credencial de {cred_arg}"))?
    } else {
        cred_arg
    };

    let raw_req = req_str.trim();
    let decoded_req = if let Some(stripped) = raw_req.strip_prefix("REQ1:") {
        let b45_bytes = gid_err(
            decode_base45(stripped),
            "error decodificando Base45 de solicitud",
        )?;
        let decompressed = gid_err(inflate(&b45_bytes), "error descomprimiendo solicitud")?;
        String::from_utf8(decompressed).with_context(|| "solicitud no es UTF-8 válido")?
    } else {
        raw_req.to_string()
    };

    let now = UnixTime::from_seconds(now_sec);

    let bundle_opt = if let Some(path) = &bundle_path {
        let content =
            fs::read_to_string(path).with_context(|| format!("error leyendo bundle de {path}"))?;
        let bundle_val = gid_err(
            gravital_id_codec::json::parse(&content),
            "error parseando JSON de bundle",
        )?;
        Some(gid_err(
            TrustBundle::from_payload(&bundle_val),
            "error instanciando TrustBundle",
        )?)
    } else {
        None
    };

    let validator = WalletRequestValidator::default();
    let validated = if decoded_req.contains('.') && decoded_req.split('.').count() == 3 {
        let bundle = bundle_opt.as_ref().ok_or_else(|| {
            anyhow!("Validación de solicitud firmada requiere --bundle <FICHERO>")
        })?;
        gid_err(
            validator.validate_signed_request(&decoded_req, now, bundle),
            "error validando solicitud firmada (REQ-PRES-007)",
        )?
    } else {
        let req_bytes = decoded_req.as_bytes();
        let off_req = gid_err(
            ProtocolVerificationRequest::from_json_bytes(req_bytes),
            "error parseando JSON de solicitud",
        )?;
        gid_err(
            validator.validate_request(&off_req, now, bundle_opt.as_ref()),
            "error validando solicitud contra política de la wallet",
        )?
    };

    println!("--------------------------------------------------");
    println!("Gravital ID — Wallet Presentación (F5.T12)");
    println!("--------------------------------------------------");
    println!("[✓] Solicitud validada por la wallet.");
    println!(
        "    Verificador:          {}",
        validated.request.verifier_id
    );
    println!(
        "    Solicitud Firmada:    {}",
        if validated.is_signed {
            "Sí (ES256)"
        } else {
            "No"
        }
    );
    println!(
        "    Verificador en Trust: {}",
        if validated.is_registered_verifier {
            "Sí (Registrado)"
        } else {
            "No"
        }
    );

    let allowed_claims: Vec<String> = if let Some(c) = claims_override {
        c.split(',').map(|s| s.trim().to_string()).collect()
    } else {
        validated
            .request
            .query
            .credentials
            .iter()
            .flat_map(|q| q.claims.iter().map(|c| c.name.clone()))
            .collect()
    };

    println!("    Claims a divulgar:    {:?}", allowed_claims);

    let parsed_cred = gid_err(
        ParsedSdJwt::parse(cred_str.trim()),
        "error parseando credencial SD-JWT",
    )?;

    let mut filtered_disclosures = Vec::new();
    for disc in parsed_cred.disclosures() {
        if let Some(claim_name) = disc.claim_name() {
            if allowed_claims.iter().any(|c| c == claim_name) {
                filtered_disclosures.push(disc.encoded().to_string());
            }
        }
    }

    let issuer_jwt = format!(
        "{}.{}",
        parsed_cred.signing_input(),
        base64url::encode(parsed_cred.signature())
    );

    let mut sd_jwt_prefix = String::with_capacity(
        issuer_jwt
            .len()
            .saturating_add(2)
            .saturating_add(filtered_disclosures.len().saturating_mul(64)),
    );
    sd_jwt_prefix.push_str(&issuer_jwt);
    sd_jwt_prefix.push('~');
    for d in &filtered_disclosures {
        sd_jwt_prefix.push_str(d);
        sd_jwt_prefix.push('~');
    }

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(holder_seed));
    let holder_handle = gid_err(
        holder_store.generate_key::<HolderBinding>(),
        "error generando clave de titular",
    )?;

    let presentation_sd_jwt = gid_err(
        KbIssuer::create_presentation(
            &sd_jwt_prefix,
            &validated.request.audience,
            &validated.request.nonce,
            now,
            &holder_store,
            &holder_handle,
        ),
        "error creando presentación con KB-JWT",
    )?;

    let final_presentation = if format_opt == "sd-jwt" {
        presentation_sd_jwt
    } else {
        gid_err(
            encode_presentation_to_base45(&presentation_sd_jwt),
            "error codificando presentación a QR Base45 (REQ-PRES-005)",
        )?
    };

    println!(
        "[✓] Presentación generada con éxito (formato: {}).",
        format_opt
    );
    println!(
        "    Tamaño: {} bytes / caracteres",
        final_presentation.len()
    );
    println!("--------------------------------------------------");

    if let Some(path) = out_path {
        fs::write(&path, final_presentation.as_bytes())
            .with_context(|| format!("error escribiendo {path}"))?;
        println!("Presentación guardada en: {path}");
    } else {
        println!("{final_presentation}");
    }

    Ok(())
}

fn run_verify(args: &[String]) -> Result<()> {
    let pres_arg = get_arg_val(args, "--presentation")
        .ok_or_else(|| anyhow!("Falta --presentation <CADENA|FICHERO>"))?;
    let bundle_path =
        get_arg_val(args, "--bundle").ok_or_else(|| anyhow!("Falta --bundle <FICHERO>"))?;
    let snap_path = get_arg_val(args, "--status-snapshot");
    let mut nonce = get_arg_val(args, "--nonce");
    let mut aud = get_arg_val(args, "--audience");
    let req_arg = get_arg_val(args, "--request");
    let now_sec: u64 = get_arg_val(args, "--now")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_770_000_000);

    let raw_pres = if Path::new(&pres_arg).exists() {
        fs::read_to_string(&pres_arg)
            .with_context(|| format!("error leyendo presentación de {pres_arg}"))?
    } else {
        pres_arg
    };

    let presentation_str =
        if raw_pres.trim().starts_with("GID1:") || raw_pres.trim().starts_with("PIP1:") {
            let prefix = &raw_pres.trim()[..5];
            println!("Detectado payload QR Base45 (prefijo {prefix}).");
            let decoded = gid_err(
                decode_presentation_from_base45(raw_pres.trim()),
                "error decodificando QR Base45 a SD-JWT (REQ-PRES-005)",
            )?;
            println!("Decodificado a SD-JWT: {} bytes.", decoded.len());
            decoded
        } else {
            raw_pres
        };

    if let Some(req_source) = req_arg {
        let req_content = if Path::new(&req_source).exists() {
            fs::read_to_string(&req_source)
                .with_context(|| format!("error leyendo solicitud de {req_source}"))?
        } else {
            req_source
        };
        let decoded_req = if let Some(stripped) = req_content.trim().strip_prefix("REQ1:") {
            let b45_bytes = gid_err(
                decode_base45(stripped),
                "error decodificando Base45 de solicitud",
            )?;
            let decompressed = gid_err(inflate(&b45_bytes), "error descomprimiendo solicitud")?;
            String::from_utf8(decompressed).with_context(|| "solicitud no es UTF-8 válido")?
        } else {
            req_content.trim().to_string()
        };

        if decoded_req.contains('.') && decoded_req.split('.').count() == 3 {
            if let Some(payload_b64) = decoded_req.split('.').nth(1) {
                if let Ok(bytes) = base64url::decode(payload_b64) {
                    if let Ok(off_req) = ProtocolVerificationRequest::from_json_bytes(&bytes) {
                        if nonce.is_none() {
                            nonce = Some(off_req.nonce);
                        }
                        if aud.is_none() {
                            aud = Some(off_req.audience);
                        }
                    }
                }
            }
        } else if let Ok(off_req) =
            ProtocolVerificationRequest::from_json_bytes(decoded_req.as_bytes())
        {
            if nonce.is_none() {
                nonce = Some(off_req.nonce);
            }
            if aud.is_none() {
                aud = Some(off_req.audience);
            }
        }
    }

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

// Verifies: REQ-PRES-005, REQ-PRES-007, REQ-PERF-003, INV-01, INV-04, INV-05, INV-11
fn run_demo_flow_offline() -> Result<()> {
    println!("================================================================================");
    println!(" Gravital ID (PIP) — Demostración Flujo Completo Offline (F5.T12)");
    println!(" Emisor -> Wallet (Almacén Cifrado) -> Solicitud -> Presentación QR -> Verificador");
    println!(" Invariantes: INV-01 (cero red), INV-05 (fail-closed), INV-11 (reloj inyectado)");
    println!("================================================================================\n");

    let now = UnixTime::from_seconds(1_770_000_000);
    let start_time = std::time::Instant::now();

    // 1. Claves del Emisor, Verificador y Titular
    println!(">>> PASO 1: Generación de claves de emisor, verificador y titular");
    let mut issuer_store = SoftwareKeyStore::new(SeededRng::new(0xCAFE_0001));
    let issuer_handle = gid_err(issuer_store.generate_key::<IssuerSigning>(), "gen issuer")?;
    let issuer_jwk = gid_err(issuer_store.public_key(&issuer_handle), "jwk issuer")?;

    let mut verifier_store = SoftwareKeyStore::new(SeededRng::new(0xCAFE_0002));
    let verifier_handle = gid_err(
        verifier_store.generate_key::<IssuerSigning>(),
        "gen verifier",
    )?;
    let verifier_jwk = gid_err(verifier_store.public_key(&verifier_handle), "jwk verifier")?;

    let mut holder_store = SoftwareKeyStore::new(SeededRng::new(0xCAFE_0003));
    let holder_handle = gid_err(holder_store.generate_key::<HolderBinding>(), "gen holder")?;
    let holder_jwk = gid_err(holder_store.public_key(&holder_handle), "jwk holder")?;
    let holder_key_id = holder_handle.id().to_string();

    let issuer_uri = "https://issuer.cedula.example.gov";
    let verifier_id = "https://verifier.example.com";
    let vct = "https://credentials.gravital.io/vct/personal/id-v1";
    let kid = "key-2026-issuer-01";

    // 2. TrustBundle que autoriza al emisor Y al verificador
    println!(">>> PASO 2: Construcción de TrustBundle con emisor y verificador registrados");
    let issuer_jwk_parsed = gid_err(
        gravital_id_codec::json::parse(&issuer_jwk.to_canonical_json()),
        "iss jwk",
    )?;
    let verifier_jwk_parsed = gid_err(
        gravital_id_codec::json::parse(&verifier_jwk.to_canonical_json()),
        "ver jwk",
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
            Value::Number(Number::PosInt(now.as_seconds().saturating_add(86_400 * 30))),
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
                        ("jwk".to_string(), issuer_jwk_parsed),
                        ("state".to_string(), Value::String("active".to_string())),
                        (
                            "state_since".to_string(),
                            Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
                        ),
                    ])]),
                ),
            ])]),
        ),
        (
            "verifiers".to_string(),
            Value::Array(vec![Value::Object(vec![
                (
                    "verifier_id".to_string(),
                    Value::String(verifier_id.to_string()),
                ),
                (
                    "profiles".to_string(),
                    Value::Array(vec![Value::String("pip-personal-v1".to_string())]),
                ),
                (
                    "valid_from".to_string(),
                    Value::Number(Number::PosInt(now.as_seconds().saturating_sub(86_400))),
                ),
                (
                    "valid_until".to_string(),
                    Value::Number(Number::PosInt(now.as_seconds().saturating_add(86_400 * 30))),
                ),
                ("jwk".to_string(), verifier_jwk_parsed),
            ])]),
        ),
        ("policies".to_string(), Value::Array(vec![])),
    ]);
    let bundle = gid_err(TrustBundle::from_payload(&bundle_payload), "bundle")?;
    println!("    [✓] TrustBundle validado con éxito.\n");

    // 3. Emisión de credencial con divulgación selectiva
    println!(">>> PASO 3: Emisión de credencial SD-JWT con divulgaciones selectivas");
    let mut cred_builder = SdObjectBuilder::new();
    cred_builder = cred_builder.add_plain_claim("iss", Value::String(issuer_uri.to_string()));
    cred_builder = cred_builder.add_plain_claim("vct", Value::String(vct.to_string()));
    cred_builder =
        cred_builder.add_plain_claim("iat", Value::Number(Number::PosInt(now.as_seconds())));
    cred_builder = cred_builder.add_plain_claim(
        "exp",
        Value::Number(Number::PosInt(
            now.as_seconds().saturating_add(86_400 * 365),
        )),
    );
    let holder_jwk_parsed = gid_err(
        gravital_id_codec::json::parse(&holder_jwk.to_canonical_json()),
        "holder jwk",
    )?;
    cred_builder = cred_builder.add_plain_claim(
        "cnf",
        Value::Object(vec![("jwk".to_string(), holder_jwk_parsed)]),
    );

    let status_list_uri = "https://status.cedula.example.gov/lists/2026-10";
    let status_val = Value::Object(vec![(
        "status_list".to_string(),
        Value::Object(vec![
            ("idx".to_string(), Value::Number(Number::PosInt(0))),
            (
                "uri".to_string(),
                Value::String(status_list_uri.to_string()),
            ),
        ]),
    )]);
    cred_builder = cred_builder.add_plain_claim("status", status_val);

    // Selective claims
    cred_builder = cred_builder.add_sd_claim("given_name", Value::String("Alice".to_string()));
    cred_builder = cred_builder.add_sd_claim("family_name", Value::String("Smith".to_string()));
    cred_builder =
        cred_builder.add_sd_claim("document_number", Value::String("ID-12345678".to_string()));
    cred_builder = cred_builder.add_sd_claim("birth_date", Value::String("1990-01-01".to_string()));
    cred_builder = cred_builder.add_sd_claim("age_over_18", Value::Bool(true));

    let header = gravital_id_credential::JwsHeader {
        alg: "ES256".to_string(),
        typ: "dc+sd-jwt".to_string(),
        kid: Some(gravital_id_types::Kid::parse(kid).expect("kid")),
    };
    let rng = SeededRng::new(0xCAFE_0004);
    let issued_cred = gid_err(
        SdIssuer::issue_signed(cred_builder, &issuer_store, &issuer_handle, header, &rng),
        "issue credential",
    )?;
    let raw_credential = issued_cred.to_compact_serialization().to_string();
    println!(
        "    [✓] Credencial SD-JWT emitida ({} divulgaciones generadas).\n",
        issued_cred.disclosures().len()
    );

    // 4. Importación en la wallet con cifrado local
    println!(">>> PASO 4: Importación en la wallet con almacén cifrado SQLite (REQ-STOR-001, REQ-KEY-008)");
    let sqlite_storage = gid_err(SqliteStorage::open_in_memory(), "sqlite memory")?;
    let kek = SecretBytes::new([0x33; 32]);
    let mut wallet = gid_err(
        HolderWallet::new(sqlite_storage, kek, SeededRng::new(0xCAFE_0005)),
        "init wallet",
    )?;
    let cred_id = gid_err(
        wallet.import_credential(
            &raw_credential,
            &holder_key_id,
            now,
            &holder_store,
            &holder_handle,
        ),
        "wallet import",
    )?;
    println!(
        "    [✓] Credencial almacenada bajo ID: {}\n",
        cred_id.as_str()
    );

    // 5. Verificador genera solicitud firmada (pidiendo claim sensible: document_number)
    println!(">>> PASO 5: Verificador emite solicitud firmada con ES256 (REQ-PRES-007)");
    let nonce = "session-nonce-flow-offline-demo";
    let requested_claims = vec![
        RequestedClaim::required("given_name"),
        RequestedClaim::required("document_number"),
    ];
    let vct_parsed = gid_err(Vct::parse(vct), "vct")?;
    let cred_query = gid_err(
        CredentialQuery::new("query1", vec![vct_parsed], requested_claims),
        "cred query",
    )?;
    let dcql = gid_err(DcqlQuery::new(vec![cred_query]), "dcql")?;
    let off_req = gid_err(
        ProtocolVerificationRequest::new(
            verifier_id,
            nonce,
            verifier_id,
            now,
            UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
            dcql,
            None,
        ),
        "new req",
    )?;
    let signed_req_jws = gid_err(
        sign_verification_request(&off_req, &verifier_store, &verifier_handle, None),
        "sign request",
    )?;
    println!("    [✓] Solicitud de verificación firmada emitida.\n");

    // 6. Wallet valida la solicitud contra el TrustBundle
    println!(
        ">>> PASO 6: Wallet valida solicitud y claims sensibles contra TrustBundle (REQ-PRES-007)"
    );
    let wallet_validator = WalletRequestValidator::default();
    let validated_req = gid_err(
        wallet_validator.validate_signed_request(&signed_req_jws, now, &bundle),
        "validate signed request",
    )?;
    assert!(validated_req.is_signed);
    assert!(validated_req.is_registered_verifier);
    println!(
        "    [✓] Verificador registrado comprobado, permiso para 'document_number' concedido.\n"
    );

    // 7. Wallet construye presentación divulgando solo los claims solicitados y firma KB-JWT
    println!(">>> PASO 7: Wallet prepara presentación con divulgación selectiva y KB-JWT (REQ-PRIV-001, REQ-PRES-002)");
    let parsed_cred = gid_err(ParsedSdJwt::parse(&raw_credential), "parse cred")?;
    let mut disclosures_to_reveal = Vec::new();
    for d in parsed_cred.disclosures() {
        if let Some(name) = d.claim_name() {
            if name == "given_name" || name == "document_number" {
                disclosures_to_reveal.push(d.encoded().to_string());
            }
        }
    }
    assert_eq!(disclosures_to_reveal.len(), 2);

    let issuer_jwt = format!(
        "{}.{}",
        parsed_cred.signing_input(),
        base64url::encode(parsed_cred.signature())
    );
    let mut sd_prefix = format!("{issuer_jwt}~");
    for d in &disclosures_to_reveal {
        sd_prefix.push_str(d);
        sd_prefix.push('~');
    }

    let pres_sd_jwt = gid_err(
        KbIssuer::create_presentation(
            &sd_prefix,
            verifier_id,
            nonce,
            now,
            &holder_store,
            &holder_handle,
        ),
        "create presentation",
    )?;

    // 8. Transcodificación a QR Base45 con prefijo normativo GID1:
    println!(
        ">>> PASO 8: Transcodificación binaria sin pérdidas a payload QR Base45 (REQ-PRES-005)"
    );
    let qr_base45 = gid_err(encode_presentation_to_base45(&pres_sd_jwt), "encode base45")?;
    println!(
        "    Payload QR Base45: {} caracteres ({}% del presupuesto offline V40)",
        qr_base45.len(),
        qr_base45
            .len()
            .saturating_mul(100)
            .checked_div(1000)
            .unwrap_or(0)
    );
    assert!(qr_base45.starts_with("GID1:"));
    println!("    [✓] Payload listo para transporte óptico offline.\n");

    // 9. Verificador escanea Base45, decodifica a SD-JWT y verifica offline
    println!(">>> PASO 9: Verificador procesa payload QR y ejecuta pipeline 100% offline (INV-01, INV-04, INV-05)");
    let decoded_presentation =
        gid_err(decode_presentation_from_base45(&qr_base45), "decode base45")?;
    let mut state_store = InMemoryStateStore::new(StateIntegrityKey::new([0x88; 32]));
    let policy = VerificationPolicy::default();
    let expected_req = VerificationRequest::new(
        nonce,
        verifier_id,
        UnixTime::from_seconds(now.as_seconds().saturating_add(300)),
        OperationClass::Default,
    );

    let snap_header = r#"{"alg":"ES256","typ":"statuslist+jwt"}"#;
    let snap_payload = format!(
        r#"{{"exp":{},"iat":{},"iss":"{}","status_list":{{"bits":2,"lst":"{}","uri":"{}"}}}}"#,
        now.as_seconds().saturating_add(86_400),
        now.as_seconds().saturating_sub(3_600),
        issuer_uri,
        pack_status_lst(2, &[0, 0, 0, 0]),
        status_list_uri
    );
    let snap_jwt = format!(
        "{}.{}.{}",
        base64url::encode(snap_header.as_bytes()),
        base64url::encode(snap_payload.as_bytes()),
        base64url::encode(&[0u8; 64])
    );
    let status_list = StatusListVerifier::parse(&snap_jwt).expect("status list parse");
    let snap = StatusSnapshot::new(status_list, status_list_uri, now);

    let verify_start = std::time::Instant::now();
    let result = VerifierPipeline::verify(
        &decoded_presentation,
        Some(&expected_req),
        &bundle,
        Some(&snap),
        &mut state_store,
        &policy,
        now,
        None,
    );
    let verify_duration = verify_start.elapsed();

    println!("    Estado de Verificación: {}", result.status().as_str());
    println!("    Tiempo de pipeline:     {:.2?}", verify_duration);
    assert_eq!(result.status(), VerificationStatus::Valid);

    // 10. Resumen y Trazabilidad
    println!("\n================================================================================");
    println!(
        " Flujo Offline E2E Completado con ÉXITO en {:.2?}",
        start_time.elapsed()
    );
    println!(" Trazabilidad verificada:");
    println!("  - REQ-PRES-005: Transporte QR Base45 verificado.");
    println!("  - REQ-PRES-007: Solicitud firmada de verificador registrado validada.");
    println!(
        "  - REQ-PRIV-001: Divulgación selectiva estricta (solo given_name y document_number)."
    );
    println!(
        "  - REQ-PERF-003: Pipeline offline completado en tiempo récord ({:.2?}).",
        verify_duration
    );
    println!("  - INV-01, INV-04, INV-05, INV-11: Todos los invariantes respetados.");
    println!("================================================================================");

    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_print_usage_does_not_panic() {
        print_usage();
    }

    #[test]
    fn test_in_process_demo_offline() {
        assert!(run_demo_offline().is_ok());
    }

    #[test]
    fn test_in_process_demo_flow_offline() {
        assert!(run_demo_flow_offline().is_ok());
    }

    #[test]
    fn test_in_process_subcommands_end_to_end() {
        let temp_dir = std::env::temp_dir().join(format!("pip_cli_inproc_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).expect("create temp dir");

        let issuer_jwk = temp_dir.join("issuer.jwk.json");
        let verifier_jwk = temp_dir.join("verifier.jwk.json");
        let bundle_file = temp_dir.join("bundle.json");
        let status_file = temp_dir.join("status.jwt");
        let cred_file = temp_dir.join("cred.txt");
        let req_file = temp_dir.join("req.b45");
        let pres_file = temp_dir.join("pres.b45");
        let wallet_db = temp_dir.join("wallet.sqlite");

        // dev-issuer stdout
        assert!(run_dev_issuer(&[]).is_ok());
        // dev-issuer file
        assert!(run_dev_issuer(&[
            "--out-jwk".to_string(),
            issuer_jwk.to_str().unwrap().to_string(),
            "--seed".to_string(),
            "42".to_string(),
        ])
        .is_ok());

        // dev-verifier stdout
        assert!(run_dev_verifier(&[]).is_ok());
        // dev-verifier file
        assert!(run_dev_verifier(&[
            "--out-jwk".to_string(),
            verifier_jwk.to_str().unwrap().to_string(),
            "--seed".to_string(),
            "84".to_string(),
        ])
        .is_ok());

        // dev-bundle stdout without verifier
        assert!(run_dev_bundle(&[
            "--jwk".to_string(),
            issuer_jwk.to_str().unwrap().to_string(),
        ])
        .is_ok());
        // dev-bundle file with verifier
        assert!(run_dev_bundle(&[
            "--issuer-uri".to_string(),
            "https://issuer.cedula.example.gov".to_string(),
            "--jwk".to_string(),
            issuer_jwk.to_str().unwrap().to_string(),
            "--verifier-id".to_string(),
            "https://verifier.example.com".to_string(),
            "--verifier-jwk".to_string(),
            verifier_jwk.to_str().unwrap().to_string(),
            "--out".to_string(),
            bundle_file.to_str().unwrap().to_string(),
        ])
        .is_ok());

        // dev-status stdout and file
        assert!(run_dev_status(&[]).is_ok());
        assert!(run_dev_status(&[
            "--issuer-uri".to_string(),
            "https://issuer.cedula.example.gov".to_string(),
            "--uri".to_string(),
            "https://status.cedula.example.gov/lists/2026-10".to_string(),
            "--bits".to_string(),
            "2".to_string(),
            "--values".to_string(),
            "0,0,0,0".to_string(),
            "--out".to_string(),
            status_file.to_str().unwrap().to_string(),
        ])
        .is_ok());

        // issue without disclosures (legacy)
        assert!(run_issue(&[
            "--issuer-uri".to_string(),
            "https://issuer.cedula.example.gov".to_string(),
            "--vct".to_string(),
            "https://credentials.gravital.io/vct/personal/id-v1".to_string(),
            "--seed".to_string(),
            "42".to_string(),
        ])
        .is_ok());

        // issue with disclosures and file output
        assert!(run_issue(&[
            "--issuer-uri".to_string(),
            "https://issuer.cedula.example.gov".to_string(),
            "--vct".to_string(),
            "https://credentials.gravital.io/vct/personal/id-v1".to_string(),
            "--status-uri".to_string(),
            "https://status.cedula.example.gov/lists/2026-10".to_string(),
            "--status-idx".to_string(),
            "0".to_string(),
            "--seed".to_string(),
            "42".to_string(),
            "--holder-seed".to_string(),
            "100".to_string(),
            "--with-disclosures".to_string(),
            "--out".to_string(),
            cred_file.to_str().unwrap().to_string(),
        ])
        .is_ok());

        // wallet-import in-memory
        assert!(run_wallet_import(&[
            "--credential".to_string(),
            cred_file.to_str().unwrap().to_string(),
            "--holder-seed".to_string(),
            "100".to_string(),
        ])
        .is_ok());

        // wallet-import with sqlite file
        let cred_id_out = temp_dir.join("id.txt");
        assert!(run_wallet_import(&[
            "--credential".to_string(),
            cred_file.to_str().unwrap().to_string(),
            "--holder-seed".to_string(),
            "100".to_string(),
            "--db".to_string(),
            wallet_db.to_str().unwrap().to_string(),
            "--out-id".to_string(),
            cred_id_out.to_str().unwrap().to_string(),
        ])
        .is_ok());

        // verify-request unsigned json stdout
        assert!(run_verify_request(&[
            "--verifier-id".to_string(),
            "https://verifier.example.com".to_string(),
            "--claims".to_string(),
            "given_name".to_string(),
        ])
        .is_ok());

        // verify-request signed base45 to file
        assert!(run_verify_request(&[
            "--verifier-id".to_string(),
            "https://verifier.example.com".to_string(),
            "--claims".to_string(),
            "given_name,document_number".to_string(),
            "--sign-seed".to_string(),
            "84".to_string(),
            "--format".to_string(),
            "base45".to_string(),
            "--out".to_string(),
            req_file.to_str().unwrap().to_string(),
        ])
        .is_ok());

        // wallet-present sd-jwt stdout
        assert!(run_wallet_present(&[
            "--request".to_string(),
            req_file.to_str().unwrap().to_string(),
            "--credential".to_string(),
            cred_file.to_str().unwrap().to_string(),
            "--bundle".to_string(),
            bundle_file.to_str().unwrap().to_string(),
            "--holder-seed".to_string(),
            "100".to_string(),
            "--format".to_string(),
            "sd-jwt".to_string(),
        ])
        .is_ok());

        // wallet-present base45 to file
        assert!(run_wallet_present(&[
            "--request".to_string(),
            req_file.to_str().unwrap().to_string(),
            "--credential".to_string(),
            cred_file.to_str().unwrap().to_string(),
            "--bundle".to_string(),
            bundle_file.to_str().unwrap().to_string(),
            "--holder-seed".to_string(),
            "100".to_string(),
            "--format".to_string(),
            "base45".to_string(),
            "--out".to_string(),
            pres_file.to_str().unwrap().to_string(),
        ])
        .is_ok());

        // verify offline with base45 presentation and request
        assert!(run_verify(&[
            "--presentation".to_string(),
            pres_file.to_str().unwrap().to_string(),
            "--request".to_string(),
            req_file.to_str().unwrap().to_string(),
            "--bundle".to_string(),
            bundle_file.to_str().unwrap().to_string(),
            "--status-snapshot".to_string(),
            status_file.to_str().unwrap().to_string(),
            "--now".to_string(),
            "1770000000".to_string(),
        ])
        .is_ok());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_subcommands_error_branches() {
        // Missing arguments
        assert!(run_dev_bundle(&[]).is_err());
        assert!(run_wallet_import(&[]).is_err());
        assert!(run_wallet_present(&[]).is_err());
        assert!(run_verify(&[]).is_err());
    }
}
