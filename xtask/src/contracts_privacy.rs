//! Verificación automatizada de ausencia de datos personales en las ABIs de contratos inteligentes (F6.T07).
//!
//! Trazabilidad:
//! - **REQ-LEDG-001:** Ninguna transacción debe contener datos personales, hashes de datos personales ni identificadores de titulares.
//! - **REQ-LEDG-007:** Emisores personas naturales deben registrarse con identificadores seudónimos opacos.
//! - **INV-02:** Cero datos personales en el ledger.

use std::fs;
use std::path::Path;

const FORBIDDEN_WORDS: &[&str] = &[
    "holder",
    "subject",
    "person",
    "given_name",
    "family_name",
    "firstname",
    "lastname",
    "fullname",
    "email",
    "phone",
    "mobile",
    "ssn",
    "tax_id",
    "document_number",
    "passport",
    "national_id",
    "birth",
    "salary",
    "income",
    "medical",
    "biometric",
    "fingerprint",
    "photo",
    "portrait",
    "postal_code",
    "zipcode",
];

// Verifies: REQ-LEDG-001, REQ-LEDG-007, INV-02
pub fn run_check_contracts_privacy(workspace_root: &Path) -> anyhow::Result<()> {
    let out_dir = workspace_root.join("contracts").join("out");
    if !out_dir.exists() {
        anyhow::bail!(
            "El directorio '{}' no existe. Ejecuta 'forge build' antes de verificar privacidad de contratos.",
            out_dir.display()
        );
    }

    let mut contracts_checked: usize = 0;
    let mut total_items_checked: usize = 0;

    let target_contracts = [
        ("TrustRegistry.sol", "TrustRegistry.json"),
        ("StatusAnchor.sol", "StatusAnchor.json"),
        ("GovernanceTimelock.sol", "GovernanceTimelock.json"),
    ];

    for (sol_dir, json_file) in &target_contracts {
        let file_path = out_dir.join(sol_dir).join(json_file);
        if !file_path.exists() {
            anyhow::bail!(
                "No se encontró el artefacto compilado '{}'. Ejecuta 'forge build' en contracts/.",
                file_path.display()
            );
        }

        let content = fs::read_to_string(&file_path)?;
        let parsed: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Error parseando JSON de {}: {e}", file_path.display()))?;

        let abi = parsed
            .get("abi")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                anyhow::anyhow!("No se encontró array 'abi' en {}", file_path.display())
            })?;

        for item in abi {
            total_items_checked = total_items_checked.saturating_add(1);
            inspect_abi_item(item, json_file)?;
        }

        contracts_checked = contracts_checked.saturating_add(1);
    }

    println!(
        "xtask: verificados {} contratos y {} elementos de ABI; 0 campos de datos personales detectados (REQ-LEDG-001, REQ-LEDG-007, INV-02).",
        contracts_checked, total_items_checked
    );

    Ok(())
}

fn inspect_abi_item(item: &serde_json::Value, contract_name: &str) -> anyhow::Result<()> {
    let item_type = item
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let item_name = item
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    check_name_for_pii(item_name, item_type, contract_name)?;

    if let Some(inputs) = item.get("inputs").and_then(serde_json::Value::as_array) {
        for input in inputs {
            inspect_param(input, item_type, item_name, contract_name, "input")?;
        }
    }

    if let Some(outputs) = item.get("outputs").and_then(serde_json::Value::as_array) {
        for output in outputs {
            inspect_param(output, item_type, item_name, contract_name, "output")?;
        }
    }

    Ok(())
}

fn inspect_param(
    param: &serde_json::Value,
    item_type: &str,
    item_name: &str,
    contract_name: &str,
    direction: &str,
) -> anyhow::Result<()> {
    let param_name = param
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    check_name_for_pii(
        param_name,
        &format!("{item_type} {item_name} {direction}"),
        contract_name,
    )?;

    if let Some(components) = param
        .get("components")
        .and_then(serde_json::Value::as_array)
    {
        for comp in components {
            inspect_param(comp, item_type, item_name, contract_name, direction)?;
        }
    }

    Ok(())
}

fn check_name_for_pii(name: &str, context: &str, contract_name: &str) -> anyhow::Result<()> {
    let lower = name.to_ascii_lowercase();
    for forbidden in FORBIDDEN_WORDS {
        if lower.contains(forbidden) {
            anyhow::bail!(
                "VIOLACIÓN DE PRIVACIDAD EN CONTRATO {contract_name} ({context}): el identificador '{name}' contiene el término prohibido '{forbidden}'. (REQ-LEDG-001, INV-02)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_abi_passes() {
        let clean_json = serde_json::json!({
            "type": "event",
            "name": "IssuerRegistered",
            "inputs": [
                { "name": "issuerId", "type": "bytes32", "indexed": true },
                { "name": "uri", "type": "string", "indexed": false },
                { "name": "validFrom", "type": "uint64", "indexed": false }
            ]
        });
        assert!(inspect_abi_item(&clean_json, "CleanContract").is_ok());
    }

    #[test]
    fn test_pii_in_param_fails() {
        let pii_json = serde_json::json!({
            "type": "function",
            "name": "registerCitizen",
            "inputs": [
                { "name": "holderName", "type": "string" },
                { "name": "national_id", "type": "bytes32" }
            ]
        });
        assert!(inspect_abi_item(&pii_json, "VulnerableContract").is_err());
    }

    #[test]
    fn test_pii_in_event_name_fails() {
        let pii_event = serde_json::json!({
            "type": "event",
            "name": "PersonRegistered",
            "inputs": []
        });
        assert!(inspect_abi_item(&pii_event, "VulnerableContract").is_err());
    }
}
