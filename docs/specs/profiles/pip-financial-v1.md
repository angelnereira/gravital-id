# Perfil PIP: Financiero v1 (`pip-financial-v1`)

> **Identificador normativo:** `pip-financial-v1`  
> **Versión:** `1.0.0-draft` (Fase F0 / Tarea `F0.T15`)  
> **Estado:** Normativo / En revisión  
> **Trazabilidad:** REQ-CRED-004, REQ-REC-005; `ARCHITECTURE.md §16`

---

## 1. Alcance y Casos de Uso

El perfil `pip-financial-v1` define los requisitos de máxima seguridad y certeza para transacciones bancarias, pagos regulados, onboarding financiero y cumplimiento KYC/AML:
* Pasaportes de identidad KYC reutilizables para apertura de cuentas y contratación de productos.
* Autorizaciones de transferencias y pagos de alto valor.
* Acreditación de residencia fiscal e ingresos auditados.
* Integración con plataformas de pago (Gravital Pay, Plenty-Pay).

---

## 2. Parámetros Técnicos del Perfil

| Parámetro | Valor Normativo | Justificación |
|---|---|---|
| **Formato de Credencial** | SD-JWT VC (`typ: dc+sd-jwt`) | RFC 9901 y `draft-ietf-oauth-sd-jwt-vc-19`. |
| **Algoritmo de Firma** | `ES256` (P-256 + SHA-256) | Criptografía asimétrica estándar bancaria. |
| **Almacenamiento de Clave de Titular** | **Hardware Obligatorio con Atestación** | Requiere Secure Enclave (iOS) o StrongBox/TEE (Android). |
| **Atestación de Clave de Dispositivo** | Obligatoria en Emisión | Validación de certificado de atestación de clave (Key Attestation). |
| **Exportación de Clave en Migración** | **Estrictamente Prohibida** | Las claves de hardware nunca abandonan el módulo criptográfico. |
| **Frescura Máxima de Estado** | 30 minutos (transacciones) / 4 horas (consultas) | Riesgo de fraude financiero requiere estado actualizado. |
| **Modo de Token Status List** | 2 bits (`00 = activo`, `01 = revocado`, `10 = suspendido`) | Soporta suspensiones cautelares por investigación de fraude. |
| **Protección contra Replay** | Obligatoria (KB-JWT con `nonce` único de sesión) | Prevenir reutilización de autorizaciones financieras. |
| **Solicitud de Verificador Firmada** | **Obligatoria** | El titular solo divulga atributos a entidades reguladas registradas. |
| **Emisión por Lotes** | Recomendada con índices y claves independientes | Evitar correlación entre transacciones y comercios. |

---

## 3. Esquema JSON Canónico de Referencia

Ejemplo para credencial KYC financiera:
* `vct`: `https://credentials.gravital.io/vct/financial/kyc-v1`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "legal_name": { "type": "string" },
    "tax_id": { "type": "string" },
    "id_document_type": { "type": "string", "enum": ["passport", "national_id"] },
    "id_document_number": { "type": "string" },
    "kyc_tier": { "type": "string", "enum": ["tier1", "tier2", "tier3"] },
    "aml_cleared": { "type": "boolean" },
    "aml_cleared_at": { "type": "string", "format": "date-time" },
    "pep_status": { "type": "boolean" },
    "country_of_residence": { "type": "string", "pattern": "^[A-Z]{3}$" }
  },
  "required": ["legal_name", "tax_id", "kyc_tier", "aml_cleared"]
}
```

---

## 4. Política de Retención y Cumplimiento Regulatorio

1. **Evidencia de Cumplimiento:** Los verificadores financieros pueden retener legalmente la evidencia criptográfica de la verificación (JWS completo verificado, prueba de posesión de clave, estado y hash de revocación) según los plazos fijados por regulaciones de prevención de blanqueo de capitales (típicamente 5 a 10 años).
2. **Cifrado de Evidencias:** Todo registro de auditoría archivado en el verificador debe cifrarse en reposo con KMS institucional y control de acceso estricto.

---

## 5. Procedimiento de Recuperación (Nivel 3 — Institucional)

Debido a que las claves de hardware no son exportables:
1. **Pérdida de Dispositivo:** El titular no recupera la clave de dispositivo anterior.
2. **Protocolo de Re-vinculación:** Si el emisor lo autoriza, la wallet presenta la clave de recuperación específica con un factor biométrico o de segundo paso (TOTP / Band-All).
3. **Re-emisión:** El emisor revoca inmediatamente el índice anterior en la Token Status List (marcando `01 = revocado`) y emite una nueva credencial vinculada a la nueva clave de hardware generada en el dispositivo nuevo.
