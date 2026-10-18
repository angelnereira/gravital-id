# Perfil PIP: Financiero v1 (`pip-financial-v1`)

> **Identificador normativo:** `pip-financial-v1`  
> **Versión:** `1.0.0` (Fase F8 / Tarea `F8.T09`)  
> **Estado:** Normativo  
> **Trazabilidad:** REQ-CRED-004, REQ-REC-005, REQ-REC-006, REQ-DEVSLOT-001..004, REQ-REC-004, REQ-REC-007; ADR-0009, ADR-0029; `ARCHITECTURE.md §16`

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

## 5. Procedimiento Normativo de Recuperación Institucional y Re-vinculación Financiera (`REQ-REC-005`, `REQ-REC-006`, `REQ-DEVSLOT-003`, `ADR-0009`, `ADR-0029`)

Debido a que las claves de titular residen en hardware criptográfico certificado con atestación (`StrongBox`/`TEE` o `Secure Enclave`, `REQ-KEY-002`, `INV-03`), su exportación está estrictamente prohibida. Ante la pérdida, robo o reemplazo del dispositivo, la re-emisión institucional de la credencial financiera se rige obligatoriamente por los siguientes requisitos normativos:

### 5.1 Marco Regulatorio Bancario y Verificación Fuera de Banda (`REQ-REC-005`)

1. **Cumplimiento SBP / GAFI (FATF):**
   - En observancia de las directrices de la **Superintendencia de Bancos de Panamá (SBP)** y las recomendaciones del GAFI sobre debida diligencia del cliente (CDD/KYC reforzado), la recuperación de una credencial financiera exige la verificación de la identidad del titular a través de:
     - **Canal Presencial en Sucursal:** Identificación física ante personal bancario autorizado, con cotejo biométrico dactilar o facial directo y presentación de documento de identidad oficial vigente; O
     - **Canal Remoto Bancario de Alta Seguridad:** Proceso digital autenticado mediante la combinación estricta de:
       1. Verificación de identidad oficial federada (`pip-identity-official-v1` o consulta biométrica en tiempo real al Tribunal Electoral / SVI),
       2. Prueba criptográfica de posesión de factor hardware bancario (token PKCS#11, llave FIDO2 / WebAuthn Nivel L3, o certificado cualificado de firma electrónica), y
       3. Prueba de vida biométrica activa (*active liveness*) con detección de inyección y suplantación.

### 5.2 Prohibición Taxativa de Correo Electrónico o Custodio Único (`REQ-REC-006`, `P-10`)

1. **Prohibición de Canal Inseguro:**
   - **Regla Inviolable:** Queda **terminantemente prohibida la recuperación, restauración o re-vinculación de credenciales financieras mediante enlaces web enviados por correo electrónico (*magic links* / email OTP) ni mediante mensajes SMS.** Los canales de mensajería no garantizan atestación criptográfica, son vulnerables a ataques de secuestro de SIM (*SIM swapping*), malware en buzones de correo y phishing.
2. **Control de Aprobación Dual (Four-Eyes Principle / Quórum Multipartito):**
   - La autorización de una re-vinculación de credencial financiera en los sistemas del emisor requiere obligatoriamente **doble control institucional** (aprobación conjunta de al menos dos entidades o roles distintos, p. ej. analista de operaciones + oficial de cumplimiento de prevención de blanqueo, o firma digital de HSM institucional de riesgo + validación de operador certificado). Ningún custodio ni empleado individual puede autorizar unilateralmente una re-vinculación financiera (`REQ-REC-006`, `P-10`).

### 5.3 Inexportabilidad de Claves y Revocación Atómica por Ranura (`REQ-DEVSLOT-001..004`, `ADR-0029`)

1. **Aislamiento de Ranura:**
   - El titular no recupera la clave privada de hardware anterior (inexportable por diseño de silicio).
   - El emisor identifica la ranura de dispositivo afectada (`device_class`: `mobile`, `card` u `other`).
   - El emisor revoca inmediatamente y de forma atómica el índice previo (`status_list_index`) de esa clase en la `TokenStatusList` de 2 bits (marcando `01 = revocado`), sin invalidar las credenciales en otras clases de dispositivo que el titular mantenga activas (`REQ-DEVSLOT-003`).
2. **Atestación de Nuevo Silicio y Re-emisión:**
   - La wallet genera un nuevo par de claves P-256 en el elemento seguro del nuevo dispositivo y presenta el certificado de atestación de hardware (`Key Attestation`).
   - El emisor valida la atestación, asigna un nuevo índice de estado y emite la nueva credencial `pip-financial-v1`.
   - Se publica el nuevo `IssuerStatusManifest` y se ancla la actualización en el `TrustLedger` registrando la evidencia criptográfica con cero datos personales ni identificadores en claro (`INV-02`).
