# Perfil PIP: Documento de Identidad Portable v1 (`pip-identity-v1`)

> **Identificador normativo:** `pip-identity-v1`  
> **Versión:** `1.0.0-draft` (Fase F19 / Tarea `F19.T11`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-18  
> **Trazabilidad:** REQ-IDDOC-001, REQ-IDDOC-002, REQ-IDDOC-003, REQ-UNIQ-001, REQ-UNIQ-002, REQ-UNIQ-003, REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-CRED-004, REQ-PRES-007, REQ-CARD-003, REQ-PROX-001; ADR-0021, ADR-0024, ADR-0026, ADR-0028, ADR-0029; `ARCHITECTURE.md §16`, `§23`, `§24`

---

## 1. Alcance y Casos de Uso

El perfil `pip-identity-v1` define los requisitos técnicos, esquemas de datos y controles de privacidad para portar documentos de identidad personal con fotografía facial (**retrato**), tales como la cédula de identidad personal o credenciales de identidad verificada equivalentes, tanto en dispositivos móviles (wallets Android/iOS) como en tarjetas físicas sin contacto (Java Card):

* Acreditación presencial de identidad con inspección visual del retrato por NFC o BLE (control de acceso a edificios, trámites bancarios o institucionales en ventanilla, hoteles, puntos de atención).
* Acreditación de mayoría de edad (`age_over_18`, `age_over_21`) sin revelar fecha de nacimiento, número de documento ni retrato (por NFC en un solo toque o por QR).
* Validación remota o telefónica mediante código numérico de sesión (`SessionCode`, `ADR-0025`).

### 1.1 Separación Estricta entre Credencial Oficial y Credencial Derivada (`REQ-IDDOC-001`)

Para evitar cualquier ambigüedad jurídica o de confianza (`R-19`, `ADR-0026`), este perfil define **dos variantes con identificadores de tipo (`vct`) distintos y mutuamente excluyentes**:

| Variante | Identificador `vct` | Emisores Autorizados en el `TrustBundle` | Alcance |
|---|---|---|---|
| **Oficial** | `urn:gravital-id:vct:pip-identity-official-v1` | Exclusivamente la autoridad estatal de registro civil / identidad nacional (p. ej. el Tribunal Electoral en la República de Panamá bajo la Ley 68 de 2015 y el Decreto N.° 43 de 8 de octubre de 2024). | Documento oficial emitido por el Estado dentro del marco de confianza. |
| **Derivada** | `urn:gravital-id:vct:pip-identity-derived-v1` | Entidades reguladas o acreditadas (bancos, instituciones financieras, proveedores de KYC autorizados) que verificaron el documento oficial del titular mediante `IdentityVerificationPort` (p. ej. Servicio de Verificación de Identidad — **SVI** del Tribunal Electoral). | Identidad verificada por el emisor para uso dentro de las organizaciones que confían en dicho emisor. |

Ningún emisor no estatal puede recibir autorización en el `TrustRegistry` ni en el `TrustBundle` para emitir `urn:gravital-id:vct:pip-identity-official-v1`.

---

## 2. Parámetros Técnicos del Perfil

| Parámetro | Valor Normativo | Justificación |
|---|---|---|
| **Formato de Credencial** | SD-JWT VC (`typ: dc+sd-jwt`) | RFC 9901 y `draft-ietf-oauth-sd-jwt-vc-19`. |
| **Algoritmo de Firma** | `ES256` (P-256 + SHA-256) | Compatibilidad universal en TEE/StrongBox, Secure Enclave y tarjetas Java Card. |
| **Almacenamiento de Clave de Titular (`cnf`)** | **Hardware Obligatorio** (`StrongBox`/`TEE` en Android, `Secure Enclave` en iOS, Elemento Seguro en Java Card) | Impide clonación del documento de identidad (`REQ-CARD-001`, `INV-03`). |
| **Atestación de Clave y Factor de Dispositivo** | Obligatoria (`ADR-0029`, `REQ-DEVSLOT-002`): `Key Attestation`/`App Attest` (+ `IMEI` en modo MDM/Device Owner) en móvil y `CPLC` en tarjeta física | Garantiza silicio genuino y aplica la regla de **ranura única por clase de factor** (`mobile`, `card`, `other`). |
| **Exportación de Clave en Migración** | **Estrictamente Prohibida** | Ante cambio o pérdida de soporte se revoca el índice anterior de esa misma clase y se re-emite (`Nivel 3`, `REQ-DEVSLOT-003`). |
| **Frescura Máxima de Estado** | $\le 24\text{ horas}$ (trámites con `document_number`/`portrait`) · $\le 7\text{ días}$ (acceso físico / mayoría de edad) | Balance entre operación offline prolongada y revocación de documentos extraviados. |
| **Modo de Token Status List** | 2 bits (`00 = activo`, `01 = revocado`, `10 = suspendido`) con índice independiente por clase de dispositivo | Permite revocar solo el teléfono o solo la tarjeta física sin invalidar los demás factores (`REQ-DEVSLOT-003`). |
| **Protección contra Replay** | Obligatoria (KB-JWT con `nonce` ligado al `transcript_hash` en proximidad) | Previene repetición y ataques de sesión cruzada (`REQ-PROX-002`). |
| **Solicitud de Verificador Firmada** | **Obligatoria** al solicitar `document_number`, `birth_date` o `portrait`; opcional para predicados `age_over_*` | Impide que un verificador anónimo recolecte números de cédula o fotografías (`REQ-PRES-007`). |
| **Emisión por Lotes** | Recomendada en móvil ($\ge 8$ copias) y en tarjeta física ($\ge 4$ ranuras si la memoria del chip lo permite) | Mitiga la correlación entre verificadores (`REQ-CRED-006`, `REQ-KEY-008`, `R-18`). |

---

## 3. Esquemas JSON Canónicos de Referencia

Todos los atributos de identidad enumerados en `properties` se emiten como **divulgaciones selectivas individuales (`_sd`)** con sal de $\ge 128$ bits (`REQ-CRED-002`, `REQ-IDDOC-003`).

### 3.1 Variante Oficial (`urn:gravital-id:vct:pip-identity-official-v1`)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "given_name": { "type": "string" },
    "family_name": { "type": "string" },
    "birth_date": { "type": "string", "format": "date" },
    "age_over_18": { "type": "boolean" },
    "age_over_21": { "type": "boolean" },
    "nationality": { "type": "string", "pattern": "^[A-Z]{2,3}$" },
    "document_number": { "type": "string" },
    "document_expiry": { "type": "string", "format": "date" },
    "issuing_authority": { "type": "string" },
    "issuing_country": { "type": "string", "pattern": "^[A-Z]{2,3}$" },
    "sex": { "type": "string", "enum": ["M", "F", "X"] },
    "place_of_birth": { "type": "string" },
    "portrait": { "type": "string" },
    "device_class": { "type": "string", "enum": ["mobile", "card", "other"] }
  },
  "required": [
    "given_name",
    "family_name",
    "birth_date",
    "age_over_18",
    "nationality",
    "document_number",
    "document_expiry",
    "issuing_authority",
    "issuing_country",
    "portrait"
  ]
}
```

### 3.2 Variante Derivada (`urn:gravital-id:vct:pip-identity-derived-v1`)

Añade los campos de trazabilidad de la verificación de origen (`evidence_type`, `verified_at`) y clase de soporte (`device_class`):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "given_name": { "type": "string" },
    "family_name": { "type": "string" },
    "birth_date": { "type": "string", "format": "date" },
    "age_over_18": { "type": "boolean" },
    "age_over_21": { "type": "boolean" },
    "nationality": { "type": "string", "pattern": "^[A-Z]{2,3}$" },
    "document_number": { "type": "string" },
    "document_expiry": { "type": "string", "format": "date" },
    "issuing_authority": { "type": "string" },
    "issuing_country": { "type": "string", "pattern": "^[A-Z]{2,3}$" },
    "sex": { "type": "string", "enum": ["M", "F", "X"] },
    "portrait": { "type": "string" },
    "evidence_type": {
      "type": "string",
      "enum": ["national_id_in_person", "national_id_liveness", "passport_in_person", "passport_liveness"]
    },
    "verified_at": { "type": "string", "format": "date-time" },
    "device_class": { "type": "string", "enum": ["mobile", "card", "other"] }
  },
  "required": [
    "given_name",
    "family_name",
    "age_over_18",
    "nationality",
    "document_number",
    "evidence_type",
    "verified_at"
  ]
}
```

---

## 4. Reglas Normativas del Retrato (`portrait`) y Transportes Permitidos (`REQ-IDDOC-002`)

1. **Codificación y Formato de Imagen:**
   - El claim `portrait` contiene la codificación **Base64URL sin padding** de una imagen **JPEG Baseline (ISO/IEC 10918-1 / JFIF)**.
   - El emisor y el verificador **DEBEN** validar que los bytes decodificados:
     - comiencen con el marcador `SOI` + `APP0/DQT/SOF0` (`0xFF 0xD8 0xFF`) y terminen con `EOI` (`0xFF 0xD9`),
     - tengan dimensiones entre $160 \times 200$ y $480 \times 600$ píxeles,
     - **carezcan por completo de segmentos `APP1`–`APP15` (EXIF, XMP, GPS) y `COM` (comentarios)** para impedir fugas de metadatos o vectores de ataque contra visores de imagen.
2. **Límites de Tamaño:**
   - **Presupuesto objetivo (tarjetas físicas y toque NFC rápido):** $\le 16\,384\text{ bytes}$ (16 KiB) en binario crudo ($\le 21\,848$ caracteres Base64URL).
   - **Tope absoluto de rechazo:** $24\,576\text{ bytes}$ (24 KiB) en binario crudo ($32\,768$ caracteres Base64URL). Cualquier retrato que supere este límite se rechaza con `GID-E3004` (`SchemaValidationFailed`) o `GID-E8002` (`ProximityMessageTooLarge`).
3. **Restricción por Transporte:**
   - **Permitido:** NFC (`GID-APDU`), BLE y flujos en línea (`SessionCode` / OID4VP), siempre dentro de un sobre cifrado con HPKE (`REQ-PROX-001`).
   - **Prohibido en Código QR:** El retrato **NUNCA** se incluye en presentaciones ópticas por código QR. Si una consulta QR solicita `portrait` como obligatorio, el titular rechaza la operación por QR con `GID-E8002` (`ProximityMessageTooLarge`).

---

## 5. Niveles de Autorización en Tarjeta Física y Teléfono (`REQ-CARD-003`, `REQ-PROX-006`)

| Nivel | Claims Cubiertos | Requisito en Tarjeta Física Java Card | Requisito en Wallet Móvil (HCE / BLE / QR) | Solicitud Firmada del Verificador |
|---|---|---|---|---|
| **Nivel 0 (Básico / Predicados)** | `age_over_18`, `age_over_21` (y `given_name` solo si el titular lo preautorizó) | Sin PIN (respuesta en un solo toque). | Credencial armada por el titular ($\le 60\text{ s}$). | Opcional. |
| **Nivel 1 (Identidad Completa / Sensible)** | `document_number`, `birth_date`, `portrait`, `family_name`, `nationality`, `document_expiry`, `sex`, `place_of_birth` | **Exige `VERIFY PIN`** (`SW=6982` / `GID-E8005` si no se ha verificado; bloqueo en `SW=6983` / `GID-E8006` tras agotar intentos). | **Exige confirmación explícita con biometría/PIN del dispositivo** (segundo toque `SW=6985` / `GID-E8004` si no estaba armado para ese verificador). | **Obligatoria (`REQ-PRES-007`)**. |

---

## 6. Política de Retención y Privacidad del Verificador (`REQ-IDDOC-002`, `REQ-IDDOC-003`)

1. **No Persistencia del Retrato:** El SDK de verificación entrega los bytes validados de `portrait` en memoria volátil exclusivamente para su renderizado inmediato ante el operador humano durante la inspección. El verificador **NO DEBE** guardar la imagen en disco, base de datos ni caché tras cerrar la pantalla de resultado, salvo que exista una obligación legal expresa (p. ej. expediente KYC bancario bajo la Ley 23 de 2015) declarada en la política.
2. **Prohibición de Correlación por `document_number`:** El campo `document_number` es un atributo civil de divulgación selectiva; ningún componente del protocolo, relay o contrato lo utiliza como índice, clave primaria de transporte ni identificador de sesión (`INV-02`, `REQ-IDDOC-003`).

---

## 7. Procedimiento de Recuperación y Revocación por Extravío (`Nivel 3`)

1. **Pérdida o Robo de Tarjeta Física o Teléfono:** Dado que la clave privada reside en hardware no exportable (`REQ-CARD-001`), el titular reporta el extravío ante el emisor (o mediante su clave de recuperación en línea) y el emisor actualiza el índice correspondiente en la `Token Status List` a `01` (revocado) o `10` (suspendido) (`REQ-CARD-005`).
2. **Efecto en Verificadores Offline:** En cuanto los verificadores sincronizan el siguiente snapshot de estado, cualquier toque con la tarjeta o teléfono extraviado produce `VerificationResult::Invalid` con código `GID-E4005` (`CredentialRevoked`) o `GID-E4006` (`CredentialSuspended`).

---

## 8. Unicidad Ciudadana por País y Regla de Ranura Única por Clase de Dispositivo (`ADR-0028`, `ADR-0029`)

1. **Perfiles Nacionales y Tribunal Electoral de Panamá (`REQ-UNIQ-001`, `REQ-UNIQ-002`):**
   - Para `issuing_country = "PA"`, el número de documento se normaliza según el formato canónico del **Tribunal Electoral de la República de Panamá** (`^(?:(?:[1-9]|1[0-3]|E|N|PE)(?:AV|PI)?|[1-9](?:AV|PI))-[0-9]{1,5}-[0-9]{1,6}$`) y se verifica contra el **Servicio de Verificación de Identidad (SVI)** o la Cédula Digital (**Decreto N.° 43 de 8 de octubre de 2024**).
   - El emisor deriva una etiqueta ciega `UniquenessTag` mediante **VOPRF (RFC 9497, P-256)** o HMAC en HSM sobre el identificador normalizado (`INV-02`, sin publicar hash crudo en blockchain). Si el ciudadano ya tiene un Gravital ID registrado, se rechaza el alta duplicada con `GID-E2010` (`CitizenIdentityAlreadyRegistered`) y se redirige al flujo de ingreso o reemplazo de soporte (`REQ-UNIQ-003`).
2. **Ranura Única por Clase de Factor de Dispositivo (`REQ-DEVSLOT-001`..`004`):**
   - Un titular puede mantener su credencial activa simultáneamente en **distintas clases de factor** (`device_class`: máximo 1 `"mobile"`, máximo 1 `"card"` tipo Visa Java Card y máximo 1 `"other"`), pero **nunca** en dos dispositivos de la misma clase al mismo tiempo.
   - Si solicita vincular un segundo teléfono o una segunda tarjeta sin orden firmada de reemplazo, el emisor rechaza con `GID-E2011` (`DuplicateDeviceClassActive`); con orden de reemplazo, el emisor revoca atómicamente el `status_list_index` del soporte reemplazado en esa misma clase sin afectar a las demás clases.

