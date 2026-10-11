# Especificación PIP: Raíz de Confianza, Trust Bundle y Manifiesto de Estado

> **Identificador normativo:** `SPEC-PIP-TRUST-001`  
> **Versión:** `0.1.0-draft` (Fase F0)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-TRUST-001..010, REQ-STAT-005, REQ-STAT-006, REQ-STAT-008, REQ-LEDG-004; ADR-0010, ADR-0016, ADR-0017, ADR-0018, ADR-0020; P-04, P-08, P-10, P-14, P-15; INV-01, INV-05, INV-06, INV-16.

---

## 1. Alcance y Principios de Diseño

Esta especificación define la estructura binaria y JSON, los algoritmos criptográficos, las reglas de derivación determinista, los límites operacionales y la máquina de estados para:

1. **La Raíz de Confianza (`TrustRoot`)**: documento emitido infrecuentemente por la Autoridad del Marco de Confianza (TFA) mediante claves fuera de línea (*cold keys*), que establece las claves de gobernanza y el conjunto autorizado de firmantes de bundles.
2. **El Lote de Confianza (`TrustBundle`)**: instantánea verificable del estado del registro público de emisores en blockchain, cofirmada por un umbral $k$-de-$n$ de operadores independientes para su consumo por verificadores desconectados (*offline*).
3. **El Manifiesto de Estado del Emisor (`IssuerStatusManifest`)**: documento firmado periódicamente por cada emisor autorizado que vincula las ubicaciones y hashes de sus listas de revocación y estado (Token Status Lists).

### Invariantes aplicados

* **INV-01 / INV-06:** La verificación de credenciales por el cliente no efectúa consultas de red; las claves autorizadas se obtienen exclusivamente del `TrustBundle` validado contra la `TrustRoot`.
* **INV-05:** Evaluación en modo *fail-closed*: cualquier inconsistencia, corrupción, firma faltante o incumplimiento de umbral invalida el documento de confianza.
* **INV-16:** Ninguna clave individual puede comprometer la confianza offline. Todo cambio o emisión requiere un umbral multifirma $k$-de-$n$.
* **REQ-TRUST-010 / ADR-0017:** El `TrustBundle` **no** contiene punteros ni hashes de listas de revocación. Las listas de estado evolucionan a un ritmo independiente y se gestionan a través del Manifiesto de Estado.

---

## 2. Formato de la Raíz de Confianza (`TrustRoot`)

### 2.1 Esquema del Payload JSON

El payload de la raíz de confianza contiene la definición de autoridades y firmantes activos. Debe serializarse en formato JSON canónico (RFC 8785 - JCS) previo a su firma.

```json
{
  "framework_id": "pip-global-mainnet",
  "root_version": 1,
  "bundle_epoch": 1,
  "issued_at": 1791633600,
  "valid_until": 1823169600,
  "chain_id": 1,
  "registry_address": "0x1234567890123456789012345678901234567890",
  "root_keys": [
    {
      "kid": "tfa-root-2026-01",
      "crv": "P-256",
      "kty": "EC",
      "x": "WKn-LZ53nmEa2Qt_P4fG8bNlT2L6lM...",
      "y": "c8D5R0YwQz1v3NxT..."
    },
    {
      "kid": "tfa-root-2026-02",
      "crv": "P-256",
      "kty": "EC",
      "x": "...",
      "y": "..."
    },
    {
      "kid": "tfa-root-2026-03",
      "crv": "P-256",
      "kty": "EC",
      "x": "...",
      "y": "..."
    }
  ],
  "root_threshold": 2,
  "bundle_signers": [
    {
      "operator": "operator-alpha.org",
      "kid": "signer-alpha-2026a",
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "..."
      }
    },
    {
      "operator": "operator-beta.com",
      "kid": "signer-beta-2026a",
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "..."
      }
    },
    {
      "operator": "operator-gamma.io",
      "kid": "signer-gamma-2026a",
      "jwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "..."
      }
    }
  ],
  "bundle_threshold": 2
}
```

### 2.2 Definición de Campos

| Campo | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `framework_id` | String | Sí | Identificador canónico del ecosistema o marco de confianza (ASCII imprimible, máx 64 caracteres). |
| `root_version` | Entero positivo (`u64`) | Sí | Versión estrictamente monotónica creciente de la raíz dentro del marco. |
| `bundle_epoch` | Entero positivo (`u64`) | Sí | Época de bundles vigente. Reinicia la numeración de bundles ante avance forzado (ver §6). |
| `issued_at` | Entero positivo (`u64`) | Sí | Marca de tiempo Unix en segundos del momento de emisión. |
| `valid_until` | Entero positivo (`u64`) | Sí | Marca de tiempo Unix en segundos que define la expiración máxima de la raíz. |
| `chain_id` | Entero positivo (`u64`) | Sí | ID de la red blockchain de origen (EIP-155). |
| `registry_address` | String | Sí | Dirección hexadecimal `0x` canónica del contrato de registro en la red indicada. |
| `root_keys` | Array de JWK | Sí | Claves públicas autorizadas para firmar la siguiente raíz de confianza. Mínimo 1, máximo 32. |
| `root_threshold` | Entero positivo (`u32`) | Sí | Número mínimo $k$ de firmas requeridas para autorizar una rotación de raíz ($1 \le k \le |root\_keys|$). |
| `bundle_signers` | Array de Objetos | Sí | Conjunto de operadores y claves públicas autorizadas para cofirmar `TrustBundle`. |
| `bundle_threshold` | Entero positivo (`u32`) | Sí | Número mínimo $k$ de operadores distintos requeridos para validar un `TrustBundle` ($1 \le k \le |bundle\_signers|$). |

### 2.3 Sobre JWS y Encadenamiento

La raíz se distribuye encapsulada en una estructura JWS con Serialización JSON General (RFC 7515 §7.2):

```json
{
  "payload": "<base64url(canonical_json(TrustRoot))>",
  "signatures": [
    {
      "protected": "<base64url({\"alg\":\"ES256\",\"kid\":\"tfa-root-2026-01\"})>",
      "signature": "<base64url(sig1)>"
    },
    {
      "protected": "<base64url({\"alg\":\"ES256\",\"kid\":\"tfa-root-2026-02\"})>",
      "signature": "<base64url(sig2)>"
    }
  ]
}
```

#### Regla de Encadenamiento en Rotación
Para actualizar una raíz instalada $R_N$ hacia una nueva raíz $R_{N+1}$:
1. $R_{N+1}.root\_version > R_N.root\_version$.
2. El documento $R_{N+1}$ **debe contener al menos**:
   - $\ge R_N.root\_threshold$ firmas válidas emitidas por claves pertenecientes a $R_N.root\_keys$.
   - $\ge R_{N+1}.root\_threshold$ firmas válidas emitidas por claves pertenecientes a $R_{N+1}.root\_keys$.
3. Si $R_{N+1}.bundle\_epoch > R_N.bundle\_epoch$, se descarta inmediatamente el `TrustBundle` activo en el cliente y se restablece el contador de versión de bundle a 0.

---

## 3. Formato del Lote de Confianza (`TrustBundle`)

### 3.1 Esquema del Payload JSON

El `TrustBundle` es una proyección determinista del estado consolidado en un bloque finalizado de la blockchain:

```json
{
  "framework_id": "pip-global-mainnet",
  "bundle_epoch": 1,
  "bundle_version": 1420,
  "chain_id": 1,
  "registry_address": "0x1234567890123456789012345678901234567890",
  "finalized_block_number": 21890450,
  "finalized_block_hash": "0x4a8f9b...",
  "issued_at": 1791633600,
  "valid_until": 1792238400,
  "issuers": [
    {
      "issuer_id": "iss-panama-tribunal-electoral",
      "profiles": ["pip-personal-v1"],
      "vcts": [
        "https://credentials.gob.pa/vct/cedula-digital-v1",
        "https://credentials.gob.pa/vct/residencia-v1"
      ],
      "valid_from": 1767225600,
      "valid_until": 1893456000,
      "state": "active",
      "status_keys": [
        {
          "kid": "te-status-2026-01",
          "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "...",
            "y": "..."
          }
        }
      ],
      "keys": [
        {
          "kid": "te-iss-2026-ecdsa-01",
          "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "...",
            "y": "..."
          },
          "state": "active",
          "state_since": 1767225600
        },
        {
          "kid": "te-iss-2025-ecdsa-02",
          "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "...",
            "y": "..."
          },
          "state": "retired",
          "state_since": 1788220800
        }
      ]
    }
  ],
  "verifiers": [],
  "policies": [
    {
      "profile_id": "pip-personal-v1",
      "version": "1.0.0",
      "policy_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

### 3.2 Definición de Campos y Estados de Claves de Emisor

* **`state` del Emisor:**
  * `active`: El emisor está plenamente autorizado para emitir en los perfiles y `vcts` indicados.
  * `suspended`: Suspensión administrativa temporal. Nuevas emisiones se rechazan; verificación produce `Unverifiable`.
* **`keys[].state` (Estado de la Clave de Emisor, ARCHITECTURE §11.6):**
  * `active`: Clave plenamente vigente. Emisiones y presentaciones válidas.
  * `retired`: Clave retirada de servicio ordenadamente desde `state_since`. Presentaciones válidas **solo si** `iat < state_since`. Nuevas emisiones firmadas con esta clave se consideran inválidas.
  * `suspended`: Clave presuntamente comprometida o en revisión técnica. Cualquier verificación de credencial firmada con esta clave resulta en `Unverifiable` (evidencia `IssuerKeySuspended`). Si la suspensión caduca sin confirmación, revierte a su estado previo.
  * `compromised`: Clave irrevocablemente comprometida. **Todas las credenciales firmadas con esta clave son Inválidas (`Invalid`)**, independientemente del `iat`.

---

## 4. Derivación Determinista del Payload

Para que múltiples operadores independientes ($n$) emitan firmas sobre el mismo contenido binario sin coordinar sesiones interactivas:

1. **Entrada Canónica:** El estado finalizado de los contratos `TrustRegistry` en un bloque determinado con etiqueta `finalized` ($B$).
2. **Determinismo Temporal:**
   * `finalized_block_number`: Número del bloque finalizado $B$.
   * `finalized_block_hash`: Hash criptográfico de dicho bloque.
   * `issued_at`: Marca de tiempo del bloque $B$ en el ledger.
   * `valid_until`: $\text{issued\_at} + \Delta T_{\text{bundle}}$ (donde $\Delta T_{\text{bundle}}$ es un parámetro inmutable fijado por el marco, típicamente 7 días / 604,800 segundos).
3. **Canonicalización JSON (RFC 8785 - JCS):**
   * Ordenación lexicográfica estricta de claves en todos los objetos JSON (código Unicode UTF-16).
   * Sin espacios en blanco superfluos (`{"a":1,"b":2}`).
   * Números enteros serializados en representación decimal sin notación exponencial ni ceros a la izquierda.
   * Strings serializados en UTF-8 canónico con escape estándar.
4. **Firma Independiente:** Cada operador indexa de forma aislada, calcula el payload $P$, genera $\text{JCS}(P)$ y genera su firma JWS con su clave de operador autorizada en `TrustRoot`.

---

## 5. Algoritmo de Verificación y Máquina de Estados del Cliente

Al recibir un nuevo `TrustBundle` (vía sincronización periódica, Bluetooth, USB o código QR administrativo), el motor de verificación ejecuta secuencialmente:

```text
[Recepción de Bundle]
       │
       ▼
1. Comprobación de Límites y Sintaxis (JWS JSON válido, tamaño <= 512 KB)
       │ Fallo ──> Rechazo (Incompatible / Descartado)
       ▼
2. Comprobación de Marco y Época:
   bundle.framework_id == root.framework_id ?
   bundle.bundle_epoch == root.bundle_epoch ?
       │ No ────> Rechazo (EpochMismatch)
       ▼
3. Anti-Rollback de Versión:
   bundle.bundle_version > current_state.bundle_version ?
       │ No ────> Rechazo (VersionRollbackDetected)
       ▼
4. Verificación de Firmantes y Umbral:
   Identificar firmas válidas emitidas por operadores de root.bundle_signers.
   ¿Número de operadores distintos con firma válida >= root.bundle_threshold?
       │ No ────> Rechazo (InsufficientSignatures / Fail-Closed)
       ▼
5. Comprobación de Vigencia Temporal:
   now >= bundle.issued_at ?
   now <= bundle.valid_until ?
       │ Expirado ──> Aceptación condicional / Unverifiable según perfil
       ▼
6. Actualización Atómica en VerifierStateStore:
   Reemplazo transaccional del bundle en memoria y almacenamiento local.
```

---

## 6. Recuperación ante Avance Forzado de Versión (*Forced Version Advance*)

### Amenaza
Si un grupo de operadores maliciosos o claves comprometidas que superen el umbral $k$-de-$n$ emitieran un bundle con una versión extrema (por ejemplo, `bundle_version: 999999999`), el mecanismo anti-rollback bloquearía permanentemente cualquier bundle legítimo posterior generado por los operadores honestos.

### Mitigación
1. La TFA convoca a las claves frías de la raíz (`root_keys`).
2. Se emite una nueva raíz $R_{N+1}$ con:
   * `bundle_epoch`: Incrementado en +1 respecto a la época comprometida.
   * `bundle_signers`: Lista purgada que remueve a los operadores comprometidos e incorpora nuevos firmantes legítimos.
   * `root_version`: $R_N.root\_version + 1$.
3. Al recibir $R_{N+1}$ con el encadenamiento de firmas válido (§2.3), el cliente de verificación descarta el bundle de la época anterior y reinicia `bundle_version = 0`, desbloqueando el sistema.

---

## 7. Manifiesto de Estado del Emisor (`IssuerStatusManifest`)

### 7.1 Estructura

Cada emisor gestiona y firma su propio manifiesto de estado para desacoplar el estado de revocación de las actualizaciones del `TrustBundle`:

```json
{
  "issuer_id": "iss-panama-tribunal-electoral",
  "manifest_version": 845,
  "issued_at": 1791633600,
  "valid_until": 1791720000,
  "status_lists": [
    {
      "status_list_id": "sl-cedula-2026-part1",
      "type": "TokenStatusList",
      "uri": "https://credentials.gob.pa/status/cedula-2026-part1.jwt",
      "sha256": "8f4e2b...",
      "valid_until": 1791720000
    }
  ]
}
```

### 7.2 Reglas de Validación
1. **Firma:** El manifiesto debe estar firmado en formato JWS por una de las claves declaradas en `status_keys` del emisor dentro del `TrustBundle` activo.
2. **Anti-rollback por Emisor:** El cliente rechaza cualquier manifiesto con `manifest_version <= last_accepted_version(issuer_id)`.
3. **Integridad de Lista:** Al procesar un Token Status List obtenido por cualquier medio, su hash SHA-256 debe coincidir estrictamente con el registrado en el manifiesto vigente.

---

## 8. Presupuestos de Recursos y Límites del Sistema

Para garantizar compatibilidad con arquitecturas embebidas, terminales punto de venta y WebAssembly:

| Parámetro | Límite Máximo | Justificación |
|---|---|---|
| Tamaño del payload `TrustBundle` | 512 KiB | Evitar desbordamientos de memoria en dispositivos limitados. |
| Número de emisores por bundle | 1,000 | Dimensionado para federaciones y ecosistemas nacionales. |
| Claves activas por emisor | 16 | Minimizar búsquedas lineales durante la resolución de claves. |
| Operadores en `bundle_signers` | 32 | Límite práctico de multifirma y tamaño de cabeceras JWS. |
| Firmantes en `root_keys` | 32 | Límite de gobierno y ceremonia de claves. |
| Tamaño de `IssuerStatusManifest` | 64 KiB | Optimizado para distribución rápida e incrustación en transportes de baja capacidad. |
