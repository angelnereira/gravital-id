# Especificación PIP: Perfiles Criptográficos y Parámetros

> **Identificador normativo:** `SPEC-PIP-CRYPTO-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T06`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-CRED-001, REQ-CRED-002, REQ-STAT-001, REQ-STAT-003, REQ-SEC-008; INV-05, INV-07, INV-08; ADR-0003, ADR-0005, ADR-0007; P-04, P-07, P-08, P-10.

---

## 1. Alcance y Filosofía

Esta especificación fija los algoritmos criptográficos, suites de cifrado, versiones normativas exactas de estándares del IETF/W3C/OpenID, tamaños de sal, parámetros de aleatoriedad y presupuestos de descompresión para el protocolo PIP (Portable Identity Protocol / Gravital ID).

### Principios Fundamentales
* **Determinismo y Fail-Closed (INV-05, INV-08):** Todo algoritmo no autorizado o cabecera `alg: "none"` se rechaza de forma incondicional.
* **Sin primitivas propias (INV-07):** Se emplean exclusivamente bibliotecas validadas y auditadas (RustCrypto por defecto; aws-lc-rs para entornos FIPS).
* **Agilidad criptográfica controlada:** Los componentes del núcleo se parametrizan por perfil criptográfico versionado; ningún cambio de suite se efectúa en tiempo de ejecución sin validar el perfil normativo.

---

## 2. Versiones Exactas de Estándares Fijadas

Para evitar divergencias de interoperabilidad entre implementaciones:

| Estándar | Versión Fijada | Identificador / Referencia |
|---|---|---|
| **SD-JWT** | RFC 9901 | IETF RFC 9901 (mayo de 2024): Selective Disclosure for JWTs. |
| **SD-JWT VC** | `draft-19` | `draft-ietf-oauth-sd-jwt-vc-19` (agosto de 2026). Tipo: `dc+sd-jwt`. |
| **Token Status List** | `draft-21` | `draft-ietf-oauth-status-list-21` (junio de 2026). Tipo: `statuslist+jwt`. |
| **JSON Web Signature (JWS)** | RFC 7515 | RFC 7515 (Serialización compacta para credenciales; serialización JSON general para bundles). |
| **JSON Web Key (JWK)** | RFC 7517 | RFC 7517 (Formatos de clave pública). |
| **JWK Thumbprint** | RFC 7638 | RFC 7638 (Huellas canónicas de clave calculadas con SHA-256). |
| **JSON Canonicalization (JCS)** | RFC 8785 | RFC 8785 (Canonicalización de payloads para multifiirma determinista). |
| **Hybrid Public Key Encryption (HPKE)** | RFC 9180 | IETF RFC 9180 (febrero de 2022): cifrado híbrido en modo base para relay y sesiones de proximidad. |
| **High Assurance Interop (HAIP)** | Versión 1.0 | OpenID HAIP 1.0 (Final, diciembre de 2025). |
| **Post-Quantum JOSE (F18)** | RFC 9964 | RFC 9964 (mayo de 2026): ML-DSA en JOSE y COSE (referencia futura). |

---

## 3. Algoritmos Permitidos y Prohibidos (Perfil Base `v1`)

### 3.1 Algoritmos Permitidos

#### Firma Digital Asimétrica
* **`ES256` (ECDSA sobre curva P-256 / secp256r1 con SHA-256):**
  * Curva estándar NIST P-256 (FIPS 186-4 / RFC 5480).
  * Generación de firmas: Debe seguir RFC 6979 (k determinista) o utilizar un generador CSPRNG verificado.
  * Formato de firma en JWS: IEEE P1363 (concatenación estricta de enteros $r \parallel s$, exactamente 64 bytes).
  * **Mitigación de Maleabilidad (ECDSA):** La verificación **NO** exige *low-S* (REQ-KEY-010): el conversor DER ↔ P1363 se realiza en Rust y la firma nunca se usa como identificador ni como clave de deduplicación (INV-02, INV-04). Todo firmante PUEDE normalizar $s$ a su valor inferior, pero el verificador acepta ambos. `CRYPTO_PROFILES.md` se alinea con `ARCHITECTURE.md §4` (decisión registrada en issue #23).

#### Funciones de Dispersión Criptográfica (Hash)
* **`SHA-256` (FIPS 180-4):**
  * Utilizado para hashes de divulgación en SD-JWT, cálculo de huellas JWK Thumbprint (RFC 7638) y resúmenes de bloques del ledger.

#### Cifrado Autenticado en Reposo y Local (AEAD)
* **`XChaCha20-Poly1305`:** AEAD con clave de 256 bits y nonce extendido de 192 bits (24 bytes). Algoritmo prioritario para almacenamiento local cifrado en dispositivos de titular.
* **`AES-256-GCM`:** Clave de 256 bits con nonce de 96 bits (12 bytes). Soportado cuando el hardware host provee aceleración criptográfica AES-NI / ARM Crypto Extensions.

#### Cifrado Híbrido de Clave Pública para Transporte y Proximidad (HPKE, RFC 9180)
* **Modo Base (`mode_base = 0x00`):**
  * **KEM:** `DHKEM(P-256, HKDF-SHA256)` (`0x0010`), clave encapsulada SEC1 sin comprimir de 65 bytes.
  * **KDF:** `HKDF-SHA256` (`0x0001`).
  * **AEAD primario (móvil, escritorio, relay, proximidad):** `ChaCha20Poly1305` (`0x0003`, clave de 32 bytes, nonce de 12 bytes, tag de 16 bytes; implementado en `gravital-id-crypto::hpke`).
  * **AEAD alternativo para elementos seguros de tarjeta física (según ADR-0024):** `AES-128-GCM` (`0x0001`) o `AES-256-GCM` (`0x0002`) cuando sea ejecutado íntegramente por el coprocesador criptográfico del chip Java Card.

#### Derivación de Claves (KDF) y Funciones de Contraseña
* **`HKDF-SHA256` (RFC 5869):** Derivación de claves de sesión efímeras y segmentación de almacén.
* **`Argon2id` (RFC 9106):** Para derivación de claves maestras a partir de frases de recuperación o contraseñas de usuario (parámetros: $m=64\,\text{MiB}, t=3, p=4$ en plataformas de escritorio/servidor; $m=32\,\text{MiB}, t=2, p=2$ en móviles).

---

### 3.2 Algoritmos y Configuraciones Estrictamente Prohibidos

El motor criptográfico en capa L1 rechaza en tiempo de compilación y de ejecución:
1. **`alg: "none"`:** Cualquier token con esta cabecera produce un rechazo inmediato e irrevocable.
2. **Firmas basadas en RSA:** `RS256`, `RS384`, `RS512`, `PS256`, etc., están prohibidas en el perfil v1 debido al excesivo tamaño de clave y firma en transportes QR offline y lentitud en WebAssembly.
3. **Curvas elípticas no estándar o inseguras:** Prohibidas curvas P-192, P-224, secp256k1 (fuera de la capa L5 de Ethereum) o curvas Brainpool sin perfil explícito.
4. **Hashes criptográficamente rotos:** Prohibidos MD5, SHA-1, RIPEMD160.
5. **Modos de cifrado sin autenticación:** Prohibidos AES-ECB, AES-CBC sin HMAC autenticado.

---

## 4. Entropía, Sales y Tamaños de Parámetros

| Parámetro | Requisito Mínimo | Formato | Propósito |
|---|---|---|---|
| **Sal de Divulgación SD-JWT** | 128 bits (16 bytes) | Base64URL sin padding | Prevenir ataques de diccionario y arcoíris sobre claims de baja entropía. |
| **Nonce de Sesión (KB-JWT)** | 128 bits (16 bytes) | Base64URL | Mitigar repetición (*replay attacks*) en presentaciones. |
| **Semilla de Recuperación** | 128 bits (16 bytes) | Mnemónico BIP-39 (12 palabras) | Clave maestra para regeneración de vinculación. |
| **Nonce AEAD (XChaCha20)** | 192 bits (24 bytes) | Binario aleatorio | Garantía de no reutilización de nonce en almacenamiento. |

---

## 5. Límites de Recursos y Mitigaciones DoS

Para proteger terminales offline y dispositivos limitados contra ataques de agotamiento de memoria (*Zip Bombs* y *Parser Flooding*):

### 5.1 Descompresión de Token Status Lists (REQ-STAT-003)
* Algoritmo de compresión permitido: `ZLIB` / `DEFLATE` (RFC 1951).
* **Ratio máximo de expansión:** $10:1$. Si la descompresión supera 10 veces el tamaño comprimido de entrada, el lector aborta la operación.
* **Límite absoluto de salida:** 2 MiB descomprimidos por lista de estado.
* Las listas de estado deben usar representación de 1 bit (0=activo, 1=revocado) o 2 bits (00=activo, 01=revocado, 10=suspendido).

### 5.2 Límites de Entrada en Presentaciones
* **Tamaño máximo de presentación QR individual:** 2,953 bytes (capacidad máxima de código QR versión 40, nivel L).
* **Presentaciones fragmentadas (Multi-QR):** Máximo 8 fragmentos (presupuesto total de presentación $\le 16$ KiB).
* **Tamaño máximo de credencial SD-JWT (en línea):** 64 KiB.
* **Máximo número de divulgaciones por credencial:** 64 elementos.

---

## 6. Política de Transición y Criptografía Post-Cuántica (PQC)

1. **Inmutabilidad de Perfil:** El perfil `pip-crypto-v1` no muta sus primitivas. Cualquier cambio algorítmico implicará un nuevo perfil `pip-crypto-v2` aprobado mediante ADR.
2. **Convivencia PQC (F18):** El protocolo contempla la introducción progresiva de algoritmos resistentes a computación cuántica conforme se consoliden los estándares JOSE (ML-DSA / RFC 9964 y ML-KEM). La arquitectura L1 aísla las primitivas en traits abstractos (`Signer`, `Verifier`, `Aead`) que permiten reemplazar backends sin alterar la lógica de negocio ni las capas superiores.
