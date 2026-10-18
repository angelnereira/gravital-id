# Especificación PIP: Formato de Almacenamiento Local Cifrado

> **Identificador normativo:** `SPEC-PIP-STORAGE-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T17`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-STOR-001..005, REQ-SEC-004; ADR-0008, ADR-0019; P-03, P-09; INV-02, INV-03.

---

## 1. Alcance y Principios de Privacidad

El almacenamiento local en el dispositivo del titular (`Wallet`) o del verificador (`VerifierStateStore`) debe salvaguardar credenciales, claves criptográficas y metadatos contra:
1. **Extracción física y análisis forense:** Acceso ilegítimo al sistema de archivos mediante volcado de memoria flash, copias de seguridad de SO no cifradas o acceso root/jailbreak.
2. **Correlación de metadatos:** Exfiltración de identificadores de emisor, tipos de credencial (`vct`) o momentos de uso.
3. **Corrupción por interrupción:** Pérdida de integridad o inconsistencia transaccional ante cortes de energía o cierres forzados de la aplicación.

### Invariantes aplicados
* **REQ-STOR-001 / P-03:** Cifrado de sobre (Envelope Encryption) con AEAD (`XChaCha20-Poly1305` o `AES-256-GCM`) y Datos Asociados Autenticados (AAD).
* **REQ-STOR-002:** La clave maestra de cifrado de claves (KEK) reside obligatoriamente en el módulo seguro de la plataforma (Keystore/Keychain).
* **REQ-STOR-003 / P-09:** Cero metadatos en claro en disco. Las consultas se ejecutan exclusivamente mediante **índices ciegos** (*blind indexing*).

---

## 2. Jerarquía de Claves Criptográficas (Cifrado de Sobre)

```text
    ┌──────────────────────────────────────────────┐
    │     Almacén Seguro de Plataforma (Host)      │
    │  (Android Keystore StrongBox / iOS Keychain) │
    └──────────────────────┬───────────────────────┘
                           │ Clave Maestra de Cifrado
                           ▼
                  ┌─────────────────┐
                  │    KEK (256b)   │
                  └────────┬────────┘
                           │ HKDF-SHA256 (Contexto)
            ┌──────────────┴──────────────┐
            ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐
   │ Blind Index Key │           │ DEK Derivada    │
   │  BIK (256 bits) │           │   (256 bits)    │
   └────────┬────────┘           └────────┬────────┘
            │ HMAC-SHA256                 │ XChaCha20-Poly1305
            ▼                             ▼
   ┌─────────────────┐           ┌─────────────────┐
   │  Blind Index    │           │ Cifrado + Tag   │
   │   (Tag ciego)   │           │    (Registro)   │
   └─────────────────┘           └─────────────────┘
```

1. **Clave de Cifrado de Claves (KEK - Key Encryption Key):**
   * Generada en el primer arranque mediante el `KeyStore` de hardware.
   * Atributos de protección: `BiometricPrompt` o acceso solo tras desbloqueo de pantalla (`kSecAccessControlBiometryAny` / `UserPresence`).
2. **Clave de Cifrado de Datos (DEK - Data Encryption Key):**
   * Derivada por registro o colección mediante `HKDF-Expand(KEK, info: "pip-storage-dek-v1" || record_id)`.
3. **Clave de Índices Ciegos (BIK - Blind Index Key):**
   * Derivada mediante `HKDF-Expand(KEK, info: "pip-storage-bik-v1")`.

---

## 3. Formato del Registro Cifrado

Cada registro en la base de datos local (SQLite o almacén clave-valor) se almacena con la estructura binaria serializada:

| Campo | Tipo | Tamaño | Descripción |
|---|---|---|---|
| `magic` | `[u8; 4]` | 4 bytes | Constante mágica `PIP$`. |
| `schema_version` | `u16` | 2 bytes | Versión del esquema del registro (Big-Endian). |
| `cipher_suite` | `u8` | 1 byte | `0x01` = XChaCha20-Poly1305, `0x02` = AES-256-GCM. |
| `nonce` | `[u8; 24]` | 24 bytes | Nonce aleatorio de 192 bits (para XChaCha20). |
| `record_id_hash` | `[u8; 16]` | 16 bytes | Truncado del índice ciego primario para particionado. |
| `ciphertext` | `[u8; N]` | N bytes | Contenido JSON canónico cifrado. |
| `auth_tag` | `[u8; 16]` | 16 bytes | Etiqueta de autenticación Poly1305 / GMAC. |

### Datos Asociados Autenticados (AAD)
Para impedir que un atacante intercambie registros entre tablas o modifique el ID de clave:
$$\text{AAD} = \texttt{"PIP-STORAGE-AAD-v1"} \parallel \text{schema\_version} \parallel \text{record\_id} \parallel \text{collection\_type}$$

---

## 4. Consultas mediante Índices Ciegos (*Blind Indexing*)

Para permitir búsquedas locales por emisor (`issuer_id`) o tipo de credencial (`vct`) sin exponer estos valores en claro en la base de datos SQLite:

$$\text{BlindIndex}(\text{value}) = \text{HMAC-SHA256}(\text{BIK}, \texttt{"idx:"} \parallel \text{attribute\_name} \parallel \texttt{":"} \parallel \text{value})$$

### Estructura de la Tabla SQLite en Adaptador L5
```sql
CREATE TABLE pip_records (
    record_id TEXT PRIMARY KEY,          -- UUID v4 en claro o BlindIndex(id)
    collection TEXT NOT NULL,            -- e.g. 'credentials', 'keys', 'sessions'
    record_data BLOB NOT NULL,           -- Carga binaria cifrada (sección 3)
    created_at INTEGER NOT NULL,         -- Timestamp Unix
    updated_at INTEGER NOT NULL
);

CREATE TABLE pip_blind_indices (
    index_hash TEXT NOT NULL,            -- BlindIndex(attribute, value)
    record_id TEXT NOT NULL,
    PRIMARY KEY (index_hash, record_id),
    FOREIGN KEY (record_id) REFERENCES pip_records(record_id) ON DELETE CASCADE
);

CREATE INDEX idx_pip_blind_lookup ON pip_blind_indices(index_hash);
```

Cualquier operador forense que inspeccione la base de datos de SQLite solo observa hashes de 256 bits pseudoaleatorios incomprensibles e inconexos sin la BIK residente en el hardware.

---

## 5. Integridad Transaccional y Escrituras Atómicas

1. **Modo WAL en SQLite:** Las implementaciones L5 sobre SQLite deben activar obligatoriamente:
   ```sql
   PRAGMA journal_mode = WAL;
   PRAGMA synchronous = NORMAL;
   PRAGMA foreign_keys = ON;
   ```
2. **Escrituras Atómicas:** Toda inserción de credencial o rotación de estado se ejecuta dentro de una transacción `BEGIN IMMEDIATE TRANSACTION ... COMMIT`. Si la aplicación finaliza abruptamente en medio de la escritura, la base de datos revierte al estado previo consistente sin pérdida de credenciales ni corrupción de índices.

---

## 6. Procedimiento y Reglas de Migración de Esquema

* **Versionado Obligatorio:** Todo registro contiene `schema_version`.
* **Migraciones Paso a Paso:** Al inicializar el almacenamiento con una versión de esquema $N$ menor que la versión del binario $M$:
  1. Se abre una transacción de migración atómica.
  2. Se aplican secuencialmente las transformaciones $N \to N+1 \to \dots \to M$.
  3. Cada migración re-cifra los registros afectados recalculando el AAD correspondiente.
  4. La suite de pruebas de CI debe verificar compatibilidad hacia atrás con bases de datos sintéticas de cada versión de esquema publicada desde v1.0.0.

---

## 7. Formato Canónico del Paquete de Respaldo Cifrado (`SPEC-PIP-BACKUP-001`)

> **Trazabilidad:** REQ-REC-002, REQ-REC-004, REQ-REC-007, REQ-STOR-001; ADR-0009; INV-01, INV-02, INV-03, INV-05, INV-11.

El respaldo deliberado del titular (Nivel 2 de recuperación, `ADR-0009`) se empaqueta como un archivo binario autónomo cifrado con autenticación AEAD y vinculado a un **código de recuperación generado** de $\ge 128$ bits de entropía (`REQ-REC-002`).

### 7.1 Estructura Binaria de la Cabecera y Paquete

| Campo | Tipo | Tamaño | Descripción |
|---|---|---|---|
| `magic` | `[u8; 4]` | 4 bytes | Constante mágica `GIDB` (`0x47, 0x49, 0x44, 0x42`) para Gravital ID Backup (compatible con `PIPB` como alias legado). |
| `format_version` | `u16` | 2 bytes | Versión de formato de respaldo en Big-Endian (versión actual = `1`). |
| `cipher_suite` | `u8` | 1 byte | Suite de cifrado: `0x01` = XChaCha20-Poly1305 (clave 256 bits, nonce 192 bits, tag 128 bits). |
| `created_at` | `u64` | 8 bytes | Timestamp Unix de emisión en segundos (Big-Endian, inyectado vía `UnixTime`, `INV-11`). |
| `salt` | `[u8; 16]` | 16 bytes | Sal criptográfica aleatoria para derivación HKDF. |
| `nonce` | `[u8; 24]` | 24 bytes | Nonce aleatorio de 192 bits para XChaCha20. |
| `ciphertext_len` | `u32` | 4 bytes | Longitud en bytes del texto cifrado (Big-Endian). Máximo admitido: 16 MiB para prevenir DoS. |
| `ciphertext` | `[u8; N]` | N bytes | Payload comprimido (DEFLATE acotado $\le 10:1$) con datos de la bóveda cifrados. |
| `auth_tag` | `[u8; 16]` | 16 bytes | Etiqueta de autenticación Poly1305. |

### 7.2 Datos Asociados Autenticados (AAD)

Para vincular criptográficamente la cabecera completa y evitar cualquier ataque de trasplante de salt, manipulación temporal o alteración de metadatos:

$$\text{AAD} = \texttt{"GID-BACKUP-AAD-v1"} \parallel \text{format\_version} \parallel \text{cipher\_suite} \parallel \text{created\_at} \parallel \text{salt}$$

### 7.3 Derivación de Claves mediante HKDF-SHA256 (RFC 5869)

A partir de la entropía de 128 bits del código de recuperación (`RecoveryCode`, codificado como mnemónico BIP-39 de 12 palabras o código compacto Crockford Base32 con suma de verificación):

1. **Extracción:**
   $$\text{PRK} = \text{HKDF-Extract}(\text{salt}, \text{RecoveryCode.entropy})$$
2. **Expansión de la Clave de Cifrado del Respaldo:**
   $$\text{BackupEncryptionKey} = \text{HKDF-Expand}(\text{PRK}, \texttt{"pip-backup-encryption-v1"}, 32)$$
3. **Expansión del Secreto de Recuperación (`RecoverySecret`):**
   $$\text{RecoverySecret} = \text{HKDF-Expand}(\text{PRK}, \texttt{"pip-recovery-secret-v1"}, 32)$$

### 7.4 Claves de Recuperación por Emisor (`REQ-REC-004`, `REQ-REC-007`)

Para garantizar la no correlación entre entidades emisoras (P-09, INV-02):
$$\text{IssuerRecoveryKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{IssuerId.as\_bytes()}, \text{RecoverySecret}), \texttt{"pip-issuer-recovery-key-v1"}, 32)$$

Dos emisores distintos $E_1 \neq E_2$ obtienen claves públicas de recuperación diferentes y matemáticamente independientes, impidiendo que la huella de recuperación actúe como un identificador global del titular.

### 7.5 Estructura del Payload Cifrado

El texto en claro antes de comprimir y cifrar contiene:
* `schema_version`: versión del esquema de payload (`1`).
* `recovery_secret`: secreto maestro de 32 bytes (`SecretBytes<32>`).
* `credentials`: array de credenciales de la wallet con sus SD-JWTs, disclosures y metadatos de emisión.
* `device_slots`: array de ranuras activas (`DeviceFactorClass`: `mobile`, `card`, `other`).
* `tenant_roles`: array de credenciales de rol e inquilinos asociados (`pip-tenant-role-v1`).
* `created_at`: `UnixTime` de generación del respaldo.

---

## 8. Formato Canónico de Fragmentos de Recuperación Social Shamir $k$-de-$n$ (`SPEC-PIP-SHAMIR-001`)

> **Trazabilidad:** `REQ-REC-003`, `P-10`, `INV-01`, `INV-02`, `INV-03`, `INV-05`, `INV-10`, `INV-11`.

Para mitigar el riesgo de punto único de fallo o coacción física en la custodia del código de recuperación, el titular puede opcionalmente fragmentar el secreto (16 bytes de entropía de `RecoveryCode` o 32 bytes de `RecoverySecret`) entre $n$ guardianes de confianza con un umbral de reconstrucción $k$ ($2 \le k \le n \le 255$).

### 8.1 Aritmética en Campo de Galois $GF(2^8)$

Las operaciones se ejecutan sobre el campo finito de Galois $GF(2^8)$ con el polinomio generador irreducible estándar de Rijndael/AES:
$$P(x) = x^8 + x^4 + x^3 + x + 1 \quad (\texttt{0x11B})$$

1. **Suma y Resta:** Operación XOR bit a bit:
   $$a \oplus b$$
2. **Multiplicación e Inversión:** Operaciones en tiempo constante o mediante tablas precomputadas de logaritmo/exponenciación base $\alpha = 3$:
   $$a \cdot b = \alpha^{(\log_\alpha(a) + \log_\alpha(b)) \pmod{255}}, \quad a^{-1} = \alpha^{(255 - \log_\alpha(a)) \pmod{255}}$$

### 8.2 Partición y Reconstrucción Polinómica

Dado un secreto $S \in GF(2^8)^L$ ($L \in \{16, 32\}$):
1. **Generación de Polinomio:** Se generan $k-1$ coeficientes aleatorios independientes $A_1, \dots, A_{k-1} \in GF(2^8)^L$ inyectados mediante `Rng` (`INV-11`):
   $$f(x) = S \oplus A_1 x \oplus A_2 x^2 \oplus \dots \oplus A_{k-1} x^{k-1}$$
2. **Evaluación de Fragmentos:** Para cada guardián $i \in \{1, \dots, n\}$, con $x_i \ne 0$ distintos:
   $$\text{Share}_i = (x_i, f(x_i))$$
3. **Reconstrucción de Lagrange:** Presentados $k$ fragmentos válidos distintos $\{(x_0, y_0), \dots, (x_{k-1}, y_{k-1})\}$:
   $$S = f(0) = \bigoplus_{j=0}^{k-1} \left( y_j \cdot \prod_{m=0, m \ne j}^{k-1} \frac{x_m}{x_m \oplus x_j} \right)$$

### 8.3 Estructura Binaria del Fragmento (`ShamirShare`)

Cada fragmento se empaqueta en una estructura binaria canónica autosuficiente con validación de integridad fail-closed:

```text
+-------------------+----------------+-------------+-------------+
| magic (4 B)       | format_ver (1B)| threshold k | total n     |
| "GIDS" (0x47494453)| 0x01           | [2..255]    | [k..255]    |
+-------------------+----------------+-------------+-------------+
| share_index x (1B)| secret_id (4 B)| val_len (1B)| share_val   |
| [1..255]          | SHA-256[..4]   | L (16 o 32) | L bytes     |
+-------------------+----------------+-------------+-------------+
| checksum (4 B)    |
| SHA-256(header || share_val)[..4]
+-------------------+
```

* `magic`: `b"GIDS"` (Gravital ID Shamir).
* `format_version`: `0x01`.
* `threshold`: número mínimo $k$ de fragmentos necesarios.
* `total_shares`: total $n$ de fragmentos emitidos.
* `share_index`: coordenada $x_i \in [1, 255]$ no nula.
* `secret_id`: identificador de 4 bytes derivado del hash del secreto para impedir mezclar fragmentos de diferentes secretos.
* `share_value`: $L$ bytes correspondientes a $f(x_i)$.
* `checksum`: 4 bytes de verificación de integridad criptográfica SHA-256 calculados sobre los bytes precedentes.

### 8.4 Formato Legible para Custodia Física (Crockford Base32)

Los fragmentos binarios pueden codificarse como cadenas alfanuméricas Crockford Base32 agrupadas con guiones (`XXXX-XXXX-...`), facilitando su almacenamiento en papel o soportes físicos seguros sin ambigüedad tipográfica (`I`, `L`, `O` normalizados).

