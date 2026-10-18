# Catálogo de Códigos de Error PIP (`ERROR_CODES.md`)

> **Identificador normativo:** `SPEC-PIP-ERRORS-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T16`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-SDK-003, REQ-SDK-004; `AGENTS.md §9.1`, `ARCHITECTURE.md §17.3`

---

## 1. Estructura y Garantías de Estabilidad

Todos los errores generados por el núcleo de Rust y expuestos a través de bindings de lenguaje (Kotlin, Swift, Python, TypeScript, Dart, Go, C#, C++) utilizan identificadores numéricos estables con el formato:

$$\texttt{PIP-E}\langle\text{Familia}\rangle\langle\text{Código}\rangle$$

### Representación Estructurada en Bindings
```rust
pub struct PipError {
    pub code: u32,             // Código numérico estándar (p. ej. 1001)
    pub code_str: &'static str,// Identificador canónico (p. ej. "PIP-E1001")
    pub message: String,       // Mensaje descriptivo en inglés (sin secretos)
    pub details: Option<String>// Información contextual no sensible
}
```

---

## 2. Familias de Códigos de Error

### Familia 1: Protocolo, Transporte y Codificación (`PIP-E1000..E1999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E1001` | `MalformedMessage` | Estructura de mensaje JSON o binario sintácticamente inválida. |
| `PIP-E1002` | `ExpiredRequest` | Solicitud recibida caducada respecto al tiempo confiable. |
| `PIP-E1003` | `NonceReused` | Nonce de sesión reutilizado o no registrado en la caché (replay). |
| `PIP-E1004` | `UnsupportedProtocolVersion` | Versión de protocolo no soportada por el motor. |
| `PIP-E1005` | `DisclosuresMismatch` | Divulgaciones entregadas no corresponden a los claims solicitados. |
| `PIP-E1006` | `KeyBindingFailed` | El KB-JWT no coincide con el `cnf` o el `sd_hash` es erróneo. |
| `PIP-E1007` | `DecompressionRatioExceeded` | Ratio de expansión DEFLATE superior al límite permitido (mitigación DoS). |
| `PIP-E1008` | `MultiQrIncomplete` | Secuencia de fragmentos Multi-QR incompleta tras expirar el temporizador. |
| `PIP-E1009` | `Base45DecodeFailed` | Error al decodificar la carga alfanumérica Base45 del código QR. |
| `PIP-E1010` | `HpkeDecryptionFailed` | Fallo al desencapsular o descifrar el sobre de operación HPKE. |

---

### Familia 2: Criptografía y Primitivas (`PIP-E2000..E2999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E2001` | `InvalidSignature` | La firma criptográfica no pudo verificarse contra la clave pública. |
| `PIP-E2002` | `UnsupportedAlgorithm` | Algoritmo prohibido o no soportado (p. ej. `alg: none`, RSA). |
| `PIP-E2003` | `InvalidKeyFormat` | Clave pública malformada, punto no en curva P-256 o JWK inválido. |
| `PIP-E2004` | `HighSValueRejected` | Firma ECDSA con componente $s$ maleable ($s > n/2$, rechazo Low-S). |
| `PIP-E2005` | `KeyNotFound` | Clave solicitada no presente en el almacén de claves del host. |
| `PIP-E2006` | `AeadAuthenticationFailed` | Fallo de autenticación en descifrado simétrico (datos corruptos o KEK incorrecta). |
| `PIP-E2007` | `InsufficientEntropy` | Generador CSPRNG falló al producir la entropía mínima requerida (128 bits). |
| `PIP-E2010` | `CitizenIdentityAlreadyRegistered` | La identidad nacional o ciudadana verificada ya posee un registro activo en el emisor (`UniquenessTag` existente); redirigir a ingreso o recuperación (`ADR-0028`, `REQ-UNIQ-003`). |
| `PIP-E2011` | `DuplicateDeviceClassActive` | Ya existe una credencial activa en la misma clase de factor de dispositivo (`mobile`, `card` u `other`) sin orden firmada de reemplazo atómico (`ADR-0029`, `REQ-DEVSLOT-001`). |

---

### Familia 3: Credenciales y SD-JWT (`PIP-E3000..E3999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E3001` | `MalformedSdJwt` | Formato de credencial no se ajusta a RFC 9901 / `draft-19`. |
| `PIP-E3002` | `MissingRequiredClaim` | Falta un claim obligatorio exigido por el esquema del perfil o del `vct`. |
| `PIP-E3003` | `InvalidDisclosureDigest` | El hash de una divulgación no coincide con ninguna entrada del array `_sd`. |
| `PIP-E3004` | `SchemaValidationFailed` | Los claims divulgados no satisfacen el esquema JSON normativo. |
| `PIP-E3005` | `CredentialExpired` | La credencial ha superado su fecha de expiración `exp`. |
| `PIP-E3006` | `CredentialNotYetValid` | La fecha actual es anterior al instante de inicio de vigencia `nbf`. |

---

### Familia 4: Estado y Revocación (`PIP-E4000..E4999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E4001` | `MalformedStatusList` | Token Status List sintácticamente corrupto o inválido. |
| `PIP-E4002` | `StatusIndexOutOfRange` | El índice asignado en la credencial supera la longitud de la lista. |
| `PIP-E4003` | `StatusListExpired` | Lista de estado caducada más allá de la tolerancia de frescura. |
| `PIP-E4004` | `StatusManifestMismatch` | El hash de la lista descargada no coincide con el manifest firmado. |
| `PIP-E4005` | `CredentialRevoked` | La credencial figura como revocada en el índice de estado. |
| `PIP-E4006` | `CredentialSuspended` | La credencial figura como suspendida temporalmente. |

---

### Familia 5: Verificación, Confianza y Ledger (`PIP-E5000..E5999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E5001` | `UntrustedIssuer` | El emisor no existe o no está registrado en el `TrustBundle` activo. |
| `PIP-E5002` | `IssuerSuspended` | El emisor se encuentra en estado de suspensión administrativa. |
| `PIP-E5003` | `IssuerKeyCompromised` | La clave pública de firma del emisor está catalogada como comprometida. |
| `PIP-E5004` | `IssuerKeyRetired` | La clave pública fue retirada antes de emitir la credencial (`iat >= state_since`). |
| `PIP-E5005` | `InsufficientBundleSignatures`| El `TrustBundle` contiene menos de $k$ firmas válidas de operadores autorizados. |
| `PIP-E5006` | `BundleVersionRollback` | Intento de cargar un bundle con versión inferior a la aceptada (anti-rollback). |
| `PIP-E5007` | `ClockRollbackDetected` | El reloj local es anterior al piso de tiempo confiable observado. |
| `PIP-E5008` | `TrustRootChainBroken` | La nueva raíz no cuenta con las firmas requeridas de la raíz precedente. |
| `PIP-E5009` | `VerifierStateCorrupted` | El estado persistente del verificador (piso de tiempo, versiones aceptadas, caché de nonces) falta, está corrupto o fue restaurado; resultado `Unverifiable` hasta reinicialización explícita (REQ-VER-011). |

---

### Familia 6: Almacenamiento Local Cifrado (`PIP-E6000..E6999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E6001` | `StorageReadFailed` | Error de lectura física en la base de datos o almacenamiento local. |
| `PIP-E6002` | `StorageWriteFailed` | Error al escribir o confirmar transacción atómica en almacenamiento. |
| `PIP-E6003` | `SchemaMigrationFailed` | Error al migrar la estructura de esquema a una versión superior. |
| `PIP-E6004` | `RecordNotFound` | Registro solicitado no localizado por su índice ciego. |

---

### Familia 7: Integración con el Host y SDK (`PIP-E7000..E7999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E7001` | `HardwareKeystoreFailed` | El enclave de seguridad o TEE del host devolvió un error de ejecución. |
| `PIP-E7002` | `ClockUnavailable` | El proveedor de reloj inyectado por el host devolvió un valor nulo o inválido. |
| `PIP-E7003` | `StateStoreCorrupted` | El almacenamiento de estado persistente del verificador falló su integridad. |
| `PIP-E7004` | `TransportTimeout` | Tiempo de espera agotado al comunicar con un relay o endpoint de red. |

---

### Familia 8: Proximidad, Tarjeta Física y Código de Sesión (`PIP-E8000..E8999` / `GID-E8000..E8999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E8001` | `UnsupportedAid` | Identificador de aplicación (AID) ISO/IEC 7816-4 desconocido o no soportado (`SW=6A82`). |
| `PIP-E8002` | `ProximityMessageTooLarge` | Mensaje APDU, fragmento de proximidad o atributo (p. ej. retrato en QR) excede los límites permitidos por el transporte (`SW=6700`). |
| `PIP-E8003` | `ProximitySessionExpired` | La sesión de proximidad, el armado de toque NFC o el código numérico de sesión (`SessionCode`) ha expirado. |
| `PIP-E8004` | `ConsentPending` | El titular debe confirmar interactivamente la divulgación en su dispositivo antes del segundo toque (`SW=6985`). |
| `PIP-E8005` | `CardPinRequired` | La tarjeta física exige verificación de PIN (`VERIFY`) para divulgar claims de Nivel 1 (`SW=6982`). |
| `PIP-E8006` | `CardPinBlocked` | El contador de intentos de PIN de la tarjeta física se ha agotado y la tarjeta está bloqueada (`SW=6983`). |
| `PIP-E8007` | `ProximityDecryptionFailed` | Fallo al abrir el sobre HPKE de proximidad o discrepancia en el `transcript_hash` asociado (rechazo fail-closed, INV-05). |
| `PIP-E8008` | `InvalidApduCommand` | Comando o respuesta APDU malformado, instrucción (`INS`) no soportada o fuera de secuencia en la máquina de estados (`SW=6D00`/`6986`). |
| `PIP-E8009` | `CardNotPersonalized` | Operación rechazada porque la tarjeta no se encuentra en el estado de ciclo de vida requerido (`PERSONALIZACION` vs `ACTIVA`). |
| `PIP-E8010` | `InvalidSessionCode` | Código numérico de sesión (`SessionCode`) malformado, dígito de control Damm inválido, ya consumido o límite de intentos excedido. |

---

### Familia 9: Errores Críticos y FFI (`PIP-E9000..E9999`)

| Código | Identificador | Descripción |
|---|---|---|
| `PIP-E9001` | `FfiBoundaryViolation` | Parámetro nulo, puntero no alineado o violación de contrato FFI. |
| `PIP-E9002` | `WasmMemoryPoisoned` | Instancia de WebAssembly abortada o envenenada tras un fallo irrecuperable. |
| `PIP-E9999` | `PanicCaught` | Pánico interno en Rust interceptado antes de cruzar hacia el lenguaje host. |
