# Gravital ID — Protocolo de Identidad Portable

> **Portabilidad real · Verificación offline sans-I/O · Divulgación selectiva · Cero datos personales en cadena · Recuperación segura**

Gravital ID (nombre técnico de desarrollo: PIP, *Portable Identity Protocol*) es un protocolo de identidad digital portable con núcleo de referencia implementado en Rust (`#![no_std]` + `alloc` en capas L1–L3, arquitectura estrictamente *sans-I/O* en L4).

El protocolo permite a los emisores generar credenciales verificables con divulgación selectiva, a los titulares almacenarlas cifradas bajo su exclusivo control en sus dispositivos personales, y a los verificadores comprobar la autenticidad, integridad, vigencia y vinculación criptográfica del titular **completamente sin conexión a Internet y sin depender de servidores centrales**. Una blockchain pública o consorciada actúa únicamente como un registro de confianza compartido y distribuido (para anclar qué emisores, operadores y claves públicas son válidos), **nunca** para almacenar datos personales, identificadores de titulares ni hashes reversibles de información confidencial.

El núcleo se distribuye como biblioteca Rust modular y de alto rendimiento, diseñada para integrarse en aplicaciones móviles, navegadores, hardware embebido y servicios distribuidos mediante SDKs y bindings en WebAssembly, Kotlin (Android), Swift (iOS), TypeScript/JavaScript, Python, Go, C# y C ABI.

---

## Principios y Diferenciadores del Protocolo

1. **Verificación Offline Real (sans-I/O):**
   La verificación de presentaciones de credenciales no realiza bajo ninguna circunstancia operaciones de I/O de red (`INV-01`). Las claves públicas de los emisores se obtienen exclusivamente del *trust bundle* multi-firma validado y cacheado localmente (`INV-06`). La verificación opera con garantías completas en túneles subterráneos, zonas rurales sin cobertura o en condiciones de desconexión deliberada.

2. **Privacidad Radical y Soberanía del Titular:**
   Ningún dato personal, ningún hash de dato personal y ningún identificador persistente del titular se publica en el ledger, ni en registros de auditoría, métricas o mensajes de error (`INV-02`, `P-09`). Las credenciales utilizan SD-JWT VC con sal criptográfica de al menos 128 bits y señuelos (*decoys*) para prevenir ataques de diccionario y correlación entre verificadores.

3. **Sin Custodia de Claves Privadas de Titulares:**
   Ningún servicio centralizado, emisor o retransmisor custodia claves privadas de titulares (`INV-03`). Las firmas de vinculación del titular (*Key Binding*) se delegan a módulos de hardware seguro (Secure Enclave, StrongBox, Java Card) o a almacenes de claves locales protegidos por biometría. Las claves privadas nunca cruzan fronteras de FFI ni salen del dispositivo.

4. **Confianza Distribuida por Umbral multi-operador ($k$-de-$n$):**
   Ninguna clave única puede alterar la confianza de un verificador offline (`INV-16`). Tanto la raíz de confianza (*TrustRoot*) como los lotes derivados (*TrustBundle*) requieren cofirmas de un umbral $k$-de-$n$ de operadores independientes, con esquemas de versiones monotónicas anti-rollback.

5. **Modelo de Verificación de 4 Estados con Evidencia Forense:**
   El resultado de verificación no es un booleano simplista; proporciona un registro de evidencia inmutable estructurado en cuatro estados normativos (`INV-04`): `Valid`, `ValidWithStaleStatus`, `Unverifiable` e `Invalid`. Las comprobaciones siguen una precedencia rigurosa con política *fail-closed* (`INV-05`).

6. **Determinismo Absoluto:**
   El núcleo criptográfico no lee el reloj del sistema operativo ni fuentes de aleatoriedad globales de forma implícita (`INV-11`). El instante temporal (`UnixTime`) y los generadores CSPRNG se inyectan explícitamente mediante traits, permitiendo auditorías formales y pruebas reproducibles al cien por cien.

7. **Neutralidad de Transporte:**
   El protocolo opera con la misma semántica a través de múltiples canales físicos y lógicos: códigos QR offline con compresión Base45, proximidad NFC y tarjetas inteligentes ISO/IEC 7816-4 (protocolo `GID-APDU`), Bluetooth Low Energy (BLE) y transporte web seguro mediante relays cifrados con HPKE.

---

## Invariantes No Negociables del Protocolo

Cualquier cambio de código, arquitectura o especificación que viole cualquiera de estos 16 invariantes es automáticamente rechazado:

| Invariante | Regla Normativa |
|---|---|
| **INV-01** | La verificación **nunca** realiza I/O de red. Capas L1–L3 son `no_std`, L4 es *sans-I/O*; el I/O vive exclusivamente en adaptadores L5 y en el host. |
| **INV-02** | **Ningún dato personal**, ni hash de dato personal, ni identificador de titular va al ledger, a logs, a métricas ni a mensajes de error. |
| **INV-03** | Ningún servicio custodia claves privadas de titulares. Las claves privadas de titulares nunca cruzan fronteras FFI. |
| **INV-04** | El resultado de verificación tiene **cuatro estados** normativos con evidencia: `Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`. |
| **INV-05** | **Fail-closed**: ante cualquier error, dato faltante, ambigüedad o inconsistencia, el resultado nunca es `Valid`. |
| **INV-06** | Las claves de emisor se obtienen **solo** del trust bundle; nunca de cabeceras remotas `jku`, `x5u`, `x5c` o `jwk`, ni de la red durante la verificación. |
| **INV-07** | Ninguna primitiva criptográfica propia; uso exclusivo de implementaciones auditadas y fijadas en `ADR-0007` a través de `gravital-id-crypto`. |
| **INV-08** | Algoritmos fijados en `CRYPTO_PROFILES.md`: ES256 (RFC 6979) y SHA-256. El algoritmo `alg: none` siempre es rechazado. |
| **INV-09** | Sin código `unsafe` fuera de `bindings/`. Cada bloque `unsafe` en bindings requiere justificación formal `// SAFETY:`. |
| **INV-10** | Sin `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` ni indexación que pueda causar pánico en bibliotecas. |
| **INV-11** | El núcleo no lee el reloj ni la aleatoriedad implícitamente: se inyectan mediante traits (`Clock`, `Rng`). |
| **INV-12** | Los vectores de prueba publicados en `conformance/vectors/` son **inmutables**. |
| **INV-13** | Ninguna fase de la hoja de ruta se salta; ninguna tarea se cierra sin cumplir íntegramente su criterio de aceptación. |
| **INV-14** | Las vulnerabilidades de seguridad se reportan y tratan exclusivamente mediante avisos privados (`SECURITY.md`). |
| **INV-15** | Los bindings FFI no contienen lógica de negocio; se limitan a adaptación ergonómica y tipos de plataforma. |
| **INV-16** | Ninguna clave única decide la confianza offline: la raíz y el trust bundle exigen umbral multi-firma $k$-de-$n$ de operadores independientes. |

---

## Arquitectura de Capas del Workspace

El repositorio está estructurado en capas estrictas y unidireccionales (verificadas en cada compilación por `cargo xtask check-layers` contra `xtask/layers.toml`):

```text
+-----------------------------------------------------------------------------------+
| L6 / Aplicaciones / Bindings: gravital-id-sdk, bindings/wasm, apps/pip-cli        |
+-----------------------------------------------------------------------------------+
| L5 (Host, Adaptadores, I/O & Servicios):                                          |
|    - gravital-id-storage-sqlite, gravital-id-transport-http,                      |
|    - gravital-id-transport-pcsc, gravital-id-ledger-evm,                          |
|    - gravital-id-service-common, services/pip-*                                  |
+-----------------------------------------------------------------------------------+
| L4 (Sans-I/O & Orquestacion de Dominio):                                          |
|    - gravital-id-holder, gravital-id-protocol,                                    |
|    - gravital-id-proximity, gravital-id-sync                                      |
+-----------------------------------------------------------------------------------+
| L3 (Logica de Negocio, Verificacion & Emision):                                   |
|    - gravital-id-issuer, gravital-id-verifier, gravital-id-recovery               |
+-----------------------------------------------------------------------------------+
| L2 (Dominio Criptografico, Confianza & Estado):                                   |
|    - gravital-id-keys, gravital-id-credential, gravital-id-status,                |
|    - gravital-id-trust, gravital-id-ledger, gravital-id-storage                   |
+-----------------------------------------------------------------------------------+
| L1 (Tipos Fundamentales, Codecs & Criptografia Base - no_std):                    |
|    - gravital-id-types, gravital-id-codec, gravital-id-crypto                     |
+-----------------------------------------------------------------------------------+
| Soporte de Pruebas: gravital-id-testkit (FixedClock, SeededRng, arneses)          |
| Contratos Inteligentes: contracts/ (Solidity 0.8.28, Foundry, 0 PII)             |
+-----------------------------------------------------------------------------------+
```

### Reglas de Dependencia entre Capas

- **L1** no depende de ningún otro crate del workspace; compila en `no_std` con `alloc`.
- **L2** solo puede depender de L1. Compila en `no_std` con `alloc`.
- **L3** solo puede depender de L1 y L2. Es estrictamente *sans-I/O*.
- **L4** solo puede depender de L1, L2 y L3. Es estrictamente *sans-I/O*; no puede realizar I/O de red ni depender de runtimes asíncronos (`tokio`, `async-std`).
- **L5** implementa los traits de I/O de L2–L4 hacia el host (red, SQLite, lectores de tarjetas inteligentes, nodos RPC blockchain, clientes HTTP).
- **L6** agrupa la fachada de integración pública para aplicaciones y plataformas externas.

---

## Catálogo de Componentes y Estado del Workspace

Estado detallado y vivo de avance por componente (actualizado conforme a `docs/STATUS.md`):

| Capa | Componente / Directorio | Estado de Implementación | Responsabilidades Técnicas y Normativas |
|---|---|---|---|
| **L1** | `crates/gravital-id-types` | Implementado (F1–F2, F19) | Identificadores fuertemente tipados con validación en constructor (`IssuerId`, `Kid`, `Vct`, `ProfileId`, `UnixTime`, `BundleVersion`, `SessionCode`), catálogo canónico de 59 errores normativos (`GidError`, familias 1 a 9) y trait `Clock`. |
| **L1** | `crates/gravital-id-codec` | Implementado (F2) | Parsers acotados anti-DoS: `base64url` estricto sin relleno, parser JSON acotado RFC 8259 sin asignaciones infinitas, CBOR determinista RFC 8949 §4.2, descompresión DEFLATE acotada (máx 2 MiB, ratio 10:1 anti-bomba de descompresión) y Base45 RFC 9285. |
| **L1** | `crates/gravital-id-crypto` | Implementado (F2) | Primitivas criptográficas auditadas: ES256 determinista (RFC 6979), SHA-256, HMAC, HKDF (RFC 5869), XChaCha20-Poly1305, HPKE Base (RFC 9180: DHKEM P-256, HKDF-SHA256, ChaCha20Poly1305), JWK EC P-256 (RFC 7517/7638) e higiene de memoria con `Zeroize` y `subtle`. |
| **L2** | `crates/gravital-id-keys` | Implementado (F2) | Abstracción de gestión de claves `KeyStore`, handles tipados por propósito (`IssuerSigning`, `HolderBinding`, `BundleSigning`), `SoftwareKeyStore` para desarrollo y transcodificación canónica DER <-> IEEE P1363. |
| **L2** | `crates/gravital-id-credential` | Implementado (F3) | Emisión, parseo y validación de SD-JWT (RFC 9901): divulgaciones selectivas de campos y arrays, cálculo de sales criptográficas de 128 bits, inserción de señuelos (*decoys*), Key Binding JWT (`typ: kb+jwt`), capa SD-JWT VC (`typ: dc+sd-jwt`) y esquemas de perfil normativos (`pip-personal-v1`, `pip-financial-v1`, `pip-enterprise-v1`). |
| **L2** | `crates/gravital-id-status` | Implementado (F4, F7) | Token Status List JWT con descompresión acotada (bitmaps de 1 y 2 bits), asignación aleatoria de índices no correlacionados (`P-09`), `IssuerStatusManifest` con versiones monotónicas y `StatusCache` acotada con políticas de frescura por perfil. |
| **L2** | `crates/gravital-id-trust` | Implementado (F4) | Raíz de confianza `TrustRoot`, `TrustBundle` derivado con cofirmas $k$-de-$n$ de operadores independientes, evaluación de estados de clave de emisor (`active`, `retired`, `suspended`, `compromised`) y protección anti-rollback por época y versión. |
| **L2** | `crates/gravital-id-ledger` | Implementado (F6) | Trait abstracto `LedgerAdapter`, modelo de eventos de registro de confianza y revocación, y algoritmos de reconstrucción determinista de estado sin red. |
| **L2** | `crates/gravital-id-storage` | Implementado (F5) | Trait `StorageBackend`, cifrado de sobre DEK/KEK en reposo (formato `PIP$`), AAD criptográfico e índices ciegos HMAC-SHA-256 para búsquedas sin revelar identificadores. |
| **L3** | `crates/gravital-id-issuer` | Implementado (F3) | Lógica pura de emisión de credenciales individuales y por lotes con claves, sales e índices independientes; cálculo de predicados de calendario precomputados (`age_over_18`, `age_over_21`). |
| **L3** | `crates/gravital-id-verifier` | Implementado (F4) | Pipeline de verificación en 11 etapas con patrón *typestate*, guardián de piso de tiempo `TimeFloorGuard` anti-rollback, `VerifierStateStore`, caché acotada de nonces anti-replay y `VerificationPolicy`. |
| **L3** | `crates/gravital-id-recovery` | Planificado (F8) | Algoritmos de recuperación social y distribuida de credenciales y claves mediante compartición de secretos de Shamir y rotación sin custodia. |
| **L4** | `crates/gravital-id-holder` | Implementado (F5) | Billetera del titular `HolderWallet`, gestión de `WalletCredential`, motor de evaluación de consultas DCQL (*Digital Credentials Query Language*), generación de planes de divulgación (*DisclosurePlan*) y vinculación con firma KB-JWT. |
| **L4** | `crates/gravital-id-protocol` | Implementado (F5) | Protocolo de presentación offline para códigos QR: serialización compacta `VerificationRequest`, transcodificación sin pérdida a CBOR determinista, compresión Base45 y segmentación Multi-QR acotada con presupuestos ópticos. |
| **L4** | `crates/gravital-id-proximity` | Especificado (F19, F20) | Protocolo de sesión de proximidad de corto alcance (NFC / BLE) con canal cifrado HPKE, transcrito canónico de sesión y protección contra ataques de retransmisión (*relay attacks*). |
| **L4** | `crates/gravital-id-sync` | En desarrollo activo (F7.T07) | Máquina de estados de sincronización sans-I/O: cola de operaciones cifrada en reposo, idempotencia estricta, backoff exponencial con jitter determinista, resolución de conflictos LWW y failover entre múltiples relays. |
| **L5** | `crates/gravital-id-storage-sqlite` | Implementado (F5) | Adaptador de almacenamiento en SQLite con WAL activado, transacciones `BEGIN IMMEDIATE`, cifrado a nivel de registro, migraciones automáticas versionadas e implementación de `VerifierStateStore`. |
| **L5** | `crates/gravital-id-transport-http` | En desarrollo (F7.T07) | Adaptador de transporte HTTP para la máquina de sincronización L4 y comunicación con servicios relay y endpoints de estado. |
| **L5** | `crates/gravital-id-transport-pcsc` | Especificado (F19, F21) | Adaptador de comunicación PC/SC para interactuar con lectores físicos de tarjetas inteligentes y tarjetas Java Card compatibles con el applet `GID-APDU`. |
| **L5** | `crates/gravital-id-ledger-evm` | Implementado (F6) | Adaptador EVM de alta disponibilidad con `MultiRpcClient`: rotación automática, failover entre nodos RPC, verificación cruzada de consistencia y tolerancia a reorganizaciones de cadena. |
| **L5** | `crates/gravital-id-service-common` | Implementado (F7) | Biblioteca común para microservicios: configuración tipada, instrumentación con OpenTelemetry y tracing, endpoints normativos `/healthz` y `/readyz`, y middleware de redacción estricta anti-PII. |
| **L6** | `crates/gravital-id-sdk` | Implementado / en expansión (F1, F5, F7) | Fachada unificada y ergonómica de la biblioteca para integradores en Rust. |
| **CLI**| `apps/pip-cli` (`gid-cli`) | Implementado (F4, F5) | Herramienta de línea de comandos para desarrollo, emisión, gestión de billetera local, verificación 100% offline, renderizado QR y ejecución de los escenarios de prueba oficiales M1 y offline. |
| **Smart Contracts** | `contracts/` | Implementado (F6) | Contratos inteligentes en Solidity 0.8.28 con suite Foundry: `TrustRegistry` (registro de operadores y emisores), `StatusAnchor` (anclaje de listas de estado) y `GovernanceTimelock` (gobernanza temporal multi-firma). 100% libre de datos personales. |
| **Servicios** | `services/` | Implementado (F7) | Microservicios del plano de soporte: `pip-issuer-service` (emisión), `pip-verifier-service` (verificación asistida), `pip-status-service` (listas de estado), `pip-relay` (retransmisión de sobres cifrados HPKE y buzones efímeros con SessionCode), `pip-indexer` (ingesta de eventos de blockchain hacia PostgreSQL) y `pip-trust-service` (compilación y firma de bundles). |
| **Testkit** | `crates/gravital-id-testkit` | Implementado (F1) | Utilidades de pruebas deterministas: `FixedClock`, `SeededRng` reproducible basado en xoshiro256** y generadores de datos sintéticos no correlacionados. |
| **WASM** | `bindings/wasm` | Implementado (F1.T13, F5) | Bindings para navegadores y entornos Node.js (`wasm32-unknown-unknown`) con pruebas de integración FFI. |

---

## Modelo de Verificación de 4 Estados

A diferencia de los sistemas de identidad convencionales que colapsan la verificación en un simple booleano (`true`/`false`), Gravital ID produce un resultado estructurado con evidencia forense inmutable estructurado en cuatro estados normativos (`INV-04`):

```text
                               +-----------------------------+
                               |     Presentacion recibida   |
                               +-----------------------------+
                                              |
                                              v
                               +-----------------------------+
                               | Pipeline de 11 Comprobaciones|
                               +-----------------------------+
                                              |
              +-------------------------------+-------------------------------+
              |                               |                               |
              v                               v                               v
     [Fallo critico]               [Evidencia incompleta]            [Comprobacion integra]
   - Firma invalida               - Clave de emisor revocada         - Criptografia valida
   - Modificacion de datos        - Snapshot local caducado          - Credencial vigente
   - Replay de nonce              - Revocacion no comprobable        - En ventana de frescura
              |                               |                               |
              v                               v                               v
         +---------+                  +---------------+               +---------------+
         | INVALID |                  | UNVERIFIABLE  |               | Estado Status |
         +---------+                  +---------------+               +---------------+
                                                                              |
                                                      +-----------------------+-----------------------+
                                                      |                                               |
                                                      v                                               v
                                              [Status fresco]                                 [Status caducado]
                                                      |                                               |
                                                      v                                               v
                                                 +---------+                             +------------------------+
                                                 |  VALID  |                             | VALID_WITH_STALE_STATUS|
                                                 +---------+                             +------------------------+
```

### Definición y Semántica de los Estados

| Estado | Significado Técnico | Decisión de Negocio Habitual |
|---|---|---|
| **`Valid`** | Todas las firmas criptográficas son válidas, la vinculación del titular es correcta, el nonce es fresco y la información de revocación está dentro de la ventana de frescura configurada por la política del perfil. | Acceso concedido plenamente. |
| **`ValidWithStaleStatus`** | La credencial es auténtica, no está alterada y pertenece al titular, pero el snapshot de revocación local ha superado la ventana de frescura de la política sin haber alcanzado el límite absoluto de descarte. | Acceso condicional para operaciones de bajo riesgo o solicitud de actualización de conectividad. |
| **`Unverifiable`** | No es posible determinar la validez debido a información ausente o degradada (por ejemplo, el emisor no está registrado en el trust bundle local, o el registro de estado no está disponible). | Solicitud de reintento o derivación a verificación alternativa asistida. |
| **`Invalid`** | Violación de integridad o seguridad comprobada: firma criptográfica incorrecta, divulgaciones alteradas, credencial expresamente revocada, expirada, o reutilización maliciosa de nonce (ataque de replay). | Acceso denegado de forma inmediata e irrevocable. |

### Precedencia Estricta y Filosofía Fail-Closed

El evaluador del pipeline aplica una precedencia estricta:
$$\text{Invalid} \succ \text{Unverifiable} \succ \text{ValidWithStaleStatus} \succ \text{Valid}$$

Si una sola comprobación de integridad o seguridad falla, el resultado final es irrevocablemente `Invalid`. Si no hay fallos de integridad pero falta información indispensable para dictaminar la validez, el resultado es `Unverifiable`. Ante cualquier error de ejecución o dato anómalo, el sistema aplica la filosofía *fail-closed* (`INV-05`) y nunca devuelve `Valid`.

---

## Pipeline de Verificación en 11 Etapas

El crate `gravital-id-verifier` ejecuta un pipeline secuencial de 11 etapas modelado mediante el patrón *typestate* en Rust, garantizando en tiempo de compilación que no se puedan omitir etapas ni evaluar propiedades secundarias antes de validar la autenticidad criptográfica:

1. **Parseo y Límites de Entrada:** Deserialización del payload y aplicación estricta de límites de tamaño y profundidad (protección anti-DoS).
2. **Validación de Cabecera:** Comprobación de parámetros JWS/JWT; imposición de `alg: ES256` y rechazo estricto de `alg: none` (`INV-08`).
3. **Resolución de Confianza en Bundle:** Búsqueda del emisor y su clave pública autorizada exclusivamente en el `TrustBundle` local preautenticado; cero I/O de red (`INV-01`, `INV-06`).
4. **Verificación de Firma del Emisor:** Validación criptográfica de la firma ECDSA P-256 (RFC 6979) sobre el Issuer-Signed JWT.
5. **Verificación de Divulgaciones Selectivas:** Comprobación de que cada valor divulgado coincide con su digest SHA-256 declarado y que la sal supera los 128 bits; detección de huérfanos y colisiones.
6. **Comprobación Temporal de Vigencia:** Evaluación de las marcas temporales `nbf` (not before), `iat` (issued at) y `exp` (expiration) frente al instante inyectado `UnixTime`.
7. **Verificación de Estado y Revocación:** Búsqueda del índice del titular en la Token Status List y comprobación del estado de vigencia conforme al `IssuerStatusManifest`.
8. **Comprobación de Vinculación del Titular (Key Binding):** Verificación de la firma del titular en el KB-JWT, validando la coincidencia de `aud`, `nonce` y el hash de presentación `sd_hash`.
9. **Evaluación de la Política de Verificación:** Aplicación de las reglas de `VerificationPolicy` (frescura máxima admisible según el perfil: personal, financiero o empresarial).
10. **Protección Anti-Replay:** Verificación de no reutilización del `nonce` en la ventana activa mediante consulta atómica a `NonceCache`.
11. **Consolidación de Evidencia:** Construcción del `VerificationResult` final con el vector de pruebas y estado normativo resultante.

---

## Modos de Operación y Transporte

### 1. Verificación Offline por Código QR (F5)

Permite presentar credenciales directamente desde la pantalla de un teléfono móvil hacia un terminal o lector sin ninguna conexión a Internet en ninguno de los dos extremos:

- **Estructura de la Solicitud:** El verificador genera una `VerificationRequest` (firmada opcionalmente con JWS) con un nonce aleatorio de 128 bits y una lista de atributos solicitados.
- **Transcodificación y Compresión:** La solicitud y la presentación se transcodifican a CBOR determinista (RFC 8949), se comprimen con DEFLATE acotado y se codifican en Base45 (RFC 9285).
- **Segmentación Multi-QR:** Para presentaciones que superan la capacidad óptica recomendada de un único código QR (máximo 800 caracteres Base45 para lectura instantánea en condiciones de baja luminosidad), el protocolo segmenta automáticamente el mensaje en múltiples cuadros secuenciales con cabeceras de reensamblado deterministas.
- **Validado en Hardware Real:** Probado empíricamente con 100% de éxito en terminales de bajo coste (Xiaomi Redmi 9A, Samsung Galaxy A53), dispositivos de gama alta (Apple iPhone 15 Pro) y lectores industriales 2D (Honeywell Xenon 1900g).

### 2. Proximidad de Corto Alcance: NFC y Tarjetas Inteligentes (F19, F20, F21)

Diseñado para escenarios de contacto físico inmediato ("tap") en control de accesos, transporte público o puntos de venta:

- **Protocolo GID-APDU:** Conjunto de comandos y respuestas APDU conformes a ISO/IEC 7816-4 bajo el Application Identifier registrado (AID: `F0475241564954414C01`).
- **Canal Seguro HPKE:** Antes del intercambio de cualquier atributo, el terminal y el dispositivo del titular establecen una sesión cifrada mediante HPKE (RFC 9180: DHKEM P-256 + HKDF-SHA256 + ChaCha20-Poly1305).
- **Transcrito Canónico de Sesión:** El intercambio vincula criptográficamente el hash de los mensajes intercambiados (`SessionTranscript`) como AAD y como nonce en el Key Binding JWT, impidiendo ataques de intermediario o retransmisión a distancia (*relay attacks*).
- **Soporte Java Card y HCE:** Especificación y applet para tarjetas inteligentes Java Card 3.0.5+ y emulación de tarjeta por software (*Host Card Emulation*) en sistemas Android e iOS.

### 3. Sincronización Asíncrona y Puntos de Encuentro (F7)

Diseñado para intercambio remoto de credenciales o sincronización entre dispositivos del mismo titular:

- **Retransmisión sin Estado (*pip-relay*):** Servicios relay stateless de alta velocidad que almacenan y retransmiten sobres cifrados con HPKE dirigidos a buzones efímeros.
- **Punto de Encuentro con SessionCode:** Códigos numéricos de 10 dígitos protegidos contra errores de transcripción mediante la suma de comprobación Damm en base 10, permitiendo emparejar emisor y titular en segundos sin revelar números de teléfono ni correos electrónicos.
- **Descargas Públicas Anónimas:** Descarga de objetos inmutables (manifestos de emisor, trust bundles, listas de estado comprimidas) direccionados exclusivamente por su digest SHA-256, sin cabeceras de usuario ni cookies que permitan rastreo (`INV-02`).

---

## Almacenamiento, Portabilidad y Topología de Datos: Titular vs. Servidor

Para entender cómo opera Gravital ID en la práctica, es fundamental comprender la separación física y criptográfica de los datos: dónde reside la credencial, cómo se transfiere entre soportes (tarjetas inteligentes y teléfonos móviles), qué custodia cada entidad y cómo se garantiza el aislamiento absoluto entre usuarios.

### 1. Dónde Vive y Cómo se Aloja una Credencial en el Dispositivo

En la arquitectura de Gravital ID, la credencial reside bajo el control físico exclusivo del usuario en su dispositivo (teléfono móvil, ordenador o tarjeta inteligente):

```text
+-----------------------------------------------------------------------------------+
|                        DISPOSITIVO DEL TITULAR (SMARTPHONE)                       |
|                                                                                   |
|  +-------------------------------------+   +-----------------------------------+  |
|  |     ALMACENAMIENTO LOCAL CIFRADO    |   |     HARDWARE SEGURO (SILICIO)     |  |
|  |     (gravital-id-storage-sqlite)    |   |     (Secure Enclave / StrongBox)  |  |
|  |                                     |   |                                   |  |
|  |  [Registro Cifrado - Formato PIP$]  |   |  [Clave Privada HolderBinding]    |  |
|  |  - Cabecera: Version, Salt, Nonce   |   |  - Curva: NIST P-256 (secp256r1)  |  |
|  |  - Datos: Issuer-Signed SD-JWT      |   |  - Estado: Inexportable en RAM    |  |
|  |  - Algoritmo: XChaCha20-Poly1305    |   |  - Acceso: Protegido por PIN o    |  |
|  |  - Clave DEK envuelta con KEK       |   |            biometria del titular  |  |
|  |                                     |   +-----------------+-----------------+  |
|  |  [Indices Ciegos Anti-Inspeccion]   |                     |                    |
|  |  - HMAC-SHA256(KEK, Vct)            |                     | Solo firma KB-JWT  |
|  |  - HMAC-SHA256(KEK, IssuerId)       |                     v (la clave nunca    |
|  |  (Busqueda sin revelar texto plano) |             +-------+-------+            |
|  +-------------------------------------+             | FFI / Bindings| (INV-03)   |
|                                                      +---------------+            |
+-----------------------------------------------------------------------------------+
```

- **Estructura de Almacenamiento Cifrado (Formato `PIP$`):**
  La biblioteca `gravital-id-holder` y el adaptador `gravital-id-storage-sqlite` almacenan cada credencial en un contenedor seguro denominado `EncryptedRecord`. Cada registro utiliza un esquema de cifrado de sobre (*envelope encryption*):
  1. Se genera una Clave de Cifrado de Datos (DEK, *Data Encryption Key*) efímera de 256 bits mediante el CSPRNG del sistema.
  2. El payload de la credencial (el SD-JWT completo emitido con sus divulgaciones y sales) se cifra mediante XChaCha20-Poly1305 con datos asociados autenticados (AAD) que vinculan la versión y el ID del registro.
  3. La DEK se cifra (*envuelve*) utilizando la Clave de Cifrado de Claves (KEK, *Key Encryption Key*). La KEK se deriva de hardware seguro del dispositivo (mediante Secure Enclave en iOS con `kSecAccessControlBiometryAny`, StrongBox Keymaster en Android o TPM 2.0 en sistemas operativos de escritorio).
- **Índices Ciegos para Consultas Locales:**
  Para que la billetera pueda buscar credenciales por tipo (`vct`) o por emisor (`iss`) sin descifrar toda la base de datos y sin almacenar identificadores en claro en las tablas SQLite, se calculan tokens de búsqueda ciegos mediante `HMAC-SHA256(KEK, Vct)` y `HMAC-SHA256(KEK, IssuerId)`. Un atacante que extraiga el archivo SQLite de la memoria flash no puede determinar qué credenciales contiene ni a quién pertenecen.
- **Aislamiento Estricto de Claves Privadas (`INV-03`):**
  La clave privada que vincula al titular con su credencial (`HolderBinding`) reside exclusivamente en el chip de hardware seguro. El software de la billetera solo mantiene un manejador opaco (`KeyHandle`). Durante una presentación, el motor sans-I/O genera el hash de los atributos divulgados (`sd_hash`) y solicita al hardware seguro la firma ECDSA del KB-JWT. La clave privada nunca se expone a la memoria RAM de la aplicación ni cruza fronteras de FFI.

---

### 2. Cómo se Pasa la Información a una Tarjeta con Chip NFC o a un Móvil

El aprovisionamiento de credenciales y su transferencia entre soportes se realiza mediante protocolos estandarizados y canales cifrados de extremo a extremo:

#### A. Aprovisionamiento y Uso en una Tarjeta Inteligente NFC (Java Card 3.0.5+)

En entornos donde el usuario no utiliza un smartphone o prefiere un documento de identidad físico infalsificable (cédula digital, tarjeta de transporte, tarjeta corporativa), la credencial se aloja directamente en el silicio de una tarjeta inteligente conforme a `ADR-0024` y `PROTOCOL.md §7`:

```text
  [Estacion de Personalizacion]                     [Tarjeta Inteligente Java Card]
  (PC con lector PC/SC USB)                         (Chip seguro con Applet GID-APDU)
              |                                                     |
              | 1. SELECT AID (F0475241564954414C01)                |
              |---------------------------------------------------->|
              |                                                     | 2. Genera par P-256 interno
              | 3. Lee clave publica cnf.jwk                        |    en coprocesador de silicio
              |<----------------------------------------------------|    (clave privada inexportable)
              |                                                     |
              | 4. Emisor firma SD-JWT VC vinculando cnf.jwk        |
              |                                                     |
              | 5. APDU UPDATE_CREDENTIAL (fragmentos cifrados)     |
              |---------------------------------------------------->| 6. Graba SD-JWT y sales
              | 7. Respuesta de estado APDU 9000 (OK)               |    en memoria EEPROM/Flash
              |<----------------------------------------------------|
```

1. **Generación de Claves en Silicio:** El chip de la tarjeta ejecuta el applet `GidSpikeApplet` (desarrollado para Java Card 3.0.5+). Durante la inicialización, el coprocesador criptográfico genera internamente un par de claves EC P-256. La clave privada queda permanentemente bloqueada dentro del silicio y físicamente no puede ser leída ni extraída mediante ningún comando o sondeo externo.
2. **Personalización Presencial o en Fábrica (`gid-perso`):** La estación de enrolamiento, conectada a través de un lector de tarjetas inteligentes estándar mediante el adaptador `gravital-id-transport-pcsc`, lee la clave pública del chip (`cnf.jwk`). El emisor institucional incorpora esta clave en el claim de vinculación (`cnf`) de la credencial SD-JWT VC y firma el documento.
3. **Inyección por Comandos APDU (ISO/IEC 7816-4):** La credencial se transfiere a la tarjeta mediante una secuencia de comandos `GID-APDU` sobre el canal seguro de personalización. La tarjeta guarda el token y las divulgaciones en su memoria no volátil protegida.
4. **Verificación Offline por Contacto Físico ("Tap"):** Al acercar la tarjeta al lector NFC de un verificador offline:
   - Se abre una sesión cifrada efímera mediante HPKE (RFC 9180).
   - El lector transmite la solicitud de verificación (`VerificationRequest`) con un nonce aleatorio.
   - El titular introduce su PIN si la política exige autenticación explícita (Nivel 1).
   - El chip de la tarjeta selecciona los atributos consentidos, calcula el `sd_hash`, firma el KB-JWT utilizando su clave privada interna, y responde con la presentación en milisegundos mediante el comando `GET_PRESENTATION`.

#### B. Aprovisionamiento en un Dispositivo Móvil (Smartphone)

En un teléfono móvil, la credencial se transfiere mediante tres modalidades posibles:

- **Vía Internet o Relay Asíncrono (`pip-relay`):** La billetera móvil genera su par de claves en el Secure Enclave/StrongBox, contacta al servicio de emisión a través de un sobre cifrado con HPKE, y recibe la credencial emitida sin que ningún intermediario de red pueda descifrar su contenido. Si la emisión es presencial, el emparejamiento inicial puede realizarse mediante un código numérico efímero de 10 dígitos (`SessionCode`) protegido con suma de comprobación Damm.
- **Vía Código QR Offline:** En terminales de autoservicio desconectados, el emisor muestra en pantalla un código QR de aprovisionamiento (o una secuencia de multi-QRs Base45). La aplicación de la billetera escanea el código mediante la cámara, valida la firma del emisor contra su `TrustBundle` local e importa la credencial en su base de datos SQLite cifrada.
- **Emulación de Tarjeta (NFC HCE - *Host Card Emulation*):** La aplicación móvil puede activar el modo HCE para responder a lectores NFC externos como si fuera una tarjeta física, ejecutando el protocolo `GID-APDU` y permitiendo verificaciones rápidas por proximidad en molinetes y controles de acceso.

---

### 3. Qué Porta el Titular vs. Qué Custodia el Servidor

Una de las premisas fundamentales de Gravital ID es que el sistema **no** es un almacén de identidad centralizado. La distribución de responsabilidades y artefactos entre las partes es asimétrica y soberana:

| Entidad / Rol | Artefactos que Custodia y Almacena | Lo que NUNCA Tiene ni Conoce |
|---|---|---|
| **Titular (Usuario en su Móvil o Tarjeta)** | - Sus credenciales emitidas (SD-JWT con divulgaciones y sales).<br>- Su clave privada de vinculación (`HolderBinding`) en hardware seguro.<br>- Sus políticas de consentimiento y claves de cifrado local (KEK/DEK).<br>- Copia local del `TrustBundle` (emisores autorizados) y `StatusSnapshot` para operar sin red. | - No tiene claves privadas de los emisores.<br>- No custodia datos de ningún otro usuario. |
| **Servidor Emisor (Entidad Emisora)** | - Su propia clave privada de emisor (custodiada en HSM institucional FIPS 140-2 L3+).<br>- La Token Status List (mapa de bits comprimido de 1 y 2 bits).<br>- El manifiesto de estado de revocación (`IssuerStatusManifest`). | - **No custodia las claves privadas de los titulares.**<br>- **No necesita retener los datos personales tras la emisión** (el titular los porta en su credencial firmada).<br>- No sabe cuándo, dónde ni ante quién el usuario presenta su credencial. |
| **Servidor Verificador (Terminal o Lector Offline)** | - El `TrustBundle` actualizado con las claves públicas de emisores autorizados.<br>- La política de verificación local (`VerificationPolicy`).<br>- La caché de nonces (`NonceCache`) para prevenir ataques de replay.<br>- El snapshot local de estado de revocación (`StatusSnapshot`). | - **No almacena datos personales ni historiales de presentaciones** (`INV-02`).<br>- No retiene identificadores de titulares ni credenciales completas.<br>- No realiza consultas en línea durante la verificación (`INV-01`). |
| **Servicio de Retransmisión (`pip-relay`)** | - Sobres cifrados efímeros en tránsito dirigidos a buzones temporales.<br>- Objetos públicos inmutables (bundles, esquemas) indexados por digest SHA-256. | - **No tiene las claves para descifrar los sobres.**<br>- No conoce la identidad de los emisores ni de los titulares.<br>- No almacena metadatos persistentes de sesiones. |
| **Blockchain Pública / Ledger (EVM)** | - Contrato `TrustRegistry`: lista de operadores, emisores registrados, claves públicas y estados normativos.<br>- Contrato `StatusAnchor`: hashes SHA-256 y versiones de las listas de revocación.<br>- Contrato `GovernanceTimelock`: reglas de gobernanza y cofirmas $k$-de-$n$. | - **CERO datos personales, cero hashes de PII y cero identificadores de titulares** (`INV-02`).<br>- Ninguna cuenta, saldo, transacción ni billetera pertenece a usuarios finales. |

---

### 4. Aislamiento y Cero Relación entre Usuarios

Una duda frecuente en arquitecturas de identidad digital es si las credenciales de los usuarios guardan relación entre sí, o si un atacante, emisor o verificador puede correlacionar a distintos usuarios. En Gravital ID, **los usuarios están completa e irrevocablemente aislados**:

1. **Ausencia Total de un Identificador Global de Usuario:**
   No existe ningún "ID de usuario", número de cuenta único ni identificador persistente compartido en el protocolo. Cada titular interactúa con el sistema de forma completamente autónoma.
2. **Sales Criptográficas Independientes ($\ge 128$ bits) por Cada Atributo:**
   Conforme a la especificación SD-JWT (RFC 9901), cada claim emitido se combina con una sal aleatoria independiente generada mediante CSPRNG de alta entropía antes de calcular su hash:
   $$\text{digest} = \text{SHA-256}(\text{sal} \parallel \text{nombre\_claim} \parallel \text{valor})$$
   Dos usuarios que compartan exactamente el mismo dato (por ejemplo, el mismo nombre "Carlos", la misma fecha de nacimiento o la misma nacionalidad) poseen valores de digest totalmente distintos e imposibles de relacionar estadísticamente.
3. **Señuelos Criptográficos (*Decoys*):**
   Para evitar que dos usuarios puedan ser comparados o clasificados por el número de campos que contiene su credencial, el emisor inserta señuelos (*decoys* o hashes falsos indistinguibles) en la estructura de divulgaciones. Esto garantiza que una credencial con 3 atributos consentidos aparente exactamente la misma estructura que una con 10 atributos.
4. **Asignación Pseudoaleatoria en la Token Status List (`P-09`, `REQ-STAT-002`):**
   La posición que ocupa cada titular en el mapa de bits de revocación de la Token Status List se asigna de manera estrictamente pseudoaleatoria e impredecible dentro de un espacio de al menos 131.072 bits. La posición no sigue el orden de emisión, ni la cédula, ni la fecha. Dos personas que soliciten su credencial consecutivamente en el mismo mostrador reciben índices dispersos y no correlacionados, impidiendo cualquier ataque de análisis de tráfico o deducción cronológica.
5. **Cero Huella y Cero Cuentas en Blockchain:**
   En el registro de blockchain no existen cuentas, direcciones, claves públicas ni transacciones de los usuarios finales. Los titulares no pagan gas, no firman transacciones de ledger ni interactúan jamás con los nodos de la red. La blockchain solo actúa como tablón de anuncios criptográfico donde los emisores institucionales publican sus claves públicas de verificación.
6. **No Vinculabilidad entre Verificaciones:**
   Cuando un titular presenta su credencial ante un verificador A (por ejemplo, un control de acceso laboral) y posteriormente ante un verificador B (por ejemplo, una aerolínea), cada presentación genera una firma de vinculación (*Key Binding JWT*) con un nonce fresco, una audiencia diferente y un instante temporal independiente. Aun si el verificador A y el verificador B intercambiaran todas sus bases de datos, es matemáticamente imposible correlacionar que ambas presentaciones fueron realizadas por la misma persona.

---

## Contratos Inteligentes y Capa de Anclaje (EVM)

El protocolo utiliza contratos inteligentes en redes Ethereum / EVM exclusivamente como registro de confianza inmutable y público:

```text
               +---------------------------------------------------+
               |               GovernanceTimelock                  |
               | (Retardo temporal y multi-firma de gobernanza)    |
               +---------------------------------------------------+
                                         |
                         +---------------+---------------+
                         |                               |
                         v                               v
         +-------------------------------+ +-------------------------------+
         |         TrustRegistry         | |         StatusAnchor          |
         | (Operadores, emisores,        | | (Raices y hashes de estado,   |
         |  claves publicas y estados)   | |  version monotonica, cero PII)|
         +-------------------------------+ +-------------------------------+
```

- **`TrustRegistry.sol`:** Gestiona el ciclo de vida de los operadores de la red, los emisores autorizados, sus claves públicas JWK EC P-256 y sus estados normativos (`active`, `retired`, `suspended`, `compromised`).
- **`StatusAnchor.sol`:** Ancla periódicamente los hashes SHA-256 y las versiones de los manifiestos de estado de revocación de cada emisor.
- **`GovernanceTimelock.sol`:** Aplica un periodo de espera obligatorio (*timelock*) y requisitos de umbral multi-firma para cualquier modificación en la raíz de gobernanza.
- **Garantía Estricta Cero PII:** Los contratos no reciben ni emiten en sus eventos ningún identificador de titular, credencial ni dato personal. Esta propiedad es validada en CI mediante el script especializado `cargo xtask check-contracts-privacy`.
- **Adaptador de Resiliencia L5 (`gravital-id-ledger-evm`):** Cuenta con `MultiRpcClient`, que orquesta múltiples proveedores RPC con rotación por fallos, verificación cruzada de consistencia entre nodos para mitigar ataques de eclipse, y tolerancia automática a reorganizaciones de bloques.

---

## Ecosistema de Microservicios Backend

Para despliegues de infraestructura institucional y operadores de confianza, el repositorio incluye un plano de servicios modular en `services/`:

- **`pip-issuer-service`:** Microservicio de emisión de credenciales SD-JWT VC con soporte de transacciones de emisión individual y por lotes, integración con HSMs y firma delegada a través de `KeyStore`.
- **`pip-verifier-service`:** Microservicio de verificación de presentaciones en línea o asistida para integradores que requieren orquestar políticas complejas en servidores perimetrales.
- **`pip-status-service`:** Servicio de generación, mantenimiento y publicación de Token Status Lists y manifiestos de emisor con actualización periódica en almacenamiento S3 / CDN.
- **`pip-relay`:** Servicio de retransmisión de sobres cifrados HPKE, gestión de buzones de entrega diferida y emparejamiento con `SessionCode` numérico de 10 dígitos.
- **`pip-indexer`:** Demonio de ingesta continua que lee bloques finalizados de la blockchain EVM, detecta eventos de confianza y revocación, y los persiste en PostgreSQL con métricas de lag y detección de reorganizaciones.
- **`pip-trust-service`:** Compilador de trust bundles que agrega periódicamente los datos del ledger, coordina las firmas umbral $k$-de-$n$ de los operadores independientes y genera los bundles firmados para distribución a verificadores.
- **`pip-service-common`:** Núcleo compartido de infraestructura: configuración basada en variables de entorno tipadas, observabilidad con tracing OpenTelemetry, endpoints `/healthz` (liveness) y `/readyz` (readiness) y middleware de redacción de logs para garantizar cero PII en telemetría.

---

## Uso de la Herramienta de Línea de Comandos (`pip-cli`)

El binario `pip-cli` (también disponible como `gid-cli`) proporciona herramientas completas para desarrollo, pruebas de integración y demostraciones reproducibles:

```bash
# Compilar la herramienta CLI
cargo build -p pip-cli --release
```

### 1. Demostración de los 4 Estados Offline

Ejecuta la demostración scriptada y determinista que reproduce de forma 100% offline los 4 estados canónicos de verificación:

```bash
cargo run -p pip-cli -- demo-offline
```

### 2. Demostración Oficial del Hito M1 (Gate G5)

Ejecuta los escenarios normativos MVP-01 (verificación offline), MVP-02 (rechazo de firmas adulteradas y emisores no autorizados), MVP-03 (rechazo determinista de replay sobre SQLite) y realiza una inspección forense en la base de datos para certificar la ausencia total de datos personales:

```bash
cargo run -p pip-cli -- demo-m1
```

### 3. Flujo Completo de Extremo a Extremo Offline

Ejecuta el ciclo íntegro: emisor genera credencial -> wallet cifra e importa credencial -> verificador emite solicitud firmada -> wallet evalúa consulta DCQL y genera presentación QR Base45 con divulgación selectiva y KB-JWT -> verificador valida sin conexión:

```bash
cargo run -p pip-cli -- demo-flow-offline
```

### 4. Operaciones Manuales de Emisión y Verificación

```bash
# 1. Generar par de claves de emisor para desarrollo
cargo run -p pip-cli -- dev-issuer --out-jwk /tmp/issuer.jwk.json

# 2. Construir un trust bundle local que contiene al emisor
cargo run -p pip-cli -- dev-bundle \
    --issuer-uri https://issuer.cedula.example.gov \
    --jwk /tmp/issuer.jwk.json \
    --out /tmp/bundle.json

# 3. Generar una lista de estado de revocacion y snapshot local
cargo run -p pip-cli -- dev-status \
    --issuer-uri https://issuer.cedula.example.gov \
    --uri https://issuer.cedula.example.gov/status/1 \
    --bits 1 \
    --values 0,0,0,0 \
    --out /tmp/status.json

# 4. Emitir una credencial SD-JWT VC con atributos selectivos
cargo run -p pip-cli -- issue \
    --issuer-uri https://issuer.cedula.example.gov \
    --vct pip-personal-v1 \
    --with-disclosures \
    --out /tmp/credential.txt

# 5. Verificar la presentacion de forma 100% offline
cargo run -p pip-cli -- verify \
    --presentation /tmp/credential.txt \
    --bundle /tmp/bundle.json \
    --status-snapshot /tmp/status.json
```

---

## Verificación de Calidad y Comprobaciones Locales

El repositorio impone estándares de calidad rigurosos. Antes de realizar cualquier aportación, es obligatorio ejecutar localmente la batería completa de comprobaciones:

```bash
# 1. Compilacion exhaustiva de todos los targets y tests del workspace
cargo build --workspace --all-targets

# 2. Ejecucion de la suite completa de pruebas unitarias y de integracion
cargo test --workspace

# 3. Lints estrictos de Clippy sin advertencias permitidas
cargo clippy --workspace --all-targets --all-features -- -D warnings

# 4. Formateo estricto del codigo fuente
cargo fmt --all -- --check

# 5. Verificacion de reglas de arquitectura de capas y no_std (xtask)
cargo xtask check-layers

# 6. Validacion de la matriz de trazabilidad de requisitos (REQUIREMENTS.md)
cargo xtask trace

# 7. Comprobacion de integridad del catalogo canonico de errores (ERROR_CODES.md)
cargo xtask check-error-codes

# 8. Verificacion de ausencia de datos personales en contratos y eventos EVM
cargo xtask check-contracts-privacy

# 9. Verificacion de higiene en plantillas de despliegue e infraestructura (IaC)
cargo xtask check-deploy-hygiene

# 10. Ejecucion de los vectores de conformidad normativos SD-JWT VC
cargo xtask conformance

# 11. Auditoria de licencias y dependencias de terceros
cargo deny check
cargo audit
```

### Compilación Cruzada hacia Entornos Limitados

El núcleo de Gravital ID está optimizado para compilar en arquitecturas embebidas y WebAssembly sin sistema operativo:

```bash
# WebAssembly para navegadores y entornos de borde
cargo check -p gravital-id-credential --target wasm32-unknown-unknown

# Arquitectura embebida bare-metal ARM Cortex-M4 (no_std)
cargo check -p gravital-id-credential --target thumbv7em-none-eabihf
```

---

## Hoja de Ruta y Estado de Avance

El proyecto se desarrolla a través de una hoja de ruta dividida en 26 fases (`F0` a `F25`), estructuradas mediante compuertas de calidad (*Gates*, `G0` a `G25`) e hitos estratégicos (`M1` a `M3`, `MP1` a `MP3`):

- **F0 — Especificaciones, Arquitectura y Gobierno:** Completada (Gate `G0` cerrado formalmente el 2026-10-11).
- **F1 — Workspace Base, Toolchain y Calidad:** Implementada (20 crates configurados, toolchain Rust fijado en `rust-toolchain.toml`, `deny.toml`, pipelines de CI y lints restrictivos).
- **F2 — Primitivas Criptográficas y Codecs:** Implementada (Gate `G2` listo para revisión; 100% de vectores superados en RFC 7515, RFC 7638, RFC 5869, RFC 9180 y Wycheproof 799/799; cobertura criptográfica $\ge 92,46\,\%$).
- **F3 — Credenciales SD-JWT VC:** Implementada (RFC 9901, 24 vectores de conformidad normativos, esquemas de perfil y predicados de calendario).
- **F4 — Verificador Offline y Pipeline:** Completada (Gate `G4` cerrado formalmente el 2026-10-16; demostración offline determinista de 4 estados con `pip-cli demo-offline` y cobertura $\ge 90\,\%$).
- **F5 — Almacenamiento Cifrado, Protocolos Offline y Wallet:** Completada (Gate `G5` cerrado formalmente el 2026-10-16; **Hito M1 alcanzado**: verificación offline sans-I/O, rechazo de manipulaciones, protección anti-replay en SQLite y auditoría forense de cero PII en reposo).
- **F6 — Anclaje en Blockchain y Contratos Inteligentes:** Completada (Gate `G6` cerrado formalmente el 2026-10-17; contratos Solidity en testnet, 25 pruebas Foundry pasando, adaptador L5 `gravital-id-ledger-evm` con failover multi-RPC y 0 PII verificado).
- **F7 — Servicios de Soporte y Sincronización:** En progreso activo (F7.T01–F7.T06 completadas; `pip-relay`, `pip-status-service`, `pip-trust-service`, `pip-indexer`, `pip-service-common` implementados; tarea activa: F7.T07 `pip-sync`).
- **F8 a F18 — Recuperación, SDKs Móviles y Auditorías:** Planificadas según `docs/ROADMAP.md`.
- **F19 a F25 — Proximidad, Tarjetas Inteligentes e Identidad Oficial:** Fase F19 de especificación y spikes cerrada (Gate `G19` cerrado formalmente el 2026-10-15); fases de implementación de proximidad programadas (`F20`–`F21`).

---

## Mapa Documental y Gobernanza

El proyecto opera bajo el principio *spec-first*: toda decisión técnica y funcional se especifica y aprueba formalmente antes de escribir código.

| Documento | Ubicación | Contenido y Alcance |
|---|---|---|
| **Reglas de Agentes y Desarrollo** | [`AGENTS.md`](AGENTS.md) | Reglas operativas estrictas para agentes de IA y desarrolladores, protocolo de sesión, Definition of Done y manejo de issues. |
| **Arquitectura del Sistema** | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Modelo arquitectónico global, modelo de amenazas STRIDE/LINDDUN, topología de confianza y protocolos de intercambio. |
| **Requisitos Normativos** | [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) | Catálogo de 167 requisitos funcionales y no funcionales trazables con identificador único (`REQ-*`). |
| **Estructura del Proyecto** | [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Reglas de organización de carpetas, jerarquía estricta de capas L1–L6 y matriz de dependencias permitidas. |
| **Hoja de Ruta y Fases** | [`docs/ROADMAP.md`](docs/ROADMAP.md) | Planificación integral del proyecto en 26 fases (`F0`–`F25`), criterios de aceptación de tareas y definición de gates. |
| **Estado Vivo del Avance** | [`docs/STATUS.md`](docs/STATUS.md) | Fuente viva del estado actual, tareas en ejecución, notas de traspaso de cada sesión y registro de bloqueos. |
| **Matriz de Trazabilidad** | [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) | Mapeo bidireccional automatizado entre requisitos normativos (`REQ-*`) y pruebas de código en el repositorio. |
| **Catálogo de Errores** | [`docs/specs/ERROR_CODES.md`](docs/specs/ERROR_CODES.md) | Especificación de los 59 códigos de error normativos (`GID-E1001` a `GID-E9999`) agrupados en 9 familias. |
| **Perfiles Criptográficos** | [`docs/specs/CRYPTO_PROFILES.md`](docs/specs/CRYPTO_PROFILES.md) | Suites criptográficas fijadas, algoritmos autorizados, longitudes de clave y parámetros de seguridad. |
| **Especificación de Confianza** | [`docs/specs/TRUST_BUNDLE.md`](docs/specs/TRUST_BUNDLE.md) | Formato y serialización del trust bundle, reglas de encadenamiento multi-firma y políticas de revocación de claves. |
| **Especificación del Protocolo** | [`docs/specs/PROTOCOL.md`](docs/specs/PROTOCOL.md) | Flujos normativos de intercambio para códigos QR, proximidad NFC (`GID-APDU`), emparejamiento numérico y transporte web. |
| **Especificación de Contratos** | [`docs/specs/CONTRACTS.md`](docs/specs/CONTRACTS.md) | Interfaces ABI, eventos, patrones de gobernanza y restricciones de cero PII para contratos EVM. |
| **Perfiles de Credenciales** | [`docs/specs/profiles/`](docs/specs/profiles/) | Definición de atributos y esquemas normativos (`pip-personal-v1`, `pip-financial-v1`, `pip-enterprise-v1`, `pip-identity-v1`). |
| **Decisiones de Arquitectura** | [`docs/adr/`](docs/adr/) | Colección de 26 Registros de Decisiones de Arquitectura aceptados (`ADR-0001` a `ADR-0026`). |
| **Política de Seguridad** | [`SECURITY.md`](SECURITY.md) | Procedimiento para reporte responsable y gestión confidencial de vulnerabilidades de seguridad. |

---

## Licencia

Este proyecto se distribuye bajo **licencia dual MIT y Apache-2.0** (a elección del receptor), conforme a la decisión formal documentada en [`ADR-0002`](docs/adr/0002-licencia-y-contribucion.md).

- [`LICENSE-MIT`](LICENSE-MIT)
- [`LICENSE-APACHE`](LICENSE-APACHE)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
