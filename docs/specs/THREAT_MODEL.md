# Especificación PIP: Modelo de Amenazas y Privacidad (STRIDE + LINDDUN)

> **Identificador normativo:** `SPEC-PIP-SEC-001`  
> **Versión:** `0.2.0-draft` (Fase F0 `F0.T05` / Fase F19 `F19.T10`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-15  
> **Trazabilidad:** REQ-SEC-001..011, REQ-PRIV-001..006, REQ-KEY-001..008, REQ-VER-001..012, REQ-PROX-001..008, REQ-CARD-001..005, REQ-CODE-001..004, REQ-IDDOC-001..003; ADR-0016, ADR-0017, ADR-0018, ADR-0020, ADR-0021, ADR-0022, ADR-0023, ADR-0024, ADR-0025, ADR-0026; P-02, P-03, P-05, P-07, P-08, P-09, P-10; INV-01, INV-02, INV-03, INV-05, INV-06, INV-16.

---

## 1. Activos del Sistema y Actores

### 1.1 Activos Críticos
1. **Claves Privadas de Emisor:** Material criptográfico asimétrico utilizado para emitir credenciales válidas.
2. **Claves Privadas de Titular (`KeyStore` y Elemento Seguro de Tarjeta):** Claves de vinculación ligadas a hardware (StrongBox/TEE, Secure Enclave o chip Java Card) utilizadas para firmar el KB-JWT de presentación.
3. **Secreto de Recuperación y Semilla Maestra:** Entropía de respaldo para re-vincular credenciales tras pérdida de dispositivo.
4. **Datos Personales, Retrato Facial y Claims:** Atributos de identidad del titular (PII), incluido el retrato JPEG y número de documento en `pip-identity-v1`.
5. **Raíz de Confianza (`TrustRoot`) y `TrustBundle`:** Documentos que definen qué emisores, verificadores y claves son confiables.
6. **Listas de Estado (Token Status Lists):** Registro de validez, suspensión o revocación de credenciales y tarjetas físicas.
7. **Claves Efímeras y Transcrito de Sesión de Proximidad (`SessionTranscript`):** Material efímero P-256 de acuerdo de claves y contexto canónico que protege la confidencialidad e integridad de cada toque NFC/BLE o código de sesión.

### 1.2 Perfiles de Amenaza y Actores Maliciosos
* **Atacante de Red Activo (Man-in-the-Middle):** Puede interceptar, modificar, inyectar o retener tráfico en transportes en línea o relays.
* **Atacante de Radiofrecuencia Cercano (Eavesdropper / Skimmer / Relay NFC-BLE):** Opera una antena oculta o pareja de dispositivos (*ghost-and-leech*) para escuchar el canal sin contacto, interrogar tarjetas/teléfonos en el bolsillo o retransmitir comandos APDU a distancia en tiempo real.
* **Operador de Relay Malicioso:** Proveedor de infraestructura que distribuye sobres cifrados, listas de estado o sesiones de código numérico.
* **Verificador Malicioso o Curioso:** Intenta correlacionar presentaciones entre servicios, provocar fuga de atributos no consentidos, persistir retratos sin base legal o retransmitir solicitudes a otras wallets.
* **Emisor Corrupto o Coaccionado:** Intenta presentar vistas divididas (*split-view*) de revocación, extraer claves durante la personalización de tarjetas o emitir credenciales no conformes.
* **Operadores de Bundle Comprometidos:** Subconjunto de operadores que intentan avanzar artificialmente la versión de bundle (*forced version advance*).
* **Malware en Dispositivo Host:** Software malicioso en el espacio de usuario que intenta leer memoria flash, interceptar llamadas de HCE o suplantar el diálogo de consentimiento.

---

## 2. Fronteras de Confianza (*Trust Boundaries*)

```text
┌────────────────────────────────────────────────────────────────────────┐
│ DISPOSITIVO HOST (Wallet / Verifier)                                   │
│                                                                        │
│   ┌───────────────────────────┐    Frontera FFI (Pánico capturado)     │
│   │ Aplicación Host / UI      ├────────────────────────────────────┐   │
│   └─────────────┬─────────────┘                                    │   │
│                 │ Inyección de Traits                              ▼   │
│   ┌─────────────┴─────────────┐         ┌───────────────────────────┐  │
│   │ Adaptadores L5 (Host)     │         │ Núcleo PIP (Rust L1-L4)   │  │
│   │ KeyStore, Clock, Storage  ├────────>│ Sans-I/O, no_std,         │  │
│   └─────────────┬─────────────┘         │ Cero PII en memoria       │  │
│                 │                       └───────────────────────────┘  │
│   Frontera Hardware de Seguridad                                       │
│   (Secure Enclave / StrongBox / Keystore / Chip Java Card)             │
│   [ Claves Privadas Titular - NUNCA SALEN ]                            │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ Frontera de Transporte (QR / NFC GID-APDU / BLE / HPKE Relay)
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ RED EXTERNA, RADIOFRECUENCIA & SERVICIOS (NFC, BLE, Relays, Blockchain)│
│ [ No confiables - Solo transportan hashes y sobres cifrados HPKE ]     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Análisis STRIDE de Seguridad (Núcleo Base)

| Categoría | Amenaza Específica | Impacto | Control Técnico y Mitigación | Requisito / ADR |
|---|---|---|---|---|
| **Spoofing** (Suplantación) | Falsificación de emisor mediante cabecera `jku`/`x5c` maliciosa. | Aceptación de credencial falsa. | Las claves del emisor **solo** se resuelven desde el `TrustBundle` activo. Cabeceras externas se ignoran incondicionalmente. | REQ-VER-004, INV-06 |
| **Spoofing** (Suplantación) | Presentación de credencial robada sin autorización del titular. | Suplantación de identidad. | Key Binding JWT (KB-JWT) obligatorio firmado por hardware del titular con `nonce` y `aud` efímeros vinculados al claim `cnf`. | REQ-PRES-002, INV-03 |
| **Tampering** (Alteración) | Modificación de claims en tránsito dentro de una presentación. | Corrupción de datos verificados. | Cada claim se valida contra su digest en el SD-JWT firmado. Modificaciones invalidan la firma. | REQ-CRED-001 |
| **Tampering** (Alteración) | Ataque de avance forzado de versión de bundle (*Forced Advance*). | Bloqueo permanente de bundles legítimos. | La TFA emite una nueva `TrustRoot` que incrementa `bundle_epoch`, reiniciando la numeración monotónica. | REQ-TRUST-009, ADR-0016 |
| **Repudiation** (Repudio) | Emisor niega haber revocado una credencial o muestra estados distintos. | Fraude de revocación (*Split-view*). | Compromisos de manifiesto de estado anclados en el contrato `StatusAnchor` en blockchain. | REQ-STAT-006, ADR-0017 |
| **Information Disclosure** | Extracción forense de credenciales desde almacenamiento de teléfono extraviado. | Fuga masiva de PII. | Cifrado de sobre (DEK/KEK) con `XChaCha20-Poly1305` y consultas mediante índices ciegos HMAC-SHA256 (sin PII en claro). | REQ-STOR-001, REQ-STOR-003 |
| **Information Disclosure** | Identificación de titulares en transferencias de red o ledger. | Pérdida de soberanía/privacidad. | Cero datos personales, ni hashes de baja entropía, en transacciones, logs o métricas. | INV-02, REQ-LEDG-001 |
| **Denial of Service** | Ataque de bomba de compresión (*Zip Bomb*) en Token Status Lists. | Caída por agotamiento de RAM. | Ratio de expansión DEFLATE restringido estrictamente a $\le 10:1$ y tope absoluto de 2 MiB. | REQ-STAT-003, PIP-E1007 |
| **Elevation of Privilege** | Compromiso de clave de respuesta a incidentes de emergencia. | Destrucción permanente del registro. | El `EMERGENCY_ROLE` **solo puede suspender** temporalmente; la suspensión caduca sola en 14 días (ADR-0018). | REQ-LEDG-004, ADR-0018 |

---

## 4. Análisis LINDDUN de Privacidad (Núcleo Base)

| Categoría LINDDUN | Amenaza de Privacidad | Mitigación del Protocolo PIP |
|---|---|---|
| **Linkability** (Vinculabilidad) | Correlación de un titular entre múltiples verificadores o transacciones. | Claves de vinculación (`cnf`) generadas independientemente por credencial/lote; cero identificadores globales de titular; índices ciegos locales. |
| **Identifiability** (Identificabilidad) | Revelación innecesaria de atributos personales en verificaciones cotidianas. | Divulgación selectiva estricta con SD-JWT (RFC 9901); soporte para predicados precomputados (`age_over_18`). |
| **Non-repudiation** (No repudio lesivo) | Asociación permanente de una consulta de verificación al titular. | El titular no firma la solicitud; el KB-JWT está vinculado únicamente a la sesión efímera del verificador con `aud` y `nonce`. |
| **Detectability** (Detectabilidad) | Descubrimiento de qué credencial se revoca analizando descargas de estado. | Token Status Lists con tamaño mínimo ($\ge 131,072$ bits), índices aleatorios y descarga completa por CDN/relay (sin consultas por índice). |
| **Disclosure of Information** | Exfiltración de atributos a relays intermediarios en sincronización. | Sobres de operación cifrados extremo a extremo mediante HPKE (RFC 9180) direccionados por contenido. |
| **Unawareness** (Falta de consentimiento) | Divulgación accidental de atributos sin intervención del usuario. | Separación arquitectónica estricta en el SDK entre fase de preparación (`prepare_presentation`) y confirmación biométrica (`confirm_presentation`). |
| **Non-compliance** (Incumplimiento legal) | Retención indebida de atributos en verificadores locales. | Perfil personal prohíbe retención de claims; verificación offline devuelve estado sin almacenar copias de credenciales en disco. |

---

## 5. Adenda de Proximidad, Tarjeta Física, Código de Sesión y Retrato (`F19.T10`)

Esta sección extiende el modelo STRIDE y LINDDUN a los factores de forma y transportes añadidos en **ADR-0021** a **ADR-0026**.

### 5.1 Análisis STRIDE de Proximidad, Tarjetas y Códigos Numéricos

| Categoría STRIDE | Amenaza Específica | Impacto | Control Técnico y Mitigación | Requisito / ADR |
|---|---|---|---|---|
| **Information Disclosure** | Escucha pasiva de la radio NFC o BLE (*RF Eavesdropping*) con antena cercana. | Exfiltración de PII y retrato facial en tránsito. | `ProximityResponse` sellada extremo a extremo con **HPKE Modo Base (RFC 9180)** hacia la clave efímera P-256 (`eph_pub`) del verificador; `HolderHello` carece de PII. | REQ-PROX-001, ADR-0023 |
| **Spoofing / Tampering** | Ataque de retransmisión (*Relay / Wormhole Attack*) o reenvío a otra sesión/verificador. | Uso en tiempo real de una tarjeta o teléfono lejano ante otro terminal. | Vinculación criptográfica doble al `SessionTranscript`: `transcript_hash = SHA-256(cbor_det(SessionTranscript))` como `aad` de HPKE y como `nonce` del KB-JWT; solicitud firmada con identidad del verificador visible en móvil; PIN obligatorio para Nivel 1 en tarjeta; ventanas de expiración cortas. | REQ-PROX-002, REQ-CARD-003, ADR-0023 |
| **Information Disclosure** | Interrogación clandestina en el bolsillo o bolso (*Skimming NFC*). | Lectura no autorizada de datos sin que el titular lo perciba. | En teléfono Android: HCE solo responde si la wallet fue explícitamente armada por el titular (`REQ-PROX-006`). En tarjeta física: sin PIN solo están disponibles predicados de Nivel 0 (`age_over_18`); claims sensibles (`document_number`, `portrait`, `birth_date`) exigen `VERIFY PIN` (`SW=6982`, `GID-E8005`). | REQ-PROX-006, REQ-CARD-003, ADR-0022, ADR-0024 |
| **Spoofing** | Clonación física de tarjeta sin contacto o extracción de clave privada en personalización. | Emisión de presentaciones falsas en nombre del titular. | Par de claves P-256 generado dentro del elemento seguro Java Card (`KeyPair.ALG_EC_FP`), no exportable ni siquiera en estado `PERSONALIZACION`; cada toque firma un KB-JWT fresco en el coprocesador. | REQ-CARD-001, INV-03, ADR-0024 |
| **Tampering / Elevation of Privilege** | Inyección no autorizada de credenciales en una tarjeta física ya emitida. | Sustitución de la identidad almacenada en la tarjeta. | Escritura de credenciales permitida exclusivamente en estado `PERSONALIZACION` autenticado criptográficamente por el emisor; transición irreversible a `ACTIVA` (`SW=6986` / `GID-E8009`). | REQ-CARD-002, ADR-0024 |
| **Spoofing** | Uso fraudulento de tarjeta o teléfono perdido o robado. | Suplantación presencial por quien halla el soporte físico. | Biometría/armado en teléfono y PIN de Nivel 1 en tarjeta; revocación remota inmediata del índice en la `Token Status List` sin contacto con la tarjeta (`01 = revocado`). | REQ-CARD-005, REQ-STAT-001, ADR-0024 |
| **Elevation of Privilege** | Verificador solicita atributos excesivos (p. ej. número de documento o retrato para un simple control de edad). | Recolección abusiva de PII. | Solicitudes firmadas obligatorias para claims sensibles (`REQ-PRES-007`); escalada a segundo toque (`ConsentPending`, `GID-E8004`) cuando la consulta excede lo armado; conjuntos preautorizados mínimos. | REQ-PRES-007, REQ-PROX-006, ADR-0026 |
| **Spoofing / Information Disclosure** | Fuerza bruta, adivinación o ingeniería social con el código numérico de 10 dígitos (`SessionCode`). | Intento de interceptar sesiones o engañar al titular por teléfono. | El `SessionCode` solo localiza la solicitud pública firmada del verificador (`REQ-CODE-003`); incluye dígito Damm (`REQ-CODE-002`), TTL $\le 180\text{ s}$, consumo atómico al primer uso y límites de tasa en el relay (`REQ-CODE-001`); la wallet muestra el nombre verificado del solicitante antes de consentir. | REQ-CODE-001, REQ-CODE-002, REQ-CODE-003, ADR-0025 |
| **Elevation of Privilege** | Malware en Android intercepta APDU en `HostApduService` o intenta usar la clave del titular. | Firma no autorizada de presentaciones desde segundo plano. | Adaptador Kotlin sin lógica de negocio (`INV-15`, `REQ-PROX-008`); clave de vinculación en StrongBox/TEE con requisito de autenticación de usuario; atestación de hardware en emisión para perfiles altos. | REQ-KEY-002, REQ-ISS-005, REQ-PROX-008, INV-15 |
| **Denial of Service** | Bloqueo intencional del PIN de una tarjeta física mediante intentos erróneos repetidos. | Inutilización de operaciones de Nivel 1 en la tarjeta. | Límite de 3–5 intentos en `OwnerPIN` (`SW=6983`, `GID-E8006`) manteniendo operativo el Nivel 0 si el perfil lo permite; comando de desbloqueo autenticado por el emisor (`RESET RETRY COUNTER`). | REQ-CARD-003, ADR-0024 |
| **Denial of Service / Elevation of Privilege** | Tramas APDU, mensajes CBOR o cabeceras JPEG malformadas enviadas para desbordar buffers. | Pánico o corrupción de memoria en el verificador o en la wallet. | Parsers CBOR, APDU y validadores JPEG estrictamente acotados (`64 KiB` máx., sin EXIF/COM) y cubiertos por objetivos de fuzzing continuos (`REQ-PROX-004`, `REQ-IDDOC-002`). | REQ-PROX-004, REQ-IDDOC-002, REQ-SEC-005 |
| **Tampering / Spoofing** | Divergencia semántica entre el applet Java Card y el núcleo Rust. | Aceptación o rechazo inconsistente o fallo criptográfico sutil. | Ejecución obligatoria de los vectores inmutables de `conformance/vectors/proximity/` contra el applet en `jCardSim` dentro de CI (`.github/workflows/cards.yml`). | REQ-CARD-004, INV-12, ADR-0024 |
| **Spoofing** | Presentación de una credencial de identidad derivada haciéndola pasar por cédula oficial del Estado. | Engaño sobre la autoridad emisora del documento. | Separación estricta de `vct`: `urn:gravital-id:vct:pip-identity-official-v1` (exclusivo registro civil) frente a `urn:gravital-id:vct:pip-identity-derived-v1`, validado contra la autorización del emisor en el `TrustBundle`. | REQ-IDDOC-001, ADR-0026 |

---

### 5.2 Análisis LINDDUN de Privacidad (Proximidad, Tarjeta, Código y Retrato)

| Categoría LINDDUN | Amenaza de Privacidad | Mitigación en el Alcance Ampliado | Requisito / ADR |
|---|---|---|---|
| **Linkability** (Vinculabilidad) | Rastreo de una tarjeta física entre múltiples verificadores por su clave pública fija (`cnf`) o por `document_number`. | Aprovisionamiento de lotes de credenciales con claves P-256 distintas en tarjetas con memoria suficiente (`REQ-KEY-008`, `R-18`); `HolderHello` sin identificadores únicos; `document_number` siempre de divulgación selectiva Nivel 1 y prohibido como clave de búsqueda del protocolo (`REQ-IDDOC-003`). | REQ-KEY-008, REQ-IDDOC-003, ADR-0024, ADR-0026 |
| **Identifiability / Disclosure** | Fuga de datos personales o nonces en los registros de depuración de transporte NFC/BLE/PC-SC. | Prohibición absoluta de registrar cargas útiles APDU, claims, nonces completos o números de sesión/emisor en logs, métricas o errores (`REQ-PROX-007`, `INV-02`). | REQ-PROX-007, INV-02 |
| **Detectability / Unawareness** | Acoso o generación de notificaciones no deseadas (*push bombing*) si se habilita el número opcional por emisor (Opción B de `ADR-0025`). | El número por emisor está **desactivado por defecto**; cuando un perfil lo habilite, se trata como dato personal (`INV-02`), exige solicitud firmada del verificador, aplica límites de tasa estrictos por número y permite bloqueo en la wallet (`REQ-CODE-004`). | REQ-CODE-004, ADR-0025 |
| **Non-compliance / Disclosure** | Almacenamiento subrepticio del retrato facial (`portrait`) o metadatos EXIF de ubicación en el terminal verificador. | Limpieza obligatoria de segmentos EXIF/GPS/COM en emisión y verificación; transmisión permitida solo por sesión cifrada NFC/BLE/Online; el verificador de referencia muestra el retrato en RAM volátil y **no lo persiste en disco** salvo política con base legal explícita (`REQ-IDDOC-002`). | REQ-IDDOC-002, ADR-0026 |

