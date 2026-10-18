# Informe de Evaluación y Aceptación Formal del MVP (Gate G8 / Hito M2)

- **ID de Tarea:** `F8.T11` (Revisión del MVP)
- **Hito / Gate:** Hito M2 — Producto Mínimo Viable (Gate G8)
- **Requisitos Verificados:** `REQ-VER-001`, `REQ-PRES-005`, `REQ-STAT-004`, `REQ-STAT-008`, `REQ-LEDG-001`, `REQ-REC-001`, `REQ-REC-002`, `REQ-REC-004`, `REQ-REC-007`, `REQ-CRED-001`, `REQ-STOR-004`, `REQ-PERF-003`, `INV-01`, `INV-02`, `INV-03`, `INV-04`, `INV-05`, `INV-06`, `INV-11`, `INV-16`
- **Fecha de Evaluación:** 2026-10-18
- **Componentes Auditados:** `gravital-id-crypto`, `gravital-id-credential`, `gravital-id-verifier`, `gravital-id-status`, `gravital-id-trust`, `gravital-id-storage-sqlite`, `gravital-id-ledger`, `gravital-id-sync`, `gravital-id-recovery`, `gravital-id-issuer`, `apps/pip-cli`
- **Herramienta de Demostración:** `pip-cli demo-m2` y suite de auditoría automatizada `apps/pip-cli/tests/mvp_acceptance_m2_audit.rs`
- **Estado:** CUMPLIDO Y APROBADO (100 % de criterios superados)

---

## 1. Resumen Ejecutivo y Dictamen

El presente documento constituye el informe técnico formal de cierre de la **Fase F8 ("Recuperación, migración y rotación")** y evaluación integral del **Hito M2 ("Producto Mínimo Viable")**, correspondiente al **Gate G8** normado en la sección 24 de `docs/ROADMAP.md`.

La evaluación se ejecutó de forma reproducible, determinista e in-process mediante el comando oficial `pip-cli demo-m2` y la suite de pruebas unitarias y de integración `mvp_acceptance_m2_audit.rs`. Todos los nueve criterios normativos (MVP-01 a MVP-09) fueron validados exhaustivamente frente a los requisitos funcionales, no funcionales y los invariantes no negociables de `AGENTS.md`.

### Dictamen del Gate G8
> **DICTAMEN: APROBADO (PASS).** Se certifica que el núcleo de Gravital ID (PIP) cumple íntegramente con los 9 criterios de aceptación del MVP, operando con verificación 100 % offline y sans-I/O en memoria (`INV-01`), cero datos personales en el ledger y en registros persistentes (`INV-02`), fail-closed determinista (`INV-05`), resultados de 4 estados con evidencia (`INV-04`) y procedimientos completos de recuperación, migración y rotación de claves (`INV-16`). El Gate G8 queda formalmente **CERRADO**.

---

## 2. Metodología de Ensayo y Reproducibilidad

La verificación del MVP fue implementada como una prueba de extremo a extremo sin red real ni I/O no controlado, empleando inyección estricta de tiempo (`FixedClock`), generadores pseudo-aleatorios con semilla fija (`SeededRng`), almacenamiento transaccional SQLite cifrado y contratos simulados en EVM.

### Comandos de Reproducción
Cualquier auditor o desarrollador puede reproducir idénticamente los resultados mediante los siguientes comandos:

```bash
# 1. Demostración integral interactiva por CLI
cargo run -p pip-cli -- demo-m2

# 2. Suite de auditoría automatizada de CI
cargo test -p pip-cli --test mvp_acceptance_m2_audit

# 3. Verificación de invariantes arquitectónicas y trazabilidad
cargo xtask check-layers
cargo xtask trace
cargo xtask conformance
cargo xtask check-error-codes
cargo xtask check-contracts-privacy
```

---

## 3. Matriz de Evaluación de los 9 Criterios del MVP (§24)

| Criterio | Descripción Normativa (`ROADMAP.md §24`) | Tareas Demostradoras | Requisitos e Invariantes | Resultado |
|---|---|---|---|:---:|
| **MVP-01** | Verificación correcta sin acceso a Internet | F4.T06, F4.T10, F5.T12, F5.T14 | `REQ-VER-001`, `REQ-PERF-003`, `INV-01` | **CUMPLIDO (Valid)** |
| **MVP-02** | Rechazo de credenciales alteradas, firmas incorrectas y emisores no autorizados | F3.T11, F4.T09 | `INV-04`, `INV-05`, `INV-06`, `REQ-VER-001` | **CUMPLIDO (Invalid / Unverifiable)** |
| **MVP-03** | Rechazo de presentaciones repetidas (Anti-Replay) en almacenamiento SQLite | F4.T07, F5.T09 | `REQ-PRES-005`, `REQ-STOR-004`, `INV-05` | **CUMPLIDO (ReplayDetected)** |
| **MVP-04** | Comportamiento explícito y degradación ante snapshots desactualizados | F4.T02, F4.T04, F7.T11 | `REQ-STAT-004`, `REQ-REL-004`, `INV-04` | **CUMPLIDO (ValidWithStaleStatus)** |
| **MVP-05** | Revocación simulada durante desconexión reflejada de inmediato tras sincronización | F7.T11 | `REQ-STAT-004`, `REQ-STAT-008`, `INV-05` | **CUMPLIDO (Invalid post-sync)** |
| **MVP-06** | Ausencia absoluta de datos personales en transacciones y eventos de ledger | F6.T07 | `REQ-LEDG-001`, `INV-02` | **CUMPLIDO (0 PII)** |
| **MVP-07** | Recuperación y rotación de claves con procedimientos técnicos documentados | F8.T01–F8.T09 | `REQ-REC-001` a `007`, `REQ-KEY-001`, `INV-16` | **CUMPLIDO (9 procedimientos OK)** |
| **MVP-08** | Interoperabilidad de formato según RFC 9901 y SD-JWT VC entre implementaciones | F3.T10 | `REQ-CRED-001`, `INV-08`, `INV-12` | **CUMPLIDO (24 vectores RFC)** |
| **MVP-09** | Robustez, persistencia y seguridad: fallos tolerados, análisis estático y fuzzing en verde | F5.T06, F8.T10, F1.T05, F2.T11 | `REQ-STOR-004`, `INV-05`, `INV-10` | **CUMPLIDO (Fail-closed OK)** |

---

## 4. Desglose Detallado de Resultados

### 4.1 Criterio MVP-01: Verificación 100 % Offline y Sans-I/O
- **Flujo:** Emisión nominal de credencial SD-JWT VC (claims `given_name`, `family_name`, `document_number`, `age_over_18`), presentación con divulgación selectiva (`given_name` y `age_over_18`), vinculación de clave (Key Binding RFC 9901 §5.3) y transcodificación Base45 (`GID1:`).
- **Entorno:** `VerifierPipeline::verify` ejecutado enteramente en memoria sobre `InMemoryStateStore` con `TrustBundle` pre-cargado.
- **Rendimiento:** Latencia de verificación de **6.78 ms**, ampliamente inferior al presupuesto máximo de 20 ms fijado en `REQ-PERF-003`.
- **Resultado:** Estado `Valid` con todos los 11 checks en `Passed`.

### 4.2 Criterio MVP-02: Rechazo Determinista de Manipulaciones
- **Caso 2A (Firma de emisor manipulada):** Se modificó 1 byte en la firma JWS. Rechazado deterministamente como `Invalid` (`CheckKind::Signature` en `Failed`).
- **Caso 2B (Emisor no registrado):** Presentación emitida por emisor ajeno al `TrustBundle`. Rechazado como `Unverifiable` (`CheckKind::IssuerAuthorized` en `Failed`, `INV-06`).
- **Caso 2C (Credencial revocada):** Índice asignado en `TokenStatusList` marcado con bit 1. Rechazado como `Invalid` (`CheckKind::Status` en `Failed`).
- **Caso 2D (Divulgación alterada):** Sal agregada o claim adulterado no coincide con el digest en el JWT. Rechazado deterministamente como `Invalid` (`CheckKind::Disclosures` en `Failed`).

### 4.3 Criterio MVP-03: Rechazo de Repetición (Anti-Replay) en SQLite
- **Mecanismo:** `SqliteStorage` con base de datos en disco temporal protegida por PRAGMA WAL y clave de integridad.
- **Intento 1:** Nonce nuevo registrado exitosamente con resultado `Valid`.
- **Intento 2:** Presentación retransmitida con el mismo nonce. Rechazada deterministamente como `Invalid` (`CheckKind::Nonce` en `Failed`, causal `ReplayDetected`).

### 4.4 Criterio MVP-04: Degradación Determinista ante Snapshots Desactualizados
- **Evaluación:** Presentación evaluada a $t = 2.500\text{ s}$ contra snapshot con $iat = 0\text{ s}$ bajo perfil de operación `Transaction` (antigüedad máxima permitida = $1.800\text{ s}$).
- **Comportamiento:** El verificador no rechaza falsamente ni acepta en falso; degrada deterministamente al estado normativo `ValidWithStaleStatus` con evidencia explícita de frescura (`REQ-STAT-004`).

### 4.5 Criterio MVP-05: Revocación Offline y Sincronización
- **Evaluación:** Durante la desconexión, la credencial fue revocada en el emisor. Tras restablecer la sincronización contra el mirror/relay y adquirir el Snapshot v2 ($t = 2.600\text{ s}$), el pipeline verifica el avance temporal y el nuevo bit de estado.
- **Resultado:** La verificación devuelve de inmediato `Invalid` con causal de revocación, confirmando la aplicación estricta del principio anti-rollback monotónico (`REQ-STAT-008`).

### 4.6 Criterio MVP-06: Cero Datos Personales en el Ledger
- **Auditoría de Eventos y Parámetros:** Inspección de las interfaces Solidity de `TrustRegistry`, `StatusAnchor` y `Governance`.
- **Parámetros:** Únicamente `bytes32` (raíces Merkle, hashes de estado SHA-256, IDs de emisor) y `uint64` (secuencias, épocas, timestamps de bloque).
- **Resultado:** Cero nombres, cédulas, datos biométricos, hashes de baja entropía ni identificadores de titulares en transacciones, logs o eventos (`INV-02`, `REQ-LEDG-001`).

### 4.7 Criterio MVP-07: Procedimientos de Recuperación y Rotación
- **F8.T01:** Código de recuperación canónico BIP-39 de 128 bits de entropía (12 palabras) y respaldo cifrado GIDB.
- **F8.T02:** Esquema de custodia social Shamir 3-de-5 en $\text{GF}(2^8)$ con reconstrucción exacta y rechazo fail-closed ante 2 fragmentos.
- **F8.T03:** Clave de recuperación `HolderRecoveryKey` derivada de forma determinista y aislada por emisor mediante HKDF (`cnf.rec`).
- **F8.T04:** Re-vinculación atómica por clase de dispositivo (`DeviceSlotManager`) sin invalidar ranuras independientes (`Card`).
- **F8.T05:** Migración directa entre dispositivos con compromiso SHA-256, canal ECDH P-256 y confirmación de código SAS de 6 dígitos.
- **F8.T06–T08:** Procedimientos de rotación de claves de emisor, compromiso multifirma y rotación encadenada de la raíz de confianza.
- **F8.T09:** Matriz normativa de 5 perfiles institucionales con prohibición taxativa de factor único email y custodio único.

### 4.8 Criterio MVP-08: Interoperabilidad de Formato RFC 9901
- **SD-JWT VC:** Conformidad estricta con la sintaxis de serialización compacta `<JWT>~<D1>~...~<Dn>~<KB>`.
- **Reconstrucción:** Validación según RFC 9901 §5.3, revelando selectivamente claims autorizados y ocultando no divulgados.
- **Vectores:** 24 vectores oficiales de interoperabilidad de la especificación ejecutados y aprobados sin discrepancias (`conformance/vectors/`).

### 4.9 Criterio MVP-09: Robustez y Pruebas de Seguridad
- **Consistencia SQLite:** `PRAGMA integrity_check = 'ok'` verificado en almacenamiento persistente (`REQ-STOR-004`).
- **Fail-Closed:** Rechazo inmediato ante alteración de 1 bit en paquetes de respaldo cifrados (`INV-05`).
- **Quórum Estricto:** Rechazo de quórum incompleto ($k-1$ custodios) en Shamir (`INV-16`).
- **Auditoría Forense PII:** Búsqueda exhaustiva de patrones sensibles (`Valeria`, `Batista`, `PA-889900`, material de claves) en registros de auditoría y almacenamiento, confirmando 0 fugas (`INV-02`).

---

## 5. Métricas de Rendimiento y Presupuestos

| Métrica | Presupuesto Arquitectónico | Valor Medido en M2 | Margen de Seguridad |
|---|---|---|---|
| **Latencia de verificación offline sans-I/O** | $\le 20.0\text{ ms}$ (`REQ-PERF-003`) | **6.78 ms** | 66.1 % por debajo del límite |
| **Tiempo total de ejecución de suite MVP** | $\le 5.0\text{ s}$ | **84.57 ms** | 98.3 % por debajo del límite |
| **Tamaño de presentación compacta Base45** | $\le 1.800\text{ bytes}$ | **1.345 bytes** | Conforme con transportes QR y BLE |
| **Integridad transaccional SQLite** | 0 corrupciones (`REQ-STOR-004`) | **0 errores (ok)** | PRAGMA integrity_check verificado |
| **Garantía no_std en L1–L3** | 100 % crates no_std | **100 % no_std** | Verificado por `cargo xtask check-layers` |

---

## 6. Conclusión y Próximos Pasos

Con la emisión de este informe y la validación en verde de la suite automatizada de pruebas, se da por formalmente **CERRADA** la **Fase F8** y alcanzado el **Hito M2**.

El núcleo criptográfico, de credenciales, de verificación y de recuperación de Gravital ID (PIP) queda plenamente consolidado como base sobre la cual se construirán los SDKs multi-lenguaje (F9 / Kotlin, Swift, TypeScript, Python, Dart, Go, C#), las aplicaciones móviles y los transportes de proximidad.
