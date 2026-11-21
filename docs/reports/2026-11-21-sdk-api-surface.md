# Revisión de la superficie pública del SDK — propuesta de congelación `0.x`

> **Fecha:** 2026-11-21 · **Tarea:** F9.T02 (issue #112) · **Requisito:** REQ-SDK-006
> **Estado:** revisión completada; **la congelación formal la declara el mantenedor**.

## 1. Objetivo

`gravital-id-sdk` es la **única API pública estable** del proyecto (`ARCHITECTURE.md §17`).
Antes de declarar la beta `0.x` congelada hay que (a) inventariar la superficie real,
(b) contrastarla con `docs/specs/SDK_API.md` y (c) dejar un control automático que impida
cambios incompatibles sin revisión. Este informe cubre (a) y (b); el job `semver` de
`.github/workflows/ci.yml` cubre (c) con `cargo-semver-checks`.

## 2. Superficie pública actual (`gravital-id-sdk`)

### 2.1 Contratos del host (inyectados por la plataforma)

| Tipo | Origen | Estado |
|---|---|---|
| `Clock` | `gravital-id-types` | Expuesto · acota el reloj (INV-11). |
| `Rng` | `gravital-id-crypto` | Expuesto · CSPRNG inyectado (INV-11). |
| `KeyStore` | `gravital-id-keys` | Expuesto · nunca exporta claves privadas (INV-03). |
| `StorageBackend` | `gravital-id-storage` | Expuesto. |
| `VerifierStateStore` | `gravital-id-verifier` | Expuesto · piso de tiempo y anti-replay. |
| `Transport` | `gravital-id-sync` | Expuesto · solo en adaptadores L5. |

### 2.2 Catálogo de errores y resultado de verificación

| Tipo | Estado |
|---|---|
| `ErrorCode`, `GidError`, `PipError` | Re-exportados; 49 códigos documentados en `ERROR_CODES.md`. |
| `VerificationResult`, `VerificationStatus`, `CheckEvidence` | Re-exportados · **cuatro estados con evidencia** (INV-04). |

### 2.3 Objetos del SDK

| Objeto | Métodos públicos | Estado |
|---|---|---|
| `TrustStore` | `new`, `import_root`, `import_bundle`, `active_root`, `active_bundle` | Implementado. |
| `Verifier` | `new`, `create_request`, `verify_presentation`, `audience` | Implementado. |
| `Wallet<B, R>` | Alias de `gravital_id_holder::HolderWallet` | Implementado. |
| `Issuer` | Re-export de `gravital_id_issuer::Issuer` | Implementado. |
| `VERSION` | Constante del crate | Implementado. |

### 2.4 Features

`verifier`, `holder`, `issuer` y `sync` permiten compilar subconjuntos en plataformas con
presupuesto reducido (F9.T01).

## 3. Hallazgos de la revisión

| # | Hallazgo | Severidad | Acción antes de congelar |
|---|---|---|---|
| 1 | `TrustStore` no expone `import_status_manifest`, declarado en `SDK_API.md §2.1`. | Media | Añadir el método o documentar su traslado a `F7.T05`/`IssuerStatusManager`. |
| 2 | `TrustStore` no expone `get_issuer(issuer_id)` ni `trusted_time_floor()`, ambos en `SDK_API.md §2.1`. | Media | Añadirlos o declararlos explícitamente fuera de la beta. |
| 3 | `Wallet<B, R>` es un *type alias*, no un tipo nuevo; `SDK_API.md §2.3` describe los métodos `import_credential`, `prepare_presentation` y `confirm_presentation` en el alias. | Baja | Comprobar que el alias expone exactamente esos métodos y documentar la decisión. |
| 4 | No existía control automático de compatibilidad SemVer antes de F9.T02. | Alta | **Resuelto**: job `semver` en CI con `cargo-semver-checks` contra la base del PR. |

Los hallazgos 1–3 **no bloquean** la ejecución de F9.T02: son desviaciones documentadas entre
la implementación y la especificación, y su resolución debe decidirse antes de la declaración
formal de congelación.

## 4. Control automático activado

`.github/workflows/ci.yml` incluye el job `semver`:

- Instala `cargo-semver-checks` con `taiki-e/install-action`.
- Compara `gravital-id-sdk` contra la base del PR (o el commit anterior en pushes).
- Falla si aparece un cambio incompatible con SemVer.
- Usa `fetch-depth: 0` para disponer del histórico completo.

## 5. Propuesta de congelación (decisión del mantenedor)

Se propone declarar **congelada la API `0.1.x` para la beta** una vez resueltos los
hallazgos 1–3 o aceptados como diferimientos documentados. A partir de ese momento:

1. Todo cambio de la superficie pública pasaría por revisión de `CODEOWNERS`.
2. `cargo-semver-checks` sería obligatorio en todos los PRs que toquen el SDK o sus crates
   re-exportados.
3. Las nuevas capacidades se a\u00f1adir\u00edan de forma aditiva; los cambios rompientes exigir\u00edan
   ADR.

**Decisión pendiente:** el mantenedor debe aprobar la congelaci\u00f3n y pronunciarse sobre los
hallazgos 1–3. Este informe no la declara por su cuenta.
