# Changelog

Todos los cambios relevantes de este proyecto se documentan aquí.
Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versionado: [SemVer](https://semver.org/lang/es/).
Cada componente publicado (SDK, servicios, contratos, especificación) indica su ámbito entre corchetes.

## [Unreleased]

### Added
- [docs] Paquete documental inicial: `AGENTS.md`, arquitectura, requisitos, estructura del proyecto, hoja de ruta F0–F18, plantillas de issues y PR, índice de ADRs.
- [docs] ADR-0016 a ADR-0020 (Propuestos): confianza por umbral, manifiesto de estado, emergencia limitada a suspensión, núcleo `no_std` con protocolos sans-I/O y fail-closed por tipos.
- [specs] Especificación normativa `TRUST_BUNDLE.md` v0.1.0-draft (F0.T13): raíz de confianza encadenada, bundle multi-firma determinista, manifiesto de estado y anti-rollback con `bundle_epoch`.
- [specs] Especificación normativa `CRYPTO_PROFILES.md` v0.1.0-draft (F0.T06): algoritmos autorizados (ES256, SHA-256, XChaCha20), versiones fijadas de RFC 9901 y borradores, mitigaciones DoS.
- [docs] `ADR-0002`: Aceptación de licencia dual MIT / Apache-2.0 y política DCO 1.1 (F0.T03); archivos `LICENSE-MIT`, `LICENSE-APACHE` y `CONTRIBUTING.md`.
- [security] `SECURITY.md` definitivo (F0.T04): canal privado en GitHub Advisories, tiempos de SLA por severidad y política de Safe Harbor.
- [infra] 57 labels oficiales creados en GitHub según `AGENTS.md §8` y sincronización de los 5 issues pendientes iniciales (#1 a #5).

### Changed
- [docs] Aceptación formal de ADR-0016 a ADR-0020 por el mantenedor Angel Nereira (#2).
- [docs] Aceptación formal de ADR-0002 (licencia y DCO) por el mantenedor Angel Nereira.
- [governance] Adaptación de `AGENTS.md §6` y `§14` para régimen de mantenedor único en Fase F0 (#1).
- [docs] Revisión de arquitectura v0.2: raíz de confianza y bundles cofirmados k-de-n; manifiesto de estado fuera del bundle; estado `suspended`; claves de recuperación por emisor; SAS con compromiso previo; claves HPKE con propósito propio; estado persistente del verificador; transcodificación binaria para QR; estrategia de pánicos en WASM.
- [docs] Estructura: adaptadores `pip-storage-sqlite` y `pip-transport-http` en L5; `pip-sdk` como esqueleto vertical desde F1; pruebas de mutación, Kani y modelos formales.

### Fixed
- [docs] Contradicción sobre I/O en L3 (`pip-storage`), configuración de lints inaplicable (`forbid` y herencia de workspace), fase de REQ-STAT-002 y dependencia de F6.T08 respecto de F4.T03 (#3, #4, #5).

<!-- Secciones permitidas: Added, Changed, Deprecated, Removed, Fixed, Security -->
