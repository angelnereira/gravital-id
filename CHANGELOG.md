# Changelog

Todos los cambios relevantes de este proyecto se documentan aquí.
Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versionado: [SemVer](https://semver.org/lang/es/).
Cada componente publicado (SDK, servicios, contratos, especificación) indica su ámbito entre corchetes.

## [Unreleased]

### Added
- [docs] Paquete documental inicial: `AGENTS.md`, arquitectura, requisitos, estructura del proyecto, hoja de ruta F0–F18, plantillas de issues y PR, índice de ADRs.
- [docs] ADR-0016 a ADR-0020 (Propuestos): confianza por umbral, manifiesto de estado, emergencia limitada a suspensión, núcleo `no_std` con protocolos sans-I/O y fail-closed por tipos.

### Changed
- [docs] Revisión de arquitectura v0.2: raíz de confianza y bundles cofirmados k-de-n; manifiesto de estado fuera del bundle; estado `suspended`; claves de recuperación por emisor; SAS con compromiso previo; claves HPKE con propósito propio; estado persistente del verificador; transcodificación binaria para QR; estrategia de pánicos en WASM.
- [docs] Estructura: adaptadores `pip-storage-sqlite` y `pip-transport-http` en L5; `pip-sdk` como esqueleto vertical desde F1; pruebas de mutación, Kani y modelos formales.

### Fixed
- [docs] Contradicción sobre I/O en L3 (`pip-storage`), configuración de lints inaplicable (`forbid` y herencia de workspace), fase de REQ-STAT-002 y dependencia de F6.T08 respecto de F4.T03.

<!-- Secciones permitidas: Added, Changed, Deprecated, Removed, Fixed, Security -->
