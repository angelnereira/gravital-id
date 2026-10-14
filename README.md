# PIP — Portable Identity Protocol *(nombre de trabajo)*

Protocolo de identidad portable con núcleo en Rust: credenciales verificables, divulgación selectiva, **verificación offline sin servidor central**, almacenamiento local cifrado, blockchain pública como registro de confianza compartido y recuperación segura. Integrable como biblioteca o SDK desde Kotlin, Swift, TypeScript/JavaScript, Python, Dart, Go, C# y C/C++.

> **Estado:** Fase **F4 — Estado, confianza y verificación offline (en curso)**. Fase F3 (credenciales SD-JWT VC) implementada y revisada; el gate G3 está abierto a revisión del mantenedor. Ver [`docs/STATUS.md`](docs/STATUS.md).
> **Nombre:** "PIP" es provisional (colisiona con el gestor de paquetes de Python). Se decide en ADR-0001.

## Este proyecto está gobernado por su documentación

La documentación define principios, requisitos, arquitectura y orden de trabajo. El código la implementa; nunca al revés.

| Documento | Para qué sirve |
|---|---|
| [`AGENTS.md`](AGENTS.md) | **Reglas obligatorias** para agentes de código y desarrolladores: invariantes, flujo de trabajo, política de bugs, Definition of Done. |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Qué se construye y por qué: viabilidad, principios, capas, componentes, seguridad. |
| [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) | Requisitos funcionales y no funcionales con IDs trazables. |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | Dónde vive cada cosa y qué puede depender de qué. |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Hoja de ruta completa F0–F18, de repositorio vacío a producción y operación. |
| [`docs/STATUS.md`](docs/STATUS.md) | Estado vivo del proyecto y notas de traspaso. |
| [`docs/adr/`](docs/adr/README.md) | Decisiones de arquitectura (aceptadas y pendientes). |
| [`docs/specs/`](docs/specs/README.md) | Especificaciones normativas detalladas (se redactan en F0). |
| [`SECURITY.md`](SECURITY.md) | Cómo reportar vulnerabilidades (nunca como issue público). |

## En una frase, cómo funciona

Un **emisor** autorizado firma una credencial SD-JWT VC para el **titular**; el titular la guarda cifrada en su dispositivo y, ante un **verificador**, presenta solo los atributos pedidos, vinculados a esa sesión; el verificador la comprueba **localmente** con un *trust bundle* cofirmado por operadores independientes y derivado de un **registro público en blockchain** que dice qué emisores y claves son válidos. Ningún dato personal toca la cadena.

## Qué hay implementado hoy

Núcleo en Rust (`no_std` + `alloc` en L1–L3, sans-I/O en L4) con 20 crates `gravital-id-*` y verificación automática de capas, trazabilidad y códigos de error.

| Zona | Crates | Estado |
|---|---|---|
| Tipos, codec y criptografía | `gravital-id-types`, `-codec`, `-crypto`, `-keys` | **Listos** (F2). Vectores externos RFC 7515/7638/5869/9180 y Wycheproof al 100 %; cobertura de crypto ≥ 90 %. |
| Credenciales SD-JWT VC | `gravital-id-credential`, `gravital-id-issuer` | **Listos** (F3). Emisión RFC 9901 con divulgación selectiva, capa SD-JWT VC, esquemas de perfil, predicados precomputados, KB-JWT y emisión por lotes. |
| Estado | `gravital-id-status` | **En curso** (F4.T01–T02 hechos). Token Status List, manifiesto de estado y caché con frescura por perfil. |
| Confianza y verificación | `gravital-id-trust`, `-verifier` | Pendiente (F4.T03 en adelante). |

**Verificación:** `cargo fmt`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, suite de pruebas del workspace, `cargo xtask check-layers`, `cargo xtask trace`, `cargo xtask check-error-codes` y `cargo xtask conformance` (24 vectores de conformidad SD-JWT VC).

```bash
# Compilar y verificar todo
cargo build --workspace
cargo test --workspace
cargo xtask conformance    # vectores de conformidad publicados
```

## Empezar a contribuir

1. Lee [`AGENTS.md`](AGENTS.md) completo.
2. Revisa [`docs/STATUS.md`](docs/STATUS.md) y elige una tarea de la fase actual en [`docs/ROADMAP.md`](docs/ROADMAP.md).
3. Abre o toma el issue correspondiente y sigue el flujo de [`AGENTS.md §6`](AGENTS.md#6-flujo-de-trabajo).

## Licencia

Este proyecto se distribuye bajo **licencia dual MIT y Apache-2.0** (a elección del receptor), formalizado en [`ADR-0002`](docs/adr/0002-licencia-y-contribucion.md).

- [`LICENSE-MIT`](LICENSE-MIT)
- [`LICENSE-APACHE`](LICENSE-APACHE)
- [`CONTRIBUTING.md`](CONTRIBUTING.md)
