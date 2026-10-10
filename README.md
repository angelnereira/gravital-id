# PIP — Portable Identity Protocol *(nombre de trabajo)*

Protocolo de identidad portable con núcleo en Rust: credenciales verificables, divulgación selectiva, **verificación offline sin servidor central**, almacenamiento local cifrado, blockchain pública como registro de confianza compartido y recuperación segura. Integrable como biblioteca o SDK desde Kotlin, Swift, TypeScript/JavaScript, Python, Dart, Go, C# y C/C++.

> **Estado:** Fase **F0 — Fundación y especificación**. Aún no hay código de producción. Ver [`docs/STATUS.md`](docs/STATUS.md).
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

## Empezar a contribuir

1. Lee [`AGENTS.md`](AGENTS.md) completo.
2. Revisa [`docs/STATUS.md`](docs/STATUS.md) y elige una tarea de la fase actual en [`docs/ROADMAP.md`](docs/ROADMAP.md).
3. Abre o toma el issue correspondiente y sigue el flujo de [`AGENTS.md §6`](AGENTS.md#6-flujo-de-trabajo).

## Licencia

Pendiente de ADR-0002 (propuesta: dual MIT / Apache-2.0).
