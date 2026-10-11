---
title: "[SPEC-GAP] PROJECT_STRUCTURE.md: I/O en crates L3 y L4 contradice INV-01 y ARCHITECTURE §6"
labels: ["type:spec-gap", "status:needs-review", "phase:F0", "area:docs", "area:storage", "area:sync"]
issue: 4
url: https://github.com/angelnereira/gravital-id/issues/4
---

## Documentos implicados

- Documento A: `AGENTS.md §4` (INV-01) y `ARCHITECTURE.md §6`.
- Documento B: `PROJECT_STRUCTURE.md §3` y `§4` (regla 2).

## Descripción

- INV-01 (v0.1): "Ningún crate de las capas L1–L3 hace I/O".
- `PROJECT_STRUCTURE.md §3` (v0.1): `pip-storage` es L3 con "I/O: Sí (backend)" y "backend SQLite (feature `sqlite`)"; la regla 2 permite `rusqlite` en ese crate.
- `ARCHITECTURE.md §6` (v0.1) sitúa "storage (SQLite/host)" y "transport (host)" en L5, mientras `ARCHITECTURE.md §17.2` dice que `Transport` tiene "por defecto cliente HTTP interno" sin indicar en qué crate.

## Impacto

- Tareas bloqueadas: F1.T01, F1.T03, F5.T04, F7.T07.
- Riesgo si se interpreta mal: un cliente HTTP o SQLite dentro del núcleo, lo que rompe la compilación a WASM y la garantía de verificación sin I/O.

## Opciones de resolución

1. Extraer los backends a crates adaptadores L5 (`pip-storage-sqlite`, `pip-transport-http`) y dejar L1–L4 sin I/O. **Aplicada en `main`** junto con ADR-0019.
2. Mover `pip-storage` completo a L5 (obligaría a `pip-holder` a depender de una capa superior).

## ¿Requiere ADR?

Sí — cambia reglas de capas: ADR-0019.
