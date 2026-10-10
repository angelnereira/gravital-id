---
title: "[SPEC-GAP] PROJECT_STRUCTURE.md §5.1: la configuración de lints descrita no se puede aplicar"
labels: ["type:spec-gap", "status:needs-review", "phase:F0", "area:docs", "area:ci"]
---

## Documentos implicados

- Documento A: `PROJECT_STRUCTURE.md §5.1` y `§6`.
- Documento B: `AGENTS.md §4` (INV-09) y `§5.2`.

## Descripción

1. La v0.1 declara `unsafe_code = "forbid"` en el workspace con el comentario "Los crates de bindings lo relajan a deny + allow puntual". `forbid` no admite un `allow` posterior, y un crate que hereda los lints con `lints.workspace = true` no puede sobrescribir uno de ellos. Los bindings no podrían compilar con `unsafe`.
2. `float_arithmetic` y `arithmetic_side_effects` figuran como `"warn"`, pero `AGENTS.md §5.2` exige `clippy ... -D warnings`: en CI son errores. El nivel declarado no describe el comportamiento real.

## Impacto

- Tareas bloqueadas: F1.T01, F9.T03.
- Riesgo si se interpreta mal: que alguien "arregle" el problema quitando el lint del workspace y se pierda INV-09 en el núcleo.

## Opciones de resolución

1. Workspace con `unsafe_code = "deny"`; `#![forbid(unsafe_code)]` en el `lib.rs` de cada crate fuera de `bindings/`, comprobado por `xtask check-layers`; `#[allow(unsafe_code)]` local con `// SAFETY:` en bindings; los dos lints aritméticos declarados `deny`. **Aplicada en `main`.**
2. Tabla de lints propia y duplicada en cada crate de bindings.

## ¿Requiere ADR?

No — no cambia una regla, corrige cómo se expresa. Comprobado el 2026-10-10 con cargo 1.99.0 en un workspace mínimo: heredar y sobrescribir falla con `cannot override workspace.lints in lints`; `forbid` con `#[allow]` local falla con E0453; `deny` con `#[allow]` local compila.
