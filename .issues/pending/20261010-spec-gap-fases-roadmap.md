---
title: "[SPEC-GAP] ROADMAP.md / REQUIREMENTS.md: fase de REQ-STAT-002 y dependencia de F6.T08"
labels: ["type:spec-gap", "status:needs-review", "phase:F0", "area:docs"]
---

## Documentos implicados

- Documento A: `REQUIREMENTS.md §1.5` (REQ-STAT-002).
- Documento B: `ROADMAP.md §2`, `§9`, `§11`, `§12`.

## Descripción

1. REQ-STAT-002 ("tamaño mínimo por perfil y asignar índices aleatoriamente") tenía fase F4, pero la única tarea que lo cita es F7.T05. `cargo xtask trace` falla si un requisito DEBE de una fase cerrada no tiene pruebas, así que el gate G4 no podría cerrarse.
2. `ROADMAP.md §2` permite empezar F6 al cerrar G2 porque "los contratos no dependen del formato de credencial". Pero F6.T08 (`pip-ledger`: "comparación estado ↔ bundle") necesita el modelo de trust bundle, que se define en F4.T03.

## Impacto

- Tareas bloqueadas: gate G4; planificación de F6.T08.
- Riesgo si se interpreta mal: adelantar funcionalidad de F7 a F4 sin sus dependencias, o implementar `pip-ledger` contra un modelo de bundle inexistente.

## Opciones de resolución

1. Mover REQ-STAT-002 a F7 y anotar que F6.T08 requiere F4.T03. **Aplicada en `main`.**
2. Dividir REQ-STAT-002 en un requisito de verificación (F4) y otro de emisión (F7).

## ¿Requiere ADR?

No — no cambia el orden de fases ni elimina un gate.
