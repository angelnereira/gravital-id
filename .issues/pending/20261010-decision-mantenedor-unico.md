---
title: "[DECISIÓN] Proceso con un único mantenedor humano"
labels: ["type:decision", "status:triage", "phase:F0", "area:docs"]
---

## Qué hay que decidir

Cómo se aplican las reglas que presuponen varios humanos mientras el proyecto tenga un solo mantenedor:

- `ROADMAP.md §0.6` dimensiona para 3–5 ingenieros.
- F0.T21 exige que cada especificación la revise "alguien distinto de su autor".
- `AGENTS.md §6` exige aprobación humana en rutas de `CODEOWNERS`; `§12` reserva la aceptación de ADRs a un mantenedor humano.

## Por qué ahora

- Tareas que bloquea: F0.T11 y F0.T21; el gate G0 requiere 16 ADRs aceptados.
- Fecha o fase límite: antes de cerrar G0.

## Opciones conocidas

1. Mantener las reglas tal cual: el mantenedor aprueba todo; los agentes redactan y se revisan entre sí (un agente distinto del autor hace la revisión cruzada de F0.T21) y el humano decide.
2. Incorporar un segundo revisor humano para las rutas de `CODEOWNERS` antes de escribir código criptográfico (F2).
3. Relajar alguna regla por ADR. No recomendado: son las barreras contra el riesgo R-09.

## Información que falta para decidir

- Disponibilidad de otros revisores humanos.

## ¿Se convertirá en ADR?

Solo si se elige la opción 3. Las opciones 1 y 2 se documentan en `CONTRIBUTING.md` (F1.T12). Riesgo registrado como R-14 en `ROADMAP.md §26`.
