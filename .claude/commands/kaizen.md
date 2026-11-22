---
description: Flujo Kaizen (start <rama> | check | done | metrics | retro)
argument-hint: start <rama> | check | done | metrics | retro
---
Lee `.kaizen/RULES.md` y ejecuta la accion pedida en $ARGUMENTS:

- start <rama>: crea la rama, copia `docs/kaizen/pr-drafts/_TEMPLATE.md` a `docs/kaizen/pr-drafts/<rama-aplanada>.md`, rellena Resumen, Componente y Plan de prueba a partir del issue.
- check: ejecuta `scripts/kaizen check` y resume fallos con la correccion propuesta.
- done: ejecuta `scripts/kaizen check`, confirma que el descriptor esta completo y actualizado, que la documentacion afectada se actualizo y que el cierre de issues es correcto. Reporta pendientes.
- metrics: ejecuta `scripts/kaizen metrics` y resume la tendencia.
- retro: ejecuta `scripts/kaizen retro` y propone hasta 3 mejoras con dueno e issue sugeridos.
No inventes resultados: si un comando no se ejecuto, dilo.
