## Resumen
Instalar KAIZEN como capa de proceso con ratchet, hooks, adaptadores y ADR-0031, previa aprobacion del mantenedor

## Componente afectado
Gobernanza del repositorio (AGENTS.md, .github/, .kaizen/, scripts/, documentacion)

## Tipo de cambio
- [x] tech-debt
- [x] documentation

## Documentos relacionados
- ADR-0031 (gobernanza Kaizen y politica K-3)
- AGENTS.md §6 y §19
- KAIZEN.md (orden de instalacion recibida)
- docs/STATUS.md, CHANGELOG.md

## Plan de prueba
- `scripts/kaizen init`
- `scripts/kaizen check --only descriptors`
- `scripts/kaizen check --only policy`
- `scripts/kaizen check --only ratchet`
- `scripts/kaizen check`
- `git commit --allow-empty` con resumen de 300 caracteres (debe ser rechazado por el hook)
- Retirar temporalmente `## Cierre de issues` del descriptor y ejecutar `check --only descriptors` (debe fallar)
- Anadir temporalmente un `TODO` y ejecutar `check --only ratchet` (debe fallar)
- `scripts/kaizen metrics` (una linea en docs/kaizen/data/metrics.jsonl)

## Impacto en calidad (ratchet)
- Cobertura: igual (no se mide: KZ_COVERAGE_CMD vacio, sin comando unico y estable)
- Advertencias: igual (no se mide: KZ_WARNINGS_CMD vacio)
- Deuda (TODO/FIXME): igual; linea base generada antes de cualquier cambio de codigo

## Criterios de salida que avanza
- Estructura .kaizen/, docs/kaizen/, scripts/kaizen y .githooks/ creada
- Adaptadores de Claude Code y opencode instalados; AGENTS.md y CLAUDE.md fusionados
- Workflows kaizen-gates.yml y kaizen-pr-autofill.yml anadidos; plantilla de PR sustituida
- config.env con comandos reales detectados (cargo test, cargo clippy, cargo fmt)
- scripts/kaizen init activa hooks y scripts/kaizen check termina en verde
- ADR-0031 aceptado y reflejado en ARCHITECTURE.md
- STATUS.md y CHANGELOG.md actualizados

## Verificacion AGENTS.md §10
- Compila y pasan tests: `cargo test --workspace` y `cargo clippy --workspace --all-targets --all-features -- -D warnings` ejecutados por `scripts/kaizen check`
- Documentacion actualizada antes o en el mismo cambio (spec-first): ADR-0031, AGENTS.md, CLAUDE.md, ARCHITECTURE.md, CHANGELOG.md, STATUS.md
- Sin cambios en codigo de biblioteca, parsers, invariantes ni APIs publicas
- Sin dependencias nuevas
- Instalacion completa aprobada por el mantenedor en #113

## Aprendizaje (opcional)
La instalacion de un sistema de gobernanza externo requirio conciliar la jerarquia de AGENTS.md antes de escribir archivos. La politica "sin emojis" obligo a limpiar tres documentos heredados; se hizo de forma mecanica y sin cambiar el contenido. Durante la verificacion aparecio el bug preexistente #114 (golden files de trybuild desactualizados para rustc 1.99.0): se abrio el issue, se obtuvo aprobacion por CODEOWNERS y se corrige en un commit separado dentro de este PR para que `scripts/kaizen check` quede en verde.

## Cierre de issues
Closes #113

## Checklist
- [x] Compila
- [x] Pasa tests
- [x] `scripts/kaizen check` en verde
- [x] Documentacion actualizada
- [x] Linea base no empeora
