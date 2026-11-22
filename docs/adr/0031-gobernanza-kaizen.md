# ADR-0031: Adoptar KAIZEN como capa de proceso y política de commits K-3

- **Estado:** Aceptado (aprobación explícita del mantenedor, 2026-11-21)
- **Fecha:** 2026-11-21
- **Autores:** OpenCode (agente)
- **Aprobado por:** @angelnereira (mantenedor humano)
- **Issue:** #113
- **Requisitos y principios afectados:** AGENTS.md §2, §3, §5, §6, §12, §15
- **Fase:** gobernanza del repositorio (sin tarea `F<n>.T<nn>` en ROADMAP.md)

## Contexto

El repositorio ya cuenta con gobernanza obligatoria en `AGENTS.md` (jerarquía documental, invariantes, flujo de trabajo) y con `CODEOWNERS` que protege `AGENTS.md` y `.github/`. Se propuso instalar el sistema KAIZEN (`KAIZEN.md`), que define reglas canónicas propias, hooks, CI de puertas y un ratchet de calidad.

La instalación planteada entraba en conflicto con `AGENTS.md` en cinco puntos: (1) `AGENTS.md` y `.github/` son rutas protegidas; (2) los adaptadores pedían seguir `.kaizen/RULES.md` "estrictamente", compitiendo con la jerarquía de `AGENTS.md §3`; (3) `docs/kaizen/adr/` duplicaba el directorio canónico `docs/adr/`; (4) la regla K-3 de commits contradice el formato Conventional Commits de `AGENTS.md §6`; (5) la plantilla de PR de KAIZEN sustituía la plantilla con lista de verificación de invariantes y trazabilidad. Conforme a `AGENTS.md §15`, se detuvo el trabajo y se pidió decisión al mantenedor, que aprobó la instalación completa, la política K-3 pura y las políticas "sin emojis" y "sin atribución a IA".

## Opciones consideradas

### Opción A — No instalar KAIZEN
- Ventajas: cero riesgo de duplicar gobernanza.
- Inconvenientes: se descarta un mecanismo de ratchet, métricas y retrospectivas que el mantenedor solicitó.
- Riesgos: pérdida de la oportunidad de automatizar la mejora continua.

### Opción B — Instalación parcial sin rutas protegidas
- Ventajas: no toca `AGENTS.md` ni `.github/`.
- Inconvenientes: deja dos fuentes de proceso sin conciliar y no activa los gates de CI.
- Riesgos: divergencia entre reglas escritas y reglas ejecutadas.

### Opción C — Instalación completa con reconciliación explícita
- Ventajas: una sola capa de proceso, con `AGENTS.md` como autoridad máxima y KAIZEN como procedimiento; hooks y gates ejecutan las reglas.
- Inconvenientes: cambia el formato de commits y la plantilla de PR; exige limpiar emojis en documentación heredada para cumplir la política activada.
- Riesgos: los workflows nuevos no ejecutarán mientras GitHub Actions siga bloqueado por facturación (ver `docs/STATUS.md` §Bloqueos); se mitiga ejecutando `scripts/kaizen check` en local y en los hooks.
- Evidencia: inventario de conflictos detectado y aprobación del mantenedor en el issue #113.

## Decisión

Se adopta KAIZEN como **capa de proceso** del repositorio, con las siguientes precisiones normativas:

1. `AGENTS.md` permanece como autoridad máxima (§3). `.kaizen/RULES.md` gobierna únicamente el ciclo PDCA, el ratchet y las métricas.
2. La regla K-3 sustituye al formato Conventional Commits de `AGENTS.md §6`. Se activan `KZ_POLICY_COMMIT_MAX=256`, `KZ_POLICY_NO_EMOJI=1` y `KZ_POLICY_NO_AI_ATTRIBUTION=1`.
3. El directorio normativo de ADR sigue siendo `docs/adr/`. `docs/kaizen/adr/` solo contiene la plantilla operativa de KAIZEN.
4. El cuerpo del PR se copia del descriptor, que debe incorporar la comprobación de la *Definition of Done* de `AGENTS.md §10`.
5. Los workflows `kaizen-*.yml` se consideran complementarios a los workflows existentes y no sustituyen ningún control de `ci.yml`, `security.yml` ni `docs.yml`.

## Consecuencias

- Positivas: línea base de calidad con ratchet, descriptor versionado por rama, recolección de métricas, retrospectivas y hooks que validan cada commit y cada push.
- Negativas y cómo se mitigan: cambio de formato de commits (documentado en `AGENTS.md §6` y §19); limpieza de emojis en tres documentos heredados (cambio cosmético, sin cambio de contenido); dependencia de GitHub Actions para los gates remotos (se ejecuta todo en local mientras Actions esté bloqueado).
- Cambios necesarios en documentación: `AGENTS.md` (§6, §19), `CLAUDE.md`, `docs/ARCHITECTURE.md`, `CHANGELOG.md`, `docs/STATUS.md`.
- Cambios en CI o `layers.toml`: se añaden `.github/workflows/kaizen-gates.yml` y `.github/workflows/kaizen-pr-autofill.yml`; se sustituye `.github/PULL_REQUEST_TEMPLATE.md`. Sin cambios en `layers.toml`.
- Tareas nuevas en `ROADMAP.md`: ninguna; se registra el issue #113 como tarea de gobernanza.

## Criterios para revisar esta decisión

- Si GitHub Actions deja de estar bloqueado y los gates `kaizen-*` no pasan de forma sostenida.
- Si el formato K-3 dificulta la trazabilidad de commits por crate en los informes de release.
- Si aparece un ADR posterior que restablezca los Conventional Commits o que unifique ambos directorios de ADR.
