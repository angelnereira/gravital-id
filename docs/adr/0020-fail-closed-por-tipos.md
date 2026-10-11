# ADR-0020: Fail-closed por tipos y resultado por comprobación

- **Estado:** Aceptado
- **Fecha:** 2026-10-10
- **Autores:** Claude (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #2
- **Requisitos y principios afectados:** REQ-VER-002, 003, 010, 011, 012; P-05, P-08; INV-04, INV-05
- **Fase:** F0 (F0.T16, `SDK_API.md`); implementación en F4.T04, F4.T06

## Contexto

La v0.1 define un pipeline de comprobaciones ordenadas y una precedencia de estados, pero deja tres huecos:

1. **Comprobaciones sobre datos no autenticados.** Si la firma del emisor no se puede verificar, el pipeline no dice qué pasa con vigencia, esquema o estado. Evaluarlas produce evidencia engañosa ("revocada", "caducada") sobre un contenido que cualquiera pudo fabricar.
2. **Fail-closed como disciplina.** Que el resultado nunca sea `Valid` ante un error depende de que nadie olvide una rama. Es el patrón de degradación más citado en `AGENTS.md §16`.
3. **Estado persistente sin dueño.** El piso de tiempo, la última versión de bundle y la caché de nonces viven en crates sin I/O y sin un trait definido. Borrar o restaurar los datos de la aplicación reinicia en silencio el anti-rollback y la protección de replay.

## Opciones consideradas

### Opción A — Mantener el pipeline como convención, reforzado con pruebas
- Inconvenientes: las pruebas detectan lo que alguien pensó en probar.

### Opción B — Typestate + resultado por comprobación + `VerifierStateStore`
- Cada comprobación termina en `Passed`, `Failed`, `Indeterminate` u `Skipped`. Son evidencia dentro del resultado; **no** añaden estados a `VerificationResult` (INV-04).
- El contenido pasa por tipos que reflejan lo ya demostrado (por ejemplo, contenido sin autenticar → contenido con firma verificada). Las comprobaciones que leen claims solo aceptan el tipo autenticado, así que no pueden ejecutarse antes; el pipeline las marca `Skipped`.
- `Valid` solo se construye a partir de un valor que demuestra que todas las comprobaciones obligatorias terminaron en `Passed`. Devolver `Valid` por otro camino no compila (prueba `trybuild`).
- El estado del verificador se lee y escribe mediante el trait `VerifierStateStore`. Si falta o no es íntegro, el resultado es `Unverifiable` con evidencia `VerifierStateReset` hasta una reinicialización explícita.
- Ventajas: INV-05 pasa a ser una propiedad del sistema de tipos; evidencia fiel; el estado tiene dueño y comportamiento ante su pérdida.
- Inconvenientes: API interna más elaborada; exige cuidado para que la API pública del SDK siga siendo simple a través de FFI.

## Decisión

Se propone la **opción B**. La forma exacta de los tipos se fija en `SDK_API.md`; este ADR fija las propiedades.

## Consecuencias

- Positivas: una clase entera de regresiones deja de ser posible.
- Negativas y cómo se mitigan: la complejidad queda dentro de `pip-verifier`; a través de FFI se expone el resultado ya construido.
- Cambios en documentación: `ARCHITECTURE.md §9.5, §10.5, §17.2`; `REQUIREMENTS.md` (REQ-VER-011, REQ-VER-012, REQ-SDK-005); `SDK_API.md`; tabla de verdad de precedencia en `PROTOCOL.md`.
- Cambios en código o CI: `pip-trust` (trait), `pip-verifier` (typestate), `pip-storage-sqlite` (implementación).
- Tareas en `ROADMAP.md`: F4.T04, F4.T06, F4.T09 (mutación), F5.T04.

## Criterios para revisar esta decisión

Que el diseño de tipos no pueda expresarse en la API pública sin romper P-11 (una API, muchos lenguajes); o que una auditoría proponga un modelo de evidencia distinto.
