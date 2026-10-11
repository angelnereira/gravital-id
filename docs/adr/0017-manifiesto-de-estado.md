# ADR-0017: Manifiesto de estado separado del trust bundle

- **Estado:** Aceptado
- **Fecha:** 2026-10-10
- **Autores:** Claude (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #2
- **Requisitos y principios afectados:** REQ-STAT-005, 006, 008; REQ-TRUST-010; P-14
- **Fase:** F0 (F0.T13); implementación en F4.T01 y F7.T05

## Contexto

En la v0.1 el trust bundle incluye `status_lists[ { uri, issuer_id, latest_hash, latest_version } ]`. El registro de emisores cambia rara vez; las listas de estado cambian con la frescura del perfil (minutos u horas en el financiero). Mezclarlos obliga a regenerar y refirmar el bundle con cada cambio de cualquier lista, usando claves que deberían emplearse poco, y hace crecer el bundle con el número de listas. Con ADR-0016, además, cada regeneración exigiría reunir k firmas.

Sin embargo, el cliente necesita un puntero mutable: las listas se distribuyen direccionadas por contenido y un verificador debe poder precargar las listas vigentes de los emisores que acepta.

## Opciones consideradas

### Opción A — Mantener los hashes de listas en el bundle
- Inconvenientes: acopla dos ritmos de cambio; convierte la firma del bundle en ruta caliente.

### Opción B — Manifiesto de estado por emisor
- Cada emisor publica `{ issuer_id, manifest_version, issued_at, lists[ { uri, version, hash } ] }`, firmado con una clave de estado listada en su entrada del bundle (`status_keys`).
- El cliente rechaza un manifiesto con versión inferior a la última aceptada de ese emisor.
- `StatusAnchor` ancla el compromiso de los manifiestos, no de cada lista.
- Ventajas: el bundle solo cambia cuando cambia el registro; cada emisor responde de su propio ritmo; el compromiso on-chain es más pequeño.
- Inconvenientes: un documento firmado más que parsear, acotar y someter a fuzzing.

### Opción C — Sin puntero: resolver cada lista por su URI
- Inconvenientes: impide la distribución por contenido direccionado vía mirrors no confiables (REQ-STAT-005) y la precarga offline.

## Decisión

Se propone la **opción B**. El trust bundle no contiene punteros ni hashes de listas de estado.

## Consecuencias

- Positivas: separación de planos lento y rápido; menos uso de las claves de bundle.
- Negativas y cómo se mitigan: el manifiesto es una extensión propia sobre Token Status List (las listas siguen siendo estándar); se documenta como perfil propio según P-04.
- Cambios en documentación: `ARCHITECTURE.md §10.3, §10.4, §11.5`; `REQUIREMENTS.md` (REQ-STAT-008, REQ-TRUST-010); `TRUST_BUNDLE.md`.
- Cambios en código o CI: `pip-status`/`pip-trust` (parseo y versión monotónica), servicio de emisión (publicación), contrato `StatusAnchor`.
- Tareas en `ROADMAP.md`: F0.T13, F4.T01, F7.T05.

## Criterios para revisar esta decisión

Que el RFC final de Token Status List defina un mecanismo estándar de agregación o descubrimiento de listas que cubra este caso: entonces se adopta en lugar del manifiesto.
