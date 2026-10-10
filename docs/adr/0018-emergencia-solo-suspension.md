# ADR-0018: El rol de emergencia solo puede suspender

- **Estado:** Propuesto
- **Fecha:** 2026-10-10
- **Autores:** Claude (agente), a petición de Angel Nereira
- **Aprobado por:** — (pendiente de un mantenedor humano)
- **Issue:** `.issues/pending/20261010-decision-revision-arquitectura.md`
- **Requisitos y principios afectados:** REQ-LEDG-004, REQ-KEY-005; P-08, P-10
- **Fase:** F0 (F0.T14, F0.T18); implementación en F4.T08, F6.T02, F6.T04, F6.T05

## Contexto

La v0.1 define un rol de emergencia con umbral propio (menor que la multisig) que revoca sin timelock, y fija como invariante que una clave `compromised` nunca vuelve a `active`. Combinadas, las dos reglas permiten que quien comprometa el rol de emergencia marque como comprometidas las claves de todos los emisores de forma **irreversible**: todas las credenciales del ecosistema quedan inválidas y deben reemitirse. El rol pensado para contener un incidente es el vector del peor incidente posible.

## Opciones consideradas

### Opción A — Mantener la revocación de emergencia irreversible
- Ventajas: respuesta inmediata y definitiva.
- Riesgos: denegación de servicio total y permanente con un umbral bajo.

### Opción B — La emergencia suspende; lo irreversible exige la multisig completa
- Nuevo estado `suspended` para claves y emisores: reversible, con caducidad fijada en `TRUST_FRAMEWORK.md`, no renovable por el propio rol.
- Durante la suspensión, la verificación devuelve `Unverifiable` con evidencia `IssuerKeySuspended` (fail-closed, sin afirmar invalidez definitiva).
- La multisig completa confirma (`compromised`) o levanta la suspensión.
- Ventajas: la respuesta sigue siendo inmediata; el daño de un rol de emergencia comprometido es acotado y reversible.
- Inconvenientes: un estado más en el registro y en el bundle; la multisig debe actuar antes de que caduque la suspensión.

### Opción C — Eliminar el rol de emergencia
- Inconvenientes: una clave comprometida seguiría aceptándose durante el timelock.

## Decisión

Se propone la **opción B**. `suspended` es un estado de clave y de emisor, no un estado nuevo del resultado de verificación (INV-04 se mantiene: se expresa como `Unverifiable` con evidencia).

## Consecuencias

- Positivas: elimina el ataque de invalidación masiva irreversible.
- Negativas y cómo se mitigan: si la multisig no actúa, la suspensión caduca y la clave vuelve a aceptarse; el plazo y el runbook de confirmación se definen en `TRUST_FRAMEWORK.md` y se ensayan (F14.T05, F15.T04).
- Cambios en documentación: `ARCHITECTURE.md §10.5, §11.2, §11.5, §11.6, §19`; `REQUIREMENTS.md` (REQ-KEY-005, REQ-LEDG-004); `CONTRACTS.md`; ajusta la propuesta de ADR-0012.
- Cambios en código o CI: contratos (estado e invariantes), `pip-trust`, `pip-verifier`.
- Tareas en `ROADMAP.md`: F4.T08, F6.T02, F6.T04, F6.T05; riesgo R-04.

## Criterios para revisar esta decisión

Que el marco legal del mercado objetivo exija una revocación inmediata e irreversible por un órgano de emergencia; o que los ensayos muestren que la multisig no puede reunirse dentro de un plazo de caducidad razonable.
