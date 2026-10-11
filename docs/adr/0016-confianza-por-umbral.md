# ADR-0016: Confianza por umbral — raíz encadenada y bundles cofirmados k-de-n

- **Estado:** Aceptado
- **Fecha:** 2026-10-10
- **Autores:** Claude (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #2
- **Requisitos y principios afectados:** REQ-TRUST-001, 002, 005, 006, 008, 009, 010; P-08, P-10, P-15; INV-16
- **Fase:** F0 (tareas F0.T13, F0.T18); implementación en F4.T03, F6.T08, F7.T04, F8.T08

## Contexto

En la v0.1 el registro on-chain se gobierna por multisig, pero un dispositivo offline no lee la cadena: confía en **una** clave ES256 que firma el trust bundle. Consecuencias:

- Quien obtenga esa clave decide qué emisores y claves acepta todo dispositivo offline. La descentralización del registro no llega al verificador.
- El bundle incluye `bundle_signing_keys` para rotar: la clave comprometida puede rotar hacia claves del atacante.
- Con anti-rollback por versión monotónica, un bundle malicioso con una versión muy alta hace que todos los bundles legítimos posteriores se rechacen (*avance forzado*). No hay vía de recuperación sin reconfigurar cada dispositivo.
- El servicio de confianza es un punto único para **actualizar** la confianza (tensión con P-10).

El modo completo (contraste con ≥ 2 RPC) solo protege a servidores que lo ejecuten y solo detecta, no impide.

## Opciones consideradas

### Opción A — Mantener una única clave de bundle en HSM
- Ventajas: simple; un solo operador.
- Inconvenientes: todo lo descrito en el contexto.
- Riesgos: compromiso o coacción de un operador equivale a captura total e irrecuperable de los clientes offline.

### Opción B — Raíz offline por umbral + bundles cofirmados k-de-n con derivación determinista
- Dos documentos: `TrustRoot` (cambia rara vez, firmado por umbral de claves offline de la TFA, encadenado con la raíz anterior) y `TrustBundle` (firmado por ≥ k de n operadores listados en la raíz).
- El bundle es una función pura del estado finalizado en un bloque, con payload canónico (JCS, RFC 8785); cada operador lo deriva con su propio indexador y firma solo lo que derivó.
- Firmas múltiples con la serialización JSON general de JWS (RFC 7515 §7.2), sin formato propio.
- `bundle_epoch` en la raíz: una raíz nueva sustituye firmantes y reinicia la numeración, lo que recupera de un avance forzado.
- Ventajas: ningún operador ni RPC único puede fabricar un bundle; la caída de un operador no bloquea; rotación y recuperación definidas; sigue el modelo de roles y umbrales de The Update Framework (P-04).
- Inconvenientes: n operadores reales (organizaciones distintas); exige serialización canónica y derivación reproducible; verificación de k firmas en lugar de una.
- Evidencia: el costo de verificación es k verificaciones ES256 por bundle importado, no por presentación.

### Opción C — Cliente ligero de la cadena en el dispositivo
- Ventajas: sin firmantes intermedios.
- Inconvenientes: peso del SDK, dependencia de RPC, fuga de privacidad, inviable en WASM y embebidos. Ya descartado en `ARCHITECTURE.md §11.5`.

## Decisión

Se propone la **opción B**. El integrador fija la raíz; el cliente acepta raíces que encadenan por umbral y bundles con ≥ `bundle_threshold` firmas de firmantes distintos de la raíz vigente; el anti-rollback compara `(bundle_epoch, bundle_version)`.

## Consecuencias

- Positivas: P-15 e INV-16 se cumplen por construcción; P-10 alcanza también a la actualización de confianza.
- Negativas y cómo se mitigan: requiere al menos tres operadores para un umbral útil (en `dev` y `testnet`, claves de desarrollo en procesos separados); la derivación determinista se prueba con bytes idénticos entre ejecuciones (F6.T08) y con un operador divergente (F7.T04).
- Cambios en documentación: `ARCHITECTURE.md §11.1, §11.2, §11.5, §12, §18, §19`; `REQUIREMENTS.md` (TRUST); `TRUST_BUNDLE.md` y `TRUST_FRAMEWORK.md` (umbrales) en F0; ajusta las propuestas de ADR-0010 y ADR-0012.
- Cambios en código o CI: `pip-trust` (raíz, multi-firma), `pip-ledger` (derivación), `pip-trust-service` (cofirma).
- Tareas en `ROADMAP.md`: F0.T13, F0.T18, F4.T03, F6.T02, F6.T08, F7.T04, F8.T08; riesgo R-13.

## Criterios para revisar esta decisión

Que no sea posible reunir operadores independientes para el piloto (entonces se documenta un umbral reducido como riesgo aceptado, no un modo de firmante único); o que una auditoría encuentre un defecto en el encadenamiento de raíces.
