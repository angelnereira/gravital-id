---
name: "Bug"
about: "Defecto: comportamiento distinto al documentado. NO usar para vulnerabilidades (ver SECURITY.md)."
title: "[BUG] <componente>: <resumen corto>"
labels: ["type:bug", "status:triage"]
---

<!--
¿Es una vulnerabilidad explotable (aceptación indebida, fuga de claves/datos, elusión de replay o anti-rollback)?
→ NO continúes aquí. Sigue SECURITY.md (advisory privado).
No incluyas datos personales reales, claves, tokens ni credenciales completas.
-->

## Resumen

<!-- Una o dos frases. -->

## Componente y versión

- Crate / binding / servicio / contrato:
- Commit o versión:
- Plataforma / target (si aplica):

## Pasos para reproducir (mínimos)

1.
2.
3.

## Resultado esperado

<!-- Cita la fuente: REQ-…, sección de especificación, ADR. -->

## Resultado obtenido

## Evidencia

<!-- Logs redactados, salida de pruebas, vector de entrada sintético. -->

## Severidad propuesta

- [ ] S0 — Crítica (acepta algo inválido, fuga, pérdida de datos) → usar SECURITY.md si es explotable
- [ ] S1 — Alta (rechaza válidos en flujo principal, bloquea recuperación, `main` rota)
- [ ] S2 — Media
- [ ] S3 — Baja

## Contexto

- Tarea en la que se detectó (F<n>.T<nn> / #issue):
- ¿Revela un hueco de especificación? Sí / No (si sí, enlazar issue `type:spec-gap`)
- ¿Prueba de regresión propuesta?:
