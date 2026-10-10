# Política de seguridad

> Borrador. Se completa en la tarea F0.T04 de `docs/ROADMAP.md`.

## Cómo reportar una vulnerabilidad

**No abras un issue público.** Usa el reporte privado de vulnerabilidades de GitHub (pestaña *Security* → *Report a vulnerability*) de este repositorio. Si no está disponible, contacta a los mantenedores por el canal privado que se indique aquí al cerrar F0.T04.

Incluye: componente y versión/commit, descripción del impacto, pasos de reproducción o prueba de concepto, y cualquier mitigación conocida. **No incluyas datos personales reales.**

## Qué consideramos vulnerabilidad

- Aceptación como válida de una credencial o presentación que no debería serlo.
- Fuga de claves, secretos o datos personales (incluidos logs, errores y telemetría).
- Elusión de la protección contra replay, de la política de frescura o del anti-rollback del trust bundle.
- Pánicos, lecturas fuera de límites o agotamiento de recursos provocados por entradas externas.
- Fallos de autorización en contratos o servicios.
- Problemas en la cadena de suministro o en el proceso de release.

## Compromisos (a confirmar en F0.T04)

| Etapa | Plazo objetivo |
|---|---|
| Acuse de recibo | 3 días hábiles |
| Evaluación inicial y severidad | 10 días hábiles |
| Corrección de severidad crítica | Lo antes posible, con divulgación coordinada |

## Para agentes y desarrolladores del proyecto

Sigue `AGENTS.md §7.4`: las vulnerabilidades se tratan en advisories privados y ramas privadas, nunca en issues públicos ni en `.issues/pending/`.
