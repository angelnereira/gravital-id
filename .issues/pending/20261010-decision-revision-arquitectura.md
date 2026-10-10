---
title: "[DECISIÓN] Revisión de arquitectura v0.2: aceptar o rechazar ADR-0016 a ADR-0020"
labels: ["type:decision", "status:needs-review", "phase:F0", "area:docs", "area:trust", "area:security"]
---

## Qué hay que decidir

Aceptar, rechazar o diferir cada propuesta de la revisión de arquitectura del 2026-10-10 (rama `docs/pending-architecture-review`):

| ADR | Decisión propuesta |
|---|---|
| 0016 | Raíz de confianza encadenada y trust bundles cofirmados k-de-n con derivación determinista |
| 0017 | Manifiesto de estado por emisor, fuera del trust bundle |
| 0018 | Rol de emergencia limitado a suspensión reversible con caducidad |
| 0019 | L1–L3 `no_std` + `alloc`; L4 sans-I/O; adaptadores en L5 |
| 0020 | Fail-closed por tipos; resultado por comprobación; `VerifierStateStore` |

Y los ajustes a propuestas de ADR aún no redactados:

| ADR | Ajuste |
|---|---|
| 0006 | Estrategia de pánicos en WASM (instancia envenenada) |
| 0007 | Backend FIPS condicional y seleccionado por tipo, no por feature |
| 0009 | Claves de recuperación por emisor; SAS con compromiso previo |
| 0010 | JWS JSON multi-firma sobre payload canónico (JCS) |
| 0011 | Transcodificación binaria antes de DEFLATE + Base45; indexado frente a códigos fuente |
| 0012 | Emergencia limitada a suspender |

## Por qué ahora

- Tareas que bloquea: F0.T11, F0.T13, F0.T14, F0.T16, F0.T18 (las especificaciones de F0 dependen de estas decisiones).
- Fecha o fase límite: gate G0 (ADR-0019: F1).

## Opciones conocidas

1. Aceptar todo: fusionar la rama; los ADR pasan a Aceptado con la firma del mantenedor.
2. Aceptar por partes: indicar qué ADR se rechaza o difiere; se revierten las secciones correspondientes de `ARCHITECTURE.md`, `REQUIREMENTS.md`, `PROJECT_STRUCTURE.md` y `ROADMAP.md` antes de fusionar.

## Información que falta para decidir

- Medición real de la transcodificación binaria y de los códigos fuente (spike F0.T07).
- Formato de firma que devuelven Secure Enclave y StrongBox (spike F0.T08).
- Compatibilidad `no_std` de las dependencias criptográficas (spike F0.T09, F1.T10).
- Cuántos operadores independientes son realistas para el piloto (umbral de ADR-0016).
- Estado actual de los estándares citados (HAIP y `x5c`, pruebas de conocimiento cero sobre ECDSA, ML-DSA en JOSE): no se verificó en línea durante la revisión.

## ¿Se convertirá en ADR?

Sí: ADR-0016 a ADR-0020 (ya redactados, estado Propuesto).
