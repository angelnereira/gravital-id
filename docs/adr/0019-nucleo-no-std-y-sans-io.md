# ADR-0019: Núcleo `no_std` y protocolos sans-I/O

- **Estado:** Aceptado
- **Fecha:** 2026-10-10
- **Autores:** Claude (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #2
- **Requisitos y principios afectados:** REQ-VER-001, REQ-PORT-003, REQ-PORT-004, REQ-SDK-005, REQ-SDK-008; P-01, P-06, P-11, P-14; INV-01, INV-11
- **Fase:** F1 (F1.T03, F1.T10, F1.T13); cambia las reglas de capas (`layers.toml`)

## Contexto

Tres problemas de la v0.1 tienen la misma raíz:

1. **Contradicción de capas.** INV-01 prohíbe I/O en L1–L3, pero `pip-storage` (L3) incluía el backend SQLite, y `pip-sync` (L4) un cliente HTTP por defecto. `ARCHITECTURE.md §6` ya situaba ambos como adaptadores L5.
2. **Garantías sostenidas por lints.** "Sin red, sin reloj, sin aleatoriedad implícita" se imponía con `clippy` (`disallowed-methods`), que no cubre dependencias transitivas ni impide que un cambio futuro las introduzca.
3. **Asincronía a través de FFI.** Los crates de I/O eran `async` "sin runtime concreto", con el host inyectando el transporte. Exponer `async` de Rust a Kotlin, Swift, JS, Go y C es la parte más frágil de los bindings y hace las pruebas dependientes de un runtime.

## Opciones consideradas

### Opción A — Mantener `std` y `async` en el núcleo, corregir solo la tabla de capas
- Ventajas: menos restricciones al escribir código.
- Inconvenientes: los puntos 2 y 3 siguen abiertos.

### Opción B — L1–L3 `no_std` + `alloc`; L4 sans-I/O; adaptadores en L5
- **L1–L3** (`pip-types` … `pip-recovery`): `#![no_std]` con `alloc`. `std::net`, `std::fs` y `SystemTime` no existen para estos crates; reloj y aleatoriedad solo llegan por los traits inyectados.
- **L4** (`pip-protocol`, `pip-sync`, `pip-ledger`): máquinas de estado que reciben eventos y devuelven efectos (petición a enviar, registro a persistir, espera). Sin `async`, sin runtime.
- **L5**: `pip-storage-sqlite`, `pip-transport-http`, `pip-ledger-evm` ejecutan los efectos. El host puede sustituirlos.
- `pip-sdk` y los bindings ofrecen el bucle de conducción idiomático de cada lenguaje, sin lógica.
- Ventajas: INV-01 e INV-11 pasan de revisables a imposibles de violar; pruebas de protocolo deterministas; desaparece el `async` en la frontera FFI; el verificador compila para hardware embebido.
- Inconvenientes: `no_std` limita dependencias (hay que comprobar cada una); las máquinas de estado son más verbosas que `async`; `thiserror` y `serde_json` deben usarse en sus modos `no_std`.
- Evidencia pendiente: el spike F0.T09 (WASM) y la tarea F1.T10 confirman que las dependencias criptográficas compilan sin `std`.

### Opción C — `no_std` solo en L1–L2
- Ventajas: menor esfuerzo.
- Inconvenientes: el verificador (L3) quedaría fuera, que es justo donde más importa la garantía.

## Decisión

Se propone la **opción B**. `check-layers` falla si un crate L1–L3 enlaza `std` o si un crate L1–L4 depende de un runtime async o de un cliente de red; CI compila L1–L3 para un target *bare-metal*.

## Consecuencias

- Positivas: las garantías centrales del protocolo las impone el compilador.
- Negativas y cómo se mitigan: si una dependencia imprescindible no admite `no_std`, se registra un issue `type:decision` y se revisa este ADR antes de relajar la regla; nunca se relaja por conveniencia.
- Cambios en documentación: `ARCHITECTURE.md §3, §4 (P-06), §6, §13, §14, §17.2`; `PROJECT_STRUCTURE.md §2, §3, §4, §9`; `AGENTS.md` (INV-01).
- Cambios en código, CI o `layers.toml`: dos crates adaptadores nuevos; regla de `no_std`; target *bare-metal* en CI.
- Tareas en `ROADMAP.md`: F1.T03, F1.T09, F1.T10, F1.T13, F5.T04, F7.T07.

## Criterios para revisar esta decisión

Que una dependencia fijada por ADR-0007 o ADR-0015 no pueda usarse sin `std`; o que el costo de las máquinas de estado en OID4VCI/OID4VP (F10) resulte desproporcionado frente a un conductor `async` confinado en L5.
