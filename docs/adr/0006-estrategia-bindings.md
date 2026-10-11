# ADR-0006: Estrategia de bindings multi-lenguaje y gestión de pánicos

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #11
- **Requisitos y principios afectados:** REQ-PORT-001; REQ-PORT-002; REQ-PORT-003; P-07
- **Fase:** F0 (F0.T11)

---

## Contexto

El núcleo del protocolo Gravital ID está desarrollado en Rust para garantizar seguridad de memoria, concurrencia sin carreras de datos y alto rendimiento criptográfico sin recolección de basura.
Para ser utilizado en productos reales, el SDK (`pip-sdk` / `gravital-id-sdk`) debe exponerse idiomáticamente en múltiples plataformas y ecosistemas:
- **Móvil:** Android (Kotlin) e iOS (Swift).
- **Web y backend ligero:** TypeScript / JavaScript en navegadores y Node.js (vía WebAssembly).
- **Multiplataforma móvil:** Flutter (Dart).
- **Servicios backend:** Python, Go, C# / .NET y C/C++.

Restricciones arquitectónicas críticas:
1. **Cero lógica de negocio en bindings:** Toda la lógica de verificación, máquinas de estados y reglas de confianza debe residir exclusivamente en el código Rust auditado; los bindings son envoltorios estrictos de FFI.
2. **Cero claves privadas cruzando FFI (INV-03):** Las claves privadas nunca se transmiten como cadenas o bytes hacia o desde Rust; se referencian mediante descriptores opacos delegados al almacén seguro del host.
3. **Manejo determinista de pánicos:** Un pánico en Rust no debe provocar el cierre abrupto (*crash*) de la aplicación anfitriona ni corromper memoria, especialmente en entornos WebAssembly.
4. **Códigos de error normalizados:** Todos los errores devueltos por cualquier binding deben compartir la misma taxonomía numérica y semántica (`GID-Exxxx` / `PIP-Exxxx`).

---

## Opciones consideradas

### Opción A — Implementaciones nativas paralelas en cada lenguaje
- **Ventajas:** Código 100 % nativo en cada plataforma.
- **Inconvenientes:** Coste prohibitivo de desarrollo y mantenimiento; divergencias inevitables en implementaciones criptográficas y vectores de ataque de seguridad; imposibilidad de garantizar consistencia estricta en verificaciones.

### Opción B — FFI manual mediante C ABI puro (`extern "C"`) para todos los lenguajes
- **Ventajas:** Mínima sobrecarga de abstracción.
- **Inconvenientes:** Extrema cantidad de código repetitivo (*boilerplate*), alta probabilidad de fugas de memoria o errores de punteros en la frontera FFI, escasa ergonomía para lenguajes modernos como Swift o Kotlin.

### Opción C — Arquitectura estratificada por generadores especializados (Recomendada)
- **Ventajas:**
  - **UniFFI (Mozilla):** Generación automática de bindings seguros, idiomáticos y tipados para Swift, Kotlin y Python a partir de la definición de UDL / proc-macros en Rust.
  - **wasm-bindgen:** Compilación directa a `wasm32-unknown-unknown` con tipos TypeScript generados para navegador y Node.js.
  - **flutter_rust_bridge:** Puente de alto rendimiento y bajo overhead asíncrono para aplicaciones Flutter (Android, iOS, Web y Escritorio).
  - **C ABI canónica (`cbindgen`):** Interfaz C pura para integraciones en Go (vía cgo), C# (.NET vía P/Invoke) y C/C++.
- **Inconvenientes:** Requiere configurar diferentes procesos de empaquetado en la tubería de CI.

---

## Decisión

Se adopta la **Opción C**:
1. Se utiliza **UniFFI** como estándar oficial para Kotlin (Android/JVM), Swift (iOS/macOS) y Python.
2. Se utiliza **wasm-bindgen** para los bindings de WebAssembly dirigidos a navegadores y Node.js.
3. Se utiliza **flutter_rust_bridge** para aplicaciones Flutter en el marco del ecosistema Gravital.
4. Se proporciona una cabecera C canónica generada con **cbindgen** para Go y lenguajes tradicionales.
5. **Aislamiento de pánicos:**
   - En plataformas nativas, toda llamada FFI externa está encapsulada en `std::panic::catch_unwind` (o mecanismo equivalente de UniFFI), convirtiendo pánicos en errores tipados estructurados (`GID-E9999`).
   - En WebAssembly, un pánico envenena la instancia Wasm; la barrera JS/TS intercepta la excepción, reporta el error y descarta inmediatamente la instancia envenenada, forzando la creación de una instancia limpia.
6. Todos los errores expuestos a través de los bindings devuelven códigos estandarizados conforme al catálogo `docs/specs/ERROR_CODES.md`.

---

## Consecuencias

- La especificación de interfaz pública `docs/specs/SDK_API.md` y el catálogo `docs/specs/ERROR_CODES.md` actúan como contrato normativo vinculante para todos los bindings.
- El spike técnico `spikes/wasm/REPORT.md` comprueba la resiliencia ante pánicos y el tamaño de binario en WebAssembly.
