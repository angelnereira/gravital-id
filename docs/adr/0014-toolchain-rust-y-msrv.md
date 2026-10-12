# ADR-0014: Toolchain de Rust y Versión Mínima Soportada (MSRV)

- **Estado:** Aceptado
- **Fecha:** 2026-10-12
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #6
- **Requisitos y principios afectados:** REQ-MAINT-001, REQ-PORT-001, REQ-PORT-004; P-06, P-11
- **Fase:** F1 (F1.T02)

---

## Contexto

El protocolo Gravital ID exige reproducibilidad estricta en compilación, verificación cruzada en múltiples arquitecturas (WASM, Android ARM64, iOS ARM64, bare-metal `no_std`) y trazabilidad de compatibilidad hacia atrás en compiladores.

Para evitar divergencias entre los entornos de desarrollo locales y CI, y para garantizar que las bibliotecas y el SDK puedan ser consumidos en entornos con políticas estrictas de actualización de compilador, es necesario fijar formalmente:
1. La versión mínima soportada del compilador Rust (MSRV).
2. El archivo de fijación de toolchain para desarrolladores (`rust-toolchain.toml`).
3. La política de verificación automatizada del MSRV en CI.

---

## Opciones consideradas

### Opción A — Última versión estable flotante (sin MSRV fijado)
- **Ventajas:** Acceso inmediato a las últimas características de Rust sin fricción.
- **Inconvenientes:** Quiebra la reproducibilidad; las actualizaciones de Rust pueden romper dependencias transitivas sin aviso previo; los integradores con toolchains fijadas no pueden predecir compatibilidad.
- **Riesgos:** Violación de REQ-MAINT-001.

### Opción B — MSRV fijado en Rust 1.85.0 con canal estable en `rust-toolchain.toml`
- **Ventajas:**
  - Rust 1.85.0 es la versión hito que consolida la edición Rust 2024 y estabiliza características clave para `no_std` y ecosistemas embebidos.
  - Ofrece compatibilidad total con las dependencias criptográficas fijadas en ADR-0007 (RustCrypto, `p256`, `sha2`, `chacha20poly1305`, `zeroize`).
  - Permite declarar `rust-version = "1.85.0"` en el workspace Cargo y verificarla taxativamente mediante un job dedicado de CI con `cargo check --workspace`.
- **Inconvenientes:** No se pueden utilizar características de lenguaje estabilizadas después de 1.85.0 sin actualizar formalmente el MSRV.
- **Evidencia:** Verificado en spike WASM (F0.T09) y soporte nativo en entornos Linux, macOS y contenedores de CI.

### Opción C — MSRV muy conservador (ej. Rust 1.75.0)
- **Ventajas:** Máxima compatibilidad con distribuciones Linux muy antiguas.
- **Inconvenientes:** Ciertas dependencias criptográficas modernas de RustCrypto (`hybrid-array`, etc.) ya requieren compiladores $\ge 1.81.0$, por lo que versiones anteriores son incompatibles con el árbol de dependencias actual.

---

## Decisión

Se adopta la **Opción B**:
1. El **MSRV** oficial de Gravital ID para el workspace y todos sus crates del núcleo es **Rust 1.85.0**.
2. Se declara `rust-version = "1.85.0"` en `[workspace.package]` de `Cargo.toml`.
3. Se fija `rust-toolchain.toml` en la raíz del repositorio especificando el canal `1.85.0` con los componentes `rustfmt` y `clippy`, y los targets `wasm32-unknown-unknown`, `aarch64-linux-android` y `thumbv7em-none-eabihf`.
4. El workflow de CI incluye un job mandatorio que compila el workspace con la versión exacta de MSRV (`cargo check --workspace`).
5. Toda elevación futura de MSRV requiere justificación técnica (p. ej., actualización de una dependencia crítica) y aprobación expresa en PR.

---

## Consecuencias

- **Positivas:** Compilación reproducible y predecible; cumplimiento total de REQ-MAINT-001.
- **Negativas y mitigación:** Los desarrolladores deben utilizar al menos Rust 1.85.0, lo cual es automatizado por `rustup` mediante `rust-toolchain.toml`.
- **Cambios en documentación:** Actualizado `docs/adr/README.md`.
- **Cambios en código y CI:** Creación de `rust-toolchain.toml`, configuración en `Cargo.toml`, job MSRV en `ci.yml`.

---

## Criterios para revisar esta decisión

Un avance de una dependencia crítica fijada (ADR-0007, ADR-0015) que eleve su propio MSRV por encima de 1.85.0, o el inicio de una fase que requiera explícitamente características de una versión posterior.
