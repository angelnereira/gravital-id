# ADR-0001: Nombre definitivo del proyecto y prefijos de paquetes

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #7
- **Requisitos y principios afectados:** REQ-DOC-001; P-06; `AGENTS.md §6`
- **Fase:** F0 (F0.T02)

---

## Contexto

El nombre de trabajo preliminar utilizado durante la redacción inicial fue **PIP** (*Portable Identity Protocol*).
Sin embargo, un análisis de disponibilidad de marcas y colisiones en los principales registros de software determinó problemas críticos:
1. **Colisión en PyPI y CLI de Python:** `pip` es la herramienta estándar universal de instalación de paquetes de Python. Un paquete o comando `pip` genera colisiones insolubles en sistemas operativos y entornos de desarrollo.
2. **Colisión en crates.io:** El crate `pip` ya se encuentra registrado por terceros.
3. **Identidad de marca del ecosistema:** El proyecto se aloja oficialmente bajo el repositorio `gravital-id` dentro del ecosistema Gravital (junto a Gravital Share, SagoOne, Gravital Cloud, Gravital-Talk y Plenty-Pay), emitiendo la *Visa Económica Digital* (VED).

Es necesario fijar un nombre definitivo para el protocolo, el repositorio, los crates de Rust y los paquetes en los diferentes gestores de dependencias (npm, PyPI, Maven, Swift Package Manager, NuGet, pub.dev y Go).

---

## Opciones consideradas

### Opción A — Mantener "PIP"
- **Ventajas:** Brevedad.
- **Inconvenientes:** Inviable técnica y legalmente debido a colisiones universales con el gestor de paquetes de Python (`pip install`), colisión en crates.io y confusión para los desarrolladores.

### Opción B — "Gravital ID" / `gid` como prefijo
- **Ventajas:**
  - Alineación total con el repositorio oficial (`gravital-id`) y la marca del ecosistema Gravital.
  - Nombre libre en los registros requeridos (`gravital-id` en PyPI, crates.io, Maven group `com.gravital.id`, npm `@gravital/id` o `gravital-id`).
  - Permite el uso del acrónimo conciso `gid` para prefijos internos de crates (`gid-core`, `gid-crypto`, `gid-sdk`), variables y códigos de error normalizados (`GID-Exxxx`).
- **Inconvenientes:** Requiere un reemplazo mecánico coordinado en la documentación y nombres de crates.

### Opción C — Nombre abstracto nuevo (e.g. "AuraID", "PortaID")
- **Ventajas:** Desacoplado de cualquier producto existente.
- **Inconvenientes:** Pierde sinergia con el ecosistema Gravital y añade complejidad innecesaria de marca.

---

## Decisión

Se adopta la **Opción B**:
1. El proyecto y protocolo se denominan formalmente **Gravital ID** (identificador canónico: `gravital-id`).
2. Los paquetes públicos en gestores de dependencias se distribuirán bajo los siguientes identificadores:
   - **Rust (crates.io):** `gravital-id-*` (e.g. `gravital-id-core`, `gravital-id-sdk`) o prefijo `gid-*`.
   - **npm:** `@gravital/id` (o `gravital-id`).
   - **PyPI:** `gravital-id`.
   - **Maven Central:** `com.gravital.id:gravital-id-sdk`.
   - **Swift Package Manager:** `gravital-id`.
   - **Go:** `github.com/angelnereira/gravital-id`.
   - **NuGet:** `GravitalId.Sdk`.
3. El prefijo de errores de protocolo y SDK se normaliza a `GID-Exxxx` (manteniendo un mapeador de compatibilidad transitorio para `PIP-Exxxx` durante la fase F0–F1).
4. El término "Visa Económica Digital" (VED) se mantiene como la credencial insignia emitida bajo el perfil financiero y de personas de Gravital ID.

---

## Consecuencias

- Se formaliza el nombre definitivo en `docs/adr/README.md` y `docs/ROADMAP.md`.
- Los nombres de módulos y crates en `PROJECT_STRUCTURE.md` y `layers.toml` adoptan la convención canónica de `gravital-id` / `gid`.
- Se prevé la actualización coordinada de referencias textuales históricas en la documentación.
