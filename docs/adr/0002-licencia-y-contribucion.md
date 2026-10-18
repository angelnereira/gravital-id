# ADR-0002: Licencia dual MIT / Apache-2.0 y política de contribución (DCO)

- **Estado:** Aceptado
- **Fecha:** 2026-10-10
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #6
- **Requisitos y principios afectados:** REQ-COMP-003; P-06; `AGENTS.md §6`
- **Fase:** F0 (F0.T03); verificación en F1 (`deny.toml`)

---

## Contexto

El protocolo PIP / Gravital ID busca convertirse en un estándar industrial abierto y de adopción masiva en diversas industrias (finanzas, administración pública, servicios digitales). Para lograrlo:
1. Las empresas y desarrolladores deben poder integrar las bibliotecas del núcleo y los SDKs sin temor a contaminación viral de código propietario (incompatibilidad con licencias copyleft como GPL o AGPL).
2. El ecosistema Rust y Web3 utiliza de forma abrumadoramente estándar la licencia dual MIT y Apache-2.0.
3. La política de contribución debe garantizar que el código aportado sea legítimo y no viole patentes ni propiedad intelectual de terceros, sin imponer la fricción burocrática de un Acuerdo de Cesión de Derechos de Autor (CLA corporativo restrictivo).

---

## Opciones consideradas

### Opción A — Licencia MIT exclusiva
- **Ventajas:** Máxima simplicidad y permisividad.
- **Inconvenientes:** Carece de concesión explícita de licencias de patentes y cláusulas de terminación por litigio de patentes (que sí provee Apache-2.0).

### Opción B — Licencia Apache-2.0 exclusiva
- **Ventajas:** Protección sólida de patentes y cláusulas de defensa.
- **Inconvenientes:** Incompatibilidad técnica estricta con ciertos proyectos bajo GPL v2 pura (aunque compatible con GPL v3).

### Opción C — Licencia dual MIT / Apache-2.0 con DCO 1.1 (Recomendada)
- **Ventajas:** Estándar de facto en el ecosistema Rust (Tokio, Serde, RustCrypto, Wasmtime, etc.). Permite a los integradores elegir la licencia que mejor se adapte a su marco legal. El Developer Certificate of Origin (DCO 1.1) asegura la procedencia del código mediante un `Signed-off-by` en cada commit de forma ágil y transparente.
- **Inconvenientes:** Mantenimiento de dos textos de licencia en el repositorio.

---

## Decisión

Se adopta la **Opción C**:
1. El proyecto se publica bajo **licencia dual MIT y Apache-2.0** (a elección del receptor).
2. Toda contribución se rige por el **Developer Certificate of Origin (DCO 1.1)**, certificado mediante la cabecera `Signed-off-by: Nombre <email>` en los commits de colaboradores externos.
3. Las dependencias externas en Rust se restringirán en `deny.toml` a licencias permisivas equivalentes: `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `CC0-1.0` y `Unicode-DFS-2016`. Cualquier licencia con copyleft fuerte (`GPL`, `AGPL`, `SSPL`) o restrictiva queda expresamente prohibida en el núcleo y los SDKs. Excepción acotada y documentada (issue #7): `unicode-ident` (dependencia de compilación de `proc-macro2`) declara `(MIT OR Apache-2.0) AND Unicode-3.0`; Unicode-3.0 es permisiva y OSI-approved, y se permite únicamente para ese crate mediante `[[licenses.exceptions]]` en `deny.toml`, sin relajar la allowlist general.

---

## Consecuencias

- Se añaden los archivos `LICENSE-MIT` y `LICENSE-APACHE` en la raíz del repositorio.
- Se crea el archivo `CONTRIBUTING.md` con las instrucciones de contribución y el texto del DCO 1.1.
- Se actualiza `README.md` referenciando la licencia dual aceptada.
