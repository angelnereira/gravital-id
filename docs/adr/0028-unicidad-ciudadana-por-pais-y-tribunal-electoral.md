# ADR-0028: Prevención de duplicidad ciudadana por país, cumplimiento del Tribunal Electoral de Panamá e índice ciego de unicidad (VOPRF/HSM)

- **Estado:** Aceptado
- **Fecha:** 2026-10-18
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira (2026-10-18)
- **Issue:** #101
- **Requisitos y principios afectados:** REQ-UNIQ-001, REQ-UNIQ-002, REQ-UNIQ-003, REQ-UNIQ-004, REQ-IDDOC-001, REQ-IDDOC-003, REQ-COMP-001, REQ-LEDG-001; P-02, P-04, P-08, P-09; INV-02, INV-05
- **Fase:** F19 / F10 / F24

---

## Contexto

Cuando un servidor o aplicación aloja el servicio de Gravital ID y un usuario selecciona **"Crear nuevo Gravital ID"**, el sistema debe garantizar de forma integral que **una misma persona natural no pueda crear dos o más identidades Gravital ID duplicadas** utilizando su documento oficial de identificación nacional emitido por la autoridad competente de su país (en la República de Panamá: la **Cédula de Identidad Personal** emitida por el **Tribunal Electoral**).

Asimismo, el diseño debe cumplir estrictamente con:
1. **El marco normativo del Tribunal Electoral (TE) de Panamá (y autoridades homólogas por país):**
   - **Constitución Política de la República de Panamá, Código Electoral, Ley 68 de 2015 y Ley 31 de 2006:** Otorgan al Tribunal Electoral la competencia exclusiva sobre el Registro Civil, la cedulación y la verificación oficial de la identidad de ciudadanos panameños y extranjeros residentes permanentes.
   - **Decreto N.° 43 de 8 de octubre de 2024 del Tribunal Electoral:** Regula formalmente la **Cédula Digital** y el servicio de *Billetera de Identidad Digital* en Panamá, disponiendo que cuenta con la misma validez jurídica que la cédula física y exigiendo resguardo mediante **verificación biométrica, reconocimiento facial con prueba de vida (*liveness*) y cifrado fuerte**.
   - **Servicio de Verificación de Identidad (SVI) del Tribunal Electoral:** Es la infraestructura oficial en línea provista por el TE para que instituciones públicas, bancos, notarías y empresas privadas afiliadas (mediante convenio formal con el TE) contrasten datos biográficos y biométricos contra el padrón oficial de cedulación y prevengan la suplantación o duplicidad de identidad.
   - **Ley 81 de 2019 y Decreto Ejecutivo 285 de 2021 (Protección de Datos Personales):** Clasifican el número de cédula como dato personal y los datos biométricos como datos sensibles (Art. 4 y Art. 9), exigiendo consentimiento informado y prohibiendo su exposición pública.
2. **El invariante no negociable `INV-02` y principio `P-02`:**
   - *"Ningún dato personal, ni hash de dato personal, ni identificador de titular va al ledger, a logs, a métricas ni a mensajes de error."*
   - Como documenta `ARCHITECTURE.md §2`, el espacio de números de cédula de un país tiene **baja entropía** (en Panamá existen ~4,5 millones de habitantes; el formato `Provincia-Tomo-Asiento`, p. ej. `8-888-8888`, `E-8-123456`, `PE-xxx-xxx`, `N-xxx-xxx`, tiene menos de $2^{25}$ combinaciones válidas). Un hash directo `SHA-256("PA:8-888-8888")` publicado en una blockchain o compartido sin clave secreta se revierte por fuerza bruta en **menos de 1 segundo**.

---

## Opciones consideradas

### Opción A — Guardar `SHA-256(pais || numero_documento)` en el contrato inteligente `TrustRegistry`

- **Ventajas:** Simple de programar.
- **Inconvenientes:**
  - **Violación crítica (S0) de `INV-02`, `REQ-LEDG-001` y la Ley 81 de 2019:** Cualquier observador de la blockchain puede enumerar todas las cédulas panameñas de `1-1-1` a `13-9999-9999`, calcular su `SHA-256` y saber exactamente qué ciudadanos tienen Gravital ID y cuándo se registraron.
- **Riesgos:** Fuga masiva e irreversible de datos personales en cadena pública (rechazada de plano).

---

### Opción B — Sin comprobación de unicidad: permitir que cada servidor emita credenciales sin verificar si el documento nacional ya tiene un Gravital ID

- **Ventajas:** No requiere índice de unicidad.
- **Inconvenientes:**
  - Incumple el requisito de integridad de usuario: una misma persona o un atacante que robe una foto de cédula podría dar de alta múltiples identidades Gravital ID inconexas en distintos servicios.

---

### Opción C — Perfiles Nacionales de Identidad por País (`NationalIdProfile` + Conector SVI del Tribunal Electoral) + Índice Ciego de Unicidad con Clave en HSM (`VOPRF` RFC 9497 / `HMAC-HSM`) y Redirección Automática a Re-vinculación (Recomendada)

Diseñar una arquitectura de dos capas que cumple simultáneamente las normas del Tribunal Electoral (y de cada país soportado), la Ley 81 de 2019 y el invariante `INV-02`:

#### 1. Capa de Validación Normativa por País (`NationalIdProfile` + `IdentityVerificationPort`)
Cada jurisdicción se modela como un perfil normativo identificado por su código ISO 3166-1 alpha-2 (`country_code`):

| País (`ISO`) | Organismo Oficial | Formatos de Documento Validados | Mecanismo Oficial de Verificación (`IdentityVerificationPort`) |
|---|---|---|---|
| **Panamá (`PA`)** | **Tribunal Electoral (TE)** | Cédula panameña canónica: `^[1-9]\|1[0-3]\|PE\|E\|N\|[1-9]AV\|[1-9]PI-[0-9]{1,5}-[0-9]{1,6}$` y Carné de Residente Permanente | **1)** Conector al **Servicio de Verificación de Identidad (SVI)** del TE bajo convenio institucional + biometría facial con prueba de vida (Decreto 43 de 2024 TE).<br/>**2)** Emisión directa de `pip-identity-official-v1` cuando el TE opere como emisor.<br/>**3)** Lectura de código QR/PDF417 del reverso de la cédula + cotejo biométrico para `pip-identity-derived-v1`. |
| **Colombia (`CO`)** | Registraduría Nacional del Estado Civil (RNEC) | Cédula de Ciudadanía (NUIP de 6 a 10 dígitos) y Cédula Digital en policarbonato | Cotejo biométrico RNEC / lectura NFC ICAO 9303 de Cédula Digital. |
| **Costa Rica (`CR`)** | Tribunal Supremo de Elecciones (TSE) | Cédula de Identidad (`[1-9]-[0-9]{4}-[0-9]{4}`) y DIMEX | Verificación TSE / lectura de código de barras PDF417 + biometría. |
| **Internacional (`ICAO`)** | Autoridades emisoras de pasaportes (ICAO Doc 9303) | Pasaporte electrónico (`eMRTD`) | Lectura NFC del chip (BAC/PACE) y verificación criptográfica de firma pasiva (`SOD`) contra la lista maestra CSCA del país emisor. |

- Antes de emitir cualquier credencial de identidad, el número de documento se **normaliza canónicamente** (eliminando espacios, convirtiendo a mayúsculas ASCII y validando la gramática exacta del país; p. ej. `"PA:CEDULA:8-888-8888"`).

#### 2. Capa de Prevención de Duplicidad sin Exposición de PII (`UniquenessTag` mediante VOPRF / HMAC en HSM)
- Para impedir que el mismo documento nacional (`country_code + doc_type + canonical_doc_number`) registre más de un Gravital ID activo:
  1. Se calcula un **Token Ciego de Unicidad (`UniquenessTag`)** usando una **Función Pseudoaleatoria Oblicua Verificable (VOPRF, RFC 9497)** o un `HMAC-SHA-256` cuya clave secreta de 256 bits (`K_uniq_hsm`) vive **exclusivamente dentro de un módulo HSM** (o umbral de HSMs del servicio de unicidad del marco de confianza) y **nunca** puede exportarse:
     $$\text{UniquenessTag} = \text{VOPRF}_{K_{\text{uniq\_hsm}}}\big(\text{"gid-uniq-v1"} \parallel \text{country\_code} \parallel \text{doc\_type} \parallel \text{canonical\_doc\_number}\big)$$
  2. **Por qué cumple `INV-02` y la Ley 81 de 2019:**
     - El `UniquenessTag` **nunca se publica en la blockchain pública (`TrustRegistry` / `StatusAnchor`)**. Vive únicamente en el índice de deduplicación de emisión protegido por HSM y con límite estricto de tasa (*rate limiting* por emisor autenticado).
     - Como un atacante externo no posee la clave `K_uniq_hsm` custodiada en el HSM, **no puede ejecutar ataques de diccionario ni fuerza bruta** sobre las cédulas de Panamá ni de ningún otro país.
     - En el flujo con **VOPRF (RFC 9497)**, el emisor ni siquiera necesita enviar el número de cédula en claro al HSM de unicidad: ciega matemáticamente el documento normalizado, el HSM evalúa la función sobre el punto cegado y el emisor descega el resultado para obtener el `UniquenessTag` con prueba de conocimiento cero DLEQ de que se usó la clave oficial.
  3. **Comportamiento Determinista ante Intento de Duplicidad (`REQ-UNIQ-003`):**
     - Si durante el flujo **"Crear nuevo Gravital ID"** el `UniquenessTag` no existe en el registro activo: se registra atómicamente asociado a las ranuras de dispositivo del nuevo Gravital ID (`ADR-0029`) y se completa la emisión.
     - Si el `UniquenessTag` **ya existe y está activo**: el sistema **rechaza la creación de un Gravital ID duplicado (`GID-E2010 CitizenIdentityAlreadyRegistered`)** y transiciona automáticamente al usuario hacia el flujo de:
       - **Ingreso con su Gravital ID existente** (`SignInWithGravitalId`), o
       - **Recuperación / Re-vinculación de dispositivo (`F8.T04`)** tras superar la prueba biométrica del SVI / código de recuperación, lo cual revoca el dispositivo anterior de esa misma clase y vincula el nuevo sin duplicar la identidad.

---

## Decisión

Se adopta la **Opción C**:
1. Estandarizar los **Perfiles Nacionales de Identidad por País (`NationalIdProfile`)**, comenzando con el cumplimiento integral del **Tribunal Electoral de Panamá** (gramática canónica de cédula panameña, Decreto N.° 43 de 8 de octubre de 2024 sobre Cédula Digital, conector al **Servicio de Verificación de Identidad - SVI** en `IdentityVerificationPort`, y separación estricta `pip-identity-official-v1` vs `pip-identity-derived-v1`).
2. Impedir la duplicidad de usuarios mediante el **`UniquenessTag` calculado con clave en HSM (VOPRF RFC 9497 / HMAC-HSM)** sobre la tupla canónica `(country_code, doc_type, canonical_doc_number)`, prohibiendo terminantemente publicar números de cédula o hashes sin clave HSM en la blockchain o en logs (`INV-02`).
3. Cuando se detecte un `UniquenessTag` ya registrado, bloquear el alta duplicada (`GID-E2010`) y redirigir al flujo de login existente o de recuperación/re-vinculación con revocación del soporte sustituido.

---

## Consecuencias

- **Positivas:**
  - Garantiza **1 ciudadano = máximo 1 identidad Gravital ID raíz** por documento nacional sin crear una base de datos en claro de cédulas ni violar `INV-02` ni la Ley 81 de 2019.
  - Alinea a Gravital ID con el **Decreto N.° 43 de 2024** y el **SVI del Tribunal Electoral de Panamá**, facilitando tanto la operación hoy con entidades privadas afiliadas al SVI (`pip-identity-derived-v1`) como la adopción directa por el Tribunal Electoral (`pip-identity-official-v1`).
  - La arquitectura por plugins de `NationalIdProfile` permite incorporar las reglas de cualquier país (Colombia, Costa Rica, México, UE, pasaportes ICAO) sin modificar el núcleo de verificación.
- **Negativas y cómo se mitigan:**
  - La comprobación de unicidad al **crear** un usuario nuevo requiere conectividad en línea con el servicio de emisión/unicidad. *Mitigación:* Como establece `ARCHITECTURE.md §2`, la **emisión** siempre es una operación en línea; la **verificación** de credenciales ya emitidas sigue siendo **100 % offline (`INV-01`)**.
- **Cambios necesarios en documentación:**
  - Actualizar `docs/ARCHITECTURE.md`, `docs/REQUIREMENTS.md` (`REQ-UNIQ-001..004`), `docs/legal/2026-analisis-regulatorio-preliminar.md` y `docs/specs/profiles/pip-identity-v1.md`.
