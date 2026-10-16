# ADR-0026: Perfil de identidad portable `pip-identity-v1` y tratamiento del retrato

- **Estado:** Aceptado
- **Fecha:** 2026-10-15
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #79
- **Requisitos y principios afectados:** REQ-IDDOC-001, REQ-IDDOC-002, REQ-IDDOC-003, REQ-CRED-004, REQ-COMP-001; P-01, P-05, P-09, P-10; INV-02, INV-05
- **Fase:** F19 (F19.T07)

---

## Contexto

El objetivo **OBJ-07** (`ADR-0021`) requiere que Gravital ID pueda portar documentos de identidad personal —incluida la cédula de identidad con fotografía del rostro (**retrato**)— para su verificación presencial u online.

El repositorio cuenta actualmente con cuatro perfiles en `docs/specs/profiles/`: `pip-personal-v1` (atributos personales básicos sin retrato), `pip-membership-v1`, `pip-Medical-v1` y `pip-financial-v1`. Ninguno define:
1. **La distinción técnica y jurídica entre una credencial oficial del Estado y una credencial de identidad derivada:** En Panamá, la cédula de identidad personal es emitida exclusivamente por el **Tribunal Electoral (TE)**. Sin un convenio o reconocimiento normativo del TE (riesgo `R-19`), una organización privada (p. ej. un banco o empresa que ejecutó debida diligencia KYC verificando la cédula física) puede emitir una **credencial de identidad verificada derivada**, pero el protocolo **jamás** debe inducir a error al verificador haciéndole creer que una credencial derivada fue emitida por el registro civil del Estado.
2. **El formato, límite de tamaño y restricciones de transporte del retrato (`portrait`):** Una imagen facial útil para inspección visual humana por un guardia o cajero pesa entre 6 KB y 24 KB en JPEG/WebP, lo que excede por un orden de magnitud la capacidad de un código QR individual (1.200 caracteres Base45 $\approx 800\text{ bytes}$, `ADR-0011`). Además, la imagen facial puede constituir un dato sensible/biométrico bajo la Ley 81 de 2019 de Panamá (`F19.T15`).

---

## Opciones consideradas

### Opción A — Añadir un campo `portrait` opcional a `pip-personal-v1` con un único `vct`

Modificar el perfil existente `pip-personal-v1` para incluir el retrato y usar el mismo identificador de tipo (`vct`) tanto para emisores gubernamentales como privados.

- **Ventajas:** Menos archivos de especificación.
- **Inconvenientes:**
  - **Ambigüedad crítica de confianza (`R-19`):** Un verificador que pida `urn:gravital-id:vct:pip-personal-v1` no distinguiría a nivel de esquema de tipo (`vct`) entre una cédula oficial emitida por una autoridad civil y una credencial de perfil personal emitida por un comercio.
  - **Ruptura del presupuesto QR:** Si una wallet intenta incluir `portrait` en una presentación QR de `pip-personal-v1`, generaría secuencias de 20–30 códigos QR ilegibles.
  - **Incumple la inmutabilidad de perfiles v1:** `pip-personal-v1` ya tiene su esquema JSON y matriz de pruebas cerrados en `F3.T06`.

---

### Opción B — Almacenar el retrato en un servidor externo y poner una URL en la credencial

Incluir en el SD-JWT un claim `portrait_url` apuntando a un CDN del emisor.

- **Ventajas:** Credencial muy pequeña (~1 KB) que cabe en un QR.
- **Inconvenientes:**
  - **Viola frontalmente INV-01 (Verificación 100 % sin red) y P-09 (Sin *phone-home*):** El verificador offline no podría descargar la foto, y si tuviera red, cada descarga le revelaría al servidor del emisor cuándo y dónde se está verificando al titular.
- **Riesgos:** Ruptura de los invariantes más importantes del proyecto (rechazada).

---

### Opción C — Nuevo perfil `pip-identity-v1` con dos variantes de `vct` explícitas (oficial vs derivada) y retrato JPEG acotado exclusivo para NFC/BLE/Online (Recomendada)

Crear la especificación normativa `docs/specs/profiles/pip-identity-v1.md` (`F19.T11`) y su esquema compilado en `gravital-id-credential` (`F24.T01`) con las siguientes reglas vinculantes:

1. **Dos identificadores de tipo (`vct`) disjuntos y obligatorios (`REQ-IDDOC-001`):**
   - **Variante Oficial (`urn:gravital-id:vct:pip-identity-official-v1`):** Reservada exclusivamente para emisores que sean autoridades públicas de registro civil o identidad nacional (p. ej. Tribunal Electoral) dados de alta en el `TrustRegistry` con autorización explícita para dicho `vct`.
   - **Variante Derivada (`urn:gravital-id:vct:pip-identity-derived-v1`):** Para entidades reguladas o autorizadas (bancos, empleadores, proveedores de KYC) que verificaron presencialmente o con prueba de vida el documento oficial del titular a través de `IdentityVerificationPort` (`F10.T03` / `F24.T03`). Incluye obligatoriamente metadatos del método de verificación inicial (`evidence_type`, `verified_at`).
   - Las políticas de verificación (`VerificationPolicy`) declaran explícitamente si aceptan solo `pip-identity-official-v1` o también `pip-identity-derived-v1` de emisores autorizados.
2. **Conjunto de claims (todos de divulgación selectiva individual `_sd` salvo los metadatos base de SD-JWT VC):**
   - Identificación civil: `given_name` (string), `family_name` (string), `birth_date` (`YYYY-MM-DD`), `nationality` (ISO 3166-1 alpha-2, p. ej. `"PA"`), `sex` (opcional según ley aplicable: `"M"`, `"F"`, `"X"`), `place_of_birth` (opcional).
   - Documento: `document_number` (string, p. ej. `"8-888-8888"`, `REQ-IDDOC-003`), `document_expiry` (`YYYY-MM-DD`), `issuing_authority` (string), `issuing_country` (ISO 3166-1 alpha-2).
   - Predicados de minimización (Nivel 0 sin PIN en tarjeta): `age_over_18` (bool), `age_over_21` (bool).
   - Retrato facial: `portrait` (cadena Base64URL sin padding de los bytes de imagen).
   - En la variante derivada: `verification_evidence` (objeto con tipo de documento origen verificado y nivel de aseguramiento, sin exponer copias crudas de expedientes).
3. **Reglas estrictas para el retrato (`portrait`, `REQ-IDDOC-002`):**
   - **Formato único en v1:** Imagen **JPEG Baseline (ISO/IEC 10918-1 / JFIF)** en espacio de color sRGB o escala de grises, validando en emisión y verificación la firma mágica de inicio (`FF D8 FF`), el marcador de fin (`FF D9`), dimensiones entre $160 \times 200$ y $480 \times 600$ píxeles, y la **ausencia total de metadatos EXIF/GPS/comentarios (`APP1`–`APP15`, `COM`)** para evitar fugas de geolocalización o exploits contra parsers de imagen en los terminales verificadores.
   - **Tamaño máximo:** **$\le 16\,384\text{ bytes}$ (16 KiB) en binario crudo** ($\le 21\,848$ caracteres en Base64URL) para tarjetas físicas y NFC estándar, con un límite absoluto de rechazo de **$24\,576\text{ bytes}$ (24 KiB)**.
   - **Restricción de transporte:** El claim `portrait` **SOLO** puede divulgarse sobre transportes de banda ancha: **NFC (`GID-APDU`), BLE o flujo en línea (`SessionCode` / OID4VP)**. Si una solicitud por **código QR** pide `portrait`, la máquina de estados del titular omite `portrait` (si es opcional en la consulta) o rechaza la presentación por QR con código de error explícito (`GID-E8002` / transporte insuficiente para retrato), ofreciendo cambiar a NFC/BLE.
   - **Prohibición de persistencia en el verificador:** El SDK de verificación y las aplicaciones de referencia muestran el retrato en memoria volátil únicamente para la comparación visual en el momento del control y **no lo persisten en disco ni en logs** salvo que el integrador configure e invoque explícitamente una política con base legal documentada (`REQ-IDDOC-002`, `INV-02`).
4. **Parámetros de seguridad del perfil `pip-identity-v1`:**
   - **Almacenamiento de clave del titular (`cnf`):** Hardware obligatorio (`KeyStorageLevel::HardwareBacked`: StrongBox/TEE en Android, Secure Enclave en iOS, Elemento Seguro en tarjeta Java Card).
   - **Nivel de autorización en tarjeta física (ADR-0024):**
     - Nivel 0 (sin PIN): `age_over_18`, `age_over_21`, `given_name` (solo si el titular lo configuró como preautorizado).
     - Nivel 1 (con PIN): `document_number`, `birth_date`, `portrait`, `family_name`, `nationality`.
   - **Solicitud firmada del verificador (`REQ-PRES-007`):** Obligatoria cuando el verificador solicita `document_number`, `birth_date` o `portrait`.
   - **Estado y revocación:** `Token Status List` de 2 bits (`00` = activa, `01` = revocada, `10` = suspendida). Ventana de frescura offline recomendada: $\le 24\text{ h}$ para trámites sensibles; $\le 7\text{ días}$ para control de acceso físico o mayoría de edad.

---

## Decisión

Se adopta la **Opción C**:
1. Definir el perfil **`pip-identity-v1`** (`docs/specs/profiles/pip-identity-v1.md`) con dos identificadores `vct` estrictamente separados: `urn:gravital-id:vct:pip-identity-official-v1` y `urn:gravital-id:vct:pip-identity-derived-v1` (`REQ-IDDOC-001`).
2. Fijar el formato del claim `portrait` en JPEG Baseline limpio de metadatos EXIF/COM, con tamaño binario $\le 16\text{ KiB}$ recomendado ($\le 24\text{ KiB}$ máximo absoluto), prohibiendo su transmisión por código QR y su persistencia por defecto en el verificador (`REQ-IDDOC-002`).
3. Mantener `document_number` siempre como claim de divulgación selectiva de Nivel 1 (con PIN en tarjeta y solicitud firmada del verificador) y nunca como identificador de correlación del protocolo (`REQ-IDDOC-003`).

---

## Consecuencias

- **Positivas:**
  - Permite implementar y demostrar técnicamente la cédula portable con foto (`OBJ-07`, hito `MP3`) hoy mismo mediante la variante derivada (`pip-identity-derived-v1`), dejando lista la variante oficial (`pip-identity-official-v1`) para el momento en que exista convenio con el Tribunal Electoral u otra autoridad civil (`F24.T04`).
  - La limpieza obligatoria de cabeceras EXIF/COM en el JPEG elimina riesgos de fuga de metadatos de cámara/ubicación y reduce la superficie de ataque del decodificador de imágenes del verificador.
  - Con un retrato JPEG de 8–16 KiB, la presentación completa cabe en una transferencia NFC `GID-APDU` con APDU extendidos en `< 800 ms` y en la memoria de una tarjeta Java Card de 64 KB.
- **Negativas y cómo se mitigan:**
  - Un titular no puede mostrar su foto mediante un código QR. *Mitigación:* El código QR sigue funcionando para predicados (`age_over_18`) y datos textuales (`given_name`, `document_number`); para inspección con foto se usa toque NFC, BLE o `SessionCode`.
- **Cambios necesarios en documentación (`ARCHITECTURE.md`, `REQUIREMENTS.md`, specs):**
  - Redacción de `docs/specs/profiles/pip-identity-v1.md` en `F19.T11` y de la adenda legal en `docs/legal/` en `F19.T15`.
- **Cambios en código, CI o `layers.toml`:**
  - Incorporación del esquema compilado y del validador de cabeceras JPEG en `gravital-id-credential` durante `F24.T01` y `F24.T02`.
- **Tareas nuevas en `ROADMAP.md`:**
  - `F19.T11`, `F19.T15`, `F24.T01`–`F24.T04`, `F24.T10`.

---

## Criterios para revisar esta decisión

1. Si la asesoría legal de `F14` / `F19.T15` bajo la Ley 81 de 2019 de Panamá establece requisitos adicionales de consentimiento expreso escrito para el retrato facial, se incorporarán a las reglas de emisión de `pip-identity-v1`.
2. Si el Tribunal Electoral publica un esquema técnico propio para la cédula digital panameña o exige compatibilidad con ISO/IEC 18013-5 (`mDL` / `eu.europa.ec.eudi.pid.1`), se mapearán los claims en `pip-identity-official-v1` y se activará `F25`.
