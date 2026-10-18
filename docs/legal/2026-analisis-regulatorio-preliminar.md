# Análisis Regulatorio Preliminar: Protección de Datos (Ley 81) y Marco KYC/AML

> **Identificador normativo:** `LEGAL-PIP-REG-001`  
> **Versión:** `0.2.0-draft` (Fase F0 `F0.T20` / Fase F19 `F19.T15`)  
> **Estado:** Documento de trabajo preparatorio / Pendiente de dictamen legal formal en F14  
> **Fecha:** 2026-10-15  
> **Trazabilidad:** REQ-COMP-001, REQ-COMP-002, REQ-COMP-003, REQ-IDDOC-001, REQ-IDDOC-002, REQ-IDDOC-003, REQ-CODE-004, REQ-CARD-002, REQ-CARD-005; ADR-0021, ADR-0024, ADR-0025, ADR-0026; INV-02; P-02, P-03, P-09.

---

## 1. Alcance y Mercado Objetivo

Este análisis evalúa la viabilidad regulatoria inicial del protocolo PIP / Gravital ID en su mercado prioritario de lanzamiento y operación:

* **Jurisdicción Primaria:** República de Panamá (sede comercial y operativa de Nereira Technology and Business Solutions).
* **Marco de Protección de Datos:** Ley 81 de 26 de marzo de 2019 de Protección de Datos Personales de Panamá (y su Decreto Ejecutivo 285 de 2021).
* **Marco Financiero y Prevención de Blanqueo:** Ley 23 de 27 de abril de 2015 (Prevención del Blanqueo de Capitales, Financiamiento del Terrorismo y Financiamiento de la Proliferación de Armas de Destrucción Masiva) y Acuerdos de la Superintendencia de Bancos de Panamá (SBP).
* **Proyección Regional e Internacional:** Compatibilidad con estándares de referencia internacional (Reglamento eIDAS 2.0 / Arquitectura EUDI Wallet de la Unión Europea y directrices GAFI/FATF sobre Identidad Digital).

---

## 2. Análisis de Conformidad con la Ley 81 de 2019 (Panamá)

La Ley 81 de 2019 establece el régimen general de protección de los derechos de los titulares de datos personales. El diseño arquitectónico del protocolo PIP adopta el principio de **Privacidad por Diseño y por Defecto (*Privacy by Design*)**:

### 2.1 Principios Fundamentales del Tratamiento (Art. 4)

| Principio Legal (Art. 4) | Exigencia Normativa | Implementación Arquitectónica en PIP |
|---|---|---|
| **Licitud y Consentimiento** | El tratamiento requiere consentimiento previo, informado e inequívoco del titular (Art. 6). | El SDK separa la preparación de la presentación de su confirmación (`REQ-PRES-003`). El titular debe consentir explícitamente en la wallet mediante autenticación biométrica/PIN antes de generar el KB-JWT. |
| **Finalidad** | Los datos deben ser recabados para fines determinados, explícitos y legítimos. | Las consultas del verificador utilizan Digital Credentials Query Language (DCQL) tipado. La wallet muestra al usuario qué entidad pregunta y con qué propósito. |
| **Proporcionalidad y Minimización** | Solo se recopilan los datos estrictamente necesarios para la finalidad perseguida. | Implementación estricta de SD-JWT (RFC 9901): divulgación selectiva de atributos puntuales y uso de predicados booleanos precomputados (`age_over_18` en lugar de fecha de nacimiento). |
| **Seguridad de los Datos** | Adopción de medidas técnicas para evitar alteración, pérdida o acceso no autorizado (Art. 8). | Cifrado de sobre (Envelope Encryption DEK/KEK con `XChaCha20-Poly1305` o `AES-256-GCM`) en el almacenamiento del titular (`REQ-STOR-001`). Claves custodiadas en hardware seguro. |
| **Confidencialidad** | Deber de reserva de quienes intervienen en el tratamiento. | Verificación desconectada punto a punto (P2P vía QR offline o NFC cifrado con HPKE). No existen servidores centrales de autenticación que registren transacciones de los usuarios. |

---

### 2.2 Invariante INV-02 y el "Derecho al Olvido" (Cancelación y Modificación - Art. 15 y 16)

Uno de los principales desafíos jurídicos en sistemas basados en blockchain es la aparente tensión entre la inmutabilidad de la cadena y el derecho de cancelación de datos personales:

* **Tesis Jurídico-Técnica del Protocolo:**  
  Bajo el invariante fundamental **INV-02**, **ningún dato personal, ni hash de dato personal de baja entropía, ni identificador persistente del titular toca jamás la blockchain o el ledger público** (`REQ-LEDG-001`).
* **Contenido de la Blockchain:**  
  Los contratos (`TrustRegistry` y `StatusAnchor`) almacenan exclusivamente:
  1. Claves públicas institucionales de personas jurídicas emisoras.
  2. Parámetros de gobernanza y hashes de políticas públicas.
  3. Raíces Merkle de listas de estado agregadas (bits de revocación sin identificador de titular).
* **Conclusión:**  
  La inmutabilidad de la blockchain en PIP **no vulnera el derecho al olvido**, ya que ningún dato que identifique o haga identificable a una persona natural reside en la cadena. El titular puede ejercer su derecho de cancelación borrando la credencial de su propio dispositivo en cualquier momento.

---

### 2.3 Transferencia Transfronteriza de Datos (Art. 33 al 35)
La Ley 81 restringe la transferencia de datos personales a países que no proporcionen niveles de protección adecuados, salvo excepciones (consentimiento del titular o cumplimiento contractual):
* En PIP, las credenciales viajan directamente desde el emisor hacia el dispositivo del titular, y desde el titular hacia el verificador elegido por él.
* No existe un proveedor centralizado de nube que transfiera bases de datos masivas de ciudadanos panameños a jurisdicciones extranjeras.

---

## 3. Requisitos KYC/AML para el Perfil Financiero (`pip-financial-v1`)

El perfil `pip-financial-v1` se orienta a operaciones reguladas bajo la Ley 23 de 2015:

### 3.1 Diligencia Debida del Cliente (CDD / KYC)
1. **Reutilización de Identidad Verificada:**  
   Un banco o sujeto obligado emisor que haya completado la debida diligencia de un cliente (presencial o mediante videoconferencia autorizada por la SBP) puede emitir una credencial SD-JWT VC con nivel `kyc_tier: tier2` o `tier3`.
2. **Aceptación por Terceros Sujetos Obligados:**  
   Un segundo sujeto obligado (p. ej. una billetera digital, cooperativa o aseguradora) puede verificar la credencial de forma instantánea y offline, confiando en la firma del emisor respaldada por el `TrustBundle`.
3. **Mitigación de Suplantación mediante Atestación de Clave:**  
   Para cumplir con los estándares de autenticación reforzada exigidos para prevención de fraude financiero, el perfil financiero exige **hardware seguro obligatorio con atestación de clave criptográfica (Android Key Attestation / iOS DeviceCheck/AppAttest)** en la fase de emisión.

### 3.2 Conservación de Documentos y Evidencia de Cumplimiento (Art. 27 Ley 23)
* Los sujetos obligados tienen la obligación legal de conservar los registros de debida diligencia durante al menos cinco (5) años.
* **Excepción de Retención:** A diferencia del perfil personal (retención cero), el perfil `pip-financial-v1` autoriza al verificador financiero a archivar la **evidencia criptográfica completa** de la presentación verificada (`VerificationResult`, hash del token presentado, constancia de verificación de estado y marca de tiempo confiable) cifrada en reposo con KMS institucional.

---

## 4. Adenda de Identidad Portable: Cédula, Retrato, Tarjeta Física y Código por Emisor (`F19.T15`)

Con la incorporación del alcance de identidad portable (**ADR-0021** a **ADR-0026**), este análisis se amplía a cuatro ámbitos regulatorios específicos:

### 4.1 Competencia del Tribunal Electoral, Decreto N.° 43 de 2024, SVI y Prevención de Duplicidad (`REQ-IDDOC-001`, `REQ-UNIQ-001..004`)
* En la República de Panamá, la emisión de la cédula de identidad personal oficial y la certificación de la identidad civil son competencia constitucional y legal exclusiva del **Tribunal Electoral (TE)** conforme al Código Electoral, la **Ley 68 de 2015** y la **Ley 31 de 2006**.
* Mediante el **Decreto N.° 43 de 8 de octubre de 2024**, el Tribunal Electoral creó y reglamentó oficialmente la **Cédula Digital** y la *Billetera de Identidad Digital*, otorgándole idéntica validez jurídica que a la cédula física y exigiendo resguardo mediante **verificación biométrica, reconocimiento facial con prueba de vida (*liveness*) y cifrado avanzado**.
* Asimismo, el Tribunal Electoral opera el **Servicio de Verificación de Identidad (SVI)**, al cual se afilian entidades públicas, bancos, notarías y empresas privadas mediante convenio formal para cotejar datos biográficos y biométricos contra el padrón oficial de cedulación.
* Por consiguiente, **ADR-0026**, **ADR-0028** y `docs/specs/profiles/pip-identity-v1.md` establecen:
  1. `urn:gravital-id:vct:pip-identity-official-v1`: reservado única y exclusivamente para el Tribunal Electoral (o la autoridad nacional de registro civil de la jurisdicción correspondiente) cuando opere como emisor dentro del marco de confianza (`F24.T04`).
  2. `urn:gravital-id:vct:pip-identity-derived-v1`: utilizado por entidades públicas o privadas acreditadas (bancos, instituciones financieras, empresas afiliadas al **SVI** del TE) para emitir una **credencial de identidad verificada derivada** tras haber comprobado la cédula oficial y la biometría del titular (`F24.T03`).
  3. **Prevención de duplicidad ciudadana compatible con la Ley 81 de 2019 e `INV-02` (`ADR-0028`):** Para impedir que un mismo ciudadano registre múltiples identidades Gravital ID sin publicar la cédula ni un hash reversible en la blockchain, el servicio de emisión calcula un **`UniquenessTag` mediante una Función Pseudoaleatoria Oblicua Verificable (VOPRF, RFC 9497) o HMAC cuya clave secreta reside exclusivamente en HSM** sobre el identificador normalizado (`PA:CEDULA:8-888-8888`). Si ya existe un `UniquenessTag` activo, se bloquea la creación duplicada (`GID-E2010`) y se redirige a recuperación/re-vinculación.
* Ni la interfaz de usuario ni la documentación comercial deben presentar jamás una credencial `pip-identity-derived-v1` como sustituto legal de la cédula ante autoridades policiales o electorales sin marco normativo que lo habilite (`R-19`).

### 4.2 Tratamiento del Retrato Facial (`portrait`) bajo la Ley 81 de 2019 (`REQ-IDDOC-002`)
* La fotografía del rostro (`portrait` en `pip-identity-v1`) permite la identificación física de una persona natural y, si se somete a procesamiento técnico de comparación facial automatizada, constituye un **dato biométrico / dato sensible** bajo el Artículo 4 (numeral 7 y 8) y Artículo 9 de la Ley 81 de 2019 y el Decreto Ejecutivo 285 de 2021.
* Controles técnicos obligatorios implementados por diseño:
  1. **Ausencia de plantillas biométricas en el protocolo:** `pip-identity-v1` almacena únicamente una imagen JPEG Baseline limpia de metadatos EXIF/GPS para inspección visual humana, nunca vectores biométricos propietarios.
  2. **Cifrado en tránsito y restricción de canal:** El retrato solo viaja dentro de una sesión cifrada con HPKE sobre NFC (`GID-APDU`), BLE o canal en línea autenticado, y requiere autorización de Nivel 1 (PIN en tarjeta o biometría/segundo toque en móvil) más solicitud firmada del verificador (`REQ-PRES-007`).
  3. **No persistencia en el verificador:** El SDK de verificación prohíbe por defecto almacenar el retrato en disco en el terminal verificador tras la inspección visual (`REQ-IDDOC-002`).

### 4.3 Número Gravital por Emisor como Dato Personal (`REQ-CODE-004`)
* Mientras que el `SessionCode` efímero (Opción A por defecto de **ADR-0025**) identifica únicamente una sesión temporal de $\le 180\text{ s}$ y no constituye dato personal, el **Número Gravital por emisor** (Opción B opcional, desactivada por defecto) es un identificador persistente asignado por un emisor a una persona natural y, por tanto, califica plenamente como **dato personal** bajo la Ley 81 de 2019.
* Si un emisor habilita la Opción B, queda obligado a: (a) no publicarlo jamás en blockchain, logs, métricas ni errores (`INV-02`), (b) exigir consentimiento interactivo del titular en su wallet para cada resolución, y (c) permitir la revocación o rotación del número a solicitud del titular.

### 4.4 Obligaciones del Emisor de Tarjetas Físicas y Exclusión de Duplicidad por Clase de Dispositivo (`REQ-CARD-002`, `REQ-CARD-005`, `REQ-DEVSLOT-001..004`)
* El emisor que personalice y entregue tarjetas físicas Java Card (`gid-perso`, **ADR-0024**) o aprovisione teléfonos móviles (**ADR-0029**) actúa como responsable del tratamiento durante el aprovisionamiento y debe:
  1. Verificar fehacientemente la identidad del titular antes de entregar la tarjeta activada o vincular el dispositivo móvil.
  2. Garantizar que la clave privada se genere dentro del chip seguro (`StrongBox`/`TEE`, `Secure Enclave` o `Java Card`) sin copia de respaldo en los servidores de personalización (`REQ-CARD-001`, `INV-03`).
  3. **Aplicar la regla de Ranura Única por Clase de Dispositivo (`DeviceFactorClass`):** un titular puede mantener simultáneamente hasta un (1) teléfono móvil activo, una (1) tarjeta física tipo Visa activa y un (1) dispositivo auxiliar compatible activo, pero nunca dos dispositivos activos de la misma clase. El identificador físico del soporte (certificado de Key/IMEI Attestation en móvil o serial de silicio CPLC en tarjeta Java Card) solo se procesa mediante compromiso ciego con clave en HSM (`REQ-DEVSLOT-004`), nunca en claro ni en la blockchain.
  4. Proveer un canal permanente para que el titular reporte el extravío o robo de un soporte y el emisor revoque inmediatamente el índice de esa ranura en la `Token Status List` sin afectar los soportes activos del titular en otras clases (`REQ-CARD-005`, `REQ-DEVSLOT-003`).

---

## 5. Preguntas Formales para Asesoría Jurídica Externa (Fase F14)

Como criterio preparatorio para la formalización del marco legal definitivo en la **Fase F14** (`REQ-COMP-001`, `REQ-COMP-002`), se trasladarán formalmente a los asesores legales las siguientes cuestiones:

1. **Validez Probatoria y Firma Electrónica:**  
   ¿En qué supuestos el Key Binding JWT emitido con clave en Secure Enclave, StrongBox o tarjeta Java Card califica como "Firma Electrónica" o "Firma Electrónica Calificada" según la Ley 51 de 2008 (modificada por la Ley 82 de 2012) ante tribunales panameños?
2. **Régimen de Responsabilidad de la Autoridad del Marco (TFA):**  
   ¿Qué responsabilidad civil extracontractual asiste a los miembros de la TFA si un emisor institucional acreditado emite credenciales con datos falsos a un tercero?
3. **Registro ante la ANTAI:**  
   ¿Requiere la Autoridad Nacional de Transparencia y Acceso a la Información (ANTAI) el registro previo del sistema de gobernanza de PIP, considerando que la plataforma no custodia bases de datos centralizadas de usuarios?
4. **Armonización Transfronteriza en Centroamérica (SICA):**  
   ¿Cuáles son los requisitos de equivalencia para que una credencial emitida bajo el perfil `pip-personal-v1` o `pip-identity-v1` en Panamá sea legalmente admisible en trámites cívicos o privados en Costa Rica o Colombia?
5. **Convenio SVI y Reconocimiento bajo el Decreto N.° 43 de 2024 del Tribunal Electoral (`pip-identity-official-v1` vs `pip-identity-derived-v1`):**  
   ¿Qué instrumento jurídico (convenio de afiliación al **SVI** del Tribunal Electoral, homologación bajo el Decreto N.° 43 de 8 de octubre de 2024 o acuerdo sectorial bancario/privado) se requiere en Panamá para: (a) que el Tribunal Electoral actúe como emisor oficial de `pip-identity-official-v1`, y (b) delimitar el valor probatorio contractual de `pip-identity-derived-v1` entre privados que verificaron al ciudadano vía SVI?
6. **Clasificación del Retrato (`portrait`) bajo el Art. 9 de la Ley 81 de 2019:**  
   ¿La transmisión de una imagen JPEG del rostro únicamente para inspección visual presencial (sin extracción automatizada de vectores biométricos) requiere el régimen reforzado de datos sensibles del Art. 9 de la Ley 81, y qué cláusula de consentimiento expreso debe firmar el titular en el momento de la emisión?
7. **Régimen Legal del Número por Emisor (Opción B de `ADR-0025`):**  
   En caso de que un emisor adopte un número de cuenta Gravital de 10 dígitos para enrutamiento con consentimiento tipo 3-D Secure, ¿qué avisos de privacidad y plazos de conservación de metadatos de enrutamiento exige el Decreto Ejecutivo 285 de 2021?
8. **Responsabilidad ante Pérdida o Uso No Autorizado de Tarjeta Física (`ADR-0024` / `ADR-0029`):**  
   ¿Qué límite de responsabilidad asume el titular y cuál el emisor desde el instante en que el titular notifica el extravío de su tarjeta física Gravital hasta que los verificadores offline sincronizan la `Token Status List` actualizada (según la ventana `max_status_age` del perfil)?

