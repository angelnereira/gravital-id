# Análisis Regulatorio Preliminar: Protección de Datos (Ley 81) y Marco KYC/AML

> **Identificador normativo:** `LEGAL-PIP-REG-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T20`)  
> **Estado:** Documento de trabajo preparatorio / Pendiente de dictamen legal formal en F14  
> **Fecha:** 2026-10-11  
> **Trazabilidad:** REQ-COMP-001, REQ-COMP-002, REQ-COMP-003; INV-02; P-02, P-03, P-09.

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
| **Confidencialidad** | Deber de reserva de quienes intervienen en el tratamiento. | Verificación desconectada punto a punto (P2P vía QR offline). No existen servidores centrales de autenticación que registren transacciones de los usuarios. |

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

## 4. Preguntas Formales para Asesoría Jurídica Externa (Fase F14)

Como criterio preparatorio para la formalización del marco legal definitivo en la **Fase F14** (REQ-COMP-001, REQ-COMP-002), se trasladarán formalmente a los asesores legales las siguientes cuestiones:

1. **Validez Probatoria y Firma Electrónica:**  
   ¿En qué supuestos el Key Binding JWT emitido con clave en Secure Enclave califica como "Firma Electrónica Calificada" según la Ley 51 de 2008 (modificada por la Ley 82 de 2012) ante tribunales panameños?
2. **Régimen de Responsabilidad de la Autoridad del Marco (TFA):**  
   ¿Qué responsabilidad civil extracontractual asiste a los miembros de la TFA si un emisor institucional acreditado emite credenciales con datos falsos a un tercero?
3. **Registro ante la ANTAI:**  
   ¿Requiere la Autoridad Nacional de Transparencia y Acceso a la Información (ANTAI) el registro previo del sistema de gobernanza de PIP, considerando que la plataforma no custodia bases de datos centralizadas de usuarios?
4. **Armonización Transfronteriza en Centroamérica (SICA):**  
   ¿Cuáles son los requisitos de equivalencia para que una credencial emitida bajo el perfil `pip-personal-v1` en Panamá sea legalmente admisible en trámites cívicos en Costa Rica o Colombia?
