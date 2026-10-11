# ADR-0012: Modelo de gobernanza del registro de confianza

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #17
- **Requisitos y principios afectados:** REQ-GOV-001; REQ-GOV-002; REQ-GOV-003; P-01; P-10
- **Fase:** F0 (F0.T11)

---

## Contexto

El contrato inteligente del registro de confianza (`TrustRegistry.sol`) y el anclaje de revocación (`StatusAnchor.sol`) gestionan la autorización de emisores de identidad, las claves de verificación y los parámetros del marco de confianza.
Riesgos y requisitos de gobernanza:
1. **Eliminación de puntos únicos de control o compromiso:** Ninguna persona o clave privada individual debe tener la capacidad de añadir, modificar o revocar emisores de manera unilateral en el registro de confianza.
2. **Prevención de captura o ataques rápidos:** La adición o modificación de emisores no debe poder ejecutarse de forma instantánea y secreta; los participantes del ecosistema deben disponer de un período de preaviso para auditar cualquier cambio y reaccionar antes de su entrada en vigor.
3. **Respuesta a incidentes de seguridad en tiempo real:** Si la clave privada de un emisor legítimo es robada o comprometida, se requiere un mecanismo inmediato para suspender temporalmente la validez de dicha clave sin esperar días de retraso burocrático, pero sin otorgar poderes destructivos o arbitrarios irrecuperables.

---

## Opciones consideradas

### Opción A — Clave de administración única con patrón Ownable
- **Ventajas:** Simplicidad y bajo coste de ejecución en pruebas.
- **Inconvenientes:** Vulnerabilidad crítica absoluta; un compromiso de la clave privada del administrador entrega el control total del ecosistema a un atacante.

### Opción B — Organización Autónoma Descentralizada (DAO) con votación pública de tokens
- **Ventajas:** Descentralización masiva.
- **Inconvenientes:** Inadecuada para marcos regulatorios de identidad y protección de datos; susceptible a ataques de gobernanza financiera (*flash loans*, concentración de tokens de voto); lentitud decisoria extrema.

### Opción C — Gobernanza institucional federada: Multisig institucional + Timelock + Rol de Emergencia limitado (Recomendada)
- **Ventajas:**
  - **Trust Framework Authority (TFA):** Órgano de gobierno técnico compuesto por miembros institucionales independientes.
  - **Multisig por umbral ($k$-de-$n$):** Todas las decisiones estructurales (alta de emisores, cambios de parámetros, reemplazo de contratos) requieren la aprobación conjunta de al menos $k$ miembros independientes utilizando billeteras hardware seguras.
  - **Timelock obligatorio (48 a 72 horas):** Toda propuesta aprobada por la multisig queda encolada en una cola temporal pública inmutable antes de poder ser ejecutada, permitiendo auditoría pública continua.
  - **Rol de Emergencia acotado (`EmergencyRole`, ADR-0018):** Capacidad de intervención inmediata sin timelock con facultades **estrictamente limitadas a suspender temporalmente** un emisor o clave comprometida (máximo 14 días). El rol de emergencia no tiene facultades para registrar nuevos emisores ni modificar parámetros. Si la suspensión no es confirmada por la multisig completa tras el período de timelock, caduca automáticamente y se restablece el estado previo.
- **Inconvenientes:** Requiere coordinar ceremonias de firma para cambios ordinarios.

---

## Decisión

Se adopta la **Opción C**:
1. La gobernanza de los contratos del registro de confianza se implementa mediante un esquema **Multisig $k$-de-$n$ con bloqueo temporal (*Timelock*) obligatorio de 48 a 72 horas** para todas las operaciones mutables ordinarias.
2. Se incorpora el **Rol de Emergencia** (`EmergencyRole`) sin timelock, sujeto estrictamente a las restricciones de `ADR-0018`:
   - Alcance limitado a suspensión reversible.
   - Caducidad forzada a los 14 días naturales.
   - Imposibilidad de alterar esquemas, modificar parámetros de confianza o autorizar nuevos emisores.
3. El proceso formal de gobernanza y las transiciones de estado se formalizan en la especificación normativa `docs/specs/TRUST_FRAMEWORK.md`.

---

## Consecuencias

- Las especificaciones normativas `CONTRACTS.md`, `TRUST_FRAMEWORK.md` y `SECURITY.md` implementan de forma coordinada las reglas de gobernanza técnica.
- Se asegura el cumplimiento del criterio de gobernanza para el Gate G0.
