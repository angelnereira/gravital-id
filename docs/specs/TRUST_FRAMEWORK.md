# Especificación PIP: Marco de Gobernanza Técnica y Confianza

> **Identificador normativo:** `SPEC-PIP-GOV-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T18`)  
> **Estado:** Normativo técnico / Pendiente de revisión legal en F14  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-GOV-001, REQ-LEDG-004, REQ-TRUST-001, 005, 006, 009, 010; ADR-0012, ADR-0016, ADR-0018; P-02, P-08, P-10, P-15.

---

## 1. Alcance y Naturaleza del Marco

El Marco de Confianza (Trust Framework) establece las reglas de gobierno, umbrales criptográficos, tiempos de observación y procedimientos operativos para garantizar la integridad descentralizada del ecosistema PIP / Gravital ID.

> ⚠️ **Aviso de Fase:** Este documento constituye la especificación de **gobernanza técnica (v0.1)**. Los términos legales de vinculación, acuerdos de nivel de servicio (SLA) comerciales, responsabilidades civiles y cláusulas de jurisdicción internacional se redactarán en la **Fase F14 (Marco de confianza v1, legal y gobernanza)** en coordinación con asesoría jurídica especializada (REQ-GOV-001).

---

## 2. Definición de Roles del Ecosistema

```text
    ┌────────────────────────────────────────────────────────┐
    │     Autoridad del Marco de Confianza (TFA Council)     │
    │          (Gobernanza Multisig k-de-n On-Chain)         │
    └───────────┬────────────────────────────────┬───────────┘
                │ Timelock (48-72h)              │ Claves Frías
                ▼                                ▼
    ┌────────────────────────┐       ┌────────────────────────┐
    │  Registro en Ledger    │       │   Raíz de Confianza    │
    │  (Ethereum / L2 EVM)   │       │      (TrustRoot)       │
    └───────────┬────────────┘       └───────────┬────────────┘
                │ Bloques Finalizados            │ Autoriza
                ▼                                ▼
    ┌────────────────────────────────────────────────────────┐
    │        Operadores de Bundle Independientes (n >= 3)    │
    │         (Indexación Determinista y Cofirma k-de-n)     │
    └───────────────────────────┬────────────────────────────┘
                                │ TrustBundle JWS
                                ▼
    ┌────────────────────────────────────────────────────────┐
    │     Verificadores Offline y Wallets de Titulares       │
    └────────────────────────────────────────────────────────┘
```

1. **Autoridad del Marco de Confianza (TFA - Trust Framework Authority):**  
   Órgano de gobernanza colegiado conformado por representantes de instituciones participantes (entidades públicas, banca, telecomunicaciones, auditoría). Gobierna los contratos inteligentes y emite las raíces de confianza.
2. **Operadores de Bundle Independientes:**  
   Organizaciones técnicas independientes que ejecutan nodos indexadores propios y cofirman periódicamente el `TrustBundle` derivado deterministamente del ledger.
3. **Emisores Acreditados:**  
   Entidades autorizadas formalmente para emitir credenciales bajo perfiles específicos (`pip-personal-v1`, `pip-financial-v1`, etc.).
4. **Verificadores Acreditados:**  
   Organizaciones registradas cuyas claves públicas constan en el registro para emitir solicitudes de verificación firmadas en perfiles que lo exijan.
5. **Titulares:**  
   Personas y entidades que custodian sus propias claves y credenciales sin depender de intermediarios de custodia.

---

## 3. Umbrales Criptográficos y Tiempos de Observación

Para erradicar puntos únicos de falla (P-10, P-15):

| Parámetro | Umbral Mínimo Normativo | Descripción |
|---|---|---|
| **Multisig On-Chain (TFA)** | $\ge 3$ de 5 (o $\ge 4$ de 7) | Administración de contratos y altas de emisores. |
| **Raíz de Confianza (`TrustRoot`)** | $\ge 2$ de 3 (o $\ge 3$ de 5) | Firmas fuera de línea (claves frías / HSM) para rotación de raíz. |
| **Operadores de Bundle** | $\ge 2$ de 3 (o $\ge 3$ de 5) | Número de operadores independientes requeridos para validar un bundle. |
| **Ventana de Timelock Ordinario** | 48 a 72 horas | Periodo de observación pública previo a activar un alta o rotación. |
| **Vigencia Máxima de `TrustBundle`** | 7 días (604,800 s) | Periodo tras el cual un bundle no renovado pasa a `Unverifiable`. |
| **Rol de Emergencia (Sin Timelock)** | Umbral separado ($\ge 2$ de 3) | **Solo puede suspender** cautelarmente por 14 días (ADR-0018). |

---

## 4. Procedimiento de Alta de Emisores

El proceso de acreditación garantiza que ningún emisor fraudulento ingrese al ecosistema:

1. **Verificación Legal Fuera de Línea:** Comprobación de personalidad jurídica, licencias regulatorias y cumplimiento de estándares de seguridad (ISO 27001, SOC 2 o equivalente).
2. **Acuerdo del Marco:** Firma bilateral de los términos de gobernanza y asunción de responsabilidades por emisión indebida.
3. **Solicitud On-Chain:** La TFA somete a la multisig la transacción `registerIssuer(...)` indicando URI oficial, perfiles admitidos y tipos de credencial autorizados.
4. **Periodo de Observación (Timelock):** La propuesta permanece visible públicamente durante 48–72 horas en el `TimelockController`. Cualquier participante puede auditar la solicitud.
5. **Ejecución y Activación:** Vencido el timelock, la transacción se ejecuta; los indexadores detectan el evento `IssuerRegistered` y los siguientes bundles incorporan al nuevo emisor.

---

## 5. Gestión de Incidentes y Bajas

### 5.1 Rotación Ordinaria de Claves de Emisor
* El emisor anuncia la nueva clave vía multisig.
* La clave saliente se marca como `Retired` a partir de `stateSince = now`. Las credenciales emitidas antes de dicha fecha siguen siendo válidas hasta su vencimiento.

### 5.2 Compromiso de Claves y Rol de Emergencia (ADR-0018)
1. **Detección de Brecha:** Ante sospecha de filtración de una clave privada de emisor:
   - El equipo de respuesta a incidentes invoca `emergencySuspendKey(issuerId, kid)` a través del `EMERGENCY_ROLE`.
   - **Efecto Inmediato:** Sin esperar timelock, los verificadores marcan las presentaciones asociadas como `Unverifiable` (evidencia `IssuerKeySuspended`).
   - **Caducidad Automática:** La suspensión dura exactamente 14 días.
2. **Investigación:**
   - Si se confirma el compromiso: La multisig completa de la TFA somete a timelock la orden irreversible `markKeyCompromised(...)`. Todas las credenciales firmadas por dicha clave pasan a ser `Invalid`.
   - Si resulta ser falsa alarma: El rol de emergencia invoca `emergencyLiftSuspension(...)` restaurando la normalidad.

### 5.3 Baja Definitiva de Emisor
La expulsión de un emisor por incumplimiento grave requiere votación mayoritaria del consejo TFA en la multisig principal.
