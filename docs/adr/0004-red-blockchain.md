# ADR-0004: Red blockchain para el registro de confianza (EVM L1 vs L2)

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #9
- **Requisitos y principios afectados:** REQ-LEDG-001; REQ-LEDG-002; REQ-LEDG-003; P-01; P-10
- **Fase:** F0 (F0.T10 / F0.T11)

---

## Contexto

El protocolo Gravital ID requiere una capa inmutable y públicamente auditable para:
1. Registrar la identidad y claves públicas de los emisores autorizados (`TrustRegistry.sol`).
2. Anclar periódicamente raíces de confianza y hashes de snapshots de listas de estado de revocación (`StatusAnchor.sol`).
3. Registrar eventos de gobernanza, timelocks y suspensiones de emergencia sin intermediarios censurables.

Sin embargo, el protocolo impone restricciones críticas:
- Los dispositivos móviles y clientes ligeros **no realizan consultas RPC directas a la cadena** en flujos ordinarios ni transportan clientes ligeros pesados (evitando fugas de privacidad y consumo excesivo de batería/datos, según ADR-0016).
- Los costes de transacción (gas) deben ser sostenibles para permitir anclajes frecuentes de lotes por parte de los emisores y operadores.
- La red debe ofrecer máxima compatibilidad con el ecosistema de desarrollo de contratos inteligentes y proveedores RPC descentralizados.

---

## Opciones consideradas

### Opción A — Ethereum Mainnet (L1) exclusivo
- **Ventajas:** Máxima seguridad económica y descentralización del mundo.
- **Inconvenientes:** Costes de gas prohibitivos para anclajes periódicos de listas ($5 a $50 USD por transacción según la congestión de la red); latencia de finalidad de 12 a 15 minutos.

### Opción B — Redes de Capa 2 (L2 Rollups basados en EVM: Arbitrum One / Base) (Recomendada)
- **Ventajas:**
  - Costes de transacción ultra-bajos (< $0.005 USD por transacción de anclaje tras la actualización EIP-4844 / Blobs).
  - Finalidad sub-segundo para confirmaciones preliminares y anclaje criptográfico final a Ethereum L1 mediante pruebas de fraude o validez.
  - Compatibilidad total con EVM estándar (Solidity 0.8.x), herramientas (Foundry, Hardhat) y bibliotecas de infraestructura existentes.
  - Múltiples proveedores de RPC públicos y privados redundantes (Alchemy, Infura, QuickNode, nodos propios).
- **Inconvenientes:** Dependencia del sequenciador L2 (mitigado por el mecanismo de auto-escape / escape hatch a L1 presente en los rollups maduros).

### Opción C — Cadena de bloques permisionada / Consorcio privado (Hyperledger Fabric / Besu privado)
- **Ventajas:** Coste marginal de transacción nulo y control total.
- **Inconvenientes:** Falta de transparencia pública y auditabilidad externa; riesgo de captura institucional; costes elevados de mantenimiento de infraestructura de nodos dedicados.

---

## Decisión

Se adopta la **Opción B**:
1. Los contratos inteligentes del protocolo (`TrustRegistry` y `StatusAnchor`) se diseñan e implementan en **Solidity estándar compatible con EVM** (versión 0.8.24 o superior), sin dependencia de opcodes propietarios.
2. Para entornos de desarrollo y testnets, se utilizarán **Arbitrum Sepolia** y **Base Sepolia**.
3. Para el despliegue en producción, se priorizará una **L2 consolidada respaldada por Ethereum (Arbitrum One o Base)**, garantizando que el coste de gas por anclaje no supere $0.01 USD.
4. Los operadores de confianza (`pip-trust-service`) y los indexadores (`pip-indexer`) consultarán el estado finalizado de la cadena utilizando al menos dos proveedores de nodos RPC independientes para detectar posibles equivocaciones o fallos de infraestructura.

---

## Consecuencias

- Los contratos inteligentes se redactan de acuerdo con las interfaces y eventos especificados en `docs/specs/CONTRACTS.md`.
- El spike técnico `spikes/ledger/REPORT.md` (F0.T10) valida empíricamente los costes de gas, los tiempos de finalidad y la disponibilidad de endpoints RPC en las testnets seleccionadas.
