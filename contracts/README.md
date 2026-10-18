# Contratos Inteligentes de Gravital ID (F6, REQ-LEDG-*)

Este directorio contiene los contratos inteligentes de registro de confianza y anclaje de estado de Gravital ID, desarrollados en Solidity `0.8.28` con Foundry.

## 1. Contratos del Protocolo

- **`TrustRegistry.sol`** (`ITrustRegistry`): Registro descentralizado de emisores institucionales, claves públicas P-256 SEC-1 con máquina de estados estricta (`Active`, `Suspended`, `Retired`, `Compromised`), registro de verificadores por perfil, compromiso de raíz de confianza y operadores firmantes de trust bundle (`REQ-TRUST-007`, `REQ-LEDG-003`).
- **`StatusAnchor.sol`** (`IStatusAnchor`): Anclaje descentralizado de compromisos de listas de estado (raíz Merkle SHA-256) con versión monotónica estricta para mitigación de bifurcaciones fraudulentas (*split-view*, `REQ-STAT-006`).
- **`GovernanceTimelock.sol`**: Controlador timelock derivado de OpenZeppelin con retardo mínimo inmutable de 48 horas (`172800` s) para altas y bajas estructurales (`REQ-LEDG-004`).

---

## 2. Invariantes de Seguridad y Privacidad

- **Sin Proxies:** Todos los contratos son inmutables sin proxies actualizables (`REQ-LEDG-003`).
- **Cero Datos Personales:** Cero PII en eventos, parámetros o almacenamiento (`REQ-LEDG-001`, `INV-02`, verificado por `cargo xtask check-contracts-privacy`).
- **Separación de Poderes:** Timelock para gobernanza, `EMERGENCY_ROLE` limitado a suspensiones de 14 días sin posibilidad de renovación ni alteración de claves (`REQ-LEDG-004`).

---

## 3. Comandos de Construcción y Pruebas

```bash
# Compilar contratos y scripts
forge build

# Ejecutar suite de pruebas unitarias, fuzz e invariantes (25 pruebas)
forge test -vvv

# Validar línea base de gas versionada
forge snapshot --check

# Validar ausencia de PII en ABIs
cargo xtask check-contracts-privacy
```

---

## 4. Despliegue

Consulte `deploy/README.md` para la guía completa de despliegue reproducible en redes locales (Anvil) y testnet (Arbitrum Sepolia, Chain ID `421614`), así como las direcciones en `deploy/environments/testnet/contracts.json`.

```bash
# Simulación local
forge script script/Deploy.s.sol

# Despliegue a Arbitrum Sepolia
forge script script/Deploy.s.sol \
    --rpc-url "https://sepolia-rollup.arbitrum.io/rpc" \
    --broadcast \
    --verify
```
