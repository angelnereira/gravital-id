# Guía de Despliegue de Contratos Inteligentes (F6.T11, REQ-LEDG-003)

Este directorio contiene las configuraciones, esquemas y artefactos de despliegue para los contratos inteligentes de Gravital ID (`TrustRegistry`, `StatusAnchor` y `GovernanceTimelock`).

## 1. Entornos de Red

| Entorno | Red EVM | Chain ID | Explorer | Artefacto |
|---|---|---|---|---|
| `testnet` | Arbitrum Sepolia | `421614` | [sepolia.arbiscan.io](https://sepolia.arbiscan.io) | `deploy/environments/testnet/contracts.json` |
| `local` | Anvil (Local EVM) | `31337` | N/A | `deploy/environments/local/contracts.json` |

---

## 2. Requisitos Previos

- **Foundry:** `forge`, `cast`, `anvil` (Foundryup).
- **Compilador:** Solidity `0.8.28` con optimizador a 200 runs y `via_ir = true` (`contracts/foundry.toml`).
- **Variables de Entorno:**
  - `DEPLOYER_PRIVATE_KEY`: Clave privada de la cuenta con fondos de gas.
  - `TFA_ADMIN_MULTISIG`: Dirección de la Safe Multisig de la TFA.
  - `EMERGENCY_MULTISIG`: Dirección de la cuenta o multisig de respuesta a incidentes (`EMERGENCY_ROLE`).
  - `TIMELOCK_DELAY_SECONDS`: Retardo mínimo para el Timelock (mínimo inmutable de 48 horas = `172800` s).
  - `ETHERSCAN_API_KEY`: Clave de API para verificación en Arbiscan.

---

## 3. Despliegue en Entorno Local (Anvil)

1. En una terminal, iniciar el nodo local:
   ```bash
   anvil
   ```

2. Ejecutar el script de despliegue en modo broadcast:
   ```bash
   forge script contracts/script/Deploy.s.sol \
       --rpc-url http://127.0.0.1:8545 \
       --broadcast \
       --root contracts
   ```

3. Las direcciones desplegadas coincidirán con las registradas en `deploy/environments/local/contracts.json`.

---

## 4. Despliegue y Verificación en Testnet (Arbitrum Sepolia)

1. Ejecutar el script apuntando al endpoint RPC de Arbitrum Sepolia y habilitando verificación automática en Arbiscan:
   ```bash
   forge script contracts/script/Deploy.s.sol \
       --rpc-url "https://sepolia-rollup.arbitrum.io/rpc" \
       --broadcast \
       --verify \
       --etherscan-api-key "$ETHERSCAN_API_KEY" \
       --root contracts
   ```

2. Una vez completado, verificar que las direcciones desplegadas queden registradas en `deploy/environments/testnet/contracts.json` conforme al esquema `deploy/schema/contracts.schema.json`.

---

## 5. Verificación de Código Fuente en el Explorador

Todos los contratos son inmutables sin proxies (`REQ-LEDG-003`) y pueden verificarse independientemente en [Arbiscan](https://sepolia.arbiscan.io) mediante el comando `forge verify-contract`:

```bash
# Verificar GovernanceTimelock
forge verify-contract <TIMELOCK_ADDRESS> contracts/src/GovernanceTimelock.sol:GovernanceTimelock \
    --chain-id 421614 --compiler-version 0.8.28

# Verificar TrustRegistry
forge verify-contract <TRUST_REGISTRY_ADDRESS> contracts/src/TrustRegistry.sol:TrustRegistry \
    --chain-id 421614 --compiler-version 0.8.28

# Verificar StatusAnchor
forge verify-contract <STATUS_ANCHOR_ADDRESS> contracts/src/StatusAnchor.sol:StatusAnchor \
    --chain-id 421614 --compiler-version 0.8.28
```
