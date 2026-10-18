# Guía de Despliegue e Infraestructura de Gravital ID (F6.T11, F7.T01, ADR-0013, REQ-REL-001)

Este directorio contiene las definiciones de infraestructura como código (IaC), contenedores OCI, esquemas y artefactos de despliegue para los contratos inteligentes y servicios backend de Gravital ID.

---

## 1. Entornos de Red y Topología

| Entorno | Red EVM | Chain ID | Infraestructura Backend | Almacenamiento S3 / CDN | Artefactos |
|---|---|---|---|---|---|
| `local` | Anvil (Local EVM) | `31337` | Docker Compose (`deploy/docker`) | MinIO local (`:9000`) | `deploy/environments/local/contracts.json` |
| `dev` | Arbitrum Sepolia Dev | `421614` | OpenTofu / AWS ECS Fargate | S3 + CloudFront | `deploy/environments/dev/contracts.json` |
| `testnet` | Arbitrum Sepolia | `421614` | OpenTofu / AWS ECS Fargate | S3 + CloudFront | `deploy/environments/testnet/contracts.json` |

---

## 2. Despliegue de Contratos Inteligentes (Foundry)

### 2.1 Requisitos Previos
- **Foundry:** `forge`, `cast`, `anvil` (Foundryup).
- **Compilador:** Solidity `0.8.28` con optimizador a 200 runs y `via_ir = true` (`contracts/foundry.toml`).
- **Variables de Entorno Requeridas:**
  - `DEPLOYER_PRIVATE_KEY`: Clave privada de la cuenta con fondos de gas.
  - `TFA_ADMIN_MULTISIG`: Dirección de la Safe Multisig de la TFA.
  - `EMERGENCY_MULTISIG`: Dirección de la cuenta o multisig de respuesta a incidentes (`EMERGENCY_ROLE`).
  - `TIMELOCK_DELAY_SECONDS`: Retardo mínimo para el Timelock (mínimo inmutable de 48 horas = `172800` s).
  - `ETHERSCAN_API_KEY`: Clave de API para verificación en Arbiscan.

### 2.2 Despliegue en Entorno Local (Anvil)
```bash
# Iniciar nodo local
anvil

# Desplegar contratos en local
forge script contracts/script/Deploy.s.sol \
    --rpc-url http://127.0.0.1:8545 \
    --broadcast \
    --root contracts
```

### 2.3 Despliegue y Verificación en Testnet (Arbitrum Sepolia)
```bash
forge script contracts/script/Deploy.s.sol \
    --rpc-url "https://sepolia-rollup.arbitrum.io/rpc" \
    --broadcast \
    --verify \
    --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --root contracts
```

---

## 3. Entorno Local de Servicios Backend (Docker Compose)

Conforme a **ADR-0013**, se provee un stack local totalmente reproducible en `deploy/docker/docker-compose.yml` que emula el plano de servicios completo de la Fase F7 sin dependencias externas:

- **`anvil`:** Nodo EVM local con los contratos predesplegados (puerto `8545`).
- **`postgres`:** PostgreSQL 16 con base de datos relacional para `pip-indexer` (puerto `5432`).
- **`minio`:** Almacenamiento compatible con S3 para Trust Bundles y Listas de Revocación (puertos `9000` y `9001`).
- **`pip-indexer`:** Ingesta continua y procesamiento idempotente de eventos del ledger (puerto `8081`).
- **`pip-trust-service`:** Generación y cofirma determinista de trust bundles (puerto `8082`).
- **`pip-relay`:** Caché de listas y buzón de sobres cifrados HPKE (puerto `8083`).

### 3.1 Puesta en Marcha Local
```bash
# 1. Copiar la plantilla sanitizada de variables de entorno
cp deploy/docker/.env.example deploy/docker/.env

# 2. Levantar el stack completo en segundo plano
docker compose -f deploy/docker/docker-compose.yml up -d

# 3. Comprobar el estado y salud de los servicios
docker compose -f deploy/docker/docker-compose.yml ps
```

---

## 4. Infraestructura como Código (OpenTofu / Terraform)

La infraestructura remota en la nube para `dev` y `testnet` se gestiona mediante OpenTofu / Terraform en `deploy/iac/`:

```text
deploy/iac/
├── modules/
│   ├── networking/    # VPC, subredes públicas y privadas multi-AZ, NAT Gateway
│   ├── database/      # RDS PostgreSQL 16 cifrado en subred privada
│   ├── storage/       # Buckets S3 (Trust Bundles, Status Lists) y CDN CloudFront
│   ├── kms/           # Claves simétricas (secretos) y asimétricas P-256 (firma de bundles)
│   └── compute/       # ECS Fargate, tareas sin privilegios y CloudWatch logs
└── environments/
    ├── dev/           # Entorno de integración y desarrollo
    └── testnet/       # Entorno oficial de testnet en Arbitrum Sepolia
```

### 4.1 Despliegue de Entorno Testnet
```bash
cd deploy/iac/environments/testnet

# 1. Copiar y configurar las variables requeridas (sin comitear secretos)
cp terraform.tfvars.example terraform.tfvars

# 2. Inicializar OpenTofu / Terraform
tofu init

# 3. Planificar y validar recursos
tofu plan -out=tfplan

# 4. Aplicar cambios
tofu apply tfplan
```

---

## 5. Higiene de Secretos y Cumplimiento Normativo

- **Cero Secretos en el Repositorio (`INV-02`, `REQ-REL-001`):** Ninguna clave privada, token ni contraseña se comitea en el repositorio.
- **Claves Criptográficas en Hardware (`REQ-ISS-002`):** En entornos remotos (`dev`, `testnet`, `prod`), las claves de los operadores residen en Cloud KMS / HSM; nunca se exportan ni cruzan FFI.
- **Protección de Datos Personales (`INV-02`, `REQ-PRIV-003`):** Ni el indexador, ni los relays, ni el almacenamiento S3 almacenan datos personales ni identificadores reversibles de titulares.
