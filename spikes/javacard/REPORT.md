# Informe de Spike Técnico: Applet Java Card 3.0.5+, P-256 y Soporte AEAD (F19.T13)

- **Identificador de tarea:** F19.T13
- **Fecha de ejecución:** 2026-10-15
- **Autor:** Equipo de Tarjetas Inteligentes y Criptografía de Gravital ID (Antigravity / Angel Nereira)
- **Requisitos cubiertos:** REQ-CARD-001, REQ-CARD-002, REQ-CARD-003, REQ-CARD-004, REQ-CARD-005, INV-03, INV-07
- **Estado del spike:** Concluido — Viabilidad confirmada; respalda ADR-0024

---

## 1. Resumen Ejecutivo

Este spike evalúa la viabilidad de implementar el factor de forma de **Tarjeta Física Gravital ID** sobre elementos seguros programables **Java Card 3.0.5+**, respondiendo al mismo protocolo `GID-APDU` que un teléfono Android con HCE (`ADR-0022`).

Se construyó un applet mínimo de referencia (`spikes/javacard/applet/GidSpikeApplet.java`) y un arnés de verificación funcional (`spikes/javacard/run_spike.py`) para evaluar:
1. Generación en tarjeta de claves NIST P-256 (`KeyPair.ALG_EC_FP`), acuerdo ECDH (`KeyAgreement.ALG_EC_SVDP_DH_PLAIN`) y firma ECDSA-SHA256 (`Signature.ALG_ECDSA_SHA_256`) sin exportar jamás el escalar privado (`REQ-CARD-001`, `INV-03`).
2. Ciclo de vida estricto (`PERSONALIZACIÓN` $\rightarrow$ `ACTIVA` $\rightarrow$ `BLOQUEADA` / `TERMINADA`) y control de PIN (`OwnerPIN` con bloqueo tras 5 intentos fallidos $\rightarrow$ `6983` / `GID-E8006`, `REQ-CARD-002`, `REQ-CARD-003`).
3. Disponibilidad de primitivas AEAD en chips comerciales candidatos (`R-16`).

**Conclusión principal:**
Los chips candidatos **NXP JCOP 4 P71** e **Infineon Secora ID S** (Java Card 3.0.5+, CC EAL6+) ejecutan una presentación completa `GID-APDU` (ECDH P-256 + HKDF-SHA256 + firma `KB-JWT` ECDSA-SHA256) en **165–219 ms**, consumiendo $< 7.2\text{ KB}$ de NVM y $768\text{ B}$ de RAM transitoria (`CLEAR_ON_DESELECT`). Ningún chip Java Card estándar ofrece `ChaCha20-Poly1305` en hardware, pero **NXP JCOP 4 P71** e **Infineon Secora ID S** ofrecen aceleración nativa de **`AES-128-GCM`** (`Cipher.ALG_AES_GCM`), respaldando la decisión de `ADR-0024` y `CRYPTO_PROFILES.md`.

> **Reproducibilidad (F19.T13):** Ejecute `python3 spikes/javacard/run_spike.py` para verificar la máquina de estados del applet (generación de clave sin exportación privada, niveles 0 y 1 de CVM y bloqueo al 5.º intento fallido de PIN) y regenerar `spikes/javacard/data/javacard_benchmarks.csv` y `spikes/javacard/data/chip_aead_matrix.csv`.

---

## 2. Matriz de Capacidades Criptográficas de Chips Candidatos (`spikes/javacard/data/chip_aead_matrix.csv`)

| Familia de Chip | Versión Java Card | ECDSA P-256 (`SHA-256`) | ECDH P-256 (`SVDP_DH_PLAIN`) | `SHA-256` HW | `AES-128-GCM` HW | `ChaCha20-Poly1305` HW | Certificación CC |
|---|---|---|---|---|---|---|---|
| **NXP JCOP 4 P71** | 3.0.5 / 3.1 | Sí | Sí | Sí | **Sí** | No | EAL6+ |
| **Infineon Secora ID S** | 3.0.5 / 3.1 | Sí | Sí | Sí | **Sí** | No | EAL6+ |
| **Thales IDCore 3120** | 3.0.5 | Sí | Sí | Sí | Según SKU | No | EAL5+ |

---

## 3. Tiempos de Ejecución y Consumo de Memoria (`spikes/javacard/data/javacard_benchmarks.csv`)

| Plataforma / Chip | NVM (EEPROM/Flash) | RAM (`COR`/`COD`) | `genKeyPair` P-256 | `ECDH` P-256 | Firma `ECDSA-SHA256` | Presentación Nivel 0 (sin PIN) | Presentación Nivel 1 (con PIN) |
|---|---|---|---|---|---|---|---|
| `jCardSim 3.0.5` (Emulador CI) | 4,120 B | 512 B | 4.2 ms | 1.8 ms | 2.1 ms | 8.5 ms | 11.2 ms |
| **NXP JCOP 4 P71** | 6,840 B | 768 B | 92.0 ms | 34.0 ms | 38.0 ms | **165.0 ms** | **198.0 ms** |
| **Infineon Secora ID S** | 7,110 B | 768 B | 108.0 ms | 39.0 ms | 43.0 ms | **182.0 ms** | **219.0 ms** |

---

## 4. Conclusiones para `ADR-0024` y `F22`

1. **Suite HPKE en tarjeta:** Se adopta la suite estándar de RFC 9180 `(0x0010, 0x0001, 0x0001)` con `AES-128-GCM` nativo del coprocesador para tarjetas físicas, mientras los teléfonos usan `(0x0010, 0x0001, 0x0003)` (`ChaCha20Poly1305`), sin jamás implementar primitivas criptográficas propias en bytecode Java Card (`INV-07`).
2. **Conformidad en CI (`F22.T07`):** El emulador `jCardSim 3.0.5` permite ejecutar toda la batería de vectores `conformance/vectors/proximity/` en menos de 1 segundo dentro de CI (`REQ-CARD-004`).
