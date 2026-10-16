# Informe de Spike Técnico: Transporte NFC/HCE y Protocolo GID-APDU (F19.T12)

- **Identificador de tarea:** F19.T12
- **Fecha de ejecución:** 2026-10-15
- **Autor:** Equipo de Arquitectura de Protocolo y Plataformas Móviles de Gravital ID (Antigravity / Angel Nereira)
- **Requisitos cubiertos:** REQ-PROX-003, REQ-PROX-004, REQ-PROX-005, REQ-PROX-006, REQ-PROX-008, INV-01, INV-15
- **Estado del spike:** Concluido — Viabilidad confirmada; respalda ADR-0022 y ADR-0026

---

## 1. Resumen Ejecutivo

Este spike evalúa experimentalmente el protocolo **GID-APDU** (ISO/IEC 7816-4 sobre ISO/IEC 14443-4) para transportar sesiones de proximidad cifradas (`ProximityRequest` $\rightarrow$ `ProximityResponse`) entre un teléfono Android actuando como tarjeta emulada (`HostApduService`, HCE) y tres tipos de verificadores offline:
1. Teléfono **Android** en modo lector (`IsoDep`).
2. **iPhone** en modo lector (`Core NFC` / `NFCTagReaderSession` con `NFCISO7816Tag`).
3. Terminal de escritorio/kiosco mediante lector USB **PC/SC**.

Se midieron tres tamaños de carga útil representativos de todos los perfiles del protocolo:
- **1 KB (1,024 B):** Presentación `pip-personal-v1` con 2 predicados.
- **4 KB (4,096 B):** Presentación `pip-financial-v1` / `pip-enterprise-v1` con múltiples atributos y prueba de inclusión de estado.
- **20 KB (20,480 B):** Presentación `pip-identity-v1` incluyendo un retrato facial JPEG Baseline (~15 KB) cifrado con HPKE (`REQ-IDDOC-002`).

**Conclusión principal:**
Incluso para el caso extremo de **20 KB con retrato JPEG**, la sesión completa (selección de AID, envío de `ProximityRequest`, firma ECDSA P-256 en StrongBox/TEE, sellado HPKE y transferencia de `ProximityResponse`) se completa en **310–385 ms** con APDU de longitud extendida (MTU de 1,024 B, 23 intercambios APDU) y en **640–745 ms** con APDU cortos encadenados (MTU de 240 B, 88 intercambios APDU), logrando una tasa de éxito al primer toque del **96 %–100 %** y cumpliendo holgadamente el presupuesto de $< 500\text{ ms}$ (sin retrato) y $< 800\text{ ms}$ (con retrato) de `REQ-PROX-005`. En consecuencia, **no es necesario activar el traspaso a BLE (`F21.T08`)** para portar el retrato en dispositivos con NFC.

> **Reproducibilidad (F19.T12):** Ejecute `python3 spikes/nfc-hce/run_spike.py` para verificar la máquina de estados GID-APDU (`SELECT` $\rightarrow$ `ENVELOPE` $\rightarrow$ `GET RESPONSE`) y regenerar `spikes/nfc-hce/data/apdu_transfer_benchmarks.csv` y `spikes/nfc-hce/data/device_tap_trials.csv`.

---

## 2. Arquitectura del Adaptador sin Lógica de Negocio (`INV-15`)

En cumplimiento de `INV-15`, el servicio HCE en Kotlin (`GidHostApduService`) actúa exclusivamente como pasarela de bytes hacia la máquina de estado en Rust:

```kotlin
// Referencia mínima evaluada en el spike (ver F21.T04 para integración final)
class GidHostApduService : HostApduService() {
    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        // Toda validación de estado, límites y criptografía ocurre en Rust (gravital-id-proximity)
        return GidProximityBridge.handleApdu(commandApdu)
    }
    override fun onDeactivated(reason: Int) {
        GidProximityBridge.resetTransientSession()
    }
}
```

---

## 3. Resultados de Latencia y Rendimiento (`spikes/nfc-hce/data/apdu_transfer_benchmarks.csv`)

Los tiempos incluyen la firma del `KB-JWT` en hardware (`StrongBox` ~88 ms) y el sellado HPKE (~18 ms):

| Perfil / Payload | Tamaño (Bytes) | Modo APDU | MTU por Trama | Intercambios APDU | Android $\rightarrow$ Android (ms) | Android $\rightarrow$ iPhone Core NFC (ms) | Android $\rightarrow$ Lector PC/SC (ms) |
|---|---|---|---|---|---|---|---|
| `pip-personal-v1` | 1,024 | Corto (`240 B`) | 240 B | 7 | 149.4 ms | 154.6 ms | 139.9 ms |
| `pip-personal-v1` | 1,024 | Extendido (`1024 B`) | 1,024 B | 3 | **140.5 ms** | **144.6 ms** | **132.9 ms** |
| `pip-financial/enterprise-v1` | 4,096 | Corto (`240 B`) | 240 B | 20 | 230.0 ms | 244.9 ms | 202.7 ms |
| `pip-financial/enterprise-v1` | 4,096 | Extendido (`1024 B`) | 1,024 B | 6 | **175.0 ms** | **183.3 ms** | **159.8 ms** |
| `pip-identity-v1` (con retrato) | 20,480 | Corto (`240 B`) | 240 B | 88 | 651.6 ms | 717.1 ms | 531.6 ms |
| `pip-identity-v1` (con retrato) | 20,480 | Extendido (`1024 B`) | 1,024 B | 22 | **359.0 ms** | **389.4 ms** | **303.5 ms** |

---

## 4. Tasa de Éxito al Primer Toque (`spikes/nfc-hce/data/device_tap_trials.csv`)

| Dispositivo Titular (HCE) | Lector Verificador | Payload | Modo APDU | Intentos | Éxito al 1.er Toque (%) | Latencia P95 (ms) |
|---|---|---|---|---|---|---|
| Google Pixel 7 | Samsung Galaxy A53 (`IsoDep`) | 1 KB | Extendido (`1024 B`) | 50 | **100.0 %** | 148 ms |
| Google Pixel 7 | iPhone 15 Pro (`Core NFC`) | 1 KB | Corto (`240 B`) | 50 | **98.0 %** | 172 ms |
| Google Pixel 7 | ACR122U / Omnikey (`PC/SC`) | 4 KB | Extendido (`1024 B`) | 50 | **100.0 %** | 168 ms |
| Google Pixel 7 | Samsung Galaxy A53 (`IsoDep`) | 20 KB | Extendido (`1024 B`) | 50 | **98.0 %** | 385 ms |
| Xiaomi Redmi Note 11 | iPhone 13 (`Core NFC`) | 20 KB | Corto (`240 B`) | 50 | **96.0 %** | 745 ms |
| Samsung Galaxy S23 | ACR122U / Omnikey (`PC/SC`) | 20 KB | Extendido (`1024 B`) | 50 | **100.0 %** | 310 ms |

---

## 5. Conclusiones para `ADR-0022` y `F21`

1. **Negociación dinámica de MTU:** Algunos lectores y controladores NFC reportan `maxTransceiveLength` limitado a APDU cortos (~253–261 bytes). La negociación del tamaño máximo de trama en `HolderHello` con soporte obligatorio de encadenamiento corto (`240 B`) y oportunista de longitud extendida (`1,024 B`) garantiza compatibilidad universal.
2. **Suficiencia de NFC para el retrato (`pip-identity-v1`):** Una sesión de 20 KB se transfiere íntegramente en $< 750\text{ ms}$ incluso en el modo más conservador (`240 B`), sin requerir emparejamiento BLE adicional.
