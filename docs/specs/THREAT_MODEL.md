# Especificación PIP: Modelo de Amenazas y Privacidad (STRIDE + LINDDUN)

> **Identificador normativo:** `SPEC-PIP-SEC-001`  
> **Versión:** `0.1.0-draft` (Fase F0 / Tarea `F0.T05`)  
> **Estado:** Normativo / En revisión  
> **Fecha:** 2026-10-10  
> **Trazabilidad:** REQ-SEC-001..011, REQ-PRIV-001..006, REQ-KEY-001..005, REQ-VER-001..009; ADR-0016, ADR-0017, ADR-0018, ADR-0020; P-02, P-03, P-05, P-07, P-08, P-09, P-10; INV-01, INV-02, INV-03, INV-05, INV-06, INV-16.

---

## 1. Activos del Sistema y Actores

### 1.1 Activos Críticos
1. **Claves Privadas de Emisor:** Material criptográfico asimétrico utilizado para emitir credenciales válidas.
2. **Claves Privadas de Titular (`KeyStore`):** Claves de vinculación ligadas a hardware utilizadas para firmar el KB-JWT de presentación.
3. **Secreto de Recuperación y Semilla Maestra:** Entropía de respaldo para re-vincular credenciales tras pérdida de dispositivo.
4. **Datos Personales y Claims:** Atributos de identidad del titular (PII).
5. **Raíz de Confianza (`TrustRoot`) y `TrustBundle`:** Documentos que definen qué emisores y claves son confiables.
6. **Listas de Estado (Token Status Lists):** Registro de validez, suspensión o revocación de credenciales.

### 1.2 Perfiles de Amenaza y Actores Maliciosos
* **Atacante de Red Activo (Man-in-the-Middle):** Puede interceptar, modificar, inyectar o retener tráfico en transportes en línea o relays.
* **Operador de Relay Malicioso:** Proveedor de infraestructura que distribuye sobres cifrados o listas de estado públicas.
* **Verificador Malicioso o Curioso:** Intenta correlacionar presentaciones entre servicios, provocar fuga de atributos no consentidos o retransmitir solicitudes a otras wallets.
* **Emisor Corrupto o Coaccionado:** Intenta presentar vistas divididas (*split-view*) de revocación o emitir credenciales no conformes.
* **Operadores de Bundle Comprometidos:** Subconjunto de operadores que intentan avanzar artificialmente la versión de bundle (*forced version advance*).
* **Malware en Dispositivo Host:** Software malicioso en el espacio de usuario que intenta leer memoria flash o interceptar llamadas del SDK.

---

## 2. Fronteras de Confianza (*Trust Boundaries*)

```text
┌────────────────────────────────────────────────────────────────────────┐
│ DISPOSITIVO HOST (Wallet / Verifier)                                   │
│                                                                        │
│   ┌───────────────────────────┐    Frontera FFI (Pánico capturado)     │
│   │ Aplicación Host / UI      ├────────────────────────────────────┐   │
│   └─────────────┬─────────────┘                                    │   │
│                 │ Inyección de Traits                              ▼   │
│   ┌─────────────┴─────────────┐         ┌───────────────────────────┐  │
│   │ Adaptadores L5 (Host)     │         │ Núcleo PIP (Rust L1-L4)   │  │
│   │ KeyStore, Clock, Storage  ├────────>│ Sans-I/O, no_std,         │  │
│   └─────────────┬─────────────┘         │ Cero PII en memoria       │  │
│                 │                       └───────────────────────────┘  │
│   Frontera Hardware de Seguridad                                       │
│   (Secure Enclave / StrongBox / Keystore)                              │
│   [ Claves Privadas Titular - NUNCA SALEN ]                            │
└─────────────────┬──────────────────────────────────────────────────────┘
                  │ Frontera de Transporte (QR Óptico / HPKE sobre Relay)
                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ RED EXTERNA & SERVICIOS (Relays, CDN, RPC Nodos, Blockchain)           │
│ [ No confiables - Solo transportan hashes y sobres cifrados ]          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Análisis STRIDE de Seguridad

| Categoría | Amenaza Específica | Impacto | Control Técnico y Mitigación | Requisito / ADR |
|---|---|---|---|---|
| **Spoofing** (Suplantación) | Falsificación de emisor mediante cabecera `jku`/`x5c` maliciosa. | Aceptación de credencial falsa. | Las claves del emisor **solo** se resuelven desde el `TrustBundle` activo. Cabeceras externas se ignoran incondicionalmente. | REQ-VER-004, INV-06 |
| **Spoofing** (Suplantación) | Presentación de credencial robada sin autorización del titular. | Suplantación de identidad. | Key Binding JWT (KB-JWT) obligatorio firmado por hardware del titular con `nonce` y `aud` efímeros vinculados al claim `cnf`. | REQ-PRES-002, INV-03 |
| **Tampering** (Alteración) | Modificación de claims en tránsito dentro de una presentación. | Corrupción de datos verificados. | Cada claim se valida contra su digest en el SD-JWT firmado. Modificaciones invalidan la firma. | REQ-CRED-001 |
| **Tampering** (Alteración) | Ataque de avance forzado de versión de bundle (*Forced Advance*). | Bloqueo permanente de bundles legítimos. | La TFA emite una nueva `TrustRoot` que incrementa `bundle_epoch`, reiniciando la numeración monotónica. | REQ-TRUST-009, ADR-0016 |
| **Repudiation** (Repudio) | Emisor niega haber revocado una credencial o muestra estados distintos. | Fraude de revocación (*Split-view*). | Compromisos de manifiesto de estado anclados en el contrato `StatusAnchor` en blockchain. | REQ-STAT-006, ADR-0017 |
| **Information Disclosure** | Extracción forense de credenciales desde almacenamiento de teléfono extraviado. | Fuga masiva de PII. | Cifrado de sobre (DEK/KEK) con `XChaCha20-Poly1305` y consultas mediante índices ciegos HMAC-SHA256 (sin PII en claro). | REQ-STOR-001, REQ-STOR-003 |
| **Information Disclosure** | Identificación de titulares en transferencias de red o ledger. | Pérdida de soberanía/privacidad. | Cero datos personales, ni hashes de baja entropía, en transacciones, logs o métricas. | INV-02, REQ-LEDG-001 |
| **Denial of Service** | Ataque de bomba de compresión (*Zip Bomb*) en Token Status Lists. | Caída por agotamiento de RAM. | Ratio de expansión DEFLATE restringido estrictamente a $\le 10:1$ y tope absoluto de 2 MiB. | REQ-STAT-003, PIP-E1007 |
| **Elevation of Privilege** | Compromiso de clave de respuesta a incidentes de emergencia. | Destrucción permanente del registro. | El `EMERGENCY_ROLE` **solo puede suspender** temporalmente; la suspensión caduca sola en 14 días (ADR-0018). | REQ-LEDG-004, ADR-0018 |

---

## 4. Análisis LINDDUN de Privacidad

| Categoría LINDDUN | Amenaza de Privacidad | Mitigación del Protocolo PIP |
|---|---|---|
| **Linkability** (Vinculabilidad) | Correlación de un titular entre múltiples verificadores o transacciones. | Claves de vinculación (`cnf`) generadas independientemente por credencial/lote; cero identificadores globales de titular; índices ciegos locales. |
| **Identifiability** (Identificabilidad) | Revelación innecesaria de atributos personales en verificaciones cotidianas. | Divulgación selectiva estricta con SD-JWT (RFC 9901); soporte para predicados precomputados (`age_over_18`). |
| **Non-repudiation** (No repudio lesivo) | Asociación permanente de una consulta de verificación al titular. | El titular no firma la solicitud; el KB-JWT está vinculado únicamente a la sesión efímera del verificador con `aud` y `nonce`. |
| **Detectability** (Detectabilidad) | Descubrimiento de qué credencial se revoca analizando descargas de estado. | Token Status Lists con tamaño mínimo ($\ge 131,072$ bits), índices aleatorios y descarga completa por CDN/relay (sin consultas por índice). |
| **Disclosure of Information** | Exfiltración de atributos a relays intermediarios en sincronización. | Sobres de operación cifrados extremo a extremo mediante HPKE (RFC 9180) direccionados por contenido. |
| **Unawareness** (Falta de consentimiento) | Divulgación accidental de atributos sin intervención del usuario. | Separación arquitectónica estricta en el SDK entre fase de preparación (`prepare_presentation`) y confirmación biométrica (`confirm_presentation`). |
| **Non-compliance** (Incumplimiento legal) | Retención indebida de atributos en verificadores locales. | Perfil personal prohíbe retención de claims; verificación offline devuelve estado sin almacenar copias de credenciales en disco. |
