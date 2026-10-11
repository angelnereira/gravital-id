# Política de Seguridad y Divulgación Coordinada

> **Identificador:** `SECURITY.md`  
> **Estado:** Definitivo (Fase F0 / Tarea `F0.T04`)  
> **Trazabilidad:** REQ-SEC-010, REQ-SEC-011; `AGENTS.md §7.4`

El proyecto PIP / Gravital ID toma la seguridad de la identidad descentralizada y la criptografía como una prioridad absoluta. Agradecemos los esfuerzos de la comunidad de seguridad e investigadores independientes para identificar vulnerabilidades y colaborar en su resolución responsable.

---

## 1. Cómo Reportar una Vulnerabilidad

**NUNCA abras un issue público ni publiques detalles en foros o redes sociales antes de una resolución coordinada (REQ-SEC-011).**

### Canal Principal (Recomendado)
Utiliza la función de reporte privado de vulnerabilidades de GitHub:
👉 **[Report a vulnerability](https://github.com/angelnereira/gravital-id/security/advisories/new)**

### Información requerida en el reporte
Por favor incluye:
1. **Componente afectado:** Crate, biblioteca, contrato o especificación afectada, indicando commit exacto o versión.
2. **Severidad estimada:** Según la clasificación de la sección 3.
3. **Descripción técnica:** Mecanismo exacto del fallo o vector de ataque.
4. **Prueba de concepto (PoC):** Pasos de reproducción mínimos o script reproducible con datos sintéticos.
5. **Mitigación propuesta:** Si tienes una solución preliminar o parche.
6. **⚠️ Privacidad:** **No incluyas datos personales reales ni claves privadas reales.** Toda evidencia debe usar credenciales sintéticas.

---

## 2. Alcance (Scope)

### En Alcance
* Núcleo criptográfico y bibliotecas Rust (`crates/pip-crypto`, `crates/pip-core`, `crates/pip-verifier`, `crates/pip-trust`, `crates/pip-status`, `crates/pip-holder`, `crates/pip-storage`).
* Contratos inteligentes del registro y anclaje (`contracts/`).
* Bindings de plataforma (Android, iOS, WebAssembly, Flutter, Python, Go).
* Especificaciones normativas de protocolo (`docs/specs/`).
* Fugas de claves, omisión de comprobación de firmas, bypass de anti-rollback o fallos en modo fail-closed.

### Fuera de Alcance
* Denegación de servicio (DoS) volumétrica contra nodos RPC o endpoints públicos de demostración.
* Vulnerabilidades que requieran acceso físico destructivo al hardware (p. ej., micro-soldadura, decapping de silicio de Secure Enclave/StrongBox).
* Ingeniería social, phishing o ataques físicos contra los mantenedores u operadores del ecosistema.
* Versiones obsoletas no soportadas o ramas experimentales no fusionadas.

---

## 3. Clasificación de Severidad y Tiempos de Respuesta

Nos comprometemos con los siguientes acuerdos de nivel de servicio (SLA) para la respuesta de seguridad:

| Severidad | Criterio | Acuse de recibo | Evaluación inicial | Corrección y publicación |
|---|---|---|---|---|
| **S0 — Crítica** | Aceptación de credenciales inválidas/forjadas, compromiso de claves maestras, fuga de datos personales o fallo del modelo *fail-closed*. | $\le 24$ horas | $\le 48$ horas | $\le 7$ días calendario (con hotfix prioritario) |
| **S1 — Alta** | Rechazo sistemático de credenciales válidas, bypass de revocación, DoS local no recuperable mediante entrada maliciosa o corrupción de almacenamiento. | $\le 48$ horas | $\le 5$ días hábiles | $\le 30$ días calendario |
| **S2 — Media** | Flujo secundario afectado, violación de límites de recursos sin caída del proceso, debilidad teórica en algoritmo auxiliar. | $\le 72$ horas | $\le 10$ días hábiles | Siguiente ciclo menor de release |
| **S3 — Baja** | Problemas cosméticos, mensajes de error informativos no redactados (sin secretos), mejoras en defensas en profundidad. | $\le 5$ días hábiles | $\le 15$ días hábiles | Backlog planificado |

---

## 4. Política de Protección al Investigador (*Safe Harbor*)

Apoyamos la investigación de seguridad ética y de buena fe. Si cumples con las siguientes pautas, **no emprenderemos acciones legales ni solicitaremos la intervención de autoridades policiales** contra ti:

1. **Buena fe:** Tu objetivo es únicamente mejorar la seguridad y la privacidad de los usuarios del protocolo.
2. **No destructivo:** No destruyas, alteres ni retengas datos personales de terceros ni degrades la disponibilidad de entornos activos de producción.
3. **Confidencialidad:** Mantienes la confidencialidad de la vulnerabilidad hasta que se haya publicado un parche oficial o haya vencido el plazo mutuamente acordado para la divulgación coordinada.
4. **Legalidad:** No violas leyes aplicables fuera del ámbito estricto de las pruebas de seguridad autorizadas sobre el código fuente público.

---

## 5. Reglas Internas para Desarrolladores y Agentes de IA

Cualquier colaborador o agente de código que trabaje en el repositorio debe cumplir estrictamente [`AGENTS.md §7.4`](AGENTS.md#74-vulnerabilidades-de-seguridad):
* Todo hallazgo o vulnerabilidad sospechosa detectada internamente (por ejemplo, mediante fuzzing o auditoría de dependencias) se trata en un **GitHub Security Advisory privado**.
* Las pruebas de regresión asociadas y el código corrector se desarrollan en la rama privada del advisory.
* Jamás se realiza push de correcciones de seguridad con mensajes que revelen la vulnerabilidad antes de la publicación coordinada del advisory.
