# ADR-0011: Transporte offline (QR dos pasos, transcodificación binaria y multi-QR)

- **Estado:** Aceptado
- **Fecha:** 2026-10-11
- **Autores:** Antigravity (agente), a petición de Angel Nereira
- **Aprobado por:** Angel Nereira
- **Issue:** #16
- **Requisitos y principios afectados:** REQ-PRES-004; REQ-PRES-005; P-02; P-05
- **Fase:** F0 (F0.T07 / F0.T11)

---

## Contexto

El protocolo Gravital ID debe permitir la verificación presencial de credenciales en escenarios 100 % desconectados de Internet (p. ej. control de acceso físico, inspecciones de transporte, pagos de proximidad, zonas rurales).
Desafíos técnicos del transporte óptico mediante códigos QR:
1. **Límites de densidad del código QR:** Los formatos estándar de credenciales SD-JWT+KB en texto plano (Base64URL con múltiples firmas y divulgaciones) suelen ocupar entre 1.5 KB y 3.5 KB. Un código QR con más de 1200 a 1500 caracteres alfanuméricos resulta prácticamente ilegible para cámaras de teléfonos móviles de gama media y baja a distancias normales (30-40 cm) o bajo condiciones de baja iluminación.
2. **Mitigación de ataques de repetición (Replay):** Una presentación QR estática puede ser fotografiada y reproducida por un atacante. Se requiere un canal bidireccional interactivo que incluya un desafío fresco (*nonce*) generado por el verificador.
3. **Manejo de presentaciones grandes:** Cuando la presentación involucra múltiples credenciales o atributos complejos que exceden el tamaño máximo de un único código QR, se requiere un mecanismo estandarizado de fragmentación y reensamblado.

---

## Opciones consideradas

### Opción A — Presentación QR estática en texto plano JSON/JWT
- **Ventajas:** Simplicidad conceptual.
- **Inconvenientes:** Vulnerabilidad total a replay; códigos QR excesivamente densos e ilegibles en dispositivos reales.

### Opción B — Obligatoriedad de canales de radiofrecuencia (BLE / NFC)
- **Ventajas:** Alto ancho de banda.
- **Inconvenientes:** Requiere permisos intrusivos del sistema operativo; problemas notorios de interoperabilidad y emparejamiento entre diferentes marcas de Android e iOS; mayor latencia de negociación.

### Opción C — Flujo interactivo en dos pasos + Transcodificación binaria (CBOR + DEFLATE + Base45) + Secuencia Multi-QR (Recomendada)
- **Ventajas:**
  - **Flujo en dos pasos:**
    1. El verificador muestra un código QR compacto de solicitud con un `nonce` efímero, identificador del verificador y parámetros requeridos.
    2. El titular escanea la solicitud, selecciona los atributos a divulgar en su billetera, y genera el código QR de respuesta.
  - **Transcodificación binaria de alta compresión:**
    La presentación SD-JWT+KB se convierte a una representación binaria estructurada en CBOR, se comprime mediante el algoritmo DEFLATE (RFC 1951) y se codifica en **Base45** (RFC 9285), el estándar internacional optimizado para el conjunto de caracteres alfanuméricos de los códigos QR.
    Esta técnica reduce el tamaño del código QR en más de un **45 % a 55 %**, permitiendo que la gran mayoría de presentaciones quepan en un único QR legible de forma instantánea.
  - **Multi-QR determinista:** Si la presentación supera el umbral de 1200 caracteres Base45, se fragmenta en una secuencia indexada con cabecera fija (`GID01/P<idx>/<total>/<payload>`), permitiendo lectura mediante carrusel manual o animación a 3-5 fps.
- **Inconvenientes:** Requiere parseo CBOR/Base45 en las capas de transporte.

---

## Decisión

Se adopta la **Opción C**:
1. El canal de transporte offline predeterminado es el **flujo óptico QR interactivo en dos pasos** conforme a la especificación normativa `docs/specs/PROTOCOL.md §5`.
2. Las presentaciones en código QR se procesan obligatoriamente mediante el esquema de compresión **transcodificación binaria CBOR + DEFLATE + Base45**.
3. Se fija un **presupuesto máximo de 1200 caracteres Base45** para códigos QR individuales con corrección de errores nivel M (15 %).
4. Toda presentación que exceda 1200 caracteres activa automáticamente la fragmentación multi-QR indexada.
5. Los canales BLE / NFC se consideran extensiones secundarias para fases futuras (F11), preservando siempre el canal QR como base universal de interoperabilidad.

---

## Consecuencias

- La especificación normativa `docs/specs/PROTOCOL.md` documenta los esquemas binarios, gramática Base45 y máquinas de estados.
- El informe técnico `spikes/qr/REPORT.md` (F0.T07) documenta las mediciones de compresión y pruebas de lectura en dispositivos físicos reales.
