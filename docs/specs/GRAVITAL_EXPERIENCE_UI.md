# Especificación PIP: Sistema de Diseño de Interfaces Flutter — Gravital-Experience-UI (M3 Expressive)

> **Identificador normativo:** `SPEC-PIP-UI-001`  
> **Nombre del estilo de diseño:** **Gravital-Experience-UI** (`gravital_experience_ui`)  
> **Versión:** `1.0.0`  
> **Estado:** Normativo / Obligatorio para todas las apps y frontends del ecosistema  
> **Fecha:** 2026-10-18 · **Autor base:** @Angel Nereira  
> **Trazabilidad:** REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004, REQ-PRES-003, REQ-PORT-001; ADR-0030; `AGENTS.md §9.5`.

---

## 1. Propósito, alcance y principios

Toda aplicación Flutter e interfaz gráfica que se construya en el ecosistema Gravital —billetera de identidad (`reference-wallet`), verificador (`reference-verifier`), consola de emisor (`issuer-console`), portales de inquilinos, finanzas, POS, inventario, facturación, movilidad, mensajería, logística, pagos, chat o landing— usará un único sistema de diseño propio denominado **Gravital-Experience-UI**, fundamentado en la física, color tonal y geometría de Material 3 Expressive (M3E). Este plano define sus tokens, componentes, patrones de UX y reglas de revisión, y se implementa como un paquete Dart compartido (`gravital_experience_ui`) que todas las apps importan.

**Qué se implementa en Gravital-Experience-UI:** el lenguaje de diseño de color tonal HCT, escala de formas de 10 tokens, tipografía variable (`Google Sans Flex`), movimiento físico por resortes sin recorte, contención tonal sin abuso de sombras, navegación adaptativa por clases de ventana y componentes de dominio tanto de identidad portable (credenciales, consentimiento selectivo, proximidad NFC/QR, código de sesión de 10 dígitos, ranuras de dispositivo, inquilinos y roles) como transaccionales (dinero, comercio, estado, mapas, personas).

**Qué no se replica:** activos de marca de terceros (logos externos, iconos propietarios de apps de terceros, fondos de pantalla con copyright), fuentes cuya licencia no lo permita, ni la UI privativa del sistema operativo (barra de estado, ajustes rápidos, launcher). Una app no controla la UI del sistema; solo se integra limpiamente con ella (edge-to-edge, color dinámico donde aplique, retroceso predictivo).

### Principios rectores de Gravital-Experience-UI

1. **Una sola fuente de verdad (`REQ-UI-001`).** Ningún widget usa colores, radios, espacios o duraciones literales; todo sale de tokens del paquete compartido `gravital_experience_ui` (`GxSpace`, `GxShape`, `GxMotion`, `GxTheme`, `SemanticColors`).
2. **Material primero, extensión después.** Se usan los componentes Material 3 y se extienden con `ThemeExtension`; solo se construye a mano o mediante adaptadores lo que el sistema expresivo define y el SDK base aún no trae.
3. **Color con intención.** Color dinámico (del fondo de pantalla) solo en apps personales de comunicación; **semilla de marca fija (`brandSeed`) en apps de identidad, seguridad, credenciales, banca, pagos y POS**, para garantizar confianza, reconocimiento institucional e invariabilidad visual en soporte y auditoría.
4. **Jerarquía por tono, no por sombra.** Las superficies se distinguen por nivel tonal (`surfaceContainerLowest` … `surfaceContainerHighest`); la sombra se reserva para elementos que flotan sobre contenido en movimiento (FAB, toolbar flotante, menús).
5. **Movimiento físico y con propósito (`REQ-UI-002`).** Transiciones con resortes (`SpringDescription.withDampingRatio`) que explican el cambio de estado; nunca decoración gratuita. Se respeta siempre «reducir movimiento» del sistema (`MediaQuery.disableAnimationsOf`).
6. **Adaptativo desde el día uno (`REQ-UI-003`).** El mismo código se acomoda a teléfono, plegable, tablet, terminal quiosco, escritorio y web por clases de tamaño de ventana (`WindowClass`: `compact`, `medium`, `expanded`, `large`, `extraLarge`), nunca bifurcando por tipo de dispositivo.
7. **Accesible por defecto (`REQ-UI-004`).** Contraste WCAG 2.2 AA (niveles estándar `0.0`, medio `0.5` y alto `1.0`), objetivos táctiles mínimos de 48 × 48 dp (56 dp en acciones críticas de terminal/POS/verificación), texto escalable al 200 % sin cortes y etiquetas semánticas para lectores de pantalla.
8. **Identidad igual, convenciones locales.** Color, forma, tipografía y componentes de `Gravital-Experience-UI` son idénticos en todas las plataformas; gestos, retroceso predictivo y física de scroll respetan la plataforma donde corre la app.

---

## 2. Estado del ecosistema y decisiones técnicas (octubre 2026)

| Pieza | Referencia | Decisión para Gravital-Experience-UI |
| --- | --- | --- |
| Lenguaje expresivo M3E | Material 3 Expressive (Android 16/17) | Base geométrica, tonal y de movimiento de `Gravital-Experience-UI` |
| Desenfoque (blur) | Reservado en Android 17 a SystemUI | Opcional y estrictamente restringido a toolbar flotante y fondo de hoja modal (sección 6.4); desactivado en web, gama baja y alto contraste |
| Flutter / Dart | Flutter 3.x / Dart 3.x (soporte de workspace y paquete compartido) | El paquete `gravital_experience_ui` encapsula las dependencias de UI y expone una única fachada pública |
| Paquete de UI base | `material_ui` (o puente compatible sobre Material 3 en entornos donde el SDK aún resida en `flutter/material.dart` dentro del adaptador interno) | Las apps **solo** importan `package:gravital_experience_ui/gravital_experience_ui.dart` |
| Color dinámico | `dynamic_color` + `material_color_utilities` (espacio HCT) | Semilla fija `brandSeed` para Gravital ID (confianza e identidad); armonización de colores semánticos |
| Componentes expresivos | Split button, button group conectado, toolbar flotante, indicador de carga de formas, morphing | Expuestos mediante adaptadores `Gx*` en `lib/src/adapters/` |
| Tipografía oficial | **Google Sans Flex** (SIL OFL 1.1, 6 ejes variables: `wght`, `wdth`, `opsz`, `slnt`, `ROND`, `GRAD`) | Fuente oficial del sistema con respaldo en `Roboto Flex` y fuente del sistema |

**Regla de actualización:** cada trimestre, al actualizar Flutter, se revisan los componentes expresivos; cualquier mejora entra en los adaptadores internos de `gravital_experience_ui` sin romper la API pública de las aplicaciones.

---

## 3. Arquitectura del sistema de diseño `Gravital-Experience-UI`

El sistema se estructura en **cinco capas estrictas**:
1. **Capa 1 — Tokens (`tokens/`):** `tokens.json` (formato W3C Design Tokens), `GxSpace`, `GxShape`, `GxMotion`, `WindowClass`.
2. **Capa 2 — Tema (`theme/`):** `GxTheme`, `SemanticColors`, `EmphasizedTextTheme`.
3. **Capa 3 — Adaptadores y Componentes (`adapters/`, `components/`):** envolturas expresivas (`GxSplitButton`, `GxButtonGroup`, `GxFloatingToolbar`, `GxLoadingIndicator`) y componentes de dominio de identidad y transacciones.
4. **Capa 4 — Patrones (`patterns/`):** `GxAdaptiveScaffold`, `GxEmptyState`, `GxErrorState`, `GxOfflineBanner`, `GxSkeletonList`.
5. **Capa 5 — Aplicaciones (`app/` y `apps/*`):** `GxApp` (arranque edge-to-edge, temas claro/oscuro/alto contraste, localización) y las aplicaciones consumidoras (`apps/reference-wallet`).

### Estructura interna del paquete compartido

```text
packages/gravital_experience_ui/lib/
├── gravital_experience_ui.dart   # Único punto de import permitido para las apps
└── src/
    ├── tokens/                   # tokens.dart, GxSpace, GxShape, GxMotion, WindowClass
    ├── theme/                    # GxTheme, SemanticColors, EmphasizedTextTheme
    ├── components/               # Identidad (CredentialCard, ConsentSheet, DeviceSlotCard,
    │                             # TenantRoleCard, SessionCodePad) + Dominio (MoneyText, StatusChip…)
    ├── adapters/                 # Envolturas expresivas M3E (GxSplitButton, GxButtonGroup, GxFloatingToolbar…)
    ├── patterns/                 # GxAdaptiveScaffold, GxEmptyState, GxErrorState, GxOfflineBanner
    └── app/                      # GxApp: arranque edge-to-edge, contraste, color dinámico/fijo
```

---

## 4. Color

Cada aplicación declara un único color semilla de marca (`brandSeed`; en Gravital ID: `#0B57D0` / Azul Gravital Soberano); de él se genera todo el esquema claro, oscuro y de alto contraste en el espacio perceptual **HCT (Hue-Chroma-Tone)**.

### 4.1 Modelo

- El esquema sale de seis paletas tonales (primaria, secundaria, terciaria, neutral, neutral variante, error), cada una con tonos de 0 (negro) a 100 (blanco).
- Los widgets **nunca** usan colores hexadecimales literales ni tonos crudos: usan **roles** (`primary`, `onSurface`, `surfaceContainerHigh`…).
- Generación: `ColorScheme.fromSeed(seedColor:, brightness:, dynamicSchemeVariant:, contrastLevel:)`.

### 4.2 Política de fuente de color por tipo de app

| Tipo de app | Fuente del color | Variante | Motivo |
| --- | --- | --- | --- |
| **Identidad portable (Gravital ID Wallet, Verificador, Consola de Emisor)** | **Semilla de marca fija (`#0B57D0`)** | `tonalSpot` o `fidelity` | **Confianza institucional y seguridad:** el usuario y el verificador deben reconocer de inmediato los estados de validez y consentimiento |
| Finanzas, banca, pagos, facturación | Semilla de marca fija | `tonalSpot` o `fidelity` | Confianza y reconocimiento; capturas de soporte iguales para todos |
| POS (de cara al cliente) | Semilla de marca fija | `tonalSpot` | La pantalla la ven terceros; debe verse igual en cada caja |
| Inventario, logística, panel de conductor | Semilla de marca fija + alto contraste opcional | `tonalSpot` | Uso operativo en exteriores o almacenes |
| Mensajería, chat, llamadas | Dinámico en Android 12+; marca como respaldo | `tonalSpot` | App personal de uso diario |
| Movilidad (pasajero) | Semilla de marca fija | `tonalSpot` | El mapa ya tiene mucho color; la marca guía las acciones |
| Landing pages | Semilla de marca fija | `expressive` en bloque principal | Impacto visual sin perder identidad |

### 4.3 Uso obligatorio de roles

| Rol | Uso obligatorio |
| --- | --- |
| `primary` / `onPrimary` | **Una sola acción principal por pantalla** (botón filled o FAB principal) |
| `primaryContainer` / `onPrimaryContainer` | Estado seleccionado, FAB, chips activos, credencial destacada |
| `secondaryContainer` / `onSecondaryContainer` | Botones tonales, filtros, acciones secundarias, indicador de navegación |
| `tertiary` / `tertiaryContainer` | Acento de contraste: insignias de verificación oficial (p. ej. Tribunal Electoral), alertas informativas |
| `error` / `errorContainer` | Solo errores, revocaciones (`Invalid`) y acciones destructivas |
| `surface` → `surfaceContainerLowest…Highest` | Fondos y jerarquía tonal de superficies (sección 6.3) |
| `onSurface` / `onSurfaceVariant` | Texto e iconos principales / secundarios |
| `outline` / `outlineVariant` | Bordes de campos y botones outlined / separadores sutiles |
| `inverseSurface` / `onInverseSurface` | Snackbars y tooltips |

### 4.4 Colores semánticos extendidos (`SemanticColors`)

Agregados como `ThemeExtension<SemanticColors>`, cada uno con cuatro roles (`color`, `onColor`, `container`, `onContainer`) armonizados con la semilla primaria:
- **Roles generales y financieros:** `success` (verde `#1E8E3E`), `warning` (ámbar `#F9AB00`), `info` (azul `#1A73E8`), `moneyIn` (`#188038`), `moneyOut` (`#C5221F`), `pending` (`#8E6B00`).
- **Mapeo a los 4 estados de verificación de Gravital ID (`INV-04`):**
  - `Valid` $\to$ `SemanticColors.success` + icono `verified_user` + etiqueta explícita.
  - `ValidWithStaleStatus` $\to$ `SemanticColors.warning` + icono `schedule` + antigüedad del snapshot.
  - `Unverifiable` $\to$ `SemanticColors.pending` / `info` + icono `help_outline` + motivo de dato faltante.
  - `Invalid` $\to$ `ColorScheme.error` + icono `gpp_bad` + código de evidencia.
- **Regla de accesibilidad cromática:** el color **nunca** es el único indicador. Todo estado o monto lleva icono y/o signo explícito (`+`, `−`, etiqueta de estado).

### 4.5 Contraste y accesibilidad de color

- Texto normal $\ge 4.5:1$, texto grande y controles $\ge 3:1$ (WCAG 2.2 AA).
- Tres niveles de contraste soportados en tiempo real: `0.0` (estándar), `0.5` (medio) y `1.0` (alto), conmutable desde Ajustes de la app y activado automáticamente si `MediaQuery.highContrastOf(context)` es verdadero.

---

## 5. Tipografía

Todas las aplicaciones usan **Google Sans Flex** (con respaldo en Roboto Flex y fuente del sistema), con los 15 estilos de la escala Material 3 más sus 15 variantes enfatizadas en `EmphasizedTextTheme`.

### 5.1 Escala base y enfatizada

| Estilo | Tamaño / interlineado (sp) | Peso base | Peso enfatizado | Uso en Gravital ID y ecosistema |
| --- | --- | --- | --- | --- |
| `displayLarge` | 57 / 64 | 400 | 500 | Código de sesión de 10 dígitos (`SessionCode`), saldo principal |
| `displayMedium` | 45 / 52 | 400 | 500 | Hero de pantalla de toque NFC / presentación activa |
| `displaySmall` | 36 / 44 | 400 | 500 | Contadores, totales destacados |
| `headlineLarge` | 32 / 40 | 400 | 500 | Título de pantalla principal en móvil/tablet |
| `headlineMedium` | 28 / 36 | 400 | 500 | Título de sección en paneles expandidos |
| `headlineSmall` | 24 / 32 | 400 | 500 | Título de diálogo o de hoja de consentimiento |
| `titleLarge` | 22 / 28 | 400 | 500 | Barra superior, nombre del titular en credencial |
| `titleMedium` | 16 / 24 | 500 | 700 | Título de credencial, nombre de inquilino/app, encabezado de grupo |
| `titleSmall` | 14 / 20 | 500 | 700 | Subtítulos densos, secciones de formulario |
| `bodyLarge` | 16 / 24 | 400 | 500 | Valor de atributo de credencial, texto principal |
| `bodyMedium` | 14 / 20 | 400 | 500 | Texto secundario, descripciones de permisos |
| `bodySmall` | 12 / 16 | 400 | 500 | Notas técnicas, huellas `Kid`, marcas de tiempo |
| `labelLarge` | 14 / 20 | 500 | 700 | Botones de acción |
| `labelMedium` | 12 / 16 | 500 | 700 | Chips de estado, pestañas, badges de rol |
| `labelSmall` | 11 / 16 | 500 | 700 | Insignias de `vct`, nivel de seguridad (`Nivel 0`/`Nivel 1`) |

### 5.2 Reglas tipográficas

1. **Cifras tabulares (`FontFeature.tabularFigures()`)** obligatorias en códigos `SessionCode` (`XXX-XXX-XXXX`), números de cédula, cronómetros TTL, versiones de bundle, montos y tablas.
2. **Escalado al 200 %:** prohibido fijar alturas rígidas (`height:` fijo) en tarjetas de texto; las filas deben fluir verticalmente sin truncar datos críticos.
3. **Ancho máximo de lectura:** 720 dp en pantallas anchas (`expanded`, `large`, `extraLarge`).

---

## 6. Forma y superficies

### 6.1 Escala de esquinas (`GxShape`)

| Token | Radio (dp) | Componentes |
| --- | --- | --- |
| `none` | 0 | Imágenes a sangre, mapas a pantalla completa |
| `extraSmall` | 4 | Campos de texto filled (esquinas superiores), tooltips |
| `small` | 8 | Chips de atributo, insignias de rol |
| `medium` | 12 | Tarjetas estándar, elementos de lista agrupada |
| `large` | 16 | FAB estándar, hojas laterales, contenedores de sección |
| `largeIncreased` | 20 | **Tarjetas de Credencial Gravital (`GxCredentialCard`)**, tarjetas destacadas |
| `extraLarge` | 28 | Diálogos, hojas inferiores de consentimiento (arriba), contenedor de QR |
| `extraLargeIncreased` | 32 | Paneles hero de NFC/Proximidad, toolbar flotante |
| `extraExtraLarge` | 48 | Contenedores de ilustración y estado vacío/éxito |
| `full` | 999 (50 %) | Botones de acción, barra de búsqueda, indicador de navegación, avatares |

### 6.2 Jerarquía tonal de superficies

| Superficie | Rol de color | Uso |
| --- | --- | --- |
| Lienzo | `surface` | Fondo borde a borde de cada pantalla |
| Contenedor bajo | `surfaceContainerLow` | Tarjetas de credenciales secas, hoja inferior |
| Contenedor medio | `surfaceContainer` | Barra de navegación inferior, `NavigationRail`, menús |
| Contenedor alto | `surfaceContainerHigh` | Diálogos, barra de búsqueda, toolbar flotante, tarjeta seleccionada |
| Contenedor máximo | `surfaceContainerHighest` | Campos de entrada filled, bloques de énfasis y código numérico |
| Contenedor mínimo | `surfaceContainerLowest` | Fondo de panel secundario en pantallas `expanded+` |

---

## 7. Movimiento y háptica (`GxMotion`)

### 7.1 Tokens de resorte

| Esquema | Token | Amortiguamiento ($\zeta$) | Rigidez ($k$) | Uso |
| --- | --- | --- | --- | --- |
| Expressive | `expressiveFastSpatial` | 0.6 | 800 | Presión táctil de tarjeta o botón (`ScaleTransition` con controlador `unbounded`), cambio de forma de toggle |
| Expressive | `expressiveDefaultSpatial` | 0.8 | 380 | Expandir credencial, abrir hoja de consentimiento DCQL, desplegar menú FAB |
| Expressive | `expressiveSlowSpatial` | 0.8 | 200 | Confirmación de presentación verificada (`Valid`), toque NFC completado |
| Standard | `standardFastSpatial` | 0.9 | 1400 | Chips de selección de claims, switches de divulgación selectiva |
| Standard | `standardDefaultSpatial` | 0.9 | 700 | Transición entre paneles de navegación, listas |
| Standard | `standardSlowSpatial` | 0.9 | 300 | Cambios de layout adaptativo |
| Efectos | `fastEffects` / `defaultEffects` / `slowEffects` | 1.0 | 3800 / 1600 / 800 | Cambios de opacidad y color sin rebote |

### 7.2 Háptica sincronizada

- Selección de atributo a divulgar (`_sd`) o cambio de pestaña $\to$ `HapticFeedback.selectionClick()`.
- Preparar presentación / abrir QR o NFC $\to$ `HapticFeedback.lightImpact()`.
- Presentación firmada o verificación `Valid` $\to$ `HapticFeedback.mediumImpact()`.
- Rechazo (`Invalid`), PIN bloqueado o duplicidad detectada $\to$ `HapticFeedback.heavyImpact()`.

---

## 8. Espaciado, layout y adaptabilidad (`GxSpace` y `WindowClass`)

- **Retícula de 4 dp (`GxSpace`):** `xs = 4`, `s = 8`, `m = 12`, `l = 16`, `xl = 24`, `xxl = 32`, `xxxl = 48`, `huge = 64`.
- **Clases de ventana (`WindowClass.of(context)`):**
  - `compact` ($< 600\text{ dp}$): `NavigationBar` inferior + 1 panel (con toolbar flotante contextual cuando aplique).
  - `medium` ($600\text{–}839\text{ dp}$): `NavigationRail` + 1 o 2 paneles.
  - `expanded` ($840\text{–}1199\text{ dp}$): `NavigationRail` + layout **Lista + Detalle** (2 paneles simultáneos con separación de `24 dp`).
  - `large` ($1200\text{–}1599\text{ dp}$) y `extraLarge` ($\ge 1600\text{ dp}$): `NavigationRail` expandido + hasta 3 paneles (Lista + Detalle + Panel de inspección técnica/evidencia).

---

## 9. Catálogo de Componentes de Dominio (`gravital_experience_ui`)

Además de los componentes transaccionales (`MoneyText`, `StatusChip`, `GxSplitButton`, `GxButtonGroup`, `GxFloatingToolbar`), el paquete compartido incluye los componentes normativos de identidad portable de Gravital ID:

1. **`GxCredentialCard`**: Representación visual de una credencial `SD-JWT VC` (`pip-identity-v1`, `pip-personal-v1`, `pip-financial-v1`, `pip-enterprise-v1`, `pip-tenant-role-v1`) con distinción clara entre **Oficial (Tribunal Electoral)** y **Derivada (`REQ-IDDOC-001`)**, retrato facial en memoria, estado de lote y animación física al tacto.
2. **`GxDisclosureConsentSheet`**: Hoja modal de consentimiento en dos pasos (`REQ-PRES-003`) que muestra el verificador autenticado, el nivel de acceso (`Nivel 0` sin PIN vs `Nivel 1` con biometría/PIN) y switches interactivos para cada atributo de divulgación selectiva (`_sd`) más predicados (`age_over_18`).
3. **`GxPresentationTransportView`**: Vista unificada de presentación por **QR (Base45 + DEFLATE / Multi-QR)**, **Toque NFC (`GID-APDU` + HPKE)** y **Código Numérico Efímero de 10 dígitos con control Damm (`SessionCode`)**.
4. **`GxTenantAccessCard`**: Tarjeta de inquilino/aplicación conectada que muestra el `TenantSubjectId` consistente del usuario, los datos que el usuario decidió compartir con esa app y las credenciales de **Roles y Permisos** activos en dicho sistema.
5. **`GxDeviceSlotCard`**: Visualizador y gestor de la política de **Ranura Única por Clase de Dispositivo (`REQ-DEVSLOT-001`)**:
   - Ranura 1: **Teléfono Móvil** (StrongBox/TEE o Secure Enclave + Key/IMEI Attestation).
   - Ranura 2: **Tarjeta Física Gravital tipo Visa** (Java Card 3.0.5+ con serial de silicio CPLC y PIN).
   - Ranura 3: **Otro Dispositivo Compatible** (Llave de seguridad / Terminal corporativo).
6. **`GxVerificationResultCard`**: Tarjeta que renderiza los **4 estados normativos (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`, `INV-04`)** con el desglose de las 11 comprobaciones del pipeline y la frescura del snapshot.

---

## 10. Checklist de gobernanza obligatorio (`AGENTS.md §9.5`)

Ningún PR que toque `packages/gravital_experience_ui/` o `apps/` puede fusionarse sin cumplir:
- [ ] Cero colores, radios, espacios o duraciones literales fuera de `tokens.dart` y `semantic_colors.dart`.
- [ ] Import exclusivo de `package:gravital_experience_ui/gravital_experience_ui.dart` en las vistas de la aplicación (prohibido importar directamente paquetes de terceros de UI en las pantallas).
- [ ] Un solo botón `FilledButton` (acción primaria) visible por pantalla.
- [ ] Soporte adaptativo verificado en `compact` ($< 600\text{ dp}$) y `expanded` ($\ge 840\text{ dp}$), vertical y horizontal.
- [ ] Escalado de texto al 200 % sin desbordamientos (`overflow`).
- [ ] Temas claro, oscuro y alto contraste (`contrastLevel: 1.0`) operativos.
- [ ] Separación estricta de preparación y consentimiento (`REQ-PRES-003`) antes de firmar cualquier presentación.
- [ ] `flutter analyze` y `flutter test` (incluyendo pruebas de accesibilidad y widgets) 100 % en verde.
