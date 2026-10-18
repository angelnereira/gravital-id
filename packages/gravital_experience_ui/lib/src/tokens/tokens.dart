// Tokens fundacionales de Gravital-Experience-UI (SPEC-PIP-UI-001 §§6–8).
// Verifies: REQ-UI-001, REQ-UI-004

import 'package:flutter/widgets.dart';

/// Escala espacial con grilla base de 4 dp (SPEC-PIP-UI-001 §8.2).
abstract final class GxSpace {
  static const double xs = 4;
  static const double s = 8;
  static const double m = 12;
  static const double l = 16;
  static const double xl = 24;
  static const double xxl = 32;
  static const double xxxl = 48;
}

/// Escala de formas de 10 niveles de esquina Material 3 Expressive (SPEC-PIP-UI-001 §6).
abstract final class GxShape {
  static const BorderRadius none = BorderRadius.zero;
  static const BorderRadius extraSmall = BorderRadius.all(Radius.circular(4));
  static const BorderRadius small = BorderRadius.all(Radius.circular(8));
  static const BorderRadius medium = BorderRadius.all(Radius.circular(12));
  static const BorderRadius large = BorderRadius.all(Radius.circular(16));
  static const BorderRadius largeIncreased =
      BorderRadius.all(Radius.circular(20));
  static const BorderRadius extraLarge = BorderRadius.all(Radius.circular(28));
  static const BorderRadius extraLargeIncreased =
      BorderRadius.all(Radius.circular(32));
  static const BorderRadius extraExtraLarge =
      BorderRadius.all(Radius.circular(48));
  static const BorderRadius full = BorderRadius.all(Radius.circular(9999));

  static const BorderRadius topSheet = BorderRadius.vertical(
    bottom: Radius.circular(28),
  );
  static const BorderRadius bottomSheet = BorderRadius.vertical(
    top: Radius.circular(28),
  );
}

/// Física de resortes Material 3 Expressive (SPEC-PIP-UI-001 §7).
///
/// Las animaciones de Gravital-Experience-UI se gobiernan por masa, rigidez y
/// razón de amortiguamiento, no por duraciones arbitrarias.
abstract final class GxMotion {
  /// Resorte espacial rápido: switches, chips, pulsación de botones e iconos.
  static final SpringDescription fastSpatial =
      SpringDescription.withDampingRatio(
    mass: 1.0,
    stiffness: 1400.0,
    ratio: 0.9,
  );

  /// Resorte espacial por defecto: hojas modales, cajones, expansión de tarjetas.
  static final SpringDescription defaultSpatial =
      SpringDescription.withDampingRatio(
    mass: 1.0,
    stiffness: 700.0,
    ratio: 0.9,
  );

  /// Resorte espacial lento: transiciones de página completa.
  static final SpringDescription slowSpatial =
      SpringDescription.withDampingRatio(
    mass: 1.0,
    stiffness: 300.0,
    ratio: 0.9,
  );

  /// Resorte de efectos rápido: cambios de color, opacidad, ripple (sin rebote).
  static final SpringDescription fastEffects =
      SpringDescription.withDampingRatio(
    mass: 1.0,
    stiffness: 3800.0,
    ratio: 1.0,
  );

  /// Resorte de efectos por defecto: elevación y difuminados de superficie.
  static final SpringDescription defaultEffects =
      SpringDescription.withDampingRatio(
    mass: 1.0,
    stiffness: 1600.0,
    ratio: 1.0,
  );

  /// Resorte de efectos lento: cambios ambientales de fondo.
  static final SpringDescription slowEffects =
      SpringDescription.withDampingRatio(
    mass: 1.0,
    stiffness: 800.0,
    ratio: 1.0,
  );
}

/// Clases de tamaño de ventana adaptativas (SPEC-PIP-UI-001 §8.1, REQ-UI-004).
enum WindowClass {
  compact, // < 600 dp — teléfonos en vertical
  medium, // 600..840 dp — tablets pequeñas, plegables internos
  expanded, // 840..1200 dp — tablets en horizontal, escritorio pequeño
  large, // 1200..1600 dp — escritorio
  extraLarge; // >= 1600 dp — ultra-wide

  /// Determina la clase de ventana desde el ancho lógico actual de MediaQuery.
  static WindowClass of(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    return fromWidth(width);
  }

  /// Determina la clase de ventana a partir de un ancho en dp.
  static WindowClass fromWidth(double width) => switch (width) {
        < 600 => compact,
        < 840 => medium,
        < 1200 => expanded,
        < 1600 => large,
        _ => extraLarge,
      };

  /// Número de columnas de la retícula adaptativa.
  int get columns => switch (this) {
        compact => 4,
        medium => 8,
        expanded || large || extraLarge => 12,
      };

  /// Margen horizontal exterior de la ventana.
  double get margin => switch (this) {
        compact => 16,
        medium => 24,
        expanded || large || extraLarge => 32,
      };

  /// Separación (gutter) entre paneles o columnas.
  double get gutter => switch (this) {
        compact => 8,
        medium => 12,
        expanded || large || extraLarge => 16,
      };

  /// Indica si la ventana admite diseño maestro-detalle de 2 paneles.
  bool get isTwoPane =>
      this == expanded || this == large || this == extraLarge;
}
