// Tipografía variable Google Sans Flex y fábrica de temas GxTheme (SPEC-PIP-UI-001 §§5, 11).
// Verifies: REQ-UI-001, REQ-UI-004

import 'package:flutter/material.dart';

import '../tokens/tokens.dart';
import 'semantic_colors.dart';

/// Familia tipográfica variable predeterminada de Gravital-Experience-UI.
const String kGxFontFamily = 'GoogleSansFlex';

/// Utilidades tipográficas de Gravital-Experience-UI (SPEC-PIP-UI-001 §5).
abstract final class GxTypography {
  /// Construye un [TextStyle] con ejes variables (`wght`, `opsz`, `GRAD`, `wdth`)
  /// y opción de cifras tabulares (`tnum`) para montos, códigos Damm, CPLC e IMEI.
  static TextStyle style({
    required double fontSize,
    required double lineHeight,
    required double weight,
    required double opticalSize,
    double letterSpacing = 0,
    double grade = 0,
    double width = 100,
    bool tabularFigures = false,
    Color? color,
  }) =>
      TextStyle(
        fontFamily: kGxFontFamily,
        fontSize: fontSize,
        height: lineHeight / fontSize,
        letterSpacing: letterSpacing,
        color: color,
        fontVariations: <FontVariation>[
          FontVariation('wght', weight),
          FontVariation('opsz', opticalSize),
          if (grade != 0) FontVariation('GRAD', grade),
          if (width != 100) FontVariation('wdth', width),
        ],
        fontFeatures: tabularFigures
            ? const <FontFeature>[FontFeature.tabularFigures()]
            : null,
      );

  /// Extiende cualquier [TextStyle] con cifras tabulares (`tnum`) para alineación
  /// vertical perfecta en códigos de sesión, montos e identificadores técnicos.
  static TextStyle tabular(TextStyle? base) => (base ?? const TextStyle())
      .copyWith(fontFeatures: const <FontFeature>[FontFeature.tabularFigures()]);

  /// Escala tipográfica Baseline de 15 roles (SPEC-PIP-UI-001 §5.2).
  static TextTheme buildBaselineTextTheme(Color textColor) => TextTheme(
        displayLarge: style(
          fontSize: 57,
          lineHeight: 64,
          letterSpacing: -0.25,
          weight: 400,
          opticalSize: 57,
          color: textColor,
        ),
        displayMedium: style(
          fontSize: 45,
          lineHeight: 52,
          weight: 400,
          opticalSize: 45,
          color: textColor,
        ),
        displaySmall: style(
          fontSize: 36,
          lineHeight: 44,
          weight: 400,
          opticalSize: 36,
          color: textColor,
        ),
        headlineLarge: style(
          fontSize: 32,
          lineHeight: 40,
          weight: 400,
          opticalSize: 32,
          color: textColor,
        ),
        headlineMedium: style(
          fontSize: 28,
          lineHeight: 36,
          weight: 400,
          opticalSize: 28,
          color: textColor,
        ),
        headlineSmall: style(
          fontSize: 24,
          lineHeight: 32,
          weight: 400,
          opticalSize: 24,
          color: textColor,
        ),
        titleLarge: style(
          fontSize: 22,
          lineHeight: 28,
          weight: 400,
          opticalSize: 22,
          color: textColor,
        ),
        titleMedium: style(
          fontSize: 16,
          lineHeight: 24,
          letterSpacing: 0.15,
          weight: 500,
          opticalSize: 16,
          color: textColor,
        ),
        titleSmall: style(
          fontSize: 14,
          lineHeight: 20,
          letterSpacing: 0.1,
          weight: 500,
          opticalSize: 14,
          color: textColor,
        ),
        bodyLarge: style(
          fontSize: 16,
          lineHeight: 24,
          letterSpacing: 0.5,
          weight: 400,
          opticalSize: 16,
          color: textColor,
        ),
        bodyMedium: style(
          fontSize: 14,
          lineHeight: 20,
          letterSpacing: 0.25,
          weight: 400,
          opticalSize: 14,
          color: textColor,
        ),
        bodySmall: style(
          fontSize: 12,
          lineHeight: 16,
          letterSpacing: 0.4,
          weight: 400,
          opticalSize: 12,
          color: textColor,
        ),
        labelLarge: style(
          fontSize: 14,
          lineHeight: 20,
          letterSpacing: 0.1,
          weight: 500,
          opticalSize: 14,
          color: textColor,
        ),
        labelMedium: style(
          fontSize: 12,
          lineHeight: 16,
          letterSpacing: 0.5,
          weight: 500,
          opticalSize: 12,
          color: textColor,
        ),
        labelSmall: style(
          fontSize: 11,
          lineHeight: 16,
          letterSpacing: 0.5,
          weight: 500,
          opticalSize: 11,
          color: textColor,
        ),
      );

  /// Escala tipográfica Emphasized de 15 roles (SPEC-PIP-UI-001 §5.2).
  static TextTheme buildEmphasizedTextTheme(Color textColor) => TextTheme(
        displayLarge: style(
          fontSize: 57,
          lineHeight: 64,
          letterSpacing: -0.25,
          weight: 600,
          opticalSize: 57,
          color: textColor,
        ),
        displayMedium: style(
          fontSize: 45,
          lineHeight: 52,
          weight: 600,
          opticalSize: 45,
          color: textColor,
        ),
        displaySmall: style(
          fontSize: 36,
          lineHeight: 44,
          weight: 600,
          opticalSize: 36,
          color: textColor,
        ),
        headlineLarge: style(
          fontSize: 32,
          lineHeight: 40,
          weight: 600,
          opticalSize: 32,
          color: textColor,
        ),
        headlineMedium: style(
          fontSize: 28,
          lineHeight: 36,
          weight: 600,
          opticalSize: 28,
          color: textColor,
        ),
        headlineSmall: style(
          fontSize: 24,
          lineHeight: 32,
          weight: 600,
          opticalSize: 24,
          color: textColor,
        ),
        titleLarge: style(
          fontSize: 22,
          lineHeight: 28,
          weight: 600,
          opticalSize: 22,
          color: textColor,
        ),
        titleMedium: style(
          fontSize: 16,
          lineHeight: 24,
          letterSpacing: 0.15,
          weight: 700,
          opticalSize: 16,
          color: textColor,
        ),
        titleSmall: style(
          fontSize: 14,
          lineHeight: 20,
          letterSpacing: 0.1,
          weight: 700,
          opticalSize: 14,
          color: textColor,
        ),
        bodyLarge: style(
          fontSize: 16,
          lineHeight: 24,
          letterSpacing: 0.5,
          weight: 500,
          opticalSize: 16,
          color: textColor,
        ),
        bodyMedium: style(
          fontSize: 14,
          lineHeight: 20,
          letterSpacing: 0.25,
          weight: 500,
          opticalSize: 14,
          color: textColor,
        ),
        bodySmall: style(
          fontSize: 12,
          lineHeight: 16,
          letterSpacing: 0.4,
          weight: 500,
          opticalSize: 12,
          color: textColor,
        ),
        labelLarge: style(
          fontSize: 14,
          lineHeight: 20,
          letterSpacing: 0.1,
          weight: 700,
          opticalSize: 14,
          color: textColor,
        ),
        labelMedium: style(
          fontSize: 12,
          lineHeight: 16,
          letterSpacing: 0.5,
          weight: 700,
          opticalSize: 12,
          color: textColor,
        ),
        labelSmall: style(
          fontSize: 11,
          lineHeight: 16,
          letterSpacing: 0.5,
          weight: 700,
          opticalSize: 11,
          color: textColor,
        ),
      );
}

/// Extensión de tema para la escala tipográfica Emphasized de M3 Expressive
/// (SPEC-PIP-UI-001 §5.2).
@immutable
class EmphasizedTextTheme extends ThemeExtension<EmphasizedTextTheme> {
  const EmphasizedTextTheme(this.textTheme);

  final TextTheme textTheme;

  @override
  EmphasizedTextTheme copyWith({TextTheme? textTheme}) =>
      EmphasizedTextTheme(textTheme ?? this.textTheme);

  @override
  EmphasizedTextTheme lerp(EmphasizedTextTheme? other, double t) {
    if (other is! EmphasizedTextTheme) return this;
    return EmphasizedTextTheme(TextTheme.lerp(textTheme, other.textTheme, t));
  }
}

/// Fábrica central de temas de Gravital-Experience-UI (SPEC-PIP-UI-001 §11).
abstract final class GxTheme {
  /// Semilla cromática oficial de Gravital ID (`#0B57D0`).
  static const Color brandSeed = kGxBrandSeed;

  /// Construye el [ThemeData] completo de Gravital-Experience-UI para un [ColorScheme].
  static ThemeData build(
    ColorScheme scheme, {
    double contrastLevel = 0.0,
  }) {
    final isDark = scheme.brightness == Brightness.dark;
    final semantic = isDark
        ? SemanticColors.dark(
            harmonizeTarget: scheme.primary,
            contrastLevel: contrastLevel,
          )
        : SemanticColors.light(
            harmonizeTarget: scheme.primary,
            contrastLevel: contrastLevel,
          );
    final baselineText = GxTypography.buildBaselineTextTheme(scheme.onSurface);
    final emphasizedText =
        GxTypography.buildEmphasizedTextTheme(scheme.onSurface);

    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: scheme.surface,
      textTheme: baselineText,
      extensions: <ThemeExtension<dynamic>>[
        semantic,
        EmphasizedTextTheme(emphasizedText),
      ],
      appBarTheme: AppBarTheme(
        backgroundColor: scheme.surface,
        foregroundColor: scheme.onSurface,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        titleTextStyle: emphasizedText.titleLarge,
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        color: scheme.surfaceContainerLow,
        margin: EdgeInsets.zero,
        shape: const RoundedRectangleBorder(borderRadius: GxShape.large),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(64, 48),
          padding: const EdgeInsets.symmetric(
            horizontal: GxSpace.xl,
            vertical: GxSpace.m,
          ),
          shape: const StadiumBorder(),
          textStyle: emphasizedText.labelLarge,
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(64, 48),
          padding: const EdgeInsets.symmetric(
            horizontal: GxSpace.xl,
            vertical: GxSpace.m,
          ),
          shape: const StadiumBorder(),
          side: BorderSide(color: scheme.outline),
          textStyle: baselineText.labelLarge,
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          minimumSize: const Size(48, 48),
          shape: const StadiumBorder(),
          textStyle: emphasizedText.labelLarge,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surfaceContainerHighest,
        border: const OutlineInputBorder(
          borderRadius: GxShape.medium,
          borderSide: BorderSide.none,
        ),
        enabledBorder: const OutlineInputBorder(
          borderRadius: GxShape.medium,
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: GxShape.medium,
          borderSide: BorderSide(color: scheme.primary, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: GxShape.medium,
          borderSide: BorderSide(color: scheme.error, width: 1.5),
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: GxSpace.l,
          vertical: GxSpace.l,
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: scheme.surfaceContainer,
        indicatorColor: scheme.secondaryContainer,
        indicatorShape: const StadiumBorder(),
        labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
        height: 76,
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: scheme.surfaceContainerLow,
        indicatorColor: scheme.secondaryContainer,
        indicatorShape: const StadiumBorder(),
        useIndicator: true,
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: scheme.surfaceContainerHigh,
        shape: const RoundedRectangleBorder(borderRadius: GxShape.extraLarge),
      ),
      bottomSheetTheme: BottomSheetThemeData(
        backgroundColor: scheme.surfaceContainerLow,
        shape: const RoundedRectangleBorder(borderRadius: GxShape.bottomSheet),
        showDragHandle: true,
      ),
      chipTheme: ChipThemeData(
        shape: const RoundedRectangleBorder(borderRadius: GxShape.small),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: scheme.inverseSurface,
        contentTextStyle: baselineText.bodyMedium?.copyWith(
          color: scheme.onInverseSurface,
        ),
        shape: const RoundedRectangleBorder(borderRadius: GxShape.medium),
      ),
      dividerTheme: DividerThemeData(
        color: scheme.outlineVariant,
        thickness: 1,
        space: 1,
      ),
    );
  }
}
