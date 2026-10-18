// Arquitectura de color tonal HCT y colores semánticos de dominio (SPEC-PIP-UI-001 §4).
// Verifies: REQ-UI-001, REQ-UI-002, INV-04

import 'package:flutter/material.dart';

/// Color semilla de marca canónico de Gravital ID (`#0B57D0`).
const Color kGxBrandSeed = Color(0xFF0B57D0);

/// Estados canónicos del resultado de verificación del protocolo (`INV-04`, `REQ-UI-002`).
///
/// Nunca se colapsa a un booleano. Cada estado se asocia a un par tonal semántico,
/// un icono inequívoco y una etiqueta textual explícita.
enum GxVerificationState {
  /// Firma, emisor, vigencia y estado fresco verificados (`Valid`).
  valid,

  /// Firma y emisor válidos; lista de estado dentro de la ventana de gracia offline (`ValidWithStaleStatus`).
  validWithStaleStatus,

  /// Sin evidencia suficiente local (p. ej. falta el emisor o el estado caducó) (`Unverifiable`).
  unverifiable,

  /// Fallo criptográfico, credencial revocada/expirada o nonce repetido (`Invalid`).
  invalid;

  /// Etiqueta corta legible por humanos (nunca depende solo del color).
  String get label => switch (this) {
        valid => 'VÁLIDA',
        validWithStaleStatus => 'VÁLIDA (ESTADO EN CACHÉ)',
        unverifiable => 'NO VERIFICABLE OFFLINE',
        invalid => 'INVÁLIDA / RECHAZADA',
      };

  /// Código canónico de protocolo para auditoría visual.
  String get protocolStateName => switch (this) {
        valid => 'VerificationResult::Valid',
        validWithStaleStatus => 'VerificationResult::ValidWithStaleStatus',
        unverifiable => 'VerificationResult::Unverifiable',
        invalid => 'VerificationResult::Invalid',
      };

  /// Icono semántico asociado (WCAG 1.4.1: forma distinta por estado).
  IconData get icon => switch (this) {
        valid => Icons.verified_rounded,
        validWithStaleStatus => Icons.history_toggle_off_rounded,
        unverifiable => Icons.help_outline_rounded,
        invalid => Icons.gpp_bad_rounded,
      };
}

/// Par tonal semántico armonizado hacia el tono primario del esquema activo.
@immutable
class SemanticTone {
  const SemanticTone({
    required this.color,
    required this.onColor,
    required this.container,
    required this.onContainer,
  });

  final Color color;
  final Color onColor;
  final Color container;
  final Color onContainer;

  /// Construye un par tonal semántico armonizando la semilla hacia [harmonizeTarget].
  factory SemanticTone.fromSeed(
    Color seed,
    Brightness brightness, {
    Color harmonizeTarget = kGxBrandSeed,
    double contrastLevel = 0.0,
  }) {
    final harmonizedSeed = _harmonizeHue(seed, harmonizeTarget, amount: 0.12);
    final scheme = ColorScheme.fromSeed(
      seedColor: harmonizedSeed,
      brightness: brightness,
      contrastLevel: contrastLevel.clamp(-1.0, 1.0),
    );
    return SemanticTone(
      color: scheme.primary,
      onColor: scheme.onPrimary,
      container: scheme.primaryContainer,
      onContainer: scheme.onPrimaryContainer,
    );
  }

  SemanticTone lerp(SemanticTone other, double t) => SemanticTone(
        color: Color.lerp(color, other.color, t)!,
        onColor: Color.lerp(onColor, other.onColor, t)!,
        container: Color.lerp(container, other.container, t)!,
        onContainer: Color.lerp(onContainer, other.onContainer, t)!,
      );

  /// Armoniza el matiz HSL/HCT de [source] acercándolo sutilmente a [target].
  static Color _harmonizeHue(
    Color source,
    Color target, {
    required double amount,
  }) {
    final sourceHsl = HSLColor.fromColor(source);
    final targetHsl = HSLColor.fromColor(target);
    var delta = targetHsl.hue - sourceHsl.hue;
    if (delta > 180) delta -= 360;
    if (delta < -180) delta += 360;
    final newHue = (sourceHsl.hue + delta * amount) % 360;
    return sourceHsl.withHue(newHue < 0 ? newHue + 360 : newHue).toColor();
  }
}

/// Extensión de tema con los 6 roles semánticos de dominio de Gravital-Experience-UI
/// (SPEC-PIP-UI-001 §4.4, REQ-UI-002).
@immutable
class SemanticColors extends ThemeExtension<SemanticColors> {
  const SemanticColors({
    required this.success,
    required this.warning,
    required this.info,
    required this.moneyIn,
    required this.moneyOut,
    required this.pending,
  });

  /// Éxito / `VerificationResult::Valid`.
  final SemanticTone success;

  /// Advertencia / `VerificationResult::ValidWithStaleStatus`.
  final SemanticTone warning;

  /// Información / metadatos de sincronización y versión de TrustBundle.
  final SemanticTone info;

  /// Flujo de valor entrante / emisión de lote o abono.
  final SemanticTone moneyIn;

  /// Flujo de valor saliente / cargo o consumo de credencial.
  final SemanticTone moneyOut;

  /// Estado pendiente / `VerificationResult::Unverifiable` o armado NFC.
  final SemanticTone pending;

  static SemanticColors light({
    Color harmonizeTarget = kGxBrandSeed,
    double contrastLevel = 0.0,
  }) =>
      _fromBrightness(
        Brightness.light,
        harmonizeTarget: harmonizeTarget,
        contrastLevel: contrastLevel,
      );

  static SemanticColors dark({
    Color harmonizeTarget = kGxBrandSeed,
    double contrastLevel = 0.0,
  }) =>
      _fromBrightness(
        Brightness.dark,
        harmonizeTarget: harmonizeTarget,
        contrastLevel: contrastLevel,
      );

  static SemanticColors _fromBrightness(
    Brightness brightness, {
    required Color harmonizeTarget,
    required double contrastLevel,
  }) =>
      SemanticColors(
        success: SemanticTone.fromSeed(
          const Color(0xFF1B873F),
          brightness,
          harmonizeTarget: harmonizeTarget,
          contrastLevel: contrastLevel,
        ),
        warning: SemanticTone.fromSeed(
          const Color(0xFFE07A00),
          brightness,
          harmonizeTarget: harmonizeTarget,
          contrastLevel: contrastLevel,
        ),
        info: SemanticTone.fromSeed(
          const Color(0xFF0066CC),
          brightness,
          harmonizeTarget: harmonizeTarget,
          contrastLevel: contrastLevel,
        ),
        moneyIn: SemanticTone.fromSeed(
          const Color(0xFF0D7A5F),
          brightness,
          harmonizeTarget: harmonizeTarget,
          contrastLevel: contrastLevel,
        ),
        moneyOut: SemanticTone.fromSeed(
          const Color(0xFFB3261E),
          brightness,
          harmonizeTarget: harmonizeTarget,
          contrastLevel: contrastLevel,
        ),
        pending: SemanticTone.fromSeed(
          const Color(0xFF6E56CF),
          brightness,
          harmonizeTarget: harmonizeTarget,
          contrastLevel: contrastLevel,
        ),
      );

  /// Devuelve el par tonal correspondiente a cualquiera de los 4 estados de
  /// `VerificationResult` (`INV-04`, `REQ-UI-002`).
  SemanticTone toneForVerificationState(
    GxVerificationState state,
    ColorScheme scheme,
  ) =>
      switch (state) {
        GxVerificationState.valid => success,
        GxVerificationState.validWithStaleStatus => warning,
        GxVerificationState.unverifiable => pending,
        GxVerificationState.invalid => SemanticTone(
            color: scheme.error,
            onColor: scheme.onError,
            container: scheme.errorContainer,
            onContainer: scheme.onErrorContainer,
          ),
      };

  @override
  SemanticColors copyWith({
    SemanticTone? success,
    SemanticTone? warning,
    SemanticTone? info,
    SemanticTone? moneyIn,
    SemanticTone? moneyOut,
    SemanticTone? pending,
  }) =>
      SemanticColors(
        success: success ?? this.success,
        warning: warning ?? this.warning,
        info: info ?? this.info,
        moneyIn: moneyIn ?? this.moneyIn,
        moneyOut: moneyOut ?? this.moneyOut,
        pending: pending ?? this.pending,
      );

  @override
  SemanticColors lerp(SemanticColors? other, double t) {
    if (other is! SemanticColors) return this;
    return SemanticColors(
      success: success.lerp(other.success, t),
      warning: warning.lerp(other.warning, t),
      info: info.lerp(other.info, t),
      moneyIn: moneyIn.lerp(other.moneyIn, t),
      moneyOut: moneyOut.lerp(other.moneyOut, t),
      pending: pending.lerp(other.pending, t),
    );
  }
}
