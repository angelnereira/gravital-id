// Punto de entrada de aplicación GxApp (SPEC-PIP-UI-001 §12).
// Verifies: REQ-UI-001, REQ-UI-004

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../theme/gx_theme.dart';
import '../theme/semantic_colors.dart';

/// Contenedor raíz de aplicaciones Gravital-Experience-UI (`GxApp`, SPEC-PIP-UI-001 §12).
///
/// Configura automáticamente:
/// - Renderizado de borde a borde (`SystemUiMode.edgeToEdge`),
/// - Esquemas tonales HCT claros, oscuros y de alto contraste (`contrastLevel` 0.0 / 0.5 / 1.0),
/// - Extensiones `SemanticColors` y `EmphasizedTextTheme`.
class GxApp extends StatefulWidget {
  const GxApp({
    required this.title,
    required this.home,
    this.seedColor = kGxBrandSeed,
    this.themeMode = ThemeMode.system,
    this.contrastLevel = 0.0,
    super.key,
  });

  final String title;
  final Widget home;
  final Color seedColor;
  final ThemeMode themeMode;
  final double contrastLevel;

  @override
  State<GxApp> createState() => _GxAppState();
}

class _GxAppState extends State<GxApp> {
  @override
  void initState() {
    super.initState();
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  }

  @override
  Widget build(BuildContext context) {
    final effectiveContrast = widget.contrastLevel.clamp(-1.0, 1.0);

    final lightScheme = ColorScheme.fromSeed(
      seedColor: widget.seedColor,
      brightness: Brightness.light,
      contrastLevel: effectiveContrast,
    );
    final darkScheme = ColorScheme.fromSeed(
      seedColor: widget.seedColor,
      brightness: Brightness.dark,
      contrastLevel: effectiveContrast,
    );
    final highContrastLightScheme = ColorScheme.fromSeed(
      seedColor: widget.seedColor,
      brightness: Brightness.light,
      contrastLevel: 1.0,
    );
    final highContrastDarkScheme = ColorScheme.fromSeed(
      seedColor: widget.seedColor,
      brightness: Brightness.dark,
      contrastLevel: 1.0,
    );

    return MaterialApp(
      title: widget.title,
      debugShowCheckedModeBanner: false,
      themeMode: widget.themeMode,
      theme: GxTheme.build(lightScheme, contrastLevel: effectiveContrast),
      darkTheme: GxTheme.build(darkScheme, contrastLevel: effectiveContrast),
      highContrastTheme:
          GxTheme.build(highContrastLightScheme, contrastLevel: 1.0),
      highContrastDarkTheme:
          GxTheme.build(highContrastDarkScheme, contrastLevel: 1.0),
      home: widget.home,
    );
  }
}
