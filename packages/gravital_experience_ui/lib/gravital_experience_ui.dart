/// Punto único de exportación del sistema de diseño **Gravital-Experience-UI**
/// (`SPEC-PIP-UI-001`, `ADR-0030`, `REQ-UI-001`..`004`).
///
/// Las aplicaciones de producto (`apps/reference-wallet`, etc.) importan
/// exclusivamente `package:gravital_experience_ui/gravital_experience_ui.dart`.
library;

export 'package:flutter/material.dart';
export 'package:flutter/physics.dart';
export 'package:flutter/services.dart';

export 'src/adapters/expressive_adapters.dart';
export 'src/app/gx_app.dart';
export 'src/components/domain_components.dart';
export 'src/patterns/gx_patterns.dart';
export 'src/theme/gx_theme.dart';
export 'src/theme/semantic_colors.dart';
export 'src/tokens/tokens.dart';
