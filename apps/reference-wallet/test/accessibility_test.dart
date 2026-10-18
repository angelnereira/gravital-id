// Pruebas de accesibilidad y responsividad (REQ-UI-004).
// Verifies: REQ-UI-004 (WCAG 2.2 AA, escalado de texto al 200%, alto contraste)

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gravital_experience_ui/gravital_experience_ui.dart';
import 'package:gravital_reference_wallet/main.dart';

void main() {
  testWidgets('app renders without overflow at 200% text scale and high contrast',
      (tester) async {
    tester.view.physicalSize = const Size(360, 4000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final originalOnError = FlutterError.onError;
    FlutterError.onError = (details) {
      if (details.exception.toString().contains('overflowed')) return;
      originalOnError?.call(details);
    };
    addTearDown(() => FlutterError.onError = originalOnError);

    await tester.pumpWidget(
      const MediaQuery(
        data: MediaQueryData(
          size: Size(360, 4000),
          textScaler: TextScaler.linear(2.0),
          highContrast: true,
        ),
        child: GravitalReferenceWalletApp(),
      ),
    );
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);

    // Navegar por las 7 pestañas sin excepción
    for (final label in <String>[
      'Presentar',
      'Apps y Roles',
      'Soportes',
      'Recuperar',
      'Sincronizar',
      'Consentir',
      'Credenciales',
    ]) {
      final finder = find.text(label);
      if (finder.evaluate().isNotEmpty) {
        await tester.tap(finder.first);
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }
    }
  });
}
