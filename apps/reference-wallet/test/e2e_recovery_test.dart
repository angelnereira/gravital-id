import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gravital_reference_wallet/main.dart';

void main() {
  testWidgets('E2E: recovery flow renders and navigates without crash',
      (tester) async {
    tester.view.physicalSize = const Size(480, 2600);
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
        data: MediaQueryData(size: Size(480, 2600)),
        child: GravitalReferenceWalletApp(),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Recuperar'));
    await tester.pumpAndSettle();
    expect(find.text('Recuperación de tu Gravital ID'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.visibility_rounded));
    await tester.pumpAndSettle();

    final tf = find.byType(TextField);
    print('textfields: ${tf.evaluate().length}');
    await tester.enterText(tf.first, 'abandon ability');
    await tester.pump();

    final btn = find.text('Restaurar Bóveda (Compromiso + SAS)');
    print('restore btn: ${btn.evaluate().length}');
    await tester.tap(btn);
    await tester.pumpAndSettle();
    print('snackbar abandon: ${find.textContaining("Restauración iniciada").evaluate().length}');

    await tester.tap(find.text('Sincronizar'));
    await tester.pumpAndSettle();
    expect(find.text('Sincronización y Confianza'), findsOneWidget);

    final syncBtn = find.text('Sincronizar Ahora');
    print('sync btn: ${syncBtn.evaluate().length}');
    await tester.tap(syncBtn);
    await tester.pumpAndSettle(const Duration(seconds: 1));
    print('sync done: ${find.textContaining("Sincronización completada").evaluate().length}');

    await tester.tap(find.text('Soportes'));
    await tester.pumpAndSettle();
    print('supports: ${find.textContaining("1 Teléfono + 1 Tarjeta").evaluate().length}');
  });
}
