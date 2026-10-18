// Pruebas unitarias y de widgets para Gravital-Experience-UI (SPEC-PIP-UI-001 §15).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004

import 'package:flutter_test/flutter_test.dart';
import 'package:gravital_experience_ui/gravital_experience_ui.dart';

void main() {
  // Verifies: REQ-UI-004
  test('WindowClass_fromWidth_maps_canonical_breakpoints', () {
    expect(WindowClass.fromWidth(360), WindowClass.compact);
    expect(WindowClass.fromWidth(600), WindowClass.medium);
    expect(WindowClass.fromWidth(840), WindowClass.expanded);
    expect(WindowClass.fromWidth(1200), WindowClass.large);
    expect(WindowClass.fromWidth(1600), WindowClass.extraLarge);
    expect(WindowClass.compact.isTwoPane, isFalse);
    expect(WindowClass.expanded.isTwoPane, isTrue);
  });

  // Verifies: REQ-UI-002
  test('SemanticColors_maps_all_four_verification_states_distinctly', () {
    final scheme = ColorScheme.fromSeed(seedColor: kGxBrandSeed);
    final semantic = SemanticColors.light(harmonizeTarget: scheme.primary);

    final validTone =
        semantic.toneForVerificationState(GxVerificationState.valid, scheme);
    final staleTone = semantic.toneForVerificationState(
      GxVerificationState.validWithStaleStatus,
      scheme,
    );
    final unverifiableTone = semantic.toneForVerificationState(
      GxVerificationState.unverifiable,
      scheme,
    );
    final invalidTone =
        semantic.toneForVerificationState(GxVerificationState.invalid, scheme);

    expect(validTone.color, semantic.success.color);
    expect(staleTone.color, semantic.warning.color);
    expect(unverifiableTone.color, semantic.pending.color);
    expect(invalidTone.color, scheme.error);
  });

  // Verifies: REQ-UI-003
  testWidgets(
      'GxDisclosureConsentSheet_locks_required_and_toggles_optional_claims',
      (tester) async {
    Set<String>? confirmed;

    await tester.pumpWidget(
      GxApp(
        title: 'Test Consent',
        home: Scaffold(
          body: GxDisclosureConsentSheet(
            verifierName: 'Banco General S.A.',
            verifierDomain: 'verificador.bgeneral.com',
            purpose: 'Apertura de cuenta e identificación KYC',
            transportLabel: 'NFC GID-APDU + HPKE',
            isVerifierSigned: true,
            claims: const <GxDisclosableClaim>[
              GxDisclosableClaim(
                key: 'age_over_18',
                label: 'Mayor de 18 años',
                valuePreview: 'true',
                isRequiredByVerifier: true,
              ),
              GxDisclosableClaim(
                key: 'document_number',
                label: 'Número de Cédula (TE)',
                valuePreview: '8-888-8888',
                isSensitiveLevel1: true,
              ),
            ],
            onConfirmDisclosures: (keys) => confirmed = keys,
          ),
        ),
      ),
    );

    expect(find.text('SOLICITUD FIRMADA'), findsOneWidget);
    expect(find.text('NIVEL 1'), findsOneWidget);

    // Desmarcar el claim opcional 'document_number'
    await tester.tap(find.text('Número de Cédula (TE)'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Confirmar y Compartir'));
    await tester.pumpAndSettle();

    expect(confirmed, equals(<String>{'age_over_18'}));
  });

  // Verifies: REQ-UI-001, REQ-UI-004
  testWidgets(
      'GxAdaptiveScaffold_switches_between_NavigationBar_and_NavigationRail_at_200_percent_text_scale',
      (tester) async {
    const destinations = <GxNavigationDestination>[
      GxNavigationDestination(
        label: 'Bóveda',
        icon: Icons.wallet_outlined,
        selectedIcon: Icons.wallet_rounded,
      ),
      GxNavigationDestination(
        label: 'Presentar',
        icon: Icons.qr_code_outlined,
        selectedIcon: Icons.qr_code_rounded,
      ),
    ];

    // Compact (390x844) + 200% text scale
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      GxApp(
        title: 'Adaptive Test',
        home: MediaQuery(
          data: const MediaQueryData(
            size: Size(390, 844),
            textScaler: TextScaler.linear(2.0),
            disableAnimations: true,
          ),
          child: GxAdaptiveScaffold(
            destinations: destinations,
            selectedIndex: 0,
            onDestinationSelected: (_) {},
            body: const Center(child: Text('Panel Principal')),
            secondaryBody: const Center(child: Text('Panel Detalle')),
          ),
        ),
      ),
    );

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(NavigationRail), findsNothing);
    expect(find.text('Panel Detalle'), findsNothing);

    // Expanded (1024x768)
    await tester.pumpWidget(
      GxApp(
        title: 'Adaptive Test',
        home: MediaQuery(
          data: const MediaQueryData(
            size: Size(1024, 768),
            disableAnimations: true,
          ),
          child: GxAdaptiveScaffold(
            destinations: destinations,
            selectedIndex: 0,
            onDestinationSelected: (_) {},
            body: const Center(child: Text('Panel Principal')),
            secondaryBody: const Center(child: Text('Panel Detalle')),
          ),
        ),
      ),
    );

    expect(find.byType(NavigationRail), findsOneWidget);
    expect(find.byType(NavigationBar), findsNothing);
    expect(find.text('Panel Detalle'), findsOneWidget);
  });
}
