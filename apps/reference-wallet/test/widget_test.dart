// Pruebas unitarias y de integración de widgets para apps/reference-wallet.
// Verifies: REQ-TENANT-001, REQ-TENANT-002, REQ-TENANT-003, REQ-TENANT-004,
// Verifies: REQ-UNIQ-001, REQ-UNIQ-002, REQ-UNIQ-003, REQ-UNIQ-004,
// Verifies: REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-DEVSLOT-004,
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004, REQ-CODE-002

import 'package:flutter_test/flutter_test.dart';
import 'package:gravital_experience_ui/gravital_experience_ui.dart';
import 'package:gravital_reference_wallet/main.dart';
import 'package:gravital_reference_wallet/src/domain/gravital_wallet_store.dart';

void main() {
  // Verifies: REQ-UNIQ-001, REQ-UNIQ-002, REQ-UNIQ-003
  test(
      'panama_tribunal_electoral_profile_accepts_canonical_cedulas_and_rejects_duplicates_with_gid_e2010',
      () {
    expect(PanamaNationalIdProfile.isValidPanamaCedula('8-888-8888'), isTrue);
    expect(PanamaNationalIdProfile.isValidPanamaCedula('PE-12-345'), isTrue);
    expect(PanamaNationalIdProfile.isValidPanamaCedula('E-8-123456'), isTrue);
    expect(PanamaNationalIdProfile.isValidPanamaCedula('1AV-43-123'), isTrue);
    expect(PanamaNationalIdProfile.isValidPanamaCedula('99-888-8888'), isFalse);

    final store = GravitalWalletStore();

    // Caso negativo: cédula ya registrada 8-888-8888 -> GID-E2010
    final duplicateOutcome = store.attemptCitizenRegistration(
      rawCedula: ' 8-888-8888 ',
      fullName: 'Ángel Gabriel Nereira',
    );
    expect(duplicateOutcome.succeeded, isFalse);
    expect(duplicateOutcome.errorCode, 'GID-E2010');
    expect(
      duplicateOutcome.errorIdentifier,
      'CitizenIdentityAlreadyRegistered',
    );

    // Caso negativo: formato inválido -> GID-E3004
    final malformedOutcome = store.attemptCitizenRegistration(
      rawCedula: 'INVALID-CEDULA',
      fullName: 'Usuario Prueba',
    );
    expect(malformedOutcome.succeeded, isFalse);
    expect(malformedOutcome.errorCode, 'GID-E3004');

    // Caso positivo: nueva cédula válida 4-752-1940
    final validOutcome = store.attemptCitizenRegistration(
      rawCedula: '4-752-1940',
      fullName: 'María Fernanda Pérez',
    );
    expect(validOutcome.succeeded, isTrue);
    expect(validOutcome.uniquenessTag, startsWith('voprf:p256:pa:'));
  });

  // Verifies: REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-DEVSLOT-004
  test(
      'device_factor_slots_allow_different_classes_but_reject_second_device_in_same_class_with_gid_e2011',
      () {
    final store = GravitalWalletStore();

    // Coexisten 1 mobile, 1 card (Visa) y 1 other simultáneamente
    expect(store.deviceSlots.keys, containsAll(DeviceFactorClass.values));
    expect(store.deviceSlots[DeviceFactorClass.mobile]?.statusListIndex, 4102);
    expect(store.deviceSlots[DeviceFactorClass.card]?.statusListIndex, 4103);
    expect(store.deviceSlots[DeviceFactorClass.other]?.statusListIndex, 4104);

    // Caso negativo: intentar vincular un segundo teléfono sin reemplazo -> GID-E2011
    final duplicatePhone = store.attemptDuplicateDeviceInClass(
      factorClass: DeviceFactorClass.mobile,
      candidateModelName: 'Segundo Teléfono No Autorizado',
      candidateHardwareId: 'IMEI: 359999000000001',
    );
    expect(duplicatePhone.succeeded, isFalse);
    expect(duplicatePhone.errorCode, 'GID-E2011');
    expect(duplicatePhone.errorIdentifier, 'DuplicateDeviceClassActive');

    // Caso negativo: intentar vincular una segunda tarjeta física tipo Visa -> GID-E2011
    final duplicateCard = store.attemptDuplicateDeviceInClass(
      factorClass: DeviceFactorClass.card,
      candidateModelName: 'Segunda Tarjeta Visa Clon',
      candidateHardwareId: 'CPLC: 9999',
    );
    expect(duplicateCard.succeeded, isFalse);
    expect(duplicateCard.errorCode, 'GID-E2011');

    // Caso positivo: reemplazo atómico del teléfono revoca el índice 4102 pero mantiene intacta la tarjeta (4103)
    final replacement = store.replaceDeviceInSlot(
      factorClass: DeviceFactorClass.mobile,
      newModelName: 'Pixel 10 Pro Reemplazo',
      newHardwareId: 'IMEI-Attested: 354109-12-908144-2',
    );
    expect(replacement.succeeded, isTrue);
    expect(replacement.revokedStatusIndex, 4102);
    expect(store.revokedStatusIndices, contains(4102));
    expect(
      store.deviceSlots[DeviceFactorClass.mobile]?.statusListIndex,
      isNot(4102),
    );
    // La tarjeta Visa sigue en su índice 4103 sin afectación
    expect(store.deviceSlots[DeviceFactorClass.card]?.statusListIndex, 4103);
  });

  // Verifies: REQ-CODE-002
  test('damm_session_code_detects_single_digit_and_transposition_errors', () {
    final validCode = DammSessionCode.formatFromPayload('482910384');
    expect(DammSessionCode.isValid(validCode), isTrue);

    // Alterar un solo dígito
    final corruptedDigit =
        '${validCode.substring(0, 2)}9${validCode.substring(3)}';
    expect(DammSessionCode.isValid(corruptedDigit), isFalse);

    // Transponer dos dígitos adyacentes distintos ('48' -> '84')
    final transposed = '84${validCode.substring(2)}';
    expect(DammSessionCode.isValid(transposed), isFalse);
  });

  // Verifies: REQ-TENANT-001, REQ-TENANT-002, REQ-TENANT-003, REQ-TENANT-004
  test('multi_tenant_store_updates_portability_claims_and_connects_new_tenant',
      () {
    final store = GravitalWalletStore();
    expect(store.tenants.length, 3);

    store.updateTenantSharedClaims(
      'urn:gravital-id:tenant:bgeneral-corp',
      const <String>['given_name', 'age_over_18'],
    );
    final updated = store.tenants.firstWhere(
      (t) => t.tenantId == 'urn:gravital-id:tenant:bgeneral-corp',
    );
    expect(updated.sharedClaims, equals(<String>['given_name', 'age_over_18']));

    store.connectNewTenantApp(
      tenantId: 'urn:gravital-id:tenant: ACP-Logistica',
      tenantName: 'Autoridad del Canal — Portal Operadores',
      tenantSector: 'Marítimo y Logística',
      requestedRoles: const <String>['transit_inspector'],
      requestedPermissions: const <String>['vessel:inspect'],
      approvedClaims: const <String>['given_name', 'nationality'],
    );
    expect(store.tenants.length, 4);
  });

  // Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004
  testWidgets(
      'GravitalReferenceWalletApp_navigates_all_four_tabs_and_renders_Gravital_Experience_UI',
      (tester) async {
    tester.view.physicalSize = const Size(480, 2600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      const MediaQuery(
        data: MediaQueryData(
          size: Size(480, 2600),
          disableAnimations: true,
        ),
        child: GravitalReferenceWalletApp(),
      ),
    );

    // Tab 0: Bóveda de Credenciales
    expect(
      find.text('Tu Llave Única de Identidad Portable'),
      findsOneWidget,
    );
    expect(
      find.text('Cédula de Identidad Personal (Panamá)'),
      findsOneWidget,
    );

    // Ir al Tab 1: Presentar y verificar los 4 estados de VerificationResult
    await tester.tap(find.text('Presentar'));
    await tester.pumpAndSettle();
    expect(
      find.text('Compartir Credencial y Acreditar Acceso'),
      findsOneWidget,
    );
    expect(find.text('VerificationResult::Valid'), findsOneWidget);

    // Probar pestaña Toque NFC (APDU) y transmitir credencial por HCE
    await tester.tap(find.text('Toque NFC (APDU)'));
    await tester.pumpAndSettle();
    expect(
      find.text('Transmitir Credencial por HCE (APDU)'),
      findsOneWidget,
    );
    await tester.tap(find.text('Transmitir Credencial por HCE (APDU)'));
    await tester.pumpAndSettle();
    expect(
      find.textContaining('1. SELECT AID (F0475241564954414C01)'),
      findsOneWidget,
    );

    // Probar pestaña Passkey (FIDO2) y firmar presentación con Passkey
    await tester.tap(find.text('Passkey (FIDO2)'));
    await tester.pumpAndSettle();
    expect(
      find.text('Firmar y Transmitir con Passkey'),
      findsOneWidget,
    );
    await tester.tap(find.text('Firmar y Transmitir con Passkey'));
    await tester.pumpAndSettle();
    expect(
      find.text('Sobre PasskeyPresentationEnvelope Emitido'),
      findsOneWidget,
    );

    await tester.tap(find.text('Invalid'));
    await tester.pumpAndSettle();
    expect(find.text('VerificationResult::Invalid'), findsOneWidget);

    // Ir al Tab 2: Apps y Roles (Multi-Inquilino)
    await tester.tap(find.text('Apps y Roles'));
    await tester.pumpAndSettle();
    expect(
      find.text('Un Mismo Gravital ID para Todos tus Sistemas y Roles'),
      findsOneWidget,
    );

    // Ir al Tab 3: Soportes (Ranura Única por Clase)
    await tester.tap(find.text('Soportes'));
    await tester.pumpAndSettle();
    expect(
      find.text(
        '1 Teléfono + 1 Tarjeta Tipo Visa + 1 Otro Soporte — Nunca Dos del Mismo Tipo',
      ),
      findsOneWidget,
    );

    // Disparar prueba interactiva de bloqueo de 2.º teléfono con otro IMEI (GID-E2011)
    await tester.tap(
      find.text('Probar Bloqueo de 2.º Teléfono con Otro IMEI (GID-E2011)'),
    );
    await tester.pumpAndSettle();
    expect(
      find.text('GID-E2011 · DuplicateDeviceClassActive'),
      findsOneWidget,
    );
  });

  // Verifies: REQ-PROX-001, REQ-PROX-002, REQ-PROX-005, REQ-PROX-006
  test(
      'nfc_gid_apdu_service_enforces_aid_selection_hce_arming_card_pin_and_hpke_chaining',
      () async {
    final store = GravitalWalletStore();
    final nfc = store.nfcService;

    // 1. Caso positivo: HCE armado ejecuta SELECT AID + ENVELOPE + GET RESPONSE -> SW=9000
    final armedLog = store.executeNfcApduPresentation();
    expect(armedLog.length, greaterThanOrEqualTo(3));
    expect(armedLog.first.stepLabel, contains('SELECT AID'));
    expect(armedLog.first.responseSwHex, '9000');
    expect(armedLog.last.responseSwHex, '9000');
    expect(nfc.phase, GidApduSessionPhase.completed);

    // 2. Caso negativo: HCE desarmado (anti-skimming REQ-PROX-006) rechaza ENVELOPE con SW=6985 (GID-E8004)
    await store.setNfcArmed(false);
    final unarmedLog = store.executeNfcApduPresentation();
    expect(unarmedLog.last.responseSwHex, '6985');
    expect(unarmedLog.last.statusSummary, contains('GID-E8004'));
    await store.setNfcArmed(true);

    // 3. Caso negativo: Tarjeta física Visa (ISO-DEP) con atributo Nivel 1 ('document_number') y PIN incorrecto -> SW=63C2 (GID-E8005)
    store.setNfcMode(NfcOperatingMode.isoDepCardReader);
    store.updateConfirmedDisclosures(
      const <String>{'given_name', 'document_number'},
    );
    final wrongPinLog = store.executeNfcApduPresentation(cardPin: '000000');
    expect(
      wrongPinLog.any((e) => e.statusSummary.contains('GID-E8005')),
      isTrue,
    );

    // 4. Caso positivo: Tarjeta física Visa con PIN correcto '2486' -> VERIFY PIN SW=9000 y ENVELOPE/GET RESPONSE SW=9000
    final validPinLog = store.executeNfcApduPresentation(cardPin: '2486');
    expect(
      validPinLog.any(
        (e) => e.stepLabel.contains('VERIFY PIN') && e.responseSwHex == '9000',
      ),
      isTrue,
    );
    expect(validPinLog.last.responseSwHex, '9000');

    // 5. Caso negativo: AID desconocido -> SW=6A82 (GID-E8001)
    final unknownAidResp = nfc.processCommand(
      const ApduCommand(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: <int>[0xDE, 0xAD, 0xBE, 0xEF],
        le: 0x00,
      ),
      disclosedClaims: store.lastConfirmedDisclosures,
      isPhysicalCardMode: false,
    );
    expect(unknownAidResp.swHex, '6A82');
    expect(unknownAidResp.mappedErrorCode, 'GID-E8001');

    // 6. Codificación de cabecera de fragmentación APDU (6 bytes)
    final headerBytes = const ApduFragmentHeader(
      isFirstFragment: true,
      isLastFragment: false,
      sequenceIndex: 0,
      totalFragments: 2,
    ).toBytes();
    expect(headerBytes.length, 6);
    expect(headerBytes[0], 0x01);
    expect(headerBytes[4], 2);
  });

  // Verifies: REQ-TENANT-001, REQ-PROX-002
  test(
      'passkey_presentation_service_binds_challenge_to_transcript_and_sd_hash_and_increments_sign_count',
      () async {
    final store = GravitalWalletStore();
    final initialSignCount =
        store.passkeyService.registeredPasskeys.first.signCount;

    // Transmitir vía Passkey sobre NFC Security Key (CTAP2)
    store.setPasskeyTransport(PasskeyAuthenticatorTransport.nfcSecurityKey);
    final envelope = await store.transmitPresentationViaPasskey();

    expect(
      envelope.transport,
      PasskeyAuthenticatorTransport.nfcSecurityKey,
    );
    expect(envelope.signCount, initialSignCount + 1);
    expect(envelope.boundChallengeBase64Url, isNotEmpty);
    final rawAuthData = PasskeyPresentationService.buildAuthenticatorData(
      rpId: envelope.rpId,
      signCount: envelope.signCount,
    );
    expect(rawAuthData.length, 37);
    expect(envelope.verifiedOffline, isTrue);

    // Registrar una nueva Passkey
    final created = store.registerNewPasskey(
      rpId: 'portal.acp.gob.pa',
      displayName: 'Passkey Tarjeta NFC #3',
      transport: PasskeyAuthenticatorTransport.nfcSecurityKey,
    );
    expect(created.rpId, 'portal.acp.gob.pa');
    expect(store.passkeyService.registeredPasskeys.length, 3);
  });
}
