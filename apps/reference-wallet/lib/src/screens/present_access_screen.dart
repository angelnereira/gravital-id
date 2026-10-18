// Pantalla de Presentación, Compartición y Accesos Offline/Proximidad (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-PRES-003, REQ-IDDOC-002, REQ-CODE-002

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Estudio interactivo de presentación (QR Offline, NFC GID-APDU y SessionCode Damm)
/// e inspector de los 4 estados de `VerificationResult` (`INV-04`).
class PresentAccessScreen extends StatefulWidget {
  const PresentAccessScreen({
    required this.store,
    super.key,
  });

  final GravitalWalletStore store;

  @override
  State<PresentAccessScreen> createState() => _PresentAccessScreenState();
}

class _PresentAccessScreenState extends State<PresentAccessScreen> {
  final TextEditingController _sessionCodeTestController =
      TextEditingController(text: '48291-03847');
  final TextEditingController _cardPinController =
      TextEditingController(text: '2486');
  String? _sessionCodeValidationMessage;
  bool _sessionCodeIsValid = true;

  @override
  void initState() {
    super.initState();
    _sessionCodeTestController.text = widget.store.activeSessionCode;
    _sessionCodeIsValid = DammSessionCode.isValid(widget.store.activeSessionCode);
  }

  @override
  void dispose() {
    _sessionCodeTestController.dispose();
    _cardPinController.dispose();
    super.dispose();
  }

  void _openDisclosureModal(BuildContext context) {
    final cred = widget.store.selectedCredential;
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (sheetContext) => GxDisclosureConsentSheet(
        verifierName: 'Terminal de Control de Acceso / Pasarela Inquilino',
        verifierDomain: 'acceso.torrepacifica.pa',
        purpose:
            'Verificación criptográfica sin servidor central (${widget.store.activeTransport.label})',
        transportLabel: widget.store.activeTransport.label,
        isVerifierSigned: true,
        claims: cred.claims,
        onConfirmDisclosures: (selectedKeys) {
          widget.store.updateConfirmedDisclosures(selectedKeys);
          Navigator.of(sheetContext).pop();
        },
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final cred = widget.store.selectedCredential;
    final transport = widget.store.activeTransport;
    final disclosures = widget.store.lastConfirmedDisclosures;

    final qrIncludesForbiddenPortrait =
        transport == PresentationTransport.qrOffline &&
            disclosures.contains('portrait');

    return ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl,
      ),
      children: <Widget>[
        Text(
          'Compartir Credencial y Acreditar Acceso',
          style: emphasized?.headlineSmall,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Credencial activa: ${cred.title} (${cred.factorClass.title})',
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        // Selector de canal de transporte mediante GxButtonGroup (M3E)
        GxButtonGroup<PresentationTransport>(
          selected: transport,
          onChanged: widget.store.setTransport,
          segments: const <GxButtonSegment<PresentationTransport>>[
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.qrOffline,
              label: 'QR Offline',
              icon: Icons.qr_code_2_rounded,
              badgeText: '≤1800 B',
            ),
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.nfcApdu,
              label: 'Toque NFC (APDU)',
              icon: Icons.contactless_rounded,
              badgeText: 'HPKE',
            ),
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.passkey,
              label: 'Passkey (FIDO2)',
              icon: Icons.fingerprint_rounded,
              badgeText: 'CTAP2',
            ),
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.sessionCode,
              label: 'Código Damm',
              icon: Icons.dialpad_rounded,
              badgeText: '10 díg',
            ),
          ],
        ),
        const SizedBox(height: GxSpace.l),
        if (qrIncludesForbiddenPortrait) ...<Widget>[
          GxErrorState(
            errorCode: 'GID-E8002',
            identifier: 'ProximityMessageTooLarge',
            title: 'Retrato Facial Prohibido en Código QR (REQ-IDDOC-002)',
            description:
                'El perfil pip-identity-v1 prohíbe incluir el retrato JPEG en presentaciones ópticas por QR para respetar el presupuesto de ≤ 1800 bytes. '
                'Cambia al canal "Toque NFC (APDU)" o "Passkey (FIDO2)", o desactiva el atributo portrait en la hoja de consentimiento.',
            remediationLabel: 'Cambiar a Toque NFC (GID-APDU)',
            onRemediate: () =>
                widget.store.setTransport(PresentationTransport.nfcApdu),
          ),
          const SizedBox(height: GxSpace.l),
        ],
        // Tarjeta visual del transporte activo
        Container(
          padding: const EdgeInsets.all(GxSpace.xl),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerLow,
            borderRadius: GxShape.extraLarge,
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: Column(
            children: <Widget>[
              StatusChip(
                label: transport.label,
                tone: semantic.info,
                icon: transport.icon,
              ),
              const SizedBox(height: GxSpace.m),
              if (transport == PresentationTransport.qrOffline) ...<Widget>[
                Container(
                  width: 196,
                  height: 196,
                  padding: const EdgeInsets.all(GxSpace.m),
                  decoration: BoxDecoration(
                    color: scheme.surfaceContainerHighest,
                    borderRadius: GxShape.large,
                    border: Border.all(color: scheme.primary, width: 2),
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: <Widget>[
                      Icon(
                        Icons.qr_code_2_rounded,
                        size: 112,
                        color: scheme.onSurface,
                      ),
                      GxTabularCodeText(
                        'PIP1:BASE45+DEFLATE:784B',
                        style: Theme.of(context).textTheme.labelSmall,
                        color: scheme.primary,
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: GxSpace.m),
                Text(
                  'Presentación firmada con KB-JWT (ES256 Low-S) · Sin I/O de red (INV-01)',
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
              ] else if (transport == PresentationTransport.nfcApdu) ...<Widget>[
                _buildNfcApduStudio(context, scheme, semantic, emphasized),
              ] else if (transport == PresentationTransport.passkey) ...<Widget>[
                _buildPasskeyStudio(context, scheme, semantic, emphasized),
              ] else ...<Widget>[
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: GxSpace.xl,
                    vertical: GxSpace.l,
                  ),
                  decoration: BoxDecoration(
                    color: scheme.primaryContainer,
                    borderRadius: GxShape.extraLarge,
                  ),
                  child: GxTabularCodeText(
                    widget.store.activeSessionCode,
                    style: emphasized?.displaySmall,
                    color: scheme.onPrimaryContainer,
                  ),
                ),
                const SizedBox(height: GxSpace.s),
                Text(
                  'Código efímero de 10 dígitos con dígito de control cuasigrupo de Damm (ADR-0025, TTL 180 s).',
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: GxSpace.m),
                Row(
                  children: <Widget>[
                    Expanded(
                      child: TextField(
                        controller: _sessionCodeTestController,
                        decoration: const InputDecoration(
                          labelText: 'Probar Validador Damm (10 dígitos)',
                          prefixIcon: Icon(Icons.pin_outlined),
                        ),
                        onChanged: (value) {
                          setState(() {
                            _sessionCodeIsValid = DammSessionCode.isValid(value);
                            _sessionCodeValidationMessage = _sessionCodeIsValid
                                ? 'Dígito verificador Damm válido (interim == 0).'
                                : 'GID-E8010 (InvalidSessionCode): Error de transcripción o transposición detectado por Damm.';
                          });
                        },
                      ),
                    ),
                    const SizedBox(width: GxSpace.s),
                    OutlinedButton(
                      onPressed: () {
                        widget.store.regenerateSessionCode('739204815');
                        setState(() {
                          _sessionCodeTestController.text =
                              widget.store.activeSessionCode;
                          _sessionCodeIsValid = true;
                          _sessionCodeValidationMessage =
                              'Nuevo código efímero generado con Damm válido.';
                        });
                      },
                      child: const Text('Rotar Código'),
                    ),
                  ],
                ),
                if (_sessionCodeValidationMessage != null) ...<Widget>[
                  const SizedBox(height: GxSpace.s),
                  StatusChip(
                    label: _sessionCodeValidationMessage!,
                    tone: _sessionCodeIsValid ? semantic.success : semantic.moneyOut,
                    icon: _sessionCodeIsValid
                        ? Icons.check_circle_rounded
                        : Icons.error_outline_rounded,
                  ),
                ],
              ],
              const SizedBox(height: GxSpace.l),
              Wrap(
                spacing: GxSpace.xs,
                runSpacing: GxSpace.xs,
                alignment: WrapAlignment.center,
                children: disclosures
                    .map(
                      (k) => Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: GxSpace.s,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: scheme.secondaryContainer,
                          borderRadius: GxShape.full,
                        ),
                        child: GxTabularCodeText(
                          '_sd: $k',
                          style: Theme.of(context).textTheme.labelSmall,
                          color: scheme.onSecondaryContainer,
                        ),
                      ),
                    )
                    .toList(),
              ),
              const SizedBox(height: GxSpace.l),
              // Único FilledButton de esta pantalla (Regla SPEC-PIP-UI-001 §15.1)
              FilledButton.icon(
                onPressed: () => _openDisclosureModal(context),
                icon: const Icon(Icons.tune_rounded),
                label: const Text('Elegir Qué Datos Compartir (Consentimiento)'),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Simulador del Motor de Verificación de 4 Estados (INV-04, REQ-UI-002)',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'El protocolo nunca reduce la verificación a un booleano. Prueba cómo se representan los 4 estados normativos:',
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        GxButtonGroup<GxVerificationState>(
          selected: widget.store.simulatedVerificationState,
          onChanged: widget.store.setSimulatedVerificationState,
          segments: const <GxButtonSegment<GxVerificationState>>[
            GxButtonSegment<GxVerificationState>(
              value: GxVerificationState.valid,
              label: 'Valid',
              icon: Icons.verified_rounded,
            ),
            GxButtonSegment<GxVerificationState>(
              value: GxVerificationState.validWithStaleStatus,
              label: 'StaleStatus',
              icon: Icons.history_toggle_off_rounded,
            ),
            GxButtonSegment<GxVerificationState>(
              value: GxVerificationState.unverifiable,
              label: 'Unverifiable',
              icon: Icons.help_outline_rounded,
            ),
            GxButtonSegment<GxVerificationState>(
              value: GxVerificationState.invalid,
              label: 'Invalid',
              icon: Icons.gpp_bad_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.m),
        _buildVerificationCardForState(widget.store.simulatedVerificationState),
      ],
    );
  }

  Widget _buildNfcApduStudio(
    BuildContext context,
    ColorScheme scheme,
    SemanticColors semantic,
    TextTheme? emphasized,
  ) {
    final nfcService = widget.store.nfcService;
    final nfcMode = widget.store.nfcMode;
    final log = nfcService.traceLog;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        const GxLoadingIndicator(
          size: 56,
          label: 'Transceptor NFC ISO/IEC 7816-4 GID-APDU Activo',
        ),
        const SizedBox(height: GxSpace.s),
        Center(
          child: GxTabularCodeText(
            'AID: ${ApduCommand.kGravitalAidHex} · HPKE(P-256, HKDF-SHA256, ChaCha20Poly1305)',
            style: Theme.of(context).textTheme.labelMedium,
            color: scheme.primary,
          ),
        ),
        const SizedBox(height: GxSpace.m),
        GxButtonGroup<NfcOperatingMode>(
          selected: nfcMode,
          onChanged: widget.store.setNfcMode,
          segments: const <GxButtonSegment<NfcOperatingMode>>[
            GxButtonSegment<NfcOperatingMode>(
              value: NfcOperatingMode.hceCardEmulation,
              label: 'Emulación HCE (Teléfono)',
              icon: Icons.phone_android_rounded,
            ),
            GxButtonSegment<NfcOperatingMode>(
              value: NfcOperatingMode.isoDepCardReader,
              label: 'Lector Tarjeta Visa (ISO-DEP)',
              icon: Icons.credit_card_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.m),
        if (nfcMode == NfcOperatingMode.hceCardEmulation) ...<Widget>[
          Container(
            padding: const EdgeInsets.symmetric(
              horizontal: GxSpace.m,
              vertical: GxSpace.s,
            ),
            decoration: BoxDecoration(
              color: scheme.surfaceContainerHighest,
              borderRadius: GxShape.medium,
            ),
            child: Row(
              children: <Widget>[
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        'Ventana de Toque NFC Armado (60 s · REQ-PROX-006)',
                        style: Theme.of(context).textTheme.labelLarge,
                      ),
                      const SizedBox(height: GxSpace.xs),
                      Text(
                        nfcService.isArmedForTap
                            ? 'HCE listo: SELECT AID + ENVELOPE transmitirán el sobre HPKE (SW=9000).'
                            : 'Desarmado (Anti-Skimming): ENVELOPE responderá SW=6985 (GID-E8004 ConsentPending).',
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
                Switch.adaptive(
                  value: nfcService.isArmedForTap,
                  onChanged: (armed) => widget.store.setNfcArmed(armed),
                ),
              ],
            ),
          ),
        ] else ...<Widget>[
          TextField(
            controller: _cardPinController,
            decoration: const InputDecoration(
              labelText: 'PIN Tarjeta Física Visa (VERIFY PIN 00 20 00 80 · Nivel 1)',
              helperText:
                  'PIN válido de prueba: 2486. Requerido al divulgar document_number, birth_date o portrait.',
              prefixIcon: Icon(Icons.dialpad_rounded),
            ),
          ),
        ],
        const SizedBox(height: GxSpace.m),
        Wrap(
          spacing: GxSpace.s,
          runSpacing: GxSpace.s,
          alignment: WrapAlignment.center,
          children: <Widget>[
            OutlinedButton.icon(
              onPressed: () {
                widget.store.executeNfcApduPresentation(
                  cardPin: _cardPinController.text,
                );
              },
              icon: const Icon(Icons.contactless_rounded),
              label: Text(
                nfcMode == NfcOperatingMode.hceCardEmulation
                    ? 'Transmitir Credencial por HCE (APDU)'
                    : 'Leer / Presentar con Tarjeta NFC (ISO-DEP)',
              ),
            ),
            TextButton.icon(
              onPressed: () {
                setState(() {
                  nfcService.processCommand(
                    const ApduCommand(
                      cla: 0x00,
                      ins: 0xA4,
                      p1: 0x04,
                      p2: 0x00,
                      data: <int>[0xA0, 0x00, 0x00, 0x00, 0x99],
                      le: 0x00,
                    ),
                    disclosedClaims: widget.store.lastConfirmedDisclosures,
                    isPhysicalCardMode:
                        nfcMode == NfcOperatingMode.isoDepCardReader,
                  );
                });
              },
              icon: const Icon(Icons.bug_report_outlined),
              label: const Text('Probar AID Desconocido (SW=6A82)'),
            ),
          ],
        ),
        if (log.isNotEmpty) ...<Widget>[
          const SizedBox(height: GxSpace.m),
          Container(
            padding: const EdgeInsets.all(GxSpace.m),
            decoration: BoxDecoration(
              color: scheme.surfaceContainerHighest,
              borderRadius: GxShape.large,
              border: Border.all(color: scheme.outlineVariant),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Row(
                  children: <Widget>[
                    Icon(
                      Icons.terminal_rounded,
                      size: 18,
                      color: scheme.primary,
                    ),
                    const SizedBox(width: GxSpace.xs),
                    Expanded(
                      child: Text(
                        'Traza APDU ISO/IEC 7816-4 (${log.length} tramas · Estado: ${nfcService.phase.name})',
                        style: emphasized?.titleSmall,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: GxSpace.s),
                ...log.map(
                  (entry) => Padding(
                    padding: const EdgeInsets.only(bottom: GxSpace.xs),
                    child: Container(
                      padding: const EdgeInsets.all(GxSpace.s),
                      decoration: BoxDecoration(
                        color: scheme.surfaceContainerLow,
                        borderRadius: GxShape.small,
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: <Widget>[
                          Row(
                            children: <Widget>[
                              Expanded(
                                child: Text(
                                  entry.stepLabel,
                                  style:
                                      Theme.of(context).textTheme.labelMedium,
                                ),
                              ),
                              StatusChip(
                                label: 'SW=${entry.responseSwHex}',
                                tone: entry.isSuccess
                                    ? semantic.success
                                    : semantic.moneyOut,
                                icon: entry.isSuccess
                                    ? Icons.check_circle_rounded
                                    : Icons.error_outline_rounded,
                              ),
                            ],
                          ),
                          const SizedBox(height: GxSpace.xs),
                          GxTabularCodeText(
                            'C-APDU >> ${entry.commandHex}',
                            style: Theme.of(context).textTheme.labelSmall,
                            color: scheme.onSurfaceVariant,
                          ),
                          GxTabularCodeText(
                            'Estado << ${entry.statusSummary}',
                            style: Theme.of(context).textTheme.labelSmall,
                            color: scheme.primary,
                          ),
                          Text(
                            entry.payloadSummary,
                            style: Theme.of(context).textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildPasskeyStudio(
    BuildContext context,
    ColorScheme scheme,
    SemanticColors semantic,
    TextTheme? emphasized,
  ) {
    final passkeyService = widget.store.passkeyService;
    final passkeys = passkeyService.registeredPasskeys;
    final selectedIdx = widget.store.selectedPasskeyIndex;
    final activeTransport = widget.store.activePasskeyTransport;
    final lastEnvelope = passkeyService.lastEnvelope;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Icon(
              Icons.fingerprint_rounded,
              size: 40,
              color: scheme.primary,
            ),
            const SizedBox(width: GxSpace.s),
            Icon(
              Icons.contactless_rounded,
              size: 36,
              color: scheme.tertiary,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Presentación y Transmisión vía Passkey (FIDO2 / WebAuthn Level 3 + CTAP2)',
          textAlign: TextAlign.center,
          style: emphasized?.titleSmall,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Vincula el challenge WebAuthn al SHA-256(transcript_hash || sd_hash) (PROTOCOL.md §7.8, ADR-0027 §6.2).',
          textAlign: TextAlign.center,
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        GxButtonGroup<PasskeyAuthenticatorTransport>(
          selected: activeTransport,
          onChanged: widget.store.setPasskeyTransport,
          segments: const <GxButtonSegment<PasskeyAuthenticatorTransport>>[
            GxButtonSegment<PasskeyAuthenticatorTransport>(
              value: PasskeyAuthenticatorTransport.platformInternal,
              label: 'Biometría Local',
              icon: Icons.fingerprint_rounded,
            ),
            GxButtonSegment<PasskeyAuthenticatorTransport>(
              value: PasskeyAuthenticatorTransport.nfcSecurityKey,
              label: 'Passkey NFC (CTAP2)',
              icon: Icons.contactless_rounded,
            ),
            GxButtonSegment<PasskeyAuthenticatorTransport>(
              value: PasskeyAuthenticatorTransport.hybridCrossDevice,
              label: 'Híbrido (QR+BLE)',
              icon: Icons.devices_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.m),
        ...List<Widget>.generate(passkeys.length, (index) {
          final pk = passkeys[index];
          final isSelected = index == selectedIdx;
          return Padding(
            padding: const EdgeInsets.only(bottom: GxSpace.xs),
            child: InkWell(
              borderRadius: GxShape.medium,
              onTap: () => widget.store.selectPasskey(index),
              child: Container(
                padding: const EdgeInsets.all(GxSpace.m),
                decoration: BoxDecoration(
                  color: isSelected
                      ? scheme.secondaryContainer
                      : scheme.surfaceContainerHighest,
                  borderRadius: GxShape.medium,
                  border: Border.all(
                    color: isSelected ? scheme.primary : scheme.outlineVariant,
                  ),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Row(
                      children: <Widget>[
                        Icon(
                          isSelected
                              ? Icons.radio_button_checked_rounded
                              : Icons.radio_button_off_rounded,
                          size: 18,
                          color: scheme.primary,
                        ),
                        const SizedBox(width: GxSpace.xs),
                        Expanded(
                          child: Text(
                            pk.displayName,
                            style: emphasized?.labelLarge,
                          ),
                        ),
                        StatusChip(
                          label: 'signCount: ${pk.signCount}',
                          tone: semantic.info,
                          icon: pk.transport.icon,
                        ),
                      ],
                    ),
                    const SizedBox(height: GxSpace.xs),
                    GxTabularCodeText(
                      'rpId: ${pk.rpId} · credId: ${pk.credentialId}',
                      style: Theme.of(context).textTheme.labelSmall,
                      color: scheme.onSurfaceVariant,
                    ),
                  ],
                ),
              ),
            ),
          );
        }),
        const SizedBox(height: GxSpace.s),
        Wrap(
          spacing: GxSpace.s,
          runSpacing: GxSpace.s,
          alignment: WrapAlignment.center,
          children: <Widget>[
            OutlinedButton.icon(
              onPressed: () {
                widget.store.transmitPresentationViaPasskey();
              },
              icon: const Icon(Icons.fingerprint_rounded),
              label: const Text('Firmar y Transmitir con Passkey'),
            ),
            TextButton.icon(
              onPressed: () {
                widget.store.registerNewPasskey(
                  rpId: 'portal.salud.gob.pa',
                  displayName:
                      'Passkey NFC / Plataforma #${passkeys.length + 1}',
                  transport: activeTransport,
                );
              },
              icon: const Icon(Icons.add_moderator_outlined),
              label: const Text('Registrar Nueva Passkey'),
            ),
          ],
        ),
        if (lastEnvelope != null) ...<Widget>[
          const SizedBox(height: GxSpace.m),
          Container(
            padding: const EdgeInsets.all(GxSpace.m),
            decoration: BoxDecoration(
              color: scheme.surfaceContainerHighest,
              borderRadius: GxShape.large,
              border: Border.all(color: scheme.outlineVariant),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Row(
                  children: <Widget>[
                    Expanded(
                      child: Text(
                        'Sobre PasskeyPresentationEnvelope Emitido',
                        style: emphasized?.titleSmall,
                      ),
                    ),
                    StatusChip(
                      label: 'UP=1 · UV=1 · ES256',
                      tone: semantic.success,
                      icon: Icons.verified_user_rounded,
                    ),
                  ],
                ),
                const SizedBox(height: GxSpace.xs),
                GxTabularCodeText(
                  'rpId: ${lastEnvelope.rpId} · transport: ${lastEnvelope.transport.code} · signCount: ${lastEnvelope.signCount}',
                  style: Theme.of(context).textTheme.labelSmall,
                  color: scheme.primary,
                ),
                GxTabularCodeText(
                  'challenge (SHA256(th||sd)): ${lastEnvelope.boundChallengeBase64Url}',
                  style: Theme.of(context).textTheme.labelSmall,
                  color: scheme.onSurfaceVariant,
                ),
                GxTabularCodeText(
                  'authenticatorData: ${lastEnvelope.authenticatorDataHex}',
                  style: Theme.of(context).textTheme.labelSmall,
                  color: scheme.onSurfaceVariant,
                ),
                GxTabularCodeText(
                  'flags: ${lastEnvelope.flagsSummary}',
                  style: Theme.of(context).textTheme.labelSmall,
                  color: scheme.onSurfaceVariant,
                ),
                GxTabularCodeText(
                  'signature: ${lastEnvelope.assertionSignatureHex}',
                  style: Theme.of(context).textTheme.labelSmall,
                  color: scheme.tertiary,
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildVerificationCardForState(GxVerificationState state) {
    switch (state) {
      case GxVerificationState.valid:
        return const GxVerificationResultCard(
          state: GxVerificationState.valid,
          headline: 'Credencial y Posesión de Clave Hardware Verificadas',
          summary:
              'Todas las 12 etapas del pipeline offline finalizaron satisfactoriamente con estado fresco.',
          trustBundleInfo:
              'TrustBundle v14 (3-de-5 firmas Ed25519 TFA) · StatusList frescura: 2h 10m',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Autenticación de Emisor en TrustBundle (INV-06)',
              passed: true,
              detail:
                  'Clave P-256 resuelta localmente desde TrustBundle v14; sin uso de jku/x5u ni red.',
            ),
            GxVerificationCheckItem(
              stepName: '2. Firma SD-JWT y Prueba de Posesión KB-JWT (Low-S)',
              passed: true,
              detail:
                  'Firma ES256 válida con s ≤ n/2; sd_hash y nonce coinciden con la sesión.',
            ),
            GxVerificationCheckItem(
              stepName: '3. Estado por Ranura de Dispositivo (Token Status List)',
              passed: true,
              detail:
                  'Índice #4102 (slot: mobile) = 00 (activo) dentro de la ventana fresca.',
            ),
          ],
        );
      case GxVerificationState.validWithStaleStatus:
        return const GxVerificationResultCard(
          state: GxVerificationState.validWithStaleStatus,
          headline: 'Válida con Lista de Estado en Ventana de Gracia Offline',
          summary:
              'La firma del emisor y el KB-JWT del titular son auténticos; el snapshot de revocación tiene 19h de antigüedad.',
          trustBundleInfo:
              'TrustBundle v14 · Snapshot de estado en caché local (edad: 19h ≤ 24h máx.)',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Autenticación de Emisor y Firma SD-JWT + KB-JWT',
              passed: true,
              detail:
                  'Criptografía autenticada completamente en local sin conexión (INV-01).',
            ),
            GxVerificationCheckItem(
              stepName: '2. Frescura de Token Status List (Política Offline)',
              passed: true,
              detail:
                  'Snapshot superó el TTL ideal (6h) pero está dentro de la tolerancia offline del perfil (24h).',
            ),
          ],
        );
      case GxVerificationState.unverifiable:
        return const GxVerificationResultCard(
          state: GxVerificationState.unverifiable,
          errorCode: 'GID-E4003',
          headline: 'Evidencia Local Insuficiente (Fail-Closed, INV-05)',
          summary:
              'El verificador lleva más de 7 días sin sincronizar el snapshot de estado y la política exige estado vigente.',
          trustBundleInfo:
              'Acción requerida: sincronizar TrustBundle y StatusManifest antes de aceptar.',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Firma Criptográfica SD-JWT y KB-JWT',
              passed: true,
              detail: 'Las firmas matemáticas son íntegras.',
            ),
            GxVerificationCheckItem(
              stepName: '2. Ventana Máxima de Frescura Expirada (GID-E4003)',
              passed: false,
              detail:
                  'StatusListExpired: el verificador rechaza aceptar en silencio (INV-05).',
            ),
          ],
        );
      case GxVerificationState.invalid:
        return const GxVerificationResultCard(
          state: GxVerificationState.invalid,
          errorCode: 'GID-E4005',
          headline: 'Credencial Rechazada (Soporte Revocado o Firma Inválida)',
          summary:
              'El índice de estado del dispositivo figura como 01 (revocado) tras un reemplazo atómico o reporte de extravío.',
          trustBundleInfo:
              'Orden de corto-circuito: si falla la firma, vigencia y estado quedan Skipped.',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Firma del Emisor y Vínculo KB-JWT',
              passed: true,
              detail: 'Firmas verificadas contra el TrustBundle.',
            ),
            GxVerificationCheckItem(
              stepName: '2. Consulta de Token Status List (GID-E4005)',
              passed: false,
              detail:
                  'CredentialRevoked: el soporte anterior fue revocado en la lista de estado.',
            ),
          ],
        );
    }
  }
}
