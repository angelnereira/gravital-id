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
  final TextEditingController _cardPinController =
      TextEditingController(text: '2486');
  bool _showNfcTrace = false;

  @override
  void dispose() {
    _cardPinController.dispose();
    super.dispose();
  }

  void _openDisclosureModal(BuildContext context) {
    final cred = widget.store.selectedCredential;
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (sheetContext) => GxDisclosureConsentSheet(
        verifierName: 'Terminal de Control de Acceso',
        verifierDomain: 'acceso.torrepacifica.pa',
        purpose: 'Verificación de identidad sin conexión',
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

  static String _humanClaimLabel(String key) => switch (key) {
        'given_name' => 'Nombres',
        'family_name' => 'Apellidos',
        'document_number' => 'N.º de Cédula',
        'birth_date' => 'Fecha de nacimiento',
        'age_over_18' => 'Mayor de 18 años',
        'nationality' => 'Nacionalidad',
        'portrait' => 'Fotografía',
        'blood_type' => 'Tipo de sangre',
        _ => key,
      };

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
        GxSpace.m,
        GxSpace.l,
        GxSpace.xxxl,
      ),
      children: <Widget>[
        Text(
          'Compartir Credencial y Acreditar Acceso',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: 2),
        Text(
          cred.title,
          style: Theme.of(context)
              .textTheme
              .bodySmall
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
            ),
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.nfcApdu,
              label: 'Toque NFC (APDU)',
              icon: Icons.contactless_rounded,
            ),
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.passkey,
              label: 'Passkey (FIDO2)',
              icon: Icons.fingerprint_rounded,
            ),
            GxButtonSegment<PresentationTransport>(
              value: PresentationTransport.sessionCode,
              label: 'Código Damm',
              icon: Icons.dialpad_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.m),
        if (qrIncludesForbiddenPortrait) ...<Widget>[
          GxErrorState(
            errorCode: 'GID-E8002',
            identifier: 'ProximityMessageTooLarge',
            title: 'Fotografía No Permitida en Código QR',
            description:
                'La fotografía solo se transmite por Toque NFC o Passkey.',
            remediationLabel: 'Cambiar a Toque NFC',
            onRemediate: () =>
                widget.store.setTransport(PresentationTransport.nfcApdu),
          ),
          const SizedBox(height: GxSpace.m),
        ],
        // Tarjeta visual del transporte activo
        Container(
          padding: const EdgeInsets.all(GxSpace.l),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerLow,
            borderRadius: GxShape.extraLarge,
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: Column(
            children: <Widget>[
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
                        size: 120,
                        color: scheme.onSurface,
                      ),
                      const SizedBox(height: GxSpace.xs),
                      Text(
                        'Listo para escanear',
                        style: Theme.of(context)
                            .textTheme
                            .labelSmall
                            ?.copyWith(color: scheme.primary),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: GxSpace.s),
                Text(
                  'Muestra este código al verificador (sin conexión).',
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
                  'Dicta o ingresa este código temporal en el verificador.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: GxSpace.m),
                OutlinedButton.icon(
                  onPressed: () {
                    widget.store.regenerateSessionCode('739204815');
                  },
                  icon: const Icon(Icons.refresh_rounded, size: 18),
                  label: const Text('Generar Nuevo Código'),
                ),
              ],
              const SizedBox(height: GxSpace.m),
              const Divider(height: GxSpace.m),
              Text(
                'Datos seleccionados (${disclosures.length}):',
                style: Theme.of(context)
                    .textTheme
                    .labelSmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.xs),
              Wrap(
                spacing: GxSpace.xs,
                runSpacing: GxSpace.xs,
                alignment: WrapAlignment.center,
                children: disclosures
                    .map(
                      (k) => Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: GxSpace.m,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: scheme.secondaryContainer,
                          borderRadius: GxShape.full,
                        ),
                        child: Text(
                          _humanClaimLabel(k),
                          style: Theme.of(context)
                              .textTheme
                              .labelSmall
                              ?.copyWith(color: scheme.onSecondaryContainer),
                        ),
                      ),
                    )
                    .toList(),
              ),
              const SizedBox(height: GxSpace.m),
              // Único FilledButton de esta pantalla (Regla SPEC-PIP-UI-001 §15.1)
              FilledButton.icon(
                onPressed: () => _openDisclosureModal(context),
                icon: const Icon(Icons.tune_rounded),
                label: const Text('Elegir Qué Datos Compartir'),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.l),
        Material(
          color: scheme.surfaceContainerLow,
          shape: RoundedRectangleBorder(
            borderRadius: GxShape.large,
            side: BorderSide(color: scheme.outlineVariant),
          ),
          clipBehavior: Clip.antiAlias,
          child: Theme(
            data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
            child: ExpansionTile(
              leading: Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: scheme.secondaryContainer,
                  borderRadius: GxShape.medium,
                ),
                child: Icon(
                  Icons.verified_outlined,
                  color: scheme.onSecondaryContainer,
                ),
              ),
              title: Text(
                'Diagnóstico del Verificador (4 Estados)',
                style: emphasized?.titleSmall,
              ),
              childrenPadding: const EdgeInsets.fromLTRB(
                GxSpace.l,
                0,
                GxSpace.l,
                GxSpace.l,
              ),
              children: <Widget>[
                const SizedBox(height: GxSpace.s),
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
                _buildVerificationCardForState(
                  widget.store.simulatedVerificationState,
                ),
              ],
            ),
          ),
        ),
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
          size: 52,
          label: 'Lector NFC activo',
        ),
        const SizedBox(height: GxSpace.s),
        Text(
          'Acerca tu teléfono o tarjeta física al terminal',
          textAlign: TextAlign.center,
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        GxButtonGroup<NfcOperatingMode>(
          selected: nfcMode,
          onChanged: widget.store.setNfcMode,
          segments: const <GxButtonSegment<NfcOperatingMode>>[
            GxButtonSegment<NfcOperatingMode>(
              value: NfcOperatingMode.hceCardEmulation,
              label: 'Teléfono',
              icon: Icons.phone_android_rounded,
            ),
            GxButtonSegment<NfcOperatingMode>(
              value: NfcOperatingMode.isoDepCardReader,
              label: 'Tarjeta Física',
              icon: Icons.credit_card_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.m),
        if (nfcMode == NfcOperatingMode.hceCardEmulation) ...<Widget>[
          Container(
            padding: const EdgeInsets.symmetric(
              horizontal: GxSpace.m,
              vertical: GxSpace.xs,
            ),
            decoration: BoxDecoration(
              color: scheme.surfaceContainerHighest,
              borderRadius: GxShape.medium,
            ),
            child: Row(
              children: <Widget>[
                Expanded(
                  child: Text(
                    nfcService.isArmedForTap
                        ? 'Toque NFC habilitado (60 s)'
                        : 'Toque NFC pausado',
                    style: Theme.of(context).textTheme.bodyMedium,
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
              labelText: 'PIN de la tarjeta física',
              prefixIcon: Icon(Icons.dialpad_rounded),
            ),
          ),
        ],
        const SizedBox(height: GxSpace.m),
        Center(
          child: OutlinedButton.icon(
            onPressed: () {
              widget.store.executeNfcApduPresentation(
                cardPin: _cardPinController.text,
              );
              setState(() {
                _showNfcTrace = true;
              });
            },
            icon: const Icon(Icons.contactless_rounded),
            label: Text(
              nfcMode == NfcOperatingMode.hceCardEmulation
                  ? 'Transmitir Credencial por HCE (APDU)'
                  : 'Leer Tarjeta Física NFC',
            ),
          ),
        ),
        if (_showNfcTrace && log.isNotEmpty) ...<Widget>[
          const SizedBox(height: GxSpace.m),
          Container(
            padding: const EdgeInsets.all(GxSpace.m),
            decoration: BoxDecoration(
              color: scheme.surfaceContainerHighest,
              borderRadius: GxShape.medium,
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Row(
                  children: <Widget>[
                    Icon(
                      Icons.check_circle_rounded,
                      size: 18,
                      color: semantic.success.color,
                    ),
                    const SizedBox(width: GxSpace.xs),
                    Expanded(
                      child: Text(
                        'Transmisión NFC completada (${log.length} pasos)',
                        style: emphasized?.labelLarge,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: GxSpace.xs),
                ...log.map(
                  (entry) => Padding(
                    padding: const EdgeInsets.only(top: 2),
                    child: Text(
                      entry.stepLabel,
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: scheme.onSurfaceVariant),
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
        Icon(
          Icons.fingerprint_rounded,
          size: 44,
          color: scheme.primary,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Confirma tu identidad con biometría o llave NFC',
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
              label: 'Biometría',
              icon: Icons.fingerprint_rounded,
            ),
            GxButtonSegment<PasskeyAuthenticatorTransport>(
              value: PasskeyAuthenticatorTransport.nfcSecurityKey,
              label: 'NFC',
              icon: Icons.contactless_rounded,
            ),
            GxButtonSegment<PasskeyAuthenticatorTransport>(
              value: PasskeyAuthenticatorTransport.hybridCrossDevice,
              label: 'QR / BLE',
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
                padding: const EdgeInsets.symmetric(
                  horizontal: GxSpace.m,
                  vertical: GxSpace.s,
                ),
                decoration: BoxDecoration(
                  color: isSelected
                      ? scheme.secondaryContainer
                      : scheme.surfaceContainerHighest,
                  borderRadius: GxShape.medium,
                  border: Border.all(
                    color: isSelected ? scheme.primary : scheme.outlineVariant,
                  ),
                ),
                child: Row(
                  children: <Widget>[
                    Icon(
                      isSelected
                          ? Icons.radio_button_checked_rounded
                          : Icons.radio_button_off_rounded,
                      size: 18,
                      color: scheme.primary,
                    ),
                    const SizedBox(width: GxSpace.s),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: <Widget>[
                          Text(
                            pk.displayName,
                            style: emphasized?.labelLarge,
                          ),
                          Text(
                            pk.rpId,
                            style: Theme.of(context)
                                .textTheme
                                .bodySmall
                                ?.copyWith(color: scheme.onSurfaceVariant),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          );
        }),
        const SizedBox(height: GxSpace.s),
        Center(
          child: OutlinedButton.icon(
            onPressed: () {
              widget.store.transmitPresentationViaPasskey();
            },
            icon: const Icon(Icons.fingerprint_rounded),
            label: const Text('Firmar y Transmitir con Passkey'),
          ),
        ),
        if (lastEnvelope != null) ...<Widget>[
          const SizedBox(height: GxSpace.m),
          Container(
            padding: const EdgeInsets.all(GxSpace.m),
            decoration: BoxDecoration(
              color: scheme.surfaceContainerHighest,
              borderRadius: GxShape.medium,
            ),
            child: Row(
              children: <Widget>[
                Icon(
                  Icons.verified_user_rounded,
                  size: 18,
                  color: semantic.success.color,
                ),
                const SizedBox(width: GxSpace.s),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        'Sobre PasskeyPresentationEnvelope Emitido',
                        style: emphasized?.labelLarge,
                      ),
                      Text(
                        'Verificado para ${lastEnvelope.rpId}',
                        style: Theme.of(context)
                            .textTheme
                            .bodySmall
                            ?.copyWith(color: scheme.onSurfaceVariant),
                      ),
                    ],
                  ),
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
              'Todas las etapas del pipeline offline finalizaron satisfactoriamente.',
          trustBundleInfo: 'TrustBundle v14 · Estado vigente',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Autenticación de Emisor en TrustBundle (INV-06)',
              passed: true,
              detail: 'Clave P-256 resuelta localmente sin uso de red.',
            ),
            GxVerificationCheckItem(
              stepName: '2. Firma SD-JWT y Prueba de Posesión KB-JWT',
              passed: true,
              detail: 'Firma ES256 válida vinculada a la sesión.',
            ),
          ],
        );
      case GxVerificationState.validWithStaleStatus:
        return const GxVerificationResultCard(
          state: GxVerificationState.validWithStaleStatus,
          headline: 'Válida con Lista de Estado en Ventana Offline',
          summary:
              'La firma del emisor y del titular son auténticas; estado en caché local.',
          trustBundleInfo: 'TrustBundle v14 · Caché local dentro de ventana',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Autenticación de Emisor y Firma SD-JWT + KB-JWT',
              passed: true,
              detail: 'Criptografía autenticada en local sin conexión.',
            ),
          ],
        );
      case GxVerificationState.unverifiable:
        return const GxVerificationResultCard(
          state: GxVerificationState.unverifiable,
          errorCode: 'GID-E4003',
          headline: 'Evidencia Local Insuficiente (Fail-Closed, INV-05)',
          summary:
              'Se requiere sincronizar la lista de estado antes de aceptar.',
          trustBundleInfo: 'Sincronización pendiente',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Ventana Máxima de Frescura Expirada (GID-E4003)',
              passed: false,
              detail: 'Rechazo seguro hasta actualizar caché.',
            ),
          ],
        );
      case GxVerificationState.invalid:
        return const GxVerificationResultCard(
          state: GxVerificationState.invalid,
          errorCode: 'GID-E4005',
          headline: 'Credencial Rechazada (Soporte Revocado o Firma Inválida)',
          summary:
              'El soporte figura como revocado tras un reemplazo o reporte.',
          trustBundleInfo: 'Revocación verificada en lista de estado',
          checks: <GxVerificationCheckItem>[
            GxVerificationCheckItem(
              stepName: '1. Consulta de Token Status List (GID-E4005)',
              passed: false,
              detail: 'El soporte anterior fue revocado.',
            ),
          ],
        );
    }
  }
}
