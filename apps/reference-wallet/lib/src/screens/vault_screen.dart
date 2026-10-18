// Pantalla de Bóveda de Credenciales y Validación Ciudadana SVI (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-UI-001, REQ-UI-003, REQ-UI-004, REQ-IDDOC-001, REQ-UNIQ-001, REQ-UNIQ-002, REQ-UNIQ-003

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Vista principal de la bóveda de credenciales del titular.
class VaultScreen extends StatefulWidget {
  const VaultScreen({
    required this.store,
    required this.onNavigateToPresent,
    required this.onNavigateToDevices,
    super.key,
  });

  final GravitalWalletStore store;
  final ValueChanged<PresentationTransport> onNavigateToPresent;
  final VoidCallback onNavigateToDevices;

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  final TextEditingController _cedulaController =
      TextEditingController(text: '8-888-8888');
  final TextEditingController _nameController =
      TextEditingController(text: 'Ángel Gabriel Nereira');

  @override
  void dispose() {
    _cedulaController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  void _openConsentSheetForSelected(BuildContext context) {
    final cred = widget.store.selectedCredential;
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (sheetContext) => GxDisclosureConsentSheet(
        verifierName: 'Punto de Atención / Verificador',
        verifierDomain: 'verificador.terminal.pa',
        purpose: 'Acreditación de identidad (${cred.title})',
        transportLabel: widget.store.activeTransport.label,
        isVerifierSigned: true,
        claims: cred.claims,
        onConfirmDisclosures: (selectedKeys) {
          widget.store.updateConfirmedDisclosures(selectedKeys);
          Navigator.of(sheetContext).pop();
          widget.onNavigateToPresent(widget.store.activeTransport);
        },
      ),
    );
  }

  void _showCredentialDetailSheet(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (sheetContext) => DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.65,
        minChildSize: 0.45,
        maxChildSize: 0.9,
        builder: (_, scrollController) => SingleChildScrollView(
          controller: scrollController,
          child: VaultCredentialDetailPane(
            store: widget.store,
            shrinkWrap: true,
            onPresentSelected: () {
              Navigator.of(sheetContext).pop();
              _openConsentSheetForSelected(context);
            },
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final bannerOutcome = widget.store.lastProtocolBanner;
    final isTwoPane = WindowClass.of(context).isTwoPane;

    return ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl,
      ),
      children: <Widget>[
        // Tarjeta principal de identidad portable
        Container(
          padding: const EdgeInsets.all(GxSpace.l),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerLow,
            borderRadius: GxShape.extraLarge,
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(
                'Tu Llave Única de Identidad Portable',
                style: emphasized?.titleLarge ??
                    Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: GxSpace.xs),
              Text(
                'Comparte solo los datos que autorices por QR, NFC o Passkey.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.m),
              Wrap(
                spacing: GxSpace.m,
                runSpacing: GxSpace.s,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: <Widget>[
                  GxSplitButton<PresentationTransport>(
                    label: 'Presentar Credencial',
                    icon: Icons.qr_code_2_rounded,
                    onPressed: () => _openConsentSheetForSelected(context),
                    items: const <GxSplitButtonMenuItem<PresentationTransport>>[
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.qrOffline,
                        label: 'Código QR (Sin conexión)',
                        subtitle: 'Escaneo rápido en punto de atención',
                        icon: Icons.qr_code_2_rounded,
                      ),
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.nfcApdu,
                        label: 'Toque NFC (Sin contacto)',
                        subtitle: 'Acerca tu teléfono o tarjeta inteligente',
                        icon: Icons.contactless_rounded,
                      ),
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.passkey,
                        label: 'Passkey Biométrica',
                        subtitle: 'Confirmación con huella o rostro',
                        icon: Icons.fingerprint_rounded,
                      ),
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.sessionCode,
                        label: 'Código de 10 dígitos',
                        subtitle: 'Para atención telefónica o remota',
                        icon: Icons.dialpad_rounded,
                      ),
                    ],
                    onItemSelected: (transport) {
                      widget.store.setTransport(transport);
                      _openConsentSheetForSelected(context);
                    },
                  ),
                  OutlinedButton.icon(
                    onPressed: widget.onNavigateToDevices,
                    icon: const Icon(Icons.devices_other_rounded, size: 18),
                    label: const Text('Mis Soportes'),
                  ),
                ],
              ),
            ],
          ),
        ),
        if (bannerOutcome != null) ...<Widget>[
          const SizedBox(height: GxSpace.l),
          if (bannerOutcome.succeeded)
            Container(
              padding: const EdgeInsets.all(GxSpace.l),
              decoration: BoxDecoration(
                color: semantic.success.container,
                borderRadius: GxShape.large,
                border: Border.all(color: semantic.success.color),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Row(
                    children: <Widget>[
                      Icon(
                        Icons.verified_rounded,
                        color: semantic.success.onContainer,
                      ),
                      const SizedBox(width: GxSpace.s),
                      Expanded(
                        child: Text(
                          bannerOutcome.title,
                          style: emphasized?.titleMedium?.copyWith(
                            color: semantic.success.onContainer,
                          ),
                        ),
                      ),
                      IconButton(
                        onPressed: widget.store.clearProtocolBanner,
                        icon: const Icon(Icons.close_rounded),
                        tooltip: 'Cerrar aviso',
                      ),
                    ],
                  ),
                  Text(
                    bannerOutcome.description,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: semantic.success.onContainer,
                        ),
                  ),
                ],
              ),
            )
          else
            GxErrorState(
              errorCode: bannerOutcome.errorCode ?? 'GID-E2010',
              identifier:
                  bannerOutcome.errorIdentifier ?? 'CitizenIdentityAlreadyRegistered',
              title: bannerOutcome.title,
              description: bannerOutcome.description,
              remediationLabel: 'Ir a Recuperación / Reemplazo de Soporte',
              onRemediate: widget.onNavigateToDevices,
            ),
        ],
        const SizedBox(height: GxSpace.l),
        Text(
          'Mis Credenciales (${widget.store.credentials.length})',
          style: emphasized?.titleMedium,
        ),
        const SizedBox(height: GxSpace.s),
        ...List<Widget>.generate(widget.store.credentials.length, (index) {
          final cred = widget.store.credentials[index];
          return Padding(
            padding: const EdgeInsets.only(bottom: GxSpace.m),
            child: GxCredentialCard(
              title: cred.title,
              subtitle: cred.subtitle,
              vct: cred.vct,
              issuerName: cred.issuerName,
              statusState: widget.store.isOfflineMode
                  ? GxVerificationState.validWithStaleStatus
                  : cred.statusState,
              deviceClassLabel: cred.factorClass.title,
              securityLevelLabel: cred.securityLevelLabel,
              remainingBatchCopies: cred.remainingBatchCopies,
              claimsCount: cred.claims.length,
              documentNumberMasked: cred.documentNumberMasked,
              hasPortrait: cred.hasPortrait,
              isOfficialStateCredential: cred.isOfficialStateCredential,
              isSelected: index == widget.store.selectedCredentialIndex,
              onTap: () {
                widget.store.selectCredential(index);
                if (!isTwoPane) {
                  _showCredentialDetailSheet(context);
                }
              },
              onPresentPressed: () {
                widget.store.selectCredential(index);
                _openConsentSheetForSelected(context);
              },
            ),
          );
        }),
        const SizedBox(height: GxSpace.s),
        // Sección plegable de Unicidad Ciudadana (Tribunal Electoral)
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
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: scheme.secondaryContainer,
                  borderRadius: GxShape.medium,
                ),
                child: Icon(
                  Icons.fact_check_rounded,
                  size: 18,
                  color: scheme.onSecondaryContainer,
                ),
              ),
              title: Text(
                'Verificación de Unicidad Ciudadana (SVI)',
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
                Text(
                  'Garantiza que una misma cédula no registre identidades duplicadas sin exponer datos personales.',
                  style: Theme.of(context)
                      .textTheme
                      .bodySmall
                      ?.copyWith(color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: GxSpace.m),
                TextField(
                  controller: _cedulaController,
                  decoration: const InputDecoration(
                    labelText: 'Número de Cédula Panameña (Formato TE)',
                    hintText: 'Ej. 8-888-8888 o 4-752-1940',
                    prefixIcon: Icon(Icons.badge_outlined),
                  ),
                ),
                const SizedBox(height: GxSpace.m),
                TextField(
                  controller: _nameController,
                  decoration: const InputDecoration(
                    labelText: 'Nombre Completo Verificado por SVI',
                    prefixIcon: Icon(Icons.person_outline_rounded),
                  ),
                ),
                const SizedBox(height: GxSpace.m),
                Wrap(
                  spacing: GxSpace.s,
                  runSpacing: GxSpace.xs,
                  children: <Widget>[
                    OutlinedButton.icon(
                      onPressed: () {
                        widget.store.attemptCitizenRegistration(
                          rawCedula: _cedulaController.text,
                          fullName: _nameController.text,
                        );
                      },
                      icon: const Icon(Icons.verified_user_rounded, size: 18),
                      label: const Text('Verificar Unicidad SVI (VOPRF)'),
                    ),
                    OutlinedButton(
                      onPressed: () {
                        setState(() {
                          _cedulaController.text = '8-888-8888';
                        });
                        widget.store.attemptCitizenRegistration(
                          rawCedula: '8-888-8888',
                          fullName: _nameController.text,
                        );
                      },
                      child: const Text('Simular Cédula Duplicada (GID-E2010)'),
                    ),
                    TextButton(
                      onPressed: () {
                        setState(() {
                          _cedulaController.text = '4-752-1940';
                        });
                      },
                      child: const Text('Cargar Cédula Nueva (4-752-1940)'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

/// Panel de detalle de credencial para ventanas de 2 paneles o sábana modal en móvil.
class VaultCredentialDetailPane extends StatelessWidget {
  const VaultCredentialDetailPane({
    required this.store,
    required this.onPresentSelected,
    this.shrinkWrap = false,
    super.key,
  });

  final GravitalWalletStore store;
  final VoidCallback onPresentSelected;
  final bool shrinkWrap;

  @override
  Widget build(BuildContext context) {
    final cred = store.selectedCredential;
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    final card = Container(
      padding: const EdgeInsets.all(GxSpace.l),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLow,
        borderRadius: GxShape.extraLarge,
        border: Border.all(color: scheme.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Text(
            cred.title,
            style: emphasized?.titleLarge,
          ),
          const SizedBox(height: GxSpace.xs),
          Text(
            'Emitida por ${cred.issuerName}',
            style: Theme.of(context)
                .textTheme
                .bodySmall
                ?.copyWith(color: scheme.onSurfaceVariant),
          ),
          const SizedBox(height: GxSpace.m),
          const Divider(),
          const SizedBox(height: GxSpace.s),
          ...cred.claims.map(
            (claim) => Padding(
              padding: const EdgeInsets.symmetric(vertical: GxSpace.xs),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Icon(
                    claim.isSensitiveLevel1
                        ? Icons.lock_person_rounded
                        : Icons.check_circle_outline_rounded,
                    size: 18,
                    color: claim.isSensitiveLevel1
                        ? scheme.tertiary
                        : scheme.primary,
                  ),
                  const SizedBox(width: GxSpace.s),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text(
                          claim.label,
                          style: emphasized?.labelLarge,
                        ),
                        GxTabularCodeText(
                          claim.valuePreview,
                          style: Theme.of(context).textTheme.bodySmall,
                          color: scheme.onSurfaceVariant,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: GxSpace.l),
          Align(
            alignment: Alignment.centerRight,
            child: OutlinedButton.icon(
              onPressed: onPresentSelected,
              icon: const Icon(Icons.qr_code_2_rounded, size: 18),
              label: const Text('Elegir Datos y Presentar'),
            ),
          ),
        ],
      ),
    );

    if (shrinkWrap) {
      return Padding(
        padding: const EdgeInsets.all(GxSpace.l),
        child: card,
      );
    }

    return ListView(
      padding: const EdgeInsets.all(GxSpace.l),
      children: <Widget>[card],
    );
  }
}
