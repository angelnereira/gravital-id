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
        verifierName: 'Verificador de Punto de Atención (Offline / Proximidad)',
        verifierDomain: 'verificador.terminal.pa',
        purpose: 'Acreditación de identidad y atributos verificables (${cred.title})',
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

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final bannerOutcome = widget.store.lastProtocolBanner;

    return ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl + GxSpace.xxl,
      ),
      children: <Widget>[
        // Tarjeta hero de identidad portable y acción rápida dividida
        Container(
          padding: const EdgeInsets.all(GxSpace.xl),
          decoration: BoxDecoration(
            color: scheme.primaryContainer,
            borderRadius: GxShape.extraLarge,
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Wrap(
                spacing: GxSpace.s,
                runSpacing: GxSpace.xs,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: <Widget>[
                  StatusChip(
                    label: 'NÚCLEO SOBERANO SIN SERVIDOR CENTRAL',
                    tone: semantic.success,
                    icon: Icons.shield_rounded,
                  ),
                  StatusChip(
                    label: '3 SOPORTES DISTINTOS ACTIVOS',
                    tone: semantic.info,
                    icon: Icons.devices_other_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              Text(
                'Tu Llave Única de Identidad Portable',
                style: (emphasized?.headlineMedium ??
                        Theme.of(context).textTheme.headlineMedium)
                    ?.copyWith(color: scheme.onPrimaryContainer),
              ),
              const SizedBox(height: GxSpace.xs),
              Text(
                'Almacena tus credenciales cifradas con XChaCha20-Poly1305, '
                'comparte solo los atributos necesarios sin conexión y reutiliza tu Gravital ID '
                'en diferentes aplicaciones, teléfonos o tarjetas tipo Visa sin duplicar tu identidad.',
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: scheme.onPrimaryContainer),
              ),
              const SizedBox(height: GxSpace.l),
              Wrap(
                spacing: GxSpace.m,
                runSpacing: GxSpace.s,
                crossAxisAlignment: WrapCrossAlignment.center,
                children: <Widget>[
                  GxSplitButton<PresentationTransport>(
                    label: 'Compartir / Presentar Ahora',
                    icon: Icons.qr_code_2_rounded,
                    onPressed: () => _openConsentSheetForSelected(context),
                    items: const <GxSplitButtonMenuItem<PresentationTransport>>[
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.qrOffline,
                        label: 'Presentar por QR Offline (Base45)',
                        subtitle: 'Óptico sin red · bloquea retrato por tamaño',
                        icon: Icons.qr_code_2_rounded,
                      ),
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.nfcApdu,
                        label: 'Transmitir por Toque NFC (GID-APDU)',
                        subtitle: 'HCE en teléfono o Lector ISO-DEP + HPKE',
                        icon: Icons.contactless_rounded,
                      ),
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.passkey,
                        label: 'Transmitir vía Passkey (FIDO2 / WebAuthn)',
                        subtitle:
                            'Aserción ES256 en StrongBox / Secure Enclave o Llave NFC CTAP2',
                        icon: Icons.fingerprint_rounded,
                      ),
                      GxSplitButtonMenuItem<PresentationTransport>(
                        value: PresentationTransport.sessionCode,
                        label: 'Código de Sesión 10 Dígitos (Damm)',
                        subtitle: 'Atención remota o telefónica sin cámara',
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
                    icon: const Icon(Icons.credit_card_rounded, size: 18),
                    label: const Text('Ver Soportes (Móvil / Visa / Otro)'),
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
        const SizedBox(height: GxSpace.xl),
        Text(
          'Credenciales en tu Bóveda Cifrada (${widget.store.credentials.length})',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Selecciona una credencial para inspeccionar sus atributos de divulgación selectiva (_sd) o presentarla.',
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
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
              deviceClassLabel: cred.factorClass.code,
              securityLevelLabel: cred.securityLevelLabel,
              remainingBatchCopies: cred.remainingBatchCopies,
              claimsCount: cred.claims.length,
              documentNumberMasked: cred.documentNumberMasked,
              hasPortrait: cred.hasPortrait,
              isOfficialStateCredential: cred.isOfficialStateCredential,
              isSelected: index == widget.store.selectedCredentialIndex,
              onTap: () => widget.store.selectCredential(index),
              onPresentPressed: () {
                widget.store.selectCredential(index);
                _openConsentSheetForSelected(context);
              },
            ),
          );
        }),
        const SizedBox(height: GxSpace.l),
        // Sección interactiva de Unicidad Ciudadana y Cumplimiento Tribunal Electoral de Panamá (ADR-0028)
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
              Row(
                children: <Widget>[
                  Container(
                    width: 44,
                    height: 44,
                    decoration: BoxDecoration(
                      color: scheme.secondaryContainer,
                      borderRadius: GxShape.large,
                    ),
                    child: Icon(
                      Icons.fact_check_rounded,
                      color: scheme.onSecondaryContainer,
                    ),
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text(
                          'Control de Unicidad Ciudadana (Tribunal Electoral Panamá)',
                          style: emphasized?.titleMedium,
                        ),
                        Text(
                          'Decreto N.° 43 de 8 de octubre de 2024 · SVI · Etiqueta Ciega VOPRF (RFC 9497)',
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
              const SizedBox(height: GxSpace.m),
              Text(
                'Evita que una misma cédula cree dos Gravital ID distintos sin publicar ningún dato personal en la blockchain (INV-02). '
                'Prueba con "8-888-8888" (ya registrada → dispara GID-E2010) o con una cédula nueva como "4-752-1940" o "PE-12-345".',
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
                  hintText: 'Ej. 8-888-8888, 4-752-1940, PE-12-345, E-8-123456',
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
                  FilledButton.icon(
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
      ],
    );
  }
}

/// Panel secundario de detalle de credencial para ventanas `WindowClass.expanded+` (2 paneles).
class VaultCredentialDetailPane extends StatelessWidget {
  const VaultCredentialDetailPane({
    required this.store,
    required this.onPresentSelected,
    super.key,
  });

  final GravitalWalletStore store;
  final VoidCallback onPresentSelected;

  @override
  Widget build(BuildContext context) {
    final cred = store.selectedCredential;
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return ListView(
      padding: const EdgeInsets.all(GxSpace.l),
      children: <Widget>[
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
                'Inspección de Divulgaciones Selectivas (_sd)',
                style: emphasized?.titleLarge,
              ),
              const SizedBox(height: GxSpace.xs),
              GxTabularCodeText(
                'vct: ${cred.vct}',
                style: Theme.of(context).textTheme.labelSmall,
                color: scheme.primary,
              ),
              const SizedBox(height: GxSpace.xs),
              GxTabularCodeText(
                'Emisor en TrustBundle: ${cred.issuerId}',
                style: Theme.of(context).textTheme.labelSmall,
                color: scheme.onSurfaceVariant,
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
                              '${claim.key} = ${claim.valuePreview}',
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
                  icon: const Icon(Icons.share_rounded, size: 18),
                  label: const Text('Configurar Divulgación Selectiva'),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
