// Componentes de dominio de Gravital-Experience-UI (SPEC-PIP-UI-001 §9.1, §10).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004, REQ-TENANT-003, REQ-DEVSLOT-001

import 'package:flutter/material.dart';

import '../adapters/expressive_adapters.dart';
import '../theme/gx_theme.dart';
import '../theme/semantic_colors.dart';
import '../tokens/tokens.dart';

/// Texto monetario con cifras tabulares (`tnum`) y signo explícito (SPEC-PIP-UI-001 §10.1).
///
/// Nunca depende únicamente del color verde/rojo para distinguir ingresos de cargos.
class MoneyText extends StatelessWidget {
  const MoneyText({
    required this.amount,
    this.currency = r'B/. ',
    this.style,
    super.key,
  });

  final double amount;
  final String currency;
  final TextStyle? style;

  @override
  Widget build(BuildContext context) {
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final isPositive = amount >= 0;
    final tone = isPositive ? semantic.moneyIn : semantic.moneyOut;
    final baseStyle = style ?? Theme.of(context).textTheme.titleMedium!;
    final sign = isPositive ? '+' : '−';
    final formatted =
        '$sign$currency${amount.abs().toStringAsFixed(2)}';

    return Text(
      formatted,
      style: GxTypography.tabular(baseStyle).copyWith(color: tone.color),
    );
  }
}

/// Texto con cifras tabulares (`tnum`) para códigos de sesión Damm, CPLC, IMEI o identificadores.
class GxTabularCodeText extends StatelessWidget {
  const GxTabularCodeText(
    this.text, {
    this.style,
    this.color,
    super.key,
  });

  final String text;
  final TextStyle? style;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final baseStyle = style ?? Theme.of(context).textTheme.titleMedium!;
    return Text(
      text,
      style: GxTypography.tabular(baseStyle).copyWith(color: color),
    );
  }
}

/// Etiqueta semántica de estado con icono y texto (cumple WCAG 1.4.1, SPEC-PIP-UI-001 §10.2).
class StatusChip extends StatelessWidget {
  const StatusChip({
    required this.label,
    required this.tone,
    required this.icon,
    super.key,
  });

  /// Construye un [StatusChip] directamente desde uno de los 4 estados de `VerificationResult`.
  factory StatusChip.fromVerificationState({
    required GxVerificationState state,
    required SemanticColors semantic,
    required ColorScheme scheme,
    Key? key,
  }) =>
      StatusChip(
        key: key,
        label: state.label,
        tone: semantic.toneForVerificationState(state, scheme),
        icon: state.icon,
      );

  final String label;
  final SemanticTone tone;
  final IconData icon;

  @override
  Widget build(BuildContext context) => Semantics(
        label: 'Estado: $label',
        child: Container(
          padding: const EdgeInsets.symmetric(
            horizontal: GxSpace.m,
            vertical: GxSpace.xs,
          ),
          decoration: BoxDecoration(
            color: tone.container,
            borderRadius: GxShape.full,
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Icon(icon, size: 16, color: tone.onContainer),
              const SizedBox(width: GxSpace.xs),
              Flexible(
                child: Text(
                  label,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context)
                      .textTheme
                      .labelMedium
                      ?.copyWith(color: tone.onContainer),
                ),
              ),
            ],
          ),
        ),
      );
}

/// Paso de evidencia individual dentro de [GxVerificationResultCard].
@immutable
class GxVerificationCheckItem {
  const GxVerificationCheckItem({
    required this.stepName,
    required this.passed,
    required this.detail,
    this.skipped = false,
  });

  final String stepName;
  final bool passed;
  final String detail;
  final bool skipped;
}

/// Tarjeta normativa de resultado de verificación de 4 estados (`INV-04`, `REQ-UI-002`).
///
/// Muestra el estado (`Valid`, `ValidWithStaleStatus`, `Unverifiable`, `Invalid`),
/// el código de error si aplica, la frescura del `TrustBundle` y la lista de comprobaciones.
class GxVerificationResultCard extends StatelessWidget {
  const GxVerificationResultCard({
    required this.state,
    required this.headline,
    required this.summary,
    required this.checks,
    this.errorCode,
    this.trustBundleInfo,
    super.key,
  });

  final GxVerificationState state;
  final String headline;
  final String summary;
  final List<GxVerificationCheckItem> checks;
  final String? errorCode;
  final String? trustBundleInfo;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final tone = semantic.toneForVerificationState(state, scheme);

    return Container(
      padding: const EdgeInsets.all(GxSpace.l),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLow,
        borderRadius: GxShape.extraLarge,
        border: Border.all(color: tone.color, width: 1.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Wrap(
            spacing: GxSpace.s,
            runSpacing: GxSpace.xs,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: <Widget>[
              StatusChip.fromVerificationState(
                state: state,
                semantic: semantic,
                scheme: scheme,
              ),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: GxSpace.s,
                  vertical: 2,
                ),
                decoration: BoxDecoration(
                  color: scheme.surfaceContainerHighest,
                  borderRadius: GxShape.small,
                ),
                child: GxTabularCodeText(
                  state.protocolStateName,
                  style: Theme.of(context).textTheme.labelSmall,
                  color: scheme.onSurfaceVariant,
                ),
              ),
              if (errorCode != null)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: GxSpace.s,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: tone.container,
                    borderRadius: GxShape.small,
                  ),
                  child: GxTabularCodeText(
                    errorCode!,
                    style: Theme.of(context).textTheme.labelSmall,
                    color: tone.onContainer,
                  ),
                ),
            ],
          ),
          const SizedBox(height: GxSpace.m),
          Text(
            headline,
            style: emphasized?.titleLarge ??
                Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: GxSpace.xs),
          Text(
            summary,
            style: Theme.of(context)
                .textTheme
                .bodyMedium
                ?.copyWith(color: scheme.onSurfaceVariant),
          ),
          if (trustBundleInfo != null) ...<Widget>[
            const SizedBox(height: GxSpace.s),
            Text(
              trustBundleInfo!,
              style: GxTypography.tabular(
                Theme.of(context).textTheme.labelSmall,
              ).copyWith(color: scheme.primary),
            ),
          ],
          const SizedBox(height: GxSpace.m),
          const Divider(),
          const SizedBox(height: GxSpace.s),
          ...checks.map((check) {
            final IconData checkIcon;
            final Color checkColor;
            if (check.skipped) {
              checkIcon = Icons.remove_circle_outline_rounded;
              checkColor = scheme.outline;
            } else if (check.passed) {
              checkIcon = Icons.check_circle_rounded;
              checkColor = semantic.success.color;
            } else {
              checkIcon = Icons.cancel_rounded;
              checkColor = scheme.error;
            }

            return Padding(
              padding: const EdgeInsets.symmetric(vertical: GxSpace.xs),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Icon(checkIcon, size: 18, color: checkColor),
                  const SizedBox(width: GxSpace.s),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text(
                          check.stepName,
                          style: emphasized?.labelLarge ??
                              Theme.of(context).textTheme.labelLarge,
                        ),
                        Text(
                          check.detail,
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
            );
          }),
        ],
      ),
    );
  }
}

/// Modelo de atributo divulgable selectivamente (`_sd`) para [GxCredentialCard] y [GxDisclosureConsentSheet].
@immutable
class GxDisclosableClaim {
  const GxDisclosableClaim({
    required this.key,
    required this.label,
    required this.valuePreview,
    this.isRequiredByVerifier = false,
    this.isSensitiveLevel1 = false,
    this.initiallySelected = true,
  });

  final String key;
  final String label;
  final String valuePreview;
  final bool isRequiredByVerifier;
  final bool isSensitiveLevel1;
  final bool initiallySelected;
}

/// Tarjeta expresiva de credencial verificable (`GxCredentialCard`, SPEC-PIP-UI-001 §9.1).
class GxCredentialCard extends StatelessWidget {
  const GxCredentialCard({
    required this.title,
    required this.subtitle,
    required this.vct,
    required this.issuerName,
    required this.statusState,
    required this.deviceClassLabel,
    required this.securityLevelLabel,
    required this.remainingBatchCopies,
    required this.claimsCount,
    this.documentNumberMasked,
    this.hasPortrait = false,
    this.isOfficialStateCredential = false,
    this.isSelected = false,
    this.onTap,
    this.onPresentPressed,
    super.key,
  });

  final String title;
  final String subtitle;
  final String vct;
  final String issuerName;
  final GxVerificationState statusState;
  final String deviceClassLabel;
  final String securityLevelLabel;
  final int remainingBatchCopies;
  final int claimsCount;
  final String? documentNumberMasked;
  final bool hasPortrait;
  final bool isOfficialStateCredential;
  final bool isSelected;
  final VoidCallback? onTap;
  final VoidCallback? onPresentPressed;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return GxSpringScale(
      onTap: onTap,
      semanticLabel: '$title emitida por $issuerName',
      child: Container(
        padding: const EdgeInsets.all(GxSpace.l),
        decoration: BoxDecoration(
          color: isSelected
              ? scheme.secondaryContainer.withValues(alpha: 0.45)
              : scheme.surfaceContainerLow,
          borderRadius: GxShape.extraLarge,
          border: Border.all(
            color: isSelected ? scheme.primary : scheme.outlineVariant,
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                if (hasPortrait) ...<Widget>[
                  Container(
                    width: 56,
                    height: 68,
                    decoration: BoxDecoration(
                      color: scheme.primaryContainer,
                      borderRadius: GxShape.medium,
                      border: Border.all(color: scheme.primary, width: 1.5),
                    ),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: <Widget>[
                        Icon(
                          Icons.account_box_rounded,
                          size: 30,
                          color: scheme.onPrimaryContainer,
                        ),
                        Text(
                          'JPEG',
                          style: Theme.of(context)
                              .textTheme
                              .labelSmall
                              ?.copyWith(color: scheme.onPrimaryContainer),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: GxSpace.m),
                ] else ...<Widget>[
                  Container(
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: scheme.primaryContainer,
                      borderRadius: GxShape.large,
                    ),
                    child: Icon(
                      Icons.badge_rounded,
                      color: scheme.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(width: GxSpace.m),
                ],
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Wrap(
                        spacing: GxSpace.xs,
                        runSpacing: GxSpace.xs,
                        children: <Widget>[
                          StatusChip.fromVerificationState(
                            state: statusState,
                            semantic: semantic,
                            scheme: scheme,
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: GxSpace.s,
                              vertical: GxSpace.xs,
                            ),
                            decoration: BoxDecoration(
                              color: isOfficialStateCredential
                                  ? scheme.primaryContainer
                                  : scheme.tertiaryContainer,
                              borderRadius: GxShape.full,
                            ),
                            child: Text(
                              isOfficialStateCredential
                                  ? 'OFICIAL ESTADO (TE)'
                                  : 'DERIVADA / VERIFICADA',
                              style: Theme.of(context)
                                  .textTheme
                                  .labelSmall
                                  ?.copyWith(
                                    color: isOfficialStateCredential
                                        ? scheme.onPrimaryContainer
                                        : scheme.onTertiaryContainer,
                                  ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: GxSpace.s),
                      Text(
                        title,
                        style: emphasized?.titleLarge ??
                            Theme.of(context).textTheme.titleLarge,
                      ),
                      Text(
                        subtitle,
                        style: Theme.of(context)
                            .textTheme
                            .bodyMedium
                            ?.copyWith(color: scheme.onSurfaceVariant),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: GxSpace.m),
            Wrap(
              spacing: GxSpace.s,
              runSpacing: GxSpace.xs,
              children: <Widget>[
                _MetaBadge(
                  icon: Icons.account_balance_rounded,
                  label: issuerName,
                ),
                _MetaBadge(
                  icon: Icons.memory_rounded,
                  label: '$deviceClassLabel · $securityLevelLabel',
                ),
                _MetaBadge(
                  icon: Icons.layers_rounded,
                  label: '$remainingBatchCopies copias de lote',
                ),
                _MetaBadge(
                  icon: Icons.tune_rounded,
                  label: '$claimsCount atributos _sd',
                ),
                if (documentNumberMasked != null)
                  _MetaBadge(
                    icon: Icons.pin_rounded,
                    label: documentNumberMasked!,
                    tabular: true,
                  ),
              ],
            ),
            const SizedBox(height: GxSpace.m),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: <Widget>[
                Flexible(
                  child: GxTabularCodeText(
                    vct,
                    style: Theme.of(context).textTheme.labelSmall,
                    color: scheme.onSurfaceVariant,
                  ),
                ),
                if (onPresentPressed != null)
                  TextButton.icon(
                    onPressed: onPresentPressed,
                    icon: const Icon(Icons.qr_code_2_rounded, size: 18),
                    label: const Text('Compartir / Acceso'),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _MetaBadge extends StatelessWidget {
  const _MetaBadge({
    required this.icon,
    required this.label,
    this.tabular = false,
  });

  final IconData icon;
  final String label;
  final bool tabular;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final style = Theme.of(context)
        .textTheme
        .labelSmall
        ?.copyWith(color: scheme.onSurfaceVariant);

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: GxSpace.s,
        vertical: GxSpace.xs,
      ),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: GxShape.small,
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Icon(icon, size: 14, color: scheme.primary),
          const SizedBox(width: 4),
          Flexible(
            child: Text(
              label,
              overflow: TextOverflow.ellipsis,
              style: tabular ? GxTypography.tabular(style) : style,
            ),
          ),
        ],
      ),
    );
  }
}

/// Hoja de consentimiento de divulgación selectiva en dos pasos (`GxDisclosureConsentSheet`,
/// `REQ-UI-003`, `REQ-PRES-003`, `ADR-0027`, `ADR-0030`).
///
/// Materializa la separación `prepare_presentation` (vista previa con interruptores por atributo)
/// y `confirm_presentation` (autorización explícita del usuario con aviso de Nivel 1).
class GxDisclosureConsentSheet extends StatefulWidget {
  const GxDisclosureConsentSheet({
    required this.verifierName,
    required this.verifierDomain,
    required this.purpose,
    required this.transportLabel,
    required this.isVerifierSigned,
    required this.claims,
    required this.onConfirmDisclosures,
    this.tenantSubjectIdPreview,
    this.onCancel,
    super.key,
  });

  final String verifierName;
  final String verifierDomain;
  final String purpose;
  final String transportLabel;
  final bool isVerifierSigned;
  final List<GxDisclosableClaim> claims;
  final ValueChanged<Set<String>> onConfirmDisclosures;
  final String? tenantSubjectIdPreview;
  final VoidCallback? onCancel;

  @override
  State<GxDisclosureConsentSheet> createState() =>
      _GxDisclosureConsentSheetState();
}

class _GxDisclosureConsentSheetState extends State<GxDisclosureConsentSheet> {
  late final Set<String> _selectedKeys = widget.claims
      .where((c) => c.isRequiredByVerifier || c.initiallySelected)
      .map((c) => c.key)
      .toSet();

  bool get _includesLevel1Claims => widget.claims.any(
        (c) => c.isSensitiveLevel1 && _selectedKeys.contains(c.key),
      );

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return Padding(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.s,
        GxSpace.l,
        GxSpace.xl,
      ),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Row(
              children: <Widget>[
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    color: scheme.primaryContainer,
                    borderRadius: GxShape.large,
                  ),
                  child: Icon(
                    Icons.privacy_tip_rounded,
                    color: scheme.onPrimaryContainer,
                  ),
                ),
                const SizedBox(width: GxSpace.m),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        'Consentimiento de Divulgación Selectiva',
                        style: emphasized?.titleMedium ??
                            Theme.of(context).textTheme.titleMedium,
                      ),
                      Text(
                        'Paso 1: prepare_presentation · Tú decides qué datos compartir',
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
            const SizedBox(height: GxSpace.l),
            Container(
              padding: const EdgeInsets.all(GxSpace.m),
              decoration: BoxDecoration(
                color: scheme.surfaceContainerHigh,
                borderRadius: GxShape.large,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Row(
                    children: <Widget>[
                      Expanded(
                        child: Text(
                          widget.verifierName,
                          style: emphasized?.titleMedium,
                        ),
                      ),
                      StatusChip(
                        label: widget.isVerifierSigned
                            ? 'SOLICITUD FIRMADA'
                            : 'NO FIRMADA',
                        tone: widget.isVerifierSigned
                            ? semantic.success
                            : semantic.warning,
                        icon: widget.isVerifierSigned
                            ? Icons.verified_rounded
                            : Icons.warning_amber_rounded,
                      ),
                    ],
                  ),
                  const SizedBox(height: GxSpace.xs),
                  GxTabularCodeText(
                    'Dominio: ${widget.verifierDomain} · Canal: ${widget.transportLabel}',
                    style: Theme.of(context).textTheme.labelSmall,
                    color: scheme.onSurfaceVariant,
                  ),
                  const SizedBox(height: GxSpace.xs),
                  Text(
                    'Propósito declarado: ${widget.purpose}',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                  if (widget.tenantSubjectIdPreview != null) ...<Widget>[
                    const SizedBox(height: GxSpace.xs),
                    GxTabularCodeText(
                      'ID de Inquilino (Pairwise): ${widget.tenantSubjectIdPreview}',
                      style: Theme.of(context).textTheme.labelSmall,
                      color: scheme.primary,
                    ),
                  ],
                ],
              ),
            ),
            if (_includesLevel1Claims) ...<Widget>[
              const SizedBox(height: GxSpace.m),
              Container(
                padding: const EdgeInsets.all(GxSpace.m),
                decoration: BoxDecoration(
                  color: semantic.warning.container,
                  borderRadius: GxShape.medium,
                ),
                child: Row(
                  children: <Widget>[
                    Icon(
                      Icons.fingerprint_rounded,
                      color: semantic.warning.onContainer,
                    ),
                    const SizedBox(width: GxSpace.s),
                    Expanded(
                      child: Text(
                        'Incluye atributos sensibles de Nivel 1 (cédula, fecha de nacimiento o retrato). Requiere autenticación biométrica/PIN al confirmar.',
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                              color: semantic.warning.onContainer,
                            ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: GxSpace.m),
            Text(
              'Atributos seleccionados (${_selectedKeys.length} de ${widget.claims.length}):',
              style: emphasized?.labelLarge,
            ),
            const SizedBox(height: GxSpace.s),
            ...widget.claims.map((claim) {
              final isSelected = _selectedKeys.contains(claim.key);
              return Padding(
                padding: const EdgeInsets.only(bottom: GxSpace.xs),
                child: Material(
                  color: isSelected
                      ? scheme.secondaryContainer.withValues(alpha: 0.45)
                      : scheme.surfaceContainer,
                  borderRadius: GxShape.medium,
                  child: SwitchListTile(
                    dense: true,
                    shape: const RoundedRectangleBorder(
                      borderRadius: GxShape.medium,
                    ),
                    value: isSelected,
                    onChanged: claim.isRequiredByVerifier
                        ? null
                        : (checked) {
                            setState(() {
                              if (checked) {
                                _selectedKeys.add(claim.key);
                              } else {
                                _selectedKeys.remove(claim.key);
                              }
                            });
                          },
                    title: Row(
                      children: <Widget>[
                        Expanded(
                          child: Text(
                            claim.label,
                            style: emphasized?.labelLarge,
                          ),
                        ),
                        if (claim.isSensitiveLevel1)
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: GxSpace.s,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: semantic.warning.container,
                              borderRadius: GxShape.full,
                            ),
                            child: Text(
                              'NIVEL 1',
                              style: Theme.of(context)
                                  .textTheme
                                  .labelSmall
                                  ?.copyWith(
                                    color: semantic.warning.onContainer,
                                  ),
                            ),
                          ),
                        const SizedBox(width: GxSpace.xs),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: GxSpace.s,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: claim.isRequiredByVerifier
                                ? scheme.primaryContainer
                                : scheme.surfaceContainerHighest,
                            borderRadius: GxShape.full,
                          ),
                          child: Text(
                            claim.isRequiredByVerifier
                                ? 'REQUERIDO'
                                : 'OPCIONAL',
                            style:
                                Theme.of(context).textTheme.labelSmall?.copyWith(
                                      color: claim.isRequiredByVerifier
                                          ? scheme.onPrimaryContainer
                                          : scheme.onSurfaceVariant,
                                    ),
                          ),
                        ),
                      ],
                    ),
                    subtitle: GxTabularCodeText(
                      '${claim.key}: ${claim.valuePreview}',
                      style: Theme.of(context).textTheme.bodySmall,
                      color: scheme.onSurfaceVariant,
                    ),
                  ),
                ),
              );
            }),
            const SizedBox(height: GxSpace.l),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: <Widget>[
                OutlinedButton(
                  onPressed:
                      widget.onCancel ?? () => Navigator.of(context).maybePop(),
                  child: const Text('Rechazar'),
                ),
                const SizedBox(width: GxSpace.m),
                FilledButton.icon(
                  onPressed: () =>
                      widget.onConfirmDisclosures(Set.unmodifiable(_selectedKeys)),
                  icon: Icon(
                    _includesLevel1Claims
                        ? Icons.fingerprint_rounded
                        : Icons.check_circle_outline_rounded,
                  ),
                  label: Text(
                    _includesLevel1Claims
                        ? 'Autenticar y Firmar KB-JWT'
                        : 'Confirmar y Compartir',
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

/// Tarjeta de ranura única por clase de factor de dispositivo (`GxDeviceSlotCard`,
/// `ADR-0029`, `REQ-DEVSLOT-001`..`004`).
class GxDeviceSlotCard extends StatelessWidget {
  const GxDeviceSlotCard({
    required this.factorClassCode,
    required this.factorTitle,
    required this.deviceModelName,
    required this.hardwareRootLabel,
    required this.hardwareAttestationId,
    required this.statusListIndex,
    required this.isActive,
    required this.icon,
    this.onSimulateDuplicateAttempt,
    this.onAtomicReplace,
    super.key,
  });

  final String factorClassCode; // "mobile", "card", "other"
  final String factorTitle;
  final String deviceModelName;
  final String hardwareRootLabel;
  final String hardwareAttestationId;
  final int statusListIndex;
  final bool isActive;
  final IconData icon;
  final VoidCallback? onSimulateDuplicateAttempt;
  final VoidCallback? onAtomicReplace;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return Container(
      padding: const EdgeInsets.all(GxSpace.l),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerLow,
        borderRadius: GxShape.extraLarge,
        border: Border.all(
          color: isActive ? semantic.success.color : scheme.outlineVariant,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: scheme.primaryContainer,
                  borderRadius: GxShape.large,
                ),
                child: Icon(icon, color: scheme.onPrimaryContainer),
              ),
              const SizedBox(width: GxSpace.m),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Wrap(
                      spacing: GxSpace.xs,
                      runSpacing: GxSpace.xs,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: <Widget>[
                        StatusChip(
                          label: isActive
                              ? 'RANURA OCUPADA (1/1)'
                              : 'RANURA DISPONIBLE',
                          tone: isActive ? semantic.success : semantic.info,
                          icon: isActive
                              ? Icons.lock_rounded
                              : Icons.add_moderator_outlined,
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: GxSpace.s,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: scheme.secondaryContainer,
                            borderRadius: GxShape.full,
                          ),
                          child: GxTabularCodeText(
                            'slot: $factorClassCode (máx. 1)',
                            style: Theme.of(context).textTheme.labelSmall,
                            color: scheme.onSecondaryContainer,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: GxSpace.xs),
                    Text(
                      factorTitle,
                      style: emphasized?.titleMedium,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      deviceModelName,
                      style: Theme.of(context)
                          .textTheme
                          .bodyMedium
                          ?.copyWith(color: scheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: GxSpace.m),
          Wrap(
            spacing: GxSpace.s,
            runSpacing: GxSpace.xs,
            children: <Widget>[
              _MetaBadge(
                icon: Icons.security_rounded,
                label: hardwareRootLabel,
              ),
              _MetaBadge(
                icon: Icons.qr_code_scanner_rounded,
                label: hardwareAttestationId,
                tabular: true,
              ),
              _MetaBadge(
                icon: Icons.list_alt_rounded,
                label: 'TokenStatusList idx #$statusListIndex',
                tabular: true,
              ),
            ],
          ),
          const SizedBox(height: GxSpace.m),
          Wrap(
            spacing: GxSpace.s,
            runSpacing: GxSpace.xs,
            children: <Widget>[
              if (onSimulateDuplicateAttempt != null)
                OutlinedButton.icon(
                  onPressed: onSimulateDuplicateAttempt,
                  icon: const Icon(Icons.block_rounded, size: 18),
                  label: Text('Probar 2.º $factorClassCode (GID-E2011)'),
                ),
              if (onAtomicReplace != null)
                TextButton.icon(
                  onPressed: onAtomicReplace,
                  icon: const Icon(Icons.swap_horiz_rounded, size: 18),
                  label: const Text('Reemplazo Atómico de Soporte'),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

/// Tarjeta de aplicación/inquilino conectado que consume Gravital ID (`GxTenantAccessCard`,
/// `ADR-0027`, `pip-tenant-role-v1`, `REQ-TENANT-001`..`004`).
class GxTenantAccessCard extends StatelessWidget {
  const GxTenantAccessCard({
    required this.tenantId,
    required this.tenantName,
    required this.tenantSector,
    required this.tenantSubjectId,
    required this.roles,
    required this.permissions,
    required this.sharedClaims,
    required this.statusState,
    this.onManagePortability,
    this.onPresentRoleAccess,
    this.onRevokeTenant,
    super.key,
  });

  final String tenantId;
  final String tenantName;
  final String tenantSector;
  final String tenantSubjectId;
  final List<String> roles;
  final List<String> permissions;
  final List<String> sharedClaims;
  final GxVerificationState statusState;
  final VoidCallback? onManagePortability;
  final VoidCallback? onPresentRoleAccess;
  final VoidCallback? onRevokeTenant;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return Container(
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
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: scheme.secondaryContainer,
                  borderRadius: GxShape.large,
                ),
                child: Icon(
                  Icons.hub_rounded,
                  color: scheme.onSecondaryContainer,
                ),
              ),
              const SizedBox(width: GxSpace.m),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Text(
                      tenantName,
                      style: emphasized?.titleMedium,
                    ),
                    Text(
                      '$tenantSector · $tenantId',
                      style: Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.copyWith(color: scheme.onSurfaceVariant),
                    ),
                    const SizedBox(height: 4),
                    GxTabularCodeText(
                      'TenantSubjectId: $tenantSubjectId',
                      style: Theme.of(context).textTheme.labelSmall,
                      color: scheme.primary,
                    ),
                  ],
                ),
              ),
              StatusChip.fromVerificationState(
                state: statusState,
                semantic: semantic,
                scheme: scheme,
              ),
            ],
          ),
          const SizedBox(height: GxSpace.m),
          Text(
            'Roles verificables en este sistema (pip-tenant-role-v1):',
            style: emphasized?.labelMedium,
          ),
          const SizedBox(height: GxSpace.xs),
          Wrap(
            spacing: GxSpace.xs,
            runSpacing: GxSpace.xs,
            children: roles
                .map(
                  (role) => Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: GxSpace.m,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: scheme.primaryContainer,
                      borderRadius: GxShape.full,
                    ),
                    child: Text(
                      'Rol: $role',
                      style: Theme.of(context)
                          .textTheme
                          .labelSmall
                          ?.copyWith(color: scheme.onPrimaryContainer),
                    ),
                  ),
                )
                .toList(),
          ),
          const SizedBox(height: GxSpace.s),
          Text(
            'Permisos delegados y atributos portados por decisión del titular:',
            style: Theme.of(context)
                .textTheme
                .labelSmall
                ?.copyWith(color: scheme.onSurfaceVariant),
          ),
          const SizedBox(height: GxSpace.xs),
          Wrap(
            spacing: GxSpace.xs,
            runSpacing: GxSpace.xs,
            children: <Widget>[
              ...permissions.map(
                (perm) => _MetaBadge(
                  icon: Icons.key_rounded,
                  label: perm,
                  tabular: true,
                ),
              ),
              ...sharedClaims.map(
                (claim) => _MetaBadge(
                  icon: Icons.check_circle_outline_rounded,
                  label: claim,
                  tabular: true,
                ),
              ),
            ],
          ),
          const SizedBox(height: GxSpace.m),
          Wrap(
            spacing: GxSpace.s,
            runSpacing: GxSpace.xs,
            children: <Widget>[
              if (onManagePortability != null)
                OutlinedButton.icon(
                  onPressed: onManagePortability,
                  icon: const Icon(Icons.tune_rounded, size: 18),
                  label: const Text('Qué Datos Comparto'),
                ),
              if (onPresentRoleAccess != null)
                TextButton.icon(
                  onPressed: onPresentRoleAccess,
                  icon: const Icon(Icons.login_rounded, size: 18),
                  label: const Text('Acceder con Rol'),
                ),
              if (onRevokeTenant != null)
                TextButton.icon(
                  onPressed: onRevokeTenant,
                  icon: Icon(
                    Icons.link_off_rounded,
                    size: 18,
                    color: scheme.error,
                  ),
                  label: Text(
                    'Desvincular',
                    style: TextStyle(color: scheme.error),
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }
}
