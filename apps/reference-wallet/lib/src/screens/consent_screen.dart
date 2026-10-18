// Pantalla de Consentimiento en Dos Pasos para Presentación (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-PRES-003, REQ-PRES-007, REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Flujo standalone de consentimiento en dos pasos (inspección + confirmación).
class ConsentScreen extends StatefulWidget {
  const ConsentScreen({
    required this.store,
    super.key,
  });

  final GravitalWalletStore store;

  @override
  State<ConsentScreen> createState() => _ConsentScreenState();
}

class _ConsentScreenState extends State<ConsentScreen> {
  bool _stepOneConfirmed = false;
  bool _stepTwoConfirmed = false;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final cred = widget.store.selectedCredential;

    return ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl,
      ),
      children: <Widget>[
        Text(
          'Consentimiento en Dos Pasos',
          style: emphasized?.headlineSmall,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Paso 1: inspecciona qué se revelará. Paso 2: confirma y firma con tu clave de dispositivo.',
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.xl),
        // Paso 1
        Container(
          padding: const EdgeInsets.all(GxSpace.l),
          decoration: BoxDecoration(
            color: _stepOneConfirmed
                ? semantic.success.container
                : scheme.surfaceContainerLow,
            borderRadius: GxShape.large,
            border: Border.all(
              color: _stepOneConfirmed
                  ? semantic.success.color
                  : scheme.outlineVariant,
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Icon(
                    _stepOneConfirmed
                        ? Icons.check_circle_rounded
                        : Icons.looks_one_rounded,
                    color: _stepOneConfirmed
                        ? semantic.success.onContainer
                        : scheme.primary,
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Text(
                      'Paso 1 · Inspección de atributos',
                      style: emphasized?.titleMedium?.copyWith(
                        color: _stepOneConfirmed
                            ? semantic.success.onContainer
                            : null,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              ...cred.claims.map(
                (claim) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: GxSpace.xs),
                  child: Row(
                    children: <Widget>[
                      Icon(
                        claim.isSensitiveLevel1
                            ? Icons.lock_person_rounded
                            : Icons.check_circle_outline_rounded,
                        size: 16,
                        color: claim.isSensitiveLevel1
                            ? scheme.tertiary
                            : scheme.primary,
                      ),
                      const SizedBox(width: GxSpace.s),
                      Expanded(child: Text(claim.label)),
                      GxTabularCodeText(
                        claim.valuePreview,
                        style: Theme.of(context).textTheme.bodySmall,
                        color: scheme.onSurfaceVariant,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: GxSpace.m),
              FilledButton.tonal(
                onPressed: () => setState(() => _stepOneConfirmed = true),
                child: Text(
                  _stepOneConfirmed ? 'Paso 1 confirmado' : 'Confirmar inspección',
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        // Paso 2
        Container(
          padding: const EdgeInsets.all(GxSpace.l),
          decoration: BoxDecoration(
            color: _stepTwoConfirmed
                ? semantic.success.container
                : scheme.surfaceContainerLow,
            borderRadius: GxShape.large,
            border: Border.all(
              color: _stepTwoConfirmed
                  ? semantic.success.color
                  : scheme.outlineVariant,
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Icon(
                    _stepTwoConfirmed
                        ? Icons.check_circle_rounded
                        : Icons.looks_two_rounded,
                    color: _stepTwoConfirmed
                        ? semantic.success.onContainer
                        : scheme.primary,
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Text(
                      'Paso 2 · Firma con clave de dispositivo',
                      style: emphasized?.titleMedium?.copyWith(
                        color: _stepTwoConfirmed
                            ? semantic.success.onContainer
                            : null,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              Text(
                'Verificador: ${widget.store.activeTransport.label}. '
                'Se firmará un KB-JWT con nonce, aud y sd_hash. '
                'La clave privada nunca cruza FFI (INV-03).',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.m),
              FilledButton.icon(
                onPressed: _stepOneConfirmed
                    ? () => setState(() => _stepTwoConfirmed = true)
                    : null,
                icon: const Icon(Icons.fingerprint_rounded, size: 18),
                label: Text(
                  _stepTwoConfirmed ? 'Firmado y transmitido' : 'Firmar y Transmitir',
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        if (_stepOneConfirmed && _stepTwoConfirmed)
          Container(
            padding: const EdgeInsets.all(GxSpace.l),
            decoration: BoxDecoration(
              color: semantic.success.container,
              borderRadius: GxShape.large,
              border: Border.all(color: semantic.success.color),
            ),
            child: Row(
              children: <Widget>[
                Icon(Icons.verified_rounded, color: semantic.success.onContainer),
                const SizedBox(width: GxSpace.m),
                Expanded(
                  child: Text(
                    'Presentación emitida con consentimiento completo. '
                    'Transporte: ${widget.store.activeTransport.label}.',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: semantic.success.onContainer,
                        ),
                  ),
                ),
              ],
            ),
          ),
      ],
    );
  }
}
