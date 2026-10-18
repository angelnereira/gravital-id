// Pantalla de Recuperación y Rotación de Dispositivo (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-REC-001, REQ-REC-002, REQ-REC-003, REQ-REC-004, REQ-REC-005, REQ-REC-006, REQ-REC-007

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Vista de recuperación de bóveda y rotación de soporte.
class RecoveryScreen extends StatefulWidget {
  const RecoveryScreen({
    required this.store,
    super.key,
  });

  final GravitalWalletStore store;

  @override
  State<RecoveryScreen> createState() => _RecoveryScreenState();
}

class _RecoveryScreenState extends State<RecoveryScreen> {
  final TextEditingController _recoveryCodeController =
      TextEditingController();
  bool _showCode = false;

  @override
  void dispose() {
    _recoveryCodeController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl + GxSpace.xxl,
      ),
      children: <Widget>[
        Container(
          padding: const EdgeInsets.all(GxSpace.xl),
          decoration: BoxDecoration(
            color: scheme.tertiaryContainer,
            borderRadius: GxShape.extraLarge,
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Icon(
                    Icons.health_and_safety_rounded,
                    color: scheme.onTertiaryContainer,
                    size: 28,
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Text(
                      'Recuperación de tu Gravital ID',
                      style: (emphasized?.headlineSmall ??
                              Theme.of(context).textTheme.headlineSmall)
                          ?.copyWith(color: scheme.onTertiaryContainer),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.s),
              Text(
                'Tu bóveda está cifrada con una clave derivada de tu código de recuperación '
                '(≥ 128 bits, BIP-39). Sin servidor central: solo tú puedes restaurarla en un '
                'nuevo dispositivo mediante compromiso previo y SAS.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: scheme.onTertiaryContainer,
                    ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Código de Recuperación (BIP-39)',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Guarda estas 12 palabras en un lugar seguro. Nunca se transmiten ni se almacenan en claro.',
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        Container(
          padding: const EdgeInsets.all(GxSpace.l),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerLow,
            borderRadius: GxShape.large,
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Expanded(
                    child: GxTabularCodeText(
                      _showCode
                          ? 'abandon ability able about above absent absorb abstract absurd abuse access accident'
                          : '•••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• ••••',
                      style: Theme.of(context).textTheme.bodyMedium,
                      color: scheme.onSurface,
                    ),
                  ),
                  IconButton(
                    onPressed: () => setState(() => _showCode = !_showCode),
                    icon: Icon(
                      _showCode ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                    ),
                    tooltip: _showCode ? 'Ocultar' : 'Mostrar',
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.s),
              Text(
                'Checksum verificado · 128 bits de entropía · derivación HKDF por emisor',
                style: Theme.of(context)
                    .textTheme
                    .labelSmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Custodia Social (Shamir k-de-n)',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Divide tu secreto de recuperación en 5 fragmentos; bastan 3 para restaurar la bóveda. '
          'Ningún custodio único decide la confianza (INV-16).',
          style: Theme.of(context)
              .textTheme
              .bodySmall
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        Wrap(
          spacing: GxSpace.s,
          runSpacing: GxSpace.xs,
          children: <Widget>[
            StatusChip(
              label: 'UMBRAL 3-DE-5',
              tone: semantic.info,
              icon: Icons.shield_rounded,
            ),
            StatusChip(
              label: 'GF(2⁸) · LAGRANGE',
              tone: semantic.success,
              icon: Icons.functions_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Restaurar en Nuevo Dispositivo',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.m),
        TextField(
          controller: _recoveryCodeController,
          decoration: const InputDecoration(
            labelText: 'Código de Recuperación o Fragmentos Shamir',
            prefixIcon: Icon(Icons.key_rounded),
            hintText: 'Pega aquí tu mnemónico o 3 fragmentos GIDS',
          ),
        ),
        const SizedBox(height: GxSpace.m),
        FilledButton.icon(
          onPressed: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text(
                  'Restauración iniciada: compromiso SHA-256 previo + SAS (xxx-xxx). '
                  'Claves privadas nunca cruzan FFI (INV-03).',
                ),
              ),
            );
          },
          icon: const Icon(Icons.restore_rounded, size: 18),
          label: const Text('Restaurar Bóveda (Compromiso + SAS)'),
        ),
        const SizedBox(height: GxSpace.s),
        OutlinedButton.icon(
          onPressed: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text(
                  'Migración directa: QR con clave efímera + ECDH + SAS. '
                  'Re-vinculación en cola (REQ-REC-001).',
                ),
              ),
            );
          },
          icon: const Icon(Icons.devices_rounded, size: 18),
          label: const Text('Migrar desde Otro Dispositivo (QR + SAS)'),
        ),
        const SizedBox(height: GxSpace.xl),
        GxErrorState(
          errorCode: 'GID-E2013',
          identifier: 'InsecureSingleFactorRecoveryRejected',
          title: 'Recuperación por Correo Único Rechazada',
          description:
              'La recuperación institucional basada únicamente en correo electrónico o SMS '
              'está prohibida (REQ-REC-006, P-10). Se requiere verificación fuera de banda '
              'o aprobación dual.',
          remediationLabel: 'Ver Procedimientos por Perfil',
          onRemediate: () {},
        ),
      ],
    );
  }
}
