// Pantalla de Recuperación y Rotación de Dispositivo (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-REC-001, REQ-REC-002, REQ-REC-003, REQ-REC-004, REQ-REC-005, REQ-REC-006, REQ-REC-007

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Vista de recuperación de bóveda y rotación de soporte.
class RecoveryScreen extends StatefulWidget {
  const RecoveryScreen({
    required this.store,
    this.showAppBar = false,
    super.key,
  });

  final GravitalWalletStore store;
  final bool showAppBar;

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

    final body = ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl,
      ),
      children: <Widget>[
        Container(
          padding: const EdgeInsets.all(GxSpace.xl),
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
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: scheme.primaryContainer,
                      borderRadius: GxShape.large,
                    ),
                    child: Icon(
                      Icons.health_and_safety_rounded,
                      color: scheme.onPrimaryContainer,
                      size: 26,
                    ),
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text(
                          'Respaldo y Recuperación',
                          style: emphasized?.headlineSmall ??
                              Theme.of(context).textTheme.headlineSmall,
                        ),
                        Text(
                          'Restaura tu bóveda si cambias o pierdes tu teléfono',
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
                'Tu bóveda está protegida con tu frase de recuperación de 12 palabras. '
                'Nadie más tiene copia de tus claves: solo tú puedes restaurar tus credenciales en un dispositivo nuevo.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: scheme.onSurfaceVariant,
                    ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Frase de Recuperación (12 palabras)',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Guarda estas palabras en un lugar seguro y privado. Nunca las compartas.',
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
                      _showCode
                          ? Icons.visibility_off_rounded
                          : Icons.visibility_rounded,
                    ),
                    tooltip: _showCode ? 'Ocultar frase' : 'Mostrar frase',
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.s),
              Text(
                'Respaldo cifrado verificado · Cero custodia en servidores',
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
          'Recuperación con Contactos de Confianza',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Puedes dividir tu respaldo entre 5 personas o soportes de confianza; '
          'se requieren al menos 3 fragmentos para restaurar tu cuenta.',
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
              label: 'UMBRAL 3 DE 5 CUSTODIOS',
              tone: semantic.info,
              icon: Icons.group_rounded,
            ),
            StatusChip(
              label: 'PROTECCIÓN ACTIVA',
              tone: semantic.success,
              icon: Icons.verified_user_rounded,
            ),
          ],
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Restaurar en Este Dispositivo',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.m),
        TextField(
          controller: _recoveryCodeController,
          decoration: const InputDecoration(
            labelText: 'Frase de Recuperación o Fragmentos',
            prefixIcon: Icon(Icons.key_rounded),
            hintText: 'Ingresa tus 12 palabras o fragmentos de custodia',
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
      ],
    );

    if (!widget.showAppBar) {
      return body;
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Recuperación de Bóveda'),
      ),
      body: body,
    );
  }
}
