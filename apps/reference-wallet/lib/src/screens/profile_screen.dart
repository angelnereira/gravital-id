// Pantalla de Información de Usuario (Capa 5).
// Verifies: REQ-IDDOC-001, REQ-IDDOC-002, REQ-UNIQ-001..004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

class ProfileScreen extends StatelessWidget {
  const ProfileScreen({
    required this.store,
    this.onOpenRegistration,
    super.key,
  });

  final GravitalWalletStore store;
  final VoidCallback? onOpenRegistration;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized = Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    final content = ListView(
      padding: const EdgeInsets.fromLTRB(GxSpace.l, GxSpace.l, GxSpace.l, GxSpace.xxxl),
      children: <Widget>[
        Container(
          padding: const EdgeInsets.all(GxSpace.xl),
          decoration: BoxDecoration(
            color: scheme.primaryContainer,
            borderRadius: GxShape.extraLarge,
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                children: <Widget>[
                  CircleAvatar(
                    radius: 32,
                    backgroundColor: scheme.onPrimaryContainer.withValues(alpha: 0.12),
                    child: Icon(Icons.person_rounded, size: 32, color: scheme.onPrimaryContainer),
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text('Ángel Gabriel Nereira', style: emphasized?.headlineSmall?.copyWith(color: scheme.onPrimaryContainer)),
                        Text('Cédula PA: 8-888-8888', style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: scheme.onPrimaryContainer)),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text('Identidad Portable', style: emphasized?.titleLarge),
        const SizedBox(height: GxSpace.m),
        const _InfoTile(label: 'Tipo de credencial', value: 'pip-identity-v1 (oficial)'),
        const _InfoTile(label: 'Emisor', value: 'Tribunal Electoral de Panamá'),
        const _InfoTile(label: 'Etiqueta de unicidad (VOPRF)', value: 'voprf:p256:pa:8-888-8888'),
        const _InfoTile(label: 'Retrato', value: 'JPEG ≤ 16 KiB (solo NFC)'),
        const _InfoTile(label: 'Nivel de verificación', value: 'Nivel 1 (biométrico)'),
        const SizedBox(height: GxSpace.xl),
        Text('Soportes vinculados', style: emphasized?.titleLarge),
        const SizedBox(height: GxSpace.m),
        const _InfoTile(label: 'Teléfono', value: 'Pixel 10 Pro (IMEI atestado)'),
        const _InfoTile(label: 'Tarjeta', value: 'Visa Gravital (Java Card)'),
        const _InfoTile(label: 'Otro', value: 'Lector USB PC/SC'),
        const SizedBox(height: GxSpace.xl),
        Text('Seguridad', style: emphasized?.titleLarge),
        const SizedBox(height: GxSpace.m),
        const _InfoTile(label: 'Clave de dispositivo', value: 'StrongBox / Secure Enclave'),
        const _InfoTile(label: 'Algoritmo', value: 'ES256 (P-256 + SHA-256)'),
        const _InfoTile(label: 'Cifrado en reposo', value: 'XChaCha20-Poly1305 (DEK/KEK)'),
        if (onOpenRegistration != null) ...<Widget>[
          const SizedBox(height: GxSpace.xl),
          OutlinedButton.icon(
            onPressed: onOpenRegistration,
            icon: const Icon(Icons.person_add_rounded, size: 18),
            label: const Text('Registrar Nueva Identidad / Cédula (SVI)'),
          ),
        ],
      ],
    );

    return Scaffold(
      appBar: AppBar(
        title: const Text('Perfil del Titular'),
      ),
      body: content,
    );
  }
}

class _InfoTile extends StatelessWidget {
  const _InfoTile({required this.label, required this.value});
  final String label;
  final String value;
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: GxSpace.s),
      child: Container(
        padding: const EdgeInsets.all(GxSpace.m),
        decoration: BoxDecoration(
          color: scheme.surfaceContainerLow,
          borderRadius: GxShape.medium,
          border: Border.all(color: scheme.outlineVariant),
        ),
        child: Row(
          children: <Widget>[
            Expanded(child: Text(label, style: Theme.of(context).textTheme.bodyMedium)),
            GxTabularCodeText(value, style: Theme.of(context).textTheme.bodySmall, color: scheme.primary),
          ],
        ),
      ),
    );
  }
}
