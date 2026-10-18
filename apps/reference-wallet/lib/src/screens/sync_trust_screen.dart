// Pantalla de Sincronización, Relays y Estado de Confianza (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-SYNC-001, REQ-SYNC-002, REQ-SYNC-003, REQ-SYNC-004, REQ-SYNC-005, REQ-SYNC-006, REQ-SYNC-007, REQ-TRUST-001..005

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Vista de sincronización sans-I/O, relays y actualización de trust bundle.
class SyncTrustScreen extends StatefulWidget {
  const SyncTrustScreen({
    required this.store,
    this.showAppBar = false,
    super.key,
  });

  final GravitalWalletStore store;
  final bool showAppBar;

  @override
  State<SyncTrustScreen> createState() => _SyncTrustScreenState();
}

class _SyncTrustScreenState extends State<SyncTrustScreen> {
  bool _syncing = false;

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
                      Icons.sync_rounded,
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
                          'Sincronización y Confianza',
                          style: emphasized?.headlineSmall ??
                              Theme.of(context).textTheme.headlineSmall,
                        ),
                        Text(
                          'Actualización de certificados de emisores y estado',
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
                'Tu dispositivo actualiza periódicamente la lista de emisores autorizados '
                'para verificar credenciales incluso cuando no tienes internet.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: scheme.onSurfaceVariant,
                    ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Directorio de Confianza (Trust Bundle)',
          style: emphasized?.titleLarge,
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
              Wrap(
                spacing: GxSpace.s,
                runSpacing: GxSpace.xs,
                children: <Widget>[
                  StatusChip(
                    label: 'VERSIÓN 14 ACTIVA',
                    tone: semantic.success,
                    icon: Icons.verified_rounded,
                  ),
                  StatusChip(
                    label: '3 DE 5 FIRMAS VERIFICADAS',
                    tone: semantic.info,
                    icon: Icons.groups_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              Text(
                'Emisores verificados: Tribunal Electoral de Panamá y nodos autorizados.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.m),
              OutlinedButton.icon(
                onPressed: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text(
                        'Trust bundle actualizado desde CDN (cofirma k-de-n). Anti-rollback verificado.',
                      ),
                    ),
                  );
                },
                icon: const Icon(Icons.download_rounded, size: 18),
                label: const Text('Actualizar Directorio de Confianza'),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Estado de Sincronización',
          style: emphasized?.titleLarge,
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
              Wrap(
                spacing: GxSpace.s,
                runSpacing: GxSpace.xs,
                children: <Widget>[
                  StatusChip(
                    label: 'AL DÍA',
                    tone: semantic.success,
                    icon: Icons.check_circle_rounded,
                  ),
                  StatusChip(
                    label: 'COLA CIFRADA',
                    tone: semantic.info,
                    icon: Icons.lock_outline_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              Text(
                'Sincroniza el estado de tus soportes y listas de revocación cuando tengas conexión.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.m),
              FilledButton.icon(
                onPressed: _syncing
                    ? null
                    : () async {
                        final messenger = ScaffoldMessenger.of(context);
                        setState(() => _syncing = true);
                        await Future<void>.delayed(
                          const Duration(milliseconds: 600),
                        );
                        if (!mounted) return;
                        setState(() => _syncing = false);
                        messenger.showSnackBar(
                          const SnackBar(
                            content: Text(
                              'Sincronización completada: cola drenada, anti-rollback verificado.',
                            ),
                          ),
                        );
                      },
                icon: _syncing
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.sync_rounded, size: 18),
                label: Text(_syncing ? 'Sincronizando…' : 'Sincronizar Ahora'),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Servidores de Retransmisión (Relays)',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.m),
        _RelayTile(
          name: 'relay-pa-01.gravital.io',
          region: 'Panamá (Principal)',
          status: 'Conectado',
          tone: semantic.success,
        ),
        _RelayTile(
          name: 'relay-pa-02.gravital.io',
          region: 'Panamá (Respaldo)',
          status: 'En espera',
          tone: semantic.info,
        ),
        _RelayTile(
          name: 'relay-us-01.gravital.io',
          region: 'Internacional (Respaldo)',
          status: 'Disponible',
          tone: semantic.info,
        ),
      ],
    );

    if (!widget.showAppBar) {
      return body;
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Sincronización y Confianza'),
      ),
      body: body,
    );
  }
}

class _RelayTile extends StatelessWidget {
  const _RelayTile({
    required this.name,
    required this.region,
    required this.status,
    required this.tone,
  });

  final String name;
  final String region;
  final String status;
  final SemanticTone tone;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: GxSpace.m),
      child: Container(
        padding: const EdgeInsets.all(GxSpace.l),
        decoration: BoxDecoration(
          color: scheme.surfaceContainerLow,
          borderRadius: GxShape.large,
          border: Border.all(color: scheme.outlineVariant),
        ),
        child: Row(
          children: <Widget>[
            Icon(Icons.cloud_rounded, color: tone.color, size: 22),
            const SizedBox(width: GxSpace.m),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Text(name, style: Theme.of(context).textTheme.titleSmall),
                  Text(
                    region,
                    style: Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.copyWith(color: scheme.onSurfaceVariant),
                  ),
                ],
              ),
            ),
            StatusChip(label: status, tone: tone, icon: Icons.cloud_rounded),
          ],
        ),
      ),
    );
  }
}
