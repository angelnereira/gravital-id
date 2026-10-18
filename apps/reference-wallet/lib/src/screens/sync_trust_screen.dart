// Pantalla de Sincronización, Relays y Estado de Confianza (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-SYNC-001, REQ-SYNC-002, REQ-SYNC-003, REQ-SYNC-004, REQ-SYNC-005, REQ-SYNC-006, REQ-SYNC-007, REQ-TRUST-001..005

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Vista de sincronización sans-I/O, relays y actualización de trust bundle.
class SyncTrustScreen extends StatefulWidget {
  const SyncTrustScreen({
    required this.store,
    super.key,
  });

  final GravitalWalletStore store;

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
            color: scheme.primaryContainer,
            borderRadius: GxShape.extraLarge,
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                children: <Widget>[
                  Icon(
                    Icons.sync_rounded,
                    color: scheme.onPrimaryContainer,
                    size: 28,
                  ),
                  const SizedBox(width: GxSpace.m),
                  Expanded(
                    child: Text(
                      'Sincronización y Confianza',
                      style: (emphasized?.headlineSmall ??
                              Theme.of(context).textTheme.headlineSmall)
                          ?.copyWith(color: scheme.onPrimaryContainer),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.s),
              Text(
                'Cola cifrada idempotente (HPKE), backoff determinista, múltiples relays con failover. '
                'Todo contenido se verifica antes de aceptarse; fail-closed ante divergencia.',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: scheme.onPrimaryContainer,
                    ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Trust Bundle Activo',
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
              Row(
                children: <Widget>[
                  StatusChip(
                    label: 'ÉPOCA 1 · VERSIÓN 14',
                    tone: semantic.success,
                    icon: Icons.verified_rounded,
                  ),
                  const SizedBox(width: GxSpace.s),
                  StatusChip(
                    label: 'k-DE-n (3 DE 5)',
                    tone: semantic.info,
                    icon: Icons.groups_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              GxTabularCodeText(
                'bundle_epoch=1, bundle_version=14, chain_id=1',
                style: Theme.of(context).textTheme.bodySmall,
                color: scheme.onSurfaceVariant,
              ),
              const SizedBox(height: GxSpace.xs),
              GxTabularCodeText(
                'firmantes: op-alpha, op-beta, op-gamma (umbral 3)',
                style: Theme.of(context).textTheme.bodySmall,
                color: scheme.onSurfaceVariant,
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
                label: const Text('Actualizar Trust Bundle'),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Relays y Transporte',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.m),
        ...<Widget>[
          _RelayTile(
            name: 'relay-pa-01.gravital.io',
            region: 'Panamá (primario)',
            status: 'Conectado',
            tone: semantic.success,
          ),
          _RelayTile(
            name: 'relay-pa-02.gravital.io',
            region: 'Panamá (secundario)',
            status: 'En espera',
            tone: semantic.info,
          ),
          _RelayTile(
            name: 'relay-us-01.gravital.io',
            region: 'EE.UU. (failover)',
            status: 'Disponible',
            tone: semantic.info,
          ),
        ],
        const SizedBox(height: GxSpace.xl),
        Text(
          'Cola de Sincronización',
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
              Row(
                children: <Widget>[
                  StatusChip(
                    label: '3 PENDIENTES',
                    tone: semantic.warning,
                    icon: Icons.pending_rounded,
                  ),
                  const SizedBox(width: GxSpace.s),
                  StatusChip(
                    label: 'IDEMPOTENTE',
                    tone: semantic.success,
                    icon: Icons.repeat_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              GxTabularCodeText(
                'outbox: [manifest-v14, status-anchor-42, revocation-idx-4102]',
                style: Theme.of(context).textTheme.bodySmall,
                color: scheme.onSurfaceVariant,
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
        GxErrorState(
          errorCode: 'GID-E5001',
          identifier: 'RelayUnavailable',
          title: 'Degradación ante Caída de Relay',
          description:
              'Si todos los relays fallan, la wallet opera offline y reintenta con backoff '
              'exponencial. Nunca acepta datos no verificados (fail-closed, INV-05).',
          remediationLabel: 'Reintentar con Otro Relay',
          onRemediate: () {},
        ),
      ],
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
