// Pantalla de Cuentas, Apps y Servicios Vinculados (Capa 5).
// Verifies: REQ-TENANT-001..004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

class LinkedAccountsScreen extends StatelessWidget {
  const LinkedAccountsScreen({required this.store, super.key});
  final GravitalWalletStore store;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized = Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    return ListView(
      padding: const EdgeInsets.fromLTRB(GxSpace.l, GxSpace.l, GxSpace.l, GxSpace.xxxl + GxSpace.xxl),
      children: <Widget>[
        Text('Cuentas y Servicios Vinculados', style: emphasized?.headlineSmall),
        const SizedBox(height: GxSpace.xs),
        Text('Tu mismo Gravital ID, múltiples apps y roles (REQ-TENANT-001..004).',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: scheme.onSurfaceVariant)),
        const SizedBox(height: GxSpace.xl),
        ...store.tenants.map((t) => Padding(
              padding: const EdgeInsets.only(bottom: GxSpace.m),
              child: Container(
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
                        Icon(Icons.hub_rounded, color: scheme.primary),
                        const SizedBox(width: GxSpace.m),
                        Expanded(child: Text(t.tenantName, style: emphasized?.titleMedium)),
                        StatusChip(label: t.statusState.label, tone: Theme.of(context).extension<SemanticColors>()!.success, icon: t.statusState.icon),
                      ],
                    ),
                    const SizedBox(height: GxSpace.s),
                    GxTabularCodeText(t.tenantId, style: Theme.of(context).textTheme.labelSmall, color: scheme.onSurfaceVariant),
                    const SizedBox(height: GxSpace.s),
                    Text('Sector: ${t.tenantSector}', style: Theme.of(context).textTheme.bodySmall),
                    Text('Roles: ${t.roles.join(", ")}', style: Theme.of(context).textTheme.bodySmall),
                    Text('Permisos: ${t.permissions.join(", ")}', style: Theme.of(context).textTheme.bodySmall),
                    Text('Claims compartidos: ${t.sharedClaims.join(", ")}', style: Theme.of(context).textTheme.bodySmall),
                  ],
                ),
              ),
            )),
        const SizedBox(height: GxSpace.xl),
        FilledButton.icon(
          onPressed: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Vincular nueva app/servicio (OID4VP).')),
            );
          },
          icon: const Icon(Icons.add_link_rounded, size: 18),
          label: const Text('Vincular Nueva App o Servicio'),
        ),
      ],
    );
  }
}
