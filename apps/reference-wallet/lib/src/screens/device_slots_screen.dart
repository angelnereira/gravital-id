// Pantalla de Soportes por Clase de Dispositivo y Atestación Hardware/IMEI/CPLC (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-DEVSLOT-004, REQ-UI-001, REQ-UI-004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';
import 'recovery_screen.dart';
import 'sync_trust_screen.dart';

/// Gestor de soportes físicos bajo la regla de ranura única por clase (`DeviceFactorClass`:
/// máximo 1 `mobile`, máximo 1 `card` tipo Visa Java Card, máximo 1 `other`, `ADR-0029`).
class DeviceSlotsScreen extends StatelessWidget {
  const DeviceSlotsScreen({
    required this.store,
    super.key,
  });

  final GravitalWalletStore store;

  void _simulateDuplicateForClass(DeviceFactorClass factorClass) {
    switch (factorClass) {
      case DeviceFactorClass.mobile:
        store.attemptDuplicateDeviceInClass(
          factorClass: DeviceFactorClass.mobile,
          candidateModelName: 'Segundo Teléfono (Galaxy S25 Ultra)',
          candidateHardwareId: 'IMEI-Attested: 359910-08-772104-9',
        );
      case DeviceFactorClass.card:
        store.attemptDuplicateDeviceInClass(
          factorClass: DeviceFactorClass.card,
          candidateModelName: 'Segunda Tarjeta Física Tipo Visa (Clon/Extra)',
          candidateHardwareId: 'CPLC IC-Serial: 4A43-4F50-8888-112B',
        );
      case DeviceFactorClass.other:
        store.attemptDuplicateDeviceInClass(
          factorClass: DeviceFactorClass.other,
          candidateModelName: 'Segunda Llave USB FIDO2',
          candidateHardwareId: 'AAGUID: 99a0579f-8113-47ea-b116-000000000001',
        );
    }
  }

  void _executeAtomicReplaceForClass(DeviceFactorClass factorClass) {
    switch (factorClass) {
      case DeviceFactorClass.mobile:
        store.replaceDeviceInSlot(
          factorClass: DeviceFactorClass.mobile,
          newModelName: 'Nuevo Teléfono Titular (Pixel 10 Pro · StrongBox)',
          newHardwareId: 'IMEI-Attested: 354109-12-908144-2 · KeyAttest v4',
        );
      case DeviceFactorClass.card:
        store.replaceDeviceInSlot(
          factorClass: DeviceFactorClass.card,
          newModelName: 'Nueva Tarjeta Gravital ID Visa-Format (Reemplazo)',
          newHardwareId: 'CPLC IC-Serial: 4A43-4F50-7741-903F',
        );
      case DeviceFactorClass.other:
        store.replaceDeviceInSlot(
          factorClass: DeviceFactorClass.other,
          newModelName: 'Nuevo Token Hardware PKCS#11 (Reemplazo)',
          newHardwareId: 'HSM-Serial: PKCS11-9042-AA19',
        );
    }
  }

  void _openRecovery(BuildContext context) {
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => RecoveryScreen(store: store, showAppBar: true),
      ),
    );
  }

  void _openSync(BuildContext context) {
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => SyncTrustScreen(store: store, showAppBar: true),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final outcome = store.lastProtocolBanner;

    return ListView(
      padding: const EdgeInsets.fromLTRB(
        GxSpace.l,
        GxSpace.l,
        GxSpace.l,
        GxSpace.xxxl,
      ),
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
                '1 Teléfono + 1 Tarjeta Tipo Visa + 1 Otro Soporte — Nunca Dos del Mismo Tipo',
                style: emphasized?.titleLarge ??
                    Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: GxSpace.xs),
              Text(
                'Un soporte activo por categoría; al reemplazar uno, el anterior se desactiva.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.m),
              Wrap(
                spacing: GxSpace.s,
                runSpacing: GxSpace.s,
                children: <Widget>[
                  OutlinedButton.icon(
                    onPressed: () => _openRecovery(context),
                    icon: const Icon(Icons.health_and_safety_outlined, size: 18),
                    label: const Text('Recuperar'),
                  ),
                  OutlinedButton.icon(
                    onPressed: () => _openSync(context),
                    icon: const Icon(Icons.sync_rounded, size: 18),
                    label: const Text('Sincronizar'),
                  ),
                ],
              ),
            ],
          ),
        ),
        if (outcome != null) ...<Widget>[
          const SizedBox(height: GxSpace.l),
          if (outcome.succeeded)
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
                        Icons.swap_horizontal_circle_rounded,
                        color: semantic.success.onContainer,
                      ),
                      const SizedBox(width: GxSpace.s),
                      Expanded(
                        child: Text(
                          outcome.title,
                          style: emphasized?.titleMedium?.copyWith(
                            color: semantic.success.onContainer,
                          ),
                        ),
                      ),
                      IconButton(
                        onPressed: store.clearProtocolBanner,
                        icon: const Icon(Icons.close_rounded),
                        tooltip: 'Cerrar aviso',
                      ),
                    ],
                  ),
                  Text(
                    outcome.description,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: semantic.success.onContainer,
                        ),
                  ),
                ],
              ),
            )
          else
            GxErrorState(
              errorCode: outcome.errorCode ?? 'GID-E2011',
              identifier:
                  outcome.errorIdentifier ?? 'DuplicateDeviceClassActive',
              title: outcome.title,
              description: outcome.description,
              remediationLabel:
                  'Ejecutar Reemplazo Atómico (Revoca el Anterior)',
              onRemediate: () =>
                  _executeAtomicReplaceForClass(DeviceFactorClass.mobile),
            ),
        ],
        const SizedBox(height: GxSpace.l),
        Text(
          'Tus Soportes Autorizados',
          style: emphasized?.titleMedium,
        ),
        const SizedBox(height: GxSpace.s),
        ...DeviceFactorClass.values.map((factorClass) {
          final slot = store.deviceSlots[factorClass]!;
          return Padding(
            padding: const EdgeInsets.only(bottom: GxSpace.m),
            child: GxDeviceSlotCard(
              factorClassCode: factorClass.code,
              factorTitle: factorClass.title,
              deviceModelName: slot.deviceModelName,
              hardwareRootLabel: factorClass.hardwareRoot,
              hardwareAttestationId: slot.hardwareAttestationId,
              statusListIndex: slot.statusListIndex,
              isActive: true,
              icon: factorClass.icon,
              onAtomicReplace: () => _executeAtomicReplaceForClass(factorClass),
            ),
          );
        }),
        const SizedBox(height: GxSpace.s),
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
                  Icons.shield_outlined,
                  size: 18,
                  color: scheme.onSecondaryContainer,
                ),
              ),
              title: Text(
                'Verificación de Límite por Soporte',
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
                // Único FilledButton de esta pantalla (Regla SPEC-PIP-UI-001 §15.1)
                FilledButton.icon(
                  onPressed: () =>
                      _simulateDuplicateForClass(DeviceFactorClass.mobile),
                  icon: const Icon(Icons.phonelink_erase_rounded),
                  label: const Text(
                    'Probar Bloqueo de 2.º Teléfono con Otro IMEI (GID-E2011)',
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}
