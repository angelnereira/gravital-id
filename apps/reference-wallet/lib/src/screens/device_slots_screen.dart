// Pantalla de Soportes por Clase de Dispositivo y Atestación Hardware/IMEI/CPLC (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-DEVSLOT-004, REQ-UI-001, REQ-UI-004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

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
              Wrap(
                spacing: GxSpace.s,
                runSpacing: GxSpace.xs,
                children: <Widget>[
                  StatusChip(
                    label: 'RANURA ÚNICA POR CLASE DE FACTOR (ADR-0029)',
                    tone: semantic.success,
                    icon: Icons.security_update_good_rounded,
                  ),
                  StatusChip(
                    label:
                        '${store.revokedStatusIndices.length} ÍNDICES REVOCADOS EN LISTA',
                    tone: semantic.info,
                    icon: Icons.history_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              Text(
                '1 Teléfono + 1 Tarjeta Tipo Visa + 1 Otro Soporte — Nunca Dos del Mismo Tipo',
                style: (emphasized?.headlineSmall ??
                        Theme.of(context).textTheme.headlineSmall)
                    ?.copyWith(color: scheme.onTertiaryContainer),
              ),
              const SizedBox(height: GxSpace.xs),
              Text(
                'Tu Gravital ID puede coexistir en un teléfono móvil (con registro de Key Attestation e IMEI en modo gestionado), '
                'en una tarjeta inteligente formato Visa (con serie de silicio CPLC) y en una llave hardware, '
                'pero el protocolo rechaza con GID-E2011 cualquier intento de activar un segundo teléfono o una segunda tarjeta al mismo tiempo.',
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: scheme.onTertiaryContainer),
              ),
              const SizedBox(height: GxSpace.l),
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
        const SizedBox(height: GxSpace.xl),
        Text(
          'Tus 3 Ranuras de Factor de Dispositivo (DeviceFactorClass)',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Cada ranura posee su propio índice en la Token Status List para que revocar un teléfono extraviado no desactive tu tarjeta física.',
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
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
              onSimulateDuplicateAttempt: () =>
                  _simulateDuplicateForClass(factorClass),
              onAtomicReplace: () => _executeAtomicReplaceForClass(factorClass),
            ),
          );
        }),
        const SizedBox(height: GxSpace.l),
        // Panel de Accesibilidad y Contraste de Gravital-Experience-UI (SPEC-PIP-UI-001 §4.3, §13)
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
                'Ajustes de Accesibilidad y Contraste (Gravital-Experience-UI)',
                style: emphasized?.titleMedium,
              ),
              const SizedBox(height: GxSpace.xs),
              Text(
                'Selecciona el nivel de contraste tonal HCT (0.0 estándar, 0.5 medio, 1.0 alto contraste WCAG AAA) y el modo de tema.',
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.m),
              GxButtonGroup<double>(
                selected: store.contrastLevel,
                onChanged: store.setContrastLevel,
                segments: const <GxButtonSegment<double>>[
                  GxButtonSegment<double>(
                    value: 0.0,
                    label: 'Estándar (0.0)',
                    icon: Icons.contrast_rounded,
                  ),
                  GxButtonSegment<double>(
                    value: 0.5,
                    label: 'Medio (0.5)',
                    icon: Icons.brightness_medium_rounded,
                  ),
                  GxButtonSegment<double>(
                    value: 1.0,
                    label: 'Alto Contraste (1.0)',
                    icon: Icons.accessibility_new_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              GxButtonGroup<ThemeMode>(
                selected: store.themeMode,
                onChanged: store.setThemeMode,
                segments: const <GxButtonSegment<ThemeMode>>[
                  GxButtonSegment<ThemeMode>(
                    value: ThemeMode.system,
                    label: 'Sistema',
                    icon: Icons.brightness_auto_rounded,
                  ),
                  GxButtonSegment<ThemeMode>(
                    value: ThemeMode.light,
                    label: 'Claro',
                    icon: Icons.light_mode_rounded,
                  ),
                  GxButtonSegment<ThemeMode>(
                    value: ThemeMode.dark,
                    label: 'Oscuro',
                    icon: Icons.dark_mode_rounded,
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
