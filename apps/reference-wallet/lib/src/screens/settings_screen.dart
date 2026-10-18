// Pantalla de Configuración (Capa 5).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';
import 'recovery_screen.dart';
import 'sync_trust_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({
    required this.store,
    this.onOpenProfile,
    this.onOpenRegistration,
    super.key,
  });

  final GravitalWalletStore store;
  final VoidCallback? onOpenProfile;
  final VoidCallback? onOpenRegistration;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    final content = ListView(
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
              Text('Apariencia y Accesibilidad', style: emphasized?.titleMedium),
              const SizedBox(height: GxSpace.m),
              Text(
                'Tema',
                style: Theme.of(context)
                    .textTheme
                    .labelLarge
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.xs),
              GxButtonGroup<ThemeMode>(
                selected: widget.store.themeMode,
                onChanged: widget.store.setThemeMode,
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
              const SizedBox(height: GxSpace.m),
              Text(
                'Nivel de contraste',
                style: Theme.of(context)
                    .textTheme
                    .labelLarge
                    ?.copyWith(color: scheme.onSurfaceVariant),
              ),
              const SizedBox(height: GxSpace.xs),
              GxButtonGroup<double>(
                selected: widget.store.contrastLevel,
                onChanged: widget.store.setContrastLevel,
                segments: const <GxButtonSegment<double>>[
                  GxButtonSegment<double>(
                    value: 0.0,
                    label: 'Normal',
                    icon: Icons.contrast_rounded,
                  ),
                  GxButtonSegment<double>(
                    value: 0.5,
                    label: 'Medio',
                    icon: Icons.brightness_medium_rounded,
                  ),
                  GxButtonSegment<double>(
                    value: 1.0,
                    label: 'Alto',
                    icon: Icons.accessibility_new_rounded,
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.l),
        Container(
          padding: const EdgeInsets.all(GxSpace.s),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerLow,
            borderRadius: GxShape.extraLarge,
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: SwitchListTile(
            title: const Text('Modo sin conexión'),
            subtitle: const Text(
              'Presentar y verificar credenciales sin usar internet',
            ),
            value: widget.store.isOfflineMode,
            onChanged: (_) => widget.store.toggleOfflineMode(),
          ),
        ),
        const SizedBox(height: GxSpace.l),
        Container(
          padding: const EdgeInsets.symmetric(vertical: GxSpace.s),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerLow,
            borderRadius: GxShape.extraLarge,
            border: Border.all(color: scheme.outlineVariant),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Padding(
                padding: const EdgeInsets.fromLTRB(
                  GxSpace.l,
                  GxSpace.s,
                  GxSpace.l,
                  GxSpace.xs,
                ),
                child: Text(
                  'Cuenta y Seguridad',
                  style: emphasized?.titleMedium,
                ),
              ),
              if (widget.onOpenProfile != null)
                ListTile(
                  leading: const Icon(Icons.person_outline_rounded),
                  title: const Text('Perfil del titular'),
                  subtitle: const Text('Ángel Gabriel Nereira · Cédula 8-888-8888'),
                  trailing: const Icon(Icons.chevron_right_rounded),
                  onTap: widget.onOpenProfile,
                ),
              ListTile(
                leading: const Icon(Icons.health_and_safety_outlined),
                title: const Text('Respaldo y recuperación'),
                subtitle: const Text('Frase de 12 palabras y contactos de confianza'),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () {
                  Navigator.of(context).push<void>(
                    MaterialPageRoute<void>(
                      builder: (_) => RecoveryScreen(
                        store: widget.store,
                        showAppBar: true,
                      ),
                    ),
                  );
                },
              ),
              ListTile(
                leading: const Icon(Icons.sync_rounded),
                title: const Text('Sincronización y confianza'),
                subtitle: const Text('Directorio de emisores y estado de soportes'),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () {
                  Navigator.of(context).push<void>(
                    MaterialPageRoute<void>(
                      builder: (_) => SyncTrustScreen(
                        store: widget.store,
                        showAppBar: true,
                      ),
                    ),
                  );
                },
              ),
              if (widget.onOpenRegistration != null)
                ListTile(
                  leading: const Icon(Icons.person_add_outlined),
                  title: const Text('Registrar nueva identidad'),
                  subtitle: const Text('Validación de cédula en Tribunal Electoral'),
                  trailing: const Icon(Icons.chevron_right_rounded),
                  onTap: widget.onOpenRegistration,
                ),
            ],
          ),
        ),
      ],
    );

    return Scaffold(
      appBar: AppBar(
        title: const Text('Configuración'),
      ),
      body: content,
    );
  }
}
