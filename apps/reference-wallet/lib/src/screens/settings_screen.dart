// Pantalla de Configuración (Capa 5).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({required this.store, super.key});
  final GravitalWalletStore store;
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized = Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    return ListView(
      padding: const EdgeInsets.fromLTRB(GxSpace.l, GxSpace.l, GxSpace.l, GxSpace.xxxl + GxSpace.xxl),
      children: <Widget>[
        Text('Configuración', style: emphasized?.headlineSmall),
        const SizedBox(height: GxSpace.xl),
        Text('Tema', style: emphasized?.titleMedium),
        const SizedBox(height: GxSpace.m),
        Wrap(spacing: GxSpace.s, children: <Widget>[
          ChoiceChip(
            label: const Text('Claro'),
            selected: widget.store.themeMode == ThemeMode.light,
            onSelected: (_) => widget.store.setThemeMode(ThemeMode.light),
          ),
          ChoiceChip(
            label: const Text('Oscuro'),
            selected: widget.store.themeMode == ThemeMode.dark,
            onSelected: (_) => widget.store.setThemeMode(ThemeMode.dark),
          ),
          ChoiceChip(
            label: const Text('Sistema'),
            selected: widget.store.themeMode == ThemeMode.system,
            onSelected: (_) => widget.store.setThemeMode(ThemeMode.system),
          ),
        ]),
        const SizedBox(height: GxSpace.xl),
        Text('Contraste', style: emphasized?.titleMedium),
        const SizedBox(height: GxSpace.m),
        Slider(
          value: widget.store.contrastLevel,
          min: 0.0,
          max: 1.0,
          divisions: 2,
          label: widget.store.contrastLevel == 0.0
              ? 'Normal'
              : widget.store.contrastLevel == 0.5
                  ? 'Medio'
                  : 'Alto',
          onChanged: widget.store.setContrastLevel,
        ),
        const SizedBox(height: GxSpace.xl),
        Text('Modo Offline', style: emphasized?.titleMedium),
        const SizedBox(height: GxSpace.m),
        SwitchListTile(
          title: const Text('Operar sin red'),
          subtitle: const Text('INV-01: verificación 100% sans-I/O'),
          value: widget.store.isOfflineMode,
          onChanged: (_) => widget.store.toggleOfflineMode(),
        ),
        const SizedBox(height: GxSpace.xl),
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
              Text('Seguridad', style: emphasized?.titleMedium),
              const SizedBox(height: GxSpace.s),
              const ListTile(
                leading: Icon(Icons.lock_rounded),
                title: Text('Claves en hardware'),
                subtitle: Text('StrongBox / Secure Enclave / TEE'),
                trailing: Icon(Icons.chevron_right_rounded),
              ),
              ListTile(
                leading: const Icon(Icons.delete_forever_rounded),
                title: const Text('Borrar bóveda'),
                subtitle: const Text('Elimina todas las credenciales cifradas'),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Bóveda borrada (simulado).')),
                  );
                },
              ),
            ],
          ),
        ),
      ],
    );
  }
}
