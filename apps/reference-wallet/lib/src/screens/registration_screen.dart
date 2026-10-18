// Pantalla de Registro / Crear Cuenta (Capa 5).
// Verifies: REQ-ISS-001, REQ-UNIQ-001..004, REQ-IDDOC-001

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

class RegistrationScreen extends StatefulWidget {
  const RegistrationScreen({required this.store, super.key});
  final GravitalWalletStore store;
  @override
  State<RegistrationScreen> createState() => _RegistrationScreenState();
}

class _RegistrationScreenState extends State<RegistrationScreen> {
  final TextEditingController _cedulaController = TextEditingController();
  final TextEditingController _nameController = TextEditingController();
  String? _resultMessage;
  bool _success = false;

  @override
  void dispose() {
    _cedulaController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  void _register() {
    final outcome = widget.store.attemptCitizenRegistration(
      rawCedula: _cedulaController.text,
      fullName: _nameController.text,
    );
    setState(() {
      _success = outcome.succeeded;
      _resultMessage = outcome.succeeded
          ? 'Cuenta creada. Etiqueta de unicidad: ${outcome.uniquenessTag}'
          : '${outcome.errorCode} · ${outcome.errorIdentifier}';
    });
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized = Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    final content = ListView(
      padding: const EdgeInsets.fromLTRB(GxSpace.l, GxSpace.l, GxSpace.l, GxSpace.xxxl),
      children: <Widget>[
        Text('Crear tu Gravital ID', style: emphasized?.headlineSmall),
        const SizedBox(height: GxSpace.xs),
        Text('Regístrate una sola vez con tu cédula panameña. Sin servidor central.',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: scheme.onSurfaceVariant)),
        const SizedBox(height: GxSpace.xl),
        TextField(
          controller: _cedulaController,
          decoration: const InputDecoration(
            labelText: 'Número de Cédula (Formato TE)',
            hintText: 'Ej. 4-752-1940',
            prefixIcon: Icon(Icons.badge_outlined),
          ),
        ),
        const SizedBox(height: GxSpace.m),
        TextField(
          controller: _nameController,
          decoration: const InputDecoration(
            labelText: 'Nombre Completo Verificado por SVI',
            prefixIcon: Icon(Icons.person_outline_rounded),
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        FilledButton.icon(
          onPressed: _register,
          icon: const Icon(Icons.person_add_rounded, size: 18),
          label: const Text('Crear Cuenta y Verificar Unicidad'),
        ),
        const SizedBox(height: GxSpace.xl),
        if (_resultMessage != null)
          Container(
            padding: const EdgeInsets.all(GxSpace.l),
            decoration: BoxDecoration(
              color: _success ? semantic.success.container : semantic.warning.container,
              borderRadius: GxShape.large,
              border: Border.all(color: _success ? semantic.success.color : semantic.warning.color),
            ),
            child: Row(
              children: <Widget>[
                Icon(_success ? Icons.check_circle_rounded : Icons.error_rounded,
                    color: _success ? semantic.success.onContainer : semantic.warning.onContainer),
                const SizedBox(width: GxSpace.m),
                Expanded(
                  child: Text(
                    _resultMessage!,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: _success ? semantic.success.onContainer : semantic.warning.onContainer,
                        ),
                  ),
                ),
              ],
            ),
          ),
        const SizedBox(height: GxSpace.xl),
        Text('¿Ya tienes cuenta?', style: emphasized?.titleMedium),
        const SizedBox(height: GxSpace.s),
        OutlinedButton.icon(
          onPressed: () {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Iniciar sesión con Gravital ID existente.')),
            );
          },
          icon: const Icon(Icons.login_rounded, size: 18),
          label: const Text('Iniciar Sesión'),
        ),
      ],
    );

    return Scaffold(
      appBar: AppBar(
        title: const Text('Crear tu Gravital ID'),
      ),
      body: content,
    );
  }
}
