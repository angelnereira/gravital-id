// Punto de entrada de la aplicación Flutter de referencia de Gravital ID.
// Construida íntegramente sobre el sistema de diseño Gravital-Experience-UI (SPEC-PIP-UI-001).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004, REQ-TENANT-001..004, REQ-UNIQ-001..004, REQ-DEVSLOT-001..004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import 'src/domain/gravital_wallet_store.dart';
import 'src/screens/device_slots_screen.dart';
import 'src/screens/present_access_screen.dart';
import 'src/screens/profile_screen.dart';
import 'src/screens/registration_screen.dart';
import 'src/screens/settings_screen.dart';
import 'src/screens/tenants_portability_screen.dart';
import 'src/screens/vault_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const GravitalReferenceWalletApp());
}

/// Aplicación raíz de la Wallet de Referencia y Hub Multi-Inquilino de Gravital ID.
class GravitalReferenceWalletApp extends StatefulWidget {
  const GravitalReferenceWalletApp({
    this.store,
    super.key,
  });

  final GravitalWalletStore? store;

  @override
  State<GravitalReferenceWalletApp> createState() =>
      _GravitalReferenceWalletAppState();
}

class _GravitalReferenceWalletAppState
    extends State<GravitalReferenceWalletApp> {
  late final GravitalWalletStore _store =
      widget.store ?? GravitalWalletStore();
  int _selectedNavIndex = 0;

  @override
  void dispose() {
    if (widget.store == null) {
      _store.dispose();
    }
    super.dispose();
  }

  void _navigateToTab(int index) {
    _store.clearProtocolBanner();
    setState(() {
      _selectedNavIndex = index;
    });
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
        listenable: _store,
        builder: (context, _) => GxApp(
          title: 'Gravital ID — Identidad Soberana & Portabilidad',
          themeMode: _store.themeMode,
          contrastLevel: _store.contrastLevel,
          home: _WalletHomeShell(
            store: _store,
            selectedIndex: _selectedNavIndex,
            onDestinationSelected: _navigateToTab,
          ),
        ),
      );
}

class _WalletHomeShell extends StatelessWidget {
  const _WalletHomeShell({
    required this.store,
    required this.selectedIndex,
    required this.onDestinationSelected,
  });

  final GravitalWalletStore store;
  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;

  void _openProfile(BuildContext context) {
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => ProfileScreen(
          store: store,
          onOpenRegistration: () => _openRegistration(context),
        ),
      ),
    );
  }

  void _openSettings(BuildContext context) {
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => SettingsScreen(
          store: store,
          onOpenProfile: () => _openProfile(context),
          onOpenRegistration: () => _openRegistration(context),
        ),
      ),
    );
  }

  void _openRegistration(BuildContext context) {
    Navigator.of(context).push<void>(
      MaterialPageRoute<void>(
        builder: (_) => RegistrationScreen(store: store),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final destinations = <GxNavigationDestination>[
      GxNavigationDestination(
        label: 'Credenciales',
        icon: Icons.wallet_outlined,
        selectedIcon: Icons.wallet_rounded,
        badgeCount: store.credentials.length,
      ),
      const GxNavigationDestination(
        label: 'Presentar',
        icon: Icons.qr_code_scanner_outlined,
        selectedIcon: Icons.qr_code_scanner_rounded,
      ),
      GxNavigationDestination(
        label: 'Apps y Roles',
        icon: Icons.hub_outlined,
        selectedIcon: Icons.hub_rounded,
        badgeCount: store.tenants.length,
      ),
      const GxNavigationDestination(
        label: 'Soportes',
        icon: Icons.devices_other_outlined,
        selectedIcon: Icons.devices_other_rounded,
      ),
    ];

    final Widget primaryBody = switch (selectedIndex) {
      0 => VaultScreen(
          store: store,
          onNavigateToPresent: (transport) {
            store.setTransport(transport);
            onDestinationSelected(1);
          },
          onNavigateToDevices: () => onDestinationSelected(3),
        ),
      1 => PresentAccessScreen(store: store),
      2 => TenantsPortabilityScreen(
          store: store,
          onNavigateToPresent: () => onDestinationSelected(1),
        ),
      3 => DeviceSlotsScreen(store: store),
      _ => VaultScreen(
          store: store,
          onNavigateToPresent: (transport) {
            store.setTransport(transport);
            onDestinationSelected(1);
          },
          onNavigateToDevices: () => onDestinationSelected(3),
        ),
    };

    final Widget? secondaryBody = switch (selectedIndex) {
      0 => VaultCredentialDetailPane(
          store: store,
          onPresentSelected: () => onDestinationSelected(1),
        ),
      _ => null,
    };

    return GxAdaptiveScaffold(
      selectedIndex: selectedIndex,
      onDestinationSelected: onDestinationSelected,
      destinations: destinations,
      appBar: AppBar(
        title: const Text('Gravital ID'),
        actions: <Widget>[
          IconButton(
            icon: Icon(
              store.isOfflineMode
                  ? Icons.cloud_off_rounded
                  : Icons.cloud_done_outlined,
            ),
            tooltip: store.isOfflineMode
                ? 'Modo sin conexión activo (toca para conectar)'
                : 'Conectado (toca para probar modo sin red)',
            onPressed: store.toggleOfflineMode,
          ),
          IconButton(
            icon: const Icon(Icons.account_circle_outlined),
            tooltip: 'Perfil del Titular',
            onPressed: () => _openProfile(context),
          ),
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Configuración',
            onPressed: () => _openSettings(context),
          ),
        ],
      ),
      banner: GxOfflineBanner(
        isOffline: store.isOfflineMode,
        trustBundleVersion: 14,
        statusFreshnessLabel: store.isOfflineMode ? '19h (en gracia)' : '2h 10m',
        onToggleOfflineMode: store.toggleOfflineMode,
      ),
      body: primaryBody,
      secondaryBody: secondaryBody,
    );
  }
}
