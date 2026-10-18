// Punto de entrada de la aplicación Flutter de referencia de Gravital ID.
// Construida íntegramente sobre el sistema de diseño Gravital-Experience-UI (SPEC-PIP-UI-001).
// Verifies: REQ-UI-001, REQ-UI-002, REQ-UI-003, REQ-UI-004, REQ-TENANT-001..004, REQ-UNIQ-001..004, REQ-DEVSLOT-001..004

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import 'src/domain/gravital_wallet_store.dart';
import 'src/screens/consent_screen.dart';
import 'src/screens/device_slots_screen.dart';
import 'src/screens/present_access_screen.dart';
import 'src/screens/recovery_screen.dart';
import 'src/screens/sync_trust_screen.dart';
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
      const GxNavigationDestination(
        label: 'Recuperar',
        icon: Icons.health_and_safety_outlined,
        selectedIcon: Icons.health_and_safety_rounded,
      ),
      const GxNavigationDestination(
        label: 'Sincronizar',
        icon: Icons.sync_outlined,
        selectedIcon: Icons.sync_rounded,
      ),
      const GxNavigationDestination(
        label: 'Consentir',
        icon: Icons.verified_user_outlined,
        selectedIcon: Icons.verified_user_rounded,
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
      4 => RecoveryScreen(store: store),
      5 => SyncTrustScreen(store: store),
      6 => ConsentScreen(store: store),
      _ => DeviceSlotsScreen(store: store),
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
        title: const Text('Gravital ID · Bóveda & Accesos'),
        actions: <Widget>[
          Flexible(
            child: Padding(
              padding: const EdgeInsets.only(right: GxSpace.m),
              child: Center(
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  child: GxTabularCodeText(
                    'Cédula PA: 8-888-8888',
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
      banner: GxOfflineBanner(
        isOffline: store.isOfflineMode,
        trustBundleVersion: 14,
        statusFreshnessLabel: store.isOfflineMode ? '19h (en gracia)' : '2h 10m',
        onToggleOfflineMode: store.toggleOfflineMode,
      ),
      floatingToolbar: GxFloatingToolbar(
        children: <Widget>[
          TextButton.icon(
            onPressed: () {
              store.setTransport(PresentationTransport.qrOffline);
              onDestinationSelected(1);
            },
            icon: const Icon(Icons.qr_code_2_rounded, size: 18),
            label: const Text('QR Offline'),
          ),
          TextButton.icon(
            onPressed: () {
              store.setTransport(PresentationTransport.nfcApdu);
              onDestinationSelected(1);
            },
            icon: const Icon(Icons.contactless_rounded, size: 18),
            label: const Text('Toque NFC'),
          ),
          TextButton.icon(
            onPressed: () {
              store.setTransport(PresentationTransport.passkey);
              onDestinationSelected(1);
            },
            icon: const Icon(Icons.fingerprint_rounded, size: 18),
            label: const Text('Passkey'),
          ),
          TextButton.icon(
            onPressed: () {
              store.setTransport(PresentationTransport.sessionCode);
              onDestinationSelected(1);
            },
            icon: const Icon(Icons.dialpad_rounded, size: 18),
            label: Text('Código ${store.activeSessionCode}'),
          ),
        ],
      ),
      body: primaryBody,
      secondaryBody: secondaryBody,
    );
  }
}
