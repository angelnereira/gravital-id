// Patrones de diseño adaptativos de Gravital-Experience-UI (SPEC-PIP-UI-001 §8.3, §9.1).
// Verifies: REQ-UI-001, REQ-UI-004

import 'package:flutter/material.dart';

import '../theme/gx_theme.dart';
import '../theme/semantic_colors.dart';
import '../tokens/tokens.dart';

/// Destino de navegación canónico para [GxAdaptiveScaffold].
@immutable
class GxNavigationDestination {
  const GxNavigationDestination({
    required this.label,
    required this.icon,
    required this.selectedIcon,
    this.badgeCount,
  });

  final String label;
  final IconData icon;
  final IconData selectedIcon;
  final int? badgeCount;
}

/// Estructura adaptativa canónica de Gravital-Experience-UI (`GxAdaptiveScaffold`, SPEC-PIP-UI-001 §8.3).
///
/// - `WindowClass.compact`: `NavigationBar` inferior.
/// - `WindowClass.medium`: `NavigationRail` colapsado.
/// - `WindowClass.expanded` / `large` / `extraLarge`: `NavigationRail` extendido y
///   vista maestro-detalle de 2 paneles si se proporciona [secondaryBody].
class GxAdaptiveScaffold extends StatelessWidget {
  const GxAdaptiveScaffold({
    required this.destinations,
    required this.selectedIndex,
    required this.onDestinationSelected,
    required this.body,
    this.secondaryBody,
    this.appBar,
    this.floatingToolbar,
    this.banner,
    super.key,
  });

  final List<GxNavigationDestination> destinations;
  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;
  final Widget body;
  final Widget? secondaryBody;
  final PreferredSizeWidget? appBar;
  final Widget? floatingToolbar;
  final Widget? banner;

  @override
  Widget build(BuildContext context) {
    final window = WindowClass.of(context);
    final scheme = Theme.of(context).colorScheme;

    final Widget mainContent = Column(
      children: <Widget>[
        if (banner != null) banner!,
        Expanded(
          child: switch (window) {
            WindowClass.compact || WindowClass.medium => body,
            WindowClass.expanded ||
            WindowClass.large ||
            WindowClass.extraLarge =>
              secondaryBody != null
                  ? Padding(
                      padding: EdgeInsets.symmetric(horizontal: window.margin),
                      child: Row(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: <Widget>[
                          Expanded(flex: 5, child: body),
                          SizedBox(width: window.gutter),
                          Expanded(flex: 7, child: secondaryBody!),
                        ],
                      ),
                    )
                  : body,
          },
        ),
      ],
    );

    if (window == WindowClass.compact) {
      return Scaffold(
        appBar: appBar,
        body: Stack(
          alignment: Alignment.bottomCenter,
          children: <Widget>[
            Positioned.fill(child: mainContent),
            if (floatingToolbar != null)
              Positioned(
                bottom: GxSpace.l,
                child: floatingToolbar!,
              ),
          ],
        ),
        bottomNavigationBar: NavigationBar(
          selectedIndex: selectedIndex.clamp(0, destinations.length - 1),
          onDestinationSelected: onDestinationSelected,
          destinations: destinations
              .map(
                (d) => NavigationDestination(
                  icon: _buildBadgedIcon(d.icon, d.badgeCount),
                  selectedIcon: _buildBadgedIcon(d.selectedIcon, d.badgeCount),
                  label: d.label,
                ),
              )
              .toList(),
        ),
      );
    }

    final isExtendedRail =
        window == WindowClass.large || window == WindowClass.extraLarge;

    return Scaffold(
      appBar: appBar,
      body: Row(
        children: <Widget>[
          NavigationRail(
            extended: isExtendedRail,
            selectedIndex: selectedIndex,
            onDestinationSelected: onDestinationSelected,
            labelType: isExtendedRail
                ? NavigationRailLabelType.none
                : NavigationRailLabelType.all,
            destinations: destinations
                .map(
                  (d) => NavigationRailDestination(
                    icon: _buildBadgedIcon(d.icon, d.badgeCount),
                    selectedIcon:
                        _buildBadgedIcon(d.selectedIcon, d.badgeCount),
                    label: Text(d.label),
                  ),
                )
                .toList(),
          ),
          VerticalDivider(width: 1, thickness: 1, color: scheme.outlineVariant),
          Expanded(
            child: Stack(
              alignment: Alignment.bottomCenter,
              children: <Widget>[
                Positioned.fill(child: mainContent),
                if (floatingToolbar != null)
                  Positioned(
                    bottom: GxSpace.l,
                    child: floatingToolbar!,
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBadgedIcon(IconData iconData, int? badgeCount) {
    if (badgeCount == null || badgeCount <= 0) {
      return Icon(iconData);
    }
    return Badge.count(
      count: badgeCount,
      child: Icon(iconData),
    );
  }
}

/// Banner informativo para indicar el modo de operación offline verificable (`INV-01`).
class GxOfflineBanner extends StatelessWidget {
  const GxOfflineBanner({
    required this.isOffline,
    required this.trustBundleVersion,
    required this.statusFreshnessLabel,
    this.onToggleOfflineMode,
    super.key,
  });

  final bool isOffline;
  final int trustBundleVersion;
  final String statusFreshnessLabel;
  final VoidCallback? onToggleOfflineMode;

  @override
  Widget build(BuildContext context) {
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final tone = isOffline ? semantic.warning : semantic.info;

    return Material(
      color: tone.container,
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: GxSpace.l,
          vertical: GxSpace.s,
        ),
        child: Wrap(
          spacing: GxSpace.s,
          runSpacing: GxSpace.xs,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: <Widget>[
            Icon(
              isOffline
                  ? Icons.wifi_off_rounded
                  : Icons.verified_user_outlined,
              size: 18,
              color: tone.onContainer,
            ),
            ConstrainedBox(
              constraints: BoxConstraints(
                maxWidth: MediaQuery.sizeOf(context).width -
                    (GxSpace.l * 2) -
                    18 -
                    GxSpace.s,
              ),
              child: Text(
                isOffline
                    ? 'Modo Offline Activo (INV-01) · TrustBundle v$trustBundleVersion · Caché: $statusFreshnessLabel'
                    : 'Sincronizado · TrustBundle v$trustBundleVersion (3/5 TFA) · Estado fresco ($statusFreshnessLabel)',
                style: (emphasized?.labelMedium ??
                        Theme.of(context).textTheme.labelMedium)
                    ?.copyWith(color: tone.onContainer),
              ),
            ),
            if (onToggleOfflineMode != null)
              TextButton.icon(
                onPressed: onToggleOfflineMode,
                icon: Icon(
                  isOffline ? Icons.cloud_sync_rounded : Icons.airplanemode_on,
                  size: 16,
                  color: tone.onContainer,
                ),
                label: Text(
                  isOffline ? 'Conectar' : 'Simular Offline',
                  style: Theme.of(context)
                      .textTheme
                      .labelSmall
                      ?.copyWith(color: tone.onContainer),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// Estado vacío expresivo con icono, título, descripción y acción opcional.
class GxEmptyState extends StatelessWidget {
  const GxEmptyState({
    required this.icon,
    required this.title,
    required this.description,
    this.actionLabel,
    this.onAction,
    super.key,
  });

  final IconData icon;
  final String title;
  final String description;
  final String? actionLabel;
  final VoidCallback? onAction;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return Center(
      child: Padding(
        padding: const EdgeInsets.all(GxSpace.xxl),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                color: scheme.secondaryContainer,
                borderRadius: GxShape.extraLarge,
              ),
              child: Icon(
                icon,
                size: 36,
                color: scheme.onSecondaryContainer,
              ),
            ),
            const SizedBox(height: GxSpace.l),
            Text(
              title,
              textAlign: TextAlign.center,
              style: emphasized?.titleLarge ??
                  Theme.of(context).textTheme.titleLarge,
            ),
            const SizedBox(height: GxSpace.s),
            Text(
              description,
              textAlign: TextAlign.center,
              style: Theme.of(context)
                  .textTheme
                  .bodyMedium
                  ?.copyWith(color: scheme.onSurfaceVariant),
            ),
            if (actionLabel != null && onAction != null) ...<Widget>[
              const SizedBox(height: GxSpace.xl),
              OutlinedButton(
                onPressed: onAction,
                child: Text(actionLabel!),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

/// Tarjeta de error normativo del protocolo con código estable (`GID-Exxxx`) sin PII (`INV-02`).
class GxErrorState extends StatelessWidget {
  const GxErrorState({
    required this.errorCode,
    required this.identifier,
    required this.title,
    required this.description,
    this.remediationLabel,
    this.onRemediate,
    super.key,
  });

  final String errorCode;
  final String identifier;
  final String title;
  final String description;
  final String? remediationLabel;
  final VoidCallback? onRemediate;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return Container(
      padding: const EdgeInsets.all(GxSpace.l),
      decoration: BoxDecoration(
        color: scheme.errorContainer,
        borderRadius: GxShape.large,
        border: Border.all(color: scheme.error),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Row(
            children: <Widget>[
              Icon(Icons.gpp_maybe_rounded, color: scheme.onErrorContainer),
              const SizedBox(width: GxSpace.s),
              Flexible(
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: GxSpace.s,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: scheme.error,
                    borderRadius: GxShape.full,
                  ),
                  child: Text(
                    '$errorCode · $identifier',
                    overflow: TextOverflow.ellipsis,
                    style: GxTypography.tabular(
                      Theme.of(context).textTheme.labelSmall,
                    ).copyWith(color: scheme.onError),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: GxSpace.m),
          Text(
            title,
            style: (emphasized?.titleMedium ??
                    Theme.of(context).textTheme.titleMedium)
                ?.copyWith(color: scheme.onErrorContainer),
          ),
          const SizedBox(height: GxSpace.xs),
          Text(
            description,
            style: Theme.of(context)
                .textTheme
                .bodyMedium
                ?.copyWith(color: scheme.onErrorContainer),
          ),
          if (remediationLabel != null && onRemediate != null) ...<Widget>[
            const SizedBox(height: GxSpace.m),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: onRemediate,
                icon: Icon(
                  Icons.arrow_forward_rounded,
                  color: scheme.onErrorContainer,
                ),
                label: Text(
                  remediationLabel!,
                  style: emphasized?.labelLarge?.copyWith(
                    color: scheme.onErrorContainer,
                  ),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}
