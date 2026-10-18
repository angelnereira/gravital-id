// Adaptadores expresivos M3E de Gravital-Experience-UI (SPEC-PIP-UI-001 §9.2).
// Verifies: REQ-UI-001, REQ-UI-004

import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/physics.dart';

import '../theme/gx_theme.dart';
import '../tokens/tokens.dart';

/// Envoltorio interactivo con retroalimentación física de resorte (`GxMotion.fastSpatial`).
///
/// Cumple con `SPEC-PIP-UI-001 §7.2` y `§10`: usa un `AnimationController` sin cotas
/// para permitir sobreimpulso subamortiguado y respeta `MediaQuery.disableAnimationsOf`.
class GxSpringScale extends StatefulWidget {
  const GxSpringScale({
    required this.child,
    this.onTap,
    this.pressedScale = 0.96,
    this.semanticLabel,
    super.key,
  });

  final Widget child;
  final VoidCallback? onTap;
  final double pressedScale;
  final String? semanticLabel;

  @override
  State<GxSpringScale> createState() => _GxSpringScaleState();
}

class _GxSpringScaleState extends State<GxSpringScale>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController.unbounded(
    value: 1.0,
    vsync: this,
  );

  void _animateTo(double target) {
    if (MediaQuery.disableAnimationsOf(context)) {
      _controller.value = target;
      return;
    }
    _controller.animateWith(
      SpringSimulation(
        GxMotion.fastSpatial,
        _controller.value,
        target,
        0.0,
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Semantics(
        button: widget.onTap != null,
        label: widget.semanticLabel,
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTapDown: widget.onTap != null
              ? (_) => _animateTo(widget.pressedScale)
              : null,
          onTapUp: widget.onTap != null
              ? (_) {
                  _animateTo(1.0);
                  widget.onTap?.call();
                }
              : null,
          onTapCancel: widget.onTap != null ? () => _animateTo(1.0) : null,
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, child) => Transform.scale(
              scale: _controller.value.clamp(0.85, 1.08),
              child: child,
            ),
            child: widget.child,
          ),
        ),
      );
}

/// Opción secundaria para el menú desplegable de [GxSplitButton].
@immutable
class GxSplitButtonMenuItem<T> {
  const GxSplitButtonMenuItem({
    required this.value,
    required this.label,
    required this.icon,
    this.subtitle,
  });

  final T value;
  final String label;
  final IconData icon;
  final String? subtitle;
}

/// Botón dividido expresivo M3E (`GxSplitButton`, SPEC-PIP-UI-001 §9.2).
///
/// Combina una acción principal rápida (segmento izquierdo con forma stadium exterior
/// y esquina interna pequeña) con un disparador de variantes secundarias (segmento derecho
/// con objetivo táctil mínimo de 48×48 dp).
class GxSplitButton<T> extends StatelessWidget {
  const GxSplitButton({
    required this.label,
    required this.icon,
    required this.onPressed,
    required this.items,
    required this.onItemSelected,
    this.menuTooltip = 'Más opciones de presentación',
    super.key,
  });

  final String label;
  final IconData icon;
  final VoidCallback? onPressed;
  final List<GxSplitButtonMenuItem<T>> items;
  final ValueChanged<T> onItemSelected;
  final String menuTooltip;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: <Widget>[
        Flexible(
          child: ConstrainedBox(
            constraints: const BoxConstraints(minHeight: 48),
            child: Material(
              color: scheme.primary,
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(9999),
                bottomLeft: Radius.circular(9999),
                topRight: Radius.circular(4),
                bottomRight: Radius.circular(4),
              ),
              clipBehavior: Clip.antiAlias,
              child: InkWell(
                onTap: onPressed,
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: GxSpace.l,
                    vertical: GxSpace.m,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: <Widget>[
                      Icon(icon, size: 20, color: scheme.onPrimary),
                      const SizedBox(width: GxSpace.s),
                      Flexible(
                        child: Text(
                          label,
                          overflow: TextOverflow.ellipsis,
                          style: (emphasized?.labelLarge ??
                                  Theme.of(context).textTheme.labelLarge)
                              ?.copyWith(color: scheme.onPrimary),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
        const SizedBox(width: 2),
        PopupMenuButton<T>(
          tooltip: menuTooltip,
          onSelected: onItemSelected,
          shape: const RoundedRectangleBorder(borderRadius: GxShape.large),
          color: scheme.surfaceContainerHigh,
          itemBuilder: (context) => items
              .map(
                (item) => PopupMenuItem<T>(
                  value: item.value,
                  child: Row(
                    children: <Widget>[
                      Icon(item.icon, size: 20, color: scheme.primary),
                      const SizedBox(width: GxSpace.m),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: <Widget>[
                            Text(
                              item.label,
                              style: Theme.of(context).textTheme.labelLarge,
                            ),
                            if (item.subtitle != null)
                              Text(
                                item.subtitle!,
                                style: Theme.of(context)
                                    .textTheme
                                    .bodySmall
                                    ?.copyWith(color: scheme.onSurfaceVariant),
                              ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              )
              .toList(),
          child: Container(
            constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
            decoration: BoxDecoration(
              color: scheme.primary,
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(4),
                bottomLeft: Radius.circular(4),
                topRight: Radius.circular(9999),
                bottomRight: Radius.circular(9999),
              ),
            ),
            alignment: Alignment.center,
            child: Icon(
              Icons.keyboard_arrow_down_rounded,
              color: scheme.onPrimary,
              size: 22,
            ),
          ),
        ),
      ],
    );
  }
}

/// Segmento individual de [GxButtonGroup].
@immutable
class GxButtonSegment<T> {
  const GxButtonSegment({
    required this.value,
    required this.label,
    required this.icon,
    this.badgeText,
  });

  final T value;
  final String label;
  final IconData icon;
  final String? badgeText;
}

/// Grupo de botones conectados con transformación de forma M3E (`GxButtonGroup`, SPEC-PIP-UI-001 §9.2).
///
/// El segmento activo adopta geometría `GxShape.full` (stadium) con relleno `secondaryContainer`,
/// mientras los segmentos inactivos conservan esquinas internas `GxShape.small`.
class GxButtonGroup<T> extends StatelessWidget {
  const GxButtonGroup({
    required this.segments,
    required this.selected,
    required this.onChanged,
    super.key,
  });

  final List<GxButtonSegment<T>> segments;
  final T selected;
  final ValueChanged<T> onChanged;

  Widget _buildSegmentButton(
    BuildContext context,
    int index, {
    required bool isGrid,
  }) {
    final scheme = Theme.of(context).colorScheme;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;
    final segment = segments[index];
    final isSelected = segment.value == selected;
    final isFirst = index == 0;
    final isLast = index == segments.length - 1;

    final borderRadius = isSelected
        ? GxShape.full
        : isGrid
            ? GxShape.large
            : BorderRadius.only(
                topLeft: Radius.circular(isFirst ? 24 : 8),
                bottomLeft: Radius.circular(isFirst ? 24 : 8),
                topRight: Radius.circular(isLast ? 24 : 8),
                bottomRight: Radius.circular(isLast ? 24 : 8),
              );

    return GxSpringScale(
      semanticLabel: segment.label,
      onTap: () => onChanged(segment.value),
      child: AnimatedContainer(
        duration: MediaQuery.disableAnimationsOf(context)
            ? Duration.zero
            : const Duration(milliseconds: 180),
        constraints: const BoxConstraints(minHeight: 48, minWidth: 48),
        padding: EdgeInsets.symmetric(
          horizontal: isGrid ? GxSpace.s + 2 : GxSpace.m,
          vertical: GxSpace.s,
        ),
        decoration: BoxDecoration(
          color: isSelected
              ? scheme.secondaryContainer
              : scheme.surfaceContainerHigh,
          borderRadius: borderRadius,
          border: Border.all(
            color: isSelected ? scheme.secondary : scheme.outlineVariant,
            width: isSelected ? 1.5 : 1,
          ),
        ),
        child: Row(
          mainAxisSize: isGrid ? MainAxisSize.max : MainAxisSize.min,
          mainAxisAlignment:
              isGrid ? MainAxisAlignment.center : MainAxisAlignment.start,
          children: <Widget>[
            Icon(
              segment.icon,
              size: 18,
              color: isSelected
                  ? scheme.onSecondaryContainer
                  : scheme.onSurfaceVariant,
            ),
            const SizedBox(width: GxSpace.xs + 2),
            Flexible(
              child: Text(
                segment.label,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: (isSelected
                        ? emphasized?.labelLarge
                        : Theme.of(context).textTheme.labelLarge)
                    ?.copyWith(
                  color: isSelected
                      ? scheme.onSecondaryContainer
                      : scheme.onSurfaceVariant,
                ),
              ),
            ),
            if (segment.badgeText != null) ...<Widget>[
              const SizedBox(width: GxSpace.xs),
              Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: GxSpace.xs + 2,
                  vertical: 2,
                ),
                decoration: BoxDecoration(
                  color: isSelected
                      ? scheme.primary
                      : scheme.surfaceContainerHighest,
                  borderRadius: GxShape.full,
                ),
                child: Text(
                  segment.badgeText!,
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                        color: isSelected
                            ? scheme.onPrimary
                            : scheme.onSurfaceVariant,
                      ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final textScale = MediaQuery.textScalerOf(context).scale(1.0);
    if (textScale > 1.35 || segments.length > 4) {
      return Wrap(
        spacing: GxSpace.xs,
        runSpacing: GxSpace.xs,
        children: List<Widget>.generate(
          segments.length,
          (index) => _buildSegmentButton(context, index, isGrid: false),
        ),
      );
    }

    if (segments.length == 4) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Row(
            children: <Widget>[
              Expanded(
                child: _buildSegmentButton(context, 0, isGrid: true),
              ),
              const SizedBox(width: GxSpace.s),
              Expanded(
                child: _buildSegmentButton(context, 1, isGrid: true),
              ),
            ],
          ),
          const SizedBox(height: GxSpace.s),
          Row(
            children: <Widget>[
              Expanded(
                child: _buildSegmentButton(context, 2, isGrid: true),
              ),
              const SizedBox(width: GxSpace.s),
              Expanded(
                child: _buildSegmentButton(context, 3, isGrid: true),
              ),
            ],
          ),
        ],
      );
    }

    return Row(
      children: <Widget>[
        for (int i = 0; i < segments.length; i++) ...<Widget>[
          if (i > 0) const SizedBox(width: GxSpace.s),
          Expanded(
            child: _buildSegmentButton(context, i, isGrid: true),
          ),
        ],
      ],
    );
  }
}

/// Barra de herramientas flotante tipo píldora M3E (`GxFloatingToolbar`, SPEC-PIP-UI-001 §9.2).
class GxFloatingToolbar extends StatelessWidget {
  const GxFloatingToolbar({
    required this.children,
    super.key,
  });

  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Material(
      color: scheme.surfaceContainerHigh,
      elevation: 3,
      shadowColor: scheme.shadow.withValues(alpha: 0.18),
      borderRadius: GxShape.full,
      child: Padding(
        padding: const EdgeInsets.symmetric(
          horizontal: GxSpace.m,
          vertical: GxSpace.xs,
        ),
        child: Wrap(
          spacing: GxSpace.xs,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: children,
        ),
      ),
    );
  }
}

/// Indicador de carga expresivo M3E con transformación suave de forma (`GxLoadingIndicator`, SPEC-PIP-UI-001 §9.2).
class GxLoadingIndicator extends StatefulWidget {
  const GxLoadingIndicator({
    this.size = 40,
    this.label,
    super.key,
  });

  final double size;
  final String? label;

  @override
  State<GxLoadingIndicator> createState() => _GxLoadingIndicatorState();
}

class _GxLoadingIndicatorState extends State<GxLoadingIndicator>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1400),
  );

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (MediaQuery.disableAnimationsOf(context)) {
      _controller.stop();
    } else if (!_controller.isAnimating) {
      _controller.repeat();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Semantics(
      label: widget.label ?? 'Cargando operación criptográfica',
      child: Center(
        child: SizedBox.square(
          dimension: widget.size,
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, _) {
              final t = _controller.value;
              final cornerFactor = 0.25 + 0.25 * math.sin(t * 2 * math.pi);
              final radius = widget.size * cornerFactor;
              return Transform.rotate(
                angle: t * math.pi,
                child: Container(
                  width: widget.size,
                  height: widget.size,
                  decoration: BoxDecoration(
                    color: scheme.primaryContainer,
                    borderRadius: BorderRadius.circular(radius),
                    border: Border.all(
                      color: scheme.primary,
                      width: 3,
                    ),
                  ),
                  alignment: Alignment.center,
                  child: Container(
                    width: widget.size * 0.36,
                    height: widget.size * 0.36,
                    decoration: BoxDecoration(
                      color: scheme.primary,
                      borderRadius: BorderRadius.circular(widget.size * 0.18),
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }
}
