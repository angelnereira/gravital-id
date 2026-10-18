// Pantalla de Inquilinos, Portabilidad de Datos y Roles Verificables (Capa 5).
// Cumple estrictamente SPEC-PIP-UI-001 (Gravital-Experience-UI).
// Verifies: REQ-TENANT-001, REQ-TENANT-002, REQ-TENANT-003, REQ-TENANT-004, REQ-UI-001, REQ-UI-003

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../domain/gravital_wallet_store.dart';

/// Hub de servicios/sistemas que consumen Gravital ID, portabilidad de atributos
/// y roles verificables por aplicación (`ADR-0027`, `pip-tenant-role-v1`).
class TenantsPortabilityScreen extends StatelessWidget {
  const TenantsPortabilityScreen({
    required this.store,
    required this.onNavigateToPresent,
    super.key,
  });

  final GravitalWalletStore store;
  final VoidCallback onNavigateToPresent;

  void _openPortabilityEditor(BuildContext context, ConnectedTenantApp app) {
    final claims = app.availableClaims
        .map(
          (key) => GxDisclosableClaim(
            key: key,
            label: _humanLabelForClaim(key),
            valuePreview: _previewForClaim(key),
            isRequiredByVerifier: key == 'given_name',
            isSensitiveLevel1: key == 'document_number' || key == 'birth_date',
            initiallySelected: app.sharedClaims.contains(key),
          ),
        )
        .toList();

    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (sheetContext) => GxDisclosureConsentSheet(
        verifierName: app.tenantName,
        verifierDomain: app.tenantId,
        purpose:
            'Portabilidad de datos controlada por el usuario y roles (${app.roles.join(", ")})',
        transportLabel: 'OID4VP / Tenant Gateway',
        isVerifierSigned: true,
        tenantSubjectIdPreview: app.tenantSubjectId,
        claims: claims,
        onConfirmDisclosures: (selectedKeys) {
          store.updateTenantSharedClaims(
            app.tenantId,
            selectedKeys.toList(),
          );
          Navigator.of(sheetContext).pop();
        },
      ),
    );
  }

  void _openConnectNewTenantDialog(BuildContext context) {
    final nameController =
        TextEditingController(text: 'Hospital Punta Pacífica — Portal Salud');
    final idController =
        TextEditingController(text: 'urn:gravital-id:tenant:salud-pacifica');
    final roleController = TextEditingController(text: 'paciente_titular');

    showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Conectar Nuevo Sistema / Inquilino con tu Gravital ID'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Text(
                'El sistema aloja el SDK / Tenant Gateway de Gravital ID. '
                'Reutilizas tu mismo Gravital ID sin crear cuentas duplicadas y eliges qué datos portar.',
              ),
              const SizedBox(height: GxSpace.m),
              TextField(
                controller: nameController,
                decoration: const InputDecoration(
                  labelText: 'Nombre de la App o Sistema',
                  prefixIcon: Icon(Icons.apps_rounded),
                ),
              ),
              const SizedBox(height: GxSpace.m),
              TextField(
                controller: idController,
                decoration: const InputDecoration(
                  labelText: 'Identificador Canónico de Inquilino (TenantId)',
                  prefixIcon: Icon(Icons.link_rounded),
                ),
              ),
              const SizedBox(height: GxSpace.m),
              TextField(
                controller: roleController,
                decoration: const InputDecoration(
                  labelText: 'Rol Solicitado en la App (pip-tenant-role-v1)',
                  prefixIcon: Icon(Icons.admin_panel_settings_outlined),
                ),
              ),
            ],
          ),
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Cancelar'),
          ),
          OutlinedButton.icon(
            onPressed: () {
              store.connectNewTenantApp(
                tenantId: idController.text.trim(),
                tenantName: nameController.text.trim(),
                tenantSector: 'Ecosistema Federado · Tenant Gateway Autoalojado',
                requestedRoles: <String>[roleController.text.trim()],
                requestedPermissions: const <String>[
                  'profile:portability:read',
                  'session:authenticated',
                ],
                approvedClaims: const <String>['given_name', 'age_over_18'],
              );
              Navigator.of(dialogContext).pop();
            },
            icon: const Icon(Icons.check_rounded),
            label: const Text('Autorizar e Ingresar'),
          ),
        ],
      ),
    );
  }

  static String _humanLabelForClaim(String key) => switch (key) {
        'given_name' => 'Nombres',
        'family_name' => 'Apellidos',
        'age_over_18' => 'Predicado Mayor de 18 Años',
        'nationality' => 'Nacionalidad (PA)',
        'document_number' => 'Número de Cédula (Nivel 1)',
        'birth_date' => 'Fecha de Nacimiento (Nivel 1)',
        _ => key,
      };

  static String _previewForClaim(String key) => switch (key) {
        'given_name' => 'Ángel Gabriel',
        'family_name' => 'Nereira',
        'age_over_18' => 'true',
        'nationality' => 'PA',
        'document_number' => '8-888-8888',
        'birth_date' => '1994-06-14',
        _ => '***',
      };

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final semantic = Theme.of(context).extension<SemanticColors>()!;
    final emphasized =
        Theme.of(context).extension<EmphasizedTextTheme>()?.textTheme;

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
            color: scheme.secondaryContainer,
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
                    label: 'CENTRALIZACIÓN SOBERANA MULTI-INQUILINO (ADR-0027)',
                    tone: semantic.info,
                    icon: Icons.hub_rounded,
                  ),
                  StatusChip(
                    label: '${store.tenants.length} SISTEMAS CONECTADOS',
                    tone: semantic.success,
                    icon: Icons.verified_user_rounded,
                  ),
                ],
              ),
              const SizedBox(height: GxSpace.m),
              Text(
                'Un Mismo Gravital ID para Todos tus Sistemas y Roles',
                style: (emphasized?.headlineSmall ??
                        Theme.of(context).textTheme.headlineSmall)
                    ?.copyWith(color: scheme.onSecondaryContainer),
              ),
              const SizedBox(height: GxSpace.xs),
              Text(
                'Cualquier servidor, app o empresa puede alojar el Tenant Gateway de Gravital ID. '
                'Tú ingresas con tu Gravital ID existente (o creas uno nuevo si aún no lo tienes), '
                'mantienes una identidad consistente por inquilino (TenantSubjectId) y decides exactamente '
                'qué atributos y qué roles (pip-tenant-role-v1) compartes con cada sistema.',
                style: Theme.of(context)
                    .textTheme
                    .bodyMedium
                    ?.copyWith(color: scheme.onSecondaryContainer),
              ),
              const SizedBox(height: GxSpace.l),
              // Único FilledButton de esta pantalla (Regla SPEC-PIP-UI-001 §15.1)
              FilledButton.icon(
                onPressed: () => _openConnectNewTenantDialog(context),
                icon: const Icon(Icons.add_link_rounded),
                label: const Text(
                  'Ingresar / Portar Datos a Nueva App o Servicio',
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: GxSpace.xl),
        Text(
          'Aplicaciones, Servicios e Inquilinos Vinculados',
          style: emphasized?.titleLarge,
        ),
        const SizedBox(height: GxSpace.xs),
        Text(
          'Toca "Qué Datos Comparto" para encender o apagar los atributos que portas hacia cada sistema.',
          style: Theme.of(context)
              .textTheme
              .bodyMedium
              ?.copyWith(color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: GxSpace.m),
        if (store.tenants.isEmpty)
          GxEmptyState(
            icon: Icons.hub_outlined,
            title: 'Ningún Sistema Conectado',
            description:
                'Conecta una aplicación o servidor que aloje Gravital ID para portar tus atributos y roles verificables.',
            actionLabel: 'Conectar Primer Inquilino',
            onAction: () => _openConnectNewTenantDialog(context),
          )
        else
          ...store.tenants.map(
            (tenant) => Padding(
              padding: const EdgeInsets.only(bottom: GxSpace.m),
              child: GxTenantAccessCard(
                tenantId: tenant.tenantId,
                tenantName: tenant.tenantName,
                tenantSector: tenant.tenantSector,
                tenantSubjectId: tenant.tenantSubjectId,
                roles: tenant.roles,
                permissions: tenant.permissions,
                sharedClaims: tenant.sharedClaims,
                statusState: store.isOfflineMode
                    ? GxVerificationState.validWithStaleStatus
                    : tenant.statusState,
                onManagePortability: () =>
                    _openPortabilityEditor(context, tenant),
                onPresentRoleAccess: () {
                  store.selectCredential(2); // Credencial pip-tenant-role-v1
                  onNavigateToPresent();
                },
                onRevokeTenant: () => store.revokeTenantApp(tenant.tenantId),
              ),
            ),
          ),
      ],
    );
  }
}
