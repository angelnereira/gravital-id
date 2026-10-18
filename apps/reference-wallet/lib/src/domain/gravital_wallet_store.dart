// Motor de estado de dominio de la Wallet de Referencia Gravital ID.
// Implementa las reglas de ADR-0025, ADR-0027, ADR-0028 y ADR-0029.
// Verifies: REQ-TENANT-001, REQ-TENANT-002, REQ-TENANT-003, REQ-TENANT-004,
// Verifies: REQ-UNIQ-001, REQ-UNIQ-002, REQ-UNIQ-003, REQ-UNIQ-004,
// Verifies: REQ-DEVSLOT-001, REQ-DEVSLOT-002, REQ-DEVSLOT-003, REQ-DEVSLOT-004,
// Verifies: REQ-CODE-002, REQ-IDDOC-001, REQ-IDDOC-002, REQ-PRES-003

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

import '../services/nfc_apdu_service.dart';
import '../services/passkey_service.dart';

export '../services/nfc_apdu_service.dart';
export '../services/passkey_service.dart';

/// Algoritmo de dígito verificador cuasigrupo de Damm (orden 10) para `SessionCode` (`ADR-0025`, `REQ-CODE-002`).
///
/// Detecta el 100 % de errores de un solo dígito y el 100 % de transposiciones adyacentes.
abstract final class DammSessionCode {
  static const List<List<int>> _matrix = <List<int>>[
    <int>[0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
    <int>[7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
    <int>[4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
    <int>[1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
    <int>[6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
    <int>[3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
    <int>[5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
    <int>[8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
    <int>[9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
    <int>[2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
  ];

  /// Calcula el dígito de control Damm para una cadena de 9 dígitos.
  static int computeCheckDigit(String nineDigits) {
    var interim = 0;
    for (final rune in nineDigits.runes) {
      final digit = rune - 0x30;
      if (digit < 0 || digit > 9) {
        throw const FormatException('Solo se permiten dígitos ASCII 0..9');
      }
      interim = _matrix[interim][digit];
    }
    return interim;
  }

  /// Genera un código de 10 dígitos con formato `DDDDD-DDDDC` a partir de 9 dígitos base.
  static String formatFromPayload(String nineDigits) {
    final clean = nineDigits.replaceAll(RegExp('[^0-9]'), '');
    if (clean.length != 9) {
      throw const FormatException('Se requieren exactamente 9 dígitos base');
    }
    final check = computeCheckDigit(clean);
    final ten = '$clean$check';
    return '${ten.substring(0, 5)}-${ten.substring(5)}';
  }

  /// Valida un código de sesión de 10 dígitos (con o sin guion).
  static bool isValid(String input) {
    final clean = input.replaceAll(RegExp(r'[\s\-]'), '');
    if (clean.length != 10) return false;
    var interim = 0;
    for (final rune in clean.runes) {
      final digit = rune - 0x30;
      if (digit < 0 || digit > 9) return false;
      interim = _matrix[interim][digit];
    }
    return interim == 0;
  }
}

/// Perfil nacional de identidad ciudadana y cumplimiento con el Tribunal Electoral de Panamá
/// (`ADR-0028`, `REQ-UNIQ-001`..`004`).
///
/// Normativa:
/// - Ley 68 de 2 de noviembre de 2015 (Cédula inteligente con chip, Tribunal Electoral),
/// - Decreto N.° 43 de 8 de octubre de 2024 (Cédula Digital y Servicio de Verificación de Identidad - SVI),
/// - Ley 81 de 26 de marzo de 2019 (Protección de Datos Personales).
abstract final class PanamaNationalIdProfile {
  /// Expresión regular canónica de la Cédula de Identidad Personal de Panamá (TE).
  static final RegExp cedulaPattern = RegExp(
    r'^(?:(?:[1-9]|1[0-3]|E|N|PE)(?:AV|PI)?|[1-9](?:AV|PI))-[0-9]{1,5}-[0-9]{1,6}$',
  );

  /// Normaliza el identificador ciudadano eliminando espacios y convirtiendo a mayúsculas ASCII.
  static String normalize(String raw) =>
      raw.trim().toUpperCase().replaceAll(RegExp(r'\s+'), '');

  /// Comprueba si el número de cédula cumple el formato oficial del Tribunal Electoral.
  static bool isValidPanamaCedula(String raw) =>
      cedulaPattern.hasMatch(normalize(raw));

  /// Deriva de forma determinista la etiqueta ciega `UniquenessTag` (representación VOPRF RFC 9497 P-256)
  /// sin exponer el número de cédula en claro ni en un hash público reversible (`INV-02`, `REQ-UNIQ-002`).
  static String deriveBlindUniquenessTag(
    String issuerId,
    String countryCode,
    String rawDocumentNumber,
  ) {
    final canonical =
        '${issuerId.toLowerCase()}|${countryCode.toUpperCase()}|${normalize(rawDocumentNumber)}';
    var acc1 = 0x811C9DC5;
    var acc2 = 0x01000193;
    for (final codeUnit in canonical.codeUnits) {
      acc1 ^= codeUnit;
      acc1 = (acc1 * 0x01000193) & 0xFFFFFFFF;
      acc2 ^= (codeUnit + 0x9E3779B9) & 0xFFFFFFFF;
      acc2 = ((acc2 << 5) | (acc2 >> 27)) & 0xFFFFFFFF;
    }
    final hex1 = acc1.toRadixString(16).padLeft(8, '0');
    final hex2 = acc2.toRadixString(16).padLeft(8, '0');
    return 'voprf:p256:${countryCode.toLowerCase()}:$hex1$hex2';
  }
}

/// Clase de factor de dispositivo (`DeviceFactorClass`, `ADR-0029`, `REQ-DEVSLOT-001`).
///
/// Un titular puede tener su Gravital ID activo en **máximo 1 dispositivo por clase**
/// simultáneamente (p. ej. 1 teléfono + 1 tarjeta tipo Visa + 1 otro dispositivo compatible),
/// pero **nunca** en dos dispositivos de la misma clase.
enum DeviceFactorClass {
  mobile(
    code: 'mobile',
    title: 'Teléfono Móvil (NFC / QR / Bluetooth)',
    hardwareRoot: 'Chip de seguridad integrado (StrongBox / Secure Enclave)',
    icon: Icons.smartphone_rounded,
  ),
  card(
    code: 'card',
    title: 'Tarjeta Física Sin Contacto Tipo Visa',
    hardwareRoot: 'Chip inteligente de alta seguridad con PIN',
    icon: Icons.credit_card_rounded,
  ),
  other(
    code: 'other',
    title: 'Llave de Seguridad USB / NFC (FIDO2)',
    hardwareRoot: 'Dispositivo criptográfico externo compatible',
    icon: Icons.usb_rounded,
  );

  const DeviceFactorClass({
    required this.code,
    required this.title,
    required this.hardwareRoot,
    required this.icon,
  });

  final String code;
  final String title;
  final String hardwareRoot;
  final IconData icon;
}

/// Estado de una ranura de dispositivo dentro del registro del titular (`ADR-0029`).
@immutable
class DeviceSlotEnrollment {
  const DeviceSlotEnrollment({
    required this.factorClass,
    required this.deviceModelName,
    required this.hardwareAttestationId,
    required this.statusListIndex,
    required this.enrolledAtIso,
    this.previousRevokedIndex,
  });

  final DeviceFactorClass factorClass;
  final String deviceModelName;
  final String hardwareAttestationId;
  final int statusListIndex;
  final String enrolledAtIso;
  final int? previousRevokedIndex;
}

/// Resultado de intentar vincular un dispositivo o registrar una identidad ciudadana.
@immutable
class ProtocolOperationOutcome {
  const ProtocolOperationOutcome({
    required this.succeeded,
    required this.title,
    required this.description,
    this.errorCode,
    this.errorIdentifier,
    this.uniquenessTag,
    this.revokedStatusIndex,
  });

  final bool succeeded;
  final String title;
  final String description;
  final String? errorCode;
  final String? errorIdentifier;
  final String? uniquenessTag;
  final int? revokedStatusIndex;
}

/// Modelo de credencial almacenada en la bóveda cifrada local.
@immutable
class WalletCredentialRecord {
  const WalletCredentialRecord({
    required this.id,
    required this.title,
    required this.subtitle,
    required this.vct,
    required this.issuerId,
    required this.issuerName,
    required this.statusState,
    required this.factorClass,
    required this.securityLevelLabel,
    required this.remainingBatchCopies,
    required this.claims,
    this.documentNumberMasked,
    this.hasPortrait = false,
    this.isOfficialStateCredential = false,
  });

  final String id;
  final String title;
  final String subtitle;
  final String vct;
  final String issuerId;
  final String issuerName;
  final GxVerificationState statusState;
  final DeviceFactorClass factorClass;
  final String securityLevelLabel;
  final int remainingBatchCopies;
  final List<GxDisclosableClaim> claims;
  final String? documentNumberMasked;
  final bool hasPortrait;
  final bool isOfficialStateCredential;
}

/// Modelo de aplicación, sistema o servicio inquilino conectado a Gravital ID (`ADR-0027`).
@immutable
class ConnectedTenantApp {
  const ConnectedTenantApp({
    required this.tenantId,
    required this.tenantName,
    required this.tenantSector,
    required this.tenantSubjectId,
    required this.roles,
    required this.permissions,
    required this.sharedClaims,
    required this.availableClaims,
    required this.statusState,
  });

  final String tenantId;
  final String tenantName;
  final String tenantSector;
  final String tenantSubjectId;
  final List<String> roles;
  final List<String> permissions;
  final List<String> sharedClaims;
  final List<String> availableClaims;
  final GxVerificationState statusState;

  ConnectedTenantApp copyWith({
    List<String>? roles,
    List<String>? permissions,
    List<String>? sharedClaims,
    GxVerificationState? statusState,
  }) =>
      ConnectedTenantApp(
        tenantId: tenantId,
        tenantName: tenantName,
        tenantSector: tenantSector,
        tenantSubjectId: tenantSubjectId,
        roles: roles ?? this.roles,
        permissions: permissions ?? this.permissions,
        sharedClaims: sharedClaims ?? this.sharedClaims,
        availableClaims: availableClaims,
        statusState: statusState ?? this.statusState,
      );
}

/// Canal de transporte de presentación seleccionable en el estudio de acceso.
enum PresentationTransport {
  qrOffline(
    label: 'QR Offline (Base45)',
    icon: Icons.qr_code_2_rounded,
    supportsPortrait: false,
  ),
  nfcApdu(
    label: 'Toque NFC (GID-APDU)',
    icon: Icons.contactless_rounded,
    supportsPortrait: true,
  ),
  passkey(
    label: 'Passkey (FIDO2 / WebAuthn)',
    icon: Icons.fingerprint_rounded,
    supportsPortrait: true,
  ),
  sessionCode(
    label: 'Código Damm 10 Dígitos',
    icon: Icons.dialpad_rounded,
    supportsPortrait: true,
  );

  const PresentationTransport({
    required this.label,
    required this.icon,
    required this.supportsPortrait,
  });

  final String label;
  final IconData icon;
  final bool supportsPortrait;
}

/// Controlador reactivo del estado de la aplicación de referencia Gravital ID.
class GravitalWalletStore extends ChangeNotifier {
  GravitalWalletStore() {
    _seedInitialState();
  }

  static const String defaultIssuerId = 'did:web:te.gob.pa:svi-emisor';

  final NfcApduService nfcService = NfcApduService();
  final PasskeyPresentationService passkeyService = PasskeyPresentationService();

  NfcOperatingMode _nfcMode = NfcOperatingMode.hceCardEmulation;
  NfcOperatingMode get nfcMode => _nfcMode;

  int _selectedPasskeyIndex = 0;
  int get selectedPasskeyIndex => _selectedPasskeyIndex;

  PasskeyAuthenticatorTransport _activePasskeyTransport =
      PasskeyAuthenticatorTransport.platformInternal;
  PasskeyAuthenticatorTransport get activePasskeyTransport =>
      _activePasskeyTransport;

  bool _isOfflineMode = false;
  bool get isOfflineMode => _isOfflineMode;

  ThemeMode _themeMode = ThemeMode.system;
  ThemeMode get themeMode => _themeMode;

  double _contrastLevel = 0.0;
  double get contrastLevel => _contrastLevel;

  int _selectedCredentialIndex = 0;
  int get selectedCredentialIndex => _selectedCredentialIndex;

  PresentationTransport _activeTransport = PresentationTransport.qrOffline;
  PresentationTransport get activeTransport => _activeTransport;

  GxVerificationState _simulatedVerificationState = GxVerificationState.valid;
  GxVerificationState get simulatedVerificationState =>
      _simulatedVerificationState;

  String _activeSessionCode = DammSessionCode.formatFromPayload('482910384');
  String get activeSessionCode => _activeSessionCode;

  Set<String> _lastConfirmedDisclosures = <String>{
    'given_name',
    'family_name',
    'age_over_18',
    'nationality',
  };
  Set<String> get lastConfirmedDisclosures => _lastConfirmedDisclosures;

  ProtocolOperationOutcome? _lastProtocolBanner;
  ProtocolOperationOutcome? get lastProtocolBanner => _lastProtocolBanner;

  final Set<String> _registeredUniquenessTags = <String>{};
  Set<String> get registeredUniquenessTags =>
      Set.unmodifiable(_registeredUniquenessTags);

  final Map<DeviceFactorClass, DeviceSlotEnrollment> _deviceSlots =
      <DeviceFactorClass, DeviceSlotEnrollment>{};
  Map<DeviceFactorClass, DeviceSlotEnrollment> get deviceSlots =>
      Map.unmodifiable(_deviceSlots);

  final List<int> _revokedStatusIndices = <int>[];
  List<int> get revokedStatusIndices => List.unmodifiable(_revokedStatusIndices);

  final List<WalletCredentialRecord> _credentials = <WalletCredentialRecord>[];
  List<WalletCredentialRecord> get credentials =>
      List.unmodifiable(_credentials);

  final List<ConnectedTenantApp> _tenants = <ConnectedTenantApp>[];
  List<ConnectedTenantApp> get tenants => List.unmodifiable(_tenants);

  int _nextStatusListIndex = 4105;

  WalletCredentialRecord get selectedCredential =>
      _credentials[_selectedCredentialIndex.clamp(0, _credentials.length - 1)];

  void _seedInitialState() {
    // Registrar la cédula titular inicial 8-888-8888 en el registro ciego VOPRF (ADR-0028)
    final primaryTag = PanamaNationalIdProfile.deriveBlindUniquenessTag(
      defaultIssuerId,
      'PA',
      '8-888-8888',
    );
    _registeredUniquenessTags.add(primaryTag);

    // Inicializar las 3 ranuras únicas por clase de factor de dispositivo (ADR-0029)
    _deviceSlots[DeviceFactorClass.mobile] = const DeviceSlotEnrollment(
      factorClass: DeviceFactorClass.mobile,
      deviceModelName: 'Google Pixel · Android (Chip Seguro)',
      hardwareAttestationId: 'Verificado por hardware · Serie #358240',
      statusListIndex: 4102,
      enrolledAtIso: '2026-10-15T09:30:00Z',
    );
    _deviceSlots[DeviceFactorClass.card] = const DeviceSlotEnrollment(
      factorClass: DeviceFactorClass.card,
      deviceModelName: 'Tarjeta Gravital ID sin Contacto (Formato Visa)',
      hardwareAttestationId: 'Chip inteligente · Serie #4A43-004A',
      statusListIndex: 4103,
      enrolledAtIso: '2026-10-15T10:15:00Z',
    );
    _deviceSlots[DeviceFactorClass.other] = const DeviceSlotEnrollment(
      factorClass: DeviceFactorClass.other,
      deviceModelName: 'Llave de Seguridad YubiKey 5 NFC',
      hardwareAttestationId: 'Llave FIDO2 certificada · Serie #2FC0',
      statusListIndex: 4104,
      enrolledAtIso: '2026-10-16T14:00:00Z',
    );

    // Inicializar credenciales de la bóveda
    _credentials.addAll(<WalletCredentialRecord>[
      const WalletCredentialRecord(
        id: 'cred-pa-te-official',
        title: 'Cédula de Identidad Personal (Panamá)',
        subtitle:
            'Tribunal Electoral · Decreto N.° 43 de 2024 · Vigente',
        vct: 'urn:gravital-id:vct:pip-identity-official-v1',
        issuerId: defaultIssuerId,
        issuerName: 'Tribunal Electoral de Panamá (SVI)',
        statusState: GxVerificationState.valid,
        factorClass: DeviceFactorClass.mobile,
        securityLevelLabel: 'Protección Hardware + PIN',
        remainingBatchCopies: 12,
        documentNumberMasked: 'Cédula: 8-888-8888 (PA)',
        hasPortrait: true,
        isOfficialStateCredential: true,
        claims: <GxDisclosableClaim>[
          GxDisclosableClaim(
            key: 'given_name',
            label: 'Nombres',
            valuePreview: 'Ángel Gabriel',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'family_name',
            label: 'Apellidos',
            valuePreview: 'Nereira',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'age_over_18',
            label: 'Mayor de 18 años',
            valuePreview: 'Sí (Verificado)',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'nationality',
            label: 'Nacionalidad',
            valuePreview: 'Panamá (PA)',
          ),
          GxDisclosableClaim(
            key: 'document_number',
            label: 'Número de Cédula',
            valuePreview: '8-888-8888',
            isSensitiveLevel1: true,
            initiallySelected: false,
          ),
          GxDisclosableClaim(
            key: 'birth_date',
            label: 'Fecha de Nacimiento',
            valuePreview: '14 de junio de 1994',
            isSensitiveLevel1: true,
            initiallySelected: false,
          ),
          GxDisclosableClaim(
            key: 'portrait',
            label: 'Fotografía Biométrica',
            valuePreview: 'Verificada (sin metadatos)',
            isSensitiveLevel1: true,
            initiallySelected: false,
          ),
        ],
      ),
      const WalletCredentialRecord(
        id: 'cred-card-identity-derived',
        title: 'Credencial en Tarjeta Física Tipo Visa (NFC)',
        subtitle:
            'Identidad verificada en tarjeta física sin contacto',
        vct: 'urn:gravital-id:vct:pip-identity-derived-v1',
        issuerId: 'did:web:bgeneral.com:emisor-kyc',
        issuerName: 'Banco General S.A. (Verificado por SVI)',
        statusState: GxVerificationState.valid,
        factorClass: DeviceFactorClass.card,
        securityLevelLabel: 'Chip Seguro · Toque o PIN',
        remainingBatchCopies: 6,
        documentNumberMasked: 'Tarjeta NFC · Terminación 004A',
        hasPortrait: true,
        claims: <GxDisclosableClaim>[
          GxDisclosableClaim(
            key: 'given_name',
            label: 'Nombres',
            valuePreview: 'Ángel Gabriel',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'age_over_18',
            label: 'Mayor de 18 años',
            valuePreview: 'Sí (Verificado)',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'evidence_type',
            label: 'Método de Verificación',
            valuePreview: 'Cédula y biometría presencial',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'document_number',
            label: 'Cédula Vinculada (Protegida con PIN)',
            valuePreview: '8-888-8888',
            isSensitiveLevel1: true,
            initiallySelected: false,
          ),
        ],
      ),
      const WalletCredentialRecord(
        id: 'cred-tenant-role-corp',
        title: 'Credencial Multi-Inquilino de Roles y Accesos',
        subtitle:
            'Acceso autorizado a edificios y sistemas corporativos',
        vct: 'urn:gravital-id:vct:pip-tenant-role-v1',
        issuerId: 'did:web:auth.torrepacifica.pa',
        issuerName: 'Consorcio Torre Financiera & Cloud Gateway',
        statusState: GxVerificationState.valid,
        factorClass: DeviceFactorClass.mobile,
        securityLevelLabel: 'Identificador Privado por Sistema',
        remainingBatchCopies: 16,
        documentNumberMasked: 'Rol: Administrador / Operador',
        claims: <GxDisclosableClaim>[
          GxDisclosableClaim(
            key: 'tenant_id',
            label: 'Organización',
            valuePreview: 'Torre Financiera Pacífica',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'tenant_subject_id',
            label: 'Identificador de Miembro',
            valuePreview: 'TP-9F4A2C81',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'roles',
            label: 'Roles Asignados',
            valuePreview: 'Administrador, Operador de Centro de Datos',
            isRequiredByVerifier: true,
          ),
          GxDisclosableClaim(
            key: 'permissions',
            label: 'Zonas y Permisos',
            valuePreview: 'Torniquete Principal, Centro de Datos B2',
          ),
        ],
      ),
    ]);

    // Inicializar sistemas e inquilinos conectados (ADR-0027)
    _tenants.addAll(<ConnectedTenantApp>[
      const ConnectedTenantApp(
        tenantId: 'urn:gravital-id:tenant:gob-pa-tramites',
        tenantName: 'Portal Ciudadano & Pasarela SVI Panamá',
        tenantSector: 'Gobierno Digital · Tribunal Electoral / AIG',
        tenantSubjectId: 'urn:gravital-id:sub:pa-7c31e804',
        roles: <String>['ciudadano_verificado', 'firmante_tramites'],
        permissions: <String>['svi:identidad:lectura', 'certificados:solicitar'],
        sharedClaims: <String>[
          'given_name',
          'family_name',
          'nationality',
          'document_number',
        ],
        availableClaims: <String>[
          'given_name',
          'family_name',
          'age_over_18',
          'nationality',
          'document_number',
          'birth_date',
        ],
        statusState: GxVerificationState.valid,
      ),
      const ConnectedTenantApp(
        tenantId: 'urn:gravital-id:tenant:bgeneral-corp',
        tenantName: 'Banco General — Portal Tesorería & KYC',
        tenantSector: 'Servicios Financieros · Ley 23 de 2015',
        tenantSubjectId: 'urn:gravital-id:sub:bg-41a0d592',
        roles: <String>['treasury_approver', 'kyc_verified_holder'],
        permissions: <String>[
          'wire:approve:50k',
          'accounts:export_portability',
          'session_code:verify',
        ],
        sharedClaims: <String>['given_name', 'family_name', 'age_over_18'],
        availableClaims: <String>[
          'given_name',
          'family_name',
          'age_over_18',
          'nationality',
          'document_number',
        ],
        statusState: GxVerificationState.valid,
      ),
      const ConnectedTenantApp(
        tenantId: 'urn:gravital-id:tenant:torre-pacifica-access',
        tenantName: 'Torre Financiera Pacífica & Cloud ERP',
        tenantSector: 'Control de Acceso Físico (NFC/QR) & SaaS Empresarial',
        tenantSubjectId: 'urn:gravital-id:sub:tp-9f4a2c81',
        roles: <String>['tenant_admin', 'datacenter_operator'],
        permissions: <String>[
          'gate:main-turnstile',
          'zone:datacenter-b2',
          'visitors:authorize',
        ],
        sharedClaims: <String>['given_name', 'age_over_18'],
        availableClaims: <String>[
          'given_name',
          'family_name',
          'age_over_18',
          'nationality',
          'document_number',
        ],
        statusState: GxVerificationState.valid,
      ),
    ]);
  }

  void toggleOfflineMode() {
    _isOfflineMode = !_isOfflineMode;
    _simulatedVerificationState = _isOfflineMode
        ? GxVerificationState.validWithStaleStatus
        : GxVerificationState.valid;
    notifyListeners();
  }

  void setThemeMode(ThemeMode mode) {
    _themeMode = mode;
    notifyListeners();
  }

  void setContrastLevel(double level) {
    _contrastLevel = level;
    notifyListeners();
  }

  void selectCredential(int index) {
    _selectedCredentialIndex = index.clamp(0, _credentials.length - 1);
    notifyListeners();
  }

  void setTransport(PresentationTransport transport) {
    _activeTransport = transport;
    notifyListeners();
  }

  void setSimulatedVerificationState(GxVerificationState state) {
    _simulatedVerificationState = state;
    notifyListeners();
  }

  void regenerateSessionCode(String nineDigitsSeed) {
    _activeSessionCode = DammSessionCode.formatFromPayload(nineDigitsSeed);
    notifyListeners();
  }

  void updateConfirmedDisclosures(Set<String> keys) {
    _lastConfirmedDisclosures = keys;
    notifyListeners();
  }

  void clearProtocolBanner() {
    _lastProtocolBanner = null;
    notifyListeners();
  }

  /// Registra un nuevo ciudadano verificando el formato del Tribunal Electoral y la unicidad VOPRF (`ADR-0028`).
  ///
  /// - Si el formato de cédula es inválido, rechaza con `GID-E3004` (`SchemaValidationFailed`).
  /// - Si el ciudadano ya tiene un Gravital ID (`UniquenessTag` existente), rechaza con
  ///   `GID-E2010` (`CitizenIdentityAlreadyRegistered`) y ofrece redirigir a ingreso/recuperación (`REQ-UNIQ-003`).
  ProtocolOperationOutcome attemptCitizenRegistration({
    required String rawCedula,
    required String fullName,
  }) {
    final normalized = PanamaNationalIdProfile.normalize(rawCedula);
    if (!PanamaNationalIdProfile.isValidPanamaCedula(normalized)) {
      final outcome = ProtocolOperationOutcome(
        succeeded: false,
        errorCode: 'GID-E3004',
        errorIdentifier: 'SchemaValidationFailed',
        title: 'Formato de Cédula Panameña Inválido',
        description:
            'El valor "$normalized" no cumple la gramática oficial del Tribunal Electoral de Panamá (ej. 8-888-8888, PE-12-345, E-8-123456).',
      );
      _lastProtocolBanner = outcome;
      notifyListeners();
      return outcome;
    }

    final tag = PanamaNationalIdProfile.deriveBlindUniquenessTag(
      defaultIssuerId,
      'PA',
      normalized,
    );

    if (_registeredUniquenessTags.contains(tag)) {
      final outcome = ProtocolOperationOutcome(
        succeeded: false,
        errorCode: 'GID-E2010',
        errorIdentifier: 'CitizenIdentityAlreadyRegistered',
        uniquenessTag: tag,
        title: 'Duplicidad Ciudadana Detectada (Tribunal Electoral SVI)',
        description:
            'La cédula $normalized ya posee un Gravital ID activo (UniquenessTag ciego: $tag). '
            'Para cumplir con el Decreto N.° 43 de 2024 del Tribunal Electoral e impedir cuentas duplicadas, '
            'debes ingresar con tu Gravital ID existente o ejecutar una recuperación / reemplazo de dispositivo.',
      );
      _lastProtocolBanner = outcome;
      notifyListeners();
      return outcome;
    }

    _registeredUniquenessTags.add(tag);
    final outcome = ProtocolOperationOutcome(
      succeeded: true,
      uniquenessTag: tag,
      title: 'Identidad Ciudadana Verificada sin Duplicidad (SVI Panamá)',
      description:
          'Cédula $normalized validada ante el SVI del Tribunal Electoral para $fullName. '
          'Se registró la etiqueta ciega VOPRF ($tag) sin publicar PII en el ledger (INV-02).',
    );
    _lastProtocolBanner = outcome;
    notifyListeners();
    return outcome;
  }

  /// Intenta vincular un dispositivo adicional en la misma clase `DeviceFactorClass` sin orden de reemplazo (`ADR-0029`).
  ///
  /// Siempre se rechaza con `GID-E2011` (`DuplicateDeviceClassActive`) cuando la ranura ya está ocupada (`REQ-DEVSLOT-001`).
  ProtocolOperationOutcome attemptDuplicateDeviceInClass({
    required DeviceFactorClass factorClass,
    required String candidateModelName,
    required String candidateHardwareId,
  }) {
    final current = _deviceSlots[factorClass];
    if (current != null) {
      final outcome = ProtocolOperationOutcome(
        succeeded: false,
        errorCode: 'GID-E2011',
        errorIdentifier: 'DuplicateDeviceClassActive',
        title:
            'Rechazo por Duplicidad en Clase "${factorClass.code}" (Regla 1-por-Clase)',
        description:
            'No se permite tener el mismo Gravital ID activo en dos soportes de tipo "${factorClass.code}". '
            'Actualmente la ranura está ocupada por "${current.deviceModelName}" (${current.hardwareAttestationId}, '
            'TokenStatusList idx #${current.statusListIndex}). Puedes tener simultáneamente 1 teléfono + 1 tarjeta Visa + 1 otro soporte, '
            'pero para usar "$candidateModelName" debes ejecutar un Reemplazo Atómico que revoca el anterior.',
      );
      _lastProtocolBanner = outcome;
      notifyListeners();
      return outcome;
    }

    return replaceDeviceInSlot(
      factorClass: factorClass,
      newModelName: candidateModelName,
      newHardwareId: candidateHardwareId,
    );
  }

  /// Ejecuta el reemplazo atómico de un soporte dentro de su misma clase `DeviceFactorClass` (`ADR-0029`, `REQ-DEVSLOT-003`).
  ///
  /// Revoca el `status_list_index` del dispositivo anterior de esa clase y asigna un nuevo índice al nuevo soporte,
  /// manteniendo intactas las demás clases de dispositivo del titular.
  ProtocolOperationOutcome replaceDeviceInSlot({
    required DeviceFactorClass factorClass,
    required String newModelName,
    required String newHardwareId,
  }) {
    final previous = _deviceSlots[factorClass];
    final newIndex = _nextStatusListIndex++;
    if (previous != null) {
      _revokedStatusIndices.add(previous.statusListIndex);
    }

    _deviceSlots[factorClass] = DeviceSlotEnrollment(
      factorClass: factorClass,
      deviceModelName: newModelName,
      hardwareAttestationId: newHardwareId,
      statusListIndex: newIndex,
      enrolledAtIso: '2026-10-18T00:35:00Z',
      previousRevokedIndex: previous?.statusListIndex,
    );

    final outcome = ProtocolOperationOutcome(
      succeeded: true,
      revokedStatusIndex: previous?.statusListIndex,
      title: 'Reemplazo Atómico Completado en Ranura "${factorClass.code}"',
      description: previous != null
          ? 'Se revocó atómicamente el índice #${previous.statusListIndex} (${previous.deviceModelName}) en la Token Status List '
              'y se emitió el nuevo lote con índice #$newIndex para "$newModelName" ($newHardwareId). '
              'Tus demás soportes en otras clases siguen activos sin interrupción.'
          : 'Se vinculó "$newModelName" en la ranura "${factorClass.code}" con índice #$newIndex.',
    );
    _lastProtocolBanner = outcome;
    notifyListeners();
    return outcome;
  }

  /// Actualiza los atributos compartidos con un inquilino específico (`REQ-TENANT-003`).
  void updateTenantSharedClaims(String tenantId, List<String> newSharedClaims) {
    final idx = _tenants.indexWhere((t) => t.tenantId == tenantId);
    if (idx == -1) return;
    _tenants[idx] = _tenants[idx].copyWith(sharedClaims: newSharedClaims);
    notifyListeners();
  }

  /// Conecta un nuevo sistema/servicio inquilino reutilizando el mismo Gravital ID (`REQ-TENANT-001`, `REQ-TENANT-002`).
  void connectNewTenantApp({
    required String tenantId,
    required String tenantName,
    required String tenantSector,
    required List<String> requestedRoles,
    required List<String> requestedPermissions,
    required List<String> approvedClaims,
  }) {
    final existingIdx = _tenants.indexWhere((t) => t.tenantId == tenantId);
    final subjectHash = tenantId.codeUnits
        .fold<int>(0x474944, (prev, elem) => (prev * 33 ^ elem) & 0xFFFFFF)
        .toRadixString(16)
        .padLeft(6, '0');
    final pairwiseSub = 'urn:gravital-id:sub:tn-$subjectHash';

    final app = ConnectedTenantApp(
      tenantId: tenantId,
      tenantName: tenantName,
      tenantSector: tenantSector,
      tenantSubjectId: pairwiseSub,
      roles: requestedRoles,
      permissions: requestedPermissions,
      sharedClaims: approvedClaims,
      availableClaims: const <String>[
        'given_name',
        'family_name',
        'age_over_18',
        'nationality',
        'document_number',
      ],
      statusState: GxVerificationState.valid,
    );

    if (existingIdx >= 0) {
      _tenants[existingIdx] = app;
    } else {
      _tenants.add(app);
    }

    _lastProtocolBanner = ProtocolOperationOutcome(
      succeeded: true,
      title: 'Inquilino Conectado con Gravital ID Existente',
      description:
          'Se vinculó "$tenantName" con sujeto seudónimo consistente $pairwiseSub '
          'y roles ${requestedRoles.join(", ")} (pip-tenant-role-v1).',
    );
    notifyListeners();
  }

  /// Revoca la vinculación con un sistema inquilino.
  void revokeTenantApp(String tenantId) {
    _tenants.removeWhere((t) => t.tenantId == tenantId);
    notifyListeners();
  }

  /// Cambia entre Modo Emulación HCE (Teléfono transmite) y Modo Lector ISO-DEP (Tarjeta física Visa).
  void setNfcMode(NfcOperatingMode mode) {
    _nfcMode = mode;
    nfcService.resetSession();
    notifyListeners();
  }

  /// Arma o desarma la ventana de toque NFC HCE (`REQ-PROX-006`).
  Future<void> setNfcArmed(bool armed) async {
    await nfcService.setArmedForTap(armed);
    notifyListeners();
  }

  /// Ejecuta el flujo completo de presentación ISO/IEC 7816-4 `GID-APDU` sobre NFC.
  List<ApduExchangeLogEntry> executeNfcApduPresentation({String? cardPin}) {
    final entries = nfcService.executeFullPresentationHandshake(
      disclosedClaims: _lastConfirmedDisclosures,
      isPhysicalCardMode: _nfcMode == NfcOperatingMode.isoDepCardReader,
      pinForCard: cardPin,
    );
    notifyListeners();
    return entries;
  }

  /// Selecciona la Passkey activa para presentar credenciales.
  void selectPasskey(int index) {
    _selectedPasskeyIndex =
        index.clamp(0, passkeyService.registeredPasskeys.length - 1);
    notifyListeners();
  }

  /// Selecciona el transporte del autenticador Passkey (Dispositivo, NFC Security Key o Híbrido QR+BLE).
  void setPasskeyTransport(PasskeyAuthenticatorTransport transport) {
    _activePasskeyTransport = transport;
    notifyListeners();
  }

  /// Firma y transmite la presentación verificable mediante la Passkey seleccionada (`PROTOCOL.md §7.8`).
  Future<PasskeyPresentationEnvelope> transmitPresentationViaPasskey() async {
    final future = passkeyService.signAndTransmitWithPasskey(
      passkeyIndex: _selectedPasskeyIndex,
      credentialVct: selectedCredential.vct,
      disclosedClaims: _lastConfirmedDisclosures,
      overrideTransport: _activePasskeyTransport,
    );
    notifyListeners();
    final env = await future;
    notifyListeners();
    return env;
  }

  /// Registra una nueva Passkey FIDO2/WebAuthn vinculada al Gravital ID.
  RegisteredPasskeyCredential registerNewPasskey({
    required String rpId,
    required String displayName,
    required PasskeyAuthenticatorTransport transport,
  }) {
    final cred = passkeyService.registerNewPasskey(
      rpId: rpId,
      displayName: displayName,
      transport: transport,
    );
    _selectedPasskeyIndex = passkeyService.registeredPasskeys.length - 1;
    notifyListeners();
    return cred;
  }
}
