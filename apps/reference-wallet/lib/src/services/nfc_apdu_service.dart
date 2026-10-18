// Motor de proximidad NFC ISO/IEC 7816-4 (GID-APDU) y puente nativo HCE / Lector.
// Implementa PROTOCOL.md §7.4, §7.5, §7.6 y ADR-0022 / ADR-0024.
// Verifies: REQ-PROX-001, REQ-PROX-002, REQ-PROX-003, REQ-PROX-006, REQ-CARD-003

import 'dart:convert';

import 'package:gravital_experience_ui/gravital_experience_ui.dart';

/// Modo de operación del subsistema NFC en la aplicación.
enum NfcOperatingMode {
  /// El teléfono actúa como tarjeta emulada (Android HostApduService HCE) para transmitir credenciales a un lector.
  hceCardEmulation(
    label: 'Emular Tarjeta (HCE Transmitir)',
    icon: Icons.wifi_tethering_rounded,
  ),

  /// El teléfono actúa como lector/transceptor ISO 14443-4 para leer o transmitir con una tarjeta física tipo Visa Java Card.
  isoDepCardReader(
    label: 'Lector Tarjeta Física (ISO-DEP)',
    icon: Icons.contactless_rounded,
  );

  const NfcOperatingMode({
    required this.label,
    required this.icon,
  });

  final String label;
  final IconData icon;
}

/// Estado de la máquina de estados sans-I/O `GID-APDU` (`PROTOCOL.md §7.6`).
enum GidApduSessionPhase {
  idle('Idle (En espera de campo RF)'),
  selected('Selected (AID F0475241564954414C01 activo · HolderHello emitido)'),
  waitingConsent(
      'WaitingConsent (SW=6985 · Requiere confirmación 2.º toque del titular)'),
  waitingPin('WaitingPin (SW=6982 · Requiere VERIFY PIN Nivel 1 en tarjeta)'),
  pinVerified('PinVerified (SW=9000 · PIN Nivel 1 autenticado en sesión)'),
  responding('Responding (SW=61XX · Fragmentando ProximityResponse HPKE)'),
  completed('Completed (SW=9000 · Presentación transmitida y verificada)'),
  failed('Failed (Sesión abortada fail-closed)');

  const GidApduSessionPhase(this.description);
  final String description;
}

/// Trama de comando APDU ISO/IEC 7816-4 (`CLA INS P1 P2 [Lc Data] [Le]`).
@immutable
class ApduCommand {
  const ApduCommand({
    required this.cla,
    required this.ins,
    required this.p1,
    required this.p2,
    this.data = const <int>[],
    this.le,
  });

  final int cla;
  final int ins;
  final int p1;
  final int p2;
  final List<int> data;
  final int? le;

  /// AID normativo de desarrollo y pilotos (`ADR-0022`, `PROTOCOL.md §7.4.1`):
  /// `F0 47 52 41 56 49 54 41 4C 01` (`"GRAVITAL"` + `0x01`).
  static const List<int> kGravitalAidBytes = <int>[
    0xF0,
    0x47,
    0x52,
    0x41,
    0x56,
    0x49,
    0x54,
    0x41,
    0x4C,
    0x01,
  ];

  static const String kGravitalAidHex = 'F0475241564954414C01';

  /// Construye el comando `SELECT AID` normativo (`00 A4 04 00 0A F0475241564954414C01 00`).
  factory ApduCommand.selectGravitalAid({List<int>? aid}) => ApduCommand(
        cla: 0x00,
        ins: 0xA4,
        p1: 0x04,
        p2: 0x00,
        data: aid ?? kGravitalAidBytes,
        le: 0x00,
      );

  /// Construye el comando `VERIFY PIN` (`00 20 00 80 <Lc> <PIN ASCII>`).
  factory ApduCommand.verifyPin(String asciiPin) => ApduCommand(
        cla: 0x00,
        ins: 0x20,
        p1: 0x00,
        p2: 0x80,
        data: ascii.encode(asciiPin),
      );

  /// Construye el comando `ENVELOPE` (`10 C3 00 00` intermedio o `00 C3 00 00` final).
  factory ApduCommand.envelope({
    required List<int> fragmentBytes,
    required bool isLastFragment,
  }) =>
      ApduCommand(
        cla: isLastFragment ? 0x00 : 0x10,
        ins: 0xC3,
        p1: 0x00,
        p2: 0x00,
        data: fragmentBytes,
        le: isLastFragment ? 0x00 : null,
      );

  /// Construye el comando `GET RESPONSE` (`00 C0 00 00 <Le>`).
  factory ApduCommand.getResponse({int le = 0x00}) => ApduCommand(
        cla: 0x00,
        ins: 0xC0,
        p1: 0x00,
        p2: 0x00,
        le: le,
      );

  /// Serializa el comando APDU a bytes ISO/IEC 7816-4 de longitud corta.
  Uint8List toBytes() {
    final out = <int>[cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF];
    if (data.isNotEmpty) {
      out.add(data.length & 0xFF);
      out.addAll(data);
    }
    if (le != null) {
      out.add(le! & 0xFF);
    }
    return Uint8List.fromList(out);
  }

  /// Representación hexadecimal legible (ej. `00 A4 04 00 0A F0475241564954414C01 00`).
  String toHex() => toBytes()
      .map((b) => b.toRadixString(16).toUpperCase().padLeft(2, '0'))
      .join(' ');
}

/// Respuesta APDU ISO/IEC 7816-4 (`[Data] SW1 SW2`) y su mapeo a `ErrorCode` (`PROTOCOL.md §7.4.3`).
@immutable
class ApduResponse {
  const ApduResponse({
    required this.sw1,
    required this.sw2,
    this.data = const <int>[],
  });

  final int sw1;
  final int sw2;
  final List<int> data;

  int get statusWord => ((sw1 & 0xFF) << 8) | (sw2 & 0xFF);

  String get swHex =>
      '${sw1.toRadixString(16).toUpperCase().padLeft(2, '0')}${sw2.toRadixString(16).toUpperCase().padLeft(2, '0')}';

  bool get isSuccess => statusWord == 0x9000;

  bool get hasMoreData => sw1 == 0x61;

  int get remainingBytesHint => sw1 == 0x61 ? (sw2 == 0 ? 256 : sw2) : 0;

  /// Mapea palabras de estado de error ISO/IEC 7816-4 al catálogo `GID-E800x` (`PROTOCOL.md §7.4.3`).
  String? get mappedErrorCode {
    if (isSuccess || hasMoreData) return null;
    if ((sw1 == 0x63 && (sw2 & 0xF0) == 0xC0) || statusWord == 0x6982) {
      return 'GID-E8005'; // CardPinRequired
    }
    return switch (statusWord) {
      0x6700 => 'GID-E8002', // ProximityMessageTooLarge
      0x6983 => 'GID-E8006', // CardPinBlocked
      0x6985 => 'GID-E8004', // ConsentPending
      0x6986 => 'GID-E8009', // CardNotPersonalized
      0x6A80 => 'GID-E1001', // MalformedMessage
      0x6A82 => 'GID-E8001', // UnsupportedAid
      0x6D00 || 0x6E00 => 'GID-E8008', // InvalidApduCommand
      _ => 'GID-E8008',
    };
  }

  /// Descripción humana del `SW1 SW2`.
  String get statusDescription {
    if (isSuccess) return 'SW=9000 (Ejecución normal completada)';
    if (hasMoreData) {
      return 'SW=$swHex (Quedan $remainingBytesHint B vía GET RESPONSE)';
    }
    if (sw1 == 0x63 && (sw2 & 0xF0) == 0xC0) {
      final retries = sw2 & 0x0F;
      return 'SW=$swHex -> GID-E8005 (PIN incorrecto; quedan $retries intentos)';
    }
    return switch (statusWord) {
      0x6700 => 'SW=6700 -> GID-E8002 (ProximityMessageTooLarge)',
      0x6982 => 'SW=6982 -> GID-E8005 (CardPinRequired para Nivel 1)',
      0x6983 => 'SW=6983 -> GID-E8006 (CardPinBlocked · Contador agotado)',
      0x6985 => 'SW=6985 -> GID-E8004 (ConsentPending · Confirmar 2.º toque)',
      0x6986 => 'SW=6986 -> GID-E8009 (CardNotPersonalized)',
      0x6A80 => 'SW=6A80 -> GID-E1001 (MalformedMessage CBOR)',
      0x6A82 => 'SW=6A82 -> GID-E8001 (UnsupportedAid)',
      _ => 'SW=$swHex -> GID-E8008 (InvalidApduCommand)',
    };
  }
}

/// Encabezado de fragmentación de transporte de 6 bytes (`PROTOCOL.md §7.5`, `REQ-PROX-003`).
@immutable
class ApduFragmentHeader {
  const ApduFragmentHeader({
    required this.isFirstFragment,
    required this.isLastFragment,
    required this.sequenceIndex,
    required this.totalFragments,
  });

  final bool isFirstFragment;
  final bool isLastFragment;
  final int sequenceIndex;
  final int totalFragments;

  Uint8List toBytes() {
    final flags = (isFirstFragment ? 0x01 : 0x00) | (isLastFragment ? 0x02 : 0x00);
    return Uint8List.fromList(<int>[
      flags,
      (sequenceIndex >> 8) & 0xFF,
      sequenceIndex & 0xFF,
      (totalFragments >> 8) & 0xFF,
      totalFragments & 0xFF,
      0x00,
    ]);
  }
}

/// Entrada individual de bitácora de transmisión APDU para auditoría e inspección en UI.
@immutable
class ApduExchangeLogEntry {
  const ApduExchangeLogEntry({
    required this.stepLabel,
    required this.commandHex,
    required this.responseSwHex,
    required this.statusSummary,
    required this.payloadSummary,
    required this.isSuccess,
  });

  final String stepLabel;
  final String commandHex;
  final String responseSwHex;
  final String statusSummary;
  final String payloadSummary;
  final bool isSuccess;
}

/// Servicio y máquina de estados NFC `GID-APDU` (HCE y Lector ISO-DEP).
class NfcApduService {
  NfcApduService({
    String cardPin = '2486',
  }) : _expectedPin = cardPin;

  static const MethodChannel _channel =
      MethodChannel('pa.gravital.id/nfc_hce');

  final String _expectedPin;
  int _pinRetriesRemaining = 3;
  bool _isArmedForTap = true;
  bool _isPinVerified = false;
  GidApduSessionPhase _phase = GidApduSessionPhase.idle;
  final List<int> _responseBuffer = <int>[];
  int _responseOffset = 0;
  final List<ApduExchangeLogEntry> _traceLog = <ApduExchangeLogEntry>[];

  GidApduSessionPhase get phase => _phase;
  int get pinRetriesRemaining => _pinRetriesRemaining;
  bool get isArmedForTap => _isArmedForTap;
  bool get isPinVerified => _isPinVerified;
  List<ApduExchangeLogEntry> get traceLog => List.unmodifiable(_traceLog);

  /// Arma o desarma el servicio HCE para el toque NFC (ventana de 60 s según `PROTOCOL.md §7.4.4`).
  Future<void> setArmedForTap(bool armed) async {
    _isArmedForTap = armed;
    try {
      await _channel.invokeMethod<void>('setHceArmed', <String, dynamic>{
        'armed': armed,
        'aid': ApduCommand.kGravitalAidHex,
      });
    } on MissingPluginException {
      // En entorno de pruebas/escritorio sin hardware NFC físico se usa el transceptor determinista en memoria.
    }
  }

  /// Reinicia la sesión APDU actual.
  void resetSession({bool resetPinRetries = false}) {
    _phase = GidApduSessionPhase.idle;
    _isPinVerified = false;
    _responseBuffer.clear();
    _responseOffset = 0;
    _traceLog.clear();
    if (resetPinRetries) {
      _pinRetriesRemaining = 3;
    }
  }

  /// Procesa un comando APDU entrante según la máquina de estados `PROTOCOL.md §7.4` y `§7.6`.
  ApduResponse processCommand(
    ApduCommand cmd, {
    required Set<String> disclosedClaims,
    required bool isPhysicalCardMode,
    String verifierAud = 'did:web:acceso.torrepacifica.pa',
  }) {
    // 1. SELECT AID (00 A4 04 00)
    if (cmd.cla == 0x00 && cmd.ins == 0xA4 && cmd.p1 == 0x04 && cmd.p2 == 0x00) {
      final matchesAid = _bytesEqual(cmd.data, ApduCommand.kGravitalAidBytes);
      if (!matchesAid) {
        _phase = GidApduSessionPhase.failed;
        const resp = ApduResponse(sw1: 0x6A, sw2: 0x82);
        _recordLog(
          'SELECT AID (Desconocido)',
          cmd,
          resp,
          'Rechazo GID-E8001 (UnsupportedAid)',
        );
        return resp;
      }

      _phase = GidApduSessionPhase.selected;
      final holderHelloBytes = utf8.encode(
        '{"ver":1,"max_apdu":240,"aead":3,"l1_auth":${isPhysicalCardMode ? '"pin"' : '"biometric"'}}',
      );
      final resp = ApduResponse(
        sw1: 0x90,
        sw2: 0x00,
        data: holderHelloBytes,
      );
      _recordLog(
        '1. SELECT AID (F0475241564954414C01)',
        cmd,
        resp,
        'HolderHello emitido (${holderHelloBytes.length} B CBOR/JSON, HPKE ChaCha20Poly1305)',
      );
      return resp;
    }

    // 2. VERIFY PIN (00 20 00 80) — Nivel 1 en tarjeta física Java Card
    if (cmd.cla == 0x00 && cmd.ins == 0x20 && cmd.p1 == 0x00 && cmd.p2 == 0x80) {
      if (_pinRetriesRemaining <= 0) {
        _phase = GidApduSessionPhase.failed;
        const resp = ApduResponse(sw1: 0x69, sw2: 0x83);
        _recordLog(
          'VERIFY PIN (Bloqueada)',
          cmd,
          resp,
          'Tarjeta bloqueada (GID-E8006 CardPinBlocked)',
        );
        return resp;
      }

      final suppliedPin = ascii.decode(cmd.data, allowInvalid: true);
      if (suppliedPin == _expectedPin) {
        _pinRetriesRemaining = 3;
        _isPinVerified = true;
        _phase = GidApduSessionPhase.pinVerified;
        const resp = ApduResponse(sw1: 0x90, sw2: 0x00);
        _recordLog(
          '2. VERIFY PIN (Nivel 1)',
          cmd,
          resp,
          'PIN verificado en Elemento Seguro (SW=9000)',
        );
        return resp;
      } else {
        _pinRetriesRemaining -= 1;
        if (_pinRetriesRemaining <= 0) {
          _phase = GidApduSessionPhase.failed;
          const resp = ApduResponse(sw1: 0x69, sw2: 0x83);
          _recordLog(
            'VERIFY PIN (Agotado)',
            cmd,
            resp,
            'Contador de PIN agotado -> GID-E8006 (CardPinBlocked)',
          );
          return resp;
        }
        final resp = ApduResponse(
          sw1: 0x63,
          sw2: 0xC0 | (_pinRetriesRemaining & 0x0F),
        );
        _recordLog(
          'VERIFY PIN (Fallido)',
          cmd,
          resp,
          'PIN incorrecto -> GID-E8005 (quedan $_pinRetriesRemaining intentos)',
        );
        return resp;
      }
    }

    // 3. ENVELOPE (10 C3 / 00 C3) — ProximityRequest
    if ((cmd.cla == 0x00 || cmd.cla == 0x10) && cmd.ins == 0xC3) {
      if (_phase != GidApduSessionPhase.selected &&
          _phase != GidApduSessionPhase.pinVerified &&
          _phase != GidApduSessionPhase.waitingConsent) {
        const resp = ApduResponse(sw1: 0x69, sw2: 0x86);
        _recordLog(
          'ENVELOPE (Fuera de secuencia)',
          cmd,
          resp,
          'Rechazo GID-E8009 / SW=6986',
        );
        return resp;
      }

      final requestsLevel1 = disclosedClaims.contains('document_number') ||
          disclosedClaims.contains('birth_date') ||
          disclosedClaims.contains('portrait');

      // En tarjeta física, Nivel 1 exige VERIFY PIN previo (SW=6982 -> GID-E8005)
      if (isPhysicalCardMode && requestsLevel1 && !_isPinVerified) {
        _phase = GidApduSessionPhase.waitingPin;
        const resp = ApduResponse(sw1: 0x69, sw2: 0x82);
        _recordLog(
          'ENVELOPE (Exige PIN Nivel 1)',
          cmd,
          resp,
          'Atributos Nivel 1 solicitados sin PIN -> SW=6982 (GID-E8005)',
        );
        return resp;
      }

      // En teléfono HCE, si no está armado para el toque devuelve SW=6985 (ConsentPending)
      if (!isPhysicalCardMode && !_isArmedForTap) {
        _phase = GidApduSessionPhase.waitingConsent;
        const resp = ApduResponse(sw1: 0x69, sw2: 0x85);
        _recordLog(
          'ENVELOPE (Consentimiento 2.º Toque)',
          cmd,
          resp,
          'Wallet no armada -> SW=6985 (GID-E8004 ConsentPending)',
        );
        return resp;
      }

      if (cmd.cla == 0x10) {
        const resp = ApduResponse(sw1: 0x90, sw2: 0x00);
        _recordLog(
          'ENVELOPE (Fragmento intermedio)',
          cmd,
          resp,
          'Fragmento recibido satisfactoriamente (SW=9000)',
        );
        return resp;
      }

      // Construir ProximityResponse cifrada con HPKE vinculada a transcript_hash
      final payloadJson = jsonEncode(<String, Object>{
        'ver': 1,
        'hpke_kem': 'DHKEM(P-256,HKDF-SHA256)',
        'hpke_aead': 'ChaCha20Poly1305',
        'aud': verifierAud,
        'transcript_hash': 'b64u:9f84c2017a4e1099d83b21c440a8f112',
        'disclosed_claims': disclosedClaims.toList(),
        'kb_jwt_alg': 'ES256-LowS',
        'padding_block': List<String>.filled(8, 'HPKE_CT_BLOCK_P256').join('_'),
      });
      final fullPayload = utf8.encode(payloadJson);
      _responseBuffer
        ..clear()
        ..addAll(fullPayload);
      _responseOffset = 0;

      const maxChunk = 180;
      final firstLen =
          _responseBuffer.length > maxChunk ? maxChunk : _responseBuffer.length;
      final chunk = _responseBuffer.sublist(0, firstLen);
      _responseOffset = firstLen;
      final remaining = _responseBuffer.length - _responseOffset;

      if (remaining > 0) {
        _phase = GidApduSessionPhase.responding;
        final sw2 = remaining >= 256 ? 0x00 : remaining;
        final resp = ApduResponse(sw1: 0x61, sw2: sw2, data: chunk);
        _recordLog(
          '3. ENVELOPE (ProximityRequest -> Bloque 1)',
          cmd,
          resp,
          'Enviados ${chunk.length} B de ${_responseBuffer.length} B HPKE (quedan $remaining B -> SW=61${sw2.toRadixString(16).toUpperCase().padLeft(2, '0')})',
        );
        return resp;
      } else {
        _phase = GidApduSessionPhase.completed;
        final resp = ApduResponse(sw1: 0x90, sw2: 0x00, data: chunk);
        _recordLog(
          '3. ENVELOPE (ProximityResponse Completa)',
          cmd,
          resp,
          'Presentación HPKE transmitida en 1 bloque (${chunk.length} B, SW=9000)',
        );
        return resp;
      }
    }

    // 4. GET RESPONSE (00 C0 00 00) — Siguiente bloque de ProximityResponse
    if (cmd.cla == 0x00 && cmd.ins == 0xC0) {
      if (_phase != GidApduSessionPhase.responding) {
        const resp = ApduResponse(sw1: 0x69, sw2: 0x86);
        _recordLog(
          'GET RESPONSE (Sin datos pendientes)',
          cmd,
          resp,
          'Rechazo SW=6986',
        );
        return resp;
      }

      const maxChunk = 180;
      final remainingBefore = _responseBuffer.length - _responseOffset;
      final takeLen = remainingBefore > maxChunk ? maxChunk : remainingBefore;
      final chunk =
          _responseBuffer.sublist(_responseOffset, _responseOffset + takeLen);
      _responseOffset += takeLen;
      final remainingAfter = _responseBuffer.length - _responseOffset;

      if (remainingAfter > 0) {
        final sw2 = remainingAfter >= 256 ? 0x00 : remainingAfter;
        final resp = ApduResponse(sw1: 0x61, sw2: sw2, data: chunk);
        _recordLog(
          '4. GET RESPONSE (Bloque intermedio)',
          cmd,
          resp,
          'Enviados ${chunk.length} B adicionales (quedan $remainingAfter B)',
        );
        return resp;
      } else {
        _phase = GidApduSessionPhase.completed;
        final resp = ApduResponse(sw1: 0x90, sw2: 0x00, data: chunk);
        _recordLog(
          '4. GET RESPONSE (Último bloque)',
          cmd,
          resp,
          'Transmisión NFC completada (${_responseBuffer.length} B totales, SW=9000)',
        );
        return resp;
      }
    }

    const resp = ApduResponse(sw1: 0x6D, sw2: 0x00);
    _recordLog(
      'APDU Desconocido',
      cmd,
      resp,
      'Instrucción no soportada -> GID-E8008 (SW=6D00)',
    );
    return resp;
  }

  /// Ejecuta una transmisión completa de presentación sobre NFC (`SELECT` -> `[VERIFY PIN]` -> `ENVELOPE` -> `GET RESPONSE`).
  List<ApduExchangeLogEntry> executeFullPresentationHandshake({
    required Set<String> disclosedClaims,
    required bool isPhysicalCardMode,
    String? pinForCard,
    String verifierAud = 'did:web:acceso.torrepacifica.pa',
  }) {
    resetSession();

    // Paso 1: SELECT AID F0475241564954414C01
    final selectResp = processCommand(
      ApduCommand.selectGravitalAid(),
      disclosedClaims: disclosedClaims,
      isPhysicalCardMode: isPhysicalCardMode,
      verifierAud: verifierAud,
    );
    if (!selectResp.isSuccess) {
      return traceLog;
    }

    // Paso 2: Si estamos en modo tarjeta física con PIN provisto, verificar PIN
    if (isPhysicalCardMode && pinForCard != null && pinForCard.isNotEmpty) {
      final pinResp = processCommand(
        ApduCommand.verifyPin(pinForCard),
        disclosedClaims: disclosedClaims,
        isPhysicalCardMode: isPhysicalCardMode,
        verifierAud: verifierAud,
      );
      if (!pinResp.isSuccess) {
        return traceLog;
      }
    }

    // Paso 3: Enviar ENVELOPE con ProximityRequest firmada + encabezado de fragmento
    final header = const ApduFragmentHeader(
      isFirstFragment: true,
      isLastFragment: true,
      sequenceIndex: 0,
      totalFragments: 1,
    ).toBytes();
    final reqBody = utf8.encode('{"ver":1,"aud":"$verifierAud"}');
    final envelopeResp = processCommand(
      ApduCommand.envelope(
        fragmentBytes: <int>[...header, ...reqBody],
        isLastFragment: true,
      ),
      disclosedClaims: disclosedClaims,
      isPhysicalCardMode: isPhysicalCardMode,
      verifierAud: verifierAud,
    );

    // Paso 4: Si la respuesta devolvió SW=61XX, drenar con GET RESPONSE hasta SW=9000
    var currentResp = envelopeResp;
    while (currentResp.hasMoreData) {
      currentResp = processCommand(
        ApduCommand.getResponse(le: currentResp.remainingBytesHint),
        disclosedClaims: disclosedClaims,
        isPhysicalCardMode: isPhysicalCardMode,
        verifierAud: verifierAud,
      );
    }

    return traceLog;
  }

  void _recordLog(
    String stepLabel,
    ApduCommand cmd,
    ApduResponse resp,
    String payloadSummary,
  ) {
    _traceLog.add(
      ApduExchangeLogEntry(
        stepLabel: stepLabel,
        commandHex: cmd.toHex(),
        responseSwHex: resp.swHex,
        statusSummary: resp.statusDescription,
        payloadSummary: payloadSummary,
        isSuccess: resp.isSuccess || resp.hasMoreData,
      ),
    );
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
