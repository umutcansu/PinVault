// PinVault for Flutter: a thin, typed bridge over the native PinVault
// libraries. Pinning, keys, signature checks and vault decryption all stay
// native; this file only shapes inputs and outputs and runs the app's
// environment guard. Nothing here stores anything (no persistence) and nothing
// here logs outside development builds.
library pinvault_flutter;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'src/types.dart';

export 'src/types.dart';
export 'src/pinvault_websocket.dart';

/// Error codes of rejected futures.
enum PinVaultErrorCode {
  /// The config (or a request) was refused by the strict native parser or a builder rule.
  invalidConfig('E_INVALID_CONFIG'),

  invalidArgument('E_INVALID_ARGUMENT'),

  /// An operation that needs `start()` first.
  notStarted('E_NOT_STARTED'),

  /// The pinned request failed: pin mismatch, TLS, network, timeout, size limit.
  fetch('E_FETCH'),

  noActivity('E_NO_ACTIVITY'),

  native('E_NATIVE');

  const PinVaultErrorCode(this.wire);
  final String wire;
}

/// A rejected PinVault call. [exception] is the native exception (class name + message).
class PinVaultError implements Exception {
  final PinVaultErrorCode code;
  final NativeException? exception;
  final String message;

  PinVaultError(this.code, this.message, {this.exception});

  @override
  String toString() => exception == null
      ? 'PinVaultError(${code.wire}): $message'
      : 'PinVaultError(${code.wire}): ${exception!.name}: $message';
}

PinVaultErrorCode _codeFromWire(String? wire) => PinVaultErrorCode.values
    .firstWhere((c) => c.wire == wire, orElse: () => PinVaultErrorCode.native);

/// Native rejections → [PinVaultError] (keeps the native code, message and exception).
PinVaultError toPinVaultError(Object error, StackTrace? stackTrace) {
  if (error is PinVaultError) return error;
  if (error is PlatformException) {
    final code = _codeFromWire(error.code);
    final details = error.details;
    NativeException? exception;
    if (details is Map) {
      final name = details['exceptionName'];
      final message = details['exceptionMessage'];
      if (name is String) {
        exception = NativeException(
          name: name,
          message: message is String ? message : null,
        );
      }
    }
    return PinVaultError(
      code,
      error.message ?? 'PinVault native call failed',
      exception: exception,
    );
  }
  return PinVaultError(PinVaultErrorCode.native, error.toString());
}

Future<T> _call<T>(Future<T> Function() body) async {
  try {
    return await body();
  } on PlatformException catch (e, st) {
    throw toPinVaultError(e, st);
  }
}

// ── Strict JSON ─────────────────────────────────────────────────────────────
// A number could be NaN/Infinity and a deeply nested structure could overflow
// the native parser. Anything that is not plain data is refused here, before it
// crosses the bridge.

/// The native parsers' nesting limit (the root object is level 0).
const int _maxDepth = 8;

void _assertPlainData(
  Object? value,
  String path,
  PinVaultErrorCode code,
  int depth,
) {
  if (depth > _maxDepth) throw PinVaultError(code, '$path: nested too deeply');
  if (value == null) return;
  if (value is String || value is bool) return;
  if (value is num) {
    if (!value.isFinite)
      throw PinVaultError(code, '$path: not a finite number');
    return;
  }
  if (value is List) {
    for (var i = 0; i < value.length; i++) {
      _assertPlainData(value[i], '$path[$i]', code, depth + 1);
    }
    return;
  }
  if (value is Map) {
    for (final entry in value.entries) {
      if (entry.key is! String)
        throw PinVaultError(code, '$path: map keys must be strings');
      _assertPlainData(entry.value, '$path.${entry.key}', code, depth + 1);
    }
    return;
  }
  throw PinVaultError(code, '$path: ${value.runtimeType} is not allowed');
}

String _strictJson(Object? value, String path, PinVaultErrorCode code) {
  _assertPlainData(value, path, code, 0);
  return jsonEncode(value);
}

// ── Environment guard ───────────────────────────────────────────────────────

const int defaultGuardTimeoutMs = 5000;

const Set<String> _guardedOperations = {
  'INIT',
  'ENROLL',
  'FETCH_FILE',
  'UNLOCK_FILE',
  'LOAD_FILE',
};

/// Runs the app's guard with a timeout. Anything but a `true` within the time —
/// `false`, another value, a thrown error, a rejected future, no answer — is a refusal.
Future<bool> evaluateGuard(
  EnvironmentGuard guard,
  GuardedOperation operation,
  int timeoutMs,
) async {
  try {
    final verdict = await guard(operation)
        .timeout(Duration(milliseconds: timeoutMs), onTimeout: () => false);
    return verdict == true;
  } catch (e) {
    if (kDebugMode) {
      debugPrint(
        'PinVault: environmentGuard threw for $operation; refused ($e)',
      );
    }
    return false;
  }
}

/// The guard of the running config, put back when a new config is refused.
EnvironmentGuard? _activeGuard;
int _activeGuardTimeoutMs = defaultGuardTimeoutMs;
StreamSubscription<dynamic>? _guardSubscription;

void _installGuard(EnvironmentGuard? guard, int timeoutMs) {
  _guardSubscription?.cancel();
  _guardSubscription = null;
  if (guard == null) return;
  // The Dart answer must arrive before the native deadline; leave it a little room.
  final dartTimeout = timeoutMs - 100 < 50 ? 50 : timeoutMs - 100;
  _guardSubscription = _guardChannel.receiveBroadcastStream().listen((event) {
    final map = _asMap(event);
    final requestId = map['requestId'] as String;
    final operation = map['operation'] as String;
    if (!_guardedOperations.contains(operation)) {
      _answerGuard(requestId, false);
      return;
    }
    final op = GuardedOperation.values.firstWhere((o) => o.wire == operation);
    evaluateGuard(
      guard,
      op,
      dartTimeout,
    ).then((allowed) => _answerGuard(requestId, allowed));
  });
}

void _answerGuard(String requestId, bool allowed) {
  _channel
      .invokeMethod<void>('answerGuard', {
        'requestId': requestId,
        'allowed': allowed,
      })
      .catchError((_) {
        // The native side already timed out; the answer arriving late is harmless.
      });
}

// ── Channels ────────────────────────────────────────────────────────────────

const MethodChannel _channel = MethodChannel('pinvault_flutter');
const EventChannel _eventsChannel = EventChannel('pinvault_flutter/events');
const EventChannel _guardChannel = EventChannel('pinvault_flutter/guard');

/// Flutter's StandardMessageCodec decodes native maps as `Map<Object?, Object?>`.
/// Convert every nested map/list to `Map<String, dynamic>` / `List<dynamic>` so
/// the `fromJson` factories' `as Map<String, dynamic>` casts hold.
dynamic _decode(Object? v) {
  if (v is Map) {
    return v.map<String, dynamic>((k, val) => MapEntry(k.toString(), _decode(val)));
  }
  if (v is List) {
    return v.map<dynamic>(_decode).toList();
  }
  return v;
}

Map<String, dynamic> _asMap(Object? v) {
  final decoded = _decode(v);
  return decoded is Map<String, dynamic> ? decoded : <String, dynamic>{};
}

/// Everything the native libraries expose, like `PinVault.shared` / the Kotlin `PinVault` object.
class PinVault {
  const PinVault._();

  // ── Start / config ────────────────────────────────────────────────────────

  /// Starts PinVault (`PinVault.init(context, config)` / `PinVault.shared.start(config:)`).
  /// Fail closed: until it returns `InitResultReady`, every pinned request is refused.
  /// An invalid config rejects with `E_INVALID_CONFIG` (unknown keys and wrong types included).
  static Future<InitResult> start(PinVaultConfig config) async {
    if (config.environmentGuard != null) {
      // The new guard answers during start (INIT is asked then). A config the
      // native side refuses changes nothing, so the running config's guard comes back.
      final previous = _activeGuard;
      final previousTimeout = _activeGuardTimeoutMs;
      _installGuard(
        config.environmentGuard,
        config.environmentGuardTimeoutMs ?? defaultGuardTimeoutMs,
      );
      try {
        final json = _strictJson(
          config.toJson(),
          'config',
          PinVaultErrorCode.invalidConfig,
        );
        final result = await _call<Map<String, dynamic>>(
          () => _channel.invokeMethod<dynamic>('start', json).then(_asMap),
        );
        _activeGuard = config.environmentGuard;
        _activeGuardTimeoutMs =
            config.environmentGuardTimeoutMs ?? defaultGuardTimeoutMs;
        return InitResult.fromJson(result);
      } catch (e) {
        _installGuard(previous, previousTimeout);
        rethrow;
      }
    }
    final json = _strictJson(
      config.toJson(),
      'config',
      PinVaultErrorCode.invalidConfig,
    );
    final result = await _call<Map<String, dynamic>>(
      () => _channel.invokeMethod<dynamic>('start', json).then(_asMap),
    );
    return InitResult.fromJson(result);
  }

  static Future<UpdateResult> updateNow() => _call<UpdateResult>(
    () => _channel
        .invokeMethod<dynamic>('updateNow')
        .then((v) => UpdateResult.fromJson(_asMap(v))),
  );

  static Future<int> currentVersion() => _call<int>(
    () => _channel.invokeMethod<int>('currentVersion').then((v) => v ?? 0),
  );

  static Future<Map<String, int>> hostPinVersions() => _call<Map<String, int>>(
    () => _channel.invokeMethod<dynamic>('hostPinVersions').then((v) {
      final map = _asMap(v);
      return map.map((k, val) => MapEntry(k, (val as num).toInt()));
    }),
  );

  /// Active pins of a host (Base64, no `sha256/`), or null when the host has no entry.
  static Future<List<String>?> pinsForHost(String hostname) =>
      _call<List<String>?>(
        () => _channel.invokeMethod<dynamic>('pinsForHost', hostname).then((v) {
          final map = _asMap(v);
          final pins = map['pins'];
          return pins is List ? pins.cast<String>() : null;
        }),
      );

  static Future<SigningStatus?> signingStatus([String? configApiId]) =>
      _call<SigningStatus?>(
        () => _channel.invokeMethod<dynamic>('signingStatus', configApiId).then(
          (v) {
            if (v == null) return null;
            return SigningStatus.fromJson(_asMap(v));
          },
        ),
      );

  static Future<bool> isForceUpdate() => _call<bool>(
    () => _channel.invokeMethod<bool>('isForceUpdate').then((v) => v ?? false),
  );

  /// Drops the active pins; the next `start` begins again (watermarks kept).
  static Future<void> reset() =>
      _call<void>(() => _channel.invokeMethod<void>('reset'));

  static Future<bool> schedulePeriodicUpdates([int? intervalHours]) =>
      _call<bool>(
        () => _channel
            .invokeMethod<bool>('schedulePeriodicUpdates', intervalHours)
            .then((v) => v ?? false),
      );

  static Future<void> cancelPeriodicUpdates() =>
      _call<void>(() => _channel.invokeMethod<void>('cancelPeriodicUpdates'));

  /// Library debug logs. Ignored (returns false) in release builds of the app.
  static Future<bool> enableDebugLogging() => _call<bool>(
    () => _channel
        .invokeMethod<bool>('enableDebugLogging')
        .then((v) => v ?? false),
  );

  // ── Pinned HTTP ───────────────────────────────────────────────────────────

  /// A request through the native pinned client (`PinVault.getClient()` /
  /// `PinVault.shared.session()`): pin check, attestation token, pin-mismatch
  /// recovery. HTTPS only; it never falls back to an unpinned path. A pin
  /// mismatch rejects with `E_FETCH`.
  static Future<PinVaultResponse> fetch(
    String url, [
    PinVaultRequestInit init = const PinVaultRequestInit(),
  ]) async {
    if (url.isEmpty)
      throw PinVaultError(
        PinVaultErrorCode.invalidArgument,
        'url: must be a non-empty string',
      );
    final json = _strictJson(
      {...init.toJson(), 'url': url},
      'request',
      PinVaultErrorCode.invalidArgument,
    );
    final response = await _call<Map<String, dynamic>>(
      () => _channel.invokeMethod<dynamic>('fetch', json).then(_asMap),
    );
    return PinVaultResponse.fromJson(response);
  }

  // ── Enrollment ────────────────────────────────────────────────────────────

  /// The device id PinVault sends (`ANDROID_ID` / `identifierForVendor`, lowercased).
  static Future<String?> deviceId() =>
      _call<String?>(() => _channel.invokeMethod<String?>('deviceId'));

  /// Token or enrollment-code enrollment. The token goes to native memory for this call only.
  static Future<ClientCertEnrollmentResult> enrollForResult(
    String token, [
    String? label,
  ]) => _call<ClientCertEnrollmentResult>(
    () => _channel
        .invokeMethod<dynamic>('enrollForResult', {
          'token': token,
          'label': label,
        })
        .then((v) => ClientCertEnrollmentResult.fromJson(_asMap(v))),
  );

  static Future<ClientCertEnrollmentResult> autoEnrollForResult() =>
      _call<ClientCertEnrollmentResult>(
        () => _channel
            .invokeMethod<dynamic>('autoEnrollForResult')
            .then((v) => ClientCertEnrollmentResult.fromJson(_asMap(v))),
      );

  static Future<ClientCertEnrollmentResult> checkPendingEnrollment() =>
      _call<ClientCertEnrollmentResult>(
        () => _channel
            .invokeMethod<dynamic>('checkPendingEnrollment')
            .then((v) => ClientCertEnrollmentResult.fromJson(_asMap(v))),
      );

  static Future<bool> isEnrolled([String? label]) => _call<bool>(
    () => _channel
        .invokeMethod<bool>('isEnrolled', label)
        .then((v) => v ?? false),
  );

  static Future<bool> isEnrollmentPending([String? label]) => _call<bool>(
    () => _channel
        .invokeMethod<bool>('isEnrollmentPending', label)
        .then((v) => v ?? false),
  );

  static Future<String?> enrollmentVerificationCode([String? label]) =>
      _call<String?>(
        () =>
            _channel.invokeMethod<String?>('enrollmentVerificationCode', label),
      );

  static Future<String?> enrolledClientCN([String? label]) => _call<String?>(
    () => _channel.invokeMethod<String?>('enrolledClientCN', label),
  );

  static Future<int?> enrolledClientNotAfter([String? label]) => _call<int?>(
    () => _channel.invokeMethod<int?>('enrolledClientNotAfter', label),
  );

  static Future<void> unenroll([String? label, bool wipeVaultFiles = false]) =>
      _call<void>(
        () => _channel.invokeMethod<void>('unenroll', {
          'label': label,
          'wipeVaultFiles': wipeVaultFiles,
        }),
      );

  static Future<KeySecurityLevel?> identityKeySecurityLevel([String? label]) =>
      _call<KeySecurityLevel?>(
        () => _channel
            .invokeMethod<String?>('identityKeySecurityLevel', label)
            .then(KeySecurityLevel.fromWire),
      );

  // ── Vault files ───────────────────────────────────────────────────────────

  /// The access token of a `TOKEN` / `TOKEN_MTLS` file. Kept in native memory only
  /// (never written to disk, gone when the process ends); `null` forgets it.
  static Future<void> setVaultToken(String key, String? token) => _call<void>(
    () => _channel.invokeMethod<void>('setVaultToken', {
      'key': key,
      'token': token,
    }),
  );

  /// Forgets every vault token (e.g. on a `REENROLL_REQUIRED` event). Returns how many there were.
  static Future<int> clearVaultTokens() => _call<int>(
    () => _channel.invokeMethod<int>('clearVaultTokens').then((v) => v ?? 0),
  );

  /// Downloads and stores a file. `token` = `setVaultToken(key, token)` before the download.
  static Future<VaultFileResult> fetchFile(String key, {String? token}) =>
      _call<VaultFileResult>(
        () => _channel
            .invokeMethod<dynamic>('fetchFile', {'key': key, 'token': token})
            .then((v) => VaultFileResult.fromJson(_asMap(v))),
      );

  /// The stored copy (checked on every read), or null — `fileStatus` says why.
  /// Files behind the screen lock never open here: use `unlockFile`.
  /// Keep the content in memory only as long as you need it, and never log it.
  static Future<String?> loadFile(
    String key, {
    String encoding = ContentEncoding.utf8,
  }) => _call<String?>(
    () => _channel.invokeMethod<String?>('loadFile', {
      'key': key,
      'encoding': encoding,
    }),
  );

  static Future<VaultFileStatus> fileStatus(String key) =>
      _call<VaultFileStatus>(
        () => _channel
            .invokeMethod<String>('fileStatus', key)
            .then((v) => VaultFileStatus.fromWire(v ?? VaultFileStatus.notStored.wire)),
      );

  /// Shows the native screen-lock prompt (BiometricPrompt / LAContext), then returns the content.
  static Future<VaultFileUnlockResult> unlockFile(
    String key,
    VaultFileUnlockPrompt prompt, {
    String encoding = ContentEncoding.utf8,
  }) {
    final json = _strictJson(
      {...prompt.toJson(), 'encoding': encoding},
      'prompt',
      PinVaultErrorCode.invalidArgument,
    );
    return _call<VaultFileUnlockResult>(
      () => _channel
          .invokeMethod<dynamic>('unlockFile', {'key': key, 'prompt': json})
          .then((v) => VaultFileUnlockResult.fromJson(_asMap(v))),
    );
  }

  static Future<bool> isFileLocked(String key) => _call<bool>(
    () => _channel
        .invokeMethod<bool>('isFileLocked', key)
        .then((v) => v ?? false),
  );

  static Future<bool> hasFile(String key) => _call<bool>(
    () => _channel.invokeMethod<bool>('hasFile', key).then((v) => v ?? false),
  );

  static Future<int> fileVersion(String key) => _call<int>(
    () => _channel.invokeMethod<int>('fileVersion', key).then((v) => v ?? 0),
  );

  static Future<void> clearFile(String key) =>
      _call<void>(() => _channel.invokeMethod<void>('clearFile', key));

  static Future<Map<String, VaultFileResult>> syncAllFiles() =>
      _call<Map<String, VaultFileResult>>(
        () => _channel.invokeMethod<dynamic>('syncAllFiles').then((v) {
          final map = _asMap(v);
          return map.map(
            (k, val) => MapEntry(k, VaultFileResult.fromJson(_asMap(val))),
          );
        }),
      );

  // ── Attestation ───────────────────────────────────────────────────────────

  static Future<AttestationStatus> attestNow([String? configApiId]) =>
      _call<AttestationStatus>(
        () => _channel
            .invokeMethod<dynamic>('attestNow', configApiId)
            .then((v) => AttestationStatus.fromJson(_asMap(v))),
      );

  /// `PinVault-Token` for your own client (a bearer credential: never log or store it).
  static Future<AttestationTokenResult> fetchAttestationToken([String? host]) =>
      _call<AttestationTokenResult>(
        () => _channel
            .invokeMethod<dynamic>('fetchAttestationToken', host)
            .then((v) => AttestationTokenResult.fromJson(_asMap(v))),
      );

  static Future<AttestationStatus> attestationStatus([String? configApiId]) =>
      _call<AttestationStatus>(
        () => _channel
            .invokeMethod<dynamic>('attestationStatus', configApiId)
            .then((v) => AttestationStatus.fromJson(_asMap(v))),
      );

  static String attestationHeaderName() => 'PinVault-Token';

  // ── Events ────────────────────────────────────────────────────────────────

  /// Connection telemetry (`onConnectionEvent`). Returns a subscription; call `remove()` when done.
  static StreamSubscription<PinVaultConnectionEvent> addConnectionListener(
    void Function(PinVaultConnectionEvent event) listener,
  ) {
    final stream = _eventsChannel.receiveBroadcastStream().map<PinVaultConnectionEvent>(
          (event) => PinVaultConnectionEvent.fromJson(_asMap(event)),
        );
    return stream.listen(listener);
  }
}
