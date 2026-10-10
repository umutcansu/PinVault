// Public types. Names, fields and enum values are the native ones
// (Kotlin `PinVaultConfig.Builder`, `ConfigApiBlock.Builder`,
// `VaultFileConfig.Builder`, `InitResult`, … and their Swift twins).
// Enum wire values are the Kotlin constant names, which are also the Swift raw values.

/// A length of time as `amount` + `unit`, matching the builder methods
/// (`expiredConfigGrace(1, TimeUnit.HOURS)`). Named `PinVaultDuration` so it
/// never shadows `dart:core`'s `Duration`.
class PinVaultDuration {
  final int amount;
  final TimeUnit unit;

  const PinVaultDuration(this.amount, this.unit);

  Map<String, dynamic> toJson() => {'amount': amount, 'unit': unit.wire};
}

enum TimeUnit {
  milliseconds('MILLISECONDS'),
  seconds('SECONDS'),
  minutes('MINUTES'),
  hours('HOURS'),
  days('DAYS');

  const TimeUnit(this.wire);
  final String wire;
}

// ── Configuration ────────────────────────────────────────────────────────────

/// A pin entry (`HostPin`). At least two pins (primary + backup), Base64 SPKI
/// SHA-256 without the `sha256/` prefix.
class HostPin {
  final String hostname;
  final List<String> sha256;
  final int? version;
  final bool? forceUpdate;
  final bool? mtls;
  final int? clientCertVersion;

  const HostPin({
    required this.hostname,
    required this.sha256,
    this.version,
    this.forceUpdate,
    this.mtls,
    this.clientCertVersion,
  });

  Map<String, dynamic> toJson() => {
    'hostname': hostname,
    'sha256': sha256,
    if (version != null) 'version': version,
    if (forceUpdate != null) 'forceUpdate': forceUpdate,
    if (mtls != null) 'mtls': mtls,
    if (clientCertVersion != null) 'clientCertVersion': clientCertVersion,
  };
}

/// One Config API (`configApi(id, url) { … }`). Keys are the `ConfigApiBlock.Builder` methods.
class ConfigApiBlock {
  final String id;
  final String url;
  final List<HostPin>? bootstrapPins;
  final String? configEndpoint;
  final String? healthEndpoint;

  /// `signaturePublicKey(key)`: one key. Use either this or [signaturePublicKeys].
  final String? signaturePublicKey;
  final List<String>? signaturePublicKeys;
  final int? requiredSignatures;
  final List<String>? recoveryPublicKeys;
  final int? requiredRecoverySignatures;
  final bool? allowUnsigned;
  final String? serverScope;
  final bool? allowUnpinnedConfigApi;
  final bool? allowServerGeneratedKey;
  final List<String>? clientCaPins;
  final int? maxClientCertLifetimeDays;
  final List<String>? clientCertHosts;
  final String? enrollmentEndpoint;
  final String? clientCertEndpoint;
  final String? vaultReportEndpoint;
  final String? clientCertLabel;
  final List<String>? wantPinsFor;
  final String? renewalUrl;
  final String? enrollmentUrl;
  final double? clientCertRenewalThreshold;
  final bool? disableClientCertRenewal;
  final bool? attestation;
  final PinVaultDuration? attestationInterval;
  final List<String>? tokenHosts;

  /// Every request that carries the `PinVault-Token` also carries a
  /// `PinVault-Proof` signed by the device key (ATTESTATION.md §5.1). Needs
  /// `attestation`. The proof is made natively, so a token handed to Dart
  /// (`fetchAttestationToken`) cannot be proven from Dart: use `PinVault.fetch`.
  final bool? proofOfPossession;

  const ConfigApiBlock({
    required this.id,
    required this.url,
    this.bootstrapPins,
    this.configEndpoint,
    this.healthEndpoint,
    this.signaturePublicKey,
    this.signaturePublicKeys,
    this.requiredSignatures,
    this.recoveryPublicKeys,
    this.requiredRecoverySignatures,
    this.allowUnsigned,
    this.serverScope,
    this.allowUnpinnedConfigApi,
    this.allowServerGeneratedKey,
    this.clientCaPins,
    this.maxClientCertLifetimeDays,
    this.clientCertHosts,
    this.enrollmentEndpoint,
    this.clientCertEndpoint,
    this.vaultReportEndpoint,
    this.clientCertLabel,
    this.wantPinsFor,
    this.renewalUrl,
    this.enrollmentUrl,
    this.clientCertRenewalThreshold,
    this.disableClientCertRenewal,
    this.attestation,
    this.attestationInterval,
    this.tokenHosts,
    this.proofOfPossession,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'url': url,
    if (bootstrapPins != null)
      'bootstrapPins': bootstrapPins!.map((e) => e.toJson()).toList(),
    if (configEndpoint != null) 'configEndpoint': configEndpoint,
    if (healthEndpoint != null) 'healthEndpoint': healthEndpoint,
    if (signaturePublicKey != null) 'signaturePublicKey': signaturePublicKey,
    if (signaturePublicKeys != null) 'signaturePublicKeys': signaturePublicKeys,
    if (requiredSignatures != null) 'requiredSignatures': requiredSignatures,
    if (recoveryPublicKeys != null) 'recoveryPublicKeys': recoveryPublicKeys,
    if (requiredRecoverySignatures != null)
      'requiredRecoverySignatures': requiredRecoverySignatures,
    if (allowUnsigned != null) 'allowUnsigned': allowUnsigned,
    if (serverScope != null) 'serverScope': serverScope,
    if (allowUnpinnedConfigApi != null)
      'allowUnpinnedConfigApi': allowUnpinnedConfigApi,
    if (allowServerGeneratedKey != null)
      'allowServerGeneratedKey': allowServerGeneratedKey,
    if (clientCaPins != null) 'clientCaPins': clientCaPins,
    if (maxClientCertLifetimeDays != null)
      'maxClientCertLifetimeDays': maxClientCertLifetimeDays,
    if (clientCertHosts != null) 'clientCertHosts': clientCertHosts,
    if (enrollmentEndpoint != null) 'enrollmentEndpoint': enrollmentEndpoint,
    if (clientCertEndpoint != null) 'clientCertEndpoint': clientCertEndpoint,
    if (vaultReportEndpoint != null) 'vaultReportEndpoint': vaultReportEndpoint,
    if (clientCertLabel != null) 'clientCertLabel': clientCertLabel,
    if (wantPinsFor != null) 'wantPinsFor': wantPinsFor,
    if (renewalUrl != null) 'renewalUrl': renewalUrl,
    if (enrollmentUrl != null) 'enrollmentUrl': enrollmentUrl,
    if (clientCertRenewalThreshold != null)
      'clientCertRenewalThreshold': clientCertRenewalThreshold,
    if (disableClientCertRenewal != null)
      'disableClientCertRenewal': disableClientCertRenewal,
    if (attestation != null) 'attestation': attestation,
    if (attestationInterval != null)
      'attestationInterval': attestationInterval!.toJson(),
    if (tokenHosts != null) 'tokenHosts': tokenHosts,
    if (proofOfPossession != null) 'proofOfPossession': proofOfPossession,
  };
}

enum StorageStrategy {
  encryptedPrefs('ENCRYPTED_PREFS'),
  encryptedFile('ENCRYPTED_FILE');

  const StorageStrategy(this.wire);
  final String wire;
}

enum VaultFileAccessPolicy {
  public('PUBLIC'),
  apiKey('API_KEY'),
  token('TOKEN'),
  tokenMtls('TOKEN_MTLS');

  const VaultFileAccessPolicy(this.wire);
  final String wire;
}

enum VaultFileEncryption {
  plain('PLAIN'),
  atRest('AT_REST'),
  endToEnd('END_TO_END'),
  userAuth('USER_AUTH');

  const VaultFileEncryption(this.wire);
  final String wire;
}

enum UserAuth {
  none('NONE'),
  required('REQUIRED'),
  ifScreenLock('IF_SCREEN_LOCK');

  const UserAuth(this.wire);
  final String wire;
}

/// One vault file (`vaultFile(key) { … }`). For `TOKEN` / `TOKEN_MTLS` files the
/// native side installs the `accessToken { … }` provider itself: it reads the token
/// you set with `setVaultToken(key, token)` (or pass to `fetchFile(key, { token })`),
/// which stays in native memory only.
class VaultFileConfig {
  final String key;
  final String endpoint;
  final String? signaturePublicKey;
  final bool? updateWithPins;
  final StorageStrategy? storage;
  final String? configApi;
  final VaultFileAccessPolicy? accessPolicy;
  final VaultFileEncryption? encryption;
  final UserAuth? userAuth;
  final PinVaultDuration? maxOfflineAge;
  final bool? wipeWhenStale;

  const VaultFileConfig({
    required this.key,
    required this.endpoint,
    this.signaturePublicKey,
    this.updateWithPins,
    this.storage,
    this.configApi,
    this.accessPolicy,
    this.encryption,
    this.userAuth,
    this.maxOfflineAge,
    this.wipeWhenStale,
  });

  Map<String, dynamic> toJson() => {
    'key': key,
    'endpoint': endpoint,
    if (signaturePublicKey != null) 'signaturePublicKey': signaturePublicKey,
    if (updateWithPins != null) 'updateWithPins': updateWithPins,
    if (storage != null) 'storage': storage!.wire,
    if (configApi != null) 'configApi': configApi,
    if (accessPolicy != null) 'accessPolicy': accessPolicy!.wire,
    if (encryption != null) 'encryption': encryption!.wire,
    if (userAuth != null) 'userAuth': userAuth!.wire,
    if (maxOfflineAge != null) 'maxOfflineAge': maxOfflineAge!.toJson(),
    if (wipeWhenStale != null) 'wipeWhenStale': wipeWhenStale,
  };
}

/// Operations the environment guard is asked about (`GuardedOperation`).
enum GuardedOperation {
  init('INIT'),
  enroll('ENROLL'),
  fetchFile('FETCH_FILE'),
  unlockFile('UNLOCK_FILE'),
  loadFile('LOAD_FILE');

  const GuardedOperation(this.wire);
  final String wire;
}

/// The app's device verdict (root / jailbreak / hooking detection of your choice)
/// before every guarded operation. Runs in Dart, so code that hooks the Dart runtime
/// can answer for it: treat it as one more signal, the decisive check is the
/// server's attestation verdict. Fail closed: a timeout, a thrown error or a
/// non-`true` value refuses the operation.
typedef EnvironmentGuard = Future<bool> Function(GuardedOperation operation);

/// `PinVaultConfig.Builder`, as a Dart object.
class PinVaultConfig {
  final List<ConfigApiBlock>? configApis;
  final List<VaultFileConfig>? vaultFiles;
  final StaticPins? staticPins;
  final int? maxRetryCount;
  final int? updateIntervalHours;
  final int? updateIntervalMinutes;
  final String? deviceAlias;
  final PinVaultDuration? expiredConfigGrace;
  final List<String>? requireCaTrust;
  final bool? wipeVaultFilesOnRevocation;
  final PinVaultDuration? vaultFileMaxOfflineAge;
  final bool? requireUnlockedDevice;
  final bool? requireHardwareBackedKeys;
  final bool? managedTrustRoots;
  final List<String>? expectedSignerSha256;
  final EnvironmentGuard? environmentGuard;

  /// How long the native side waits for `environmentGuard` (ms, 100–30000, default 5000).
  final int? environmentGuardTimeoutMs;

  /// Android-only settings (ignored on iOS).
  final AndroidSettings? android;

  /// iOS-only settings (ignored on Android).
  final IosSettings? ios;

  const PinVaultConfig({
    this.configApis,
    this.vaultFiles,
    this.staticPins,
    this.maxRetryCount,
    this.updateIntervalHours,
    this.updateIntervalMinutes,
    this.deviceAlias,
    this.expiredConfigGrace,
    this.requireCaTrust,
    this.wipeVaultFilesOnRevocation,
    this.vaultFileMaxOfflineAge,
    this.requireUnlockedDevice,
    this.requireHardwareBackedKeys,
    this.managedTrustRoots,
    this.expectedSignerSha256,
    this.environmentGuard,
    this.environmentGuardTimeoutMs,
    this.android,
    this.ios,
  });

  /// The JSON the native side parses strictly. [environmentGuard] is stripped:
  /// the facade installs it as a Dart callback and only sends its timeout.
  Map<String, dynamic> toJson() => {
    if (configApis != null)
      'configApis': configApis!.map((e) => e.toJson()).toList(),
    if (vaultFiles != null)
      'vaultFiles': vaultFiles!.map((e) => e.toJson()).toList(),
    if (staticPins != null) 'staticPins': staticPins!.toJson(),
    if (maxRetryCount != null) 'maxRetryCount': maxRetryCount,
    if (updateIntervalHours != null) 'updateIntervalHours': updateIntervalHours,
    if (updateIntervalMinutes != null)
      'updateIntervalMinutes': updateIntervalMinutes,
    if (deviceAlias != null) 'deviceAlias': deviceAlias,
    if (expiredConfigGrace != null)
      'expiredConfigGrace': expiredConfigGrace!.toJson(),
    if (requireCaTrust != null) 'requireCaTrust': requireCaTrust,
    if (wipeVaultFilesOnRevocation != null)
      'wipeVaultFilesOnRevocation': wipeVaultFilesOnRevocation,
    if (vaultFileMaxOfflineAge != null)
      'vaultFileMaxOfflineAge': vaultFileMaxOfflineAge!.toJson(),
    if (requireUnlockedDevice != null)
      'requireUnlockedDevice': requireUnlockedDevice,
    if (requireHardwareBackedKeys != null)
      'requireHardwareBackedKeys': requireHardwareBackedKeys,
    if (managedTrustRoots != null) 'managedTrustRoots': managedTrustRoots,
    if (expectedSignerSha256 != null)
      'expectedSignerSha256': expectedSignerSha256,
    if (environmentGuard != null)
      'environmentGuard': {'timeoutMs': environmentGuardTimeoutMs ?? 5000},
    if (android != null) 'android': android!.toJson(),
    if (ios != null) 'ios': ios!.toJson(),
  };
}

class StaticPins {
  final List<HostPin> pins;
  final int? version;
  final bool? forceUpdate;

  const StaticPins({required this.pins, this.version, this.forceUpdate});

  Map<String, dynamic> toJson() => {
    'pins': pins.map((e) => e.toJson()).toList(),
    if (version != null) 'version': version,
    if (forceUpdate != null) 'forceUpdate': forceUpdate,
  };
}

class AndroidSettings {
  /// `requireUnlockedDevice(allowFallback = true)`.
  final bool? requireUnlockedDeviceAllowFallback;

  const AndroidSettings({this.requireUnlockedDeviceAllowFallback});

  Map<String, dynamic> toJson() => {
    if (requireUnlockedDeviceAllowFallback != null)
      'requireUnlockedDeviceAllowFallback': requireUnlockedDeviceAllowFallback,
  };
}

class IosSettings {
  /// `resolve(host:to:)`: connect to `address` while pinning and verifying `host`.
  final Map<String, String>? resolve;
  final List<String>? expectedBundleIds;
  final List<String>? expectedTeamIds;

  /// `userAuthStrength(_:)`; `BIOMETRIC_CURRENT_SET` = `userAuthBiometricOnly()`.
  final String? userAuthStrength;

  const IosSettings({
    this.resolve,
    this.expectedBundleIds,
    this.expectedTeamIds,
    this.userAuthStrength,
  });

  Map<String, dynamic> toJson() => {
    if (resolve != null) 'resolve': resolve,
    if (expectedBundleIds != null) 'expectedBundleIds': expectedBundleIds,
    if (expectedTeamIds != null) 'expectedTeamIds': expectedTeamIds,
    if (userAuthStrength != null) 'userAuthStrength': userAuthStrength,
  };
}

// ── Results ─────────────────────────────────────────────────────────────────

/// A native exception: its class name (`SSLPinningException`, …) and message.
class NativeException {
  final String name;
  final String? message;

  const NativeException({required this.name, this.message});

  factory NativeException.fromJson(Map<String, dynamic> json) =>
      NativeException(
        name: json['name'] as String? ?? 'Error',
        message: json['message'] as String?,
      );

  @override
  String toString() => message == null ? name : '$name: $message';
}

/// `nativeSecurityApplied`: the trust anchors came from the app's native
/// security file (README "Native security file"); false when Dart supplied them.
sealed class InitResult {
  const InitResult();

  factory InitResult.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'ready':
        return InitResultReady(
          version: json['version'] as int,
          nativeSecurityApplied:
              json['nativeSecurityApplied'] as bool? ?? false,
        );
      default:
        return InitResultFailed(
          reason: json['reason'] as String? ?? 'failed',
          exception: json['exception'] == null
              ? null
              : NativeException.fromJson(
                  json['exception'] as Map<String, dynamic>,
                ),
          nativeSecurityApplied:
              json['nativeSecurityApplied'] as bool? ?? false,
        );
    }
  }
}

class InitResultReady extends InitResult {
  final int version;
  final bool nativeSecurityApplied;
  const InitResultReady({
    required this.version,
    required this.nativeSecurityApplied,
  });
}

class InitResultFailed extends InitResult {
  final String reason;
  final NativeException? exception;
  final bool nativeSecurityApplied;
  const InitResultFailed({
    required this.reason,
    this.exception,
    required this.nativeSecurityApplied,
  });
}

sealed class UpdateResult {
  const UpdateResult();

  factory UpdateResult.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'updated':
        return UpdateResultUpdated(newVersion: json['newVersion'] as int);
      case 'alreadyCurrent':
        return const UpdateResultAlreadyCurrent();
      default:
        return UpdateResultFailed(
          reason: json['reason'] as String? ?? 'failed',
          exception: json['exception'] == null
              ? null
              : NativeException.fromJson(
                  json['exception'] as Map<String, dynamic>,
                ),
        );
    }
  }
}

class UpdateResultUpdated extends UpdateResult {
  final int newVersion;
  const UpdateResultUpdated({required this.newVersion});
}

class UpdateResultAlreadyCurrent extends UpdateResult {
  const UpdateResultAlreadyCurrent();
}

class UpdateResultFailed extends UpdateResult {
  final String reason;
  final NativeException? exception;
  const UpdateResultFailed({required this.reason, this.exception});
}

enum KeySecurityLevel {
  strongbox('STRONGBOX'),
  trustedEnvironment('TRUSTED_ENVIRONMENT'),
  software('SOFTWARE'),
  unknown('UNKNOWN'),
  secureEnclave('SECURE_ENCLAVE');

  const KeySecurityLevel(this.wire);
  final String wire;

  static KeySecurityLevel? fromWire(String? w) => w == null
      ? null
      : values.firstWhere(
          (e) => e.wire == w,
          orElse: () => KeySecurityLevel.unknown,
        );
}

enum EnrollmentRefusal {
  invalidToken('INVALID_TOKEN'),
  tokenRequired('TOKEN_REQUIRED'),
  deviceAlreadyEnrolled('DEVICE_ALREADY_ENROLLED'),
  revoked('REVOKED'),
  rejected('REJECTED'),
  limitReached('LIMIT_REACHED'),
  expired('EXPIRED'),
  attestationFailed('ATTESTATION_FAILED'),
  csrRequired('CSR_REQUIRED'),
  other('OTHER');

  const EnrollmentRefusal(this.wire);
  final String wire;
}

sealed class ClientCertEnrollmentResult {
  const ClientCertEnrollmentResult();

  factory ClientCertEnrollmentResult.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'enrolled':
        return EnrollmentEnrolled(
          alreadyEnrolled: json['alreadyEnrolled'] as bool? ?? false,
          keySecurityLevel: KeySecurityLevel.fromWire(
            json['keySecurityLevel'] as String?,
          ),
        );
      case 'refused':
        return EnrollmentRefused(
          reason: EnrollmentRefusal.values.firstWhere(
            (e) => e.wire == json['reason'],
            orElse: () => EnrollmentRefusal.other,
          ),
          httpStatus: json['httpStatus'] as int,
          serverError: json['serverError'] as String?,
          message: json['message'] as String?,
        );
      case 'pending':
        return EnrollmentPending(
          requestId: json['requestId'] as String,
          clientId: json['clientId'] as String?,
          message: json['message'] as String?,
          retryAfterSeconds: json['retryAfterSeconds'] as int?,
          verificationCode: json['verificationCode'] as String?,
        );
      default:
        return EnrollmentFailed(
          message: json['message'] as String? ?? 'failed',
          cause: json['cause'] == null
              ? null
              : NativeException.fromJson(json['cause'] as Map<String, dynamic>),
        );
    }
  }
}

class EnrollmentEnrolled extends ClientCertEnrollmentResult {
  final bool alreadyEnrolled;
  final KeySecurityLevel? keySecurityLevel;
  const EnrollmentEnrolled({
    required this.alreadyEnrolled,
    this.keySecurityLevel,
  });
}

class EnrollmentRefused extends ClientCertEnrollmentResult {
  final EnrollmentRefusal reason;
  final int httpStatus;
  final String? serverError;
  final String? message;
  const EnrollmentRefused({
    required this.reason,
    required this.httpStatus,
    this.serverError,
    this.message,
  });
}

class EnrollmentPending extends ClientCertEnrollmentResult {
  final String requestId;
  final String? clientId;
  final String? message;
  final int? retryAfterSeconds;
  final String? verificationCode;
  const EnrollmentPending({
    required this.requestId,
    this.clientId,
    this.message,
    this.retryAfterSeconds,
    this.verificationCode,
  });
}

class EnrollmentFailed extends ClientCertEnrollmentResult {
  final String message;
  final NativeException? cause;
  const EnrollmentFailed({required this.message, this.cause});
}

/// `VaultFileResult`. `updated` carries no content: read it with `loadFile(key)`
/// (or `unlockFile` for files behind the screen lock).
sealed class VaultFileResult {
  const VaultFileResult();

  factory VaultFileResult.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'updated':
        return VaultFileUpdated(
          key: json['key'] as String,
          version: json['version'] as int,
        );
      case 'alreadyCurrent':
        return VaultFileAlreadyCurrent(
          key: json['key'] as String,
          version: json['version'] as int,
        );
      default:
        return VaultFileFailed(
          key: json['key'] as String,
          reason: json['reason'] as String? ?? 'failed',
          code: json['code'] as String? ?? '',
          exception: json['exception'] == null
              ? null
              : NativeException.fromJson(
                  json['exception'] as Map<String, dynamic>,
                ),
        );
    }
  }
}

class VaultFileUpdated extends VaultFileResult {
  final String key;
  final int version;
  const VaultFileUpdated({required this.key, required this.version});
}

class VaultFileAlreadyCurrent extends VaultFileResult {
  final String key;
  final int version;
  const VaultFileAlreadyCurrent({required this.key, required this.version});
}

class VaultFileFailed extends VaultFileResult {
  final String key;
  final String reason;
  final String code;
  final NativeException? exception;
  const VaultFileFailed({
    required this.key,
    required this.reason,
    required this.code,
    this.exception,
  });
}

enum VaultFileStatus {
  available('AVAILABLE'),
  locked('LOCKED'),
  notStored('NOT_STORED'),
  stale('STALE'),
  needsFetch('NEEDS_FETCH'),
  integrityFailed('INTEGRITY_FAILED'),
  storageUnavailable('STORAGE_UNAVAILABLE');

  const VaultFileStatus(this.wire);
  final String wire;

  static VaultFileStatus fromWire(String w) => values.firstWhere(
    (e) => e.wire == w,
    orElse: () => VaultFileStatus.notStored,
  );
}

class ContentEncoding {
  static const String utf8 = 'utf8';
  static const String base64 = 'base64';
}

class VaultFileUnlockPrompt {
  final String title;
  final String? subtitle;
  final String? description;
  final String? negativeButtonText;

  const VaultFileUnlockPrompt({
    required this.title,
    this.subtitle,
    this.description,
    this.negativeButtonText,
  });

  Map<String, dynamic> toJson() => {
    'title': title,
    if (subtitle != null) 'subtitle': subtitle,
    if (description != null) 'description': description,
    if (negativeButtonText != null) 'negativeButtonText': negativeButtonText,
  };
}

sealed class VaultFileUnlockResult {
  const VaultFileUnlockResult();

  factory VaultFileUnlockResult.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'unlocked':
        return VaultFileUnlocked(
          key: json['key'] as String,
          version: json['version'] as int,
          content: json['content'] as String,
          encoding: json['encoding'] as String? ?? ContentEncoding.utf8,
        );
      case 'notFound':
        return VaultFileUnlockNotFound(key: json['key'] as String);
      case 'cancelled':
        return VaultFileUnlockCancelled(key: json['key'] as String);
      case 'invalidated':
        return VaultFileUnlockInvalidated(key: json['key'] as String);
      case 'stale':
        return VaultFileUnlockStale(key: json['key'] as String);
      default:
        return VaultFileUnlockFailed(
          key: json['key'] as String,
          reason: json['reason'] as String? ?? 'failed',
          exception: json['exception'] == null
              ? null
              : NativeException.fromJson(
                  json['exception'] as Map<String, dynamic>,
                ),
        );
    }
  }
}

class VaultFileUnlocked extends VaultFileUnlockResult {
  final String key;
  final int version;
  final String content;
  final String encoding;
  const VaultFileUnlocked({
    required this.key,
    required this.version,
    required this.content,
    required this.encoding,
  });
}

class VaultFileUnlockNotFound extends VaultFileUnlockResult {
  final String key;
  const VaultFileUnlockNotFound({required this.key});
}

class VaultFileUnlockCancelled extends VaultFileUnlockResult {
  final String key;
  const VaultFileUnlockCancelled({required this.key});
}

class VaultFileUnlockInvalidated extends VaultFileUnlockResult {
  final String key;
  const VaultFileUnlockInvalidated({required this.key});
}

class VaultFileUnlockStale extends VaultFileUnlockResult {
  final String key;
  const VaultFileUnlockStale({required this.key});
}

class VaultFileUnlockFailed extends VaultFileUnlockResult {
  final String key;
  final String reason;
  final NativeException? exception;
  const VaultFileUnlockFailed({
    required this.key,
    required this.reason,
    this.exception,
  });
}

enum AttestationResult {
  pass('PASS'),
  reject('REJECT'),
  failed('FAILED'),
  notAttested('NOT_ATTESTED'),
  unsupported('UNSUPPORTED');

  const AttestationResult(this.wire);
  final String wire;

  static AttestationResult fromWire(String w) => values.firstWhere(
    (e) => e.wire == w,
    orElse: () => AttestationResult.failed,
  );
}

class AttestationStatus {
  final String configApiId;
  final AttestationResult result;
  final String? arc;
  final List<String> rejectionReasons;
  final List<String> warnings;
  final int? tokenExpiresAt;
  final int? lastAttestedAt;
  final int? nextAttestAt;
  final int? clockSkewMs;
  final String? lastError;
  final int? policyVersion;

  const AttestationStatus({
    required this.configApiId,
    required this.result,
    this.arc,
    this.rejectionReasons = const [],
    this.warnings = const [],
    this.tokenExpiresAt,
    this.lastAttestedAt,
    this.nextAttestAt,
    this.clockSkewMs,
    this.lastError,
    this.policyVersion,
  });

  factory AttestationStatus.fromJson(Map<String, dynamic> json) =>
      AttestationStatus(
        configApiId: json['configApiId'] as String? ?? '',
        result: AttestationResult.fromWire(json['result'] as String? ?? ''),
        arc: json['arc'] as String?,
        rejectionReasons:
            (json['rejectionReasons'] as List?)?.cast<String>() ?? const [],
        warnings: (json['warnings'] as List?)?.cast<String>() ?? const [],
        tokenExpiresAt: json['tokenExpiresAt'] as int?,
        lastAttestedAt: json['lastAttestedAt'] as int?,
        nextAttestAt: json['nextAttestAt'] as int?,
        clockSkewMs: json['clockSkewMs'] as int?,
        lastError: json['lastError'] as String?,
        policyVersion: json['policyVersion'] as int?,
      );
}

/// `PinVault-Token` for your own HTTP client. The value is a bearer credential: never log it.
sealed class AttestationTokenResult {
  const AttestationTokenResult();

  factory AttestationTokenResult.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'token':
        return AttestationTokenToken(
          value: json['value'] as String,
          expiresAt: json['expiresAt'] as int,
        );
      case 'rejected':
        return AttestationTokenRejected(
          status: AttestationStatus.fromJson(
            json['status'] as Map<String, dynamic>,
          ),
        );
      case 'unsupported':
        return const AttestationTokenUnsupported();
      default:
        return AttestationTokenFailed(
          message: json['message'] as String? ?? 'failed',
        );
    }
  }
}

class AttestationTokenToken extends AttestationTokenResult {
  final String value;
  final int expiresAt;
  const AttestationTokenToken({required this.value, required this.expiresAt});
}

class AttestationTokenRejected extends AttestationTokenResult {
  final AttestationStatus status;
  const AttestationTokenRejected({required this.status});
}

class AttestationTokenFailed extends AttestationTokenResult {
  final String message;
  const AttestationTokenFailed({required this.message});
}

class AttestationTokenUnsupported extends AttestationTokenResult {
  const AttestationTokenUnsupported();
}

class SigningStatus {
  final String configApiId;
  final List<String> trustedKeyIds;
  final int requiredSignatures;
  final int keySetVersion;
  final List<String> recoveryKeyIds;
  final List<String> lastConfigSignedBy;

  const SigningStatus({
    required this.configApiId,
    required this.trustedKeyIds,
    required this.requiredSignatures,
    required this.keySetVersion,
    required this.recoveryKeyIds,
    required this.lastConfigSignedBy,
  });

  factory SigningStatus.fromJson(Map<String, dynamic> json) => SigningStatus(
    configApiId: json['configApiId'] as String? ?? '',
    trustedKeyIds: (json['trustedKeyIds'] as List?)?.cast<String>() ?? const [],
    requiredSignatures: json['requiredSignatures'] as int? ?? 0,
    keySetVersion: json['keySetVersion'] as int? ?? 0,
    recoveryKeyIds:
        (json['recoveryKeyIds'] as List?)?.cast<String>() ?? const [],
    lastConfigSignedBy:
        (json['lastConfigSignedBy'] as List?)?.cast<String>() ?? const [],
  );
}

// ── Events ──────────────────────────────────────────────────────────────────

/// `PinVaultConnectionEvent`. Never carries a token, a password or file content.
sealed class PinVaultConnectionEvent {
  const PinVaultConnectionEvent();

  factory PinVaultConnectionEvent.fromJson(Map<String, dynamic> json) {
    switch (json['type']) {
      case 'connection':
        return ConnectionEvent(
          hostname: json['hostname'] as String? ?? '',
          success: json['success'] as bool? ?? false,
          pinVersion: json['pinVersion'] as int? ?? 0,
          deviceManufacturer: json['deviceManufacturer'] as String? ?? '',
          deviceModel: json['deviceModel'] as String? ?? '',
          actualPin: json['actualPin'] as String? ?? '',
          expectedPins:
              (json['expectedPins'] as List?)?.cast<String>() ?? const [],
        );
      case 'configUpdate':
        return ConfigUpdateEvent(
          status: json['status'] as String? ?? 'FAILED',
          newVersion: json['newVersion'] as int? ?? 0,
          deviceManufacturer: json['deviceManufacturer'] as String? ?? '',
          deviceModel: json['deviceModel'] as String? ?? '',
          failureReason: json['failureReason'] as String?,
        );
      case 'clientCertRenewal':
        return ClientCertRenewalEvent(
          status: json['status'] as String? ?? 'FAILED',
          notAfterEpochMs: json['notAfterEpochMs'] as int? ?? 0,
          via: json['via'] as String?,
          configApiId: json['configApiId'] as String? ?? '',
          deviceManufacturer: json['deviceManufacturer'] as String? ?? '',
          deviceModel: json['deviceModel'] as String? ?? '',
          failureReason: json['failureReason'] as String?,
        );
      default:
        return AttestationEvent(
          configApiId: json['configApiId'] as String? ?? '',
          status: json['status'] as String? ?? 'FAILED',
          arc: json['arc'] as String?,
          rejectionReasons:
              (json['rejectionReasons'] as List?)?.cast<String>() ?? const [],
          warnings: (json['warnings'] as List?)?.cast<String>() ?? const [],
          tokenExpiresAt: json['tokenExpiresAt'] as int?,
          deviceManufacturer: json['deviceManufacturer'] as String? ?? '',
          deviceModel: json['deviceModel'] as String? ?? '',
          failureReason: json['failureReason'] as String?,
        );
    }
  }
}

class ConnectionEvent extends PinVaultConnectionEvent {
  final String hostname;
  final bool success;
  final int pinVersion;
  final String deviceManufacturer;
  final String deviceModel;
  final String actualPin;
  final List<String> expectedPins;
  const ConnectionEvent({
    required this.hostname,
    required this.success,
    required this.pinVersion,
    required this.deviceManufacturer,
    required this.deviceModel,
    required this.actualPin,
    required this.expectedPins,
  });
}

class ConfigUpdateEvent extends PinVaultConnectionEvent {
  final String status;
  final int newVersion;
  final String deviceManufacturer;
  final String deviceModel;
  final String? failureReason;
  const ConfigUpdateEvent({
    required this.status,
    required this.newVersion,
    required this.deviceManufacturer,
    required this.deviceModel,
    this.failureReason,
  });
}

class ClientCertRenewalEvent extends PinVaultConnectionEvent {
  final String status;
  final int notAfterEpochMs;
  final String? via;
  final String configApiId;
  final String deviceManufacturer;
  final String deviceModel;
  final String? failureReason;
  const ClientCertRenewalEvent({
    required this.status,
    required this.notAfterEpochMs,
    this.via,
    required this.configApiId,
    required this.deviceManufacturer,
    required this.deviceModel,
    this.failureReason,
  });
}

class AttestationEvent extends PinVaultConnectionEvent {
  final String configApiId;
  final String status;
  final String? arc;
  final List<String> rejectionReasons;
  final List<String> warnings;
  final int? tokenExpiresAt;
  final String deviceManufacturer;
  final String deviceModel;
  final String? failureReason;
  const AttestationEvent({
    required this.configApiId,
    required this.status,
    this.arc,
    required this.rejectionReasons,
    required this.warnings,
    this.tokenExpiresAt,
    required this.deviceManufacturer,
    required this.deviceModel,
    this.failureReason,
  });
}

// ── Pinned HTTP ─────────────────────────────────────────────────────────────

enum HttpMethod {
  get('GET'),
  head('HEAD'),
  post('POST'),
  put('PUT'),
  patch('PATCH'),
  delete('DELETE'),
  options('OPTIONS');

  const HttpMethod(this.wire);
  final String wire;
}

/// `HttpConnectionSettings` (seconds). With settings the request uses
/// `getClient(settings)` / `session(settings:)`: pinning without pin-mismatch recovery.
class HttpConnectionSettings {
  final int? connectTimeout;
  final int? readTimeout;
  final int? writeTimeout;
  final int? callTimeout;

  const HttpConnectionSettings({
    this.connectTimeout,
    this.readTimeout,
    this.writeTimeout,
    this.callTimeout,
  });

  Map<String, dynamic> toJson() => {
    if (connectTimeout != null) 'connectTimeout': connectTimeout,
    if (readTimeout != null) 'readTimeout': readTimeout,
    if (writeTimeout != null) 'writeTimeout': writeTimeout,
    if (callTimeout != null) 'callTimeout': callTimeout,
  };
}

class PinVaultRequestInit {
  final HttpMethod? method;
  final Map<String, String>? headers;

  /// Request body: text, or Base64 with `bodyEncoding: 'base64'`. At most 10 MiB.
  final String? body;
  final String? bodyEncoding;

  /// How the response body comes back (default `utf8`).
  final String? responseEncoding;

  /// Whole-call timeout in ms (default: the client's).
  final int? timeoutMs;

  /// Larger responses are refused (default 10 MiB, at most 50 MiB).
  final int? maxResponseBytes;
  final HttpConnectionSettings? settings;

  const PinVaultRequestInit({
    this.method,
    this.headers,
    this.body,
    this.bodyEncoding,
    this.responseEncoding,
    this.timeoutMs,
    this.maxResponseBytes,
    this.settings,
  });

  Map<String, dynamic> toJson() => {
    if (method != null) 'method': method!.wire,
    if (headers != null) 'headers': headers,
    if (body != null) 'body': body,
    if (bodyEncoding != null) 'bodyEncoding': bodyEncoding,
    if (responseEncoding != null) 'responseEncoding': responseEncoding,
    if (timeoutMs != null) 'timeoutMs': timeoutMs,
    if (maxResponseBytes != null) 'maxResponseBytes': maxResponseBytes,
    if (settings != null) 'settings': settings!.toJson(),
  };
}

class PinVaultResponse {
  final int status;
  final String url;

  /// Lower-case names; repeated headers joined with `, `.
  final Map<String, String> headers;
  final String body;
  final String bodyEncoding;

  const PinVaultResponse({
    required this.status,
    required this.url,
    required this.headers,
    required this.body,
    required this.bodyEncoding,
  });

  bool get ok => status >= 200 && status < 300;

  factory PinVaultResponse.fromJson(Map<String, dynamic> json) =>
      PinVaultResponse(
        status: json['status'] as int,
        url: json['url'] as String? ?? '',
        headers:
            (json['headers'] as Map?)?.map(
              (k, v) => MapEntry(k as String, v as String),
            ) ??
            const {},
        body: json['body'] as String? ?? '',
        bodyEncoding: json['bodyEncoding'] as String? ?? ContentEncoding.utf8,
      );
}
