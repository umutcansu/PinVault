// Public types. Names, fields and enum values are the native ones
// (Kotlin `PinVaultConfig.Builder`, `ConfigApiBlock.Builder`,
// `VaultFileConfig.Builder`, `InitResult`, … and their Swift twins).
// Enum values are the Kotlin constant names, which are also the Swift raw values.

// ── Configuration ────────────────────────────────────────────────────────────

export type TimeUnit = 'MILLISECONDS' | 'SECONDS' | 'MINUTES' | 'HOURS' | 'DAYS';

/** `amount` + `unit`, as the builder methods take them (`expiredConfigGrace(1, TimeUnit.HOURS)`). */
export type Duration = { amount: number; unit: TimeUnit };

/** A pin entry (`HostPin`). At least two pins (primary + backup), Base64 SPKI SHA-256 without `sha256/`. */
export type HostPin = {
  hostname: string;
  sha256: string[];
  version?: number;
  forceUpdate?: boolean;
  mtls?: boolean;
  clientCertVersion?: number;
};

/** One Config API (`configApi(id, url) { … }`). Keys are the `ConfigApiBlock.Builder` methods. */
export type ConfigApiBlock = {
  id: string;
  url: string;
  bootstrapPins?: HostPin[];
  configEndpoint?: string;
  healthEndpoint?: string;
  /** `signaturePublicKey(key)`: one key. Use either this or `signaturePublicKeys`. */
  signaturePublicKey?: string;
  signaturePublicKeys?: string[];
  requiredSignatures?: number;
  recoveryPublicKeys?: string[];
  requiredRecoverySignatures?: number;
  allowUnsigned?: boolean;
  serverScope?: string;
  allowUnpinnedConfigApi?: boolean;
  allowServerGeneratedKey?: boolean;
  clientCaPins?: string[];
  maxClientCertLifetimeDays?: number;
  clientCertHosts?: string[];
  enrollmentEndpoint?: string;
  clientCertEndpoint?: string;
  vaultReportEndpoint?: string;
  clientCertLabel?: string;
  wantPinsFor?: string[];
  renewalUrl?: string;
  enrollmentUrl?: string;
  clientCertRenewalThreshold?: number;
  disableClientCertRenewal?: boolean;
  attestation?: boolean;
  attestationInterval?: Duration;
  tokenHosts?: string[];
  /**
   * Every request that carries the `PinVault-Token` also carries a
   * `PinVault-Proof` signed by the device key (ATTESTATION.md §5.1). Needs
   * `attestation`. The proof is made natively, so a token handed to JS
   * (`fetchAttestationToken`) cannot be proven from JS: use `PinVault.fetch`.
   */
  proofOfPossession?: boolean;
};

export type StorageStrategy = 'ENCRYPTED_PREFS' | 'ENCRYPTED_FILE';
export type VaultFileAccessPolicy = 'PUBLIC' | 'API_KEY' | 'TOKEN' | 'TOKEN_MTLS';
export type VaultFileEncryption = 'PLAIN' | 'AT_REST' | 'END_TO_END' | 'USER_AUTH';
export type UserAuth = 'NONE' | 'REQUIRED' | 'IF_SCREEN_LOCK';

/**
 * One vault file (`vaultFile(key) { … }`). For `TOKEN` / `TOKEN_MTLS` files the
 * native side installs the `accessToken { … }` provider itself: it reads the token
 * you set with `setVaultToken(key, token)` (or pass to `fetchFile(key, { token })`),
 * which stays in native memory only.
 */
export type VaultFileConfig = {
  key: string;
  endpoint: string;
  signaturePublicKey?: string;
  updateWithPins?: boolean;
  storage?: StorageStrategy;
  configApi?: string;
  accessPolicy?: VaultFileAccessPolicy;
  encryption?: VaultFileEncryption;
  userAuth?: UserAuth;
  maxOfflineAge?: Duration;
  wipeWhenStale?: boolean;
};

/** Operations the environment guard is asked about (`GuardedOperation`). */
export type GuardedOperation = 'INIT' | 'ENROLL' | 'FETCH_FILE' | 'UNLOCK_FILE' | 'LOAD_FILE';

/**
 * The app's device verdict (root / jailbreak / hooking detection of your choice)
 * before every guarded operation. Runs in JS, so code that hooks the JS runtime
 * can answer for it: treat it as one more signal, the decisive check is the
 * server's attestation verdict. Fail closed: a timeout, a thrown error or a
 * non-`true` value refuses the operation.
 */
export type EnvironmentGuard = (operation: GuardedOperation) => boolean | Promise<boolean>;

/** `PinVaultConfig.Builder`, as JSON. */
export type PinVaultConfig = {
  configApis?: ConfigApiBlock[];
  vaultFiles?: VaultFileConfig[];
  staticPins?: { pins: HostPin[]; version?: number; forceUpdate?: boolean };
  maxRetryCount?: number;
  updateIntervalHours?: number;
  updateIntervalMinutes?: number;
  deviceAlias?: string;
  expiredConfigGrace?: Duration;
  requireCaTrust?: string[];
  wipeVaultFilesOnRevocation?: boolean;
  vaultFileMaxOfflineAge?: Duration;
  requireUnlockedDevice?: boolean;
  requireHardwareBackedKeys?: boolean;
  managedTrustRoots?: boolean;
  expectedSignerSha256?: string[];
  environmentGuard?: EnvironmentGuard;
  /** How long the native side waits for `environmentGuard` (ms, 100–30000, default 5000). */
  environmentGuardTimeoutMs?: number;
  /**
   * `start` fails with `E_NETWORKING_NOT_PINNED` when React Native's own networking
   * does not go through PinVault: on Android when another library replaced the
   * OkHttp hooks (or they are not installed), on iOS when RCTNetworking does not
   * pick the plugin's request handler for https. Default false (a warning is logged).
   */
  requirePinnedReactNativeNetworking?: boolean;
  /** Android-only settings (ignored on iOS). */
  android?: {
    /** `requireUnlockedDevice(allowFallback = true)`. */
    requireUnlockedDeviceAllowFallback?: boolean;
    /**
     * Pin React Native's own `fetch` / `XMLHttpRequest` / `WebSocket` / images (default true).
     * The plugin's content provider installs the hooks before the app starts; `false`
     * is refused while they are installed — opt out natively (README, "Networking").
     */
    pinGlobalNetworking?: boolean;
    /** Keep React Native's 10 MiB disk HTTP cache for its `fetch` / XHR (default false: no disk cache). */
    keepReactNativeHttpCache?: boolean;
    /** Keep React Native's persistent cookie jar for its `fetch` / XHR (default false: no cookies). */
    keepReactNativeCookies?: boolean;
  };
  /** iOS-only settings (ignored on Android). */
  ios?: {
    /** `resolve(host:to:)`: connect to `address` while pinning and verifying `host`. */
    resolve?: Record<string, string>;
    expectedBundleIds?: string[];
    expectedTeamIds?: string[];
    /** `userAuthStrength(_:)`; `BIOMETRIC_CURRENT_SET` = `userAuthBiometricOnly()`. */
    userAuthStrength?: 'DEVICE_OWNER' | 'BIOMETRIC_CURRENT_SET';
    /** The largest answer React Native's own https request may get (bytes, default 50 MiB, at most 256 MiB). */
    reactNativeMaxResponseBytes?: number;
  };
};

// ── Results ─────────────────────────────────────────────────────────────────

/** A native exception: its class name (`SSLPinningException`, …) and message. */
export type NativeException = { name: string; message: string | null };

/**
 * `nativeSecurityApplied`: the trust anchors came from the app's native
 * security file (README "Native security file"); false when JS supplied them.
 */
export type InitResult =
  | { type: 'ready'; version: number; nativeSecurityApplied: boolean }
  | { type: 'failed'; reason: string; exception: NativeException | null; nativeSecurityApplied: boolean };

export type UpdateResult =
  | { type: 'updated'; newVersion: number }
  | { type: 'alreadyCurrent' }
  | { type: 'failed'; reason: string; exception: NativeException | null };

export type KeySecurityLevel =
  | 'STRONGBOX'
  | 'TRUSTED_ENVIRONMENT'
  | 'SOFTWARE'
  | 'UNKNOWN'
  | 'SECURE_ENCLAVE';

export type EnrollmentRefusal =
  | 'INVALID_TOKEN'
  | 'TOKEN_REQUIRED'
  | 'DEVICE_ALREADY_ENROLLED'
  | 'REVOKED'
  | 'REJECTED'
  | 'LIMIT_REACHED'
  | 'EXPIRED'
  | 'ATTESTATION_FAILED'
  | 'CSR_REQUIRED'
  | 'OTHER';

export type ClientCertEnrollmentResult =
  | { type: 'enrolled'; alreadyEnrolled: boolean; keySecurityLevel: KeySecurityLevel | null }
  | {
      type: 'refused';
      reason: EnrollmentRefusal;
      httpStatus: number;
      serverError: string | null;
      message: string | null;
    }
  | {
      type: 'pending';
      requestId: string;
      clientId: string | null;
      message: string | null;
      retryAfterSeconds: number | null;
      verificationCode: string | null;
    }
  | { type: 'failed'; message: string; cause: NativeException | null };

/**
 * `VaultFileResult`. `updated` carries no content: read it with `loadFile(key)`
 * (or `unlockFile` for files behind the screen lock).
 */
export type VaultFileResult =
  | { type: 'updated'; key: string; version: number }
  | { type: 'alreadyCurrent'; key: string; version: number }
  | { type: 'failed'; key: string; reason: string; code: string; exception: NativeException | null };

export type VaultFileStatus =
  | 'AVAILABLE'
  | 'LOCKED'
  | 'NOT_STORED'
  | 'STALE'
  | 'NEEDS_FETCH'
  | 'INTEGRITY_FAILED'
  | 'STORAGE_UNAVAILABLE';

export type ContentEncoding = 'utf8' | 'base64';

export type VaultFileUnlockPrompt = {
  title: string;
  subtitle?: string;
  description?: string;
  negativeButtonText?: string;
};

export type VaultFileUnlockResult =
  | { type: 'unlocked'; key: string; version: number; content: string; encoding: ContentEncoding }
  | { type: 'notFound'; key: string }
  | { type: 'cancelled'; key: string }
  | { type: 'invalidated'; key: string }
  | { type: 'stale'; key: string }
  | { type: 'failed'; key: string; reason: string; exception: NativeException | null };

export type AttestationResult = 'PASS' | 'REJECT' | 'FAILED' | 'NOT_ATTESTED' | 'UNSUPPORTED';

export type AttestationStatus = {
  configApiId: string;
  result: AttestationResult;
  arc: string | null;
  rejectionReasons: string[];
  warnings: string[];
  tokenExpiresAt: number | null;
  lastAttestedAt: number | null;
  nextAttestAt: number | null;
  clockSkewMs: number | null;
  lastError: string | null;
  policyVersion: number | null;
};

/** `PinVault-Token` for your own HTTP client. The value is a bearer credential: never log it. */
export type AttestationTokenResult =
  | { type: 'token'; value: string; expiresAt: number }
  | { type: 'rejected'; status: AttestationStatus }
  | { type: 'failed'; message: string }
  | { type: 'unsupported' };

export type SigningStatus = {
  configApiId: string;
  trustedKeyIds: string[];
  requiredSignatures: number;
  keySetVersion: number;
  recoveryKeyIds: string[];
  lastConfigSignedBy: string[];
};

// ── Events ──────────────────────────────────────────────────────────────────

/** `PinVaultConnectionEvent`. Never carries a token, a password or file content. */
export type PinVaultConnectionEvent =
  | {
      type: 'connection';
      hostname: string;
      success: boolean;
      pinVersion: number;
      deviceManufacturer: string;
      deviceModel: string;
      actualPin: string;
      expectedPins: string[];
    }
  | {
      type: 'configUpdate';
      status: 'UPDATED' | 'UNCHANGED' | 'FAILED';
      newVersion: number;
      deviceManufacturer: string;
      deviceModel: string;
      failureReason: string | null;
    }
  | {
      type: 'clientCertRenewal';
      status: 'RENEWED' | 'NOT_NEEDED' | 'REENROLL_REQUIRED' | 'FAILED';
      notAfterEpochMs: number;
      via: string | null;
      configApiId: string;
      deviceManufacturer: string;
      deviceModel: string;
      failureReason: string | null;
    }
  | {
      type: 'attestation';
      configApiId: string;
      status: 'PASS' | 'REJECT' | 'FAILED';
      arc: string | null;
      rejectionReasons: string[];
      warnings: string[];
      tokenExpiresAt: number | null;
      deviceManufacturer: string;
      deviceModel: string;
      failureReason: string | null;
    };

// ── Pinned HTTP ─────────────────────────────────────────────────────────────

export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

/**
 * `HttpConnectionSettings` (seconds). With settings the request uses
 * `getClient(settings)` / `session(settings:)`: pinning without pin-mismatch recovery.
 */
export type HttpConnectionSettings = {
  connectTimeout?: number;
  readTimeout?: number;
  writeTimeout?: number;
  callTimeout?: number;
};

export type PinVaultRequestInit = {
  method?: HttpMethod;
  headers?: Record<string, string>;
  /** Request body: text, or Base64 with `bodyEncoding: 'base64'`. At most 10 MiB. */
  body?: string;
  bodyEncoding?: ContentEncoding;
  /** How the response body comes back (default `utf8`). */
  responseEncoding?: ContentEncoding;
  /** Whole-call timeout in ms (default: the client's). */
  timeoutMs?: number;
  /** Larger responses are refused (default 10 MiB, at most 50 MiB). */
  maxResponseBytes?: number;
  settings?: HttpConnectionSettings;
};

export type PinVaultResponse = {
  status: number;
  url: string;
  /** Lower-case names; repeated headers joined with `, `. */
  headers: Record<string, string>;
  body: string;
  bodyEncoding: ContentEncoding;
  ok: boolean;
};
