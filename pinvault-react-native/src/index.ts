// PinVault for React Native: a thin, typed bridge over the native PinVault
// libraries. Pinning, keys, signature checks and vault decryption all stay
// native; this file only shapes inputs and outputs and runs the app's
// environment guard. Nothing here stores anything (no AsyncStorage) and nothing
// here logs outside development builds.
import NativePinVault, { type GuardRequest } from './NativePinVault';
import type {
  AttestationStatus,
  AttestationTokenResult,
  ClientCertEnrollmentResult,
  ContentEncoding,
  EnvironmentGuard,
  GuardedOperation,
  InitResult,
  KeySecurityLevel,
  PinVaultConfig,
  PinVaultConnectionEvent,
  PinVaultRequestInit,
  PinVaultResponse,
  SigningStatus,
  UpdateResult,
  VaultFileResult,
  VaultFileStatus,
  VaultFileUnlockPrompt,
  VaultFileUnlockResult,
} from './types';

export * from './types';

/** Error codes of rejected promises. */
export type PinVaultErrorCode =
  /** The config (or a request) was refused by the strict native parser or a builder rule. */
  | 'E_INVALID_CONFIG'
  | 'E_INVALID_ARGUMENT'
  /** An operation that needs `start()` first. */
  | 'E_NOT_STARTED'
  /** The pinned request failed: pin mismatch, TLS, network, timeout, size limit. */
  | 'E_FETCH'
  | 'E_NO_ACTIVITY'
  | 'E_NATIVE';

/** A rejected PinVault call. `exception` is the native exception (class name + message). */
export class PinVaultError extends Error {
  readonly code: PinVaultErrorCode;
  readonly exception: { name: string; message: string | null } | null;

  constructor(code: PinVaultErrorCode, message: string, exception: PinVaultError['exception'] = null) {
    super(message);
    this.name = 'PinVaultError';
    this.code = code;
    this.exception = exception;
  }
}

const KNOWN_CODES: ReadonlySet<string> = new Set([
  'E_INVALID_CONFIG',
  'E_INVALID_ARGUMENT',
  'E_NOT_STARTED',
  'E_FETCH',
  'E_NO_ACTIVITY',
  'E_NATIVE',
]);

/** Native rejections → PinVaultError (keeps the native code, message and exception). */
function toPinVaultError(error: unknown): PinVaultError {
  if (error instanceof PinVaultError) return error;
  const e = (error ?? {}) as { code?: unknown; message?: unknown; userInfo?: unknown };
  const code = typeof e.code === 'string' && KNOWN_CODES.has(e.code) ? (e.code as PinVaultErrorCode) : 'E_NATIVE';
  const message = typeof e.message === 'string' ? e.message : 'PinVault native call failed';
  const info = (e.userInfo ?? null) as { exceptionName?: unknown; exceptionMessage?: unknown } | null;
  const exception =
    info && typeof info.exceptionName === 'string'
      ? {
          name: info.exceptionName,
          message: typeof info.exceptionMessage === 'string' ? info.exceptionMessage : null,
        }
      : null;
  return new PinVaultError(code, message, exception);
}

async function call<T>(promise: Promise<unknown>): Promise<T> {
  try {
    return (await promise) as T;
  } catch (error) {
    throw toPinVaultError(error);
  }
}

// ── Strict JSON ─────────────────────────────────────────────────────────────
// JSON.stringify silently drops functions and turns NaN into null; the native
// parser could then not refuse them. Anything that is not plain data is refused here.

function assertPlainData(value: unknown, path: string, code: PinVaultErrorCode): void {
  if (value === null) return;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return;
    case 'number':
      if (!Number.isFinite(value)) throw new PinVaultError(code, `${path}: not a finite number`);
      return;
    case 'object': {
      if (Array.isArray(value)) {
        value.forEach((item, i) => {
          if (item === undefined) throw new PinVaultError(code, `${path}[${i}]: undefined in a list`);
          assertPlainData(item, `${path}[${i}]`, code);
        });
        return;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new PinVaultError(code, `${path}: must be a plain object`);
      }
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (v === undefined) continue; // an optional field left out
        assertPlainData(v, `${path}.${k}`, code);
      }
      return;
    }
    default:
      throw new PinVaultError(code, `${path}: ${typeof value} is not allowed`);
  }
}

function strictJson(value: unknown, path: string, code: PinVaultErrorCode): string {
  assertPlainData(value, path, code);
  return JSON.stringify(value);
}

// ── Environment guard ───────────────────────────────────────────────────────

export const DEFAULT_GUARD_TIMEOUT_MS = 5000;

let guardSubscription: { remove(): void } | null = null;

/**
 * Runs the app's guard with a timeout. Anything but a `true` within the time —
 * `false`, another value, a thrown error, a rejected promise, no answer — is a refusal.
 */
export async function evaluateGuard(
  guard: EnvironmentGuard,
  operation: GuardedOperation,
  timeoutMs: number,
): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const verdict = await Promise.race<unknown>([
      Promise.resolve().then(() => guard(operation)),
      new Promise<boolean>((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      }),
    ]);
    return verdict === true;
  } catch (error) {
    if (__DEV__) console.warn(`PinVault: environmentGuard threw for ${operation}; refused`, error);
    return false;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

const GUARDED_OPERATIONS: ReadonlySet<string> = new Set(['INIT', 'ENROLL', 'FETCH_FILE', 'UNLOCK_FILE']);

function installGuard(guard: EnvironmentGuard | undefined, timeoutMs: number): void {
  guardSubscription?.remove();
  guardSubscription = null;
  if (!guard) return;
  // The JS answer must arrive before the native deadline; leave it a little room.
  const jsTimeout = Math.max(50, timeoutMs - 100);
  guardSubscription = NativePinVault.onGuardRequest((request: GuardRequest) => {
    const operation = request.operation;
    if (!GUARDED_OPERATIONS.has(operation)) {
      NativePinVault.answerGuard(request.requestId, false);
      return;
    }
    void evaluateGuard(guard, operation as GuardedOperation, jsTimeout).then((allowed) =>
      NativePinVault.answerGuard(request.requestId, allowed),
    );
  });
}

// ── Start / config ──────────────────────────────────────────────────────────

/**
 * Starts PinVault (`PinVault.init(context, config)` / `PinVault.shared.start(config:)`).
 * Fail closed: until it returns `{ type: 'ready' }`, every pinned request is refused.
 * An invalid config rejects with `E_INVALID_CONFIG` (unknown keys and wrong types included).
 */
export async function start(config: PinVaultConfig): Promise<InitResult> {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new PinVaultError('E_INVALID_CONFIG', 'config: must be an object');
  }
  const { environmentGuard, environmentGuardTimeoutMs, ...rest } = config;
  if (environmentGuard !== undefined && typeof environmentGuard !== 'function') {
    throw new PinVaultError('E_INVALID_CONFIG', 'config.environmentGuard: must be a function');
  }
  const timeoutMs = environmentGuardTimeoutMs ?? DEFAULT_GUARD_TIMEOUT_MS;
  if (
    typeof timeoutMs !== 'number' ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs < 100 ||
    timeoutMs > 30000
  ) {
    throw new PinVaultError('E_INVALID_CONFIG', 'config.environmentGuardTimeoutMs: an integer between 100 and 30000');
  }
  const nativeConfig: Record<string, unknown> = { ...rest };
  if (environmentGuard) nativeConfig.environmentGuard = { timeoutMs };
  const json = strictJson(nativeConfig, 'config', 'E_INVALID_CONFIG');
  installGuard(environmentGuard, timeoutMs);
  return call<InitResult>(NativePinVault.start(json));
}

export const updateNow = (): Promise<UpdateResult> => call(NativePinVault.updateNow());
export const currentVersion = (): Promise<number> => call(NativePinVault.currentVersion());
export const hostPinVersions = (): Promise<Record<string, number>> => call(NativePinVault.hostPinVersions());

/** Active pins of a host (Base64, no `sha256/`), or null when the host has no entry. */
export async function pinsForHost(hostname: string): Promise<string[] | null> {
  const result = await call<{ pins: string[] | null }>(NativePinVault.pinsForHost(hostname));
  return result.pins;
}

export const signingStatus = (configApiId?: string): Promise<SigningStatus | null> =>
  call(NativePinVault.signingStatus(configApiId ?? null));
export const isForceUpdate = (): Promise<boolean> => call(NativePinVault.isForceUpdate());
/** Drops the active pins; the next `start` begins again (watermarks kept). */
export const reset = (): Promise<void> => call(NativePinVault.reset());
export const schedulePeriodicUpdates = (intervalHours?: number): Promise<boolean> =>
  call(NativePinVault.schedulePeriodicUpdates(intervalHours ?? null));
export const cancelPeriodicUpdates = (): Promise<void> => call(NativePinVault.cancelPeriodicUpdates());
/** Library debug logs. Ignored (returns false) in release builds of the app. */
export const enableDebugLogging = (): Promise<boolean> => call(NativePinVault.enableDebugLogging());

// ── Pinned HTTP ─────────────────────────────────────────────────────────────

/**
 * A request through the native pinned client (`PinVault.getClient()` /
 * `PinVault.shared.session()`): pin check, attestation token, pin-mismatch
 * recovery. HTTPS only; it never falls back to an unpinned path. A pin
 * mismatch rejects with `E_FETCH` (`exception.name` e.g. `SSLPeerUnverifiedException`).
 */
export async function fetch(url: string, init: PinVaultRequestInit = {}): Promise<PinVaultResponse> {
  if (typeof url !== 'string') throw new PinVaultError('E_INVALID_ARGUMENT', 'url: must be a string');
  if (init === null || typeof init !== 'object' || Array.isArray(init)) {
    throw new PinVaultError('E_INVALID_ARGUMENT', 'init: must be an object');
  }
  const json = strictJson({ ...init, url }, 'request', 'E_INVALID_ARGUMENT');
  const response = await call<Omit<PinVaultResponse, 'ok'>>(NativePinVault.fetch(json));
  return { ...response, ok: response.status >= 200 && response.status < 300 };
}

// ── Enrollment ──────────────────────────────────────────────────────────────

/** The device id PinVault sends (`ANDROID_ID` / `identifierForVendor`, lowercased). */
export const deviceId = (): Promise<string | null> => call(NativePinVault.deviceId());

/** Token or enrollment-code enrollment. The token goes to native memory for this call only. */
export const enrollForResult = (token: string, label?: string): Promise<ClientCertEnrollmentResult> =>
  call(NativePinVault.enrollForResult(token, label ?? null));
export const autoEnrollForResult = (): Promise<ClientCertEnrollmentResult> =>
  call(NativePinVault.autoEnrollForResult());
export const checkPendingEnrollment = (): Promise<ClientCertEnrollmentResult> =>
  call(NativePinVault.checkPendingEnrollment());
export const isEnrolled = (label?: string): Promise<boolean> => call(NativePinVault.isEnrolled(label ?? null));
export const isEnrollmentPending = (label?: string): Promise<boolean> =>
  call(NativePinVault.isEnrollmentPending(label ?? null));
export const enrollmentVerificationCode = (label?: string): Promise<string | null> =>
  call(NativePinVault.enrollmentVerificationCode(label ?? null));
export const enrolledClientCN = (label?: string): Promise<string | null> =>
  call(NativePinVault.enrolledClientCN(label ?? null));
export const enrolledClientNotAfter = (label?: string): Promise<number | null> =>
  call(NativePinVault.enrolledClientNotAfter(label ?? null));
export const unenroll = (label?: string, options: { wipeVaultFiles?: boolean } = {}): Promise<void> =>
  call(NativePinVault.unenroll(label ?? null, options.wipeVaultFiles === true));
export const identityKeySecurityLevel = (label?: string): Promise<KeySecurityLevel | null> =>
  call(NativePinVault.identityKeySecurityLevel(label ?? null));

// ── Vault files ─────────────────────────────────────────────────────────────

/**
 * The access token of a `TOKEN` / `TOKEN_MTLS` file. Kept in native memory only
 * (never written to disk, gone when the process ends); `null` forgets it.
 */
export const setVaultToken = (key: string, token: string | null): Promise<void> =>
  call(NativePinVault.setVaultToken(key, token));
/** Forgets every vault token (e.g. on a `REENROLL_REQUIRED` event). Returns how many there were. */
export const clearVaultTokens = (): Promise<number> => call(NativePinVault.clearVaultTokens());

/** Downloads and stores a file. `token` = `setVaultToken(key, token)` before the download. */
export const fetchFile = (key: string, options: { token?: string } = {}): Promise<VaultFileResult> =>
  call(NativePinVault.fetchFile(key, options.token ?? null));

/**
 * The stored copy (checked on every read), or null — `fileStatus` says why.
 * Files behind the screen lock never open here: use `unlockFile`.
 * Keep the content in memory only as long as you need it, and never log it.
 */
export const loadFile = (key: string, encoding: ContentEncoding = 'utf8'): Promise<string | null> =>
  call(NativePinVault.loadFile(key, encoding));
export const fileStatus = (key: string): Promise<VaultFileStatus> => call(NativePinVault.fileStatus(key));

/** Shows the native screen-lock prompt (BiometricPrompt / LAContext), then returns the content. */
export const unlockFile = (
  key: string,
  prompt: VaultFileUnlockPrompt,
  encoding: ContentEncoding = 'utf8',
): Promise<VaultFileUnlockResult> =>
  call(NativePinVault.unlockFile(key, strictJson({ ...prompt, encoding }, 'prompt', 'E_INVALID_ARGUMENT')));

export const isFileLocked = (key: string): Promise<boolean> => call(NativePinVault.isFileLocked(key));
export const hasFile = (key: string): Promise<boolean> => call(NativePinVault.hasFile(key));
export const fileVersion = (key: string): Promise<number> => call(NativePinVault.fileVersion(key));
export const clearFile = (key: string): Promise<void> => call(NativePinVault.clearFile(key));
export const syncAllFiles = (): Promise<Record<string, VaultFileResult>> => call(NativePinVault.syncAllFiles());

// ── Attestation ─────────────────────────────────────────────────────────────

export const attestNow = (configApiId?: string): Promise<AttestationStatus> =>
  call(NativePinVault.attestNow(configApiId ?? null));
/** `PinVault-Token` for your own client (a bearer credential: never log or store it). */
export const fetchAttestationToken = (host?: string): Promise<AttestationTokenResult> =>
  call(NativePinVault.fetchAttestationToken(host ?? null));
export const attestationStatus = (configApiId?: string): Promise<AttestationStatus> =>
  call(NativePinVault.attestationStatus(configApiId ?? null));
export const attestationHeaderName = (): string => 'PinVault-Token';

// ── Events ──────────────────────────────────────────────────────────────────

/** Connection telemetry (`onConnectionEvent`). Returns a subscription; call `remove()` when done. */
export function addConnectionListener(listener: (event: PinVaultConnectionEvent) => void): { remove(): void } {
  return NativePinVault.onConnectionEvent((event) => listener(event as PinVaultConnectionEvent));
}

/** Everything above as one object, like `PinVault.shared` / the Kotlin `PinVault` object. */
const PinVault = {
  start,
  updateNow,
  currentVersion,
  hostPinVersions,
  pinsForHost,
  signingStatus,
  isForceUpdate,
  reset,
  schedulePeriodicUpdates,
  cancelPeriodicUpdates,
  enableDebugLogging,
  fetch,
  deviceId,
  enrollForResult,
  autoEnrollForResult,
  checkPendingEnrollment,
  isEnrolled,
  isEnrollmentPending,
  enrollmentVerificationCode,
  enrolledClientCN,
  enrolledClientNotAfter,
  unenroll,
  identityKeySecurityLevel,
  setVaultToken,
  clearVaultTokens,
  fetchFile,
  loadFile,
  fileStatus,
  unlockFile,
  isFileLocked,
  hasFile,
  fileVersion,
  clearFile,
  syncAllFiles,
  attestNow,
  fetchAttestationToken,
  attestationStatus,
  attestationHeaderName,
  addConnectionListener,
} as const;

export default PinVault;
