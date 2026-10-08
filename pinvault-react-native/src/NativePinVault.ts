// TurboModule codegen spec (New Architecture only).
//
// The native side is a thin bridge over the PinVault libraries
// (Android: io.github.umutcansu:pinvault, iOS: the PinVault Swift package).
// Every structured input crosses as a JSON string and is parsed STRICTLY on the
// native side (unknown keys and wrong types are refused, sizes are bounded);
// results come back as plain objects that keep the native names. Use the typed
// wrappers in `index.ts`, not this module directly.
import { TurboModuleRegistry, type TurboModule, type CodegenTypes } from 'react-native';

export type GuardRequest = {
  requestId: string;
  operation: string;
};

export interface Spec extends TurboModule {
  // ── Start / config ────────────────────────────────────────────────────────
  start(configJson: string): Promise<CodegenTypes.UnsafeObject>;
  updateNow(): Promise<CodegenTypes.UnsafeObject>;
  currentVersion(): Promise<number>;
  hostPinVersions(): Promise<CodegenTypes.UnsafeObject>;
  pinsForHost(hostname: string): Promise<CodegenTypes.UnsafeObject>;
  signingStatus(configApiId: string | null): Promise<CodegenTypes.UnsafeObject>;
  isForceUpdate(): Promise<boolean>;
  reset(): Promise<void>;
  schedulePeriodicUpdates(intervalHours: number | null): Promise<boolean>;
  cancelPeriodicUpdates(): Promise<void>;
  enableDebugLogging(): Promise<boolean>;

  // ── Pinned HTTP ───────────────────────────────────────────────────────────
  fetch(requestJson: string): Promise<CodegenTypes.UnsafeObject>;

  // ── Enrollment ────────────────────────────────────────────────────────────
  deviceId(): Promise<string | null>;
  enrollForResult(token: string, label: string | null): Promise<CodegenTypes.UnsafeObject>;
  autoEnrollForResult(): Promise<CodegenTypes.UnsafeObject>;
  checkPendingEnrollment(): Promise<CodegenTypes.UnsafeObject>;
  isEnrolled(label: string | null): Promise<boolean>;
  isEnrollmentPending(label: string | null): Promise<boolean>;
  enrollmentVerificationCode(label: string | null): Promise<string | null>;
  enrolledClientCN(label: string | null): Promise<string | null>;
  enrolledClientNotAfter(label: string | null): Promise<number | null>;
  unenroll(label: string | null, wipeVaultFiles: boolean): Promise<void>;
  identityKeySecurityLevel(label: string | null): Promise<string | null>;

  // ── Vault files ───────────────────────────────────────────────────────────
  setVaultToken(key: string, token: string | null): Promise<void>;
  clearVaultTokens(): Promise<number>;
  fetchFile(key: string, token: string | null): Promise<CodegenTypes.UnsafeObject>;
  loadFile(key: string, encoding: string): Promise<string | null>;
  fileStatus(key: string): Promise<string>;
  unlockFile(key: string, promptJson: string): Promise<CodegenTypes.UnsafeObject>;
  isFileLocked(key: string): Promise<boolean>;
  hasFile(key: string): Promise<boolean>;
  fileVersion(key: string): Promise<number>;
  clearFile(key: string): Promise<void>;
  syncAllFiles(): Promise<CodegenTypes.UnsafeObject>;

  // ── Attestation ───────────────────────────────────────────────────────────
  attestNow(configApiId: string | null): Promise<CodegenTypes.UnsafeObject>;
  fetchAttestationToken(host: string | null): Promise<CodegenTypes.UnsafeObject>;
  attestationStatus(configApiId: string | null): Promise<CodegenTypes.UnsafeObject>;

  // ── environmentGuard answers (JS → native) ────────────────────────────────
  answerGuard(requestId: string, allowed: boolean): void;

  // ── Events ────────────────────────────────────────────────────────────────
  readonly onConnectionEvent: CodegenTypes.EventEmitter<CodegenTypes.UnsafeObject>;
  readonly onGuardRequest: CodegenTypes.EventEmitter<GuardRequest>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('RNPinVault');
