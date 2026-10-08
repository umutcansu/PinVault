// PinVault kurulumu: sample-host'un değerlerinden (src/generated/hostConfig.ts)
// config'i kurar ve başlatır. Android/iOS örnekleriyle aynı bloklar ve dosyalar,
// sadeleştirilmiş: TLS Config API + (kayıtlıysa) mTLS Config API.
import { Platform } from 'react-native';
import PinVault, {
  type ConfigApiBlock,
  type GuardedOperation,
  type HostPin,
  type InitResult,
  type PinVaultConfig,
  type VaultFileConfig,
} from '@umutcansu/react-native-pinvault';
import { HOST } from './generated/hostConfig';

export const CONFIG_API_ID = 'sample-host';
export const MTLS_API_ID = 'sample-mtls';

export const CONFIG_BASE_URL = `https://${HOST.ip}:${HOST.httpsPort}/`;
export const MTLS_BASE_URL = `https://${HOST.ip}:${HOST.mtlsPort}/`;
export const RECOVERY_BASE_URL = HOST.recoveryPort ? `https://${HOST.ip}:${HOST.recoveryPort}/` : '';
export const TARGET_URL = `https://${HOST.targetHost}/`;
/** mTLS Config API'nin sağlık ucu: istemci sertifikası olmadan TLS el sıkışması bitmez. */
export const MTLS_TEST_URL = `${MTLS_BASE_URL}health`;

// ── Vault dosyaları (sample-host/scripts/seed-vault.sh yükler) ────────────────
/** Herkese açık, gizli olmayan demo dosyası (TLS bloğu, public). */
export const VAULT_PUBLIC = 'sample-flags';
/** Gizli dosya: istemci sertifikası + cihaza özel token; sunucu cihaz anahtarıyla şifreler (end_to_end). */
export const VAULT_TOKEN = 'sample-e2e';
/** Gizli dosya: sertifika + token + ekran kilidi (user_auth); içerik yalnızca kilit açılınca. */
export const VAULT_LOCKED = 'sample-secret';
/** Gizli dosyaların sunucuya danışmadan açılabileceği en uzun süre (gün). */
const SECRET_MAX_OFFLINE_DAYS = 7;

/** Test kontrolü (yalnız debug): ortam koruması her işlemi reddetsin mi. */
export const guardSettings = { refuseAll: false };

/**
 * Uygulamanın ortam kararı. Kütüphane INIT, ENROLL, FETCH_FILE ve UNLOCK_FILE
 * öncesinde sorar; yanıt gelmezse ya da hata olursa işlem reddedilir. JS
 * kancalanabilir: asıl karar sunucunun atestasyonudur (host.attestation).
 */
async function environmentGuard(_operation: GuardedOperation): Promise<boolean> {
  return !guardSettings.refuseAll;
}

function hostPin(): HostPin {
  return { hostname: HOST.ip, sha256: [...HOST.bootstrapPins] };
}

function signing(): Partial<ConfigApiBlock> {
  const keys = HOST.signingPublicKeys.length > 0 ? [...HOST.signingPublicKeys] : [HOST.signingPublicKey];
  return {
    signaturePublicKeys: keys,
    ...(HOST.requiredSignatures > 1 ? { requiredSignatures: HOST.requiredSignatures } : {}),
    ...(HOST.recoveryPublicKeys.length > 0 ? { recoveryPublicKeys: [...HOST.recoveryPublicKeys] } : {}),
    ...(HOST.clientCaPins.length > 0 ? { clientCaPins: [...HOST.clientCaPins] } : {}),
  };
}

function tlsBlock(): ConfigApiBlock {
  return {
    id: CONFIG_API_ID,
    url: CONFIG_BASE_URL,
    bootstrapPins: [hostPin()],
    ...signing(),
    ...(HOST.tlsScope ? { serverScope: HOST.tlsScope } : {}),
    // Kütüphane cihaz sertifikasını yalnızca bloğun kendi adreslerine ve burada
    // açıkça yazılan adreslere verir: mTLS ekranındaki istek mTLS Config API'ye gider.
    clientCertHosts: [MTLS_BASE_URL],
    attestation: HOST.attestation,
  };
}

function mtlsBlock(): ConfigApiBlock {
  const pins: HostPin[] = [hostPin()];
  // Süresi dolmuş sertifika mTLS portuna giremez: yenileme kurtarma kapısından
  // gider. Kapının sertifikası sunucu CA'sının; bu pin'ler yalnızca o port için.
  const door = RECOVERY_BASE_URL && HOST.recoveryPins.length > 0;
  if (door) pins.push({ hostname: `${HOST.ip}:${HOST.recoveryPort}`, sha256: [...HOST.recoveryPins] });
  return {
    id: MTLS_API_ID,
    url: MTLS_BASE_URL,
    bootstrapPins: pins,
    ...signing(),
    ...(HOST.mtlsScope ? { serverScope: HOST.mtlsScope } : {}),
    ...(door ? { renewalUrl: RECOVERY_BASE_URL } : {}),
    attestation: HOST.attestation,
  };
}

function vaultFiles(enrolled: boolean): VaultFileConfig[] {
  const files: VaultFileConfig[] = [
    { key: VAULT_PUBLIC, configApi: CONFIG_API_ID, endpoint: `api/v1/vault/${VAULT_PUBLIC}` },
  ];
  // Gizli dosyalar yalnızca mTLS bloğunda: cihaz kayıtlı değilken tanımlanmaz.
  if (!enrolled) return files;
  const secret = {
    configApi: MTLS_API_ID,
    accessPolicy: 'TOKEN_MTLS',
    maxOfflineAge: { amount: SECRET_MAX_OFFLINE_DAYS, unit: 'DAYS' },
  } as const;
  files.push(
    { key: VAULT_TOKEN, endpoint: `api/v1/vault/${VAULT_TOKEN}`, encryption: 'END_TO_END', ...secret },
    {
      key: VAULT_LOCKED,
      endpoint: `api/v1/vault/${VAULT_LOCKED}`,
      encryption: 'USER_AUTH',
      userAuth: 'REQUIRED',
      ...secret,
    },
  );
  return files;
}

export function buildConfig(enrolled: boolean): PinVaultConfig {
  return {
    // Kayıt (token) varsayılan blok olan TLS bloğundan yapılır.
    configApis: enrolled ? [tlsBlock(), mtlsBlock()] : [tlsBlock()],
    vaultFiles: vaultFiles(enrolled),
    ...(HOST.targetRequireCaTrust ? { requireCaTrust: [HOST.targetHost] } : {}),
    deviceAlias: `RN ${Platform.OS}`,
    updateIntervalMinutes: 15,
    wipeVaultFilesOnRevocation: true,
    // Release: anahtarlar yalnızca cihazın kilidi açıkken çalışır ve güvenli donanımda
    // üretilmek zorunda. Debug'da kapalı: emülatör / simülatörde güvenli donanım yok ve
    // Android 9 emülatörünün yazılım keymaster'ı, kilit şartlı anahtarın atestasyonunda
    // çöküyor (keymaster@3.0 build_auth_list SIGSEGV; sonra keystore yeniden başlatılmalı).
    ...(HOST.release ? { requireUnlockedDevice: true, requireHardwareBackedKeys: true } : {}),
    ...(HOST.expectedSignerSha256.length > 0 ? { expectedSignerSha256: [...HOST.expectedSignerSha256] } : {}),
    environmentGuard,
  };
}

/** Kayıt durumuna göre config'i kurar ve PinVault'u (yeniden) başlatır. */
export async function startPinVault(): Promise<{ result: InitResult; enrolled: boolean }> {
  const enrolled = await PinVault.isEnrolled();
  const result = await PinVault.start(buildConfig(enrolled));
  return { result, enrolled };
}
