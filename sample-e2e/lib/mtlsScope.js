// mTLS Config API'nin (sample-mtls) kendi pin kapsamı.
//
// Neden gerekli: uygulama MTLS_CONFIG modunda config'i mTLS Config API'den
// çeker ve o bloğun config'i "birincil" olur — `PinVault.applyTo` ile kurulan
// pinli istemci artık bu kapsamın pin'lerini uygular. Kapsam boşsa kütüphane
// config'i reddeder ("Config must contain at least one pin entry") ve
// başlatma düşer. Ayrıca host'a özel istemci sertifikası (`upload-client-cert`)
// host kaydının o kapsamda olmasını şart koşuyor.
//
// Host ekleme yolu "Yükle" sekmesidir: pin'leri gerçek sunucu sertifikasından
// hesaplattığı için kapsama elle pin girmek gerekmiyor. ("Manuel" form ve pin
// düzenleme akışı da artık seçili kapsama yazıyor — eskiden her zaman
// `default-tls`e yazıyorlardı.)
const path = require('path');
const env = require('./env');
const hostApi = require('./hostApi');

/** Container'daki keystore dosyaları; pin'ler bunlardan hesaplanır. */
const KEYSTORES = {
  [env.LAN_IP]: 'demo-server.jks',
  [env.MOCK_MTLS_HOST]: 'mock-mtls_sample.jks',
  [env.MOCK_TLS_HOST]: 'mock-tls_sample.jks',
};

/** Keystore'ların dışa aktarıldığı geçici dizin (koşuya özel, git dışı). */
const CERT_DIR = path.join(env.LOCAL_DIR, 'keystores');

function keystoreFor(hostname) {
  const name = KEYSTORES[hostname];
  if (!name) throw new Error(`Bu host için container'da keystore adı bilinmiyor: ${hostname}`);
  return hostApi.exportKeystore(name, path.join(CERT_DIR, name));
}

/**
 * Verilen host'ları mTLS Config API kapsamına ekler (zaten varsa dokunmaz) ve
 * her adımın sunucu yanıtını döndürür. Dashboard üzerinden yapılır: her ekleme
 * arayüzdeki "+ → Yükle" formundan geçer.
 */
async function ensureHosts(dashboard, hostnames, { apiId = env.MTLS_API } = {}) {
  const lines = [];
  for (const hostname of hostnames) {
    const before = await hostApi.scopedConfig(apiId);
    if ((before.pins || []).some((p) => p.hostname === hostname)) {
      lines.push(`${hostname}: kapsamda zaten var`);
      continue;
    }
    const file = keystoreFor(hostname);
    // Dışa aktarılan keystore host'un kendi parolasıyla (KEYSTORE_PASSWORD) şifreli.
    lines.push(`${hostname}: ${await dashboard.addHostUpload(apiId, hostname, file, env.KEYSTORE_PASSWORD)}`);
  }
  const after = await hostApi.scopedConfig(apiId);
  lines.push('', `${apiId} kapsamı: ${(after.pins || []).map((p) => `${p.hostname} v${p.version}`).join(', ')}`);
  return lines.join('\n');
}

/** Kapsamı temel duruma (boş) döndürür. */
async function reset({ apiId = env.MTLS_API } = {}) {
  return hostApi.clearScopedHosts(apiId);
}

/**
 * Çalışan mTLS dinleyicilerinin truststore'unu tazeler: mTLS Config API
 * durdurulup başlatılır, mock mTLS hedefi yeniden başlatılır.
 *
 * Sunucu bunu artık kendisi yapıyor: `/client-certs/generate`, `/upload`,
 * `/enroll` ve iptal uçlarının hepsi dinleyicileri güncel truststore ile
 * yeniden başlatıyor. Yardımcı, operatörün elle yapabildiği aynı işi
 * senaryolardan tetiklemek için duruyor (ve sunucu yolu bozulursa senaryonun
 * neden düştüğünü ayırmayı kolaylaştırıyor).
 */
async function refreshTrust(dashboard, { withMock = true } = {}) {
  await dashboard.setConfigApiRunning(env.MTLS_API, false);
  await dashboard.setConfigApiRunning(env.MTLS_API, true);
  const lines = [`${env.MTLS_API} durduruldu ve yeniden başlatıldı (truststore tazelendi)`];
  if (withMock) {
    // Mock mTLS hedefinin host kaydı varsayılan kapsamda; container içi portu 8444.
    const toast = await dashboard.restartMock(env.VAULT_API, env.MOCK_MTLS_HOST, { port: 8444, mtls: true });
    lines.push(`${env.MOCK_MTLS_HOST} mock sunucusu yeniden başlatıldı — ${toast}`);
  }
  return lines.join('\n');
}

module.exports = { CERT_DIR, KEYSTORES, keystoreFor, ensureHosts, reset, refreshTrust };
