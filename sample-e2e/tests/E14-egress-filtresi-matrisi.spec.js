// E14 — Sunucunun dışarıya bağlandığı uçlar (SSRF) ve izin verilmeyen hedefler.
//
// "URL'den sertifika al" (host ve bootstrap için) ve canlı sertifika kontrolü
// (`/api/v1/pins/live-check`) sunucunun KENDİ ağından, yöneticinin verdiği bir
// adrese TLS el sıkışması yapar. Filtresiz bu, sunucunun erişebildiği her şey
// için "orada bir şey dinliyor mu, hangi sertifikayı sunuyor" sorusunu
// cevaplar: bulut metadata servisi, yandaki veritabanı, sunucunun kendi yönetim
// portu. EgressFilter adı bir kez çözer, adresi kontrol eder ve bağlantıyı tam o
// adrese kurar (DNS rebinding işe yaramaz; birim testi DeploymentHardeningTest):
//
//   • her zaman reddedilen: link-local (169.254/16, fe80::/10 — metadata
//     adresleri burada), 100.100.100.200, fd00:ec2::254, 0.0.0.0, multicast,
//   • FETCH_ALLOW_PRIVATE_TARGETS=true değilse reddedilen: loopback,
//     RFC 1918, LAN, carrier-grade NAT (100.64/10), IPv6 unique-local,
//   • https dışındaki şemalar.
//
// Sertifika alma yalnızca TLS el sıkışması yapar, HTTP yönlendirmesi izlemez:
// 302 ile içeriye kıvırma bu uçlarda yoktur. Örnek host LAN'daki hedefleri
// pin'lediği için FETCH_ALLOW_PRIVATE_TARGETS=true çalışır; senaryo önce bu
// haliyle her zaman yasak olanları, sonra ayarı kapatıp özel adresleri dener.
// Denenen uçlar: panelin "URL'den host ekle" düğmesi (`POST /api/v1/hosts/fetch-from-url`;
// örnek host'ta kayıtlı host olmadığı için var olan host'u yenileyen
// `fetch-cert-url` adres kontrolüne gelmeden 404 döner, aynı kodu kullanır) ve
// canlı kontrol. Hiçbir denemede yeni host eklenmemeli, pin'ler değişmemeli.
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const env = require('../lib/env');

const ALWAYS_REFUSED = [
  'https://169.254.169.254/latest/meta-data/',
  'https://[fe80::1]/',
  'https://100.100.100.200/',
  'https://[fd00:ec2::254]/',
  'https://0.0.0.0:8080/',
  'https://224.0.0.1/',
];

const PRIVATE = [
  'https://127.0.0.1:8080/',
  'https://localhost:8080/',
  'https://[::1]:8080/',
  `https://${env.LAN_IP}:6650/`,
  'https://10.0.0.1/',
  'https://172.16.0.1/',
  'https://100.64.0.1/',
  'https://[fd12:3456::1]/',
];

const NOT_HTTPS = ['http://169.254.169.254/latest/meta-data/', 'file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO'];

/** Varsayılan Config API'nin bütün host'ları ve sürümleri (yeni host eklenmemeli, hiçbiri değişmemeli). */
async function pinState() {
  return (await hostApi.getConfig()).pins.map((p) => `${p.hostname} v${p.version} ${p.sha256.join(',')}`).sort();
}

/** Bir URL'yi üç uçtan dener; her birinin durum kodu ve kısa yanıtı. */
async function tryAll(url) {
  const hostFetch = await hostApi.api(`/api/v1/hosts/fetch-from-url?configApiId=${env.VAULT_API}`, {
    method: 'POST',
    body: { url },
  });
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  const port = new URL(url).port || '443';
  const live = await hostApi.api('/api/v1/pins/live-check', {
    method: 'POST',
    body: { pins: [{ hostname: `${host}:${port}`, sha256: [hostApi.randomPin(), hostApi.randomPin()] }] },
  });
  const check = live.json && live.json.hosts ? live.json.hosts[0] : live.json && live.json.checks ? live.json.checks[0] : undefined;
  return { url, hostFetch, live, check };
}

const line = (r) =>
  [
    r.url,
    `  fetch-from-url → HTTP ${r.hostFetch.status} ${r.hostFetch.text.trim().slice(0, 120)}`,
    `  live-check     → HTTP ${r.live.status} ${r.check ? `reachable=${r.check.reachable} error=${(r.check.error || '').slice(0, 100)}` : r.live.text.trim().slice(0, 120)}`,
  ].join('\n');

/** Bağlanılmadığının kanıtı: alma 4xx, canlı kontrol hedefe ulaşmadı ve canlı pin döndürmedi. */
function expectRefused(r) {
  expect(r.hostFetch.status, `${r.url}: fetch-from-url`).toBeGreaterThanOrEqual(400);
  expect(r.hostFetch.status, `${r.url}: fetch-from-url`).toBeLessThan(500);
  if (r.live.status === 200 && r.check) {
    expect(r.check.reachable, `${r.url}: live-check`).toBe(false);
    expect(r.check.livePins || [], `${r.url}: live-check`).toEqual([]);
  } else {
    expect(r.live.status, `${r.url}: live-check`).toBeGreaterThanOrEqual(400);
  }
}

test('Terminal: sunucu metadata, link-local, loopback, LAN ve https dışı hedeflere bağlanmıyor ("URL\'den sertifika al" ve canlı kontrol); pin\'ler değişmiyor', async ({}, testInfo) => {
  test.setTimeout(15 * 60 * 1000);
  let overridden = false;
  let before;

  try {
    await test.step('Sunucu (FETCH_ALLOW_PRIVATE_TARGETS=true, örnek host): metadata ve link-local adresler yine de reddediliyor', async () => {
      before = await pinState();
      const results = [];
      for (const url of ALWAYS_REFUSED) results.push(await tryAll(url));
      await attachText(testInfo, 'Her zaman yasak hedefler (özel adreslere izin varken)', results.map(line).join('\n\n'));
      for (const r of results) {
        expectRefused(r);
        expect(r.hostFetch.text).toMatch(/target_not_allowed|not allowed|may not/i);
      }
    });

    await test.step('Sunucu: https dışındaki şemalar reddediliyor', async () => {
      const results = [];
      for (const url of NOT_HTTPS) {
        const r = await hostApi.api(`/api/v1/hosts/fetch-from-url?configApiId=${env.VAULT_API}`, {
          method: 'POST',
          body: { url },
        });
        results.push({ url, r });
      }
      await attachText(testInfo, 'https dışı şemalar', results.map(({ url, r }) => `${url}\n  → HTTP ${r.status} ${r.text.trim().slice(0, 140)}`).join('\n\n'));
      for (const { url, r } of results) expect(r.status, url).toBe(400);
    });

    await test.step('Sunucu: FETCH_ALLOW_PRIVATE_TARGETS=false → loopback, LAN, RFC 1918, CGNAT ve IPv6 ULA da reddediliyor', async () => {
      await hostControl.setEnv({ FETCH_ALLOW_PRIVATE_TARGETS: 'false' });
      overridden = true;
      const results = [];
      for (const url of [...PRIVATE, ...ALWAYS_REFUSED.slice(0, 1)]) results.push(await tryAll(url));
      await attachText(
        testInfo,
        'Özel adresler (FETCH_ALLOW_PRIVATE_TARGETS=false)',
        ['$ ./scripts/env-override.sh set FETCH_ALLOW_PRIVATE_TARGETS=false', '', ...results.map(line)].join('\n\n'),
      );
      for (const r of results) {
        expectRefused(r);
        expect(r.hostFetch.text).toMatch(/target_not_allowed|not allowed|may not/i);
      }
    });

    await test.step('Sunucu: hiçbir deneme yeni host eklemedi, hiçbir pin değişmedi', async () => {
      const after = await pinState();
      await attachText(testInfo, "Varsayılan Config API: host'lar ve pin'ler", `önce:\n${before.join("\n")}\n\nsonra:\n${after.join("\n")}`);
      expect(after).toEqual(before);
    });
  } finally {
    if (overridden) await hostControl.resetEnv();
  }
});
