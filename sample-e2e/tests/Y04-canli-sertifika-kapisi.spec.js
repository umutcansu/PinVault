// Y04 — Canlı sertifika kontrolü (PIN_LIVE_CHECK).
//
// Yanlış bir pin listesi yayımlamak (yazım hatası, yanlış host'un anahtarı, ara
// sertifikanın pin'i, gelecek yılın sertifikası…) o host'a bağlanan bütün
// cihazları config'i aldıkları anda kilitler. Kontrol açıkken sunucu, yeni ya
// da değişen her pin listesini kaydetmeden önce host'a bağlanır ve host'un ŞU
// AN sunduğu kendi sertifikasının (zincirin ilk halkası) SPKI pin'ini hesaplar;
// liste onu içermiyorsa:
//
//   • engelleme modu (`enforce`) → 422 {error, liveCheck, overridable};
//     dashboard başarısız host'u ve sunulan sertifikayı gösterip bir gerekçe
//     ister. Gerekçe boşsa kaydedilmez; gerekçeyle ?liveCheckOverride=<gerekçe>
//     kaydedilir ve live_check_overridden olarak denetime ve webhook'a düşer,
//   • uyarı modu (`warn`) → kaydedilir, yanıtta X-PinVault-Live-Check: warn,
//     dashboard uyarır, denetimde live_check_warning.
//
// "Canlı Kontrol" düğmesi aynı kontrolü kaydetmeden yapar (POST
// /api/v1/pins/live-check). Test için kurulan hedef sunuculara (mock host)
// yalnızca container içinden adlarıyla erişilebildiği için LIVE_CHECK_HOST_MAP
// ile container içi portlara yönlendirilir (mock-tls.sample=127.0.0.1:8443).
// Telefon kontrolün neyi önlediğini görür: kontrol reddettiğinde mock TLS
// bağlantısı sürer; gerekçeyle kaydedilen yanlış liste ise telefonda pin
// uyuşmazlığına düşer.
//
// Ana host üzerinde çalışır; sonunda ortam .env değerlerine ve temel pin'lere döner.
const crypto = require('crypto');
const { test, expect } = require('../lib/fixtures');
const { attachText } = require('../lib/evidence');
const { SampleApp } = require('../lib/sampleApp');
const hostApi = require('../lib/hostApi');
const hostControl = require('../lib/hostControl');
const webhookSink = require('../lib/webhookSink');
const env = require('../lib/env');

const MOCK = env.MOCK_TLS_HOST;
const HOST_MAP = 'mock-tls.sample=127.0.0.1:8443;mock-mtls.sample=127.0.0.1:8444';
const short = (pin) => `${String(pin).slice(0, 12)}…`;

async function mockPins() {
  const cfg = await hostApi.getConfig();
  return cfg.pins.find((p) => p.hostname === MOCK);
}

/** En yeni [action] kaydı ([afterId]'den sonra), yoksa null. */
async function latestAudit(action, afterId = 0) {
  const log = await hostApi.auditLog({ action, limit: 10 });
  return log.entries.find((e) => e.id > afterId && e.target.split(',').includes(MOCK)) || null;
}

test('Web+Mobil+Terminal: canlı sertifika kontrolü — sunucunun şu an sunduğu sertifikayı içermeyen pin listesi 422 ile reddediliyor (telefon etkilenmiyor), kaydetmeden kontrol aynı sonucu veriyor; gerekçe yazıp yine de kaydetme denetim kaydına ve webhook\'a düşüyor; uyarı modunda (`warn`) kaydediliyor ama uyarı veriliyor', async ({
  app,
  dashboard,
  run,
}, testInfo) => {
  test.setTimeout(20 * 60 * 1000);
  const secret = crypto.randomBytes(24).toString('hex');
  const sink = await webhookSink.start({ secret });
  const wrong = [hostApi.randomPin(), hostApi.randomPin()];
  const warnPins = [hostApi.randomPin(), hostApi.randomPin()];
  const reason = 'Planlı rotasyon: yeni sertifika bu gece devreye girecek (E2E)';
  const envOverrides = (mode) => ({
    PIN_LIVE_CHECK: mode,
    LIVE_CHECK_HOST_MAP: HOST_MAP,
    NOTIFY_WEBHOOK_URL: sink.url,
    NOTIFY_WEBHOOK_SECRET: secret,
  });
  const envDisplay = (mode) =>
    `$ ./scripts/env-override.sh set PIN_LIVE_CHECK=${mode} LIVE_CHECK_HOST_MAP='${HOST_MAP}' \\\n      NOTIFY_WEBHOOK_URL=${sink.url} NOTIFY_WEBHOOK_SECRET=<rastgele, gizli>`;
  let overridden = false;
  let v0;
  let leaf;
  let lastAuditId = 0;
  let blocked;
  let overrideEntry;

  try {
    await test.step('Sunucu: canlı kontrol engelleme modunda (PIN_LIVE_CHECK=enforce); test için kurulan hedef sunuculara (mock host) container içinden ulaşılır (LIVE_CHECK_HOST_MAP); webhook açık. Web: kimlik rozetinde "Canlı kontrol: zorunlu"', async () => {
      await hostControl.setEnv(envOverrides('enforce'));
      overridden = true;
      await dashboard.reload();
      await expect(dashboard.page.locator('#admin-chip .gov-badge-live-enforce')).toBeVisible({ timeout: 20_000 });
      const badges = await dashboard.adminBadges();
      await dashboard.openHostIn(env.VAULT_API, MOCK);
      v0 = await dashboard.version();
      await dashboard.snap(`canlı kontrol engelleme modunda: kimlik rozetinde "Canlı kontrol: zorunlu"; ${MOCK} v${v0}`);
      const me = await hostApi.adminMe();
      leaf = await hostApi.servedPin(env.MOCK_TLS_PORT, MOCK);
      lastAuditId = (await hostApi.auditLog({ limit: 1 })).entries[0].id;
      await attachText(
        testInfo,
        'env-override.sh + GET /api/v1/admin/me + mock host\'un şu an sunduğu sertifika',
        [
          envDisplay('enforce'),
          'Host hazır: http://localhost:6650 (set)',
          '',
          `GET /api/v1/admin/me → liveCheck=${me.liveCheck}, liveCheckOverridable=${me.liveCheckOverridable}, notificationsConfigured=${me.notificationsConfigured}`,
          `dashboard rozetleri: ${badges.join(', ')}`,
          '',
          `TLS bağlantısı (Mac → localhost:${env.MOCK_TLS_PORT}, SNI ${MOCK}) → sunucunun kendi sertifikasının (zincirin ilk halkası) SPKI SHA-256'sı:`,
          `${MOCK} şu an sunduğu sertifikanın pin'i: ${leaf}`,
          `kayıtlı pin'ler (v${v0}): ${run.baseline[MOCK].join(', ')}`,
        ].join('\n'),
      );
      expect(me.liveCheck).toBe('enforce');
      expect(me.liveCheckOverridable).toBe(true);
      expect(badges).toContain('Canlı kontrol: zorunlu');
      expect(run.baseline[MOCK]).toContain(leaf);
    });

    await test.step('Web: pin düzenleyicisinde "Canlı Kontrol" (kaydetmez) — iki rastgele pin → ✗ sunulan sertifika pin listesinde yok (sertifikanın pin\'i gösteriliyor); mevcut pin\'ler → ✓', async () => {
      const bad = await dashboard.liveCheckInEditor(MOCK, wrong);
      await dashboard.snapHostSummary(`"Canlı Kontrol": iki rastgele pin → ✗ sunulan sertifika (${short(leaf)}) pin listesinde yok`);
      const good = await dashboard.liveCheckInEditor(MOCK, run.baseline[MOCK]);
      await dashboard.snapHostSummary('"Canlı Kontrol": mevcut pin\'ler → ✓ sunulan sertifika pin listesinde var');
      await dashboard.cancelEditPins(MOCK);
      const stored = await mockPins();
      await attachText(
        testInfo,
        'POST /api/v1/pins/live-check (düğmenin çağırdığı, kaydetmeden kontrol)',
        [
          `pin'ler: ${wrong.map(short).join(', ')}`,
          `HTTP ${bad.status} ${JSON.stringify(bad.json)}`,
          `dashboard: ${bad.text.replace(/\n+/g, ' | ')}`,
          '',
          `pin'ler: ${run.baseline[MOCK].map(short).join(', ')}`,
          `HTTP ${good.status} ${JSON.stringify(good.json)}`,
          `dashboard: ${good.text.replace(/\n+/g, ' | ')}`,
          '',
          `kayıtlı ${MOCK}: v${stored.version} (kontrol hiçbir şey kaydetmedi)`,
        ].join('\n'),
      );
      expect(bad.status).toBe(200);
      expect(bad.json.passed).toBe(false);
      expect(bad.json.checks[0].probed).toBe('127.0.0.1:8443');
      expect(bad.json.checks[0].reachable).toBe(true);
      expect(bad.json.checks[0].livePins[0]).toBe(leaf);
      expect(bad.text).toContain(`${MOCK}: sunucunun şu an sunduğu sertifika (${leaf.slice(0, 12)}…) pin listesinde yok`);
      expect(bad.text).toContain(`sha256/${leaf}`);
      expect(good.json.passed).toBe(true);
      expect(good.text).toContain(`${MOCK}: sunucunun şu an sunduğu sertifika (${leaf.slice(0, 12)}…) pin listesinde var`);
      expect(stored.version).toBe(v0);
    });

    await test.step('Web: iki rastgele pin kaydedilmek istenir → 422; gerekçe sorusu boş bırakılır → kaydedilmedi; Mobil: mock TLS bağlantısı sürüyor', async () => {
      await dashboard.openHostIn(env.VAULT_API, MOCK);
      dashboard.answerPrompt('');
      const response = dashboard.page.waitForResponse(
        (r) => r.url().includes('/api/v1/certificate-config') && r.request().method() === 'PUT',
        { timeout: 30_000 },
      );
      const dialogsBefore = dashboard.dialogs.length;
      await dashboard.setPins(MOCK, wrong, { expectSaved: false });
      const res = await response;
      const body = JSON.parse(await res.text());
      await expect(dashboard.page.locator('.toast.error').last()).toContainText('Kaydedilmedi — canlı sertifika kontrolü');
      await dashboard.snapWithToast('422: "Kaydedilmedi — canlı sertifika kontrolü …" (gerekçe boş bırakıldı)');
      const prompt = dashboard.dialogs.slice(dialogsBefore).join('\n---\n');
      const stored = await mockPins();
      blocked = await latestAudit('live_check_blocked', lastAuditId);
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap(`canlı kontrol reddetti: mock TLS bağlantısı sürüyor (${MOCK} v${v0})`);
      await app.backToMain();
      await attachText(
        testInfo,
        'PUT /api/v1/certificate-config → 422 ve gerekçe sorusu',
        [
          `HTTP ${res.status()} ${JSON.stringify(body)}`,
          '',
          'gerekçe sorusu:',
          prompt,
          '→ yanıt: "" (boş) — yeniden gönderilmedi',
          '',
          `kayıtlı ${MOCK}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')} (değişmedi)`,
          blocked ? `denetim: #${blocked.id} ${blocked.actor} ${blocked.action}: ${blocked.summary}` : 'denetim: live_check_blocked YOK',
          '',
          `telefon: ${result.split('\n')[0]}`,
        ].join('\n'),
      );
      expect(res.status()).toBe(422);
      expect(body.overridable).toBe(true);
      expect(body.liveCheck.passed).toBe(false);
      expect(body.liveCheck.checks[0].livePins[0]).toBe(leaf);
      expect(prompt).toContain('Canlı sertifika kontrolü başarısız');
      expect(prompt).toContain(`${MOCK}: sunucunun şu an sunduğu sertifika (${leaf.slice(0, 12)}…) pin listesinde yok`);
      expect(stored.version).toBe(v0);
      expect(stored.sha256).toEqual(run.baseline[MOCK]);
      expect(blocked).toBeTruthy();
      expect(result).toContain('host bağlantısı başarılı');
    });

    await test.step('Web: tekrar "Kaydet", bu kez gerekçe yazılır → yine de kaydedildi (?liveCheckOverride=…); denetim kaydında gerekçesiyle live_check_overridden', async () => {
      // 422'den sonra düzenleyici açık ve aynı iki pin yazılı kalıyor: yalnızca "Kaydet".
      await expect(dashboard.page.locator('#pins-edit input.form-input').first()).toHaveValue(wrong[0]);
      dashboard.answerPrompt(reason);
      const overrideResponse = dashboard.page.waitForResponse(
        (r) => r.url().includes('/api/v1/certificate-config') && r.url().includes('liveCheckOverride=') && r.request().method() === 'PUT',
        { timeout: 30_000 },
      );
      await dashboard.page.locator('#pins-edit [data-action="saveInlinePins"]').click();
      const res = await overrideResponse;
      await expect(dashboard.page.locator('#pins-view')).toContainText(wrong[0], { timeout: 20_000 });
      await expect.poll(() => dashboard.version(), { timeout: 20_000 }).toBe(v0 + 1);
      await dashboard.snapHostSummary(`gerekçeyle kaydedildi: ${MOCK} v${v0 + 1} (sunulan sertifika pin listesinde YOK)`);
      overrideEntry = await latestAudit('live_check_overridden', blocked.id);
      const pinsChanged = await latestAudit('pins_changed', blocked.id);
      // Her gerekçesiz deneme ayrıca live_check_blocked olarak düşer: 3. adımdaki ve bu
      // adımdaki ilk gönderim (dashboard 422'yi alınca gerekçeyi sorup yeniden gönderir).
      const story = (await hostApi.auditLog({ limit: 20 })).entries
        .filter((e) => e.id > lastAuditId && e.target.split(',').includes(MOCK))
        .sort((a, b) => a.id - b.id);
      await dashboard.openAudit();
      await dashboard.expandAuditEntry(overrideEntry.id);
      await dashboard.snapAudit(`Denetim Kaydı: live_check_blocked (gerekçesiz denemeler) → live_check_overridden (gerekçe) → pins_changed`, {
        ids: story.map((e) => e.id),
      });
      const url = new URL(res.url());
      await attachText(
        testInfo,
        'Gerekçe yazıp yine de kaydetme',
        [
          `PUT ${url.pathname}?${decodeURIComponent(url.search.slice(1))}`,
          `HTTP ${res.status()}`,
          '',
          ...story.map((e) => `#${e.id} ${e.actor} ${e.action}: ${e.summary}`),
        ].join('\n'),
      );
      expect(res.status()).toBe(200);
      expect(url.searchParams.get('liveCheckOverride')).toBe(reason);
      expect(overrideEntry.summary).toContain(`Override "${reason}"`);
      expect(overrideEntry.summary).toContain(`${MOCK}: the certificate it serves now (${leaf.slice(0, 12)}…) is not in the new pins`);
      expect(pinsChanged.summary).toContain(`${MOCK}: pins v${v0}→v${v0 + 1}`);
      expect(story.map((e) => e.action)).toEqual(['live_check_blocked', 'live_check_blocked', 'live_check_overridden', 'pins_changed']);
    });

    await test.step('Terminal: webhook live_check_overridden bildirimini gerekçesiyle aldı (HMAC imzası doğru, auditId/auditHash denetim kaydıyla aynı)', async () => {
      const hit = await sink.waitFor((r) => r.json && r.json.event === 'live_check_overridden' && r.json.auditId === overrideEntry.id);
      await expect
        .poll(async () => ((await hostApi.notifications()).recent || []).some((d) => d.auditId === overrideEntry.id), { timeout: 20_000 })
        .toBe(true);
      await dashboard.refreshAudit();
      await dashboard.snapCard('#notif-card', `Webhook Bildirimleri: live_check_overridden teslim edildi (denetim #${overrideEntry.id})`);
      await attachText(
        testInfo,
        `Webhook alıcısı (${sink.url})`,
        [
          `X-PinVault-Event: ${hit.event}   X-PinVault-Timestamp: ${hit.timestamp}   X-PinVault-Signature: ${hit.signature.slice(0, 23)}… → HMAC("<zaman damgası>.<gövde>") ${hit.signatureValid ? 'doğru ✓' : 'YANLIŞ'}`,
          '',
          JSON.stringify({ ...hit.json, detail: '(canlı kontrol sonucu: sunulan sertifika, bağlanılan adres)' }, null, 2),
        ].join('\n'),
      );
      expect(hit.signatureValid).toBe(true);
      expect(hit.json.summary).toContain(reason);
      expect(hit.json.auditHash).toBe(overrideEntry.hash);
      expect(hit.json.target).toBe(MOCK);
    });

    await test.step('Mobil: config yenile → gerekçeyle kaydedilen pin listesi telefona geldi; mock TLS bağlantısı pin uyuşmazlığıyla reddediliyor (canlı kontrolün önlemek istediği tam buydu)', async () => {
      const status = await app.refreshConfig();
      await app.openMtls();
      const result = await app.mockTls();
      await app.snap(`yanlış pin listesi telefonda (${MOCK} v${v0 + 1}): host bağlantısı reddedildi`);
      await app.backToMain();
      await attachText(
        testInfo,
        'Telefon: yenileme ve mock TLS host',
        [`yenileme: ${status.split('\n')[0]} → ${MOCK} v${SampleApp.hostVersion(status, MOCK)}`, '', result].join('\n'),
      );
      expect(status).toContain('Yeni config uygulandı');
      expect(SampleApp.hostVersion(status, MOCK)).toBe(v0 + 1);
      expect(result).toContain('host bağlantısı reddedildi');
    });

    await test.step('Web: temel pin\'ler geri yüklenir (sunulan sertifika listede, canlı kontrol geçiyor); Mobil: mock TLS bağlantısı yeniden başarılı', async () => {
      await dashboard.openHostIn(env.VAULT_API, MOCK);
      const response = dashboard.page.waitForResponse(
        (r) => r.url().includes('/api/v1/certificate-config') && r.request().method() === 'PUT',
        { timeout: 30_000 },
      );
      await dashboard.setPins(MOCK, run.baseline[MOCK]);
      const res = await response;
      await expect.poll(() => dashboard.version(), { timeout: 20_000 }).toBe(v0 + 2);
      await dashboard.snapHostSummary(`temel pin'ler geri: ${MOCK} v${v0 + 2} (canlı kontrol geçti)`);
      const status = await app.refreshConfig();
      await app.openMtls();
      const result = await app.expectRepeated(() => app.mockTls(), 'host bağlantısı başarılı', 30_000);
      await app.snap(`temel pin'ler (${MOCK} v${v0 + 2}): host bağlantısı başarılı`);
      await app.backToMain();
      await attachText(
        testInfo,
        'Geri dönüş',
        [
          `PUT /api/v1/certificate-config → HTTP ${res.status()} (canlı kontrol geçti: liste, sunulan sertifikanın pin'ini içeriyor)`,
          `telefon: ${status.split('\n')[0]} → ${MOCK} v${SampleApp.hostVersion(status, MOCK)}; ${result.split('\n')[0]}`,
        ].join('\n'),
      );
      expect(res.status()).toBe(200);
      expect(SampleApp.hostVersion(status, MOCK)).toBe(v0 + 2);
    });

    await test.step('Sunucu: uyarı modu (`warn`, PIN_LIVE_CHECK=warn) — kontrolden geçmeyen pin listesi yine kaydediliyor; "uyarı modu" bildirimi ve X-PinVault-Live-Check: warn başlığı; denetim kaydında live_check_warning', async () => {
      await hostControl.setEnv(envOverrides('warn'));
      await dashboard.reload();
      await expect(dashboard.page.locator('#admin-chip .gov-badge-live-warn')).toBeVisible({ timeout: 20_000 });
      const before = (await hostApi.auditLog({ limit: 1 })).entries[0].id;
      await dashboard.openHostIn(env.VAULT_API, MOCK);
      const v1 = await dashboard.version();
      const response = dashboard.page.waitForResponse(
        (r) => r.url().includes('/api/v1/certificate-config') && r.request().method() === 'PUT',
        { timeout: 30_000 },
      );
      await dashboard.setPins(MOCK, warnPins);
      const res = await response;
      await expect(dashboard.page.locator('.toast.warning').last()).toContainText('uyarı modu');
      await dashboard.snapWithToast(`uyarı modu: kaydedildi + "canlı sertifika kontrolü başarısız (uyarı modu)"; ${MOCK} v${v1 + 1}`);
      const warnEntry = await latestAudit('live_check_warning', before);
      const hit = await sink.waitFor((r) => r.json && r.json.event === 'live_check_warning' && warnEntry && r.json.auditId === warnEntry.id);
      const stored = await mockPins();
      await attachText(
        testInfo,
        'Uyarı modu (PIN_LIVE_CHECK=warn)',
        [
          envDisplay('warn'),
          'Host hazır: http://localhost:6650 (set)',
          '',
          `PUT /api/v1/certificate-config → HTTP ${res.status()}, X-PinVault-Live-Check: ${res.headers()['x-pinvault-live-check']}`,
          `kayıtlı ${MOCK}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')}`,
          `denetim: #${warnEntry.id} ${warnEntry.action}: ${warnEntry.summary}`,
          `webhook: ${hit.event} (auditId ${hit.json.auditId}), HMAC ${hit.signatureValid ? 'doğru ✓' : 'YANLIŞ'}`,
        ].join('\n'),
      );
      expect(res.status()).toBe(200);
      expect(res.headers()['x-pinvault-live-check']).toBe('warn');
      expect(stored.sha256).toEqual(warnPins);
      expect(stored.version).toBe(v1 + 1);
      expect(warnEntry.summary).toContain(`${MOCK}: the certificate it serves now (${leaf.slice(0, 12)}…) is not in the new pins`);
      expect(hit.signatureValid).toBe(true);
    });
  } finally {
    if (overridden) {
      await test.step('Sunucu: ortam .env değerlerine döner (canlı kontrol kapalı), temel pin\'ler geri yüklenir, webhook alıcısı durur', async () => {
        await hostControl.resetEnv();
        await hostApi.restoreBaseline(run.baseline);
        const me = await hostApi.adminMe();
        const stored = await mockPins();
        await attachText(
          testInfo,
          'env-override.sh reset + temel pin\'ler',
          [
            '$ ./scripts/env-override.sh reset',
            'Host hazır: http://localhost:6650 (reset)',
            '',
            `GET /api/v1/admin/me → liveCheck=${me.liveCheck}, notificationsConfigured=${me.notificationsConfigured}`,
            `${MOCK}: v${stored.version}, pin'ler ${stored.sha256.map(short).join(', ')} (temel)`,
            `webhook alıcısı: ${sink.received.length} bildirim (${[...new Set(sink.received.map((r) => r.event))].join(', ')})`,
          ].join('\n'),
        );
        expect(me.liveCheck).toBe('off');
        expect(stored.sha256).toEqual(run.baseline[MOCK]);
      });
    }
    await sink.stop();
  }
});
