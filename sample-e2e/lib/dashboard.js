// sample-host web dashboard'u için sayfa nesnesi. Seçiciler arayüz
// dilinden bağımsız `data-action` özniteliklerine ve form alanı kimliklerine
// dayanır.
const { expect } = require('@playwright/test');
const { testDeviceUid } = require('./device');

/**
 * Playwright ek adındaki son noktadan sonrasını dosya uzantısı sayar
 * ("…example.com pinleri" → ".com-pinleri"). Noktaları benzer bir
 * karakterle değiştirip uzantının içerik türünden (png) gelmesini sağlar.
 */
function attachmentName(icon, title) {
  return `${icon} ${title.replace(/\./g, '․')}`;
}

class Dashboard {
  /**
   * [baseUrl] verilirse dashboard o adresten açılır (taze host örneği için;
   * varsayılan Playwright'ın baseURL'i, yani ana host).
   */
  constructor(page, testInfo, { baseUrl } = {}) {
    this.page = page;
    this.testInfo = testInfo;
    this.baseUrl = baseUrl || '/';
    /** Sayfanın açtığı alert/confirm/prompt metinleri (fixture kabul eder ve buraya yazar). */
    this.dialogs = [];
    /** prompt() diyaloglarına sırayla verilecek yanıtlar ([answerPrompt] doldurur). */
    this.promptAnswers = [];
  }

  /**
   * Sayfanın diyaloglarını kabul eder ve metinlerini [dialogs]'a yazar;
   * prompt'lara [promptAnswers] kuyruğundaki değeri verir. Fixture ve taze
   * host sayfaları aynı davranışı paylaşsın diye burada.
   */
  /**
   * Yönetici anahtarını sayfanın sessionStorage'ına, sayfanın kendi betikleri
   * çalışmadan önce yazar (her yüklemede). Dashboard anahtarı sessionStorage'da
   * tutar; localStorage'daki eski kopyayı bir kez taşıyıp siler.
   */
  static async seedApiKey(page, key) {
    await page.addInitScript((value) => {
      try {
        sessionStorage.setItem('pinvault_api_key', value);
      } catch {
        /* depolama kapalı: dashboard anahtarı sorar */
      }
    }, key);
  }

  static async attachDialogs(page, dashboard) {
    page.on('dialog', (dialog) => {
      dashboard.dialogs.push(dialog.message());
      const answer = dialog.type() === 'prompt' ? dashboard.promptAnswers.shift() : undefined;
      dialog.accept(answer);
    });
    // Dashboard'un kendi giriş penceresi (app-core.js pvInputDialog) prompt()'un
    // yerini aldı: aynı kuyruktan, aynı kuralla yanıtlanır. Metni (başlık +
    // açıklama) [dialogs]'a yazılır; kuyrukta yanıt varsa kutuya o yazılır, yoksa
    // kutudaki hazır değer kalır (prompt'un accept() davranışı) ve "Tamam" basılır.
    await page.exposeBinding('__pvE2EInputDialog', (_source, text) => {
      dashboard.dialogs.push(text);
      return dashboard.promptAnswers.length
        ? { answer: true, value: String(dashboard.promptAnswers.shift()) }
        : { answer: false, value: '' };
    });
    await page.addInitScript(() => {
      const handled = new WeakSet();
      const answer = async (overlay) => {
        if (handled.has(overlay)) return;
        handled.add(overlay);
        const text = (id) => (overlay.querySelector(id) || {}).textContent || '';
        const reply = await window.__pvE2EInputDialog(
          [text('#pv-input-dialog-title'), text('#pv-input-dialog-message')].filter(Boolean).join('\n'),
        );
        const input = overlay.querySelector('#pv-input-dialog-input');
        if (reply.answer && input) input.value = reply.value;
        const ok = overlay.querySelector('#pv-input-dialog-ok');
        if (ok) ok.click();
      };
      new MutationObserver(() => {
        const overlay = document.getElementById('pv-input-dialog');
        if (overlay) answer(overlay);
      }).observe(document, { childList: true, subtree: true });
    });
  }

  /** Sıradaki prompt() / dashboard giriş penceresinin yanıtı. */
  answerPrompt(value) {
    this.promptAnswers.push(value);
  }

  /** Son diyalog metni (onay/uyarı panelleri için). */
  lastDialog() {
    return this.dialogs[this.dialogs.length - 1] || '';
  }

  async open() {
    await this.page.goto(this.baseUrl);
    await expect(this.page.locator('#host-list .api-header').first()).toBeVisible();
  }

  /** Sayfayı yeniden yükler (container yeniden oluşturulduktan sonra: durum sunucudan yeniden okunur). */
  async reload() {
    await this.page.reload();
    await expect(this.page.locator('#host-list .api-header').first()).toBeVisible({ timeout: 30_000 });
  }

  /** Son toast mesajı (işlem sonucu); görünmezse boş. */
  async toastText(timeout = 5000) {
    const toast = this.page.locator('.toast').last();
    try {
      await expect(toast).toBeVisible({ timeout });
      return (await toast.innerText()).trim();
    } catch {
      return '';
    }
  }

  // ── Host'lar ─────────────────────────────────────────────────────────

  hostItem(host) {
    return this.page.locator(`#host-list .host-item[data-arg0="${host}"]`);
  }

  async openHost(host) {
    await this.hostItem(host).click();
    await expect(this.page.locator('.section-title-main')).toHaveText(host);
    await expect(this.page.locator('#pins-card')).toBeVisible();
  }

  /**
   * Belirli bir Config API kapsamındaki host satırı. Aynı hostname birden fazla
   * kapsamda olabildiği için ([env.MTLS_API] kapsamına da eklenen mock host'lar)
   * kapsamsız [hostItem] iki satır bulur ve Playwright strict mode ile düşer.
   */
  hostItemIn(apiId, host) {
    return this.page.locator(`#host-list .host-item[data-arg0="${host}"][data-arg1="${apiId}"]`);
  }

  /**
   * Kenar çubuğunda o Config API'nin ağacını açık bırakır.
   *
   * `toggleApiTree` seçili API'ye ikinci kez tıklandığında ağacı KAPATIYOR;
   * aynı Config API'nin sekmelerini art arda açan bir senaryo (ör. önce
   * "Client Cert Üret", sonra "Token Üret") ağacı farkında olmadan kapatıyor ve
   * kapsamdaki host satırları DOM'dan kalkıyor.
   */
  async ensureApiExpanded(apiId) {
    const isExpanded = () =>
      this.page.evaluate((id) => !window._apiExpanded || window._apiExpanded[id] !== false, apiId);
    if (!(await isExpanded())) {
      await this.page.locator(`#host-list [data-action="toggleApiTree"][data-arg0="${apiId}"]`).first().click();
    }
    await expect.poll(isExpanded, { timeout: 10_000 }).toBe(true);
  }

  /** Host detayını o kapsamın ağacından açar; sayfanın seçili Config API'si de değişir. */
  async openHostIn(apiId, host) {
    await this.ensureApiExpanded(apiId);
    await this.hostItemIn(apiId, host).click();
    await expect(this.page.locator('.section-title-main')).toHaveText(host);
    await expect(this.page.locator('#pins-card')).toBeVisible();
  }

  /**
   * Config API'nin "+" düğmesi → "Yükle" sekmesi: diskteki JKS/P12'den host
   * ekler, pin'leri sunucu sertifikadan hesaplar. Manuel sekmenin aksine bu yol
   * kapsamlıdır (`/api/v1/hosts/upload-cert?configApiId=…`).
   */
  async addHostUpload(apiId, host, filePath, password = 'changeit') {
    await this.page.locator(`#host-list [data-action="showAddHostScoped"][data-arg0="${apiId}"]`).click();
    await this.page.locator('[data-action="switchAddTab"][data-arg0="upload"]').click();
    await this.page.fill('#upload-hostname', host);
    await this.page.setInputFiles('#upload-file', filePath);
    await this.page.fill('#upload-password', password);
    const response = this.page.waitForResponse((r) => r.url().includes('/api/v1/hosts/upload-cert'), { timeout: 30_000 });
    await this.page.locator('[data-action="createHostUpload"]').click();
    const res = await response;
    const text = (await res.text()).trim();
    if (!res.ok()) throw new Error(`Host yüklenemedi (${apiId}/${host}): HTTP ${res.status()} ${text}`);
    await this.ensureApiExpanded(apiId);
    await expect(this.hostItemIn(apiId, host)).toBeVisible({ timeout: 20_000 });
    return `HTTP ${res.status()} ${text}`;
  }

  // ── Host'a özel istemci sertifikası (mTLS) ───────────────────────────

  /** Host detayındaki "mTLS" anahtarı; sunucudaki gerçek duruma göre doğrulanır. */
  async setHostMtls(apiId, host, enable) {
    await this.openHostIn(apiId, host);
    const card = this.page.locator('#host-client-cert-card');
    await expect(card).toBeVisible();
    if ((await this.hostMtlsFlag(apiId, host)) !== enable) {
      await card.locator(`[data-action="toggleHostMtls"][data-arg0="${host}"]`).click();
    }
    await expect.poll(() => this.hostMtlsFlag(apiId, host), { timeout: 20_000 }).toBe(enable);
  }

  /** Kapsamdaki pin kaydının mTLS bayrağı (sunucudan okunur, sayfadan değil). */
  async hostMtlsFlag(apiId, host) {
    return this.page.evaluate(
      async ([id, hostname]) => {
        const key = sessionStorage.getItem('pinvault_api_key') || '';
        const res = await fetch(`/api/v1/config/${encodeURIComponent(id)}`, { headers: { 'X-API-Key': key } });
        const cfg = await res.json();
        return !!(cfg.pins || []).find((p) => p.hostname === hostname)?.mtls;
      },
      [apiId, host],
    );
  }

  /**
   * Host detayındaki "Client Cert Yükle": host'a özel istemci P12'si. Parola
   * `prompt()` ile sorulur; yanıt [answerPrompt] kuyruğundan verilir.
   * Yüklenen `clientCertVersion`'ı döndürür.
   */
  async uploadHostClientCert(apiId, host, p12Path, password = 'changeit') {
    await this.openHostIn(apiId, host);
    await expect(this.page.locator('#host-client-cert-card')).toBeVisible();
    this.answerPrompt(password);
    const response = this.page.waitForResponse((r) => r.url().includes('/upload-client-cert'), { timeout: 30_000 });
    await this.page.setInputFiles('#host-cc-file', p12Path);
    const res = await response;
    const body = (await res.text()).trim();
    await expect.poll(() => this.hostClientCertVersion(apiId, host), { timeout: 20_000 }).toBeGreaterThan(0);
    return `HTTP ${res.status()} ${body}`;
  }

  /** Kapsamdaki pin kaydının `clientCertVersion` değeri (0 = yok). */
  async hostClientCertVersion(apiId, host) {
    return this.page.evaluate(
      async ([id, hostname]) => {
        const key = sessionStorage.getItem('pinvault_api_key') || '';
        const res = await fetch(`/api/v1/config/${encodeURIComponent(id)}`, { headers: { 'X-API-Key': key } });
        const cfg = await res.json();
        return (cfg.pins || []).find((p) => p.hostname === hostname)?.clientCertVersion || 0;
      },
      [apiId, host],
    );
  }

  /** Host detayındaki "Client Cert (mTLS)" kartının metni. */
  async hostClientCertCardText() {
    return (await this.page.locator('#host-client-cert-card').innerText()).trim();
  }

  /** Host detayındaki sürüm kartı ("v30" → 30). */
  async version() {
    const text = await this.page.locator('.stats .card').first().locator('.stat-value').innerText();
    return Number(text.replace(/\D/g, ''));
  }

  /**
   * "Pinleri Düzenle" ile pin listesini verilen değerlere getirip kaydeder.
   * [expectSaved] false ise kaydın reddedilmesi beklenir; sonucu çağıran denetler.
   */
  async setPins(host, pins, { expectSaved = true } = {}) {
    const page = this.page;
    await page.locator(`#pins-card [data-action="toggleEditPins"][data-arg0="${host}"]`).click();
    const inputs = page.locator('#pins-edit input.form-input');
    await expect(inputs.first()).toBeVisible();

    while ((await inputs.count()) < pins.length) {
      await page.locator('#pins-edit [data-action="addEditHashInline"]').click();
    }
    while ((await inputs.count()) > pins.length) {
      await page.locator('#pins-edit [data-action="removeEditHashInline"]').last().click();
    }
    for (let i = 0; i < pins.length; i++) {
      await inputs.nth(i).fill(pins[i]);
      await inputs.nth(i).dispatchEvent('change');
    }

    await this.snapHostSummary('pinler kaydedilmeden önce');
    await page.locator('#pins-edit [data-action="saveInlinePins"]').click();
    if (expectSaved) await expect(page.locator('#pins-view')).toContainText(pins[0]);
  }

  /** Pin düzenleme formunu kaydetmeden kapatır ("İptal"); görünüm moduna döner. */
  async cancelEditPins(host) {
    const cancel = this.page.locator(`#pins-edit [data-action="toggleEditPins"][data-arg0="${host}"]`);
    if (await cancel.count()) await cancel.click();
    await expect(this.page.locator('#pins-view')).toBeVisible();
  }

  /** Görünen pin listesindeki hash'ler (#pins-view). */
  async viewedPins(host) {
    await this.openHost(host);
    const text = await this.page.locator('#pins-view').innerText();
    return text
      .split('\n')
      .map((s) => s.replace('sha256/', '').trim())
      .filter((s) => /^[A-Za-z0-9+/=]{44}$/.test(s));
  }

  /** Hostu siler ("Hostu Sil" + onay). */
  async deleteHost(host) {
    await this.openHost(host);
    await this.page.locator(`[data-action="deleteHost"][data-arg0="${host}"]`).click();
    await expect(this.hostItem(host)).toHaveCount(0);
  }

  /** Ağaçtaki bütün host adları (her Config API için). */
  async hostNames() {
    const items = this.page.locator('#host-list .host-item');
    const count = await items.count();
    const names = [];
    for (let i = 0; i < count; i++) names.push(await items.nth(i).getAttribute('data-arg0'));
    return names.filter(Boolean);
  }

  /** Bütün host'ları tek tek siler; config boş kalır. */
  async deleteAllHosts() {
    for (const host of await this.hostNames()) await this.deleteHost(host);
    await expect(this.page.locator('#host-list .host-item')).toHaveCount(0);
  }

  /** Config API'nin "+" düğmesi → "Manuel" sekmesi ile host ekler. */
  async addHostManual(apiId, host, pins) {
    await this.page.locator(`#host-list [data-action="showAddHostScoped"][data-arg0="${apiId}"]`).click();
    await this.page.locator('[data-action="switchAddTab"][data-arg0="manual"]').click();
    await this.page.fill('#add-hostname', host);
    await this.page.fill('#add-hash-0', pins[0]);
    await this.page.fill('#add-hash-1', pins[1]);
    await this.page.locator('[data-action="createHostManual"]').click();
    await expect(this.hostItem(host)).toBeVisible();
  }

  async forceActive(host) {
    return (await this.hostItem(host).getByText('FORCE', { exact: true }).count()) > 0;
  }

  /** Host sayfasındaki "Force Update" anahtarı. Açarken çıkan onay kutusu fixture'da kabul edilir. */
  async setForce(host, active) {
    if ((await this.forceActive(host)) !== active) {
      await this.page.locator(`[data-action="toggleForce"][data-arg0="${host}"]`).click();
    }
    const badge = this.hostItem(host).getByText('FORCE', { exact: true });
    if (active) await expect(badge).toBeVisible();
    else await expect(badge).toHaveCount(0);
  }

  /** "Bağlı Cihazlar" kartında cihaz satırı beklenen sürüm ve durumda görünene kadar yeniler. */
  async expectClientRow(deviceModel, { version, status }) {
    const card = this.page.locator('#client-devices-card');
    await expect(async () => {
      await card.locator('[data-action="loadClientDevices"]').click();
      const row = card.locator('tbody tr', { hasText: deviceModel }).first();
      await expect(row).toContainText(`v${version}`, { timeout: 1000 });
      await expect(row).toContainText(status, { timeout: 1000 });
    }).toPass({ timeout: 30_000, intervals: [1000, 2000] });
  }

  /** "Bağlı Cihazlar" kartında cihaz satırı (sürüm beklemeden) görünene kadar yeniler. */
  async expectClientRowPresent(deviceModel, { status } = {}) {
    const card = this.page.locator('#client-devices-card');
    await expect(async () => {
      await card.locator('[data-action="loadClientDevices"]').click();
      const row = card.locator('tbody tr', { hasText: deviceModel }).first();
      await expect(row).toBeVisible({ timeout: 1000 });
      if (status) await expect(row).toContainText(status, { timeout: 1000 });
    }).toPass({ timeout: 60_000, intervals: [1000, 2000] });
  }

  /** "Bağlantı Geçmişi" kartında cihazın en yeni kaydı beklenen durumda görünene kadar yeniler. */
  async expectLatestConnection(deviceModel, { status }) {
    const card = this.page.locator('#conn-history-card');
    await expect(async () => {
      await card.locator('[data-action="loadHostConnectionHistory"]').click();
      const row = card.locator('tbody tr', { hasText: deviceModel }).first();
      await expect(row).toContainText(status, { timeout: 1000 });
    }).toPass({ timeout: 30_000, intervals: [1000, 2000] });
  }

  /** Config API'nin "+" düğmesi → "Sunucuda Üret" sekmesi ile host ekler. */
  async addHostGenerate(apiId, host) {
    await this.page.locator(`#host-list [data-action="showAddHostScoped"][data-arg0="${apiId}"]`).click();
    await this.page.locator('[data-action="switchAddTab"][data-arg0="generate"]').click();
    await this.page.fill('#gen-hostname', host);
    await this.page.locator('[data-action="createHostGenerate"]').click();
    await expect(this.hostItem(host)).toBeVisible({ timeout: 30_000 });
  }

  /** Config API'nin "+" düğmesi → "URL'den Al" sekmesi ile host ekler (pin'leri sunucu çeker). */
  async addHostFromUrl(apiId, url) {
    await this.page.locator(`#host-list [data-action="showAddHostScoped"][data-arg0="${apiId}"]`).click();
    await this.page.locator('[data-action="switchAddTab"][data-arg0="fetch"]').click();
    await this.page.fill('#fetch-url', url);
    await this.page.locator('[data-action="createHostFetch"]').click();
  }

  /** "Manuel" sekmesini hatalı pin'le doldurup kaydeder; başarı beklenmez. */
  async addHostManualExpectingRejection(apiId, host, pins) {
    await this.page.locator(`#host-list [data-action="showAddHostScoped"][data-arg0="${apiId}"]`).click();
    await this.page.locator('[data-action="switchAddTab"][data-arg0="manual"]').click();
    await this.page.fill('#add-hostname', host);
    await this.page.fill('#add-hash-0', pins[0]);
    await this.page.fill('#add-hash-1', pins[1]);
    await this.page.locator('[data-action="createHostManual"]').click();
    const toast = await this.toastText();
    await expect(this.hostItem(host)).toHaveCount(0);
    return toast;
  }

  // ── Config API yönetimi ──────────────────────────────────────────────

  /** Config API detay sayfasını açar (ağaçtaki başlığa tıklar). */
  async openConfigApi(apiId) {
    await this.page.locator(`#host-list [data-action="toggleApiTree"][data-arg0="${apiId}"]`).click();
    await expect(this.page.locator(`[data-action="deleteConfigApi"][data-arg0="${apiId}"]`).first()).toBeVisible();
  }

  /**
   * "+ Config API" formu: yeni dinleyici oluşturur. Sunucunun yanıtını
   * (durum + gövde) döndürür — toast'lar üç saniyede kaybolduğu için önceki
   * işlemin toast'ıyla karışabiliyor.
   */
  async createConfigApi(id, port, mode) {
    await this.page.locator('#btn-add-api').click();
    await this.page.fill('#new-api-id', id);
    await this.page.fill('#new-api-port', String(port));
    await this.page.selectOption('#new-api-mode', mode);
    const response = this.page.waitForResponse((r) => r.url().includes('/api/v1/config-apis/start'), {
      timeout: 60_000,
    });
    await this.page.locator('form[data-action-submit="createConfigApi"] button[type="submit"]').click();
    const res = await response;
    return `HTTP ${res.status()} ${(await res.text()).trim()}`;
  }

  /**
   * Detay sayfasındaki aç/kapa anahtarı; [running] false ise durdurur.
   *
   * Anahtar, sayfanın kendi `allApiConfigs` kopyasına bakarak "durdur" ya da
   * "başlat" isteği yolluyor. Durdurma isteği sunucuda birkaç saniye sürdüğü
   * için (Netty graceful shutdown) bu kopya geç tazeleniyor; art arda iki
   * tıklamada ikincisi yine "durdur" gönderebiliyor. Bu yüzden her çağrı
   * sayfayı tazeleyip sunucunun gerçek durumundan başlıyor.
   */
  async setConfigApiRunning(apiId, running) {
    await this.page.reload();
    await expect(this.page.locator('#host-list .api-header').first()).toBeVisible();
    await this.openConfigApi(apiId);
    const toggle = this.page.locator(`[data-action="toggleConfigApi"][data-arg0="${apiId}"]`).first();
    if ((await this.apiRunning(apiId)) !== running) await toggle.click();
    await expect.poll(() => this.apiRunning(apiId), { timeout: 30_000 }).toBe(running);
    // Sunucu API'yi listeden hemen düşürür, dinleyiciyi ise 1,5 sn bekleme +
    // 3 sn üst sınırla kapatır (ConfigApiManager.stop): o arada açık bağlantılar
    // hâlâ yanıt alır. Hızlı bir istemci (iOS) bu pencereye düşmesin.
    if (!running) await this.page.waitForTimeout(3_500);
  }

  /** all-configs'teki çalışma durumu (kenar çubuğundaki nokta yerine kaynağından). */
  async apiRunning(apiId) {
    return this.page.evaluate(async (id) => {
      const key = sessionStorage.getItem('pinvault_api_key') || '';
      const res = await fetch('/api/v1/all-configs', { headers: { 'X-API-Key': key } });
      const list = await res.json();
      const api = (list || []).find((a) => a.id === id);
      return !!api && api.running !== false;
    }, apiId);
  }

  async deleteConfigApi(apiId) {
    await this.openConfigApi(apiId);
    await this.page.locator(`[data-action="deleteConfigApi"][data-arg0="${apiId}"]`).first().click();
    await expect(this.page.locator(`#host-list .api-header[data-arg0="${apiId}"]`)).toHaveCount(0);
  }

  // ── Mock hedef host'lar ──────────────────────────────────────────────

  /** Host detayındaki mock sunucu anahtarı: verilen portta (ve modda) başlatır. */
  async startMock(host, { port, mtls = false }) {
    await this.openHost(host);
    await this.page.fill('#mock-port', String(port));
    if (mtls) await this.page.locator('#mock-mtls').check();
    await this.page.locator(`[data-action="toggleMock"][data-arg0="${host}"]`).first().click();
    return this.toastText();
  }

  /** Host'un mock sunucusu çalışıyor mu (sunucudan okunur). */
  async mockRunning(apiId, host) {
    return this.page.evaluate(
      async ([id, hostname]) => {
        const key = sessionStorage.getItem('pinvault_api_key') || '';
        const res = await fetch(
          `/api/v1/hosts/${encodeURIComponent(hostname)}/status?configApiId=${encodeURIComponent(id)}`,
          { headers: { 'X-API-Key': key } },
        );
        const data = await res.json();
        return !!data.mockServerRunning;
      },
      [apiId, host],
    );
  }

  /**
   * Mock sunucuyu durdurup aynı ayarlarla yeniden başlatır.
   *
   * Çalışan bir mTLS mock sunucusu, başlatıldığı andaki truststore'u tutuyor:
   * sonradan üretilen / yüklenen istemci sertifikaları ancak yeniden başlatma
   * sonrası kabul ediliyor (yalnızca kayıt ve iptal uçları kendiliğinden
   * yeniden başlatıyor).
   */
  async restartMock(apiId, host, { port, mtls = false }) {
    await this.openHostIn(apiId, host);
    const toggle = this.page.locator(`[data-action="toggleMock"][data-arg0="${host}"]`).first();
    if (await this.mockRunning(apiId, host)) {
      await toggle.click();
      await expect.poll(() => this.mockRunning(apiId, host), { timeout: 30_000 }).toBe(false);
    }
    await expect(this.page.locator('#mock-port')).toBeVisible({ timeout: 20_000 });
    await this.page.fill('#mock-port', String(port));
    if (mtls) await this.page.locator('#mock-mtls').check();
    await this.page.locator(`[data-action="toggleMock"][data-arg0="${host}"]`).first().click();
    await expect.poll(() => this.mockRunning(apiId, host), { timeout: 30_000 }).toBe(true);
    return this.toastText(10_000);
  }

  /**
   * Host detayındaki Sertifika kartından "Sertifikayı Yenile": sunucu host
   * için yeni bir anahtar çifti üretir, pin'leri ve sürümü artırır, mock
   * sunucu çalışıyorsa yeni sertifikayla yeniden başlatır. Onay kutusu
   * fixture'da kabul edilir; sonuç toast'ını döndürür.
   */
  async renewHostCert(host) {
    await this.openHost(host);
    const button = this.page.locator(`[data-action="renewCertAuto"][data-arg0="${host}"]`).first();
    await expect(button).toBeVisible({ timeout: 20_000 });
    await button.click();
    return this.toastText(20_000);
  }

  /**
   * Host detayındaki "Yedek Anahtara Geç": sertifika saklı yedek anahtarla
   * yeniden üretilir, yeni bir yedek hazırlanır. Onay kutusu fixture'da kabul
   * edilir; sonuç toast'ını döndürür. [apiId] verilirse host o kapsamın
   * ağacından açılır (ağaç kapalı olsa da).
   */
  async rotateHostToBackup(host, apiId) {
    if (apiId) await this.openHostIn(apiId, host);
    else await this.openHost(host);
    const button = this.page.locator(`[data-action="rotateHostToBackup"][data-arg0="${host}"]`).first();
    await expect(button).toBeVisible({ timeout: 20_000 });
    await button.click();
    return this.toastText(20_000);
  }

  /** Host detayındaki "Bağlantıyı test et"; sonuç toast'ını döndürür. */
  async testConnection(host) {
    await this.openHost(host);
    await this.page.locator(`[data-action="testHostConnection"][data-arg0="${host}"]`).first().click();
    return this.toastText(15_000);
  }

  // ── Cihaz ACL'i ──────────────────────────────────────────────────────

  /** Config API → Genel sekmesi → "Cihaz ACL'lerini yönet". */
  async openAclManager(apiId) {
    await this.openConfigApi(apiId);
    await this.page.locator(`[data-action="showDeviceAclManager"][data-arg0="${apiId}"]`).click();
    await expect(this.page.locator('#default-acl-input')).toBeVisible();
  }

  /** ACL yöneticisindeki cihaz satırları (id + model). */
  async aclDeviceIds() {
    const rows = this.page.locator('.card table.data-table tbody tr');
    const ids = [];
    for (let i = 0; i < (await rows.count()); i++) {
      const text = (await rows.nth(i).locator('td').first().innerText()).trim();
      if (text && !text.includes('—')) ids.push(text);
    }
    return ids;
  }

  /** Cihazın host ACL'ini düzenler (prompt ile); [hosts] boş dizi ACL'i temizler. */
  async setDeviceAcl(apiId, deviceId, hosts) {
    await this.openAclManager(apiId);
    this.answerPrompt(hosts.join(', '));
    await this.page.locator(`[data-action="editDeviceAcl"][data-arg1="${deviceId}"]`).click();
    await expect(this.page.locator('#default-acl-input')).toBeVisible();
  }

  async setDefaultAcl(apiId, hosts) {
    await this.openAclManager(apiId);
    await this.page.fill('#default-acl-input', hosts.join(', '));
    await this.page.locator(`[data-action="saveDefaultAcl"][data-arg0="${apiId}"]`).click();
    return this.toastText();
  }

  // ── Bölümler, dil, sayfalama ─────────────────────────────────────────

  /** Kenar çubuğundaki "Bağlantı Geçmişi" (sağlık + sertifika süre kartı). */
  async openHealth() {
    await this.page.locator('#nav-health').click();
    await expect(this.page.locator('.stats .card').first()).toBeVisible();
  }

  /** Arayüz dili (TR/EN). */
  async setLang(lang) {
    await this.page.locator(`[data-action="setLang"][data-arg0="${lang}"]`).click();
    await expect(this.page.locator(`#lang-${lang}`)).toHaveClass(/active/);
  }

  /** Bootstrap sekmesindeki sunucu TLS pin'leri (birincil, yedek). */
  async bootstrapPins(apiId) {
    await this.openConfigApiTab(apiId, 'bootstrap');
    const boxes = this.page.locator('.hash-box span');
    await expect(boxes.first()).toBeVisible();
    const out = [];
    for (let i = 0; i < (await boxes.count()); i++) {
      out.push((await boxes.nth(i).innerText()).replace('sha256/', '').trim());
    }
    return out;
  }

  /** Bootstrap sekmesi → "Sertifikayı Yenile" (onay fixture'da kabul edilir). */
  async regenerateBootstrapCert(apiId) {
    await this.openConfigApiTab(apiId, 'bootstrap');
    await this.page.locator('[data-action="regenerateBootstrapCert"]').first().click();
    return this.toastText(20_000);
  }

  /** Bootstrap sekmesi → "Yedek Anahtara Geç" (onay fixture'da kabul edilir). */
  async rotateBootstrapToBackup(apiId) {
    await this.openConfigApiTab(apiId, 'bootstrap');
    await this.page.locator('[data-action="rotateBootstrapToBackup"]').first().click();
    return this.toastText(20_000);
  }

  /** İmzalama sekmesindeki public key. */
  async signingPublicKey(apiId) {
    await this.openConfigApiTab(apiId, 'signing');
    const box = this.page.locator('.key-box, .hash-box span').first();
    await expect(box).toBeVisible();
    return (await box.innerText()).trim();
  }

  /**
   * İmzalama sekmesi → "Anahtarı Yenile": sunucu diskteki ECDSA anahtarını
   * silip yenisini üretir. Onay kutusu fixture'da kabul edilir; sonuç
   * toast'ını döndürür.
   *
   * DİKKAT: çalışan sunucu yeni anahtarı HEMEN kullanmaya başlamıyor —
   * dinleyicilere imza servisi başlangıçta değer olarak geçiliyor (bkz. A19
   * bulgusu). Yeni anahtarın devreye girmesi için container yeniden
   * başlatılmalı.
   */
  async regenerateSigningKey(apiId) {
    await this.openConfigApiTab(apiId, 'signing');
    await this.page.locator('[data-action="regenerateSigningKey"]').first().click();
    return this.toastText(20_000);
  }

  // ── İmzalama sekmesi: imzalayıcılar, anahtar seti, imza önbelleği ─────

  /** İmzalama sekmesini açar; imzalayıcılar kartı çizilene kadar bekler. */
  async openSigning(apiId) {
    await this.openConfigApiTab(apiId, 'signing');
    await expect(this.page.locator('#signers-card')).toBeVisible({ timeout: 20_000 });
  }

  /**
   * İmzalayıcılar kartının satırları: { name, primary, type, keyId (tam,
   * hücrenin title özniteliğinden), inSet (true/false; set yoksa null),
   * description }.
   */
  async signerRows() {
    return this.page.locator('#signers-card tbody tr').evaluateAll((rows) =>
      rows.map((tr) => {
        const td = tr.querySelectorAll('td');
        const id = td[2] && td[2].querySelector('.mono');
        return {
          name: ((td[0] && td[0].querySelector('b')) || { textContent: '' }).textContent.trim(),
          primary: !!(td[0] && td[0].querySelector('.gov-badge-primary')),
          type: td[1] ? td[1].textContent.trim() : '',
          keyId: id ? id.getAttribute('title') : '',
          inSet: td[2] && td[2].querySelector('.status-healthy') ? true : td[2] && td[2].querySelector('.status-error') ? false : null,
          description: td[3] ? td[3].textContent.trim() : '',
        };
      }),
    );
  }

  /** Anahtar seti kartının metni (sürüm, listelenen anahtarlar, uyarılar). */
  async keySetCardText() {
    return (await this.page.locator('#keyset-card').innerText()).trim();
  }

  /**
   * Anahtar seti kartına imzalı seti (JSON metni, olduğu gibi) yapıştırıp
   * "Seti Yükle". Sunucunun yanıtını ve kartın sonuç kutusunu döndürür:
   * { status, body, result }. Başarıda sekme yeniden çizilir; sonuç kutusu
   * yeni çizimde de görünür.
   */
  async uploadKeySet(apiId, wireText) {
    await this.openSigning(apiId);
    await this.page.fill('#keyset-json', wireText);
    const response = this.page.waitForResponse(
      (r) => r.url().includes('/api/v1/signing-keyset') && r.request().method() === 'PUT',
      { timeout: 30_000 },
    );
    await this.page.locator('[data-action="uploadKeyset"]').click();
    const res = await response;
    const body = (await res.text()).trim();
    const box = this.page.locator('#keyset-upload-result .notice');
    await expect(box).toContainText(res.ok() ? /yüklendi|uploaded/ : /reddedildi|rejected/i, { timeout: 20_000 });
    if (res.ok()) await expect(this.page.locator('#keyset-card .ver-badge')).toBeVisible({ timeout: 20_000 });
    return { status: res.status(), body, result: (await box.innerText()).trim() };
  }

  /** İmza önbelleği kartındaki değerler: { enabled, ttl, produced, hits, cached }. */
  async sigCacheStats() {
    const card = this.page.locator('#sig-cache-card');
    await expect(card).toBeVisible({ timeout: 20_000 });
    const values = await card.locator('.mini-stat-value').allInnerTexts();
    const badge = (await card.locator('.gov-badge').first().innerText()).trim();
    return {
      enabled: !/kapal|off/i.test(badge),
      badge,
      ttl: values[0],
      produced: Number(values[1]),
      hits: Number(values[2]),
      cached: Number(values[3]),
    };
  }

  /** "Anahtarı Yenile" düğmesi: devre dışı mı, neden (title) ve başlığın altındaki uyarı. */
  async regenerateState() {
    const button = this.page.locator('[data-action="regenerateSigningKey"]').first();
    await expect(button).toBeVisible({ timeout: 20_000 });
    const notice = this.page.locator('#content > .notice-warn').first();
    return {
      disabled: await button.isDisabled(),
      title: (await button.getAttribute('title')) || '',
      notice: (await notice.count()) ? (await notice.innerText()).trim() : '',
    };
  }

  // ── Yönetişim: kimlik, onaylar, denetim kaydı, canlı kontrol ─────────

  /**
   * [action]'ı çalıştırır ve [viewId] görünümü (Onaylar / Denetim Kaydı)
   * sunucudan YENİDEN çizilene kadar bekler. Bu bölümler veriyi çekince
   * içeriği baştan yazar; görünüm zaten ekrandayken "görünür mü" beklemesi eski
   * DOM'la hemen geçiyor ve ardından okunan satır bir önceki çizime ait
   * olabiliyordu. Eski görünüm işaretlenir, işaretsiz yenisi beklenir.
   */
  async rerender(viewId, action) {
    await this.page.evaluate((id) => {
      const view = document.getElementById(id);
      if (view) view.dataset.e2eStale = '1';
    }, viewId);
    await action();
    await expect(this.page.locator(`#${viewId}:not([data-e2e-stale])`)).toBeVisible({ timeout: 20_000 });
  }

  /**
   * Dashboard'u ayrı bir tarayıcı bağlamında, verilen yönetici anahtarıyla
   * açar (ADMIN_KEYS: alice, bob). İki yönetici aynı anda iki bağlamda
   * çalışabilsin diye her çağrı yeni bir bağlam açar; anahtar yalnızca
   * sayfanın sessionStorage'ına yazılır, kanıta girmez. Kapatmak için
   * `dashboard.context.close()`.
   */
  static async openAs(browser, testInfo, key, { baseUrl } = {}) {
    const { WEB_URL } = require('./env');
    const origin = baseUrl || `${WEB_URL}/`;
    const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
    const page = await context.newPage();
    const dashboard = new Dashboard(page, testInfo, { baseUrl: origin });
    dashboard.context = context;
    await Dashboard.attachDialogs(page, dashboard);
    await Dashboard.seedApiKey(page, key);
    await dashboard.open();
    return dashboard;
  }

  /** Kenar çubuğundaki kimlik rozetinin adı (GET /api/v1/admin/me → name). */
  async adminName() {
    const name = this.page.locator('#admin-name');
    await expect(name).not.toHaveText(/Kimlik yok|Not signed in/, { timeout: 20_000 });
    return (await name.innerText()).trim();
  }

  /** Kimlik rozetinin altındaki özellik rozetleri ("2 kişi onayı", "Canlı kontrol: zorunlu" …). */
  async adminBadges() {
    return (await this.page.locator('#admin-chip .gov-badge').allInnerTexts()).map((s) => s.trim());
  }

  /**
   * Kenar çubuğu → "Onaylar", ardından [tab] sekmesi. Bölüm zaten açıkken
   * menüye tıklamak seçili sekmeyi korur ("Geçmiş"te kalınabilir); bu yüzden
   * sekme her seferinde açıkça seçilir.
   */
  async openApprovals(tab = 'pending') {
    await this.rerender('approvals-view', () => this.page.locator('#nav-approvals').click());
    await this.setApprovalsTab(tab);
  }

  /** Onaylar bölümünde "Bekleyen" / "Geçmiş" sekmesi. */
  async setApprovalsTab(tab) {
    const button = () => this.page.locator(`#approvals-view [data-action="setApprovalsTab"][data-arg0="${tab}"]`);
    await this.rerender('approvals-view', () => button().click());
    await expect(button()).toHaveClass(/tab-active/);
  }

  /** Bekleyen değişiklik isteğinin kartı. */
  changeCard(id) {
    return this.page.locator(`#cr-card-${id}`);
  }

  /** Kartın "Onayla" düğmesi: { disabled, title }. */
  async approveButtonState(id) {
    const button = this.changeCard(id).locator(`[data-action="approveChange"][data-arg0="${id}"]`);
    await expect(button).toBeVisible({ timeout: 20_000 });
    return { disabled: await button.isDisabled(), title: (await button.getAttribute('title')) || '' };
  }

  /** Değişikliğin ayrıntısını (pin farkı) açar. */
  async expandChange(id) {
    const detail = this.page.locator(`#cr-detail-${id}`);
    if (!(await detail.isVisible())) {
      await this.page.locator(`[data-action="toggleChangeDetail"][data-arg0="${id}"]`).first().click();
    }
    await expect(detail).toBeVisible();
  }

  /**
   * "Onayla": sunucunun yanıtını ({ status, body }) döndürür. Toast'ı çağıran
   * görüntüler (başarı ya da 409 hata metni).
   */
  async approveChange(id) {
    const response = this.page.waitForResponse(
      (r) => r.url().includes(`/api/v1/change-requests/${id}/approve`) && r.request().method() === 'POST',
      { timeout: 60_000 },
    );
    await this.changeCard(id).locator(`[data-action="approveChange"][data-arg0="${id}"]`).click();
    const res = await response;
    return { status: res.status(), body: (await res.text()).trim() };
  }

  /** "Reddet" / "Geri çek": gerekçe prompt'la sorulur. Sunucunun yanıtını döndürür. */
  async rejectChange(id, reason) {
    this.answerPrompt(reason);
    const response = this.page.waitForResponse(
      (r) => r.url().includes(`/api/v1/change-requests/${id}/reject`) && r.request().method() === 'POST',
      { timeout: 30_000 },
    );
    await this.changeCard(id).locator(`[data-action="rejectChange"][data-arg0="${id}"]`).click();
    const res = await response;
    return { status: res.status(), body: (await res.text()).trim() };
  }

  /** "Geçmiş" sekmesindeki satır (karara bağlanmış istek). */
  decidedRow(id) {
    return this.page.locator(`#approvals-view tr[data-action="toggleChangeDetail"][data-arg0="${id}"]`);
  }

  /**
   * Onaylar görünümünün görüntüsü; [ids] verilirse başka isteklerin kartları /
   * satırları (önceki koşulardan kalan geçmiş) görüntü süresince gizlenir.
   */
  async snapApprovals(title, { ids } = {}) {
    await expect(this.page.locator('#approvals-view')).toBeVisible({ timeout: 20_000 });
    if (ids) {
      await this.page.evaluate((keep) => {
        const hide = (el) => {
          el.dataset.e2eHidden = el.style.display || '';
          el.style.display = 'none';
        };
        document.querySelectorAll('#approvals-view .cr-card').forEach((card) => {
          if (!keep.includes(card.id.replace('cr-card-', ''))) hide(card);
        });
        document.querySelectorAll('#approvals-view tr.row-toggle').forEach((tr) => {
          const id = tr.getAttribute('data-arg0');
          if (keep.includes(id)) return;
          hide(tr);
          const detail = document.getElementById(`cr-detail-${id}`);
          if (detail) hide(detail);
        });
      }, ids.map(String));
    }
    try {
      await this.snapCard('#approvals-view', title);
    } finally {
      await this.page.evaluate(() => {
        document.querySelectorAll('[data-e2e-hidden]').forEach((el) => {
          el.style.display = el.dataset.e2eHidden;
          delete el.dataset.e2eHidden;
        });
      });
    }
  }

  /** Kenar çubuğu → "Denetim Kaydı". */
  async openAudit() {
    await this.rerender('audit-view', () => this.page.locator('#nav-audit').click());
  }

  /** Denetim kaydını yeniden çizer (↻). */
  async refreshAudit() {
    await this.rerender('audit-view', () => this.page.locator('#audit-view [data-action="refreshAudit"]').click());
  }

  /** İşlem süzgeci (boş = tümü); tablo yeniden çizilene kadar bekler. */
  async setAuditFilter(action) {
    const select = this.page.locator('#audit-action-filter');
    if ((await select.inputValue()) === (action || '')) return;
    await this.rerender('audit-view', () => select.selectOption(action || ''));
    await expect(this.page.locator('#audit-action-filter')).toHaveValue(action || '', { timeout: 20_000 });
  }

  auditRow(id) {
    return this.page.locator(`#audit-view tr[data-action="toggleAuditDetail"][data-arg0="${id}"]`);
  }

  /** Denetim satırının hücreleri: { id, time, actor, action, configApiId, target, summary }. */
  async auditRowCells(id) {
    const row = this.auditRow(id);
    await expect(row).toBeVisible({ timeout: 20_000 });
    const cells = (await row.locator('td').allInnerTexts()).map((s) => s.trim());
    return { id: cells[0], time: cells[1], actor: cells[2], action: cells[3], configApiId: cells[4], target: cells[5], summary: cells[6] };
  }

  /** Satırın ayrıntısını (kaynak IP, hash, JSON fark) açar; ayrıntı metnini döndürür. */
  async expandAuditEntry(id) {
    const detail = this.page.locator(`#audit-detail-${id}`);
    if (!(await detail.isVisible())) await this.auditRow(id).click();
    await expect(detail).toBeVisible();
    return (await detail.innerText()).trim();
  }

  /** "Zinciri Doğrula": sonuç metni ("✓ Zincir sağlam — N kayıt" / "✗ Zincir #id kaydında bozuk"). */
  async verifyAuditChain() {
    const response = this.page.waitForResponse((r) => r.url().includes('/api/v1/audit-log/verify'), { timeout: 30_000 });
    await this.page.locator('#audit-view [data-action="verifyAuditChain"]').click();
    const res = await response;
    const box = this.page.locator('#audit-verify-result .verify-result');
    await expect(box).toBeVisible({ timeout: 20_000 });
    return { status: res.status(), json: JSON.parse(await res.text()), text: (await box.innerText()).trim() };
  }

  /**
   * Denetim görünümünün (başlık + doğrulama sonucu + kayıt tablosu) görüntüsü;
   * [ids] verilirse tablodaki diğer satırlar görüntü süresince gizlenir (sayfa
   * 25 satır gösteriyor, kanıt yalnızca ilgili kayıtlar). [notifications]
   * false ise webhook kartı da gizlenir.
   */
  async snapAudit(title, { ids, notifications = false } = {}) {
    await expect(this.page.locator('#audit-view')).toBeVisible({ timeout: 20_000 });
    for (const id of ids || []) await expect(this.auditRow(id)).toBeVisible({ timeout: 20_000 });
    await this.page.evaluate(
      ([keep, showNotif]) => {
        const hide = (el) => {
          el.dataset.e2eHidden = el.style.display || '';
          el.style.display = 'none';
        };
        if (keep) {
          document.querySelectorAll('#audit-view tr.row-toggle').forEach((tr) => {
            const id = tr.getAttribute('data-arg0');
            if (keep.includes(id)) return;
            hide(tr);
            const detail = document.getElementById(`audit-detail-${id}`);
            if (detail) hide(detail);
          });
        }
        const notif = document.getElementById('notif-card');
        if (notif && !showNotif) hide(notif);
      },
      [ids ? ids.map(String) : null, notifications],
    );
    try {
      await this.snapCard('#audit-view', title);
    } finally {
      await this.page.evaluate(() => {
        document.querySelectorAll('[data-e2e-hidden]').forEach((el) => {
          el.style.display = el.dataset.e2eHidden;
          delete el.dataset.e2eHidden;
        });
      });
    }
  }

  /**
   * Host detayındaki pin düzenleyicisinde "Canlı Kontrol" (kaydetmez): alanlara
   * [pins] yazılır, düğmeye basılır; sonuç kutusunun metni döndürülür.
   * Düzenleyici açık kalır (ardından "Kaydet" ya da [cancelEditPins]).
   */
  async liveCheckInEditor(host, pins) {
    const page = this.page;
    const editor = page.locator('#pins-edit');
    if (!(await editor.isVisible())) {
      // Başlıktaki "Pinleri Düzenle" (kapatılmış düzenleyicinin "İptal"i de DOM'da kalıyor).
      await page.locator(`#pins-card [data-action="toggleEditPins"][data-arg0="${host}"]`).first().click();
    }
    const inputs = page.locator('#pins-edit input.form-input');
    await expect(inputs.first()).toBeVisible();
    while ((await inputs.count()) < pins.length) await page.locator('#pins-edit [data-action="addEditHashInline"]').click();
    while ((await inputs.count()) > pins.length) await page.locator('#pins-edit [data-action="removeEditHashInline"]').last().click();
    for (let i = 0; i < pins.length; i++) {
      await inputs.nth(i).fill(pins[i]);
      await inputs.nth(i).dispatchEvent('change');
    }
    const response = page.waitForResponse((r) => r.url().includes('/api/v1/pins/live-check'), { timeout: 30_000 });
    await page.locator(`#pins-edit [data-action="liveCheckPins"][data-arg1="inline"]`).click();
    const res = await response;
    const box = page.locator('#live-check-result .live-check-line').first();
    await expect(box).not.toHaveText(/kontrol ediliyor|Checking/, { timeout: 20_000 });
    return { status: res.status(), json: JSON.parse(await res.text()), text: (await page.locator('#live-check-result').innerText()).trim() };
  }

  /** Bir tablonun sayfa boyutunu değiştirir (ilk sayfalama seçicisi). */
  async setPageSize(size) {
    const select = this.page.locator('select[data-action-change="pagSizeChange"]').first();
    await select.scrollIntoViewIfNeeded();
    await select.selectOption(String(size));
  }

  /** Sayfalama satırındaki "sonraki sayfa" düğmesi. */
  async nextPage() {
    await this.page.locator('[data-action="pagGo"]', { hasText: '›' }).first().click();
  }

  // ── Config API sekmeleri ─────────────────────────────────────────────

  async openConfigApiTab(apiId, tab) {
    // Yalnızca sekme çubuğundaki düğme: vault sekmesindeki yenile simgesi ve
    // dosya detayındaki "Geri" düğmesi de aynı data-action'ı taşır.
    const tabButton = this.page.locator(`button.tab-btn[data-action="setConfigApiTab"][data-arg0="${tab}"][data-arg1="${apiId}"]`);
    // API başlığı hem API'yi seçer hem ağacını aç/kapa yapar: seçili API'ye ikinci
    // tıklama ağacı kapatır ve host satırları DOM'dan kalkar (E10'da 25 dakikalık
    // takılma). Başlığa yalnızca sekmeler ekranda değilse tıklanır, ağaç açık tutulur.
    if (!(await tabButton.isVisible())) {
      await this.page.locator(`#host-list [data-action="toggleApiTree"][data-arg0="${apiId}"]`).click();
    }
    await this.ensureApiExpanded(apiId);
    // Sekmeye tıklamak içeriği her seferinde yeniden çizer (setConfigApiTab).
    await tabButton.click();
  }

  // ── Vault ────────────────────────────────────────────────────────────

  vaultFileRow(key) {
    return this.page.locator(`tr[data-action="showVaultFileDetail"][data-arg1="${key}"]`);
  }

  /** Vault sekmesinde "Metin" ile dosya yükler; yüklenen sürümü döndürür. */
  async uploadVaultText(apiId, key, text, { policy = 'public', encryption = 'plain' } = {}) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.page.locator('#vault-tab-text').click();
    await this.page.fill('#vault-upload-text', text);
    await this.page.fill('#vault-upload-key', key);
    await this.page.selectOption('#vault-upload-policy', policy);
    await this.page.selectOption('#vault-upload-encryption', encryption);
    const before = (await this.vaultFileRow(key).count()) ? await this.vaultVersion(key) : 0;
    await this.page.locator('form[data-action-submit="uploadVaultFile"] button[type="submit"]').click();
    await expect.poll(() => this.vaultVersion(key).catch(() => 0)).toBeGreaterThan(before);
    return this.vaultVersion(key);
  }

  /** Vault sekmesinde "Dosya" ile diskteki bir dosyayı yükler. */
  async uploadVaultFileFromDisk(apiId, key, filePath, { policy = 'public', encryption = 'plain' } = {}) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.page.locator('#vault-tab-file').click();
    await this.page.setInputFiles('#vault-upload-file', filePath);
    await this.page.fill('#vault-upload-key', key);
    await this.page.selectOption('#vault-upload-policy', policy);
    await this.page.selectOption('#vault-upload-encryption', encryption);
    const before = (await this.vaultFileRow(key).count()) ? await this.vaultVersion(key) : 0;
    await this.page.locator('form[data-action-submit="uploadVaultFile"] button[type="submit"]').click();
    await expect.poll(() => this.vaultVersion(key).catch(() => 0)).toBeGreaterThan(before);
    return this.vaultVersion(key);
  }

  /**
   * Dosya listesindeki satırın hücreleri: anahtar, sürüm, boyut, politika,
   * şifreleme. Sayfa dosya detayındaysa satır DOM'da olmaz — çağıran önce
   * vault sekmesini açmalı; kısa bir bekleme ile hızlı hata verilir.
   */
  async vaultRowCells(key) {
    await expect(this.vaultFileRow(key)).toBeVisible({ timeout: 15_000 });
    const cells = this.vaultFileRow(key).locator('td');
    const out = [];
    for (let i = 0; i < 5; i++) out.push((await cells.nth(i).innerText()).trim());
    return { key: out[0], version: out[1], size: out[2], policy: out[3], encryption: out[4] };
  }

  async vaultVersion(key) {
    const text = await this.vaultFileRow(key).locator('td').nth(1).innerText({ timeout: 2000 });
    return Number(text.replace(/\D/g, ''));
  }

  async deleteVaultFile(apiId, key) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.page.locator(`[data-action="deleteVaultFile"][data-arg1="${key}"]`).click();
    await expect(this.vaultFileRow(key)).toHaveCount(0);
  }

  /** Dosya detayında cihaz için token üretir; tek seferlik gösterilen token'ı döndürür. */
  async generateVaultToken(apiId, key, deviceId) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.vaultFileRow(key).click();
    await this.page.fill(`#tk-device-${key}`, deviceId);
    const before = this.dialogs.length;
    await this.page.locator(`[data-action="generateVaultToken"][data-arg1="${key}"]`).click();
    await expect.poll(() => this.dialogs.length).toBeGreaterThan(before);
    // "…kopyalandı:\n\n<token>\n\nBu değer bir daha gösterilmeyecek…"
    return this.dialogs[this.dialogs.length - 1].split('\n\n')[1].trim();
  }

  /** Dosya detayındaki bütün etkin token'ları iptal eder. */
  async revokeVaultTokens(apiId, key) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.vaultFileRow(key).click();
    const revoke = this.page.locator(`[data-action="revokeVaultToken"][data-arg2="${key}"]`);
    await expect(revoke.first()).toBeVisible();
    for (let left = await revoke.count(); left > 0; left--) {
      await revoke.first().click();
      await expect(revoke).toHaveCount(left - 1);
    }
  }

  /** Vault sekmesinin "Dağıtım Geçmişi" tablosunda cihazın bu dosya için en yeni kaydı. */
  async expectDistribution(apiId, { key, deviceModel, status, version }) {
    await expect(async () => {
      await this.openConfigApiTab(apiId, 'vault');
      const row = this.page.locator('tbody tr', { hasText: deviceModel }).filter({ hasText: key }).first();
      await expect(row).toContainText(status, { timeout: 1000 });
      if (version) await expect(row).toContainText(`v${version}`, { timeout: 1000 });
    }).toPass({ timeout: 30_000, intervals: [1000, 2000] });
  }

  /** Vault sekmesinde dosya satırına tıklar; dosya detayı açılır. */
  async openVaultFileDetail(apiId, key) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.vaultFileRow(key).click();
    await expect(this.page.locator(`#policy-edit-${key}`)).toBeVisible({ timeout: 15_000 });
  }

  /**
   * Dosya detayındaki "Erişim politikası" kartı: içeriğe dokunmadan politikayı
   * ve şifreleme modunu değiştirir. Dönen değer toast metni.
   */
  async setVaultPolicy(apiId, key, { policy, encryption }) {
    await this.openVaultFileDetail(apiId, key);
    if (policy) await this.page.selectOption(`#policy-edit-${key}`, policy);
    if (encryption) await this.page.selectOption(`#encryption-edit-${key}`, encryption);
    const response = this.page.waitForResponse(
      (r) => r.url().includes(`/vault/${encodeURIComponent(key)}/policy`),
      { timeout: 20_000 },
    );
    await this.page.locator(`[data-action="saveVaultFilePolicy"][data-arg1="${key}"]`).click();
    const res = await response;
    if (!res.ok()) throw new Error(`Politika değiştirilemedi: HTTP ${res.status()} ${await res.text()}`);
    // Detay yeniden çizilince "Şu an" satırı yeni değerleri gösterir.
    await expect(this.page.locator(`#policy-edit-${key}`)).toHaveValue(policy, { timeout: 15_000 });
    return this.vaultPolicySummary(key);
  }

  /** Dosya detayındaki "Şu an: <politika> / <şifreleme>" değerleri. */
  async vaultPolicySummary(key) {
    return {
      policy: await this.page.locator(`#policy-edit-${key}`).inputValue(),
      encryption: await this.page.locator(`#encryption-edit-${key}`).inputValue(),
    };
  }

  /**
   * Config API → Genel sekmesindeki "vault aktif" anahtarı. Sunucunun yanıtını
   * ve toast'ı döndürür; hata durumunu çağıran değerlendirir (varsayılan Config
   * API veritabanında satır olarak bulunmadığı için orada 404 dönüyor).
   */
  async setVaultEnabled(apiId, enabled) {
    await this.openConfigApiTab(apiId, 'general');
    const box = this.page.locator(`#vault-enabled-${apiId}`);
    await expect(box).toBeVisible({ timeout: 15_000 });
    if ((await box.isChecked()) === enabled) return { status: null, body: '', toast: '' };
    const response = this.page.waitForResponse(
      (r) => r.url().includes('/vault-enabled') && r.request().method() === 'PUT',
      { timeout: 20_000 },
    );
    await box.setChecked(enabled);
    const res = await response;
    return { status: res.status(), body: (await res.text()).trim(), toast: await this.toastText() };
  }

  /** Vault sekmesindeki dört istatistik kartının değerleri. */
  async vaultStatCards(apiId) {
    await this.openConfigApiTab(apiId, 'vault');
    const cards = this.page.locator('.stats .card');
    await expect(cards.first()).toBeVisible({ timeout: 15_000 });
    const read = async (i) => ({
      value: (await cards.nth(i).locator('.stat-value').innerText()).trim(),
      label: (await cards.nth(i).locator('.stat-label').innerText()).trim(),
    });
    return { keys: await read(0), devices: await read(1), ok: await read(2), failed: await read(3) };
  }

  /**
   * "Başarılı"/"Başarısız" istatistik kartına tıklayarak dağıtım geçmişini
   * süzer. Aynı süzgeç ikinci kez tıklanınca kalkar (arayüzün davranışı).
   */
  async setVaultStatusFilter(apiId, status) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.page.locator(`[data-action="setVaultStatusFilter"][data-arg1="${status}"]`).first().click();
    await expect(this.page.locator('.card-title', { hasText: /Dağıtım Geçmişi|Distribution History/ }).first())
      .toBeVisible({ timeout: 15_000 });
  }

  /**
   * Vault sekmesindeki "Dağıtım Geçmişi" tablosunun görünen satırları
   * (süzgeç ve sayfalama uygulanmış hali).
   *
   * Sekmede iki tablo var; dağıtım tablosu sekiz sütunlu olan. Başlık metnine
   * göre seçmek arayüz diline bağımlı olurdu.
   */
  async vaultDistributionRows() {
    const rows = this.page.locator('table.data-table tbody tr');
    const out = [];
    for (let i = 0; i < (await rows.count()); i++) {
      const cells = rows.nth(i).locator('td');
      if ((await cells.count()) !== 8) continue;
      out.push({
        key: (await cells.nth(0).innerText()).trim(),
        version: (await cells.nth(1).innerText()).trim(),
        device: (await cells.nth(2).innerText()).trim(),
        status: (await cells.nth(3).innerText()).trim(),
        auth: (await cells.nth(4).innerText()).trim(),
        reason: (await cells.nth(5).innerText()).trim(),
      });
    }
    return out;
  }

  /** Dağıtım satırındaki cihaz rozetine tıklar; cihaz detayı açılır. */
  async openVaultDeviceDetail(apiId, deviceId) {
    await this.openConfigApiTab(apiId, 'vault');
    await this.page.locator(`[data-action="showDeviceDetail"][data-arg1="${deviceId}"]`).first().click();
    await expect(this.page.locator('.section-title-main')).toContainText('📱', { timeout: 15_000 });
    return (await this.page.locator('.section-sub').first().innerText()).trim();
  }

  // ── mTLS ─────────────────────────────────────────────────────────────

  /**
   * mTLS sekmesinde istemci kimliği için kayıt token'ı üretir ve döndürür.
   *
   * Sunucu artık token'ın yalnızca SHA-256 hash'ini saklıyor; düz metin
   * üretildiği anda tek seferlik bir dialog'da gösteriliyor ve listede yalnızca
   * maskeli önek görünüyor. Bu yüzden token tablodan değil dialog'dan okunuyor
   * — generateVaultToken ile aynı akış.
   *
   * "Cihaz kimliği (ANDROID_ID)" alanı varsayılan olarak test telefonundaki
   * uygulamanın ANDROID_ID'siyle doldurulur: token yalnızca o telefona çalışır
   * ve sunucu telefonun kimliğini kanıtlanmış sayar (token_mtls dosyaları,
   * mTLS üzerinden anahtar değişimi, host ACL'i, iptal bloğunun kalkması).
   * `{ deviceUid: null }` alanı boş bırakır (bağlanmamış token); bir dize
   * verilirse o yazılır.
   */
  async generateEnrollmentToken(apiId, clientId, { deviceUid } = {}) {
    const uid = deviceUid === undefined ? testDeviceUid() : deviceUid;
    await this.openConfigApiTab(apiId, 'mtls');
    await this.page.fill('#enrollment-client-id', clientId);
    await this.page.fill('#enrollment-device-uid', uid || '');
    const before = this.dialogs.length;
    await this.page.locator('form[data-action-submit="generateEnrollmentToken"] button[type="submit"]').click();
    await expect.poll(() => this.dialogs.length).toBeGreaterThan(before);
    // "…kopyalandı:\n\n<token>\n\nBu değer bir daha gösterilmeyecek…"
    const token = this.dialogs[this.dialogs.length - 1].split('\n\n')[1].trim();
    // Liste tazelendiğinde satır maskeli önekle görünür olmalı.
    await expect(
      this.page.locator('#enrollment-token-list tbody tr', { hasText: clientId }).first()
    ).toBeVisible();
    return token;
  }

  /**
   * mTLS sekmesi → "Kayıt politikaları": ad, en fazla cihaz, gün ve "Her cihaz
   * için onay iste" → "Politika oluştur". Kod yalnızca bu anda, QR'ıyla birlikte
   * gösterilir; kutudan okunup döndürülür.
   */
  async createEnrollmentPolicy(apiId, { name, maxDevices = 5, validDays = 1, requireApproval = true }) {
    await this.openConfigApiTab(apiId, 'mtls');
    await this.page.locator('#enrollment-policies-card').scrollIntoViewIfNeeded();
    await this.page.fill('#policy-name', name);
    await this.page.fill('#policy-max', String(maxDevices));
    await this.page.fill('#policy-days', String(validDays));
    const approval = this.page.locator('#policy-approval');
    if ((await approval.isChecked()) !== requireApproval) await approval.click();
    await this.page.locator('form[data-action-submit="createEnrollmentPolicy"] button[type="submit"]').click();
    const codeBox = this.page.locator('#policy-code-value');
    await expect(codeBox).toBeVisible({ timeout: 20_000 });
    await expect(this.policyRow(name)).toBeVisible();
    return (await codeBox.textContent()).trim();
  }

  policyRow(name) {
    return this.page.locator('#enrollment-policies-card tbody tr', { hasText: name }).first();
  }

  /** "Onay bekleyen cihazlar" kartındaki satır. Kart açıkken 10 sn'de bir kendiliğinden tazelenir. */
  enrollmentRequestRow(text) {
    return this.page.locator('#enrollment-requests-card tbody tr', { hasText: text }).first();
  }

  async approveEnrollmentRequest(text) {
    const row = this.enrollmentRequestRow(text);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.locator('[data-action="approveEnrollmentRequest"]').click();
    // Satır "Onaylandı" olur; cihaz sertifikasını aldığında kart tazelenince kalkar.
    await expect
      .poll(async () => ((await this.enrollmentRequestRow(text).count()) === 0 ? 'alındı' : await this.enrollmentRequestRow(text).textContent()), { timeout: 20_000 })
      .toMatch(/Onaylandı|Approved|alındı/);
  }

  async rejectEnrollmentRequest(text) {
    const row = this.enrollmentRequestRow(text);
    await expect(row).toBeVisible({ timeout: 30_000 });
    await row.locator('[data-action="rejectEnrollmentRequest"]').click();
    await expect(this.enrollmentRequestRow(text)).toHaveCount(0, { timeout: 20_000 });
  }

  async stopEnrollmentPolicy(name) {
    await this.policyRow(name).locator('[data-action="stopEnrollmentPolicy"]').click();
    await expect(this.policyRow(name)).toContainText(/Durduruldu|Stopped/, { timeout: 20_000 });
  }

  /**
   * "Onay bekleyen cihazlar" kartındaki "Kodsuz başvurular" anahtarı: açıkken
   * cihazlar token ya da kod girmeden başvurabilir, hepsi onay bekler.
   */
  async setOpenApplications(apiId, enabled) {
    await this.openConfigApiTab(apiId, 'mtls');
    const toggle = this.page.locator('#open-applications-switch');
    await expect(toggle).toBeVisible({ timeout: 20_000 });
    if ((await toggle.isChecked()) !== enabled) await toggle.click();
    // Görünüm sunucunun cevabıyla yeniden çizilir.
    await expect(this.page.locator('#open-applications-switch')).toBeChecked({ checked: enabled, timeout: 20_000 });
  }

  /** Sayfadaki tek bir öğenin görüntüsü dosyaya (ör. QR'ı okutmak için). */
  async elementScreenshot(selector, path) {
    await this.page.locator(selector).first().screenshot({ path });
    return path;
  }

  /** Sayfadaki tek bir öğenin görüntüsü rapora (kart, satır). */
  async snapElement(title, selector) {
    // Kartlar sunucu cevabıyla yeniden çizilebiliyor; öğe o anda DOM'dan
    // koparsa konumlayıcı yeniden çözülüp tekrar denenir.
    let body;
    for (let attempt = 0; ; attempt++) {
      try {
        const target = this.page.locator(selector).first();
        await target.waitFor({ state: 'visible', timeout: 10_000 });
        await target.scrollIntoViewIfNeeded();
        body = await target.screenshot();
        break;
      } catch (e) {
        if (attempt >= 4 || !/not attached|detached/i.test(String(e.message))) throw e;
        await this.page.waitForTimeout(300);
      }
    }
    await this.testInfo.attach(attachmentName('🌐', title), { body, contentType: 'image/png' });
  }

  /**
   * mTLS sekmesinde istemci sertifikası üretir (P12 tarayıcıya iner).
   * [saveTo] verilirse inen dosya oraya kaydedilir ve yol döndürülür.
   */
  async generateClientCert(apiId, clientId, { saveTo } = {}) {
    await this.openConfigApiTab(apiId, 'mtls');
    await this.page.fill('#mtls-client-id', clientId);
    const download = this.page.waitForEvent('download', { timeout: 30_000 }).catch(() => null);
    await this.page.locator('form[data-action-submit="generateClientCert"] button[type="submit"]').click();
    const file = await download;
    await expect(this.clientCertRow(clientId)).toBeVisible({ timeout: 20_000 });
    if (!saveTo) return null;
    if (!file) throw new Error(`P12 indirilemedi: ${clientId}`);
    await file.saveAs(saveTo);
    return saveTo;
  }

  /**
   * mTLS sekmesindeki "Client Cert Yükle": dışarıdan üretilmiş PEM/DER bir
   * istemci sertifikasını truststore'a ekler (özel anahtar sunucuya gitmez).
   */
  async uploadTrustedClientCert(apiId, clientId, certPath) {
    await this.openConfigApiTab(apiId, 'mtls');
    await this.page.fill('#mtls-client-id', clientId);
    const response = this.page.waitForResponse((r) => r.url().includes('/api/v1/client-certs/upload'), { timeout: 30_000 });
    await this.page.setInputFiles('#mtls-upload-file', certPath);
    const res = await response;
    const body = (await res.text()).trim();
    await expect(this.clientCertRow(clientId)).toBeVisible({ timeout: 20_000 });
    return `HTTP ${res.status()} ${body}`;
  }

  /**
   * mTLS sekmesini yeniden çizer. [openConfigApiTab] her çağrıda ağaç
   * başlığına da tıklıyor; aynı Config API için ikinci çağrıda bu ağacı
   * kapatıyor ve iki ayrı `renderConfigApiDetail` yarışıyor. Sekme çubuğu
   * zaten ekrandaysa yalnızca sekme düğmesine tıklamak hem yeterli hem güvenli.
   */
  async refreshMtlsSection(apiId) {
    const tabBtn = this.page.locator(
      `button.tab-btn[data-action="setConfigApiTab"][data-arg0="mtls"][data-arg1="${apiId}"]`,
    );
    if (await tabBtn.count()) await tabBtn.click();
    else await this.openConfigApiTab(apiId, 'mtls');
    await expect(this.page.locator('#enrollment-client-id')).toBeVisible({ timeout: 20_000 });
  }

  /**
   * Kayıt token'ı listesindeki satırın metni (maskeli token, istemci, durum).
   *
   * Ekrandaki satırı okur, sekmeyi tazelemez: satır "Token Üret"ten hemen
   * sonraki hâlini gösterir. Sunucudaki güncel durumu (ör. sonradan süresi
   * dolmuş bir token) görmek isteyen çağıran önce [refreshMtlsSection]
   * çağırmalı.
   */
  async enrollmentTokenCells(clientId) {
    const row = this.page.locator('#enrollment-token-list tbody tr', { hasText: clientId }).first();
    await expect(row).toBeVisible({ timeout: 20_000 });
    return (await row.innerText()).replace(/\s*\n\s*/g, ' | ').trim();
  }

  /** Kayıt token'ı listesindeki satır sayısı (0 = liste boş / çizilmemiş). */
  async enrollmentTokenRowCount() {
    return this.page.locator('#enrollment-token-list tbody tr').count();
  }

  /** İstemci sertifikaları tablosundaki satır (token listesi hariç). */
  clientCertRow(clientId) {
    return this.page.locator('.card > table.data-table > tbody > tr', { hasText: clientId }).first();
  }

  async expectClientCert(apiId, clientId, { revoked }) {
    await expect(async () => {
      await this.openConfigApiTab(apiId, 'mtls');
      const row = this.clientCertRow(clientId);
      await expect(row).toBeVisible({ timeout: 1000 });
      await expect(row.locator('[data-action="revokeClientCert"]')).toHaveCount(revoked ? 0 : 1, { timeout: 1000 });
    }).toPass({ timeout: 30_000, intervals: [1000, 2000] });
  }

  async revokeClientCert(apiId, clientId) {
    await this.openConfigApiTab(apiId, 'mtls');
    await this.clientCertRow(clientId).locator('[data-action="revokeClientCert"]').click();
    await expect(this.clientCertRow(clientId).locator('[data-action="revokeClientCert"]')).toHaveCount(0);
  }

  /**
   * İptal edilmiş satırdaki "Kimliği unut" (onay penceresi kabul edilir):
   * satır listeden kalkar, aynı kimlikle yeniden kayıt olunabilir.
   */
  async forgetClientIdentity(apiId, clientId) {
    await this.openConfigApiTab(apiId, 'mtls');
    await this.clientCertRow(clientId).locator('[data-action="forgetClientIdentity"]').click();
    await expect(this.clientCertRow(clientId)).toHaveCount(0, { timeout: 20_000 });
  }

  // ── Host sertifikası ve bootstrap sertifikası yükleme ────────────────

  /**
   * Host detayı → Sertifika kartı → "JKS Yükle": var olan host'un sertifikası
   * diskteki JKS/P12 ile değiştirilir (POST …/hosts/{host}/upload-cert). Pin
   * sürümü artar, çalışan mock dinleyici yeni keystore ile yeniden başlar.
   * Sunucunun yanıtını ({ status, body, json }) döndürür.
   */
  async uploadHostCert(host, filePath, password = 'changeit') {
    await this.openHost(host);
    const button = this.page.locator(`[data-action="showCertUploadForm"][data-arg0="${host}"]`).first();
    await expect(button).toBeVisible({ timeout: 20_000 });
    await button.click();
    await this.page.setInputFiles('#renew-cert-file', filePath);
    await this.page.fill('#renew-cert-password', password);
    const response = this.page.waitForResponse((r) => r.url().includes('/upload-cert'), { timeout: 60_000 });
    await this.page.locator('form[data-action-submit="renewCertUpload"] button[type="submit"]').click();
    const res = await response;
    const body = (await res.text()).trim();
    if (!res.ok()) throw new Error(`Sertifika yüklenemedi (${host}): HTTP ${res.status()} ${body}`);
    let json;
    try {
      json = JSON.parse(body);
    } catch {
      json = null;
    }
    return { status: res.status(), body, json };
  }

  /**
   * Config API → Bootstrap sekmesi → "JKS Yükle": sunucunun kendi TLS
   * sertifikası yüklenen anahtar çiftine geçer (POST /api/v1/server-tls-pins/
   * upload). Yanıt restartRequired döner; dinleyiciler yeniden başlatılmalı.
   */
  async uploadBootstrapCert(apiId, filePath, password = 'changeit') {
    await this.openConfigApiTab(apiId, 'bootstrap');
    await this.page.locator('[data-action="toggleBootstrapUpload"]').first().click();
    await this.page.setInputFiles('#bootstrap-file', filePath);
    await this.page.fill('#bootstrap-password', password);
    const response = this.page.waitForResponse((r) => r.url().includes('/server-tls-pins/upload'), { timeout: 60_000 });
    await this.page.locator('form[data-action-submit="uploadBootstrapCert"] button[type="submit"]').click();
    const res = await response;
    const body = (await res.text()).trim();
    if (!res.ok()) throw new Error(`Sunucu sertifikası (bootstrap) yüklenemedi: HTTP ${res.status()} ${body}`);
    let json;
    try {
      json = JSON.parse(body);
    } catch {
      json = null;
    }
    // Sekme yeni pin'lerle yeniden çizilir.
    await expect(this.page.locator('.hash-box span').first()).toBeVisible({ timeout: 20_000 });
    return { status: res.status(), body, json };
  }

  // ── Kanıt ────────────────────────────────────────────────────────────

  async snap(title) {
    await this.testInfo.attach(attachmentName('🌐', title), {
      body: await this.page.screenshot({ fullPage: true }),
      contentType: 'image/png',
    });
  }

  /**
   * Toast (işlem sonucu) ekrandayken sayfa görüntüsü. Toast sağ altta sabit
   * konumlu ve kayarak beliriyor (slideIn: opacity 0 → 1); görünür olduğu
   * anda çekilen görüntüde henüz saydam kalıyordu. Animasyon bitene (opacity
   * 1) kadar beklenir, sonra çekilir; toast üç saniye ekranda kalıyor.
   */
  async snapWithToast(title, timeout = 5000) {
    const toast = this.page.locator('.toast').last();
    await expect(toast).toBeVisible({ timeout });
    await expect
      .poll(() => toast.evaluate((el) => getComputedStyle(el).opacity).catch(() => '0'), { timeout: 2000 })
      .toBe('1');
    await this.testInfo.attach(attachmentName('🌐', title), {
      body: await this.page.screenshot({ fullPage: true }),
      contentType: 'image/png',
    });
  }

  /**
   * [fromSelector] ile [toSelector] arasındaki bölgeyi (ikisi dahil) tek
   * görüntü olarak çeker. Sayfa pencere düzeyinde kaymadığı için (gövde
   * overflow:hidden) fullPage+clip kullanılamıyor; eleman görüntüsü ise uzun
   * elemanları da bütünüyle çekebiliyor. Bu yüzden kapsayıcının aralık
   * dışındaki doğrudan çocukları görüntü süresince gizlenir, kapsayıcı
   * çekilir, gizlenenler geri açılır. Sayfaya kalıcı hiçbir şey yapılmaz.
   */
  async snapRange(fromSelector, toSelector, title, { container = '#content' } = {}) {
    await expect(this.page.locator(fromSelector).first()).toBeVisible({ timeout: 20_000 });
    await expect(this.page.locator(toSelector).first()).toBeVisible({ timeout: 20_000 });
    const hide = () =>
      this.page.evaluate(
        ([a, b, c]) => {
          const root = document.querySelector(c);
          const from = document.querySelector(a);
          const to = document.querySelector(b);
          if (!root || !from || !to) return 0;
          const childOf = (el) => {
            let x = el;
            while (x && x.parentElement !== root) x = x.parentElement;
            return x;
          };
          const kids = [...root.children];
          const i0 = kids.indexOf(childOf(from));
          const i1 = kids.indexOf(childOf(to));
          if (i0 < 0 || i1 < 0) return 0;
          let hidden = 0;
          kids.forEach((k, i) => {
            if (i >= Math.min(i0, i1) && i <= Math.max(i0, i1)) return;
            k.dataset.e2eHidden = k.style.display || '';
            k.style.display = 'none';
            hidden += 1;
          });
          return hidden;
        },
        [fromSelector, toSelector, container],
      );
    const restore = () =>
      this.page.evaluate(() => {
        document.querySelectorAll('[data-e2e-hidden]').forEach((k) => {
          k.style.display = k.dataset.e2eHidden;
          delete k.dataset.e2eHidden;
        });
      });
    const shoot = async () => {
      await hide();
      try {
        return await this.page.locator(container).screenshot();
      } finally {
        await restore();
      }
    };
    let body;
    try {
      body = await shoot();
    } catch {
      // Kapsayıcı o anda yeniden çizilmiş olabilir; bir kez daha dene.
      await this.page.waitForTimeout(1500);
      body = await shoot();
    }
    await this.testInfo.attach(attachmentName('🌐', title), { body, contentType: 'image/png' });
  }

  /** Host sayfası özeti: host adı, sürüm/pin sayısı/force kartları, sertifika bilgisi ve pin listesi. */
  async snapHostSummary(title) {
    await this.snapRange('.section-header', '#pins-card', title);
  }

  /** Vault dosya detayı: dosya adı başlığı + erişim politikası / şifreleme kartı. */
  async snapVaultPolicy(title) {
    await this.snapRange('.section-header', '.card:has([data-action="saveVaultFilePolicy"])', title);
  }

  /** mTLS sekmesindeki istemci sertifikaları tablosunun kartı (token listesi değil). */
  async snapClientCertTable(title) {
    await this.snapCard('.card:has(> table.data-table)', title);
  }

  /**
   * Kayıt token'ı listesi: sekme tazelenir, [rows] içindeki her satırın
   * ({ clientId, status }) listede ve beklenen durumda olduğu doğrulanır,
   * liste kartı çekilir. Liste sayfalanmıyor ve koşular arasında yüzlerce
   * satır birikiyor (bu koşunun satırları en üstte); en yeni birkaç satır ve
   * beklenen satırlar dışındakiler görüntü süresince gizlenir.
   */
  async snapTokenList(apiId, title, rows = []) {
    await this.refreshMtlsSection(apiId);
    const list = this.page.locator('#enrollment-token-list').first();
    for (const { clientId, status } of rows) {
      const row = list.locator('tbody tr', { hasText: clientId }).first();
      await expect(row).toBeVisible({ timeout: 20_000 });
      if (status) await expect(row).toContainText(status, { timeout: 20_000 });
    }
    const KEEP = 6;
    const kept = await this.page.evaluate(
      ([ids, keep]) => {
        const trs = [...document.querySelectorAll('#enrollment-token-list tbody tr')];
        let shown = 0;
        trs.forEach((tr, i) => {
          const mine = ids.some((id) => tr.textContent.includes(id));
          if (i < keep || mine) {
            shown += 1;
            return;
          }
          tr.dataset.e2eHidden = tr.style.display || '';
          tr.style.display = 'none';
        });
        return { total: trs.length, shown };
      },
      [rows.map((r) => r.clientId), KEEP],
    );
    try {
      await this.snapCard('.card:has(#enrollment-token-list)', `${title} (en yeni ${kept.shown} / ${kept.total} satır)`);
    } finally {
      await this.page.evaluate(() => {
        document.querySelectorAll('#enrollment-token-list tbody tr[data-e2e-hidden]').forEach((tr) => {
          tr.style.display = tr.dataset.e2eHidden;
          delete tr.dataset.e2eHidden;
        });
      });
    }
  }

  async snapCard(selector, title) {
    // Kart, kaydetme/yenileme sonrası yeniden çizilebiliyor; o anda alınan
    // görüntü "element is not attached to the DOM" ile düşüyordu. Bir kez
    // bekleyip tekrar denenir.
    const shoot = async () => {
      const element = this.page.locator(selector).first();
      await element.scrollIntoViewIfNeeded();
      return element.screenshot();
    };
    let body;
    try {
      body = await shoot();
    } catch {
      await this.page.waitForTimeout(1500);
      body = await shoot();
    }
    await this.testInfo.attach(attachmentName('🌐', title), { body, contentType: 'image/png' });
  }
}

module.exports = { Dashboard, attachmentName };
