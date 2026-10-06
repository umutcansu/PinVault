// sample-client'ın ekranları için sayfa nesnesi. Düğmelere basar, durum
// kutularını ve olay listesini okur, her adımın ekran görüntüsünü rapora ekler.
//
// Ekranlar: ana ekran, mTLS, Vault, Depolama, Ayarlar. Uygulama modu
// (AppSettings.Mode) Ayarlar ekranından ya da açılışta intent ekiyle seçilir.
//
// Android ve iOS'ta aynı: görünüm kimlikleri (Android resource-id = iOS
// accessibilityIdentifier), Türkçe metinler ve "#<sıra> · saat" damgası
// ortak; dokunma, yazma, açma/kapama cihaz nesnesinden (lib/device.js) geçer.
const { APP_ID, VAULT_KEYS, SCREEN_LOCK_PIN, UNLOCK_PROMPT_TITLE } = require('./env');
const { sleep } = require('./device');
const { attachmentName } = require('./dashboard');

const RESULT = {
  request: /(bağlantı başarılı|Bağlantı başarısız|bağlantı başarısız|istemci bağlandı|istemci başarısız)/,
  refresh: /(Yeni config uygulandı|Config güncel|Config yenilenemedi|zaman aşımına uğradı)/,
  // Atestasyon düğmesi: geçti / kaldı / yapılamadı / backend desteklemiyor.
  attest: /(Atestasyon geçti|Atestasyon KALDI|Atestasyon yapılamadı|backend desteklemiyor)/,
  enroll: /(Kayıt başarılı|Kayıt başarısız|Önce kayıt token)/,
  // Onay isteyen bir kayıt kodu: sonuç gelmeden önce ekranda kalan ara metin.
  enrollPending: /Onay bekleniyor/,
  autoEnroll: /(Otomatik kayıt başarılı|Otomatik kayıt reddedildi|Otomatik kayıt yapılamadı)/,
  mtls: /(mTLS bağlantısı başarılı|mTLS bağlantısı reddedildi)/,
  mock: /(host bağlantısı başarılı|host bağlantısı reddedildi)/,
  unenroll: /(Kayıt silindi|başlatılamadı)/,
  p12: /(P12 içe aktarıldı|P12 bulunamadı|Elle P12 bırakıldı|P12 açılamadı|P12 parolasını gir)/,
  vault: /( indirildi| güncel \(v| indirilemedi)/,
  // "Aç": açıldı / vazgeçildi / açılamadı; anahtar geçersiz ya da kopya yoksa yeniden indirme sonucu.
  vaultUnlock: /( açıldı\n| açılmadı| açılamadı| indirildi| güncel \(v| indirilemedi)/,
  vaultInfo: /ℹ️ /,
  vaultClear: / silindi/,
  vaultSync: /(Eşitleme tamamlandı|Eşitlenecek dosya yok)/,
  token: /Token kaydedildi/,
  // "Sıfırla" sonucu iki satırdan oluşur: "PinVault sıfırlandı" + pinli istek
  // denemesi ("Pinli istek reddedildi" ya da "İSTEK GEÇTİ"). Büyük/küçük harf
  // farkı için [Ss]: "Sıfırlandı ve yeniden başlatıldı" ve "PinVault sıfırlandı".
  settings: /([Ss]ıfırland[ıi]|Ayarlar uygulandı|init tekrar çağrıldı|init çağrıldı|Planlı işler|planlı iş yok|iptal edildi|planlandı|istemci bağlandı|istemci başarısız|İSTEK GEÇTİ)/,
};

const VAULT_BUTTONS = {
  [VAULT_KEYS.flags]: 'fetchFlagsButton',
  [VAULT_KEYS.secret]: 'fetchSecretButton',
  [VAULT_KEYS.e2e]: 'fetchE2eButton',
  [VAULT_KEYS.atrest]: 'fetchAtRestButton',
  [VAULT_KEYS.admin]: 'fetchAdminButton',
  [VAULT_KEYS.model]: 'fetchModelButton',
  [VAULT_KEYS.mtlsSecret]: 'fetchMtlsSecretButton',
};

const MODE_RADIOS = {
  TLS: 'modeTls',
  MTLS_CONFIG: 'modeMtlsConfig',
  CUSTOM_BACKEND: 'modeCustomBackend',
  EMBEDDED_API: 'modeEmbeddedApi',
  STATIC: 'modeStatic',
};

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

class SampleApp {
  constructor(device, testInfo) {
    this.device = device;
    this.testInfo = testInfo;
  }

  // ── Uygulama yaşam döngüsü ────────────────────────────────────────────

  /**
   * Uygulama verisini siler ve baştan açar: saklı config, sertifika, olay
   * listesi ve ayarlar (mod) yok. [mode] verilirse o modda açılır.
   */
  launchFresh({ mode } = {}) {
    this.device.launchApp(mode, { keepData: false });
  }

  /** Uygulamayı kapatıp açar; saklı config, sertifika ve ayarlar korunur. */
  relaunch({ mode } = {}) {
    this.device.launchApp(mode, { keepData: true });
  }

  start(mode) {
    this.device.startApp(mode);
  }

  // ── Okuma ────────────────────────────────────────────────────────────

  node(name) {
    const id = this.device.viewId(name, APP_ID);
    return this.device.uiNodes().find((n) => n.id === id) || null;
  }

  text(name) {
    return (this.node(name) || {}).text || '';
  }

  status() {
    return this.text('statusView');
  }

  eventLog() {
    return this.text('eventLogView');
  }

  async waitFor(name, predicate, { timeout = 30_000, what = name } = {}) {
    const deadline = Date.now() + timeout;
    let last = null;
    // Görünmeyen (ekran dışı, klavyenin altında kalan) düğümler UI dökümüne
    // girmez. Bulunamazsa önce klaviyeyi kapat, sonra ekranı kaydırarak ara.
    const recover = [() => this.dismissIme(), () => this.device.swipeVertical('down'), () => this.device.swipeVertical('up')];
    let recovery = 0;
    while (Date.now() < deadline) {
      last = this.node(name);
      if (last && predicate(last)) return last;
      if (!last && recovery < recover.length) {
        recover[recovery]();
        recovery += 1;
      }
      await sleep(700);
    }
    throw new Error(`Mobil: "${what}" beklenen duruma gelmedi.\nSon metin:\n${last ? last.text : '(görünüm yok)'}`);
  }

  async waitReady() {
    const node = await this.waitFor(
      'statusView',
      (n) => /Hazır — config v\d+/.test(n.text) || n.text.includes('başlatılamadı'),
      { timeout: 60_000, what: 'PinVault hazır' },
    );
    if (node.text.includes('başlatılamadı')) throw new Error(`Mobil: PinVault başlatılamadı\n${node.text}`);
    return node.text;
  }

  async waitInitFailed() {
    return (await this.waitFor('statusView', (n) => n.text.includes('başlatılamadı'), {
      timeout: 60_000,
      what: 'başlatma hatası',
    })).text;
  }

  async waitForEvent(fragment, timeout = 20_000) {
    return (await this.waitFor('eventLogView', (n) => n.text.includes(fragment), {
      timeout,
      what: `olay listesinde "${fragment}"`,
    })).text;
  }

  /** Durum kutusunun altındaki "#<n> · saat" sırası; sonuç yoksa 0. */
  static seqOf(text) {
    const m = text.match(/#(\d+) · \d\d:\d\d:\d\d\s*$/);
    return m ? Number(m[1]) : 0;
  }

  /** Durum metnindeki "• host → pin vN" satırından N; host yoksa null. */
  static hostVersion(text, host) {
    const m = text.match(new RegExp(`${escapeRegExp(host)} → pin v(\\d+)`));
    return m ? Number(m[1]) : null;
  }

  /** Durum metnindeki "Mod: …" etiketi. */
  /**
   * Durum ya da "config yenile" metnindeki imza satırı:
   * { required, trusted, keySetVersion, signedBy: ['abc123def456…', …] } ya da null.
   */
  static signingOf(text) {
    const m = /🔏 İmza: (\d+) imza gerekli · (\d+) güvenilen anahtar · anahtar seti v(\d+)\s*\nSon config'i imzalayan: ([^\n]*)/.exec(text || '');
    if (!m) return null;
    const signedBy = m[4].trim() === '—' ? [] : m[4].split(',').map((s) => s.trim().replace(/…$/, ''));
    return { required: Number(m[1]), trusted: Number(m[2]), keySetVersion: Number(m[3]), signedBy };
  }

  /**
   * Depolama ekranındaki "== İmza doğrulaması (PinVault.signingStatus) =="
   * bölümü: { required, keySetVersion, fromServer, trusted: [tam kimlik…],
   * recovery: [...], lastSignedBy: [...], text } ya da null.
   */
  static signingDetailOf(storage) {
    const start = (storage || '').indexOf('== İmza doğrulaması');
    if (start < 0) return null;
    const rest = storage.slice(start);
    const end = rest.indexOf('\n\n==');
    const text = (end < 0 ? rest : rest.slice(0, end)).trim();
    const head = /gereken imza: (\d+), anahtar seti: v(\d+)/.exec(text);
    const list = (label) => {
      const m = new RegExp(`${label}:[^\\n]*\\n((?:\\s+• [^\\n]+\\n?)*)`).exec(text);
      return m ? m[1].split('\n').map((l) => l.replace(/^\s*•\s*/, '').trim()).filter(Boolean) : [];
    };
    const signed = /son config'i imzalayan: ([^\n]*)/.exec(text);
    return {
      required: head ? Number(head[1]) : null,
      keySetVersion: head ? Number(head[2]) : null,
      fromServer: /sunucudan gelen/.test(text),
      trusted: list('güvenilen anahtarlar'),
      recovery: list('kurtarma anahtarları'),
      lastSignedBy: !signed || signed[1].trim() === '—' ? [] : signed[1].split(',').map((s) => s.trim()),
      text,
    };
  }

  static modeOf(text) {
    const m = text.match(/Mod: ([^\n]+)/);
    return m ? m[1].trim() : null;
  }

  // ── Dokunma ──────────────────────────────────────────────────────────

  async tapButton(name) {
    const node = await this.waitFor(name, (n) => n.enabled, { what: `${name} etkin` });
    this.device.tapNode(node);
  }

  /** Alanı boşaltır (imleç sona, mevcut metin kadar silme). */
  async clearText(name) {
    const node = await this.waitFor(name, (n) => n.enabled, { what: `${name} etkin` });
    await this.device.clearField(node);
  }

  async enterText(name, value) {
    const node = await this.waitFor(name, (n) => n.enabled, { what: `${name} etkin` });
    await this.device.setFieldText(node, value);
    // Parola alanında (token girişleri textPassword) döküm metni "•" dizisi:
    // yazılanın kendisi okunamaz, uzunluk eşitliği doğrulama sayılır.
    await this.waitFor(name, (n) => n.text === value || (n.password && n.text.length === value.length), {
      what: `${name} içeriği`,
    });
    // Klavye açık kalırsa alttaki düğmeler ve sonuç kutusu UI dökümüne girmez.
    this.dismissIme();
  }

  /** Yazılım klavyesini kapatır. Klavye açık değilse hiçbir şey yapmaz. */
  dismissIme() {
    return this.device.hideIme();
  }

  async setChecked(name, value) {
    const node = await this.waitFor(name, (n) => n.enabled, { what: `${name} etkin` });
    if (node.checked !== value) this.device.tapNode(node);
    await this.waitFor(name, (n) => n.checked === value, { what: `${name} = ${value}` });
  }

  async press(button, resultPattern, what, timeout = 45_000) {
    const before = SampleApp.seqOf(this.status());
    await this.tapButton(button);
    const result = await this.waitFor(
      'statusView',
      (n) => SampleApp.seqOf(n.text) > before && resultPattern.test(n.text),
      { timeout, what },
    );
    return result.text;
  }

  // ── Ana ekran ────────────────────────────────────────────────────────

  testLibraryClient() {
    return this.press('testButton', RESULT.request, 'library client sonucu');
  }

  testProductionStyle() {
    return this.press('prodStyleButton', RESULT.request, 'production-style client sonucu');
  }

  refreshConfig() {
    return this.press('refreshButton', RESULT.refresh, 'config yenileme sonucu');
  }

  /**
   * Ana ekrandaki atestasyon düğmesi: raporu şimdi gönderir, token alır ve
   * token'lı isteği mock TLS host'a atar; sonuç metnini döndürür.
   */
  attest() {
    return this.press('attestButton', RESULT.attest, 'atestasyon sonucu', 60_000);
  }

  /**
   * Başlatma hatasından sonra ana ekrandaki "Tekrar dene" (aynı düğme): init
   * baştan çalışır. Durum "Hazır" olana kadar bekler ve metni döndürür; yeni
   * bir hata gelirse onunla düşer.
   */
  async retryInit() {
    await this.backToMain();
    const failed = this.status();
    await this.tapButton('refreshButton');
    const node = await this.waitFor(
      'statusView',
      (n) => /Hazır — config v\d+/.test(n.text) || (n.text.includes('başlatılamadı') && n.text !== failed),
      { timeout: 90_000, what: '"Tekrar dene" sonrası Hazır' },
    );
    if (!/Hazır — config v\d+/.test(node.text)) throw new Error(`Mobil: tekrar denemede de başlatılamadı\n${node.text}`);
    return node.text;
  }

  // Ekran açma yardımcıları, ekran zaten açıksa hiçbir şey yapmaz: art arda
  // iki adımda aynı ekranı kullanan senaryolar araya backToMain koymak zorunda
  // kalmasın (ana ekrana dönülmediğinde "vaultButton" UI dökümünde olmadığı
  // için ikinci çağrı düşüyordu).

  async openMtls() {
    if (this.node('enrollButton')) return;
    await this.tapButton('mtlsButton');
    await this.waitFor('enrollButton', () => true, { what: 'mTLS ekranı' });
  }

  async openVault() {
    if (this.node('fetchFlagsButton')) return;
    await this.tapButton('vaultButton');
    await this.waitFor('fetchFlagsButton', () => true, { what: 'Vault ekranı' });
  }

  async openStorage() {
    if (!this.node('storageView')) await this.tapButton('storageButton');
    await this.waitFor('storageView', (n) => n.text && !n.text.startsWith('Okunuyor'), {
      what: 'Depolama ekranı',
    });
  }

  async openSettings() {
    if (this.node('applyButton')) return;
    await this.tapButton('settingsButton');
    await this.waitFor('applyButton', () => true, { what: 'Ayarlar ekranı' });
  }

  async backToMain() {
    for (let i = 0; i < 4; i++) {
      if (this.node('mtlsButton')) return;
      this.device.pressBack();
      await sleep(800);
    }
    if (!this.node('mtlsButton')) throw new Error('Mobil: ana ekrana dönülemedi');
  }

  // ── Ayarlar ekranı ───────────────────────────────────────────────────

  /** Modu seçer, "Uygula" ile PinVault'u yeniden kurar; sonuç metnini döndürür. */
  async applyMode(mode) {
    await this.tapButton(MODE_RADIOS[mode]);
    return this.press('applyButton', RESULT.settings, `mod ${mode} uygulandı`, 90_000);
  }

  /**
   * "Yalnızca hedef host'un pin'lerini iste" anahtarı (wantPinsFor) ve
   * "Uygula": PinVault bu ayarla yeniden kurulur. Sonuç metnini döndürür.
   */
  async setScopedPins(enabled) {
    await this.setChecked('scopedPinsCheck', enabled);
    return this.press('applyButton', RESULT.settings, `pin kapsamı ${enabled ? 'açık' : 'kapalı'}`, 90_000);
  }

  /**
   * "İki imza iste" (m-of-n: requiredSignatures=2) ve "Uygula": PinVault bu
   * ayarla yeniden kurulur. Sonuç metnini döndürür ("Gereken imza: 2").
   */
  async setTwoSignatures(enabled) {
    await this.setChecked('twoSignaturesCheck', enabled);
    return this.press('applyButton', RESULT.settings, `gereken imza ${enabled ? 2 : 1}`, 90_000);
  }

  async setTelemetry({ reportSuccess = true, dedupMs = 0 } = {}) {
    await this.setChecked('reportSuccessCheck', reportSuccess);
    await this.enterText('dedupMsInput', String(dedupMs));
    return this.press('applyButton', RESULT.settings, 'cihaz raporu (telemetri) ayarı uygulandı', 90_000);
  }

  settingsClientTest() {
    return this.press('settingsClientButton', RESULT.settings, 'özel ayarlı istemci sonucu');
  }

  resetAndProbe() {
    return this.press('resetButton', RESULT.settings, 'sıfırlama sonucu');
  }

  reinit() {
    return this.press('reinitButton', RESULT.settings, 'init tekrar sonucu', 90_000);
  }

  restart() {
    return this.press('restartButton', RESULT.settings, 'yeniden başlatma sonucu', 90_000);
  }

  workInfo() {
    return this.press('workInfoButton', RESULT.settings, 'planlı iş bilgisi');
  }

  cancelWork() {
    return this.press('cancelWorkButton', RESULT.settings, 'iş iptali');
  }

  scheduleWork() {
    return this.press('scheduleWorkButton', RESULT.settings, 'iş planlama');
  }

  // ── Depolama ekranı ──────────────────────────────────────────────────

  async storageText() {
    return (await this.waitFor('storageView', (n) => n.text && !n.text.startsWith('Okunuyor'), {
      what: 'depolama dökümü',
    })).text;
  }

  async refreshStorage() {
    await this.tapButton('refreshStorageButton');
    await sleep(500);
    return this.storageText();
  }

  // ── mTLS ekranı ──────────────────────────────────────────────────────

  enrollState() {
    return this.text('enrollStateView');
  }

  async enroll(token) {
    await this.enterText('tokenInput', token);
    return this.press('enrollButton', RESULT.enroll, 'kayıt sonucu');
  }

  /**
   * Onay isteyen bir politikanın kayıt kodu: düğmeye basar ve ekranda "Onay
   * bekleniyor" görünene kadar bekler (bu ara metnin sıra damgası yok). Sonuç
   * — yönetici onaylayınca ya da reddedince — [awaitEnrollResult] ile okunur.
   */
  async enrollAwaitingApproval(code) {
    await this.enterText('tokenInput', code);
    this.pendingSeq = SampleApp.seqOf(this.status());
    await this.tapButton('enrollButton');
    const node = await this.waitFor('statusView', (n) => RESULT.enrollPending.test(n.text), { what: 'onay bekleniyor' });
    return node.text;
  }

  /**
   * Kodsuz başvuru: "Otomatik kayıt" — token ya da kod girilmez. Sunucu kodsuz
   * başvuruları açtıysa ekranda "Onay bekleniyor", kimlik ve doğrulama kodu
   * görünür; sonuç [awaitEnrollResult] ile okunur.
   */
  async autoEnrollAwaitingApproval() {
    this.pendingSeq = SampleApp.seqOf(this.status());
    await this.tapButton('autoEnrollButton');
    const node = await this.waitFor('statusView', (n) => RESULT.enrollPending.test(n.text), { what: 'onay bekleniyor (kodsuz)' });
    return node.text;
  }

  /** Onay bekleyen kaydın sonucu: uygulama birkaç saniyede bir sorar ve kendiliğinden yazar. */
  async awaitEnrollResult(timeout = 60_000) {
    const before = this.pendingSeq ?? -1;
    const node = await this.waitFor('statusView', (n) => SampleApp.seqOf(n.text) > before && RESULT.enroll.test(n.text), {
      timeout,
      what: 'kayıt sonucu (yönetici kararından sonra)',
    });
    return node.text;
  }

  autoEnroll() {
    return this.press('autoEnrollButton', RESULT.autoEnroll, 'otomatik kayıt sonucu');
  }

  mtlsTest() {
    return this.press('mtlsTestButton', RESULT.mtls, 'mTLS test sonucu');
  }

  mockTls() {
    return this.press('mockTlsButton', RESULT.mock, 'mock TLS host sonucu');
  }

  mockMtls() {
    return this.press('mockMtlsButton', RESULT.mock, 'mock mTLS host sonucu');
  }

  /**
   * mTLS testini sonuç beklenen olana kadar tekrarlar. Sunucu kayıt ve iptal
   * sonrası mTLS dinleyicisini yeniden başlattığı için kısa bir geçiş olur.
   */
  async expectMtls(accepted, timeout = 30_000) {
    return this.expectRepeated(() => this.mtlsTest(),
      accepted ? 'mTLS bağlantısı başarılı' : 'mTLS bağlantısı reddedildi', timeout);
  }

  async expectMockMtls(accepted, timeout = 30_000) {
    return this.expectRepeated(() => this.mockMtls(),
      accepted ? 'host bağlantısı başarılı' : 'host bağlantısı reddedildi', timeout);
  }

  async expectRepeated(action, want, timeout) {
    const deadline = Date.now() + timeout;
    let last = '';
    while (Date.now() < deadline) {
      last = await action();
      if (last.includes(want)) return last;
      await sleep(2000);
    }
    throw new Error(`Mobil: sonuç "${want}" olmadı.\nSon metin:\n${last}`);
  }

  unenroll() {
    return this.press('unenrollButton', RESULT.unenroll, 'kayıt silme sonucu', 90_000);
  }

  /**
   * files/manual-client.p12 dosyasını mTLS bloğunun sertifikası yapar (ya da
   * bırakır). İçe aktarırken uygulama P12'nin parolasını ister: [password]
   * parola alanına yazılır (bırakırken verilmez). Uygulama dosyayı Keystore
   * anahtarıyla şifreleyip düz kopyayı siler.
   */
  async toggleManualP12(password) {
    if (password) await this.enterText('p12PasswordInput', password);
    return this.press('importP12Button', RESULT.p12, 'P12 içe aktarma sonucu', 90_000);
  }

  // ── Vault ekranı ─────────────────────────────────────────────────────

  deviceId() {
    const m = this.text('deviceIdView').match(/Cihaz ID:\s*(\S+)/);
    if (!m) throw new Error('Mobil: cihaz kimliği okunamadı');
    return m[1];
  }

  /**
   * mTLS ekranındaki "Cihaz kimliği: <ANDROID_ID>": yönetici panelde token'ı
   * bu telefona bağlamak için onu yazar. Vault ekranındakiyle aynı değer.
   */
  mtlsDeviceId() {
    const m = this.text('mtlsDeviceIdView').match(/Cihaz kimliği:\s*(\S+)/);
    if (!m) throw new Error('Mobil: mTLS ekranında cihaz kimliği okunamadı');
    return m[1];
  }

  async setVaultKey(key) {
    if (this.text('keyInput') !== key) await this.enterText('keyInput', key);
  }

  async saveVaultToken(token, key = VAULT_KEYS.secret) {
    await this.setVaultKey(key);
    await this.enterText('tokenInput', token);
    return this.press('saveTokenButton', RESULT.token, 'token kaydı');
  }

  fetchVault(key) {
    const button = VAULT_BUTTONS[key];
    if (!button) throw new Error(`Uygulamada düğmesi olmayan vault anahtarı: ${key}`);
    return this.press(button, RESULT.vault, `${key} indirme sonucu`);
  }

  /**
   * "Aç": anahtar alanındaki dosyayı açar. Kilitli (gizli) dosyada sistem
   * ekran kilidini sorar; pencere görünürse [pin] yazılır ([cancel] ise geri
   * tuşuyla kapatılır). Kilitsiz dosya soru sorulmadan açılır. Sonuç metnini
   * döndürür; açılan içerik ekranda görünür.
   */
  async unlockVault(key, { pin = SCREEN_LOCK_PIN, cancel = false, timeout = 45_000 } = {}) {
    await this.setVaultKey(key);
    const before = SampleApp.seqOf(this.status());
    await this.tapButton('unlockButton');
    const deadline = Date.now() + timeout;
    let answered = false;
    let last = '';
    while (Date.now() < deadline) {
      const node = this.node('statusView');
      last = node ? node.text : last;
      if (node && SampleApp.seqOf(node.text) > before && RESULT.vaultUnlock.test(node.text)) return node.text;
      if (!answered && this.device.credentialPromptShown(UNLOCK_PROMPT_TITLE)) {
        // Pencere yeni açıldıysa açılış animasyonu bitip PIN alanı hazır olana kadar beklenir.
        await sleep(2000);
        // Vazgeç: Android'de GERİ tuşu (ilki klavyeyi kapatır), iOS'ta Face ID
        // eşleşmez + sistem penceresinin Vazgeç düğmesi (lib/android.js, lib/ios.js).
        if (cancel) await this.device.cancelCredentialPrompt(UNLOCK_PROMPT_TITLE);
        else this.device.enterCredential(pin);
        answered = true;
      }
      await sleep(700);
    }
    throw new Error(`Mobil: "${key}" açma sonucu gelmedi.\nSon metin:\n${last}`);
  }

  async vaultInfo(key) {
    await this.setVaultKey(key);
    return this.press('infoButton', RESULT.vaultInfo, `${key} bilgisi`);
  }

  async vaultClear(key) {
    await this.setVaultKey(key);
    return this.press('clearButton', RESULT.vaultClear, `${key} silme`);
  }

  syncAll() {
    return this.press('syncAllButton', RESULT.vaultSync, 'tümünü eşitle sonucu', 60_000);
  }

  // ── Kanıt ────────────────────────────────────────────────────────────

  async snap(title) {
    await this.testInfo.attach(attachmentName('📱', title), {
      body: this.device.screenshot(),
      contentType: 'image/png',
    });
  }

  /**
   * Sonuç kutusunu (statusView) bütünüyle görünür kılar: kaydırılabilir
   * ekranlarda (Ayarlar) kutu en altta ve çoğu zaman ekranın dışında kalıyor;
   * "#N · saat" damgası da kutunun son satırında. Ekran, kutunun sınırları
   * değişmeyene kadar (kaydırmanın sonu) yavaşça aşağı kaydırılır.
   */
  async revealStatus() {
    let last = null;
    for (let i = 0; i < 6; i++) {
      const node = this.node('statusView');
      const key = node && node.bounds ? node.bounds.join(',') : null;
      if (node && key === last) return;
      last = key;
      this.device.swipeVertical('down', 0.3, 700);
      await sleep(600);
    }
  }

  /** Sonuç kutusu görünürken ekran görüntüsü (Ayarlar ekranındaki sonuçlar için). */
  async snapResult(title) {
    await this.revealStatus();
    await this.snap(title);
  }
}

module.exports = { SampleApp, RESULT, VAULT_BUTTONS, MODE_RADIOS };
