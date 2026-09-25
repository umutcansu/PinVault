let currentConfig = null;
let allApiConfigs = []; // [{id, port, mode, hosts, version}]
let selectedHost = null;
let selectedApiId = null;
let currentSection = null;

// ── HTML escaping (H-02) ─────────────────────────────
// All values that originate from server responses must pass through this
// before being interpolated into innerHTML strings. The connection-history
// and vault-report endpoints accept unauthenticated POSTs, so without
// escaping a client can post a hostname like `<script>...</script>` and
// trigger script execution when the admin loads the dashboard.
function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

// ── API Key Authentication ──────────────────────────
function getApiKey() { return localStorage.getItem('pinvault_api_key') || ''; }
function setApiKey(key) { localStorage.setItem('pinvault_api_key', key); }

/**
 * Authenticated fetch wrapper — adds the X-API-Key header and handles the
 * answers any admin write may get from the governance features:
 *
 *  - 401/403 → asks for a key and retries once. Background refreshes pass
 *    `{ quiet: true }` and never open a dialog.
 *  - 202 `{pendingApproval}` → the change was NOT applied; it waits for
 *    another admin (PIN_CHANGE_APPROVALS). See notePendingApproval().
 *  - 422 `{liveCheck}` → the live certificate gate refused the pins. The
 *    failing hosts are shown and, when the server allows an override, a
 *    reason is asked for and the request resent once with
 *    `liveCheckOverride=<reason>`. The response is marked `liveCheckHandled`
 *    so callers do not report the same failure again.
 *  - `X-PinVault-Live-Check: warn` → stored, but the gate flagged it.
 *
 * 409/422 never prompt for a key: they are answers, not auth failures.
 */
async function apiFetch(url, options = {}) {
    const { quiet = false, liveCheckRetry = false, ...init } = options;
    const key = getApiKey();
    if (key) {
        init.headers = { ...init.headers, 'X-API-Key': key };
    }
    // Host-scoped endpoint'lere (/api/v1/hosts/...) seçili Config API'yi
    // `?configApiId=<id>` olarak ekle — yoksa management server `default-tls`
    // varsayılanına düşer ve yanlış scope'un verisini gösterir.
    if (url.startsWith('/api/v1/hosts/')
        && typeof selectedApiId === 'string' && selectedApiId
        && !url.includes('configApiId=')) {
        const sep = url.includes('?') ? '&' : '?';
        url = url + sep + 'configApiId=' + encodeURIComponent(selectedApiId);
    }
    let resp = await fetch(url, init);
    if ((resp.status === 401 || resp.status === 403) && !quiet) {
        const newKey = prompt('API Key gerekli (X-API-Key):');
        if (newKey) {
            setApiKey(newKey);
            init.headers = { ...init.headers, 'X-API-Key': newKey };
            resp = await fetch(url, init);
            // Another key may belong to another admin: refresh the chip.
            loadAdminIdentity();
        }
    }
    return handleGovernanceResponse(url, init, resp, { quiet, liveCheckRetry });
}

async function handleGovernanceResponse(url, init, resp, ctx) {
    const method = String(init.method || 'GET').toUpperCase();
    if (method === 'GET' || method === 'HEAD') return resp;
    if (resp.status === 202) {
        const body = await resp.clone().json().catch(() => null);
        if (body && body.pendingApproval) notePendingApproval(body);
        return resp;
    }
    if (resp.status === 422) {
        const body = await resp.clone().json().catch(() => null);
        if (body && body.liveCheck) {
            const failures = liveCheckFailureLines(body.liveCheck);
            if (body.overridable && !ctx.liveCheckRetry) {
                const reason = prompt(t('liveCheckOverridePrompt',
                    t('liveCheckFailedHeader') + '\n• ' + failures.join('\n• ')));
                if (reason && reason.trim()) {
                    const sep = url.includes('?') ? '&' : '?';
                    return apiFetch(`${url}${sep}liveCheckOverride=${encodeURIComponent(reason.trim())}`,
                        { ...init, quiet: ctx.quiet, liveCheckRetry: true });
                }
            }
            toast(t('liveCheckBlocked', failures.join(' · ')), 'error', 8000);
            resp.liveCheckHandled = true;
        }
        return resp;
    }
    if (resp.ok && (resp.headers.get('X-PinVault-Live-Check') || '').toLowerCase() === 'warn') {
        toast(t('liveCheckWarnSaved'), 'warning', 8000);
    }
    return resp;
}

// ── i18n ─────────────────────────────────────────────

const i18n = {
  tr: {
    hosts: 'Hostlar', addHost: '+ Yeni Host', selectHost: 'Host seçin',
    selectHostSub: 'Sol menüden bir host seçin veya yeni host ekleyin.',
    navHealth: 'Bağlantı Geçmişi', navSigning: 'İmzalama Anahtarı',
    pins: 'pin', noPins: 'Henüz pin eklenmemiş',
    pinCount: 'Pin Sayısı', primaryPin: 'Primary Pin', backupPin: 'Backup Pin',
    copy: 'Kopyala', copied: 'Kopyalandı',
    editPins: 'Pinleri Düzenle', deleteHost: 'Hostu Sil',
    addHash: '+ Hash Ekle', save: 'Kaydet', cancel: 'İptal',
    primaryPlaceholder: 'Primary pin hash (Base64, 44 karakter)',
    backupPlaceholder: 'Backup pin hash',
    addHostTitle: 'Yeni Host Ekle', hostname: 'Hostname',
    hostnamePlaceholder: 'api.example.com',
    hostnameHint: 'Pin\'lemek istediğiniz sunucunun hostname\'i',
    hashHint: 'openssl komutu ile sertifika hash\'ini hesaplayın',
    create: 'Oluştur',
    duplicateHost: 'Bu hostname zaten mevcut',
    tabManual: 'Elle Gir', tabGenerate: 'Sertifika Üret', tabUpload: 'Dosya Yükle', tabFetch: 'URL\'den Çek',
    urlLabel: 'URL', urlPlaceholder: 'https://api.example.com',
    urlHint: 'Sunucuya bağlanıp sertifikayı otomatik çeker',
    fileLabel: 'Sertifika Dosyası', fileHint: 'JKS, P12 veya PFX formatı',
    passwordLabel: 'Keystore Şifresi',
    generating: 'Oluşturuluyor...', fetching: 'Bağlanılıyor...', uploading: 'Yükleniyor...',
    certGenerated: 'Sertifika üretildi', certFetched: 'Sertifika çekildi', certUploaded: 'Sertifika yüklendi',
    certInfo: 'Sertifika Bilgileri', noCert: 'Sertifika yok',
    regenerateCert: 'Sertifikayı Yenile', certRegenerated: 'Sertifika yenilendi',
    startMock: 'Mock Server Başlat', stopMock: 'Mock Server Durdur',
    mockPort: 'Port', mockRunning: 'Çalışıyor', mockStopped: 'Durduruldu', mockReady: 'Sertifika hazır',
    mockStarted: 'Mock server başlatıldı', mockStoppedMsg: 'Mock server durduruldu',
    deleteConfirm: 'bu hostu silmek istediğinizden emin misiniz?',
    hostDeleted: 'Host silindi', hostAdded: 'Host eklendi',
    pinsUpdated: 'Pinler güncellendi',
    saveError: 'Kaydetme hatası', serverError: 'Sunucu hatası', error: 'Hata oluştu',
    forceUpdate: 'Force Update', forceRemove: 'Force Kaldır',
    forceConfirm: 'Force update aktif edilecek. Tüm istemciler anında güncellenecek. Devam?',
    forceEnabled: 'Force update aktif edildi', forceDisabled: 'Force update kaldırıldı',
    version: 'Versiyon', forceStatus: 'Force Update',
    forceActive: 'AKTİF', forcePassive: 'Pasif',
    forceActiveDesc: 'Tüm istemciler güncellenmeli', forcePassiveDesc: 'Normal zamanlama',
    history: 'Değişiklik Geçmişi', noHistory: 'Henüz kayıt yok',
    thVersion: 'Versiyon', thEvent: 'Olay', thPinPrefix: 'Pin (ön ek)', thDate: 'Tarih',
    evHostAdded: 'Host eklendi', evHostRemoved: 'Host silindi',
    evPinsUpdated: 'Pinler güncellendi', evForce: 'Force Update',
    connHistory: 'Bağlantı Geçmişi (Host)', noConnHistory: 'Bu host için bağlantı kaydı yok',
    thClient: 'İstemci', thPinVer: 'Pin Ver.',
    connectedClients: 'Bağlı Cihazlar', noClients: 'Henüz cihaz kaydı yok',
    thDevice: 'Cihaz', thLastStatus: 'Son Durum', thLastSeen: 'Son Görülme',
    healthTitle: 'Bağlantı Geçmişi', healthSub: 'Web ve mobil istemci bağlantı kayıtları',
    runHealthCheck: 'Health Check Çalıştır',
    serverStatus: 'Sunucu Durumu', healthy: 'Sağlıklı', unhealthy: 'Hata',
    healthEndpoint: '/health uç noktası',
    webChecks: 'Web Kontrolleri', webFrom: 'Web arayüzünden',
    mobileReports: 'Mobil Raporlar', mobileFrom: 'Android istemciden',
    allConnections: 'Tüm Bağlantılar', noConnections: 'Henüz bağlantı kaydı yok',
    thSource: 'Kaynak', thStatus: 'Durum', thDuration: 'Süre', thPin: 'Pin', thError: 'Hata',
    success: 'Başarılı', failed: 'Hata', matched: 'Eşleşti', mismatch: 'Uyuşmadı',
    configUpdated: 'Config Güncellendi', configUnchanged: 'Config Değişmedi', configUpdateFailed: 'Config Güncelleme Hatası',
    healthOk: 'Health check', healthFailed: 'Health check başarısız',
    signingTitle: 'ECDSA İmzalama Anahtarı',
    signingSub: 'Bu açık anahtarı APK\'ya gömün (PinVaultConfig.Builder.signaturePublicKey)',
    publicKey: 'Açık Anahtar (Base64, X.509)',
    androidIntegration: 'Android Entegrasyonu',
    signingError: 'İmzalama anahtarı yüklenemedi',
    ecdsaWhat: 'ECDSA Nedir?',
    ecdsaExplain: 'ECDSA (Elliptic Curve Digital Signature Algorithm), sunucudan gelen pin config\'inin değiştirilmediğini doğrular. Sunucu config\'i private key ile imzalar, client bu public key ile doğrular. Böylece MITM saldırganı config\'i değiştiremez.',
    navBootstrap: 'Bootstrap Pin\'ler',
    bootstrapTitle: 'Bootstrap Pin\'ler',
    bootstrapSub: 'İlk HTTPS bağlantıyı korumak için bu pin\'leri APK\'ya gömün (PinVaultConfig.Builder.bootstrapPins)',
    bootstrapWhat: 'Bootstrap Pin Nedir?',
    bootstrapExplain: 'Bootstrap pin\'ler, uygulamanın ilk kez config sunucusuna HTTPS ile bağlanırken MITM saldırısına karşı korunmasını sağlar. Sunucunun TLS sertifikasının SHA-256 hash\'i APK\'ya derlenir. İlk bağlantıda bu hash doğrulanır, sonraki pin\'ler sunucudan dinamik olarak alınır.',
    bootstrapError: 'Bootstrap pin bilgisi yüklenemedi',
    serverTlsPin: 'Config Server TLS Pin',
    regenerateSigningKey: 'Anahtarı Yenile',
    regenerateSigningConfirm: 'İmzalama anahtarı yenilenecek. Tüm istemcilerin APK\'sındaki public key güncellenmelidir. Devam?',
    signingRegenerated: 'İmzalama anahtarı yenilendi',
    regenerateBootstrap: 'Sertifikayı Yenile',
    regenerateBootstrapConfirm: 'Config server TLS sertifikası yenilenecek. Tüm istemcilerin bootstrap pin\'leri güncellenmelidir. Sunucu yeniden başlatılmalıdır. Devam?',
    bootstrapRegenerated: 'Bootstrap sertifika yenilendi — sunucu yeniden başlatılmalı',
    rotateToBackup: 'Yedek Anahtara Geç',
    rotateHostConfirm: 'Sertifika saklı yedek anahtarla yeniden üretilecek ve yeni bir yedek hazırlanacak. Telefonlar yedeğin pinini zaten bildiği için bağlantı kesilmez. Devam?',
    rotateBootstrapConfirm: 'Config sunucusunun sertifikası saklı yedek anahtara geçirilecek ve yeni bir yedek hazırlanacak. Uygulamalar yedeğin pinini başlangıç pini olarak taşıdığı için güncelleme gerekmez. Sunucu yeniden başlatılmalı. Devam?',
    rotatedToBackup: 'Yedek anahtara geçildi; yeni yedek hazırlandı',
    bootstrapRotated: 'Yedek anahtara geçildi — sunucu yeniden başlatılmalı. Yeni yedek pini uygulamanın sonraki sürümüne eklenmeli.',
    noBackupKey: 'Bu sertifika için saklanmış yedek anahtar yok: pinler adresten alınmış ya da sertifika bu özellik gelmeden önce üretilmiş. Yedek anahtar, sertifika yeniden üretilince oluşur.',
    noSecondCertificate: 'Site sertifikasını tek başına sunuyor; yedek pin olabilecek bir üst sertifika yok. Pinleri elle girin: sitenin pini ve site sahibinin sakladığı bir yedek anahtarın pini.',
    pinsMustDiffer: 'En az iki farklı pin gerekir: biri birincil, biri yedek.',
    backupNotPublished: 'Saklı yedek anahtarın pini yayımlanan pinler arasında yok; telefonlar bu anahtarı reddeder. Önce pini listeye ekleyin ya da sertifikayı yeniden üretin.',
    tabAutoGenerate: 'Otomatik Üret', tabUploadJks: 'JKS Yükle', tabFetchUrl: 'URL\'den Çek',
    uploadJksLabel: 'Sertifika Dosyası (JKS/P12/PFX)', uploadPassword: 'Keystore Şifresi',
    uploadBtn: 'Yükle', fetchUrlLabel: 'URL', fetchUrlPlaceholder: 'https://api.example.com',
    fetchBtn: 'Çek', uploading: 'Yükleniyor...', fetching: 'Bağlanılıyor...',
    bootstrapUploaded: 'Sertifika yüklendi — sunucu yeniden başlatılmalı',
    bootstrapFetched: 'Pin\'ler çekildi',
    navMtls: 'mTLS',
    mtlsTitle: 'mTLS — Mutual TLS',
    mtlsSub: 'Client sertifikası ile çift yönlü TLS doğrulama',
    mtlsWhat: 'mTLS Nedir?',
    mtlsExplain: 'Mutual TLS (mTLS), hem sunucunun hem de istemcinin birbirini sertifika ile doğrulamasıdır. Normal TLS\'de sadece sunucu doğrulanır. mTLS ile yetkisiz cihazlar config API\'ye erişemez — sertifikası olmayan cihazların bağlantısı reddedilir.',
    mtlsStatus: 'mTLS Durumu', mtlsEnabled: 'Aktif', mtlsDisabled: 'Pasif',
    mtlsEnvHint: 'Aktifleştirmek için: MTLS_ENABLED=true ile sunucuyu başlatın',
    generateClientCert: 'Client Cert Üret', uploadClientCert: 'Client Cert Yükle',
    clientCerts: 'Kayıtlı Client Sertifikaları', noClientCerts: 'Henüz client sertifikası yok',
    hostCertGuide: 'Bu host için client cert yükleyerek mTLS\'i aktifleştirebilirsiniz. Client cert yüklendikten sonra, enroll olan cihazlar bu cert\'i mTLS Config API üzerinden otomatik indirir.',
    hostCertNone: 'Client cert yüklenmemiş',
    hostCertUploadHint: 'PKCS12 (.p12/.pfx) formatında client cert yükleyin',
    testConnection: 'Bağlantıyı Test Et',
    testingConnection: 'Test ediliyor...',
    connTestOk: 'Bağlantı başarılı',
    connTestFail: 'Bağlantı başarısız',
    mockNotRunning: 'Mock server çalışmıyor — önce başlatın',
    thFingerprint: 'Fingerprint', thCreated: 'Oluşturma', thRevoked: 'Durum',
    revoke: 'İptal Et', active: 'Aktif', revoked: 'İptal Edildi',
    certGenerated: 'Client sertifika üretildi — indiriliyor',
    certUploaded: 'Client sertifika yüklendi',
    certRevoked: 'Client sertifika iptal edildi',
    clientIdLabel: 'Client ID', clientIdPlaceholder: 'ornek: mobil-app-1',
    loading: 'Yükleniyor...',
    renewCert: 'Sertifika Yenile', renewAuto: 'Otomatik Üret', renewUpload: 'JKS Yükle', renewFetch: 'URL\'den Çek',
    renewAutoDesc: 'Otomatik self-signed sertifika üretir. Demo ve test için uygundur.',
    renewUploadLabel: 'Sertifika Dosyası (JKS/P12/PFX)', renewUploadPassword: 'Keystore Şifresi',
    renewUploadBtn: 'Yükle', renewFetchLabel: 'URL', renewFetchPlaceholder: 'https://api.example.com',
    renewFetchBtn: 'Çek', certRenewed: 'Sertifika yenilendi', certUploadRenewed: 'Sertifika yüklendi ve güncellendi',
    certFetchRenewed: 'Sertifika URL\'den çekildi ve güncellendi',
    vaultTitle: 'Vault Dosyaları', vaultSub: 'Uzaktan dağıtılan dosyalar ve dağıtım geçmişi',
    vaultUpload: 'Dosya Yükle', vaultDelete: 'Sil', vaultKey: 'Anahtar',
    vaultVersion: 'Versiyon', vaultSize: 'Boyut', vaultDistCount: 'Dağıtım',
    vaultNoFiles: 'Henüz vault dosyası yok', vaultUploadBtn: 'Yükle',
    vaultUploadTitle: 'Vault\'a Yükle',
    vaultUploadFileLabel: 'Dosya', vaultUploadTextLabel: 'Metin',
    vaultUploadTextPlaceholder: 'Düz metin yapıştır (txt yerine)…',
    vaultUploadHint: 'Dosya seç ya da metni buraya yaz — biri yeterli.',
    vaultUploadNeedContent: 'Bir dosya seç veya metin gir',
    encDescPlain: 'Şifreleme yok — dosya sunucuda düz saklanır, düz servis edilir (bağlantı yine de pinli TLS). Hassas olmayan içerik için.',
    encDescAtRest: 'Sunucu diskinde AES-256-GCM ile şifreli tutulur; istemciye gönderilirken çözülür (cihaza düz iner). Sunucu diski/yedeği sızsa bile içerik korunur.',
    encDescE2E: 'Dosya, hedef cihazın açık anahtarıyla şifrelenir; teslim edilen paketi yalnızca o cihaz (Keystore\'daki özel anahtarıyla) açar — aradaki cache/relay/başka cihaz açamaz. Anahtarı uygulama otomatik üretip kaydeder, sen elle girmezsin (cihaz E2E ayarlı değilse indirme 412 döner). Not: şifrelemeyi sunucu yapar, yani içeriği sunucu görür; sunucudan da gizlemek istersen yüklemeden önce şifrelemelisin.',
    vaultKeyPlaceholder: 'feature-flags', vaultFilePlaceholder: 'Dosya seçin',
    vaultDistTitle: 'Dağıtım Geçmişi', vaultNoDistHistory: 'Dağıtım kaydı yok', vaultReason: 'Neden',
    vaultStats: 'İstatistikler', vaultTotalDist: 'Toplam Dağıtım',
    vaultUniqueDevices: 'Cihaz', vaultUniqueKeys: 'Dosya', vaultDownloaded: 'İndirilen',
    vaultFailed: 'Başarısız', vaultSucceeded: 'Başarılı', back: 'Geri', vaultDevice: 'Cihaz', vaultStatus: 'Durum',
    vaultTimestamp: 'Tarih', vaultLabel: 'Etiket',
    vaultVersionTimeline: 'Versiyon Zaman Çizelgesi', vaultDeviceSummary: 'Cihaz Özeti',
    vaultFullHistory: 'Tüm Geçmiş', vaultFetchCount: 'Çekim', vaultLastFetch: 'Son Çekim',
    vaultLastVersion: 'Son Ver.', vaultFileSummary: 'Dosya Özeti', vaultDeviceHistory: 'Cihaz Geçmişi',
    vaultSuccess: 'Başarılı',
    // ── V2 additions ──
    tabGeneral: 'Genel', tabBootstrap: 'Bootstrap Pin', tabSigning: 'İmzalama',
    tabMtlsCerts: 'Client Sertifikaları', tabVault: 'Vault', tabHistory: 'Bağlantı Geçmişi',
    vaultV2Section: 'Vault (V2)', vaultEnabledLabel: 'Bu Config API\'de vault aktif',
    manageDeviceAcl: 'Cihaz ACL yönet',
    vaultDisabledHint: 'Vault kapalıyken bu Config API\'nin indirme ucu (GET /api/v1/vault/{key}) her anahtar için 403 döner; yükleme, listeleme ve silme açık kalır.',
    vaultEnabledOn: 'Vault açıldı', vaultEnabledOff: 'Vault kapatıldı', vaultToggleError: 'Değiştirilemedi',
    aclManagerTitle: 'Device ACL', aclManagerSub: 'Her cihaz hangi host\'ların pin\'ini indirebilir kontrolü',
    aclBack: '← Geri', aclSave: 'Kaydet',
    defaultAclTitle: 'Default ACL (per Config API)',
    defaultAclHint: 'Cihaz bazlı ACL\'i olmayan cihazlar bu listeyi alır. Virgülle ayrılmış hostname listesi.',
    defaultAclPlaceholder: 'ör: cdn.example.com, api.example.com',
    defaultAclUpdated: 'Default ACL güncellendi', defaultAclSaveError: 'Kaydedilemedi',
    enrolledDevicesTitle: 'Enrolled Cihazlar', noEnrolledDevices: 'Henüz enrolled cihaz yok',
    aclEditBtn: 'ACL düzenle', aclEditPrompt: 'Cihaz {0} için host ACL (virgülle ayrılmış):',
    aclUpdated: 'ACL güncellendi',
    // Policy dropdown
    policyLabel: 'Policy', encryptionLabel: 'Encryption',
    policyTokenOpt: 'token (önerilen)', policyPublicOpt: 'public (demo)',
    policyApiKeyOpt: 'api_key', policyTokenMtlsOpt: 'token + mTLS',
    policyApiKeyWarn: 'api_key: cihazdan İNMEZ — kütüphane yönetim anahtarını göndermez (APK\'ya gömülürdü), her indirme 401 alır. Yalnızca sunucu-sunucu araçlar için. Cihaz içinse token / token + mTLS seç.',
    // Vault dosya politikası düzenleme
    policyEditTitle: 'Erişim Politikası ve Şifreleme',
    policyEditHint: 'Dosya içeriğine dokunmadan politikayı değiştirir. token + mTLS, geçerli token\'ın YANINDA istemci sertifikası da ister.',
    policySaveBtn: 'Politikayı Kaydet', policyCurrent: 'Şu an',
    policySaved: 'Politika güncellendi: {0}', policySaveError: 'Politika güncellenemedi',
    // Kayıt token'ı — düz metin yalnızca bir kez gösterilir
    enrollTokenGeneratedAlert: 'Kayıt token\'ı üretildi ve panoya kopyalandı:\n\n{0}\n\nBu değer bir daha gösterilmeyecek. Cihaza güvenli kanaldan iletin.',
    tokenMaskedHint: 'Sunucu yalnızca SHA-256 hash saklıyor — bu maskeli öneki kayıt için kullanamazsınız.',
    // Sertifika süre izleme
    certExpiryTitle: 'Sertifika Süreleri', certNearExpiry: 'Yakında dolacak',
    certExpiryHint: 'Her host sertifikasının kalan ömrü. Uyarı eşiği sunucudaki CERT_EXPIRY_WARN_DAYS ile ayarlanır.',
    certExpiryEmpty: 'Süre bilgisi olan sertifika yok.',
    certOk: 'geçerli', certWarning: 'yakında doluyor', certExpired: 'süresi doldu',
    certDaysLeft: '{0} gün', certExpiredAgo: '{0} gün önce doldu',
    certRemaining: 'Kalan', certValidUntil: 'Geçerlilik sonu',
    // Toplu force update
    forceAllTitle: 'Toplu Force Update',
    forceAllHint: 'Bu Config API\'deki tüm host\'lara force bayrağı basar — cihazlar bir sonraki fetch\'te pin\'leri zorunlu olarak günceller.',
    forceAllBtn: 'Tümüne Force Ver', clearForceAllBtn: 'Tümünden Force Kaldır',
    forceAllConfirm: 'Bu Config API\'deki TÜM host\'lara force update verilecek. Devam edilsin mi?',
    forceAllEnabled: 'Tüm host\'lara force update verildi',
    forceAllDisabled: 'Force bayrakları temizlendi',
    forceAllCount: '{0}/{1} host force durumunda',
    // Host ekleme — URL'den çek
    tabFetch: 'URL\'den Al',
    fetchUrlLabel: 'Sunucu adresi',
    fetchUrlHint: 'TLS el sıkışması yapılıp sertifika pin\'leri otomatik çıkarılır. Örn: https://api.example.com',
    // Bootstrap — URL'den pin çek
    bootstrapFetchLabel: 'Pin\'lerin çekileceği adres',
    bootstrapFetchHint: 'Sunucu bir TLS sonlandırıcı (reverse proxy) arkasındaysa istemcilerin pinlemesi gereken sertifika proxy\'ninkidir. Pin\'ler o adresten alınır.',
    bootstrapFetchBtn: 'Pin\'leri Çek',
    // Token management
    tokenMgmtTitle: 'Token Yönetimi', tokenNewBtn: '+ Yeni Token',
    tokenDevicePlaceholder: 'deviceId (ör. mi-9t)',
    tokenMgmtHint: 'Token\'lar per-cihaz ve per-dosya geçerlidir. Plaintext sadece üretildiğinde bir kez gösterilir — kaybedilirse yenisi üretilmelidir.',
    tokenColDeviceId: 'Device ID', tokenColStatus: 'Durum', tokenColCreated: 'Oluşturma',
    tokenStatusActive: '✓ aktif', tokenStatusRevoked: '✗ iptal',
    tokenBtnRevoke: 'İptal', tokenBtnDash: '—',
    tokenNoRows: 'Bu dosya için token yok',
    tokenGeneratedAlert: 'Token üretildi ve panoya kopyalandı:\n\n{0}\n\nBu değer bir daha gösterilmeyecek. Cihaza güvenli kanaldan iletin.',
    tokenGenError: 'Token üretimi başarısız', tokenDeviceIdRequired: 'deviceId gerekli',
    tokenRevokeConfirm: 'Token iptal edilecek (sonraki fetch 401). Devam?',
    tokenRevoked: 'Token iptal edildi', tokenRevokeError: 'İptal başarısız',
    // Filter chip
    filterRemove: 'Filtreyi kaldır',
    // Upload toast
    vaultUploadSuccess: '{0} v{1} [{2}/{3}] uploaded',
    // ── i18n sweep additions ──
    serverInfo: 'Sunucu Bilgisi', mode: 'Mod', hostCountLabel: 'Host sayısı',
    clientCertMtls: 'Client Cert (mTLS)', refresh: 'Yenile', addHostTooltip: 'Host ekle',
    pkcs12Hint: 'PKCS12 (.p12/.pfx)', apiIdLabel: 'API ID',
    newConfigApiTitle: 'Yeni Config API', newConfigApiSub: 'TLS veya mTLS config API başlatın',
    modeTlsOption: 'TLS (tek yönlü)', modeMtlsOption: 'mTLS (çift yönlü — client cert gerekir)',
    startConfigApi: 'Config API Başlat', deleteApi: 'API Sil',
    enrollmentToken: 'Enrollment Token', tokenRequiredBadge: 'Token zorunlu',
    openModeBadge: 'Açık mod — deviceId ile kayıt aktif (demo)',
    secureFlowLabel: 'Güvenli akış:',
    secureFlowSteps: 'Admin token üretir → Uygulama token ile kayıt olur → Client cert alır → mTLS Config API\'ye erişir → Host cert\'leri otomatik indirilir',
    enrollmentModeHint: 'ENROLLMENT_MODE=token ile sunucuyu başlatarak deviceId enrollment\'ı kapatabilirsiniz.',
    generateToken: 'Token Üret', tokenUsed: 'Kullanıldı', tokenPending: 'Bekliyor',
    tokenExpired: 'Süresi doldu', tokenExpiresAt: 'Geçerlilik bitişi',
    thForce: 'Force', thToken: 'Token',
    revokeCertConfirm: '{0} iptal edilecek. Devam?',
    deleteFileConfirm: '"{0}" silinsin mi?', fileDeleted: '{0} silindi',
    mockServer: 'MOCK SERVER', algorithmLabel: 'Algorithm', validUntilLabel: 'Geçerlilik Sonu',
    updateClientCert: 'Client Cert Güncelle',
    apiIdPlaceholder: 'tls-8093 veya mtls-8092',
    mockStart: 'Başlat', thAuth: 'Auth',
    mockRemoteOnlyHint: 'Bu host için yerel mock kurulmamış — sertifika sadece pin doğrulama için üretildi.',
    mockServerTitle: 'Mock Server', mockCertNeeded: 'mock server için sertifika gerekli',
    vaultAuthError: 'Yetki hatası ({0}). Sağ üstten API key gir veya localStorage.setItem(\'pinvault_api_key\', \'testkey\') sonra sayfayı yenile.',
    vaultUnexpectedResponse: 'Beklenmeyen yanıt formatı. Console\'a bak: {0}',
    // ── Yönetişim: kimlik, onaylar, denetim kaydı, canlı kontrol, imzalama ──
    navApprovals: 'Onaylar', navAudit: 'Denetim Kaydı',
    adminUnknown: 'Kimlik yok', adminChipTitle: 'Bu panelin kullandığı yönetici anahtarının sahibi',
    switchAdminKey: 'Anahtar değiştir',
    switchAdminKeyPrompt: 'Kayıtlı anahtar silindi. Yeni yönetici API anahtarını girin (X-API-Key):',
    adminKeySwitched: 'Yönetici: {0}',
    badgeApprovals: '{0} kişi onayı', badgeApprovalsTitle: 'Pin ve anahtar değişiklikleri {0} yöneticinin onayını gerektirir (PIN_CHANGE_APPROVALS)',
    badgeLiveCheck: 'Canlı kontrol: {0}', badgeLiveCheckTitle: 'Yeni pin setleri hostun şu an sunduğu sertifikayla karşılaştırılır (PIN_LIVE_CHECK)',
    badgeSigCache: 'İmza önbelleği', badgeSigCacheTitle: 'Aynı içerik bir kez imzalanıp yeniden sunulur (CONFIG_SIGNATURE_CACHE)',
    liveModeWarn: 'uyarı', liveModeEnforce: 'zorunlu', liveModeOff: 'kapalı',
    approvalsBadgeTitle: '{0} değişiklik onay bekliyor',
    pendingChange: 'Değişiklik #{0} onay bekliyor — başka bir yönetici onaylayana kadar uygulanmadı.',
    liveCheckFailedHeader: 'Canlı sertifika kontrolü başarısız:',
    liveCheckOverridePrompt: '{0}\n\nYine de kaydetmek için bir gerekçe yazın (denetim kaydına ve bildirimlere geçer). Boş bırakırsanız kaydedilmez.',
    liveCheckBlocked: 'Kaydedilmedi — canlı sertifika kontrolü: {0}',
    liveCheckWarnSaved: 'Kaydedildi, ancak canlı sertifika kontrolü başarısız (uyarı modu) — ayrıntılar Denetim Kaydı\'nda.',
    liveOk: '{0}: sunucunun şu an sunduğu sertifika ({1}…) pin listesinde var',
    liveNotInSet: '{0}: sunucunun şu an sunduğu sertifika ({1}…) pin listesinde yok',
    liveUnreachable: '{0}: ulaşılamadı — {1}',
    liveIssuerNoChain: 'Listedeki pin zincirdeki bir üst sertifikaya ait, ama sunucunun sertifikası ona geçerli biçimde bağlanmıyor (süresi dolmuş, CA yetkisi yok ya da imzası tutmuyor).',
    liveOkIssuer: '{0}: sunucunun sertifikası listedeki üst sertifikaya (CA, {1}…) bağlanıyor',
    liveProbed: 'denenen', liveCheckTitle: 'Canlı sertifika kontrolü',
    livePassed: 'geçti', liveFailed: 'başarısız',
    liveEnforceWillFail: 'Zorunlu modda canlı kontrol başarısız: istek bir gerekçe (liveCheckOverride) içermediği için onaylansa da uygulanmaz (HTTP 422).',
    liveOverrideCarried: 'İstek bir liveCheckOverride gerekçesi taşıyor: {0}',
    liveCheckBtn: 'Canlı Kontrol', liveCheckBtnTitle: 'Bu pinleri hostun şu an sunduğu sertifikayla karşılaştırır (kaydetmez)',
    liveCheckRunning: 'Host kontrol ediliyor…', liveCheckNeedHost: 'Önce hostname girin', liveCheckNeedPins: 'En az bir pin girin',
    liveRotationHint: 'Rotasyon: önce {mevcut, yeni} yayınlayın, host sertifikasını değiştirin, sonra {yeni, yedek} yayınlayın.',
    approvalsTitle: 'Onaylar', approvalsSub: 'Pin ve anahtar değişiklikleri ikinci bir yöneticinin onayını bekler (iki kişi kuralı).',
    approvalsOff: 'İki kişi onayı kapalı (PIN_CHANGE_APPROVALS=1): değişiklikler hemen uygulanır. Açmak için sunucuyu PIN_CHANGE_APPROVALS=2 ve kişisel ADMIN_KEYS ile başlatın.',
    approvalsOn: 'Her değişiklik, isteyen dışında {0} yöneticinin onayıyla uygulanır. Siz: {1}.',
    tabPending: 'Bekleyen ({0})', tabDecided: 'Geçmiş ({0})',
    noPendingChanges: 'Onay bekleyen değişiklik yok.', noDecidedChanges: 'Henüz karara bağlanmış değişiklik yok.',
    crRequestedBy: 'İsteyen', crCreated: 'Oluşturma', crExpires: 'Son geçerlilik', crApprovals: 'Onay',
    crDetails: 'Ayrıntı', crDecidedBy: 'Karar veren', crDecidedAt: 'Karar tarihi', crReason: 'Gerekçe',
    crResult: 'Sonuç', crResultBody: 'Sunucu yanıtı',
    approve: 'Onayla', reject: 'Reddet', withdraw: 'Geri çek',
    cannotApproveOwn: 'Kendi isteğinizi onaylayamazsınız — başka bir yönetici onaylamalı.',
    cannotApproveShared: 'Paylaşılan anahtar (API_KEY) onaylayamaz: kimin onayladığını söylemez. ADMIN_KEYS\'teki kişisel anahtarınızı kullanın.',
    alreadyApproved: 'Bu isteği zaten onayladınız.',
    rejectReasonPrompt: '#{0} reddedilecek. Gerekçe (isteğe bağlı):',
    withdrawReasonPrompt: '#{0} geri çekilecek. Gerekçe (isteğe bağlı):',
    changeApplied: 'Değişiklik #{0} onaylandı ve uygulandı',
    changeApplyFailed: 'Değişiklik #{0} onaylandı ama uygulanamadı (HTTP {1})',
    changeApprovalRecorded: 'Onayınız kaydedildi (#{0}: {1}/{2})',
    changeRejected: 'Değişiklik #{0} reddedildi', changeWithdrawn: 'Değişiklik #{0} geri çekildi',
    crStatus_pending: 'bekliyor', crStatus_applied: 'uygulandı', crStatus_failed: 'başarısız',
    crStatus_rejected: 'reddedildi', crStatus_expired: 'süresi doldu', crStatus_stale: 'eskidi',
    op_pins_update: 'Pin güncelleme', op_force_on: 'Force açma', op_force_off: 'Force kapatma',
    op_host_add: 'Host ekleme', op_host_cert: 'Host sertifikası', op_config_api_delete: 'Config API silme',
    op_config_api_lifecycle: 'Config API başlat/durdur',
    op_bootstrap_pins: 'Bootstrap pin', op_signing_key: 'İmzalama anahtarı', op_signing_keyset: 'Anahtar seti',
    diffGlobalForce: 'Genel force', diffOn: 'açık', diffOff: 'kapalı',
    diffNoDetail: 'Bu işlem için pin farkı yok; özet ve istek yolu değişikliği tanımlar.',
    diffNoChange: 'Pinlerde değişiklik yok.', diffDescribeError: 'Fark hesaplanamadı: {0}',
    auditTitle: 'Denetim Kaydı', auditSub: 'Her yönetici işlemi, hash zinciriyle bağlı, yalnızca eklenebilen bir kayıtta tutulur.',
    auditVerify: 'Zinciri Doğrula', auditVerifyOk: 'Zincir sağlam — {0} kayıt', auditVerifyBroken: 'Zincir #{0} kaydında bozuk',
    auditFilterAll: 'Tüm işlemler', auditThTime: 'Zaman', auditThActor: 'Kim', auditThAction: 'İşlem',
    auditThTarget: 'Hedef', auditThSummary: 'Özet', auditEmpty: 'Kayıt yok',
    auditSourceIp: 'Kaynak IP', auditNoDetail: 'Ek ayrıntı yok', auditEntries: '{0} kayıt',
    act_pins_changed: 'Pinler değişti', act_change_requested: 'Değişiklik istendi', act_change_approved: 'Onay verildi',
    act_change_applied: 'Değişiklik uygulandı', act_change_failed: 'Değişiklik başarısız', act_change_rejected: 'Değişiklik reddedildi',
    act_change_expired: 'Değişiklik süresi doldu', act_change_stale: 'Değişiklik eskidi',
    act_change_approval_refused: 'Onay girişimi reddedildi',
    act_live_check_warning: 'Canlı kontrol uyarısı', act_live_check_blocked: 'Canlı kontrol engelledi', act_live_check_overridden: 'Canlı kontrol gerekçeyle geçildi',
    act_signing_key_regenerated: 'İmzalama anahtarı yenilendi', act_signing_keyset_uploaded: 'Anahtar seti yüklendi',
    act_auth_failed: 'Geçersiz API anahtarı', act_cert_expiring: 'Sertifika süresi doluyor',
    act_notification_test: 'Test bildirimi', act_http: 'Yönetici isteği',
    notifTitle: 'Webhook Bildirimleri', notifStatus: 'Durum', notifConfigured: 'Yapılandırılmış',
    notifNotConfigured: 'Yapılandırılmamış — NOTIFY_WEBHOOK_URL ile açılır',
    notifTarget: 'Hedef', notifSigned: 'HMAC imzası', notifSignedYes: 'Evet (X-PinVault-Signature)',
    notifSignedNo: 'Hayır — NOTIFY_WEBHOOK_SECRET ayarlanmamış', notifEvents: 'Olaylar',
    notifRecent: 'Son teslimatlar', notifNoDeliveries: 'Henüz teslimat yok',
    notifTestBtn: 'Test Bildirimi Gönder', notifTestSent: 'Test bildirimi kuyruğa alındı (denetim #{0})',
    notifThAttempts: 'Deneme', notifThAudit: 'Denetim',
    signersTitle: 'İmzalayıcılar',
    signersHint: 'Her imzalayıcı her config\'i ayrıca imzalar; requiredSignatures(n) ile yapılandırılmış cihazlar n imza ister. İlk imzalayıcı birincildir — eski istemciler onun imzasını okur.',
    thSignerName: 'Ad', thSignerType: 'Tür', thKeyId: 'Anahtar kimliği', thDescription: 'Açıklama',
    primarySigner: 'birincil', signerNotInSet: 'Bu anahtar aktif sette yok',
    sigCacheTitle: 'İmza Önbelleği',
    sigCacheOn: 'Açık — aynı içerik bir kez imzalanır ve config ömrünün yarısına kadar birebir aynı imzalı yanıt verilir (yalnızca bunu desteklediğini X-PinVault-Features: redelivery ile bildiren uygulamalara).',
    sigCacheOff: 'Kapalı — her istek taze imzalanır (CONFIG_SIGNATURE_CACHE=true ile açılır).',
    sigTtl: 'Config ömrü', sigProduced: 'Üretilen imza', sigCacheHits: 'Önbellek isabeti', sigCachedEnvelopes: 'Önbellekteki imzalı yanıt',
    unitHours: '{0} sa', unitMinutes: '{0} dk', unitSeconds: '{0} sn',
    keysetTitle: 'İmzalama Anahtarı Seti',
    keysetHint: 'Anahtar seti, cihazların güvendiği imzalama anahtarlarının listesidir; anahtar değiştirmek (rotasyon) ya da bir anahtarı iptal etmek için kullanılır. Kurtarma anahtar(lar)ıyla ÇEVRİMDIŞI imzalanır; sunucu yalnızca doğrular ve cihazlara iletir.',
    keysetDisabled: 'Kapalı — RECOVERY_PUBLIC_KEYS ayarlanmadı; set yüklemeleri reddedilir.',
    keysetNone: 'Henüz set yüklenmedi (sürüm 0).',
    keysetVersion: 'Set sürümü', keysetKeyIds: 'Listelenen anahtarlar', keysetRequired: 'Gereken imza',
    keysetRecoveryKeys: 'Kurtarma anahtarları', keysetRecoveryRequired: 'Gereken kurtarma imzası',
    keysetUploadedBy: 'Yükleyen', keysetUploadedAt: 'Yükleme',
    keysetMissingWarn: 'Dikkat: şu aktif imzalayıcılar sette YOK — seti uygulayan cihazlar yalnızca bu anahtarlarla imzalanmış config\'leri reddeder: {0}',
    keysetPasteLabel: 'İmzalı set (JSON: payload + signatures)',
    keysetUploadBtn: 'Seti Yükle', keysetPasteFirst: 'Önce imzalı seti yapıştırın',
    keysetInvalidJson: 'Geçersiz JSON: {0}', keysetBadShape: 'Beklenen biçim: {"payload": "…", "signatures": [{"keyId": "…", "signature": "…"}]}',
    keysetUploaded: 'Anahtar seti v{0} yüklendi', keysetUploadWarnings: 'Uyarılar', keysetRejected: 'Set reddedildi',
    regenDisabledSigner: 'Birincil imzalayıcı "{0}" türünde: anahtarı bulunduğu yerde (HSM/KMS) döndürün ve sunucuyu yeni anahtarla yeniden başlatın.',
    regenDisabledKeySet: 'Bir anahtar seti aktif: yeni üretilen anahtar hiçbir sette olmaz ve seti uygulayan cihazlar onu reddeder. Anahtar değişikliğini anahtar seti üzerinden yapın.',
    signingStatusError: 'İmzalama durumu yüklenemedi',
  },
  en: {
    hosts: 'Hosts', addHost: '+ New Host', selectHost: 'Select a host',
    selectHostSub: 'Select a host from the sidebar or add a new one.',
    navHealth: 'Connection History', navSigning: 'Signing Key',
    pins: 'pins', noPins: 'No pins added yet',
    pinCount: 'Pin Count', primaryPin: 'Primary Pin', backupPin: 'Backup Pin',
    copy: 'Copy', copied: 'Copied',
    editPins: 'Edit Pins', deleteHost: 'Delete Host',
    addHash: '+ Add Hash', save: 'Save', cancel: 'Cancel',
    primaryPlaceholder: 'Primary pin hash (Base64, 44 chars)',
    backupPlaceholder: 'Backup pin hash',
    addHostTitle: 'Add New Host', hostname: 'Hostname',
    hostnamePlaceholder: 'api.example.com',
    hostnameHint: 'Hostname of the server you want to pin',
    hashHint: 'Use openssl to compute the certificate hash',
    create: 'Create',
    duplicateHost: 'This hostname already exists',
    tabManual: 'Manual', tabGenerate: 'Generate Cert', tabUpload: 'Upload File', tabFetch: 'Fetch from URL',
    urlLabel: 'URL', urlPlaceholder: 'https://api.example.com',
    urlHint: 'Connects to server and fetches certificate automatically',
    fileLabel: 'Certificate File', fileHint: 'JKS, P12 or PFX format',
    passwordLabel: 'Keystore Password',
    generating: 'Generating...', fetching: 'Connecting...', uploading: 'Uploading...',
    certGenerated: 'Certificate generated', certFetched: 'Certificate fetched', certUploaded: 'Certificate uploaded',
    certInfo: 'Certificate Info', noCert: 'No certificate',
    regenerateCert: 'Regenerate Cert', certRegenerated: 'Certificate regenerated',
    startMock: 'Start Mock Server', stopMock: 'Stop Mock Server',
    mockPort: 'Port', mockRunning: 'Running', mockStopped: 'Stopped', mockReady: 'Cert ready',
    mockStarted: 'Mock server started', mockStoppedMsg: 'Mock server stopped',
    deleteConfirm: 'Are you sure you want to delete this host?',
    hostDeleted: 'Host deleted', hostAdded: 'Host added',
    pinsUpdated: 'Pins updated',
    saveError: 'Save error', serverError: 'Server error', error: 'Error occurred',
    forceUpdate: 'Force Update', forceRemove: 'Clear Force',
    forceConfirm: 'Force update will be enabled. All clients will update immediately. Continue?',
    forceEnabled: 'Force update enabled', forceDisabled: 'Force update cleared',
    version: 'Version', forceStatus: 'Force Update',
    forceActive: 'ACTIVE', forcePassive: 'Passive',
    forceActiveDesc: 'All clients must update', forcePassiveDesc: 'Normal schedule',
    history: 'Change History', noHistory: 'No records yet',
    thVersion: 'Version', thEvent: 'Event', thPinPrefix: 'Pin (prefix)', thDate: 'Date',
    evHostAdded: 'Host added', evHostRemoved: 'Host removed',
    evPinsUpdated: 'Pins updated', evForce: 'Force Update',
    connHistory: 'Connection History (Host)', noConnHistory: 'No connection records for this host',
    thClient: 'Client', thPinVer: 'Pin Ver.',
    connectedClients: 'Connected Clients', noClients: 'No client records yet',
    thDevice: 'Device', thLastStatus: 'Last Status', thLastSeen: 'Last Seen',
    healthTitle: 'Connection History', healthSub: 'Web and mobile client connection records',
    runHealthCheck: 'Run Health Check',
    serverStatus: 'Server Status', healthy: 'Healthy', unhealthy: 'Error',
    healthEndpoint: '/health endpoint',
    webChecks: 'Web Checks', webFrom: 'From web UI',
    mobileReports: 'Mobile Reports', mobileFrom: 'From Android client',
    allConnections: 'All Connections', noConnections: 'No connection records yet',
    thSource: 'Source', thStatus: 'Status', thDuration: 'Duration', thPin: 'Pin', thError: 'Error',
    success: 'Success', failed: 'Error', matched: 'Matched', mismatch: 'Mismatch',
    configUpdated: 'Config Updated', configUnchanged: 'Config Unchanged', configUpdateFailed: 'Config Update Failed',
    healthOk: 'Health check', healthFailed: 'Health check failed',
    signingTitle: 'ECDSA Signing Key',
    signingSub: 'Embed this public key in your APK (PinVaultConfig.Builder.signaturePublicKey)',
    ecdsaWhat: 'What is ECDSA?',
    ecdsaExplain: 'ECDSA (Elliptic Curve Digital Signature Algorithm) verifies that the pin config from the server has not been tampered with. The server signs the config with a private key, and the client verifies it with this public key. This prevents MITM attackers from modifying the config.',
    navBootstrap: 'Bootstrap Pins',
    bootstrapTitle: 'Bootstrap Pins',
    bootstrapSub: 'Embed these pins in your APK to protect the first HTTPS connection (PinVaultConfig.Builder.bootstrapPins)',
    bootstrapWhat: 'What is a Bootstrap Pin?',
    bootstrapExplain: 'Bootstrap pins protect the app against MITM attacks during the first connection to the config server over HTTPS. The SHA-256 hash of the server\'s TLS certificate public key is compiled into the APK. On first connect, this hash is verified. Subsequent pins are fetched dynamically from the server.',
    bootstrapError: 'Could not load bootstrap pin info',
    serverTlsPin: 'Config Server TLS Pin',
    regenerateSigningKey: 'Regenerate Key',
    regenerateSigningConfirm: 'The signing key will be regenerated. All clients must update the public key in their APK. Continue?',
    signingRegenerated: 'Signing key regenerated',
    regenerateBootstrap: 'Regenerate Cert',
    regenerateBootstrapConfirm: 'The config server TLS certificate will be regenerated. All clients must update bootstrap pins. Server restart required. Continue?',
    bootstrapRegenerated: 'Bootstrap certificate regenerated — server restart required',
    rotateToBackup: 'Switch to Backup Key',
    rotateHostConfirm: 'The certificate will be reissued with the stored backup key and a new backup prepared. Devices already know the backup pin, so connections keep working. Continue?',
    rotateBootstrapConfirm: 'The config server certificate will switch to the stored backup key and a new backup will be prepared. Apps carry the backup pin as a bootstrap pin, so no app update is needed. Server restart required. Continue?',
    rotatedToBackup: 'Switched to the backup key; a new backup is ready',
    bootstrapRotated: 'Switched to the backup key — restart the server. Add the new backup pin to the next app release.',
    noBackupKey: 'No backup key is stored for this certificate: its pins were fetched from a URL, or it was generated before backup keys were kept. A backup key is created when the certificate is regenerated.',
    noSecondCertificate: 'The site serves its certificate alone, so there is no issuer to pin as the backup. Enter the pins by hand: the site\'s pin and the pin of a backup key its owner keeps.',
    pinsMustDiffer: 'At least two different pins are needed: a primary and a backup.',
    backupNotPublished: 'The stored backup key\'s pin is not among the published pins, so devices would reject it. Publish it first or regenerate the certificate.',
    tabAutoGenerate: 'Auto Generate', tabUploadJks: 'Upload JKS', tabFetchUrl: 'Fetch from URL',
    uploadJksLabel: 'Certificate File (JKS/P12/PFX)', uploadPassword: 'Keystore Password',
    uploadBtn: 'Upload', fetchUrlLabel: 'URL', fetchUrlPlaceholder: 'https://api.example.com',
    fetchBtn: 'Fetch', uploading: 'Uploading...', fetching: 'Connecting...',
    bootstrapUploaded: 'Certificate uploaded — server restart required',
    bootstrapFetched: 'Pins fetched',
    navMtls: 'mTLS',
    mtlsTitle: 'mTLS — Mutual TLS',
    mtlsSub: 'Two-way TLS authentication with client certificates',
    mtlsWhat: 'What is mTLS?',
    mtlsExplain: 'Mutual TLS (mTLS) requires both the server and the client to authenticate each other with certificates. In standard TLS, only the server is verified. With mTLS, unauthorized devices cannot access the config API — connections without a valid client certificate are rejected.',
    mtlsStatus: 'mTLS Status', mtlsEnabled: 'Enabled', mtlsDisabled: 'Disabled',
    mtlsEnvHint: 'To enable: start the server with MTLS_ENABLED=true',
    generateClientCert: 'Generate Client Cert', uploadClientCert: 'Upload Client Cert',
    clientCerts: 'Registered Client Certificates', noClientCerts: 'No client certificates yet',
    hostCertGuide: 'Upload a client cert for this host to enable mTLS. Once uploaded, enrolled devices will auto-download it via the mTLS Config API.',
    hostCertNone: 'No client cert uploaded',
    hostCertUploadHint: 'Upload a client cert in PKCS12 (.p12/.pfx) format',
    testConnection: 'Test Connection',
    testingConnection: 'Testing...',
    connTestOk: 'Connection successful',
    connTestFail: 'Connection failed',
    mockNotRunning: 'Mock server not running — start it first',
    thFingerprint: 'Fingerprint', thCreated: 'Created', thRevoked: 'Status',
    revoke: 'Revoke', active: 'Active', revoked: 'Revoked',
    certGenerated: 'Client certificate generated — downloading',
    certUploaded: 'Client certificate uploaded',
    certRevoked: 'Client certificate revoked',
    clientIdLabel: 'Client ID', clientIdPlaceholder: 'e.g. mobile-app-1',
    publicKey: 'Public Key (Base64, X.509)',
    androidIntegration: 'Android Integration',
    signingError: 'Could not load signing key',
    loading: 'Loading...',
    renewCert: 'Renew Certificate', renewAuto: 'Auto Generate', renewUpload: 'Upload JKS', renewFetch: 'Fetch from URL',
    renewAutoDesc: 'Generates a self-signed certificate automatically. Suitable for demo and testing.',
    renewUploadLabel: 'Certificate File (JKS/P12/PFX)', renewUploadPassword: 'Keystore Password',
    renewUploadBtn: 'Upload', renewFetchLabel: 'URL', renewFetchPlaceholder: 'https://api.example.com',
    renewFetchBtn: 'Fetch', certRenewed: 'Certificate renewed', certUploadRenewed: 'Certificate uploaded and updated',
    certFetchRenewed: 'Certificate fetched from URL and updated',
    vaultTitle: 'Vault Files', vaultSub: 'Remotely distributed files and distribution history',
    vaultUpload: 'Upload File', vaultDelete: 'Delete', vaultKey: 'Key',
    vaultVersion: 'Version', vaultSize: 'Size', vaultDistCount: 'Distributions',
    vaultNoFiles: 'No vault files yet', vaultUploadBtn: 'Upload',
    vaultUploadTitle: 'Upload to Vault',
    vaultUploadFileLabel: 'File', vaultUploadTextLabel: 'Text',
    vaultUploadTextPlaceholder: 'Paste plain text (instead of a .txt)…',
    vaultUploadHint: 'Pick a file or type text here — either one.',
    vaultUploadNeedContent: 'Pick a file or enter text',
    encDescPlain: 'No encryption — stored and served as-is (the connection is still pinned TLS). For non-sensitive content.',
    encDescAtRest: 'Stored AES-256-GCM encrypted on the server disk; decrypted when sent to the client (reaches the device as plaintext). Protects the content if the server disk/backup leaks.',
    encDescE2E: 'The file is encrypted with the target device\'s public key; only that device (with its Keystore private key) opens the delivered package — relays/caches/other devices can\'t. The app generates and registers the key automatically (a device not set up for E2E gets a 412). Note: the server performs the encryption, so it does see the content; to hide it from the server too, encrypt before upload.',
    vaultKeyPlaceholder: 'feature-flags', vaultFilePlaceholder: 'Choose file',
    vaultDistTitle: 'Distribution History', vaultNoDistHistory: 'No distribution records', vaultReason: 'Reason',
    vaultStats: 'Statistics', vaultTotalDist: 'Total Distributions',
    vaultUniqueDevices: 'Devices', vaultUniqueKeys: 'Files', vaultDownloaded: 'Downloaded',
    vaultFailed: 'Failed', vaultSucceeded: 'Successful', back: 'Back', vaultDevice: 'Device', vaultStatus: 'Status',
    vaultTimestamp: 'Date', vaultLabel: 'Label',
    vaultVersionTimeline: 'Version Timeline', vaultDeviceSummary: 'Device Summary',
    vaultFullHistory: 'Full History', vaultFetchCount: 'Fetches', vaultLastFetch: 'Last Fetch',
    vaultLastVersion: 'Last Ver.', vaultFileSummary: 'File Summary', vaultDeviceHistory: 'Device History',
    vaultSuccess: 'Success',
    // ── V2 additions ──
    tabGeneral: 'General', tabBootstrap: 'Bootstrap Pin', tabSigning: 'Signing',
    tabMtlsCerts: 'Client Certificates', tabVault: 'Vault', tabHistory: 'Connection History',
    vaultV2Section: 'Vault (V2)', vaultEnabledLabel: 'Vault enabled on this Config API',
    manageDeviceAcl: 'Manage Device ACL',
    vaultDisabledHint: 'When vault is disabled, this Config API\'s download endpoint (GET /api/v1/vault/{key}) returns 403 for every key; upload, list and delete stay available.',
    vaultEnabledOn: 'Vault enabled', vaultEnabledOff: 'Vault disabled', vaultToggleError: 'Could not change',
    aclManagerTitle: 'Device ACL', aclManagerSub: 'Per-device control of which hostnames\' pins can be fetched',
    aclBack: '← Back', aclSave: 'Save',
    defaultAclTitle: 'Default ACL (per Config API)',
    defaultAclHint: 'Devices without a per-device ACL inherit this list. Comma-separated hostnames.',
    defaultAclPlaceholder: 'e.g. cdn.example.com, api.example.com',
    defaultAclUpdated: 'Default ACL updated', defaultAclSaveError: 'Could not save',
    enrolledDevicesTitle: 'Enrolled Devices', noEnrolledDevices: 'No enrolled devices yet',
    aclEditBtn: 'Edit ACL', aclEditPrompt: 'Host ACL for device {0} (comma-separated):',
    aclUpdated: 'ACL updated',
    // Policy dropdown
    policyLabel: 'Policy', encryptionLabel: 'Encryption',
    policyTokenOpt: 'token (recommended)', policyPublicOpt: 'public (demo)',
    policyApiKeyOpt: 'api_key', policyTokenMtlsOpt: 'token + mTLS',
    policyApiKeyWarn: 'api_key: NOT downloadable from a device — the library never sends the admin key (it would ship inside the APK), so every fetch gets 401. Server-to-server tooling only. For devices pick token / token + mTLS.',
    // Vault file policy editing
    policyEditTitle: 'Access Policy & Encryption',
    policyEditHint: 'Changes the policy without touching the file content. token + mTLS requires a client certificate IN ADDITION to a valid token.',
    policySaveBtn: 'Save Policy', policyCurrent: 'Current',
    policySaved: 'Policy updated: {0}', policySaveError: 'Could not update policy',
    // Enrollment token — plaintext is shown exactly once
    enrollTokenGeneratedAlert: 'Enrollment token generated and copied to clipboard:\n\n{0}\n\nThis value will not be shown again. Deliver to device via a secure channel.',
    tokenMaskedHint: 'The server stores only a SHA-256 hash — this masked prefix cannot be used to enroll.',
    // Certificate expiry monitoring
    certExpiryTitle: 'Certificate Expiry', certNearExpiry: 'Near expiry',
    certExpiryHint: 'Remaining lifetime of each host certificate. The warning threshold is set by CERT_EXPIRY_WARN_DAYS on the server.',
    certExpiryEmpty: 'No certificates with expiry information.',
    certOk: 'valid', certWarning: 'expiring soon', certExpired: 'expired',
    certDaysLeft: '{0} days', certExpiredAgo: 'expired {0} days ago',
    certRemaining: 'Remaining', certValidUntil: 'Valid until',
    // Bulk force update
    forceAllTitle: 'Bulk Force Update',
    forceAllHint: 'Sets the force flag on every host of this Config API — devices are required to update their pins on the next fetch.',
    forceAllBtn: 'Force All', clearForceAllBtn: 'Clear All Force',
    forceAllConfirm: 'Force update will be set on ALL hosts of this Config API. Continue?',
    forceAllEnabled: 'Force update set on all hosts',
    forceAllDisabled: 'Force flags cleared',
    forceAllCount: '{0}/{1} hosts forced',
    // Add host — fetch from URL
    tabFetch: 'Fetch from URL',
    fetchUrlLabel: 'Server address',
    fetchUrlHint: 'Performs a TLS handshake and extracts the certificate pins automatically. e.g. https://api.example.com',
    // Bootstrap — fetch pins from URL
    bootstrapFetchLabel: 'Address to fetch pins from',
    bootstrapFetchHint: 'When the server sits behind a TLS terminator (reverse proxy), clients must pin the proxy\'s certificate. Pins are taken from that address.',
    bootstrapFetchBtn: 'Fetch Pins',
    // Token management
    tokenMgmtTitle: 'Token Management', tokenNewBtn: '+ New Token',
    tokenDevicePlaceholder: 'deviceId (e.g. mi-9t)',
    tokenMgmtHint: 'Tokens are valid per device + per file. Plaintext is shown only once at generation — if lost, issue a new one.',
    tokenColDeviceId: 'Device ID', tokenColStatus: 'Status', tokenColCreated: 'Created',
    tokenStatusActive: '✓ active', tokenStatusRevoked: '✗ revoked',
    tokenBtnRevoke: 'Revoke', tokenBtnDash: '—',
    tokenNoRows: 'No tokens for this file',
    tokenGeneratedAlert: 'Token generated and copied to clipboard:\n\n{0}\n\nThis value will not be shown again. Deliver to device via a secure channel.',
    tokenGenError: 'Token generation failed', tokenDeviceIdRequired: 'deviceId required',
    tokenRevokeConfirm: 'Token will be revoked (next fetch 401). Continue?',
    tokenRevoked: 'Token revoked', tokenRevokeError: 'Revoke failed',
    // Filter chip
    filterRemove: 'Remove filter',
    // Upload toast
    vaultUploadSuccess: '{0} v{1} [{2}/{3}] uploaded',
    // ── i18n sweep additions ──
    serverInfo: 'Server Info', mode: 'Mode', hostCountLabel: 'Host count',
    clientCertMtls: 'Client Cert (mTLS)', refresh: 'Refresh', addHostTooltip: 'Add host',
    pkcs12Hint: 'PKCS12 (.p12/.pfx)', apiIdLabel: 'API ID',
    newConfigApiTitle: 'New Config API', newConfigApiSub: 'Start a TLS or mTLS config API',
    modeTlsOption: 'TLS (one-way)', modeMtlsOption: 'mTLS (two-way — client cert required)',
    startConfigApi: 'Start Config API', deleteApi: 'Delete API',
    enrollmentToken: 'Enrollment Token', tokenRequiredBadge: 'Token required',
    openModeBadge: 'Open mode — deviceId enrollment active (demo)',
    secureFlowLabel: 'Secure flow:',
    secureFlowSteps: 'Admin generates token → App enrolls with token → Receives client cert → Accesses mTLS Config API → Host certs are downloaded automatically',
    enrollmentModeHint: 'Start the server with ENROLLMENT_MODE=token to disable deviceId enrollment.',
    generateToken: 'Generate Token', tokenUsed: 'Used', tokenPending: 'Pending',
    tokenExpired: 'Expired', tokenExpiresAt: 'Expires',
    thForce: 'Force', thToken: 'Token',
    revokeCertConfirm: '{0} will be revoked. Continue?',
    deleteFileConfirm: 'Delete "{0}"?', fileDeleted: '{0} deleted',
    mockServer: 'MOCK SERVER', algorithmLabel: 'Algorithm', validUntilLabel: 'Valid Until',
    updateClientCert: 'Update Client Cert',
    apiIdPlaceholder: 'tls-8093 or mtls-8092',
    mockStart: 'Start', thAuth: 'Auth',
    mockRemoteOnlyHint: 'No local mock for this host — the certificate was generated for pin validation only.',
    mockServerTitle: 'Mock Server', mockCertNeeded: 'a certificate is required for the mock server',
    vaultAuthError: 'Authorization error ({0}). Enter an API key from the top-right or run localStorage.setItem(\'pinvault_api_key\', \'testkey\') then refresh the page.',
    vaultUnexpectedResponse: 'Unexpected response format. Check the console: {0}',
    // ── Governance: identity, approvals, audit log, live check, signing ──
    navApprovals: 'Approvals', navAudit: 'Audit Log',
    adminUnknown: 'Not signed in', adminChipTitle: 'Owner of the admin key this dashboard uses',
    switchAdminKey: 'Switch key',
    switchAdminKeyPrompt: 'The stored key was cleared. Enter the new admin API key (X-API-Key):',
    adminKeySwitched: 'Admin: {0}',
    badgeApprovals: '{0}-person approval', badgeApprovalsTitle: 'Pin and key changes need {0} admins (PIN_CHANGE_APPROVALS)',
    badgeLiveCheck: 'Live check: {0}', badgeLiveCheckTitle: 'New pin sets are checked against the certificate each host serves now (PIN_LIVE_CHECK)',
    badgeSigCache: 'Signature cache', badgeSigCacheTitle: 'The same content is signed once and served again (CONFIG_SIGNATURE_CACHE)',
    liveModeWarn: 'warn', liveModeEnforce: 'enforce', liveModeOff: 'off',
    approvalsBadgeTitle: '{0} change(s) awaiting approval',
    pendingChange: 'Change #{0} is waiting for approval — nothing is applied until another admin approves it.',
    liveCheckFailedHeader: 'Live certificate check failed:',
    liveCheckOverridePrompt: '{0}\n\nTo save anyway, enter a reason (recorded in the audit log and notifications). Leave empty to cancel.',
    liveCheckBlocked: 'Not saved — live certificate check: {0}',
    liveCheckWarnSaved: 'Saved, but the live certificate check failed (warn mode) — details in the Audit Log.',
    liveOk: '{0}: the served leaf ({1}…) is in the pin set',
    liveNotInSet: '{0}: served leaf {1}… is not in the set',
    liveUnreachable: '{0}: unreachable — {1}',
    liveIssuerNoChain: 'The set pins a certificate further up the chain, but the served certificate does not validly chain to it (expired, not a CA, or not signed by it).',
    liveOkIssuer: '{0}: the served certificate chains to the pinned issuer (CA, {1}…)',
    liveProbed: 'probed', liveCheckTitle: 'Live certificate check',
    livePassed: 'passed', liveFailed: 'failed',
    liveEnforceWillFail: 'The live check fails in enforce mode: the request carries no liveCheckOverride, so approving it will not apply it (HTTP 422).',
    liveOverrideCarried: 'The request carries a liveCheckOverride reason: {0}',
    liveCheckBtn: 'Live Check', liveCheckBtnTitle: 'Compares these pins with the certificate the host serves now (does not save)',
    liveCheckRunning: 'Checking the host…', liveCheckNeedHost: 'Enter a hostname first', liveCheckNeedPins: 'Enter at least one pin',
    liveRotationHint: 'Rotation: publish {current, next} first, switch the host\'s certificate, then publish {next, backup}.',
    approvalsTitle: 'Approvals', approvalsSub: 'Pin and key changes wait for a second admin (two-person rule).',
    approvalsOff: 'Two-person approval is off (PIN_CHANGE_APPROVALS=1): changes apply immediately. Start the server with PIN_CHANGE_APPROVALS=2 and personal ADMIN_KEYS to turn it on.',
    approvalsOn: 'Each change is applied once {0} admin(s) other than the requester approve it. You: {1}.',
    tabPending: 'Pending ({0})', tabDecided: 'History ({0})',
    noPendingChanges: 'No changes are waiting for approval.', noDecidedChanges: 'No decided changes yet.',
    crRequestedBy: 'Requested by', crCreated: 'Created', crExpires: 'Expires', crApprovals: 'Approvals',
    crDetails: 'Details', crDecidedBy: 'Decided by', crDecidedAt: 'Decided at', crReason: 'Reason',
    crResult: 'Result', crResultBody: 'Server response',
    approve: 'Approve', reject: 'Reject', withdraw: 'Withdraw',
    cannotApproveOwn: 'You cannot approve your own request — another admin must.',
    cannotApproveShared: 'A shared key (API_KEY) cannot approve: it does not say who approves. Use your personal key from ADMIN_KEYS.',
    alreadyApproved: 'You already approved this request.',
    rejectReasonPrompt: 'Reject #{0}. Reason (optional):',
    withdrawReasonPrompt: 'Withdraw #{0}. Reason (optional):',
    changeApplied: 'Change #{0} approved and applied',
    changeApplyFailed: 'Change #{0} was approved but could not be applied (HTTP {1})',
    changeApprovalRecorded: 'Approval recorded (#{0}: {1}/{2})',
    changeRejected: 'Change #{0} rejected', changeWithdrawn: 'Change #{0} withdrawn',
    crStatus_pending: 'pending', crStatus_applied: 'applied', crStatus_failed: 'failed',
    crStatus_rejected: 'rejected', crStatus_expired: 'expired', crStatus_stale: 'stale',
    op_pins_update: 'Pin update', op_force_on: 'Force on', op_force_off: 'Force off',
    op_host_add: 'Add host', op_host_cert: 'Host certificate', op_config_api_delete: 'Delete Config API',
    op_config_api_lifecycle: 'Start/stop Config API',
    op_bootstrap_pins: 'Bootstrap pins', op_signing_key: 'Signing key', op_signing_keyset: 'Key set',
    diffGlobalForce: 'Global force', diffOn: 'on', diffOff: 'off',
    diffNoDetail: 'No pin diff for this operation; the summary and the request path describe the change.',
    diffNoChange: 'No pin change.', diffDescribeError: 'Could not compute the diff: {0}',
    auditTitle: 'Audit Log', auditSub: 'Every admin action, kept in an append-only, hash-chained log.',
    auditVerify: 'Verify Chain', auditVerifyOk: 'Chain intact — {0} entries', auditVerifyBroken: 'Chain broken at #{0}',
    auditFilterAll: 'All actions', auditThTime: 'Time', auditThActor: 'Actor', auditThAction: 'Action',
    auditThTarget: 'Target', auditThSummary: 'Summary', auditEmpty: 'No entries',
    auditSourceIp: 'Source IP', auditNoDetail: 'No further detail', auditEntries: '{0} entries',
    act_pins_changed: 'Pins changed', act_change_requested: 'Change requested', act_change_approved: 'Approval given',
    act_change_applied: 'Change applied', act_change_failed: 'Change failed', act_change_rejected: 'Change rejected',
    act_change_expired: 'Change expired', act_change_stale: 'Change stale',
    act_change_approval_refused: 'Approval refused',
    act_live_check_warning: 'Live check warning', act_live_check_blocked: 'Live check blocked', act_live_check_overridden: 'Live check overridden',
    act_signing_key_regenerated: 'Signing key regenerated', act_signing_keyset_uploaded: 'Key set uploaded',
    act_auth_failed: 'Invalid API key', act_cert_expiring: 'Certificate expiring',
    act_notification_test: 'Test notification', act_http: 'Admin request',
    notifTitle: 'Webhook Notifications', notifStatus: 'Status', notifConfigured: 'Configured',
    notifNotConfigured: 'Not configured — set NOTIFY_WEBHOOK_URL to enable',
    notifTarget: 'Target', notifSigned: 'HMAC signature', notifSignedYes: 'Yes (X-PinVault-Signature)',
    notifSignedNo: 'No — NOTIFY_WEBHOOK_SECRET is not set', notifEvents: 'Events',
    notifRecent: 'Recent deliveries', notifNoDeliveries: 'No deliveries yet',
    notifTestBtn: 'Send Test Notification', notifTestSent: 'Test notification queued (audit #{0})',
    notifThAttempts: 'Attempts', notifThAudit: 'Audit',
    signersTitle: 'Signers',
    signersHint: 'Every signer signs every config; devices configured with requiredSignatures(n) need n of them. The first signer is the primary — older clients read its signature.',
    thSignerName: 'Name', thSignerType: 'Type', thKeyId: 'Key ID', thDescription: 'Description',
    primarySigner: 'primary', signerNotInSet: 'This key is not in the active set',
    sigCacheTitle: 'Signature Cache',
    sigCacheOn: 'On — the same content is signed once and the same envelope served for half its TTL (only to clients sending X-PinVault-Features: redelivery).',
    sigCacheOff: 'Off — every request is signed fresh (enable with CONFIG_SIGNATURE_CACHE=true).',
    sigTtl: 'Config TTL', sigProduced: 'Signatures produced', sigCacheHits: 'Cache hits', sigCachedEnvelopes: 'Cached envelopes',
    unitHours: '{0} h', unitMinutes: '{0} min', unitSeconds: '{0} s',
    keysetTitle: 'Signing-Key Set',
    keysetHint: 'A signing-key set lists the signing keys devices accept (rotation / revocation). It is signed OFFLINE with the recovery key(s); the server only checks it and relays it to devices.',
    keysetDisabled: 'Off — RECOVERY_PUBLIC_KEYS is not set; set uploads are refused.',
    keysetNone: 'No set uploaded yet (version 0).',
    keysetVersion: 'Set version', keysetKeyIds: 'Listed keys', keysetRequired: 'Required signatures',
    keysetRecoveryKeys: 'Recovery keys', keysetRecoveryRequired: 'Required recovery signatures',
    keysetUploadedBy: 'Uploaded by', keysetUploadedAt: 'Uploaded at',
    keysetMissingWarn: 'Warning: these active signers are NOT in the set — devices that applied it reject configs signed only by them: {0}',
    keysetPasteLabel: 'Signed set (JSON: payload + signatures)',
    keysetUploadBtn: 'Upload Set', keysetPasteFirst: 'Paste the signed set first',
    keysetInvalidJson: 'Invalid JSON: {0}', keysetBadShape: 'Expected shape: {"payload": "…", "signatures": [{"keyId": "…", "signature": "…"}]}',
    keysetUploaded: 'Signing-key set v{0} uploaded', keysetUploadWarnings: 'Warnings', keysetRejected: 'Set rejected',
    regenDisabledSigner: 'The primary signer is "{0}": rotate its key where it lives (HSM/KMS) and restart the server with the new key.',
    regenDisabledKeySet: 'A signing-key set is active: a freshly generated key would be in no set and devices that applied one would reject it. Rotate through a set.',
    signingStatusError: 'Could not load signing status',
  }
};

let lang = localStorage.getItem('pinvault_lang') || 'tr';
/**
 * Translate [key]. Optional positional args substitute `{0}`, `{1}`, … in
 * the localized string. Missing keys fall back to the key itself so UI is
 * never blank even for typos.
 */
function t(key, ...args) {
  const raw = i18n[lang]?.[key] || i18n.tr[key] || key;
  if (args.length === 0) return raw;
  return raw.replace(/\{(\d+)\}/g, (_, i) => args[+i] ?? '');
}

function setLang(newLang) {
  if (newLang === lang) return;
  lang = newLang;
  localStorage.setItem('pinvault_lang', lang);
  updateLangUI();
  renderHostList();
  if (selectedHost) selectHost(selectedHost);
  else if (currentSection) showSection(currentSection);
  else renderEmpty();
}

function updateLangUI() {
  document.getElementById('lang-tr').classList.toggle('active', lang === 'tr');
  document.getElementById('lang-en').classList.toggle('active', lang === 'en');
  document.getElementById('sidebar-hosts-label').textContent = 'Config API';
  const btnAddApi = document.getElementById('btn-add-api');
  if (btnAddApi) btnAddApi.textContent = '+ Config API';
  const navHealth = document.getElementById('nav-health');
  if (navHealth) navHealth.textContent = t('healthTitle');
  const navApprovals = document.getElementById('nav-approvals-label');
  if (navApprovals) navApprovals.textContent = t('navApprovals');
  const navAudit = document.getElementById('nav-audit');
  if (navAudit) navAudit.textContent = t('navAudit');
  renderAdminChip();
  setApprovalsBadge(_approvalsPending);
}

// ── Init ─────────────────────────────────────────────

async function init() {
  updateLangUI();
  await loadConfig();
  renderHostList();
  renderEmpty();
  // After loadConfig: its request is the one that asks for a missing key.
  // These two are quiet and must never open a dialog themselves.
  await loadAdminIdentity();
  refreshApprovalsBadge();
}

/**
 * Üzerinde çalışılan Config API kapsamı. Kenar çubuğunda bir Config API ya da
 * host seçildiğinde `selectedApiId` dolar; hiçbiri seçilmemişken (ilk açılış)
 * varsayılan kapsama düşülür.
 */
function scopeId() { return selectedApiId || 'default-tls'; }

async function loadConfig() {
  try {
    // Tüm API'lerin özetini al
    const apisRes = await apiFetch('/api/v1/all-configs');
    // A refused request (no/invalid key) answers `{error}`, not a list —
    // treat it as a failed load instead of iterating an object later.
    if (!apisRes.ok) throw new Error('all-configs: HTTP ' + apisRes.status);
    allApiConfigs = await apisRes.json();

    // SEÇİLİ Config API'nin config'i. Eskiden burası her zaman
    // `/api/v1/certificate-config?signed=false` okuyordu; o uç management
    // server'da `default-tls` kapsamına sabit. `currentConfig` üzerinden
    // çalışan "+ → Manuel", "Pinleri Düzenle" ve "Hostu Sil" yolları bu
    // yüzden başka bir kapsam seçiliyken bile varsayılan kapsamı okuyup
    // yazıyordu. `/api/v1/config/{id}` kapsamlıdır (ve yalnızca yönetim
    // API anahtarıyla erişilir) — host detayı zaten bunu kullanıyordu.
    const res = await apiFetch(`/api/v1/config/${encodeURIComponent(scopeId())}`);
    if (!res.ok) throw new Error('config: HTTP ' + res.status);
    currentConfig = await res.json();
    console.log('Config loaded:', currentConfig, 'scope:', scopeId(), 'APIs:', allApiConfigs);
  } catch (e) {
    console.error('Config load failed', e);
    currentConfig = { version: 0, pins: [], forceUpdate: false };
    allApiConfigs = [];
  }
}

function renderEmpty() {
  document.getElementById('content').innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">&#x1F510;</div>
      <div class="empty-title">${t('selectHost')}</div>
      <div class="empty-sub">${t('selectHostSub')}</div>
    </div>`;
}

// ── Pagination helper ───────────────────────────────
//
// Sayfalama tüm geçmiş tabloları için kullanılır: global bağlantı geçmişi,
// host bazlı bağlantı geçmişi, vault distribution, pin history. Sayfa durumu
// (_pagState) anahtar başına saklanır — `onChange` callback'i render'ı
// tekrar tetikler. Sayfa boyutu 10/25/50/100 seçenekli, varsayılan 10.
const _pagState = {}; // key -> { page, size }
const PAG_DEFAULT_SIZE = 10;

function pagSlice(items, key) {
  const st = _pagState[key] || (_pagState[key] = { page: 0, size: PAG_DEFAULT_SIZE });
  const size = st.size > 0 ? st.size : items.length || 1;
  const pageCount = Math.max(1, Math.ceil(items.length / size));
  if (st.page >= pageCount) st.page = pageCount - 1;
  if (st.page < 0) st.page = 0;
  const start = st.page * size;
  return { slice: items.slice(start, start + size), page: st.page, pageCount, size: st.size, total: items.length };
}

function pagControls(key, info, onChangeGlobalFn) {
  // Az kayıtta da "X / Toplam" sayacı + sayfa boyutu seçici görünsün;
  // prev/next butonları sadece birden fazla sayfa varsa aktif.
  const prev = info.page > 0;
  const next = info.page < info.pageCount - 1;
  const cb = onChangeGlobalFn ? esc(onChangeGlobalFn) : '';
  const btn = (label, enabled, newPage) => enabled
    ? `<button class="btn" style="padding:2px 8px;font-size:11px" data-action="pagGo" data-arg0="${esc(key)}" data-arg1="${newPage}" data-arg2="${cb}">${label}</button>`
    : `<button class="btn" style="padding:2px 8px;font-size:11px;opacity:.35;cursor:not-allowed" disabled>${label}</button>`;
  const sizeOpts = [10, 25, 50, 100].map(s => `<option value="${s}" ${s === info.size ? 'selected' : ''}>${s}</option>`).join('');
  const shownStart = info.total === 0 ? 0 : info.page * info.size + 1;
  const shownEnd = Math.min(info.total, (info.page + 1) * info.size);
  return `<div style="display:flex;gap:8px;align-items:center;padding:6px 0;font-size:11px;color:#94a3b8;justify-content:flex-end">
    <span>${shownStart}-${shownEnd} / ${info.total}</span>
    <select data-action-change="pagSizeChange" data-arg0="${esc(key)}" data-arg1="${cb}" data-event="1" style="background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:4px;padding:2px 4px;font-size:11px">${sizeOpts}</select>
    ${btn('«', prev, 0)}
    ${btn('‹', prev, info.page - 1)}
    <span>${info.page + 1} / ${info.pageCount}</span>
    ${btn('›', next, info.page + 1)}
    ${btn('»', next, info.pageCount - 1)}
  </div>`;
}

function pagGo(key, page, onChangeGlobalFn) {
  const st = _pagState[key] || (_pagState[key] = { page: 0, size: PAG_DEFAULT_SIZE });
  st.page = parseInt(page, 10) || 0;
  if (onChangeGlobalFn && typeof window[onChangeGlobalFn] === 'function') window[onChangeGlobalFn]();
}
function pagSize(key, size, onChangeGlobalFn) {
  const st = _pagState[key] || (_pagState[key] = { page: 0, size: PAG_DEFAULT_SIZE });
  st.size = parseInt(size, 10) || PAG_DEFAULT_SIZE;
  st.page = 0;
  if (onChangeGlobalFn && typeof window[onChangeGlobalFn] === 'function') window[onChangeGlobalFn]();
}

// ── Host List ────────────────────────────────────────

let hostStatuses = {}; // hostname -> { mockServerRunning, mockServerPort, keystorePath }
let _hostStatusesLastFetch = 0;     // epoch ms — in-flight throttle
let _hostStatusesInFlight = null;   // promise varsa tekrar atma
const HOST_STATUS_TTL_MS = 15000;   // 15sn içinde tekrar fetch etme

function getHosts() {
  if (!currentConfig) return [];
  return currentConfig.pins.map(p => ({ hostname: p.hostname, pinCount: p.sha256.length, sha256: p.sha256, version: p.version || 0 }));
}

async function loadAllHostStatuses(opts = {}) {
  const now = Date.now();
  // TTL içinde ise cache'i kullan. `force:true` ile manuel bypass.
  if (!opts.force && (now - _hostStatusesLastFetch) < HOST_STATUS_TTL_MS) {
    return;
  }
  // Aynı anda birden fazla tetiklenmesin — tek promise'a bind et.
  if (_hostStatusesInFlight) return _hostStatusesInFlight;

  _hostStatusesInFlight = (async () => {
    const tasks = [];
    for (const api of allApiConfigs) {
      if (!api.pins) continue;
      for (const p of api.pins) {
        tasks.push((async () => {
          try {
            const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(p.hostname)}/status`);
            if (res.ok) hostStatuses[p.hostname] = await res.json();
          } catch (_) {}
          // Remote reachability — mock çalışsa bile kontrol et
          try {
            const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(p.hostname)}/ping-remote`);
            if (res.ok) {
              const ping = await res.json();
              hostStatuses[p.hostname] = { ...(hostStatuses[p.hostname] || {}), remote: ping };
            }
          } catch (_) {}
        })());
      }
    }
    await Promise.all(tasks);
    _hostStatusesLastFetch = Date.now();
  })();

  try { await _hostStatusesInFlight; } finally { _hostStatusesInFlight = null; }
}

async function renderHostList() {
  const list = document.getElementById('host-list');

  if (allApiConfigs.length === 0) {
    list.innerHTML = `<div class="loading">${t('noPins')}</div>`;
    return;
  }

  // Cached durumla anında render — tıklama seçimi bekletmesin.
  // Arka planda fresh status çekip bir kere daha render edeceğiz.
  renderHostListSync();

  // Host durumlarını arkaplanda yenile, sonra yeniden render et.
  loadAllHostStatuses().then(() => renderHostListSync()).catch(() => {});
  return;
}

function renderHostListSync() {
  const list = document.getElementById('host-list');
  if (!list || allApiConfigs.length === 0) return;

  // Tree yapısı — açık/kapalı state
  if (!window._apiExpanded) window._apiExpanded = {};

  let html = '';
  for (const api of allApiConfigs) {
    const isRunning = api.running !== false;
    const modeColor = isRunning ? (api.mode === 'mtls' ? '#f59e0b' : '#22c55e') : '#475569';
    const modeLabel = api.mode.toUpperCase();
    const isSelectedApi = selectedApiId === api.id;
    const isExpanded = window._apiExpanded[api.id] !== false; // varsayılan açık
    const arrow = isExpanded ? '▼' : '▶';
    const apiBg = isSelectedApi ? 'background:rgba(59,130,246,0.15);border-radius:4px;' : '';
    const hostCount = api.pins?.length || 0;
    const stoppedBadge = !isRunning ? '<span style="color:#ef4444;font-size:8px;font-weight:700;margin-left:4px">●</span>' : '';

    html += `<div class="api-group" style="margin-bottom:4px">
      <div class="api-header" style="padding:6px 10px;font-size:11px;font-weight:700;color:${modeColor};cursor:pointer;${apiBg};display:flex;justify-content:space-between;align-items:center;user-select:none;${!isRunning ? 'opacity:0.6;' : ''}" data-action="toggleApiTree" data-arg0="${esc(api.id)}">
        <span style="display:flex;align-items:center;gap:6px">
          <span style="font-size:9px;color:#64748b">${arrow}</span>
          <span>${modeLabel} :${api.port}${stoppedBadge}</span>
          <span style="color:#475569;font-weight:400;font-size:10px">(${hostCount})</span>
        </span>
        ${isRunning ? `<span style="font-size:16px;color:#60a5fa;cursor:pointer;line-height:1" data-action="showAddHostScoped" data-arg0="${esc(api.id)}" data-stop="1" title="${t('addHostTooltip')}">+</span>` : ''}
      </div>`;

    if (isExpanded) {
      if (api.pins && api.pins.length > 0) {
        // Sidebar'daki host listesi de sayfalamalı — API başına anahtar.
        // 10'dan az host'ta nav gizlenir (pagControls kendisi halleder).
        const hostsPagKey = 'sidebar-hosts-' + api.id;
        const hostsPagInfo = pagSlice(api.pins, hostsPagKey);
        for (const p of hostsPagInfo.slice) {
          const isSelected = selectedHost === p.hostname && selectedApiId === api.id;
          const forceBadge = p.forceUpdate ? '<span style="color:#22c55e;font-size:9px;font-weight:700;margin-left:4px">FORCE</span>' : '';
          const hs = hostStatuses[p.hostname];
          // Priority: local mock running > remote pin OK > remote reachable w/ pin mismatch >
          // remote unreachable > has cert (mock down) > bilinmiyor
          const dotClass =
              hs?.mockServerRunning                     ? 'host-dot-running'  :
              (hs?.remote?.reachable && hs?.remote?.pinMatch) ? 'host-dot-remote' :
              (hs?.remote?.reachable && !hs?.remote?.pinMatch) ? 'host-dot-warn' :
              (hs?.remote && hs?.remote?.reachable === false) ? 'host-dot-offline' :
              hs?.keystorePath                          ? 'host-dot-cert'     :
                                                          'host-dot';
          const dotTitle =
              hs?.mockServerRunning                     ? 'Local mock ayakta' :
              (hs?.remote?.reachable && hs?.remote?.pinMatch) ? `Remote OK (:${hs.remote.port}) · pin match` :
              (hs?.remote?.reachable && !hs?.remote?.pinMatch) ? `⚠ Pin mismatch (:${hs.remote.port}) — cert rotate?` :
              (hs?.remote && hs?.remote?.reachable === false) ? `Offline — ${hs.remote.error || 'unreachable'}` :
              hs?.keystorePath                          ? 'Cert var, mock kapalı' :
                                                          'Durum bilinmiyor';
          html += `
            <div class="host-item ${isSelected ? 'selected' : ''}" style="margin-left:20px" data-action="selectHostInApi" data-arg0="${esc(p.hostname)}" data-arg1="${esc(api.id)}">
              <div class="${dotClass}" title="${dotTitle}"></div>
              <div class="host-info">
                <div class="host-name" style="font-size:13px">${p.hostname}${forceBadge}</div>
                <div class="host-pins">${p.sha256?.length || 0} ${t('pins')} · v${p.version || 0}</div>
              </div>
            </div>`;
        }
        // Sidebar sayfalama navigasyonu — sadece >10 host'ta görünür.
        if (api.pins.length > 10) {
          const pk = 'sidebar-hosts-' + api.id;
          const pi = pagSlice(api.pins, pk);
          html += `<div style="margin-left:20px">${pagControls(pk, pi, 'renderHostListSync')}</div>`;
        }
      } else {
        html += `<div style="padding:4px 12px 4px 32px;color:#475569;font-size:11px">${t('noPins')}</div>`;
      }
    }

    html += '</div>';
  }

  list.innerHTML = html;
}

function toggleApiTree(apiId) {
  if (!window._apiExpanded) window._apiExpanded = {};
  if (selectedApiId === apiId) {
    // Zaten seçiliyse aç/kapat
    window._apiExpanded[apiId] = window._apiExpanded[apiId] === false ? true : false;
  } else {
    // Farklı API seçildi — aç ve detay göster
    window._apiExpanded[apiId] = true;
  }
  selectedApiId = apiId;
  selectedHost = null;
  currentSection = null;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('selected'));
  renderHostListSync();
  renderHostList();
  // Önceki host spinner/detay'ını anında temizle — Config API başlığı için
  // yeni bir loading state yaz.
  renderConfigApiLoading(apiId);
  renderConfigApiDetail(apiId);
}

function renderConfigApiLoading(apiId) {
  const el = document.getElementById('content');
  if (!el) return;
  el.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:60vh;color:#475569">
      <div style="width:32px;height:32px;border:3px solid #334155;border-top-color:#60a5fa;border-radius:50%;animation:hostDetailSpin 0.8s linear infinite;margin-bottom:16px"></div>
      <div style="font-size:13px;color:#64748b">${apiId}</div>
    </div>
    <style>@keyframes hostDetailSpin { to { transform: rotate(360deg); } }</style>`;
}

// ── Config API Detail (tabbed) ──────────────────────

let configApiTab = 'general';

async function renderConfigApiDetail(apiId) {
  const api = allApiConfigs.find(a => a.id === apiId);
  if (!api) {
    // allApiConfigs henüz yüklenmediyse veya silinmişse loading state'inde
    // takılı kalmayalım — anlamlı bir boş mesaj göster.
    const el = document.getElementById('content');
    if (el) el.innerHTML = `<div class="empty-state"><div class="empty-title">${apiId}</div><div class="empty-sub">${t('selectHostSub') || ''}</div></div>`;
    return;
  }

  const modeColor = api.mode === 'mtls' ? '#f59e0b' : '#22c55e';
  const tabs = [
    { id: 'general', label: t('tabGeneral') },
    ...(api.mode === 'tls' ? [{ id: 'bootstrap', label: t('tabBootstrap') }] : []),
    { id: 'signing', label: t('tabSigning') },
    ...(api.mode === 'mtls' ? [{ id: 'mtls', label: t('tabMtlsCerts') }] : []),
    { id: 'vault', label: t('tabVault') },
    { id: 'history', label: t('tabHistory') }
  ];
  // Seçili tab bu API'de yoksa genel'e dön
  if (!tabs.find(t => t.id === configApiTab)) configApiTab = 'general';

  const tabBar = tabs.map(tab =>
    `<button class="tab-btn ${configApiTab === tab.id ? 'tab-active' : ''}" data-action="setConfigApiTab" data-arg0="${esc(tab.id)}" data-arg1="${esc(apiId)}">${tab.label}</button>`
  ).join('');

  const isRunning = api.running !== false;
  const toggleHtml = `
    <div style="display:flex;align-items:center;gap:10px">
      <div style="cursor:pointer;display:flex;align-items:center;gap:10px" data-action="toggleConfigApi" data-arg0="${esc(apiId)}">
        <div style="width:40px;height:22px;border-radius:11px;background:${isRunning ? '#22c55e' : '#334155'};position:relative;transition:background 0.2s">
          <div style="width:18px;height:18px;border-radius:50%;background:white;position:absolute;top:2px;${isRunning ? 'right:2px' : 'left:2px'};transition:all 0.2s"></div>
        </div>
        <span style="color:${isRunning ? '#22c55e' : '#64748b'};font-weight:700;font-size:13px">${isRunning ? t('mockRunning') : t('mockStopped')}</span>
      </div>
      ${!isRunning ? `
        <input id="capi-port-${apiId}" class="form-input" style="width:80px;padding:4px 8px;font-size:12px" value="${api.port}" placeholder="${t('mockPort')}">
      ` : ''}
    </div>`;

  document.getElementById('content').innerHTML = `
    <div class="section-header">
      <div>
        <div class="section-title-main" style="display:flex;align-items:center;gap:8px">
          <span style="color:${modeColor};font-weight:700">${api.mode.toUpperCase()}</span>
          :${api.port}
          <span style="color:#64748b;font-size:14px;font-weight:400">${esc(api.id)}</span>
        </div>
        <div class="section-sub" style="display:flex;align-items:center;gap:12px">
          <span>${api.pins?.length || 0} host · v${api.version}</span>
          ${toggleHtml}
        </div>
      </div>
      <div class="action-bar">
        <button class="btn btn-danger" data-action="deleteConfigApi" data-arg0="${esc(apiId)}">${t('deleteApi')}</button>
      </div>
    </div>
    <div class="tab-bar" style="margin-bottom:16px">${tabBar}</div>
    <div id="config-api-tab-content"><div class="loading">${t('loading')}</div></div>`;

  // Tab içeriğini yükle — her tab fonksiyonu content'e yazar
  // general tab'ı config-api-tab-content'e yazar, diğerleri content'in üzerine yazar
  if (configApiTab === 'general') {
    renderApiGeneralTab(apiId);
  } else {
    // Diğer tab'lar content'e yazacak — header+tabbar'ı kaybederiz
    // O yüzden content'e yazdıktan sonra başa header+tabbar ekleyelim
    const headerHtml = document.getElementById('content').innerHTML;
    switch (configApiTab) {
      case 'bootstrap': await renderBootstrapSection(); break;
      case 'signing': await renderSigningSection(); break;
      case 'mtls': await renderMtlsSection(); break;
      case 'vault': await renderApiVaultTab(apiId); break;
      case 'history': await renderHealthSection(); break;
    }
    // Tab fonksiyonu content'i değiştirdi — başına header+tabbar ekle
    const tabContent = document.getElementById('content').innerHTML;
    document.getElementById('content').innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="display:flex;align-items:center;gap:8px">
            <span style="color:${modeColor};font-weight:700">${api.mode.toUpperCase()}</span>
            :${api.port}
            <span style="color:#64748b;font-size:14px;font-weight:400">${esc(api.id)}</span>
          </div>
          <div style="margin-top:4px">${toggleHtml}</div>
        </div>
        <div class="action-bar">
          <button class="btn btn-danger" data-action="deleteConfigApi" data-arg0="${esc(apiId)}">${t('deleteApi')}</button>
        </div>
      </div>
      <div class="tab-bar" style="margin-bottom:16px">${tabBar}</div>
      ${tabContent}`;
  }
}

async function renderApiGeneralTab(apiId) {
  const api = allApiConfigs.find(a => a.id === apiId);
  if (!api) return;
  const container = document.getElementById('config-api-tab-content');
  if (!container) return;

  // V2: read the vault_enabled flag for this Config API so the toggle shows
  // the current value. If the endpoint errs (old server), default to true.
  let vaultEnabled = true;
  try {
    const r = await apiFetch(`/api/v1/config-apis/${encodeURIComponent(apiId)}/vault-enabled`);
    if (r.ok) {
      const d = await r.json();
      vaultEnabled = d.vault_enabled === 'true' || d.vault_enabled === true;
    }
  } catch (_) { /* ignore */ }

  const hostsPagKey = 'api-hosts-' + apiId;
  const hostsPagInfo = (api.pins && api.pins.length > 0) ? pagSlice(api.pins, hostsPagKey) : null;
  const hostRows = hostsPagInfo
    ? hostsPagInfo.slice.map(p => `<tr>
        <td style="font-weight:600">${p.hostname}</td>
        <td><span class="ver-badge">v${p.version}</span></td>
        <td>${p.sha256?.length || 0} pin</td>
        <td>${p.forceUpdate ? '<span style="color:#22c55e;font-weight:700">FORCE</span>' : '<span style="color:#64748b">Normal</span>'}</td>
      </tr>`).join('')
    : `<tr><td colspan="4" style="color:#475569">${t('noPins')}</td></tr>`;
  const reloadKey = '_reloadApiGeneral_' + apiId.replace(/[^a-zA-Z0-9]/g,'_');
  window[reloadKey] = () => renderApiGeneralTab(apiId);
  const hostsPagNav = hostsPagInfo ? pagControls(hostsPagKey, hostsPagInfo, reloadKey) : '';

  container.innerHTML = `
    <div class="card">
      <div class="card-title">${t('serverInfo')}</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;color:#94a3b8;font-size:13px">
        <div>${t('mockPort')}: <span style="color:#7dd3fc;font-weight:600">:${api.port}</span></div>
        <div>${t('mode')}: <span style="color:${api.mode === 'mtls' ? '#f59e0b' : '#22c55e'};font-weight:600">${api.mode.toUpperCase()}</span></div>
        <div>${t('hostCountLabel')}: <span style="color:#7dd3fc;font-weight:600">${api.pins?.length || 0}</span></div>
        <div>${t('version')}: <span style="color:#7dd3fc;font-weight:600">v${api.version}</span></div>
      </div>
    </div>
    <!-- Global force update — sunucudaki toplu uçlar (host adı almayan
         force-update / clear-force) arayüzde hiç kullanılmıyordu. -->
    <div class="card">
      <div class="card-title">${t('forceAllTitle')}</div>
      <div style="color:#94a3b8;font-size:12px;margin-bottom:10px">${t('forceAllHint')}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button class="btn btn-warning" data-action="forceUpdateAll" data-arg0="${esc(apiId)}">${t('forceAllBtn')}</button>
        <button class="btn btn-secondary" data-action="clearForceAll" data-arg0="${esc(apiId)}">${t('clearForceAllBtn')}</button>
        <span style="color:#64748b;font-size:11px">${t('forceAllCount', (api.pins || []).filter(p => p.forceUpdate).length, api.pins?.length || 0)}</span>
      </div>
    </div>
    <!-- V2 Vault toggle + Device ACL shortcut -->
    <div class="card">
      <div class="card-title">${t('vaultV2Section')}</div>
      <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:#e2e8f0">
          <input type="checkbox" id="vault-enabled-${apiId}" ${vaultEnabled ? 'checked' : ''}
                 data-action-change="setVaultEnabledChange" data-arg0="${esc(apiId)}" data-event="1"/>
          <span>${t('vaultEnabledLabel')}</span>
        </label>
        <button class="btn btn-secondary" style="padding:4px 10px;font-size:12px"
                data-action="showDeviceAclManager" data-arg0="${esc(apiId)}">${t('manageDeviceAcl')}</button>
        <span style="color:#64748b;font-size:11px">${t('vaultDisabledHint')}</span>
      </div>
    </div>
    <div class="card">
      <div class="card-title">${t('hosts')}</div>
      <table class="data-table">
        <thead><tr><th>${t('hostname')}</th><th>${t('version')}</th><th>${t('thPin')}</th><th>${t('thForce')}</th></tr></thead>
        <tbody>${hostRows}</tbody>
      </table>${hostsPagNav}
    </div>`;
}

async function setVaultEnabled(apiId, enabled) {
  // Kutuyu sunucunun yanıtına bağla. Önceden yazma başarısız olsa da kutu
  // kullanıcının bıraktığı konumda kalıyordu: operatör "vault kapalı" sanıp
  // dosyanın inmeye devam ettiğini fark etmiyordu (bulgu C09). Hata olursa
  // kutuyu eski konumuna al ve durum kodunu toast'a yaz.
  const box = document.getElementById(`vault-enabled-${apiId}`);
  const revert = () => { if (box) box.checked = !enabled; };
  try {
    const res = await apiFetch(`/api/v1/config-apis/${encodeURIComponent(apiId)}/vault-enabled`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    if (!res.ok) {
      revert();
      toast(`${t('vaultToggleError')} — ${apiId} (HTTP ${res.status})`, 'error');
      return;
    }
    toast(`${enabled ? t('vaultEnabledOn') : t('vaultEnabledOff')} — ${apiId}`, 'success');
  } catch (err) {
    revert();
    toast(err.message, 'error');
  }
}

/**
 * V2 Device ACL manager: lists enrolled devices + lets admin edit
 * per-device host ACL and default ACL for a Config API. Uses the
 * adminVaultRoutes endpoints added in backend phase 2.5.
 */
async function showDeviceAclManager(configApiId) {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    // Fetch default ACL + enrolled devices (reuse existing endpoint).
    const [defRes, devRes] = await Promise.all([
      apiFetch(`/api/v1/config-apis/${encodeURIComponent(configApiId)}/default-host-acl`),
      apiFetch(`/api/v1/client-devices?configApiId=${encodeURIComponent(configApiId)}`).catch(() => null)
    ]);
    const defaultAcl = defRes.ok ? await defRes.json() : [];
    const devices = (devRes && devRes.ok) ? await devRes.json() : [];

    const defaultStr = Array.isArray(defaultAcl) ? defaultAcl.join(', ') : '';

    const devRows = devices.length === 0
      ? `<tr><td colspan="3" class="empty-msg">${t('noEnrolledDevices')}</td></tr>`
      : devices.map(d => {
          const label = (d.deviceManufacturer || d.manufacturer || '') + ' ' + (d.deviceModel || d.model || '');
          return `<tr>
            <td style="font-weight:600;color:#7dd3fc">${d.device_id || d.deviceId}</td>
            <td>${label.trim() || '—'}</td>
            <td><button class="btn btn-secondary" style="padding:3px 8px;font-size:11px"
                data-action="editDeviceAcl" data-arg0="${esc(configApiId)}" data-arg1="${esc(d.device_id || d.deviceId)}">${t('aclEditBtn')}</button></td>
          </tr>`;
        }).join('');

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="color:#7dd3fc">${t('aclManagerTitle')} — ${configApiId}</div>
          <div class="section-sub">${t('aclManagerSub')}</div>
        </div>
        <button class="btn btn-secondary" data-action="renderConfigApiDetail" data-arg0="${esc(configApiId)}">${t('aclBack')}</button>
      </div>

      <div class="card">
        <div class="card-title">${t('defaultAclTitle')}</div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:8px">${t('defaultAclHint')}</div>
        <div style="display:flex;gap:8px;align-items:center">
          <input type="text" id="default-acl-input" class="form-input" style="flex:1"
                 placeholder="${t('defaultAclPlaceholder')}"
                 value="${defaultStr.replace(/"/g, '&quot;')}"/>
          <button class="btn btn-primary" data-action="saveDefaultAcl" data-arg0="${esc(configApiId)}">${t('aclSave')}</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">${t('enrolledDevicesTitle')} (${devices.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('tokenColDeviceId')}</th><th>${t('vaultDevice')}</th><th></th></tr></thead>
          <tbody>${devRows}</tbody>
        </table>
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${e.message}</div></div>`;
  }
}

async function saveDefaultAcl(configApiId) {
  const raw = document.getElementById('default-acl-input')?.value || '';
  const hostnames = raw.split(',').map(s => s.trim()).filter(Boolean);
  try {
    const res = await apiFetch(`/api/v1/config-apis/${encodeURIComponent(configApiId)}/default-host-acl`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostnames })
    });
    if (!res.ok) { toast(t('defaultAclSaveError'), 'error'); return; }
    toast(t('defaultAclUpdated'), 'success');
    showDeviceAclManager(configApiId);
  } catch (err) { toast(err.message, 'error'); }
}

async function editDeviceAcl(configApiId, deviceId) {
  try {
    const res = await apiFetch(`/api/v1/config-apis/${encodeURIComponent(configApiId)}/devices/${encodeURIComponent(deviceId)}/host-acl`);
    const current = res.ok ? await res.json() : [];
    const currentStr = Array.isArray(current) ? current.join(', ') : '';
    const newStr = prompt(t('aclEditPrompt', deviceId), currentStr);
    if (newStr === null) return;
    const hostnames = newStr.split(',').map(s => s.trim()).filter(Boolean);
    const putRes = await apiFetch(`/api/v1/config-apis/${encodeURIComponent(configApiId)}/devices/${encodeURIComponent(deviceId)}/host-acl`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostnames })
    });
    if (!putRes.ok) { toast(t('defaultAclSaveError'), 'error'); return; }
    toast(t('aclUpdated'), 'success');
    showDeviceAclManager(configApiId);
  } catch (err) { toast(err.message, 'error'); }
}

async function deleteConfigApi(apiId) {
  if (!confirm(apiId + ' silinecek. Tüm host\'ları ve pin config\'i de silinecek. Devam?')) return;
  try {
    await apiFetch('/api/v1/config-apis/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: apiId })
    });
    if (selectedApiId === apiId) selectedApiId = null;
    await loadConfig();
    renderHostList();
    renderEmpty();
    toast('Config API silindi: ' + apiId, 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

function selectHostInApi(hostname, apiId) {
  selectedHost = hostname;
  selectedApiId = apiId;
  currentSection = null;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('selected'));
  // Sidebar highlight'ı senkron uygula — async renderHostList'in microtask
  // gecikmesini beklemeden tıklamanın görsel feedback'i anlık olsun.
  renderHostListSync();
  renderHostList();
  // Detay yüklenirken sayfa üstünde ince loading bar + sağ panelde merkezli
  // spinner göster. Eski host'un verisi yanıltıcı olmasın diye anlık olarak
  // içerik değişimi belli olsun.
  showTopLoader();
  renderHostDetailLoading(hostname);
  loadHostDetail(hostname, apiId);
}

function renderHostDetailLoading(hostname) {
  const el = document.getElementById('content');
  if (!el) return;
  el.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:60vh;color:#475569">
      <div style="width:32px;height:32px;border:3px solid #334155;border-top-color:#60a5fa;border-radius:50%;animation:hostDetailSpin 0.8s linear infinite;margin-bottom:16px"></div>
      <div style="font-size:13px;color:#64748b">${hostname}</div>
    </div>
    <style>@keyframes hostDetailSpin { to { transform: rotate(360deg); } }</style>`;
}

// ── Top loading bar ──────────────────────────────────
// Sağ paneli nuke etmeden "bir şey yükleniyor" feedback'i vermek için
// sayfanın en üstüne ince bir animasyonlu çubuk ekler. Aynı anda birden fazla
// yükleme varsa counter ile senkronize olur, son yükleme bittiğinde kaybolur.
let _topLoaderCount = 0;
function showTopLoader() {
  _topLoaderCount++;
  let bar = document.getElementById('top-loader');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'top-loader';
    bar.innerHTML = '<div class="top-loader-bar"></div>';
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;height:2px;z-index:9999;pointer-events:none;overflow:hidden;background:transparent';
    document.body.appendChild(bar);
    const style = document.createElement('style');
    style.textContent = `
      .top-loader-bar {
        width:40%;height:100%;
        background:linear-gradient(90deg,transparent,#60a5fa,transparent);
        animation:topLoaderSlide 1.1s linear infinite;
      }
      @keyframes topLoaderSlide {
        from { transform: translateX(-100%); }
        to   { transform: translateX(350%); }
      }`;
    document.head.appendChild(style);
  }
  bar.style.display = 'block';
}
function hideTopLoader() {
  _topLoaderCount = Math.max(0, _topLoaderCount - 1);
  if (_topLoaderCount === 0) {
    const bar = document.getElementById('top-loader');
    if (bar) bar.style.display = 'none';
  }
}

// Monotonic request counter — guards against stale fetch responses overwriting
// the pane when the user clicks hosts faster than the network replies.
let _hostDetailReq = 0;

async function loadHostDetail(hostname, apiId) {
  const reqId = ++_hostDetailReq;
  try {
    const res = await apiFetch(`/api/v1/config/${encodeURIComponent(apiId)}`);
    if (!res.ok) return;
    const cfg = await res.json();
    // Ignore if a newer click has superseded us, or selection changed while we
    // were waiting on the network.
    if (reqId !== _hostDetailReq) return;
    if (selectedHost !== hostname || selectedApiId !== apiId) return;
    currentConfig = cfg;
    const host = getHosts().find(h => h.hostname === hostname);
    if (host) renderHostDetail(host);
  } catch (e) {
    console.error('Failed to load host detail', e);
  } finally {
    hideTopLoader();
  }
}

function selectHost(hostname) {
  selectedHost = hostname;
  currentSection = null;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('selected'));
  renderHostList();
  const host = getHosts().find(h => h.hostname === hostname);
  if (host) renderHostDetail(host);
}

// ── Host Detail (with history) ───────────────────────

async function renderHostDetail(host) {
  const pinsHtml = host.sha256.map((hash, i) => `
    <div class="hash-label">${i === 0 ? t('primaryPin') : t('backupPin') + (i > 1 ? ' #' + i : '')}</div>
    <div class="hash-box">
      <span>sha256/${hash}</span>
      <button class="copy-btn" data-action="copyText" data-arg0="${esc(hash)}">${t('copy')}</button>
    </div>
  `).join('');

  // Pin değişiklik geçmişi artık ayrı `loadPinHistory()` ile yükleniyor
  // (sayfalama callback'i sadece ilgili card'ı render edebilsin diye).

  document.getElementById('content').innerHTML = `
    <div class="section-header">
      <div>
        <div class="section-title-main">${host.hostname}</div>
        <div class="section-sub">${host.pinCount} ${t('pins')}</div>
      </div>
      <div class="action-bar">
        <button class="btn btn-danger" data-action="deleteHost" data-arg0="${esc(host.hostname)}">${t('deleteHost')}</button>
      </div>
    </div>

    <div class="stats">
      <div class="card">
        <div class="card-title">${t('version')}</div>
        <div class="stat-value" style="color:#7dd3fc">v${host.version}</div>
      </div>
      <div class="card">
        <div class="card-title">${t('pinCount')}</div>
        <div class="stat-value" style="color:#22c55e">${host.pinCount}</div>
      </div>
      <div class="card" style="cursor:pointer" data-action="toggleForce" data-arg0="${esc(host.hostname)}">
        <div class="card-title">${t('forceStatus')}</div>
        <div style="display:flex;align-items:center;gap:10px">
          <div style="width:40px;height:22px;border-radius:11px;background:${(currentConfig.pins.find(p => p.hostname === host.hostname)?.forceUpdate) ? '#22c55e' : '#334155'};position:relative;transition:background 0.2s">
            <div style="width:18px;height:18px;border-radius:50%;background:white;position:absolute;top:2px;${(currentConfig.pins.find(p => p.hostname === host.hostname)?.forceUpdate) ? 'right:2px' : 'left:2px'};transition:all 0.2s"></div>
          </div>
          <span style="color:${(currentConfig.pins.find(p => p.hostname === host.hostname)?.forceUpdate) ? '#22c55e' : '#64748b'};font-weight:700">${(currentConfig.pins.find(p => p.hostname === host.hostname)?.forceUpdate) ? t('forceActive') : t('forcePassive')}</span>
        </div>
      </div>
      <div class="card" id="mock-server-card">
        <div class="loading">${t('loading')}</div>
      </div>
    </div>

    <div class="card" id="cert-info-card">
      <div class="card-title">${t('certInfo')}</div>
      <div class="loading">${t('loading')}</div>
    </div>

    <div class="card" id="pins-card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="card-title">${t('pins')}</div>
        <button class="btn btn-primary" style="padding:4px 12px;font-size:11px" data-action="toggleEditPins" data-arg0="${esc(host.hostname)}">${t('editPins')}</button>
      </div>
      <div id="pins-view">${pinsHtml}</div>
      <div id="pins-edit" style="display:none"></div>
    </div>

    <div class="card" id="host-client-cert-card">
      <div class="card-title">${t('clientCertMtls')}</div>
      <div class="loading">${t('loading')}</div>
    </div>

    <div class="card" id="pin-history-card">
      <div class="card-title">${t('history')}</div>
      <div class="loading">${t('loading')}</div>
    </div>

    <div class="card" id="conn-history-card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div class="card-title">${t('connHistory')}</div>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn btn-primary" style="padding:4px 12px;font-size:11px" data-action="testHostConnection" data-arg0="${esc(host.hostname)}">${t('testConnection')}</button>
          <span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadHostConnectionHistory" data-arg0="${esc(host.hostname)}" title="${t('refresh')}">&#x21bb;</span>
        </div>
      </div>
      <div class="loading">${t('loading')}</div>
    </div>

    <div class="card" id="client-devices-card">
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connectedClients')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadClientDevices" data-arg0="${esc(host.hostname)}" title="${t('refresh')}">&#x21bb;</span></div>
      <div class="loading">${t('loading')}</div>
    </div>
  `;

  // Cert info, mock server durumu, bağlantı geçmişi ve cihazları ayrı yükle
  loadCertInfo(host.hostname);
  loadMockStatus(host.hostname);
  loadHostClientCert(host.hostname);
  loadPinHistory(host.hostname);
  loadHostConnectionHistory(host.hostname);
  loadClientDevices(host.hostname);
}

async function loadPinHistory(hostname) {
  const card = document.getElementById('pin-history-card');
  if (!card) return;
  try {
    const res = await apiFetch('/api/v1/certificate-config/history/' + encodeURIComponent(hostname));
    const entries = await res.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
    const eventLabel = e => ({
      host_added:   { icon: '&#x2795;', text: t('evHostAdded'),   color: '#22c55e' },
      host_removed: { icon: '&#x274C;', text: t('evHostRemoved'), color: '#ef4444' },
      pins_updated: { icon: '&#x270F;', text: t('evPinsUpdated'), color: '#60a5fa' },
      force_update: { icon: '&#x26A1;', text: t('evForce'),       color: '#f59e0b' },
      mtls_enabled: { icon: '&#x1F512;', text: 'mTLS Enabled',    color: '#f59e0b' },
      mtls_disabled:{ icon: '&#x1F513;', text: 'mTLS Disabled',   color: '#94a3b8' },
      client_cert_uploaded: { icon: '&#x1F4E4;', text: 'Client Cert Uploaded', color: '#a78bfa' },
    }[e] || { icon: '&#x2022;', text: e, color: '#94a3b8' });

    if (entries.length === 0) {
      card.innerHTML = `<div class="card-title">${t('history')}</div><div class="empty-msg">${t('noHistory')}</div>`;
      return;
    }
    const pagKey = 'pin-hist-' + hostname;
    const pagInfo = pagSlice(entries, pagKey);
    const rows = pagInfo.slice.map((e, i) => {
      const ev = eventLabel(e.event);
      const latest = pagInfo.page === 0 && i === 0;
      return `<tr class="${latest ? 'row-latest' : ''}">
        <td><span class="ver-badge" style="${latest ? 'background:#1d4ed8;color:#93c5fd' : ''}">v${esc(e.version)}</span></td>
        <td style="color:${ev.color}">${ev.icon} ${esc(ev.text)}</td>
        <td style="font-family:monospace;font-size:10px;color:#7dd3fc">${e.pinPrefix ? esc(e.pinPrefix) + '...' : '&#x2014;'}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
      </tr>`;
    }).join('');
    window['_reloadPinHist_' + hostname.replace(/[^a-zA-Z0-9]/g,'_')] = () => loadPinHistory(hostname);
    const pagNav = pagControls(pagKey, pagInfo, '_reloadPinHist_' + hostname.replace(/[^a-zA-Z0-9]/g,'_'));
    card.innerHTML = `<div class="card-title">${t('history')}</div>
      <table class="data-table">
        <thead><tr><th>${t('thVersion')}</th><th>${t('thEvent')}</th><th>${t('thPinPrefix')}</th><th>${t('thDate')}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>${pagNav}`;
  } catch (e) {
    card.innerHTML = `<div class="card-title">${t('history')}</div><div class="empty-msg">${t('error')}</div>`;
  }
}

async function testHostConnection(hostname) {
  try {
    const statusRes = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/status`);
    if (!statusRes.ok) { toast(t('error'), 'error'); return; }
    const status = await statusRes.json();

    // Yerel mock çalışmıyorsa (ya keystorePath hiç yok ya da sunucu başlatılmamış)
    // ping-remote ile gerçek uzak host'u dene. Bazı host'larda server cert dosyası
    // üretilmiş olsa bile fiziksel olarak uzakta olabilir (örn. 192.168.1.217) —
    // bu nedenle yalnızca keystorePath'e değil mockServerRunning'e de bakılır.
    if (!status.keystorePath || !status.mockServerRunning) {
      const pingRes = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/ping-remote`);
      if (pingRes.ok) {
        const ping = await pingRes.json();
        if (ping.reachable) {
          toast(`Remote ${hostname}:${ping.port} ulaşılabilir — pin ${ping.pinMatch ? 'eşleşiyor ✓' : 'EŞLEŞMİYOR ⚠'}`, ping.pinMatch ? 'success' : 'error');
        } else {
          toast(`Remote ${hostname} ulaşılamaz — ${ping.error || 'offline'}`, 'error');
        }
      } else {
        toast(t('error'), 'error');
      }
      return;
    }

    const port = status.mockTlsPort || status.mockMtlsPort || status.mockServerPort || 8443;
    const mode = status.mockServerMode || 'tls';
    const testUrl = `https://${hostname}:${port}/health`;

    // Management API üzerinden proxy test — sunucu kendi mock server'ına bağlanır
    const start = Date.now();
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/test-connection`, { method: 'POST' });
    const elapsed = Date.now() - start;
    const data = await res.json();

    // Sonucu connection history'ye kaydet
    await apiFetch('/api/v1/connection-history/web', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hostname: hostname,
        status: data.success ? 'healthy' : 'error',
        responseTimeMs: data.responseTimeMs || elapsed,
        errorMessage: data.error || undefined
      })
    });

    if (data.success) {
      toast(`${t('connTestOk')} — ${data.responseTimeMs || elapsed}ms`, 'success');
    } else {
      toast(`${t('connTestFail')}: ${data.error || ''}`, 'error');
    }
    loadHostConnectionHistory(hostname);
  } catch (e) {
    toast(t('connTestFail') + ': ' + e.message, 'error');
  }
}

async function loadHostConnectionHistory(hostname) {
  const card = document.getElementById('conn-history-card');
  if (!card) return;
  try {
    const res = await apiFetch('/api/v1/connection-history/' + encodeURIComponent(hostname));
    const entries = await res.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

    if (entries.length === 0) {
      card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-primary" style="padding:4px 12px;font-size:11px" data-action="testHostConnection" data-arg0="${esc(hostname)}">${t('testConnection')}</button><span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadHostConnectionHistory" data-arg0="${esc(hostname)}" title="${t('refresh')}">&#x21bb;</span></div></div><div class="empty-msg">${t('noConnHistory')}</div>`;
      return;
    }

    const pagKey = 'host-conn-' + hostname;
    const pagInfo = pagSlice(entries, pagKey);
    const rows = pagInfo.slice.map((e, i) => {
      const src = e.source === 'android'
        ? `<span style="color:#60a5fa">📱 ${esc(e.deviceManufacturer || '')} ${esc(e.deviceModel || '')}</span>`
        : '<span style="color:#94a3b8">💻 Web</span>';
      const statusColor = e.status === 'healthy' || e.status === 'ok' ? '#22c55e' : '#ef4444';
      const pinInfo = e.pinMatched === true ? `<span style="color:#22c55e">✓ ${t('matched')}</span>`
        : e.pinMatched === false ? `<span style="color:#ef4444">✗ ${t('mismatch')}</span>`
        : '—';
      const pinVer = e.pinVersion != null ? `v${esc(e.pinVersion)}` : '—';
      return `<tr class="${pagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
        <td>${src}</td>
        <td style="color:${statusColor}">${esc(e.status)}</td>
        <td>${esc(e.responseTimeMs)}ms</td>
        <td>${pinInfo}</td>
        <td>${pinVer}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
        <td style="color:#64748b;font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.errorMessage && e.errorMessage !== 'null' ? esc(e.errorMessage) : ''}</td>
      </tr>`;
    }).join('');
    // Pagination callback host-özel; window'a geçici bir reload fonksiyonu yaz.
    window['_reloadHostConn_' + hostname.replace(/[^a-zA-Z0-9]/g,'_')] = () => loadHostConnectionHistory(hostname);
    const pagNav = pagControls(pagKey, pagInfo, '_reloadHostConn_' + hostname.replace(/[^a-zA-Z0-9]/g,'_'));

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-primary" style="padding:4px 12px;font-size:11px" data-action="testHostConnection" data-arg0="${esc(hostname)}">${t('testConnection')}</button><span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadHostConnectionHistory" data-arg0="${esc(hostname)}" title="${t('refresh')}">&#x21bb;</span></div></div>
      <table class="data-table">
        <thead><tr>
          <th>${t('thClient')}</th><th>${t('thStatus')}</th><th>${t('thDuration')}</th>
          <th>${t('thPin')}</th><th>${t('thPinVer')}</th><th>${t('thDate')}</th><th>${t('thError')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>${pagNav}`;
  } catch (e) {
    card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-primary" style="padding:4px 12px;font-size:11px" data-action="testHostConnection" data-arg0="${esc(hostname)}">${t('testConnection')}</button><span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadHostConnectionHistory" data-arg0="${esc(hostname)}" title="${t('refresh')}">&#x21bb;</span></div></div><div class="empty-msg">${t('error')}</div>`;
  }
}

async function loadClientDevices(hostname) {
  const card = document.getElementById('client-devices-card');
  if (!card) return;
  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/clients`);
    const devices = await res.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

    if (devices.length === 0) {
      card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connectedClients')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadClientDevices" data-arg0="${esc(hostname)}" title="${t('refresh')}">&#x21bb;</span></div><div class="empty-msg">${t('noClients')}</div>`;
      return;
    }

    const rows = devices.map((d, i) => {
      const statusColor = d.lastStatus === 'healthy' ? '#22c55e' : '#ef4444';
      const timeAgo = new Date(d.lastSeen).toLocaleString(locale);
      return `<tr class="${i === 0 ? 'row-latest' : ''}">
        <td><span style="color:#60a5fa">📱 ${esc(d.deviceManufacturer || '')} ${esc(d.deviceModel || '')}</span></td>
        <td><span class="ver-badge">v${esc(d.pinVersion)}</span></td>
        <td style="color:${statusColor}">${esc(d.lastStatus)}</td>
        <td style="color:#64748b;font-size:11px">${timeAgo}</td>
      </tr>`;
    }).join('');

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connectedClients')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" data-action="loadClientDevices" data-arg0="${esc(hostname)}" title="${t('refresh')}">&#x21bb;</span></div>
      <table class="data-table">
        <thead><tr>
          <th>${t('thDevice')}</th><th>${t('thPinVer')}</th>
          <th>${t('thLastStatus')}</th><th>${t('thLastSeen')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (e) {
    card.innerHTML = `<div class="card-title">${t('connectedClients')}</div><div class="empty-msg">${t('error')}</div>`;
  }
}

// ── Host Client Cert (mTLS) ──────────────────────────

async function loadHostClientCert(hostname) {
  const card = document.getElementById('host-client-cert-card');
  if (!card) return;

  const pin = currentConfig?.pins?.find(p => p.hostname === hostname);
  const isMtls = pin?.mtls || false;
  const certVer = pin?.clientCertVersion;

  let certInfo = null;
  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/client-cert/info`);
    if (res.ok) certInfo = await res.json();
  } catch (_) {}

  const mtlsToggle = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
      <span style="color:#94a3b8;font-size:12px">mTLS:</span>
      <div style="cursor:pointer;width:40px;height:22px;border-radius:11px;background:${isMtls ? '#22c55e' : '#334155'};position:relative;transition:background 0.2s" data-action="toggleHostMtls" data-arg0="${esc(hostname)}" data-arg1="${!isMtls}">
        <div style="width:18px;height:18px;border-radius:50%;background:white;position:absolute;top:2px;${isMtls ? 'right:2px' : 'left:2px'};transition:all 0.2s"></div>
      </div>
      <span style="color:${isMtls ? '#22c55e' : '#64748b'};font-weight:600;font-size:12px">${isMtls ? t('mtlsEnabled') : t('mtlsDisabled')}</span>
      ${certVer ? `<span class="ver-badge" style="margin-left:auto">cert v${certVer}</span>` : ''}
    </div>`;

  const certSection = certInfo ? `
    <div style="background:#0f172a;border-radius:8px;padding:10px;margin-bottom:12px;font-size:12px">
      <div style="color:#94a3b8">CN: <span style="color:#7dd3fc">${certInfo.commonName || '—'}</span></div>
      <div style="color:#94a3b8">${t('thFingerprint')}: <span style="color:#7dd3fc;font-family:monospace;font-size:10px">${certInfo.fingerprint ? certInfo.fingerprint.substring(0,20) + '...' : '—'}</span></div>
      <div style="color:#94a3b8">${t('version')}: <span style="color:#22c55e">${certInfo.version}</span></div>
    </div>` : `
    <div style="background:#0f172a;border-radius:8px;padding:10px;margin-bottom:12px;font-size:12px">
      <div style="color:#64748b;margin-bottom:6px">${t('hostCertNone')}</div>
      <div style="color:#475569;font-size:11px;line-height:1.5">${t('hostCertGuide')}</div>
    </div>`;

  const uploadBtn = `
    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn btn-secondary" style="padding:4px 12px;font-size:11px" data-action="clickFileInput" data-arg0="host-cc-file">
        ${certInfo ? t('updateClientCert') : t('uploadClientCert')}
      </button>
      <input type="file" id="host-cc-file" accept=".p12,.pfx" style="display:none" data-action-change="uploadHostClientCert" data-arg0="${esc(hostname)}"/>
      <span style="color:#64748b;font-size:10px">${t('pkcs12Hint')}</span>
    </div>`;

  card.innerHTML = `
    <div class="card-title">${t('clientCertMtls')}</div>
    ${mtlsToggle}
    ${certSection}
    ${uploadBtn}
  `;
}

async function toggleHostMtls(hostname, enable) {
  const mtls = enable === true || enable === 'true';
  try {
    await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/toggle-mtls`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ mtls })
    });
    await loadConfig();
    loadHostClientCert(hostname);
  } catch (e) { toast(t('error'), 'error'); }
}

async function uploadHostClientCert(hostname) {
  const file = document.getElementById('host-cc-file').files[0];
  if (!file) return;
  const password = prompt('P12 password:', 'changeit');
  if (password === null) return;

  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);

  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/upload-client-cert`, { method: 'POST', body: formData });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); return; }
    const data = await res.json();
    toast(`Client cert uploaded — v${data.clientCertVersion}`, 'success');
    await loadConfig();
    loadHostClientCert(hostname);
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Add Host (4 tab) ─────────────────────────────────

let addHostTab = 'manual';

function showAddHost() {
  if (!selectedApiId && allApiConfigs.length > 0) {
    selectedApiId = allApiConfigs[0].id;
  }
  if (!selectedApiId) {
    toast('Önce bir Config API oluşturun', 'error');
    return;
  }
  selectedHost = null;
  currentSection = null;
  addHostTab = 'generate';
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('selected'));
  renderHostList();
  renderAddHostForm();
}

function showAddConfigApi() {
  selectedHost = null;
  currentSection = null;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('selected'));
  renderHostList();
  document.getElementById('content').innerHTML = `
    <div class="section-header">
      <div><div class="section-title-main">${t('newConfigApiTitle')}</div><div class="section-sub">${t('newConfigApiSub')}</div></div>
    </div>
    <div class="card">
      <form data-action-submit="createConfigApi">
        <div class="form-group">
          <label class="form-label">${t('apiIdLabel')}</label>
          <input type="text" id="new-api-id" placeholder="${t('apiIdPlaceholder')}" required class="form-input"/>
        </div>
        <div class="form-group">
          <label class="form-label">${t('mockPort')}</label>
          <input type="number" id="new-api-port" placeholder="8093" required class="form-input"/>
        </div>
        <div class="form-group">
          <label class="form-label">${t('mode')}</label>
          <select id="new-api-mode" class="form-input">
            <option value="tls">${t('modeTlsOption')}</option>
            <option value="mtls">${t('modeMtlsOption')}</option>
          </select>
        </div>
        <button type="submit" class="btn btn-primary">${t('startConfigApi')}</button>
      </form>
    </div>`;
}

async function createConfigApi(e) {
  e.preventDefault();
  const id = document.getElementById('new-api-id').value.trim();
  const port = parseInt(document.getElementById('new-api-port').value);
  const mode = document.getElementById('new-api-mode').value;
  if (!id || !port) return;
  try {
    const res = await apiFetch('/api/v1/config-apis/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, port, mode })
    });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }
    toast('Config API başlatıldı: ' + id + ' :' + port, 'success');
    selectedApiId = id;
    await loadConfig();
    renderHostList();
    renderEmpty();
  } catch (err) { toast(t('error'), 'error'); }
}

function switchAddTab(tab) {
  addHostTab = tab;
  renderAddHostForm();
}

function renderAddHostForm() {
  const tabs = [
    { id: 'manual', label: t('tabManual') },
    { id: 'generate', label: t('tabGenerate') },
    { id: 'upload', label: t('tabUpload') },
    // createHostFetch() uzun süre hiçbir yerden çağrılmıyordu; sunucudaki
    // POST /api/v1/hosts/fetch-from-url ucu arayüzden erişilemez durumdaydı.
    { id: 'fetch', label: t('tabFetch') },
  ];

  const tabsHtml = tabs.map(tb => `
    <button class="tab-btn ${addHostTab === tb.id ? 'tab-active' : ''}" data-action="switchAddTab" data-arg0="${esc(tb.id)}">${tb.label}</button>
  `).join('');

  let formHtml = '';

  if (addHostTab === 'manual') {
    formHtml = `
      <div class="form-group">
        <label class="form-label">${t('hostname')}</label>
        <input id="add-hostname" class="form-input" placeholder="${t('hostnamePlaceholder')}" autofocus>
      </div>
      <div class="form-group">
        <label class="form-label">${t('primaryPin')}</label>
        <input id="add-hash-0" class="form-input" placeholder="${t('primaryPlaceholder')}">
      </div>
      <div class="form-group">
        <label class="form-label">${t('backupPin')}</label>
        <input id="add-hash-1" class="form-input" placeholder="${t('backupPlaceholder')}">
        <div class="form-hint">${t('hashHint')}</div>
      </div>
      <div class="form-actions">
        <button class="btn btn-primary" data-action="createHostManual">${t('create')}</button>
        <button class="btn btn-secondary" data-action="liveCheckPins" data-arg0="" data-arg1="add" title="${esc(t('liveCheckBtnTitle'))}">${t('liveCheckBtn')}</button>
        <button class="btn btn-secondary" data-action="renderEmptyAndHostList">${t('cancel')}</button>
      </div>
      <div id="live-check-result" class="live-check-result"></div>`;
  } else if (addHostTab === 'generate') {
    formHtml = `
      <div class="form-group">
        <label class="form-label">${t('hostname')}</label>
        <input id="gen-hostname" class="form-input" placeholder="${t('hostnamePlaceholder')}" autofocus>
        <div class="form-hint">${t('hostnameHint')}</div>
      </div>
      <div class="form-actions">
        <button class="btn btn-success" id="gen-btn" data-action="createHostGenerate">${t('create')}</button>
        <button class="btn btn-secondary" data-action="renderEmptyAndHostList">${t('cancel')}</button>
      </div>`;
  } else if (addHostTab === 'upload') {
    formHtml = `
      <div class="form-group">
        <label class="form-label">${t('hostname')}</label>
        <input id="upload-hostname" class="form-input" placeholder="${t('hostnamePlaceholder')}">
      </div>
      <div class="form-group">
        <label class="form-label">${t('fileLabel')}</label>
        <input type="file" id="upload-file" class="form-input" accept=".jks,.p12,.pfx">
        <div class="form-hint">${t('fileHint')}</div>
      </div>
      <div class="form-group">
        <label class="form-label">${t('passwordLabel')}</label>
        <input id="upload-password" class="form-input" value="changeit" type="password">
      </div>
      <div class="form-actions">
        <button class="btn btn-success" id="upload-btn" data-action="createHostUpload">${t('create')}</button>
        <button class="btn btn-secondary" data-action="renderEmptyAndHostList">${t('cancel')}</button>
      </div>`;
  } else if (addHostTab === 'fetch') {
    formHtml = `
      <div class="form-group">
        <label class="form-label">${t('fetchUrlLabel')}</label>
        <input id="fetch-url" class="form-input" placeholder="https://api.example.com" autofocus>
        <div class="form-hint">${t('fetchUrlHint')}</div>
      </div>
      <div class="form-actions">
        <button class="btn btn-success" id="fetch-btn" data-action="createHostFetch">${t('create')}</button>
        <button class="btn btn-secondary" data-action="renderEmptyAndHostList">${t('cancel')}</button>
      </div>`;
  }

  document.getElementById('content').innerHTML = `
    <div class="section-header"><div>
      <div class="section-title-main">${t('addHostTitle')}</div>
    </div></div>
    <div class="tab-bar">${tabsHtml}</div>
    <div class="card">${formHtml}</div>
  `;
}

async function createHostManual() {
  const hostname = document.getElementById('add-hostname').value.trim();
  const hash0 = document.getElementById('add-hash-0').value.trim();
  const hash1 = document.getElementById('add-hash-1').value.trim();
  if (!hostname || !hash0 || !hash1) { toast(t('saveError'), 'error'); return; }
  if (hash0 === hash1) { toast(t('pinsMustDiffer'), 'error'); return; }
  if (currentConfig.pins.some(p => p.hostname === hostname)) { toast(t('duplicateHost'), 'error'); return; }

  const newPins = [...currentConfig.pins, { hostname, sha256: [hash0, hash1] }];
  const saved = await saveFullConfig(newPins);
  if (!saved) return;
  if (saved === 'pending') return; // the host exists only once approved
  toast(t('hostAdded') + ' — ' + hostname, 'success');
  selectedHost = hostname;
  await loadConfig();
  renderHostList();
  const host = getHosts().find(h => h.hostname === hostname);
  if (host) renderHostDetail(host);
}

async function createHostGenerate() {
  const hostname = document.getElementById('gen-hostname').value.trim();
  if (!hostname) { toast(t('saveError'), 'error'); return; }

  const btn = document.getElementById('gen-btn');
  btn.disabled = true; btn.textContent = t('generating');

  try {
    const apiId = selectedApiId || 'default-tls';
    const res = await apiFetch(`/api/v1/management/hosts/${encodeURIComponent(apiId)}/generate-cert`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname })
    });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); btn.disabled = false; btn.textContent = t('create'); return; }
    // 202: waiting for approval (apiFetch said so) — no host to open yet.
    if (res.status === 202) { btn.disabled = false; btn.textContent = t('create'); return; }

    toast(t('certGenerated') + ' — ' + hostname, 'success');
    selectedHost = hostname;
    await loadConfig();
    renderHostList();
    const host = getHosts().find(h => h.hostname === hostname);
    if (host) renderHostDetail(host);
  } catch (e) { toast(t('serverError'), 'error'); btn.disabled = false; btn.textContent = t('create'); }
}

async function createHostFetch() {
  const url = document.getElementById('fetch-url').value.trim();
  if (!url) { toast(t('saveError'), 'error'); return; }

  const btn = document.getElementById('fetch-btn');
  btn.disabled = true; btn.textContent = t('fetching');

  try {
    const res = await apiFetch('/api/v1/hosts/fetch-from-url', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!res.ok) { toast(reasonError(await res.json()), 'error'); btn.disabled = false; btn.textContent = t('create'); return; }
    // 202: waiting for approval (apiFetch said so) — no host to open yet.
    if (res.status === 202) { btn.disabled = false; btn.textContent = t('create'); return; }

    const data = await res.json();
    toast(t('certFetched') + ' — ' + data.hostname, 'success');
    selectedHost = data.hostname;
    await loadConfig();
    renderHostList();
    const host = getHosts().find(h => h.hostname === data.hostname);
    if (host) renderHostDetail(host);
  } catch (e) { toast(t('serverError'), 'error'); btn.disabled = false; btn.textContent = t('create'); }
}

async function createHostUpload() {
  const hostname = document.getElementById('upload-hostname').value.trim();
  const fileInput = document.getElementById('upload-file');
  const password = document.getElementById('upload-password').value || 'changeit';

  if (!hostname) { toast(t('saveError'), 'error'); return; }
  if (!fileInput.files.length) { toast(t('fileLabel'), 'error'); return; }

  const btn = document.getElementById('upload-btn');
  btn.disabled = true; btn.textContent = t('uploading');

  const file = fileInput.files[0];
  const ext = file.name.split('.').pop().toLowerCase();
  const format = ext === 'p12' || ext === 'pfx' ? 'pkcs12' : ext;

  const formData = new FormData();
  formData.append('file', file);
  formData.append('hostname', hostname);
  formData.append('password', password);
  formData.append('format', format);

  try {
    const res = await apiFetch('/api/v1/hosts/upload-cert', { method: 'POST', body: formData });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); btn.disabled = false; btn.textContent = t('create'); return; }
    // 202: waiting for approval (apiFetch said so) — no host to open yet.
    if (res.status === 202) { btn.disabled = false; btn.textContent = t('create'); return; }

    toast(t('certUploaded') + ' — ' + hostname, 'success');
    selectedHost = hostname;
    await loadConfig();
    renderHostList();
    const host = getHosts().find(h => h.hostname === hostname);
    if (host) renderHostDetail(host);
  } catch (e) { toast(t('serverError'), 'error'); btn.disabled = false; btn.textContent = t('create'); }
}

// ── Edit Pins ────────────────────────────────────────

let editHashes = [];

function renderEditPins(hostname) {
  document.getElementById('content').innerHTML = `
    <div class="section-header"><div>
      <div class="section-title-main">${esc(hostname)}</div>
      <div class="section-sub">${t('editPins')}</div>
    </div></div>
    <div class="card" id="pins-page-edit">
      ${editHashes.map((hash, i) => `
        <div class="pin-row">
          <input class="form-input" value="${esc(hash)}" data-action-change="updateEditHash" data-arg0="${i}" data-event="1"
                 placeholder="${i === 0 ? t('primaryPlaceholder') : t('backupPlaceholder')}">
          ${editHashes.length > 2 ? `<button class="btn-icon btn-remove" data-action="removeEditHashEdit" data-arg0="${i}" data-arg1="${esc(hostname)}">x</button>` : ''}
        </div>
      `).join('')}
      <button class="btn btn-secondary" style="margin-top:4px;font-size:11px" data-action="addEditHashEdit" data-arg0="${esc(hostname)}">${t('addHash')}</button>
      <div class="form-actions">
        <button class="btn btn-primary" data-action="savePins" data-arg0="${esc(hostname)}">${t('save')}</button>
        <button class="btn btn-secondary" data-action="liveCheckPins" data-arg0="${esc(hostname)}" data-arg1="page" title="${esc(t('liveCheckBtnTitle'))}">${t('liveCheckBtn')}</button>
        <button class="btn btn-secondary" data-action="selectHost" data-arg0="${esc(hostname)}">${t('cancel')}</button>
      </div>
      <div id="live-check-result" class="live-check-result"></div>
    </div>
  `;
}

function toggleEditPins(hostname) {
  const viewEl = document.getElementById('pins-view');
  const editEl = document.getElementById('pins-edit');
  if (!viewEl || !editEl) return;

  if (editEl.style.display === 'none') {
    // Edit moduna geç
    const host = getHosts().find(h => h.hostname === hostname);
    if (!host) return;
    editHashes = [...host.sha256];
    viewEl.style.display = 'none';
    editEl.style.display = 'block';
    renderInlineEditPins(hostname);
  } else {
    // View moduna dön
    editEl.style.display = 'none';
    viewEl.style.display = 'block';
  }
}

function renderInlineEditPins(hostname) {
  const editEl = document.getElementById('pins-edit');
  if (!editEl) return;
  editEl.innerHTML = `
    ${editHashes.map((hash, i) => `
      <div class="pin-row" style="margin-bottom:6px">
        <input class="form-input" value="${esc(hash)}" data-action-change="updateEditHash" data-arg0="${i}" data-event="1"
               placeholder="${i === 0 ? t('primaryPlaceholder') : t('backupPlaceholder')}">
        ${editHashes.length > 2 ? `<button class="btn-icon btn-remove" data-action="removeEditHashInline" data-arg0="${i}" data-arg1="${esc(hostname)}">x</button>` : ''}
      </div>
    `).join('')}
    <button class="btn btn-secondary" style="margin-top:4px;font-size:11px" data-action="addEditHashInline" data-arg0="${esc(hostname)}">${t('addHash')}</button>
    <div class="form-actions" style="margin-top:8px">
      <button class="btn btn-primary" data-action="saveInlinePins" data-arg0="${esc(hostname)}">${t('save')}</button>
      <button class="btn btn-secondary" data-action="liveCheckPins" data-arg0="${esc(hostname)}" data-arg1="inline" title="${esc(t('liveCheckBtnTitle'))}">${t('liveCheckBtn')}</button>
      <button class="btn btn-secondary" data-action="toggleEditPins" data-arg0="${esc(hostname)}">${t('cancel')}</button>
    </div>
    <div id="live-check-result" class="live-check-result"></div>`;
}

async function saveInlinePins(hostname) {
  const filtered = editHashes.map(h => h.trim()).filter(Boolean);
  if (new Set(filtered).size < 2) { toast(t('pinsMustDiffer'), 'error'); return; }
  const newPins = currentConfig.pins.map(p => p.hostname === hostname ? { hostname, sha256: filtered } : p);
  if (!(await saveFullConfig(newPins))) return;
  toast(t('pinsUpdated'), 'success');
  selectHost(hostname);
}

async function savePins(hostname) {
  const filtered = editHashes.map(h => h.trim()).filter(Boolean);
  if (new Set(filtered).size < 2) { toast(t('pinsMustDiffer'), 'error'); return; }
  const newPins = currentConfig.pins.map(p => p.hostname === hostname ? { hostname, sha256: filtered } : p);
  if (!(await saveFullConfig(newPins))) return;
  toast(t('pinsUpdated'), 'success');
  selectHost(hostname);
}

// ── Delete Host ──────────────────────────────────────

async function deleteHost(hostname) {
  if (!confirm(`"${hostname}" ${t('deleteConfirm')}`)) return;
  const newPins = currentConfig.pins.filter(p => p.hostname !== hostname);
  if (!(await saveFullConfig(newPins))) return;
  toast(t('hostDeleted'), 'success');
  selectedHost = null;
  renderHostList();
  renderEmpty();
}

// ── Save Config ──────────────────────────────────────

/**
 * Saves the full pin config of the SELECTED Config API scope. Returns true
 * only when the server accepted it; callers must not report success otherwise
 * (a rejected save used to be followed by a "pins updated" toast right after
 * the error toast).
 *
 * `?configApiId=` olmadan bu uç management server'da `default-tls`e yazıyordu:
 * mTLS Config API seçiliyken eklenen/düzenlenen/silinen host varsayılan
 * kapsamı değiştiriyordu.
 *
 * The PUT replaces the whole scope, flags included. Callers pass edited hosts
 * as `{hostname, sha256}` only, so every flag they do not set is carried over
 * from `currentConfig` — each host's `mtls`, `clientCertVersion` and
 * `forceUpdate`, and the scope-level `forceUpdate`. Sending
 * `{version:0, pins:[{hostname, sha256}], forceUpdate:false}` used to switch
 * mTLS and force off for EVERY host of the scope whenever one host's pins
 * were edited. (`version` is informational: the server assigns versions.)
 */
async function saveFullConfig(pins) {
  const current = new Map((currentConfig?.pins || []).map(p => [p.hostname, p]));
  const merged = pins.map(p => {
    const cur = current.get(p.hostname) || {};
    const pin = {
      hostname: p.hostname,
      sha256: p.sha256,
      forceUpdate: !!(p.forceUpdate ?? cur.forceUpdate),
      mtls: !!(p.mtls ?? cur.mtls)
    };
    const version = p.version ?? cur.version;
    if (version != null) pin.version = version;
    const certVersion = p.clientCertVersion ?? cur.clientCertVersion;
    if (certVersion != null) pin.clientCertVersion = certVersion;
    return pin;
  });
  try {
    const res = await apiFetch(`/api/v1/certificate-config?configApiId=${encodeURIComponent(scopeId())}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: 0, pins: merged, forceUpdate: !!currentConfig?.forceUpdate })
    });
    if (!res.ok) {
      // apiFetch already listed the hosts the live check failed on.
      if (!res.liveCheckHandled) {
        const err = await res.json().catch(() => ({}));
        toast((err.errors || (err.error ? [err.error] : [t('saveError')])).join('\n'), 'error');
      }
      return false;
    }
    // 202: stored as a change request (PIN_CHANGE_APPROVALS); nothing changed
    // yet. Truthy, so callers carry on as before; apiFetch told the user.
    if (res.status === 202) return 'pending';
    await loadConfig();
    return true;
  } catch (e) {
    toast(t('serverError'), 'error');
    return false;
  }
}

// ── Force Update ─────────────────────────────────────

async function toggleForce(hostname) {
  const isActive = currentConfig.pins.find(p => p.hostname === hostname)?.forceUpdate;
  if (!isActive && !confirm(t('forceConfirm'))) return;
  try {
    const endpoint = isActive ? 'clear-force' : 'force-update';
    // Bayrak `currentConfig`ten (seçili kapsam) okunuyor; yazma da aynı
    // kapsama gitmeli.
    await apiFetch(
      `/api/v1/certificate-config/${endpoint}/${encodeURIComponent(hostname)}?configApiId=${encodeURIComponent(scopeId())}`,
      { method: 'POST' }
    );
    await loadConfig(); renderHostList();
    if (selectedHost) selectHost(selectedHost);
    toast(isActive ? t('forceDisabled') : t('forceEnabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

// Host bazlı forceUpdate()/clearForce() kaldırıldı: toggleForce() ile birebir
// aynı uçları çağıran ölü kopyalardı. Global (tüm host'lar) uçları ise hiç
// bağlanmamıştı — aşağıdaki iki fonksiyon onları Config API genel sekmesine
// bağlar.

/** Bu Config API'deki TÜM pin'lere forceUpdate=true yazar. */
async function forceUpdateAll(apiId) {
  if (!confirm(t('forceAllConfirm'))) return;
  try {
    const res = await apiFetch(`/api/v1/certificate-config/force-update?configApiId=${encodeURIComponent(apiId)}`, { method: 'POST' });
    if (!res.ok) { toast(t('error'), 'error'); return; }
    await loadConfig();
    renderHostList();
    renderConfigApiDetail(apiId);
    toast(t('forceAllEnabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

/** Tüm pin'lerdeki forceUpdate bayrağını temizler. */
async function clearForceAll(apiId) {
  try {
    const res = await apiFetch(`/api/v1/certificate-config/clear-force?configApiId=${encodeURIComponent(apiId)}`, { method: 'POST' });
    if (!res.ok) { toast(t('error'), 'error'); return; }
    await loadConfig();
    renderHostList();
    renderConfigApiDetail(apiId);
    toast(t('forceAllDisabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Section Navigation ───────────────────────────────

function showSection(section) {
  // Entering Approvals from elsewhere opens the pending list (what the badge
  // counts); re-rendering it in place (language, key switch) keeps the tab.
  if (section === 'approvals' && currentSection !== 'approvals') approvalsTab = 'pending';
  selectedHost = null;
  currentSection = section;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('selected'));
  document.getElementById('nav-' + section)?.classList.add('selected');
  renderHostList();
  switch (section) {
    case 'health': renderHealthSection(); break;
    case 'bootstrap': renderBootstrapSection(); break;
    case 'signing': renderSigningSection(); break;
    case 'mtls': renderMtlsSection(); break;
    case 'approvals': renderApprovalsSection(); break;
    case 'audit': renderAuditSection(); break;
  }
}

// ── Health Section ───────────────────────────────────

async function renderHealthSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    // Zengin /api/v1/health ve /api/v1/cert-expiry uçları sunucuda vardı ama
    // arayüzde hiç kullanılmıyordu — sertifikaların ne zaman dolacağı yalnızca
    // sunucu loglarından görülebiliyordu.
    const [historyRes, healthRes, richHealthRes, expiryRes] = await Promise.all([
      apiFetch('/api/v1/connection-history'),
      apiFetch('/health'),
      apiFetch('/api/v1/health').catch(() => null),
      apiFetch('/api/v1/cert-expiry').catch(() => null)
    ]);
    const entries = await historyRes.json();
    const serverHealth = await healthRes.json();
    const richHealth = (richHealthRes && richHealthRes.ok) ? await richHealthRes.json() : null;
    const expiryRaw = (expiryRes && expiryRes.ok) ? await expiryRes.json() : [];
    const expiry = Array.isArray(expiryRaw) ? expiryRaw : [];
    const webEntries = entries.filter(e => e.source === 'web');
    const androidEntries = entries.filter(e => e.source === 'android');
    const configUpdateEntries = entries.filter(e => e.source === 'config_update');
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

    const sourceBadge = (s, e) => {
      if (s === 'android') {
        return `<span class="source-badge android-src">&#x1F4F1; ${e.deviceManufacturer ? esc(e.deviceManufacturer) + ' ' + esc(e.deviceModel||'') : 'Android'}</span>`;
      }
      if (s === 'config_update') {
        const device = e.deviceManufacturer ? esc(e.deviceManufacturer) + ' ' + esc(e.deviceModel||'') : 'Config';
        return `<span class="source-badge" style="background:#7c3aed;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px">&#x1F501; ${device}</span>`;
      }
      return '<span class="source-badge web-src">&#x1F5A5; Web</span>';
    };

    const pinInfo = e => {
      if (e.source === 'config_update') {
        return e.pinVersion != null ? `<span style="color:#a78bfa">v${esc(e.pinVersion)}</span>` : '&#x2014;';
      }
      if (e.source !== 'android' || e.pinMatched == null) return '&#x2014;';
      return e.pinMatched
        ? `<span class="status-healthy">&#x2713; ${t('matched')}</span>`
        : `<span class="status-error">&#x2717; ${t('mismatch')}</span>`;
    };

    // config_updated / config_unchanged are healthy outcomes; config_update_failed isn't.
    const isOkStatus = s => s === 'ok' || s === 'healthy' || s === 'config_updated' || s === 'config_unchanged';
    const statusLabel = (e, ok) => {
      if (e.source === 'config_update') {
        if (e.status === 'config_updated') return `&#x2713; ${t('configUpdated') || 'Config Updated'}`;
        if (e.status === 'config_unchanged') return `&#x2713; ${t('configUnchanged') || 'Config Unchanged'}`;
        if (e.status === 'config_update_failed') return `&#x2717; ${t('configUpdateFailed') || 'Update Failed'}`;
      }
      return ok ? `&#x2713; ${t('success')}` : `&#x2717; ${t('failed')}`;
    };

    const pagKey = 'health-global';
    const pagInfo = pagSlice(entries, pagKey);
    const rows = pagInfo.slice.map((e, i) => {
      const ok = isOkStatus(e.status);
      const durationCell = e.source === 'config_update' ? '&#x2014;' : `${esc(e.responseTimeMs)}ms`;
      return `<tr class="${pagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
        <td>${sourceBadge(e.source, e)}</td>
        <td class="${ok ? 'status-healthy' : 'status-error'}">${statusLabel(e, ok)}</td>
        <td>${durationCell}</td>
        <td>${pinInfo(e)}</td>
        <td style="color:#ef4444;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.errorMessage ? esc(e.errorMessage) : '&#x2014;'}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
      </tr>`;
    }).join('');
    const healthPagNav = pagControls(pagKey, pagInfo, 'renderHealthSection');

    // ── Sertifika süre izleme kartı ────────────────────────────────────
    // Her host için kalan gün + seviye (ok / warning / expired) renkli.
    const expiryColor = lvl => lvl === 'expired' ? '#ef4444' : lvl === 'warning' ? '#f59e0b' : '#22c55e';
    const expiryIcon  = lvl => lvl === 'expired' ? '✗' : lvl === 'warning' ? '⚠' : '✓';
    const expiryLabel = lvl => lvl === 'expired' ? t('certExpired')
                             : lvl === 'warning' ? t('certWarning')
                             : t('certOk');
    // En kritik olan en üstte: expired → warning → ok, sonra kalan güne göre.
    const levelRank = { expired: 0, warning: 1, ok: 2 };
    const expirySorted = [...expiry].sort((a, b) =>
      (levelRank[a.level] ?? 3) - (levelRank[b.level] ?? 3) || a.daysRemaining - b.daysRemaining);

    const expiryRows = expirySorted.map(c => {
      const color = expiryColor(c.level);
      const days = c.daysRemaining < 0
        ? t('certExpiredAgo', Math.abs(c.daysRemaining))
        : t('certDaysLeft', c.daysRemaining);
      return `<tr>
        <td style="font-weight:600;color:#7dd3fc">${esc(c.hostname)}</td>
        <td style="color:#64748b;font-size:11px">${esc(c.configApiId)}</td>
        <td style="color:${color};font-weight:700">${expiryIcon(c.level)} ${expiryLabel(c.level)}</td>
        <td style="color:${color};font-weight:600">${days}</td>
        <td style="color:#64748b;font-size:11px">${new Date(c.validUntil).toLocaleString(locale)}</td>
      </tr>`;
    }).join('');

    const certsSummary = richHealth?.certs || {};
    const overall = richHealth?.status || (expiry.some(c => c.level === 'expired') ? 'critical'
                                        : expiry.some(c => c.level === 'warning') ? 'degraded' : 'ok');
    const overallColor = overall === 'critical' ? '#ef4444' : overall === 'degraded' ? '#f59e0b' : '#22c55e';

    const certExpiryCard = `
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <span>${t('certExpiryTitle')} (${expiry.length})</span>
          <span style="color:${overallColor};font-weight:700;font-size:12px">
            ${expiryIcon(overall === 'critical' ? 'expired' : overall === 'degraded' ? 'warning' : 'ok')}
            ${esc(overall)}${certsSummary.nearExpiry != null ? ` · ${t('certNearExpiry')}: ${certsSummary.nearExpiry}` : ''}
          </span>
        </div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:8px">${t('certExpiryHint')}</div>
        ${expiry.length > 0 ? `<table class="data-table">
          <thead><tr><th>${t('hostname')}</th><th>Config API</th><th>${t('thStatus')}</th><th>${t('certRemaining')}</th><th>${t('certValidUntil')}</th></tr></thead>
          <tbody>${expiryRows}</tbody></table>`
        : `<div class="empty-msg">${t('certExpiryEmpty')}</div>`}
      </div>`;

    document.getElementById('content').innerHTML = `
      <div class="section-header">
        <div><div class="section-title-main">${t('healthTitle')}</div><div class="section-sub">${t('healthSub')}</div></div>
        <button class="btn btn-primary" data-action="runHealthCheck">${t('runHealthCheck')}</button>
      </div>
      <div class="stats">
        <div class="card"><div class="card-title">${t('serverStatus')}</div>
          <div class="stat-value ${serverHealth.status === 'ok' ? 'status-healthy' : 'status-error'}">${serverHealth.status === 'ok' ? `&#x2713; ${t('healthy')}` : `&#x2717; ${t('unhealthy')}`}</div>
          <div class="stat-label">${t('healthEndpoint')}</div></div>
        <div class="card"><div class="card-title">${t('webChecks')}</div>
          <div class="stat-value" style="color:#7dd3fc">${webEntries.length}</div>
          <div class="stat-label">${t('webFrom')}</div></div>
        <div class="card"><div class="card-title">${t('mobileReports')}</div>
          <div class="stat-value" style="color:#60a5fa">${androidEntries.length}</div>
          <div class="stat-label">${t('mobileFrom')}</div></div>
        <div class="card"><div class="card-title">${t('certExpiryTitle')}</div>
          <div class="stat-value" style="color:${overallColor}">${expiry.filter(c => c.level !== 'ok').length}</div>
          <div class="stat-label">${t('certNearExpiry')}</div></div>
      </div>
      ${certExpiryCard}
      <div class="card"><div class="card-title">${t('allConnections')}</div>
        ${entries.length > 0 ? `<table class="data-table">
          <thead><tr><th>${t('thSource')}</th><th>${t('thStatus')}</th><th>${t('thDuration')}</th><th>${t('thPin')}</th><th>${t('thError')}</th><th>${t('thDate')}</th></tr></thead>
          <tbody>${rows}</tbody></table>${healthPagNav}` : `<div class="empty-msg">${t('noConnections')}</div>`}
      </div>`;
  } catch (e) {
    document.getElementById('content').innerHTML = `<div class="card"><div class="empty-msg">${t('error')}</div></div>`;
  }
}

async function runHealthCheck() {
  try {
    const start = Date.now();
    const res = await apiFetch('/health');
    const elapsed = Date.now() - start;
    const data = await res.json();
    await apiFetch('/api/v1/connection-history/web', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: data.status === 'ok' ? 'healthy' : 'error', responseTimeMs: elapsed })
    });
    toast(t('healthOk') + ': ' + data.status + ' (' + elapsed + 'ms)', 'success');
    renderHealthSection();
  } catch (e) { toast(t('healthFailed'), 'error'); }
}

// ── Bootstrap Pins Section ───────────────────────────

async function renderBootstrapSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const res = await apiFetch('/api/v1/server-tls-pins');
    const data = await res.json();
    const hasPins = data.primaryPin && data.primaryPin.length > 0;
    // Kod parçasındaki adres: sayfanın açıldığı host adı + seçili (ya da ilk
    // TLS) Config API'nin gerçek portu — mTLS sekmesindeki mtlsPort deseniyle
    // aynı. Sunucunun döndürdüğü hostname/httpsPort yalnızca varsayılan
    // dinleyiciyi tarif ediyordu ("localhost:8081").
    const tlsApi = allApiConfigs.find(a => a.id === selectedApiId && a.mode !== 'mtls')
      || allApiConfigs.find(a => a.mode !== 'mtls');
    const tlsPort = tlsApi ? tlsApi.port : data.httpsPort;

    document.getElementById('content').innerHTML = `
      <div class="section-header">
        <div><div class="section-title-main">${t('bootstrapTitle')}</div><div class="section-sub">${t('bootstrapSub')}</div></div>
      </div>
      <div class="card">
        <div class="card-title" style="color:#f59e0b">${t('bootstrapWhat')}</div>
        <div style="color:#94a3b8;line-height:1.6;font-size:13px">${t('bootstrapExplain')}</div>
      </div>

      ${hasPins ? `
      <div class="card">
        <div class="card-title">${t('serverTlsPin')}</div>
        <div style="color:#64748b;font-size:11px;margin-bottom:8px">HTTPS: ${location.hostname}:${tlsPort}</div>
        <div class="hash-label">${t('primaryPin')}</div>
        <div class="hash-box">
          <span>sha256/${data.primaryPin}</span>
          <button class="copy-btn" data-action="copyText" data-arg0="${esc(data.primaryPin)}">${t('copy')}</button>
        </div>
        ${data.backupPin ? `
        <div class="hash-label">${t('backupPin')}</div>
        <div class="hash-box">
          <span>sha256/${data.backupPin}</span>
          <button class="copy-btn" data-action="copyText" data-arg0="${esc(data.backupPin)}">${t('copy')}</button>
        </div>` : ''}
        <div style="margin-top:16px;padding-top:16px;border-top:1px solid #334155;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-secondary" data-action="rotateBootstrapToBackup">${t('rotateToBackup')}</button>
          <button class="btn btn-warning" data-action="regenerateBootstrapCert">${t('regenerateBootstrap')}</button>
          <button class="btn btn-secondary" data-action="toggleBootstrapUpload">${t('tabUploadJks')}</button>
          <button class="btn btn-secondary" data-action="toggleBootstrapFetch">${t('tabFetch')}</button>
        </div>
        <div id="bootstrap-upload-form" style="display:none"></div>
        <div id="bootstrap-fetch-form" style="display:none"></div>
      </div>
      <div class="card">
        <div class="card-title">${t('androidIntegration')}</div>
        <div class="key-box">private val BOOTSTRAP_PINS = listOf(
    HostPin("${location.hostname}:${data.httpsPort}", listOf(
        "${data.primaryPin}",
        "${data.backupPin || 'BACKUP_PIN'}"
    ), 0, false, false, null)
)

val config = PinVaultConfig.Builder()
    .configApi("default", "https://${location.hostname}:${data.httpsPort}/") {
        bootstrapPins(BOOTSTRAP_PINS)
    }
    .build()</div>
      </div>` : ''}

      ${!hasPins ? `<div class="card">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-warning" data-action="regenerateBootstrapCert">${t('regenerateBootstrap')}</button>
          <button class="btn btn-secondary" data-action="toggleBootstrapUpload">${t('tabUploadJks')}</button>
          <button class="btn btn-secondary" data-action="toggleBootstrapFetch">${t('tabFetch')}</button>
        </div>
        <div id="bootstrap-upload-form" style="display:none"></div>
        <div id="bootstrap-fetch-form" style="display:none"></div>
      </div>` : ''}`;
  } catch (e) {
    document.getElementById('content').innerHTML = `<div class="card"><div class="empty-msg">${t('bootstrapError')}</div></div>`;
  }
}

function toggleBootstrapUpload() {
  const form = document.getElementById('bootstrap-upload-form');
  if (!form) return;
  if (form.style.display !== 'none') { form.style.display = 'none'; return; }
  form.style.display = 'block';
  form.innerHTML = `<form data-action-submit="uploadBootstrapCert">
    <div class="form-group">
      <label class="form-label">${t('uploadJksLabel')}</label>
      <input type="file" id="bootstrap-file" accept=".jks,.p12,.pfx" required style="color:#94a3b8"/>
    </div>
    <div class="form-group">
      <label class="form-label">${t('uploadPassword')}</label>
      <input type="password" id="bootstrap-password" value="changeit" class="form-input"/>
    </div>
    <button type="submit" class="btn btn-primary">${t('uploadBtn')}</button>
  </form>`;
}

/**
 * URL'den bootstrap pin çekme formunu açar/kapatır.
 *
 * fetchBootstrapFromUrl() sunucudaki POST /api/v1/server-tls-pins/fetch-from-url
 * ucunu çağırıyordu ama arayüzde hiçbir düğmeye bağlı değildi. Senaryo:
 * sunucu bir TLS sonlandırıcının (reverse proxy / yük dengeleyici) arkasındaysa
 * istemcilerin pinlemesi gereken sertifika sunucunun kendi sertifikası değil,
 * proxy'nin sertifikasıdır — pin'ler o adresten çekilmelidir.
 */
function toggleBootstrapFetch() {
  const form = document.getElementById('bootstrap-fetch-form');
  if (!form) return;
  if (form.style.display !== 'none') { form.style.display = 'none'; return; }
  form.style.display = 'block';
  form.innerHTML = `<form data-action-submit="fetchBootstrapFromUrl">
    <div class="form-group">
      <label class="form-label">${t('bootstrapFetchLabel')}</label>
      <input type="text" id="bootstrap-url" class="form-input" placeholder="https://proxy.example.com" required/>
      <div class="form-hint">${t('bootstrapFetchHint')}</div>
    </div>
    <button type="submit" class="btn btn-primary">${t('bootstrapFetchBtn')}</button>
  </form>`;
}

// The server's messages are English; its reason codes pick the dashboard's own text.
const REASON_TEXTS = {
  no_backup_key: 'noBackupKey',
  backup_not_published: 'backupNotPublished',
  no_second_certificate: 'noSecondCertificate',
};
function reasonError(data) {
  const key = data && REASON_TEXTS[data.reason];
  return key ? t(key) : (data && data.error) || t('error');
}

async function rotateBootstrapToBackup() {
  if (!confirm(t('rotateBootstrapConfirm'))) return;
  try {
    const res = await apiFetch('/api/v1/server-tls-pins/rotate-to-backup', { method: 'POST' });
    if (res.status === 202) return; // waits for a second admin; apiFetch said so
    const data = await res.json();
    if (!res.ok) { toast(reasonError(data), 'error'); return; }
    toast(t('bootstrapRotated'), 'success');
    renderBootstrapSection();
  } catch (e) { toast(t('error'), 'error'); }
}

async function regenerateBootstrapCert() {
  if (!confirm(t('regenerateBootstrapConfirm'))) return;
  try {
    await apiFetch('/api/v1/server-tls-pins/regenerate', { method: 'POST' });
    toast(t('bootstrapRegenerated'), 'success');
    renderBootstrapSection();
  } catch (e) { toast(t('error'), 'error'); }
}

async function uploadBootstrapCert(e) {
  e.preventDefault();
  const file = document.getElementById('bootstrap-file').files[0];
  if (!file) return;
  const password = document.getElementById('bootstrap-password').value;
  const format = file.name.endsWith('.p12') || file.name.endsWith('.pfx') ? 'pkcs12' : 'jks';

  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);
  formData.append('format', format);

  try {
    const res = await apiFetch('/api/v1/server-tls-pins/upload', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }
    toast(t('bootstrapUploaded'), 'success');
    renderBootstrapSection();
  } catch (err) { toast(t('error'), 'error'); }
}

async function fetchBootstrapFromUrl(e) {
  e.preventDefault();
  const url = document.getElementById('bootstrap-url').value;
  try {
    const res = await apiFetch('/api/v1/server-tls-pins/fetch-from-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (data.error) { toast(reasonError(data), 'error'); return; }
    toast(t('bootstrapFetched'), 'success');
    renderBootstrapSection();
  } catch (err) { toast(t('error'), 'error'); }
}

async function regenerateSigningKey() {
  if (!confirm(t('regenerateSigningConfirm'))) return;
  try {
    const res = await apiFetch('/api/v1/signing-key/regenerate', { method: 'POST' });
    // 202: waiting for approval — apiFetch said so; nothing changed yet.
    if (res.status === 202) return;
    // 409: not a local key file, or a signing-key set is active. The success
    // toast used to be shown regardless of the answer.
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      toast(err.error || t('error'), 'error');
      return;
    }
    toast(t('signingRegenerated'), 'success');
    refreshSigningView();
  } catch (e) { toast(t('error'), 'error'); }
}

// ── mTLS Section ────────────────────────────────────

async function renderMtlsSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const [statusRes, certsRes, modeRes] = await Promise.all([
      apiFetch('/api/v1/mtls-status'),
      apiFetch('/api/v1/client-certs'),
      apiFetch('/api/v1/enrollment-mode')
    ]);
    const status = await statusRes.json();
    const certs = await certsRes.json();
    const enrollMode = await modeRes.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
    // Port of the mTLS Config API shown in the integration snippet below. This
    // section used to reference an undefined `data.httpsPort`, which threw and
    // left the whole tab on the generic error message.
    const mtlsApi = allApiConfigs.find(a => a.id === selectedApiId && a.mode === 'mtls')
      || allApiConfigs.find(a => a.mode === 'mtls');
    const mtlsPort = mtlsApi ? mtlsApi.port : '<mtls-port>';

    const certsPagKey = 'client-certs';
    const certsPagInfo = pagSlice(certs, certsPagKey);
    const certsPagNav = pagControls(certsPagKey, certsPagInfo, "renderMtlsSection");
    const certRows = certs.length === 0
      ? `<div class="empty-msg">${t('noClientCerts')}</div>`
      : `<table class="data-table">
          <thead><tr><th>ID</th><th>${t('thFingerprint')}</th><th>${t('thCreated')}</th><th>${t('thRevoked')}</th><th></th></tr></thead>
          <tbody>${certsPagInfo.slice.map((c, i) => `<tr class="${certsPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
            <td style="font-weight:600">${c.id}</td>
            <td style="font-family:monospace;font-size:10px;color:#7dd3fc">${c.fingerprint.substring(0, 20)}...</td>
            <td style="color:#64748b;font-size:11px">${new Date(c.createdAt).toLocaleString(locale)}</td>
            <td>${c.revoked
              ? `<span style="color:#ef4444">${t('revoked')}</span>`
              : `<span style="color:#22c55e">${t('active')}</span>`}</td>
            <td>${!c.revoked ? `<button class="btn btn-danger" style="padding:2px 8px;font-size:11px" data-action="revokeClientCert" data-arg0="${esc(c.id)}">${t('revoke')}</button>` : ''}</td>
          </tr>`).join('')}</tbody>
        </table>${certsPagNav}`;

    document.getElementById('content').innerHTML = `
      <div class="stats">
        <div class="card">
          <div class="card-title">${t('clientCerts')}</div>
          <div class="stat-value" style="color:#7dd3fc">${status.activeCerts}</div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">${t('generateClientCert')}</div>
        <form data-action-submit="generateClientCert" style="display:flex;gap:8px;align-items:end">
          <div class="form-group" style="flex:1;margin:0">
            <label class="form-label">${t('clientIdLabel')}</label>
            <input type="text" id="mtls-client-id" placeholder="${t('clientIdPlaceholder')}" required class="form-input"/>
          </div>
          <button type="submit" class="btn btn-primary">${t('generateClientCert')}</button>
          <button type="button" class="btn btn-secondary" data-action="clickFileInput" data-arg0="mtls-upload-file">${t('uploadClientCert')}</button>
          <input type="file" id="mtls-upload-file" accept=".pem,.der,.crt,.cer" style="display:none" data-action-change="uploadClientCert"/>
        </form>
      </div>
      <div class="card">
        <div class="card-title">${t('clientCerts')}</div>
        ${certRows}
      </div>
      <div class="card">
        <div class="card-title">${t('androidIntegration')}</div>
        <div class="key-box">// Otomatik enrollment (token ile):
// 1. Web UI'dan token üretin
// 2. App ilk açılışta token sorar
// 3. Token ile P12 indirilir ve şifreli kaydedilir

// PinVault.isEnrolled(context) ile kontrol edin
// PinVault.enroll(context, token) ile kayıt olun

// Veya manuel P12:
val p12 = context.assets.open("client.p12").readBytes()
val config = PinVaultConfig.Builder()
    .configApi("mtls", "https://${location.hostname}:${mtlsPort}/") {
        bootstrapPins(BOOTSTRAP_PINS)
        clientKeystore(p12, "changeit")
    }
    .build()</div>
      </div>
      <div class="card">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div class="card-title" style="margin:0">${t('enrollmentToken')}</div>
          ${enrollMode.tokenRequired
            ? '<span style="background:#166534;color:#bbf7d0;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">&#x1F512; ' + t('tokenRequiredBadge') + '</span>'
            : '<span style="background:#92400e;color:#fef08a;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">&#x26A0; ' + t('openModeBadge') + '</span>'}
        </div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:12px;line-height:1.5">
          <strong>${t('secureFlowLabel')}</strong> ${t('secureFlowSteps')}
          ${!enrollMode.tokenRequired ? '<br><span style="color:#fbbf24">' + t('enrollmentModeHint') + '</span>' : ''}
        </div>
        <form data-action-submit="generateEnrollmentToken" style="display:flex;gap:8px;align-items:end">
          <div class="form-group" style="flex:1;margin:0">
            <label class="form-label">${t('clientIdLabel')}</label>
            <input type="text" id="enrollment-client-id" placeholder="${t('clientIdPlaceholder')}" required class="form-input"/>
          </div>
          <button type="submit" class="btn btn-primary">${t('generateToken')}</button>
        </form>
        <div id="enrollment-token-list" style="margin-top:12px"></div>
      </div>`;
    // Bilerek `await` edilmiyor: `renderConfigApiDetail` bu fonksiyon döner
    // dönmez #content'in innerHTML'ini kopyalayıp başlık + sekme çubuğuyla
    // geri yazıyor, bu arada beklemek forma yazılanı silecek kadar uzun bir
    // pencere açıyor. Listenin dolması loadEnrollmentTokens'ın konteyneri
    // fetch'ten SONRA çözmesiyle garanti altında.
    loadEnrollmentTokens();
  } catch (e) {
    document.getElementById('content').innerHTML = `<div class="card"><div class="empty-msg">${t('error')}</div></div>`;
  }
}

async function generateClientCert(e) {
  e.preventDefault();
  const clientId = document.getElementById('mtls-client-id').value.trim();
  if (!clientId) return;
  try {
    const res = await apiFetch('/api/v1/client-certs/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId })
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = clientId + '.p12'; a.click();
    URL.revokeObjectURL(url);
    toast(t('certGenerated'), 'success');
    renderMtlsSection();
  } catch (err) { toast(t('error'), 'error'); }
}

async function uploadClientCert() {
  const file = document.getElementById('mtls-upload-file').files[0];
  if (!file) return;
  const clientId = document.getElementById('mtls-client-id').value.trim() || file.name.replace(/\.[^.]+$/, '');
  const formData = new FormData();
  formData.append('file', file);
  formData.append('clientId', clientId);
  try {
    const res = await apiFetch('/api/v1/client-certs/upload', { method: 'POST', body: formData });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }
    toast(t('certUploaded'), 'success');
    renderMtlsSection();
  } catch (err) { toast(t('error'), 'error'); }
}


async function toggleConfigApi(apiId) {
  const api = allApiConfigs.find(a => a.id === apiId);
  if (!api) return;

  const isRunning = api.running !== false;
  try {
    if (isRunning) {
      await apiFetch('/api/v1/config-apis/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: apiId })
      });
      toast(`Config API durduruldu: ${apiId}`, 'success');
    } else {
      const portEl = document.getElementById(`capi-port-${apiId}`);
      const modeEl = document.getElementById(`capi-mode-${apiId}`);
      const port = parseInt(portEl?.value) || api.port;
      const mode = modeEl?.value || api.mode;
      await apiFetch('/api/v1/config-apis/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: apiId, port, mode })
      });
      toast(`Config API başlatıldı: ${apiId} :${port} (${mode.toUpperCase()})`, 'success');
    }
    await loadConfig();
    renderHostList();
    renderConfigApiDetail(apiId);
  } catch (err) { toast(t('error'), 'error'); }
}

async function generateEnrollmentToken(e) {
  e.preventDefault();
  const clientId = document.getElementById('enrollment-client-id').value.trim();
  if (!clientId) return;
  try {
    const res = await apiFetch('/api/v1/enrollment-tokens/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId })
    });
    const data = await res.json();
    // Sunucu artık yalnızca SHA-256 hash saklıyor — düz metin SADECE burada,
    // bir kez görünüyor. Vault token akışıyla aynı desen: panoya kopyala +
    // kapatılana kadar ekranda kalan bir dialog.
    navigator.clipboard?.writeText(data.token).catch(() => {});
    alert(t('enrollTokenGeneratedAlert', data.token));
    loadEnrollmentTokens();
  } catch (err) { toast(t('error'), 'error'); }
}

async function loadEnrollmentTokens() {
  if (!document.getElementById('enrollment-token-list')) return;
  try {
    const res = await apiFetch('/api/v1/enrollment-tokens');
    const tokens = await res.json();
    // Konteyner fetch'ten SONRA çözülüyor. Eskiden referans fetch'ten önce
    // alınıyordu; `renderConfigApiDetail` bu arada #content'i başlık + sekme
    // çubuğuyla yeniden yazdığı için o referans DOM'dan kopuyor ve liste
    // "Client Sertifikaları" sekmesinde hep boş kalıyordu. Yeniden yazma
    // aynı id'yi ürettiğinden burada güncel eleman bulunuyor.
    const container = document.getElementById('enrollment-token-list');
    if (!container) return;
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
    const usedTxt = t('tokenUsed'), pendingTxt = t('tokenPending'), expiredTxt = t('tokenExpired');
    const expiresAtLabel = t('tokenExpiresAt');
    // map() içinde `t` parametresi çeviri fonksiyonunu gölgeliyor — metinler
    // döngüden önce çözülüyor.
    const tokenMaskedTitle = t('tokenMaskedHint');
    if (tokens.length === 0) { container.innerHTML = ''; return; }
    // Durum sırası: kullanıldıysa "Kullanıldı", değilse süresi dolmuşsa
    // "Süresi doldu", yoksa "Bekliyor". Süresi dolmuş bir token'ın
    // "Bekliyor" görünmesi operatöre kullanılabilir bir kayıt token'ı varmış
    // gibi gösteriyordu; sunucu (EnrollmentTokenStore.validate) onu zaten
    // reddediyor.
    const statusCell = (tok) => {
      if (tok.used) return `<span style="color:#64748b">${usedTxt}</span>`;
      if (tok.expired) return `<span style="color:#f59e0b">${expiredTxt}</span>`;
      return `<span style="color:#22c55e">${pendingTxt}</span>`;
    };
    container.innerHTML = `<table class="data-table">
      <thead><tr><th>${t('thToken')}</th><th>${t('clientIdLabel')}</th><th>${t('thStatus')}</th><th>${t('thDate')}</th></tr></thead>
      <tbody>${tokens.map((t, i) => `<tr class="${i === 0 ? 'row-latest' : ''}">
        <td style="font-family:monospace;font-weight:700;color:#64748b" title="${esc(tokenMaskedTitle)}">${esc(t.token)}</td>
        <td>${esc(t.clientId)}</td>
        <td${t.expiresAt ? ` title="${esc(expiresAtLabel)}: ${esc(new Date(t.expiresAt).toLocaleString(locale))}"` : ''}>${statusCell(t)}</td>
        <td style="color:#64748b;font-size:11px">${new Date(t.createdAt).toLocaleString(locale)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch (_) {}
}

async function revokeClientCert(id) {
  if (!confirm(t('revokeCertConfirm', id))) return;
  try {
    await apiFetch(`/api/v1/client-certs/${encodeURIComponent(id)}`, { method: 'DELETE' });
    toast(t('certRevoked'), 'success');
    renderMtlsSection();
  } catch (err) { toast(t('error'), 'error'); }
}

// ── Signing Key Section ──────────────────────────────

/**
 * The signing section is shown inside a Config API's "İmzalama" tab. After a
 * change, re-render that tab (header + tab bar included) rather than the bare
 * section, which used to drop the Config API header.
 */
function refreshSigningView() {
  if (currentSection === 'signing' || !selectedApiId) return renderSigningSection();
  configApiTab = 'signing';
  return renderConfigApiDetail(selectedApiId);
}

async function renderSigningSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    // /signing/status is admin-only and newer than /signing-key: without it
    // the section still shows the key, as before.
    const [res, statusRes] = await Promise.all([
      apiFetch('/api/v1/signing-key'),
      apiFetch('/api/v1/signing/status').catch(() => null)
    ]);
    const data = await res.json();
    const status = (statusRes && statusRes.ok) ? await statusRes.json().catch(() => null) : null;
    const keySetActive = !!(status && status.keySet && status.keySet.version > 0);
    const regenBlocked = !status ? ''
      : !status.canRegenerate ? t('regenDisabledSigner', status.signers?.[0]?.type || '?')
      : keySetActive ? t('regenDisabledKeySet') : '';
    // The public key box stays the first .key-box of the section: tooling
    // (and the E2E suite) reads the key from it.
    document.getElementById('content').innerHTML = `
      <div class="section-header">
        <div><div class="section-title-main">${t('signingTitle')}</div><div class="section-sub">${t('signingSub')}</div></div>
        <div class="action-bar">
          <button class="btn btn-primary" data-action="copyText" data-arg0="${esc(data.publicKey)}">${t('copy')}</button>
          <span title="${esc(regenBlocked)}"><button class="btn btn-warning" data-action="regenerateSigningKey"${regenBlocked ? ` disabled title="${esc(regenBlocked)}"` : ''}>${t('regenerateSigningKey')}</button></span>
        </div>
      </div>
      ${regenBlocked ? `<div class="notice notice-warn">${esc(regenBlocked)}</div>` : ''}
      <div class="card">
        <div class="card-title" style="color:#f59e0b">${t('ecdsaWhat')}</div>
        <div style="color:#94a3b8;line-height:1.6;font-size:13px">${t('ecdsaExplain')}</div>
      </div>
      <div class="card"><div class="card-title">${t('publicKey')}</div><div class="key-box">${esc(data.publicKey)}</div></div>
      <div class="card"><div class="card-title">${t('androidIntegration')}</div>
        <div class="key-box">val config = PinVaultConfig.Builder()
    .configApi("default", "https://api.example.com/") {
        signaturePublicKey("${esc(data.publicKey)}")
    }
    .build()</div></div>
      ${status
        ? renderSignersCard(status) + renderKeySetCard(status) + renderSigCacheCard(status.cache || {})
        : `<div class="card"><div class="empty-msg">${t('signingStatusError')}</div></div>`}`;
  } catch (e) {
    document.getElementById('content').innerHTML = `<div class="card"><div class="empty-msg">${t('signingError')}</div></div>`;
  }
}

/** First characters of a key id / pin, full value in the tooltip. */
function shortId(value, n = 16) {
  const s = String(value ?? '');
  return `<span class="mono" title="${esc(s)}">${esc(s.slice(0, n))}${s.length > n ? '…' : ''}</span>`;
}

function renderSignersCard(status) {
  const signers = status.signers || [];
  const setActive = !!(status.keySet && status.keySet.version > 0);
  const inSet = new Set(status.keySet?.keyIds || []);
  const rows = signers.map((s, i) => `<tr>
      <td><b>${esc(s.name)}</b>${i === 0 ? ` <span class="gov-badge gov-badge-primary">${t('primarySigner')}</span>` : ''}</td>
      <td><span class="type-badge type-${esc(s.type)}">${esc(s.type)}</span></td>
      <td>${shortId(s.keyId)}${setActive
        ? (inSet.has(s.keyId) ? ' <span class="status-healthy">&#x2713;</span>'
                              : ` <span class="status-error" title="${esc(t('signerNotInSet'))}">&#x2717;</span>`)
        : ''}</td>
      <td class="muted">${esc(s.description)}</td>
    </tr>`).join('');
  return `<div class="card" id="signers-card">
      <div class="card-title">${t('signersTitle')} (${signers.length})</div>
      <div class="card-hint">${t('signersHint')}</div>
      <table class="data-table">
        <thead><tr><th>${t('thSignerName')}</th><th>${t('thSignerType')}</th><th>${t('thKeyId')}</th><th>${t('thDescription')}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function fmtDuration(seconds) {
  const s = Number(seconds) || 0;
  if (s > 0 && s % 3600 === 0) return t('unitHours', s / 3600);
  if (s > 0 && s % 60 === 0) return t('unitMinutes', s / 60);
  return t('unitSeconds', s);
}

function renderSigCacheCard(c) {
  const stat = (value, label) =>
    `<div><div class="mini-stat-value">${esc(value)}</div><div class="mini-stat-label">${label}</div></div>`;
  return `<div class="card" id="sig-cache-card">
      <div class="card-head">
        <div class="card-title">${t('sigCacheTitle')}</div>
        <span class="gov-badge ${c.cacheEnabled ? 'gov-badge-cache' : ''}">${c.cacheEnabled ? t('diffOn') : t('diffOff')}</span>
      </div>
      <div class="card-hint">${c.cacheEnabled ? t('sigCacheOn') : t('sigCacheOff')}</div>
      <div class="mini-stats">
        ${stat(fmtDuration(c.ttlSeconds), t('sigTtl'))}
        ${stat(c.signaturesProduced ?? 0, t('sigProduced'))}
        ${stat(c.cacheHits ?? 0, t('sigCacheHits'))}
        ${stat(c.cachedEnvelopes ?? 0, t('sigCachedEnvelopes'))}
      </div>
    </div>`;
}

// Result of the last key-set upload, kept across the re-render that follows
// it (the warnings are what the operator needs to read). Shown for 10 min.
let _keysetUploadResult = null;

function renderKeySetCard(status) {
  const ks = status.keySet || {};
  const row = (k, v) => `<div class="info-row"><span class="info-key">${k}</span><span class="info-val">${v}</span></div>`;
  let body;
  if (!ks.enabled) {
    body = `<div class="notice">${t('keysetDisabled')}</div>`;
  } else {
    body = row(t('keysetRecoveryKeys'),
        (ks.recoveryKeyIds || []).map(k => shortId(k)).join('<br>') || '&#x2014;')
      + row(t('keysetRecoveryRequired'), esc(ks.recoveryRequiredSignatures ?? 1));
    if (ks.version > 0) {
      body += row(t('keysetVersion'), `v${esc(ks.version)}`)
        + row(t('keysetKeyIds'), (ks.keyIds || []).map(k => shortId(k)).join('<br>') || '&#x2014;')
        + row(t('keysetRequired'), esc(ks.requiredSignatures ?? 1))
        + row(t('keysetUploadedBy'), esc(ks.uploadedBy || '—'))
        + row(t('keysetUploadedAt'), fmtTime(ks.uploadedAt));
    } else {
      body += `<div class="muted" style="font-size:12px;padding:8px 0">${t('keysetNone')}</div>`;
    }
    if ((ks.activeSignersMissing || []).length) {
      body += `<div class="notice notice-danger" style="margin-top:10px">${esc(t('keysetMissingWarn',
        ks.activeSignersMissing.map(k => String(k).slice(0, 12) + '…').join(', ')))}</div>`;
    }
  }
  return `<div class="card" id="keyset-card">
      <div class="card-head">
        <div class="card-title">${t('keysetTitle')}</div>
        ${ks.enabled && ks.version > 0 ? `<span class="ver-badge">v${esc(ks.version)}</span>` : ''}
      </div>
      <div class="card-hint">${t('keysetHint')}</div>
      ${body}
      <div class="form-group" style="margin-top:14px">
        <label class="form-label" for="keyset-json">${esc(t('keysetPasteLabel'))}</label>
        <textarea id="keyset-json" class="form-input keyset-textarea" rows="6" spellcheck="false"
          placeholder="${esc('{"payload":"{\\"type\\":\\"pinvault-signing-keys\\",…}","signatures":[{"keyId":"…","signature":"…"}]}')}"
          ${ks.enabled ? '' : 'disabled'}></textarea>
      </div>
      <button class="btn btn-primary" data-action="uploadKeyset"${ks.enabled ? '' : ` disabled title="${esc(t('keysetDisabled'))}"`}>${t('keysetUploadBtn')}</button>
      <div id="keyset-upload-result">${renderKeysetUploadResult()}</div>
    </div>`;
}

function renderKeysetUploadResult() {
  const r = _keysetUploadResult;
  if (!r || Date.now() - r.at > 10 * 60 * 1000) return '';
  if (!r.ok) {
    return `<div class="notice notice-danger" style="margin-top:10px"><b>${t('keysetRejected')}:</b> ${esc(r.error)}</div>`;
  }
  const warnings = (r.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
  return `<div class="notice ${warnings ? 'notice-warn' : 'notice-info'}" style="margin-top:10px">
      <b>${esc(t('keysetUploaded', r.version))}</b>
      ${warnings ? `<div style="margin-top:6px">${t('keysetUploadWarnings')}:</div><ul class="notice-list">${warnings}</ul>` : ''}
    </div>`;
}

/**
 * PUT /api/v1/signing-keyset with the pasted JSON. The set is signed OFFLINE
 * by the recovery key(s); the dashboard only relays it. The text is sent as
 * pasted — `payload` must stay byte-for-byte what was signed.
 */
async function uploadKeyset() {
  const raw = (document.getElementById('keyset-json')?.value || '').trim();
  if (!raw) { toast(t('keysetPasteFirst'), 'error'); return; }
  let parsed;
  try { parsed = JSON.parse(raw); } catch (e) { toast(t('keysetInvalidJson', e.message), 'error'); return; }
  if (!parsed || typeof parsed.payload !== 'string' || !Array.isArray(parsed.signatures)) {
    toast(t('keysetBadShape'), 'error');
    return;
  }
  try {
    const res = await apiFetch('/api/v1/signing-keyset', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: raw
    });
    if (res.status === 202) return; // waiting for approval — apiFetch said so
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      _keysetUploadResult = { at: Date.now(), ok: false, error: data.error || `HTTP ${res.status}` };
      const box = document.getElementById('keyset-upload-result');
      if (box) box.innerHTML = renderKeysetUploadResult();
      toast(data.error || t('keysetRejected'), 'error');
      return;
    }
    _keysetUploadResult = { at: Date.now(), ok: true, version: data.version, warnings: data.warnings || [] };
    toast(t('keysetUploaded', data.version), (data.warnings || []).length ? 'warning' : 'success');
    refreshSigningView();
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Cert Info & Mock Server ──────────────────────────

async function loadCertInfo(hostname) {
  const card = document.getElementById('cert-info-card');
  if (!card) return;

  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/cert-info`);
    if (!res.ok) {
      card.innerHTML = `<div class="card-title">${t('certInfo')}</div><div class="empty-msg">${t('noCert')}</div>
        ${renderCertRenewSection(hostname)}`;
      return;
    }
    const c = await res.json();
    const cn = (c.subject.match(/CN=([^,]+)/) || [])[1] || c.subject;

    card.innerHTML = `
      <div class="card-title">${t('certInfo')}</div>
      <div style="font-size:12px">
        <div class="info-row"><span class="info-key">CN</span><span class="info-val">${cn}</span></div>
        <div class="info-row"><span class="info-key">${t('algorithmLabel')}</span><span class="info-val">${c.publicKeyAlgorithm} ${c.publicKeyBits}-bit</span></div>
        <div class="info-row"><span class="info-key">${t('validUntilLabel')}</span><span class="info-val" style="color:#f59e0b">${new Date(c.validUntil).toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')}</span></div>
        <div class="info-row"><span class="info-key">SAN</span><span class="info-val">${c.subjectAltNames.join(', ')}</span></div>
        <div class="info-row" style="border:none"><span class="info-key">${t('thFingerprint')}</span><span class="info-val" style="font-size:9px;font-family:monospace;color:#94a3b8">${c.sha256Fingerprint}</span></div>
      </div>
      ${renderCertRenewSection(hostname)}`;
  } catch (e) {
    card.innerHTML = `<div class="card-title">${t('certInfo')}</div><div class="empty-msg">${t('noCert')}</div>
      ${renderCertRenewSection(hostname)}`;
  }
}

function renderCertRenewSection(hostname) {
  return `
    <div style="margin-top:16px;padding-top:16px;border-top:1px solid #334155;display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-secondary" data-action="rotateHostToBackup" data-arg0="${esc(hostname)}">${t('rotateToBackup')}</button>
      <button class="btn btn-warning" data-action="renewCertAuto" data-arg0="${esc(hostname)}">${t('regenerateCert')}</button>
      <button class="btn btn-secondary" data-action="showCertUploadForm" data-arg0="${esc(hostname)}">${t('renewUpload')}</button>
    </div>
    <div id="cert-upload-form" style="display:none;margin-top:12px"></div>`;
}

function showCertUploadForm(hostname) {
  const form = document.getElementById('cert-upload-form');
  if (!form) return;
  if (form.style.display !== 'none') { form.style.display = 'none'; return; }
  form.style.display = 'block';
  form.innerHTML = `<form data-action-submit="renewCertUpload" data-arg0="${esc(hostname)}">
    <div class="form-group">
      <label class="form-label">${t('renewUploadLabel')}</label>
      <input type="file" id="renew-cert-file" accept=".jks,.p12,.pfx" required style="color:#94a3b8"/>
    </div>
    <div class="form-group">
      <label class="form-label">${t('renewUploadPassword')}</label>
      <input type="password" id="renew-cert-password" value="changeit" class="form-input"/>
    </div>
    <button type="submit" class="btn btn-primary">${t('renewUploadBtn')}</button>
  </form>`;
}

async function renewCertUpload(e, hostname) {
  e.preventDefault();
  const file = document.getElementById('renew-cert-file').files[0];
  if (!file) return;
  const password = document.getElementById('renew-cert-password').value;
  const format = file.name.endsWith('.p12') || file.name.endsWith('.pfx') ? 'pkcs12' : 'jks';

  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);
  formData.append('format', format);

  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/upload-cert`, { method: 'POST', body: formData });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); return; }
    toast(t('certUploadRenewed'), 'success');
    await loadConfig();
    renderHostList();
    selectHost(hostname);
  } catch (e) { toast(t('error'), 'error'); }
}

async function rotateHostToBackup(hostname) {
  if (!confirm(t('rotateHostConfirm'))) return;
  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/rotate-to-backup`, { method: 'POST' });
    if (res.status === 202) return; // waits for a second admin; apiFetch said so
    if (!res.ok) { toast(reasonError(await res.json()), 'error'); return; }
    toast(t('rotatedToBackup'), 'success');
    await loadConfig();
    renderHostList();
    selectHost(hostname);
  } catch (e) { toast(t('error'), 'error'); }
}

async function renewCertAuto(hostname) {
  if (!confirm(t('renewCert') + '?')) return;
  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/regenerate-cert`, { method: 'POST' });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); return; }
    toast(t('certRenewed'), 'success');
    await loadConfig();
    renderHostList();
    selectHost(hostname);
  } catch (e) { toast(t('error'), 'error'); }
}


async function loadMockStatus(hostname) {
  const card = document.getElementById('mock-server-card');
  if (!card) return;

  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/status`);
    if (!res.ok) { card.innerHTML = `<div class="card-title">${t('mockServerTitle')}</div><div class="empty-msg">${t('noCert')}</div>`; return; }
    const data = await res.json();
    const running = data.mockServerRunning;
    const port = data.mockServerPort || 8443;

    if (!data.keystorePath) {
      card.innerHTML = `<div class="card-title">${t('mockServerTitle')}</div><div class="empty-msg">${t('noCert')} — ${t('mockCertNeeded')}</div>`;
      return;
    }

    const mode = data.mockServerMode || 'tls';
    const tlsPort = data.mockTlsPort;
    const mtlsPort = data.mockMtlsPort;

    // Hiç başlatılmamış + port kaydı yok → host mock olarak eklenmedi, sadece
    // remote pinleme için cert üretildi. Kompakt "başlat" sunan küçük kart göster.
    if (!running && tlsPort == null && mtlsPort == null && data.mockServerPort == null) {
      card.innerHTML = `<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          <span>${t('mockServer')}</span>
          <span style="color:#64748b;font-size:11px;font-weight:normal">remote-only</span>
        </div>
        <div style="font-size:12px;color:#94a3b8;margin-bottom:6px">${t('mockRemoteOnlyHint')}</div>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="mock-port" class="form-input" style="width:80px;padding:4px 8px;font-size:12px" value="8443" placeholder="${t('mockPort')}">
          <label style="display:flex;align-items:center;gap:6px;color:#94a3b8;font-size:12px;cursor:pointer">
            <input type="checkbox" id="mock-mtls" style="accent-color:#f59e0b"> mTLS
          </label>
          <button class="btn btn-primary" style="padding:4px 10px;font-size:11px" data-action="toggleMock" data-arg0="${esc(hostname)}">${t('mockStart')}</button>
        </div>`;
      return;
    }

    let statusText;
    if (mode === 'both') {
      statusText = `TLS :${tlsPort} + mTLS :${mtlsPort}`;
    } else if (running) {
      statusText = `${t('mockRunning')} (port ${port}${mode === 'mtls' ? ' mTLS' : ' TLS'})`;
    } else {
      statusText = t('mockStopped');
    }

    card.innerHTML = `
      <div class="card-title">${t('mockServer')}</div>
      <div style="display:flex;align-items:center;gap:10px;cursor:pointer" data-action="toggleMock" data-arg0="${esc(hostname)}">
        <div style="width:40px;height:22px;border-radius:11px;background:${running ? '#22c55e' : '#334155'};position:relative;transition:background 0.2s">
          <div style="width:18px;height:18px;border-radius:50%;background:white;position:absolute;top:2px;${running ? 'right:2px' : 'left:2px'};transition:all 0.2s"></div>
        </div>
        <span style="color:${running ? '#22c55e' : '#64748b'};font-weight:700">${statusText}</span>
      </div>
      ${!running ? `<div style="display:flex;gap:8px;align-items:center;margin-top:8px">
        <input id="mock-port" class="form-input" style="width:80px;padding:4px 8px;font-size:12px" value="${port}" placeholder="${t('mockPort')}">
        <label style="display:flex;align-items:center;gap:6px;color:#94a3b8;font-size:12px;cursor:pointer">
          <input type="checkbox" id="mock-mtls" style="accent-color:#f59e0b"> mTLS
        </label>
      </div>` : ''}`;
  } catch (e) {
    card.innerHTML = `<div class="card-title">${t('mockServerTitle')}</div><div class="empty-msg">${t('error')}</div>`;
  }
}

async function toggleMock(hostname) {
  const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/status`);
  if (!res.ok) return;
  const data = await res.json();
  if (data.mockServerRunning) {
    await stopMock(hostname);
  } else {
    await startMock(hostname);
  }
}

async function startMock(hostname) {
  const portInput = document.getElementById('mock-port');
  const mtlsInput = document.getElementById('mock-mtls');
  const port = parseInt(portInput?.value) || 8443;
  const mtls = mtlsInput?.checked || false;
  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/start-mock`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port, mtls })
    });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); return; }
    toast(t('mockStarted') + ' — port ' + port, 'success');
    loadMockStatus(hostname);
    renderHostList();
  } catch (e) { toast(t('error'), 'error'); }
}

async function stopMock(hostname) {
  try {
    await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/stop-mock`, { method: 'POST' });
    toast(t('mockStoppedMsg'), 'success');
    loadMockStatus(hostname);
    renderHostList();
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Governance: admin identity ───────────────────────
//
// Everything below is driven by optional server features; each view says so
// when its feature is off instead of hiding. `adminMe` is
// GET /api/v1/admin/me, or null when that failed (no/invalid key, old server).

let adminMe = null;

async function loadAdminIdentity() {
  let me = null;
  try {
    const res = await apiFetch('/api/v1/admin/me', { quiet: true });
    if (res.ok) me = await res.json();
  } catch (_) { /* chip shows "not signed in" */ }
  adminMe = me;
  renderAdminChip();
  scheduleApprovalsPoll();
  return me;
}

function liveModeLabel(mode) {
  return mode === 'enforce' ? t('liveModeEnforce') : mode === 'warn' ? t('liveModeWarn') : t('liveModeOff');
}

function renderAdminChip() {
  const el = document.getElementById('admin-chip');
  if (!el) return;
  const me = adminMe;
  const badges = [];
  if (me && me.approvalsRequired >= 2) {
    badges.push(`<span class="gov-badge gov-badge-approvals" title="${esc(t('badgeApprovalsTitle', me.approvalsRequired))}">${esc(t('badgeApprovals', me.approvalsRequired))}</span>`);
  }
  if (me && me.liveCheck && me.liveCheck !== 'off') {
    const cls = me.liveCheck === 'enforce' ? 'gov-badge-live-enforce' : 'gov-badge-live-warn';
    badges.push(`<span class="gov-badge ${cls}" title="${esc(t('badgeLiveCheckTitle'))}">${esc(t('badgeLiveCheck', liveModeLabel(me.liveCheck)))}</span>`);
  }
  if (me && me.signatureCache) {
    badges.push(`<span class="gov-badge gov-badge-cache" title="${esc(t('badgeSigCacheTitle'))}">${esc(t('badgeSigCache'))}</span>`);
  }
  el.innerHTML = `
    <div class="admin-chip-row">
      <span class="admin-avatar">&#x1F464;</span>
      <span class="admin-name${me ? '' : ' admin-name-unknown'}" id="admin-name" title="${esc(t('adminChipTitle'))}">${me ? esc(me.name) : esc(t('adminUnknown'))}</span>
      <button class="admin-switch" data-action="switchAdminKey" title="${esc(t('switchAdminKey'))}" aria-label="${esc(t('switchAdminKey'))}">&#x21C4;</button>
    </div>
    ${badges.length ? `<div class="admin-badges">${badges.join('')}</div>` : ''}`;
}

/** Forget the stored key, ask for another, then reload everything with it. */
async function switchAdminKey() {
  localStorage.removeItem('pinvault_api_key');
  const key = prompt(t('switchAdminKeyPrompt'));
  if (key && key.trim()) setApiKey(key.trim());
  adminMe = null;
  renderAdminChip();
  await loadConfig();
  renderHostList();
  await loadAdminIdentity();
  refreshApprovalsBadge();
  rerenderCurrentView();
  if (adminMe) toast(t('adminKeySwitched', adminMe.name), 'info');
}

function rerenderCurrentView() {
  if (currentSection) return showSection(currentSection);
  if (selectedHost && selectedApiId) return selectHostInApi(selectedHost, selectedApiId);
  if (selectedApiId) return renderConfigApiDetail(selectedApiId);
  renderEmpty();
}

// ── Governance: pending approvals badge ──────────────

let _approvalsPending = null;   // pending count, null = unknown
let _approvalsPendingIds = '';  // to notice changes between polls
let _approvalsPoll = null;
const APPROVALS_POLL_MS = 30000;

function setApprovalsBadge(count) {
  _approvalsPending = count;
  const badge = document.getElementById('approvals-badge');
  if (!badge) return;
  if (count && count > 0) {
    badge.textContent = String(count);
    badge.title = t('approvalsBadgeTitle', count);
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
}

/** Quiet: runs in the background (poll, after writes) and never prompts. */
async function refreshApprovalsBadge() {
  try {
    const res = await apiFetch('/api/v1/change-requests?status=pending', { quiet: true });
    if (!res.ok) return;
    const list = await res.json();
    if (!Array.isArray(list)) return;
    setApprovalsBadge(list.length);
    const ids = list.map(c => c.id).join(',');
    const changed = ids !== _approvalsPendingIds;
    _approvalsPendingIds = ids;
    if (changed && currentSection === 'approvals') renderApprovalsSection();
  } catch (_) { /* badge keeps its last value */ }
}

// Polls only while approvals are on and the page is visible.
function scheduleApprovalsPoll() {
  const wanted = !!(adminMe && adminMe.approvalsRequired >= 2);
  if (wanted && !_approvalsPoll) {
    _approvalsPoll = setInterval(() => { if (!document.hidden) refreshApprovalsBadge(); }, APPROVALS_POLL_MS);
  } else if (!wanted && _approvalsPoll) {
    clearInterval(_approvalsPoll);
    _approvalsPoll = null;
  }
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && _approvalsPoll) refreshApprovalsBadge();
});

// A 202 means NOTHING was applied. Callers still run their "saved" path
// (they check res.ok, and 202 is ok), so their success toast is suppressed
// after this notice instead of contradicting it — until the user starts
// another action (see beginUserAction) or at most PENDING_SUPPRESS_MS.
// Time alone is not enough: an approver clicking right after would lose the
// genuine "applied" toast.
let _pendingNoticeUntil = 0;
const PENDING_SUPPRESS_MS = 3000;

function notePendingApproval(p) {
  _pendingNoticeUntil = Date.now() + PENDING_SUPPRESS_MS;
  toast(t('pendingChange', p.changeRequestId), 'info', 7000);
  refreshApprovalsBadge();
}

/** Called by the action dispatcher: a new user action ends the suppression. */
function beginUserAction() { _pendingNoticeUntil = 0; }

// ── Governance: shared rendering helpers ─────────────

function fmtTime(iso) {
  if (!iso) return '&#x2014;';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return esc(iso);
  return esc(d.toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US'));
}

function parseJsonText(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch (_) { return null; }
}

function onOff(v) { return v ? t('diffOn') : t('diffOff'); }

/** One line per failed host of a live-check result (plain text). */
function liveCheckFailureLines(result) {
  return (result?.checks || []).filter(c => !c.matched).map(c => c.reachable
    ? t('liveNotInSet', c.hostname, String((c.livePins || [])[0] || '').slice(0, 12))
    : t('liveUnreachable', c.hostname, c.error || '?'));
}

/** One live-check host result as HTML; [pins] = the set that was checked. */
function liveCheckLine(c, pins) {
  const leaf = String((c.livePins || [])[0] || '');
  const probed = c.probed ? ` <span class="muted">(${t('liveProbed')}: ${esc(c.probed)})</span>` : '';
  // Devices accept the leaf's pin or the pin of an issuer the leaf really chains to.
  const issuerPin = (c.livePins || []).slice(1).find(p => (pins || []).includes(p));
  if (c.matched) {
    const text = (pins || []).includes(leaf) || !issuerPin
      ? t('liveOk', c.hostname, leaf.slice(0, 12))
      : t('liveOkIssuer', c.hostname, issuerPin.slice(0, 12));
    return `<div class="live-check-line live-ok">&#x2713; ${esc(text)}${probed}</div>`;
  }
  if (c.reachable) {
    const intermediate = Boolean(issuerPin);
    return `<div class="live-check-line live-bad">&#x2717; ${esc(t('liveNotInSet', c.hostname, leaf.slice(0, 12)))}${probed}
        ${leaf ? `<div class="live-leaf"><span class="mono">sha256/${esc(leaf)}</span>
          <button class="copy-btn" data-action="copyText" data-arg0="${esc(leaf)}">${t('copy')}</button></div>` : ''}
        ${intermediate ? `<div class="muted">${t('liveIssuerNoChain')}</div>` : ''}
      </div>`;
  }
  return `<div class="live-check-line live-warn">&#x26A0; ${esc(t('liveUnreachable', c.hostname, c.error || '?'))}${probed}</div>`;
}

// ── Pin editors: live certificate dry run ────────────

/**
 * POST /api/v1/pins/live-check with the pins currently in the editor. Works
 * whatever PIN_LIVE_CHECK is set to; saves nothing. [source]: `inline` (host
 * detail), `page` (full-page editor) or `add` (new host, manual tab).
 */
async function liveCheckPins(hostname, source) {
  let host = hostname;
  let pins;
  if (source === 'add') {
    host = (document.getElementById('add-hostname')?.value || '').trim();
    pins = ['add-hash-0', 'add-hash-1'].map(id => (document.getElementById(id)?.value || '').trim());
  } else {
    const editor = document.getElementById(source === 'page' ? 'pins-page-edit' : 'pins-edit');
    const inputs = editor ? [...editor.querySelectorAll('input.form-input')] : [];
    pins = inputs.length ? inputs.map(i => i.value.trim()) : editHashes.map(h => String(h || '').trim());
  }
  pins = pins.filter(Boolean);
  if (!host) { toast(t('liveCheckNeedHost'), 'error'); return; }
  if (!pins.length) { toast(t('liveCheckNeedPins'), 'error'); return; }
  const box = document.getElementById('live-check-result');
  if (box) box.innerHTML = `<div class="live-check-line">${t('liveCheckRunning')}</div>`;
  try {
    const res = await apiFetch('/api/v1/pins/live-check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pins: [{ hostname: host, sha256: pins }] })
    });
    const data = await res.json().catch(() => null);
    const target = document.getElementById('live-check-result');
    if (!res.ok || !data || !Array.isArray(data.checks)) {
      const msg = (data && data.error) || `HTTP ${res.status}`;
      if (target) target.innerHTML = `<div class="live-check-line live-bad">${esc(msg)}</div>`;
      else toast(msg, 'error');
      return;
    }
    if (!target) return;
    target.innerHTML = data.checks.map(c => liveCheckLine(c, pins)).join('')
      + (data.passed ? '' : `<div class="muted live-hint">${esc(t('liveRotationHint'))}</div>`);
  } catch (e) {
    const target = document.getElementById('live-check-result');
    if (target) target.innerHTML = `<div class="live-check-line live-bad">${esc(e.message)}</div>`;
  }
}

// ── Governance: Approvals section ────────────────────

let approvalsTab = 'pending';
const _crExpanded = new Set();   // change request ids whose detail is open
const _crById = new Map();       // last rendered requests, for the actions

function crStatusBadge(status) {
  const key = 'crStatus_' + status;
  const label = (i18n[lang]?.[key] || i18n.tr[key]) ? t(key) : status;
  return `<span class="cr-status cr-status-${esc(status)}">${esc(label)}</span>`;
}

function opBadge(op) {
  if (!op) return '';
  const key = 'op_' + op;
  const label = (i18n[lang]?.[key] || i18n.tr[key]) ? t(key) : op;
  return `<span class="op-badge" title="${esc(op)}">${esc(label)}</span>`;
}

function pinChip(hash, kind) {
  const s = String(hash || '');
  const cls = kind === 'add' ? ' pin-add' : kind === 'del' ? ' pin-del' : '';
  const mark = kind === 'add' ? '+' : kind === 'del' ? '−' : '';
  return `<span class="pin-chip${cls}" title="${esc(s)}">${mark}${esc(s.slice(0, 12))}…</span>`;
}

function pinFlags(p) {
  const flags = [];
  if (p.forceUpdate) flags.push('force');
  if (p.mtls) flags.push('mTLS');
  if (p.clientCertVersion != null) flags.push('client cert v' + p.clientCertVersion);
  return flags.length ? ` <span class="diff-note">${esc(flags.join(' · '))}</span>` : '';
}

/** The diff (and live-check dry run) a change request was stored with. */
function renderChangeDetail(cr, d) {
  if (!d) return `<div class="muted small">${t('diffNoDetail')}</div>`;
  const out = [];
  if (d.describeError) out.push(`<div class="notice notice-warn">${esc(t('diffDescribeError', d.describeError))}</div>`);
  const hasDiff = Array.isArray(d.added) || Array.isArray(d.removed) || Array.isArray(d.changed) || d.forceUpdate;
  (d.added || []).forEach(p => out.push(`<div class="diff-row diff-add"><span class="diff-mark">+</span><b>${esc(p.hostname)}</b>
      <span class="ver-badge">v${esc(p.version)}</span>${pinFlags(p)}
      <div class="diff-pins">${(p.sha256 || []).map(h => pinChip(h, 'add')).join('')}</div></div>`));
  (d.removed || []).forEach(p => out.push(`<div class="diff-row diff-del"><span class="diff-mark">−</span><b>${esc(p.hostname)}</b>
      <span class="ver-badge">v${esc(p.version)}</span>${pinFlags(p)}
      <div class="diff-pins">${(p.sha256 || []).map(h => pinChip(h, 'del')).join('')}</div></div>`));
  (d.changed || []).forEach(c => {
    const from = c.from || {}, to = c.to || {};
    const before = new Set(from.sha256 || []), after = new Set(to.sha256 || []);
    const chips = (to.sha256 || []).map(h => pinChip(h, before.has(h) ? 'keep' : 'add'))
      .concat((from.sha256 || []).filter(h => !after.has(h)).map(h => pinChip(h, 'del')));
    const notes = [];
    if (from.version !== to.version) notes.push(`v${from.version} → v${to.version}`);
    if (!!from.forceUpdate !== !!to.forceUpdate) notes.push(`force ${onOff(from.forceUpdate)} → ${onOff(to.forceUpdate)}`);
    if (!!from.mtls !== !!to.mtls) notes.push(`mTLS ${onOff(from.mtls)} → ${onOff(to.mtls)}`);
    if ((from.clientCertVersion ?? null) !== (to.clientCertVersion ?? null)) {
      notes.push(`client cert v${from.clientCertVersion ?? '–'} → v${to.clientCertVersion ?? '–'}`);
    }
    out.push(`<div class="diff-row diff-mod"><span class="diff-mark">~</span><b>${esc(c.hostname)}</b>
        <span class="diff-note">${esc(notes.join(' · '))}</span>
        <div class="diff-pins">${chips.join('')}</div></div>`);
  });
  if (d.forceUpdate) {
    out.push(`<div class="diff-row diff-mod"><span class="diff-mark">~</span>${t('diffGlobalForce')}:
        ${onOff(d.forceUpdate.from)} → ${onOff(d.forceUpdate.to)}</div>`);
  }
  if (!hasDiff) out.push(`<div class="muted small">${t('diffNoDetail')}</div>`);
  else if (!(d.added || []).length && !(d.removed || []).length && !(d.changed || []).length && !d.forceUpdate) {
    out.push(`<div class="muted small">${t('diffNoChange')}</div>`);
  }
  if (d.liveCheck) out.push(renderStoredLiveCheck(d.liveCheck, cr));
  if (cr.resultBody) {
    const parsed = parseJsonText(cr.resultBody);
    out.push(`<div class="diff-section-title">${t('crResultBody')} (HTTP ${esc(cr.resultStatus ?? '?')})</div>
      <pre class="json-box">${esc(parsed ? JSON.stringify(parsed, null, 2) : cr.resultBody)}</pre>`);
  }
  return out.join('');
}

function renderStoredLiveCheck(lc, cr) {
  const override = new URLSearchParams(cr.query || '').get('liveCheckOverride');
  const verdict = lc.passed
    ? `<span class="status-healthy">&#x2713; ${t('livePassed')}</span>`
    : `<span class="status-error">&#x2717; ${t('liveFailed')}</span>`;
  let note = '';
  if (!lc.passed && override) note = `<div class="notice notice-info">${esc(t('liveOverrideCarried', override))}</div>`;
  else if (!lc.passed && lc.mode === 'enforce' && cr.status === 'pending') {
    note = `<div class="notice notice-danger">${esc(t('liveEnforceWillFail'))}</div>`;
  }
  return `<div class="diff-section-title">${t('liveCheckTitle')} (${esc(liveModeLabel(lc.mode))}): ${verdict}</div>
    ${(lc.checks || []).map(c => liveCheckLine(c, null)).join('')}${note}`;
}

function approveBlockReason(cr) {
  const me = adminMe?.name;
  if (!me) return '';
  if (cr.requestedBy === me) return t('cannotApproveOwn');
  // The shared API_KEY holder is named "admin" and can never approve.
  if (me === 'admin' || me === 'anonymous') return t('cannotApproveShared');
  if ((cr.approvedBy || []).includes(me)) return t('alreadyApproved');
  return '';
}

function renderPendingChange(cr) {
  const id = String(cr.id);
  const d = parseJsonText(cr.detail);
  const own = adminMe && cr.requestedBy === adminMe.name;
  const block = approveBlockReason(cr);
  const need = Math.max(1, (adminMe?.approvalsRequired || 2) - 1);
  const open = _crExpanded.has(id);
  const live = d?.liveCheck
    ? `<span class="${d.liveCheck.passed ? 'status-healthy' : 'status-error'}">${t('liveCheckTitle')}: ${d.liveCheck.passed ? '&#x2713; ' + t('livePassed') : '&#x2717; ' + t('liveFailed')}</span>`
    : '';
  return `<div class="card cr-card" id="cr-card-${esc(id)}">
      <div class="cr-head">
        <div class="cr-title">
          <span class="cr-id">#${esc(id)}</span>${opBadge(d?.operation)}
          <span class="cr-summary">${esc(cr.summary)}</span>
        </div>
        <div class="cr-actions">
          <button class="btn btn-secondary btn-sm" data-action="toggleChangeDetail" data-arg0="${esc(id)}">${t('crDetails')} <span class="cr-caret">${open ? '&#x25B4;' : '&#x25BE;'}</span></button>
          <span title="${esc(block)}"><button class="btn btn-success btn-sm" data-action="approveChange" data-arg0="${esc(id)}"${block ? ` disabled title="${esc(block)}"` : ''}>${t('approve')}</button></span>
          <button class="btn btn-danger btn-sm" data-action="rejectChange" data-arg0="${esc(id)}">${own ? t('withdraw') : t('reject')}</button>
        </div>
      </div>
      <div class="cr-meta">
        <span>${t('crRequestedBy')}: <b>${esc(cr.requestedBy)}</b></span>
        <span>${t('crCreated')}: ${fmtTime(cr.createdAt)}</span>
        <span>${t('crExpires')}: ${fmtTime(cr.expiresAt)}</span>
        ${cr.configApiId ? `<span>Config API: <b>${esc(cr.configApiId)}</b></span>` : ''}
        <span>${t('crApprovals')}: <b>${(cr.approvedBy || []).length}/${need}</b>${(cr.approvedBy || []).length ? ' (' + esc(cr.approvedBy.join(', ')) + ')' : ''}</span>
        ${live}
      </div>
      <div class="cr-meta"><span class="mono">${esc(cr.method)} ${esc(cr.path)}${cr.query ? '?' + esc(cr.query) : ''}</span></div>
      <div class="cr-detail" id="cr-detail-${esc(id)}" style="${open ? '' : 'display:none'}">${renderChangeDetail(cr, d)}</div>
    </div>`;
}

function renderDecidedTable(decided) {
  if (!decided.length) return `<div class="card"><div class="empty-msg">${t('noDecidedChanges')}</div></div>`;
  const pagKey = 'cr-history';
  const info = pagSlice(decided, pagKey);
  const rows = info.slice.map(cr => {
    const id = String(cr.id);
    const d = parseJsonText(cr.detail);
    const open = _crExpanded.has(id);
    return `<tr class="row-toggle" data-action="toggleChangeDetail" data-arg0="${esc(id)}">
        <td class="cr-id">#${esc(id)} <span class="cr-caret">${open ? '&#x25B4;' : '&#x25BE;'}</span></td>
        <td>${crStatusBadge(cr.status)}</td>
        <td>${opBadge(d?.operation)} ${esc(cr.summary)}</td>
        <td>${esc(cr.requestedBy)}</td>
        <td>${esc(cr.decidedBy || '—')}${(cr.approvedBy || []).some(a => a !== cr.decidedBy) ? `<div class="muted small">${esc(t('crApprovals'))}: ${esc(cr.approvedBy.join(', '))}</div>` : ''}</td>
        <td class="muted nowrap">${fmtTime(cr.decidedAt)}</td>
        <td class="muted">${esc(cr.reason || '—')}</td>
        <td>${cr.resultStatus != null ? `<span class="${cr.resultStatus >= 200 && cr.resultStatus < 300 ? 'status-healthy' : 'status-error'}">HTTP ${esc(cr.resultStatus)}</span>` : '&#x2014;'}</td>
      </tr>
      <tr class="detail-row" id="cr-detail-${esc(id)}" style="${open ? '' : 'display:none'}"><td colspan="8">${renderChangeDetail(cr, d)}</td></tr>`;
  }).join('');
  return `<div class="card">
      <table class="data-table">
        <thead><tr><th>#</th><th>${t('thStatus')}</th><th>${t('auditThSummary')}</th><th>${t('crRequestedBy')}</th>
          <th>${t('crDecidedBy')}</th><th>${t('crDecidedAt')}</th><th>${t('crReason')}</th><th>${t('crResult')}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>${pagControls(pagKey, info, 'renderApprovalsSection')}
    </div>`;
}

async function renderApprovalsSection() {
  const content = document.getElementById('content');
  if (!document.getElementById('approvals-view')) content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    if (!adminMe) await loadAdminIdentity();
    // Pending separately: the full list is capped (newest 100).
    const [pendingRes, allRes] = await Promise.all([
      apiFetch('/api/v1/change-requests?status=pending'),
      apiFetch('/api/v1/change-requests?status=all')
    ]);
    if (currentSection !== 'approvals') return; // navigated away meanwhile
    if (!pendingRes.ok || !allRes.ok) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')} (HTTP ${pendingRes.ok ? allRes.status : pendingRes.status})</div></div>`;
      return;
    }
    const pending = await pendingRes.json();
    const decided = (await allRes.json()).filter(c => c.status !== 'pending');
    _crById.clear();
    [...pending, ...decided].forEach(c => _crById.set(String(c.id), c));
    setApprovalsBadge(pending.length);
    _approvalsPendingIds = pending.map(c => c.id).join(',');

    const required = adminMe?.approvalsRequired || 1;
    const mode = required >= 2
      ? `<div class="notice notice-info">${esc(t('approvalsOn', required - 1, adminMe?.name || '?'))}</div>`
      : `<div class="notice">${t('approvalsOff')}</div>`;
    const list = approvalsTab === 'history'
      ? renderDecidedTable(decided)
      : (pending.length ? pending.map(renderPendingChange).join('')
                        : `<div class="card"><div class="empty-msg">${t('noPendingChanges')}</div></div>`);
    content.innerHTML = `
      <div id="approvals-view">
        <div class="section-header">
          <div><div class="section-title-main">${t('approvalsTitle')}</div><div class="section-sub">${t('approvalsSub')}</div></div>
          <span class="refresh-icon" data-action="refreshApprovals" title="${t('refresh')}">&#x21bb;</span>
        </div>
        ${mode}
        <div class="tab-bar">
          <button class="tab-btn ${approvalsTab === 'pending' ? 'tab-active' : ''}" data-action="setApprovalsTab" data-arg0="pending">${esc(t('tabPending', pending.length))}</button>
          <button class="tab-btn ${approvalsTab === 'history' ? 'tab-active' : ''}" data-action="setApprovalsTab" data-arg0="history">${esc(t('tabDecided', decided.length))}</button>
        </div>
        ${list}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${esc(e.message)}</div></div>`;
  }
}

function setApprovalsTab(tab) { approvalsTab = tab === 'history' ? 'history' : 'pending'; renderApprovalsSection(); }
function refreshApprovals() { renderApprovalsSection(); }

function toggleChangeDetail(id) {
  const key = String(id);
  const show = !_crExpanded.has(key);
  if (show) _crExpanded.add(key); else _crExpanded.delete(key);
  const el = document.getElementById('cr-detail-' + key);
  if (el) el.style.display = show ? '' : 'none';
  document.querySelectorAll(`[data-action="toggleChangeDetail"][data-arg0="${CSS.escape(key)}"] .cr-caret`)
    .forEach(c => { c.innerHTML = show ? '&#x25B4;' : '&#x25BE;'; });
}

/** After a decision: pins may have changed — reload them, then the list. */
async function afterChangeDecision() {
  await loadConfig();
  renderHostList();
  refreshApprovalsBadge();
  if (currentSection === 'approvals') renderApprovalsSection();
}

async function approveChange(id) {
  try {
    const res = await apiFetch(`/api/v1/change-requests/${encodeURIComponent(id)}/approve`, { method: 'POST' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      // 409: own request, shared key, already decided, pins changed since (stale).
      toast(body.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000);
    } else if (body.status === 'applied') {
      toast(t('changeApplied', id), 'success');
    } else if (body.status === 'failed') {
      toast(t('changeApplyFailed', id, body.resultStatus ?? '?'), 'error', 6000);
    } else {
      const need = Math.max(1, (adminMe?.approvalsRequired || 2) - 1);
      toast(t('changeApprovalRecorded', id, (body.approvedBy || []).length, need), 'info');
    }
  } catch (e) {
    toast(t('error'), 'error');
  }
  await afterChangeDecision();
}

async function rejectChange(id) {
  const cr = _crById.get(String(id));
  const own = !!(cr && adminMe && cr.requestedBy === adminMe.name);
  const reason = prompt(t(own ? 'withdrawReasonPrompt' : 'rejectReasonPrompt', id), '');
  if (reason === null) return;
  try {
    const res = await apiFetch(`/api/v1/change-requests/${encodeURIComponent(id)}/reject`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reason.trim() ? { reason: reason.trim() } : {})
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) toast(body.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000);
    else toast(t(own ? 'changeWithdrawn' : 'changeRejected', id), 'success');
  } catch (e) {
    toast(t('error'), 'error');
  }
  await afterChangeDecision();
}

// ── Governance: Audit log section ────────────────────

const AUDIT_ACTIONS = [
  'pins_changed', 'change_requested', 'change_approved', 'change_applied', 'change_failed',
  'change_rejected', 'change_expired', 'change_stale', 'change_approval_refused', 'live_check_warning', 'live_check_blocked',
  'live_check_overridden', 'signing_key_regenerated', 'signing_keyset_uploaded', 'auth_failed',
  'cert_expiring', 'notification_test', 'http'
];
const AUDIT_PAG_KEY = 'audit-log';
let auditActionFilter = '';
let _auditVerify = null;          // last /audit-log/verify answer
const _auditExpanded = new Set(); // entry ids whose detail is open

function auditActionLabel(action) {
  const key = 'act_' + action;
  return (i18n[lang]?.[key] || i18n.tr[key]) ? t(key) : action;
}

function auditActionBadge(action) {
  const cls =
    action === 'pins_changed' ? 'act-pins' :
    action === 'change_applied' || action === 'change_approved' ? 'act-ok' :
    action === 'change_requested' ? 'act-pins' :
    action === 'live_check_blocked' || action === 'auth_failed' || action === 'change_failed' ? 'act-bad' :
    action === 'live_check_warning' || action === 'live_check_overridden' || action === 'cert_expiring' ||
      action === 'change_rejected' || action === 'change_expired' || action === 'change_stale' ||
      action === 'change_approval_refused' ? 'act-warn' :
    action === 'signing_key_regenerated' || action === 'signing_keyset_uploaded' ? 'act-key' :
    'act-muted';
  return `<span class="act-badge ${cls}" title="${esc(auditActionLabel(action))}">${esc(action)}</span>`;
}

function renderAuditDetail(e) {
  let pretty = '';
  if (e.detail) {
    const parsed = parseJsonText(e.detail);
    pretty = parsed ? JSON.stringify(parsed, null, 2) : e.detail;
  }
  return `<div class="audit-detail-meta">
      <span>${t('auditSourceIp')}: <span class="mono">${esc(e.sourceIp || '—')}</span></span>
      <span>hash: ${shortId(e.hash)}</span>
      <span>prev: ${shortId(e.prevHash)}</span>
    </div>
    ${pretty ? `<pre class="json-box">${esc(pretty)}</pre>` : `<div class="muted small">${t('auditNoDetail')}</div>`}`;
}

function renderAuditVerify(v) {
  if (!v) return '';
  return v.ok
    ? `<span class="verify-result status-healthy">&#x2713; ${esc(t('auditVerifyOk', v.entries))}</span>`
    : `<span class="verify-result status-error">&#x2717; ${esc(t('auditVerifyBroken', v.firstBrokenId ?? '?'))}</span>`;
}

function renderNotificationsCard(n) {
  const row = (k, v) => `<div class="info-row"><span class="info-key">${k}</span><span class="info-val">${v}</span></div>`;
  if (!n) {
    return `<div class="card" id="notif-card"><div class="card-title">${t('notifTitle')}</div><div class="empty-msg">${t('error')}</div></div>`;
  }
  const recent = n.recent || [];
  const rows = recent.map(d => {
    const ok = d.status != null && d.status >= 200 && d.status < 300;
    return `<tr>
        <td class="mono">${esc(d.event)}</td>
        <td class="muted nowrap">${fmtTime(d.at)}</td>
        <td>${d.auditId != null ? '#' + esc(d.auditId) : '&#x2014;'}</td>
        <td class="${ok ? 'status-healthy' : 'status-error'}">${d.status != null ? esc(d.status) : '&#x2014;'}</td>
        <td>${esc(d.attempts)}</td>
        <td class="status-error small">${esc(d.error || '')}</td>
      </tr>`;
  }).join('');
  return `<div class="card" id="notif-card">
      <div class="card-head">
        <div class="card-title">${t('notifTitle')}</div>
        <button class="btn btn-secondary btn-sm" data-action="sendTestNotification"${n.configured ? '' : ` disabled title="${esc(t('notifNotConfigured'))}"`}>${t('notifTestBtn')}</button>
      </div>
      ${row(t('notifStatus'), n.configured
        ? `<span class="status-healthy">&#x2713; ${t('notifConfigured')}</span>`
        : `<span class="muted">${t('notifNotConfigured')}</span>`)}
      ${n.configured ? row(t('notifTarget'), esc(n.target || '—'))
        + row(t('notifSigned'), n.signed ? `<span class="status-healthy">${t('notifSignedYes')}</span>` : `<span class="muted">${t('notifSignedNo')}</span>`)
        + row(t('notifEvents'), esc((n.events || []).join(', ') || '*')) : ''}
      ${n.configured ? `<div class="diff-section-title">${t('notifRecent')} (${recent.length})</div>
        ${recent.length ? `<table class="data-table">
          <thead><tr><th>${t('thEvent')}</th><th>${t('thDate')}</th><th>${t('notifThAudit')}</th><th>${t('thStatus')}</th><th>${t('notifThAttempts')}</th><th>${t('thError')}</th></tr></thead>
          <tbody>${rows}</tbody></table>` : `<div class="empty-msg">${t('notifNoDeliveries')}</div>`}` : ''}
    </div>`;
}

async function renderAuditSection() {
  const content = document.getElementById('content');
  if (!document.getElementById('audit-view')) content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  const st = _pagState[AUDIT_PAG_KEY] || (_pagState[AUDIT_PAG_KEY] = { page: 0, size: 25 });
  const size = st.size > 0 ? st.size : 25;
  const params = new URLSearchParams({ limit: String(size), offset: String(st.page * size) });
  if (auditActionFilter) params.set('action', auditActionFilter);
  try {
    const [logRes, notifRes] = await Promise.all([
      apiFetch('/api/v1/audit-log?' + params.toString()),
      apiFetch('/api/v1/notifications').catch(() => null)
    ]);
    if (currentSection !== 'audit') return; // navigated away meanwhile
    if (!logRes.ok) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')} (HTTP ${logRes.status})</div></div>`;
      return;
    }
    const log = await logRes.json();
    const notif = (notifRes && notifRes.ok) ? await notifRes.json().catch(() => null) : null;
    const total = log.total || 0;
    const pageCount = Math.max(1, Math.ceil(total / size));
    if (st.page > 0 && st.page >= pageCount) { st.page = pageCount - 1; return renderAuditSection(); }
    const entries = log.entries || [];
    const rows = entries.map(e => {
      const id = String(e.id);
      const open = _auditExpanded.has(id);
      return `<tr class="row-toggle" data-action="toggleAuditDetail" data-arg0="${esc(id)}">
          <td class="mono muted">#${esc(id)}</td>
          <td class="muted nowrap">${fmtTime(e.at)}</td>
          <td><b>${esc(e.actor)}</b></td>
          <td>${auditActionBadge(e.action)}</td>
          <td class="muted">${esc(e.configApiId || '—')}</td>
          <td class="mono small">${esc(e.target || '—')}</td>
          <td>${esc(e.summary)}</td>
        </tr>
        <tr class="detail-row" id="audit-detail-${esc(id)}" style="${open ? '' : 'display:none'}"><td colspan="7">${renderAuditDetail(e)}</td></tr>`;
    }).join('');
    const options = [''].concat(AUDIT_ACTIONS.includes(auditActionFilter) || !auditActionFilter
        ? AUDIT_ACTIONS : AUDIT_ACTIONS.concat(auditActionFilter))
      .map(a => `<option value="${esc(a)}"${a === auditActionFilter ? ' selected' : ''}>${a ? esc(auditActionLabel(a) + ' — ' + a) : esc(t('auditFilterAll'))}</option>`)
      .join('');
    const pag = pagControls(AUDIT_PAG_KEY, { page: st.page, pageCount, size, total }, 'renderAuditSection');
    content.innerHTML = `
      <div id="audit-view">
        <div class="section-header">
          <div><div class="section-title-main">${t('auditTitle')}</div><div class="section-sub">${t('auditSub')}</div></div>
          <div class="toolbar">
            <span id="audit-verify-result">${renderAuditVerify(_auditVerify)}</span>
            <button class="btn btn-primary" data-action="verifyAuditChain">${t('auditVerify')}</button>
            <span class="refresh-icon" data-action="refreshAudit" title="${t('refresh')}">&#x21bb;</span>
          </div>
        </div>
        <div class="card">
          <div class="card-head">
            <div class="card-title">${t('auditTitle')} (${esc(t('auditEntries', total))})</div>
            <select id="audit-action-filter" class="form-input select-sm" data-action-change="setAuditActionFilter" data-event="1">${options}</select>
          </div>
          ${entries.length ? `<table class="data-table">
            <thead><tr><th>#</th><th>${t('auditThTime')}</th><th>${t('auditThActor')}</th><th>${t('auditThAction')}</th>
              <th>Config API</th><th>${t('auditThTarget')}</th><th>${t('auditThSummary')}</th></tr></thead>
            <tbody>${rows}</tbody></table>` : `<div class="empty-msg">${t('auditEmpty')}</div>`}
          ${pag}
        </div>
        ${renderNotificationsCard(notif)}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${esc(e.message)}</div></div>`;
  }
}

function refreshAudit() { renderAuditSection(); }

function setAuditActionFilter(ev) {
  auditActionFilter = ev.target.value || '';
  const st = _pagState[AUDIT_PAG_KEY] || (_pagState[AUDIT_PAG_KEY] = { page: 0, size: 25 });
  st.page = 0;
  renderAuditSection();
}

function toggleAuditDetail(id) {
  const key = String(id);
  const show = !_auditExpanded.has(key);
  if (show) _auditExpanded.add(key); else _auditExpanded.delete(key);
  const el = document.getElementById('audit-detail-' + key);
  if (el) el.style.display = show ? '' : 'none';
}

async function verifyAuditChain() {
  try {
    const res = await apiFetch('/api/v1/audit-log/verify');
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.error || `${t('error')} (HTTP ${res.status})`, 'error'); return; }
    _auditVerify = data;
    const el = document.getElementById('audit-verify-result');
    if (el) el.innerHTML = renderAuditVerify(data);
    toast(data.ok ? t('auditVerifyOk', data.entries) : t('auditVerifyBroken', data.firstBrokenId ?? '?'),
      data.ok ? 'success' : 'error');
  } catch (e) { toast(t('error'), 'error'); }
}

async function sendTestNotification() {
  try {
    const res = await apiFetch('/api/v1/notifications/test', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.error || `${t('error')} (HTTP ${res.status})`, 'error'); return; }
    toast(t('notifTestSent', data.auditId), 'success');
    // Delivery is asynchronous: give it a moment before showing the result.
    setTimeout(() => { if (currentSection === 'audit') renderAuditSection(); }, 1500);
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Utils ────────────────────────────────────────────

function copyText(text) { navigator.clipboard.writeText(text).then(() => toast(t('copied'), 'success')); }

/**
 * Toasts stack bottom-right (newest last). `type`: success | error | info |
 * warning. Success toasts are dropped right after a "waiting for approval"
 * notice — see notePendingApproval().
 */
function toast(msg, type = 'success', ms = 3000) {
  if (type === 'success' && Date.now() < _pendingNoticeUntil) return;
  let stack = document.getElementById('toast-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'toast-stack';
    stack.className = 'toast-stack';
    document.body.appendChild(stack);
  }
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  stack.appendChild(el);
  // Never let a burst of notices bury the page: keep the newest five.
  while (stack.children.length > 5) stack.firstElementChild.remove();
  setTimeout(() => el.remove(), ms);
}

// ── Vault Files — scoped to a Config API ────────────
//
// V2: every vault file belongs to one Config API. The UI lives inside the
// Config API detail page as a "Vault" tab; there is no longer a global
// "Vault Files" sidebar entry. All HTTP endpoints are scope-aware:
//   /api/v1/config-apis/{configApiId}/vault/...

// Status filter state for distribution history (null = all)
window.__vaultStatusFilter = window.__vaultStatusFilter || null;
function setVaultStatusFilter(apiId, f) {
  window.__vaultStatusFilter = (window.__vaultStatusFilter === f) ? null : f;
  setConfigApiTab('vault', apiId);
}

/** Render the "Vault" tab inside a Config API detail page. */
async function renderApiVaultTab(apiId) {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

  // V2: all vault admin paths live under /api/v1/config-apis/{id}/vault/...
  const base = `/api/v1/config-apis/${encodeURIComponent(apiId)}/vault`;

  try {
    const [filesRes, statsRes, distRes] = await Promise.all([
      apiFetch(base),
      apiFetch(`${base}/stats`),
      apiFetch(`${base}/distributions`)
    ]);
    // Defansif: 401/403 dönerse response bir error object olur; array beklendiği için .map() patlar.
    if (!filesRes.ok || !distRes.ok) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('vaultAuthError', filesRes.status)}</div></div>`;
      return;
    }
    const files = await filesRes.json();
    const stats = await statsRes.json();
    const dists = await distRes.json();
    if (!Array.isArray(files) || !Array.isArray(dists)) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('vaultUnexpectedResponse', JSON.stringify(files).slice(0, 120))}</div></div>`;
      return;
    }

    const filesPagKey = 'vault-files-' + apiId;
    const filesPagInfo = pagSlice(files, filesPagKey);
    const fileRows = files.length === 0
      ? `<tr><td colspan="6" class="empty-msg">${t('vaultNoFiles')}</td></tr>`
      : filesPagInfo.slice.map((f, i) => {
          const policyColor =
              f.access_policy === 'public'     ? '#f59e0b' :
              f.access_policy === 'api_key'    ? '#8b5cf6' :
              f.access_policy === 'token_mtls' ? '#06b6d4' : '#22c55e';
          const encIcon =
              f.encryption === 'end_to_end' ? '🔒' :
              f.encryption === 'at_rest'    ? '🔐' : '·';
          return `<tr class="${filesPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}" style="cursor:pointer" data-action="showVaultFileDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(f.key)}">
            <td style="font-weight:700;color:#7dd3fc">${esc(f.key)}</td>
            <td>v${f.version}</td>
            <td>${formatBytes(f.size || 0)}</td>
            <td><span style="background:${policyColor};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px">${f.access_policy || 'token'}</span></td>
            <td style="font-size:12px">${encIcon} ${f.encryption || 'plain'}</td>
            <td><span style="cursor:pointer;color:#ef4444;font-size:11px" data-action="deleteVaultFile" data-arg0="${esc(apiId)}" data-arg1="${esc(f.key)}" data-stop="1">&#x2715;</span></td>
          </tr>`;
        }).join('');
    const filesPagNav = filesPagInfo ? pagControls(filesPagKey, filesPagInfo, '_reloadVaultTab_' + apiId.replace(/[^a-zA-Z0-9]/g,'_')) : '';

    // Apply status filter (if active) and show up to 200 rows.
    const activeFilter = window.__vaultStatusFilter;
    const filteredDists = activeFilter
      ? dists.filter(d => activeFilter === 'failed'
          ? d.status === 'failed'
          : (d.status === 'downloaded' || d.status === 'cached'))
      : dists;

    const distPagKey = 'vault-dist-' + apiId + (activeFilter || '');
    const distPagInfo = pagSlice(filteredDists, distPagKey);
    const distRows = filteredDists.length === 0
      ? `<tr><td colspan="8" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : distPagInfo.slice.map((d, i) => {
          const ok = d.status === 'downloaded' || d.status === 'cached';
          const _ss = vaultStatusStyle(d.status);
          const statusIcon = _ss.icon;
          const statusColor = _ss.color;
          const device = d.deviceManufacturer ? `📱 ${esc(d.deviceManufacturer)} ${esc(d.deviceModel || '')}` : esc(d.deviceId);
          // Başarısızlık nedeni — HTTP kodu, decrypt fail, network, vs. Uzun
          // string'lere title attribute'le tooltip olarak tam hali verilir.
          const reasonCell = d.failureReason
              ? `<span style="color:#f87171;font-family:monospace;font-size:11px" title="${esc((d.failureReason+'').slice(0,300))}">${esc((d.failureReason+'').slice(0,80))}${(d.failureReason+'').length > 80 ? '…' : ''}</span>`
              : (ok ? '<span style="color:#475569">—</span>' : '<span style="color:#64748b;font-style:italic">reason yok</span>');
          // Auth method rozeti: cihazın hangi yetkilendirmeyle fetch ettiği.
          const authIcon = d.authMethod === 'public' ? '⚡' : d.authMethod === 'token' ? '🔒' : d.authMethod === 'token_mtls' ? '🔐' : d.authMethod === 'api_key' ? '🔑' : '—';
          const authColor = d.authMethod === 'public' ? '#f59e0b' : d.authMethod === 'token' ? '#22c55e' : d.authMethod === 'token_mtls' ? '#06b6d4' : d.authMethod === 'api_key' ? '#8b5cf6' : '#475569';
          const authCell = d.authMethod
              ? `<span style="background:${authColor};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600" title="${esc(d.authMethod)}">${authIcon} ${esc(d.authMethod)}</span>`
              : '<span style="color:#475569">—</span>';
          return `<tr class="${distPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
            <td style="font-weight:600;color:#7dd3fc;cursor:pointer" data-action="showVaultFileDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(d.vaultKey)}">${esc(d.vaultKey)}</td>
            <td>v${d.version}</td>
            <td><span class="source-badge android-src" style="cursor:pointer" data-action="showDeviceDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(d.deviceId)}">${device}</span></td>
            <td style="color:${statusColor};font-weight:600">${statusIcon} ${esc(d.status)}</td>
            <td>${authCell}</td>
            <td>${reasonCell}</td>
            <td style="color:#64748b;font-size:11px">${esc(d.enrollmentLabel) || '—'}</td>
            <td style="color:#64748b;font-size:11px">${new Date(d.timestamp).toLocaleString(locale)}</td>
          </tr>`;
        }).join('');
    // Sayfa değişince tüm tab'ı yeniden render etmek yerine bu konumu yeniden
    // çağır — aktif filter + apiId state zaten scope dışında tutuluyor.
    window['_reloadVaultTab_' + apiId.replace(/[^a-zA-Z0-9]/g,'_')] = () => setConfigApiTab('vault', apiId);
    const distPagNav = distPagInfo ? pagControls(distPagKey, distPagInfo, '_reloadVaultTab_' + apiId.replace(/[^a-zA-Z0-9]/g,'_')) : '';

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main">${t('vaultTitle')}</div>
          <div class="section-sub">${t('vaultSub')}</div>
        </div>
        <span style="cursor:pointer;color:#60a5fa;font-size:18px" data-action="setConfigApiTab" data-arg0="vault" data-arg1="${esc(apiId)}">&#x21bb;</span>
      </div>

      <div class="stats">
        <div class="card"><div class="stat-value" style="color:#60a5fa">${files.length}</div><div class="stat-label">${t('vaultUniqueKeys')}</div></div>
        <div class="card"><div class="stat-value" style="color:#f59e0b">${stats.uniqueDevices || 0}</div><div class="stat-label">${t('vaultUniqueDevices')}</div></div>
        <div class="card" style="cursor:pointer;${activeFilter === 'downloaded' ? 'outline:2px solid #22c55e;' : ''}" data-action="setVaultStatusFilter" data-arg0="${esc(apiId)}" data-arg1="downloaded" title="${t('vaultSucceeded')}">
          <div class="stat-value" style="color:#22c55e">${(stats.totalDistributions || 0) - (stats.failed || 0)}</div>
          <div class="stat-label">${t('vaultSucceeded')}</div>
        </div>
        <div class="card" style="cursor:pointer;${activeFilter === 'failed' ? 'outline:2px solid #ef4444;' : ''}" data-action="setVaultStatusFilter" data-arg0="${esc(apiId)}" data-arg1="failed" title="${t('vaultFailed')}">
          <div class="stat-value" style="color:#ef4444">${stats.failed || 0}</div>
          <div class="stat-label">${t('vaultFailed')}</div>
        </div>
      </div>

      <div class="card">
        <div class="card-title" style="margin:0 0 12px 0">${t('vaultUploadTitle')}</div>
        <div style="display:flex;gap:6px;margin-bottom:14px">
          <button type="button" class="btn btn-primary" id="vault-tab-file" style="padding:5px 16px;font-size:12px" data-action="setVaultUploadMode" data-arg0="file">${t('vaultUploadFileLabel')}</button>
          <button type="button" class="btn btn-secondary" id="vault-tab-text" style="padding:5px 16px;font-size:12px" data-action="setVaultUploadMode" data-arg0="text">${t('vaultUploadTextLabel')}</button>
        </div>
        <form data-action-submit="uploadVaultFile" data-arg0="${esc(apiId)}">
          <div class="form-group" id="vault-text-group" style="margin:0 0 12px 0;display:none">
            <label class="form-label">${t('vaultUploadTextLabel')}</label>
            <textarea id="vault-upload-text" rows="3" placeholder="${t('vaultUploadTextPlaceholder')}" class="form-input" style="width:100%;resize:vertical;font-family:inherit"></textarea>
          </div>
          <div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap">
            <div class="form-group" style="margin:0">
              <label class="form-label">${t('vaultKey')}</label>
              <input type="text" id="vault-upload-key" placeholder="${t('vaultKeyPlaceholder')}" required class="form-input" style="width:180px"/>
            </div>
            <div class="form-group" id="vault-file-group" style="margin:0">
              <label class="form-label">${t('vaultUploadFileLabel')}</label>
              <input type="file" id="vault-upload-file" style="color:#94a3b8;font-size:12px"/>
            </div>
            <div class="form-group" style="margin:0">
              <label class="form-label">${t('policyLabel')}</label>
              <select id="vault-upload-policy" class="form-input" style="width:150px">
                <option value="token" selected>${t('policyTokenOpt')}</option>
                <option value="token_mtls">${t('policyTokenMtlsOpt')}</option>
                <option value="public">${t('policyPublicOpt')}</option>
                <option value="api_key">${t('policyApiKeyOpt')}</option>
              </select>
              <!-- api_key cihazdan kullanılamaz; operatör seçmeden önce görsün. -->
              <div id="vault-upload-policy-warn" style="color:#f59e0b;font-size:11px;max-width:340px;margin-top:4px">${t('policyApiKeyWarn')}</div>
            </div>
            <div class="form-group" style="margin:0">
              <label class="form-label">${t('encryptionLabel')}</label>
              <select id="vault-upload-encryption" class="form-input" style="width:130px" data-action-change="updateEncDesc" data-event="1">
                <option value="plain" selected>plain</option>
                <option value="at_rest">at_rest</option>
                <option value="end_to_end">end_to_end</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary">${t('vaultUploadBtn')}</button>
          </div>
          <div id="vault-enc-desc" style="margin-top:10px;color:#94a3b8;font-size:12px;line-height:1.4">${t('encDescPlain')}</div>
        </form>
      </div>

      <div class="card">
        <div class="card-title">${t('vaultUniqueKeys')} (${files.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('vaultKey')}</th><th>${t('vaultVersion')}</th><th>${t('vaultSize')}</th><th>Policy</th><th>Encryption</th><th></th></tr></thead>
          <tbody>${fileRows}</tbody>
        </table>${filesPagNav}
      </div>

      <div class="card">
        <div class="card-title" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <span>${t('vaultDistTitle')} (${filteredDists.length}${activeFilter ? ` / ${dists.length}` : ''})</span>
          ${activeFilter ? `<span style="background:${activeFilter === 'failed' ? '#ef4444' : '#22c55e'};color:#fff;padding:2px 10px;border-radius:12px;font-size:11px;cursor:pointer" data-action="setVaultStatusFilter" data-arg0="${esc(apiId)}" data-arg1="${esc(activeFilter)}" title="${t('filterRemove')}">${activeFilter === 'failed' ? '✗ ' + t('vaultFailed') : '✓ ' + t('vaultSucceeded')} ✕</span>` : ''}
        </div>
        <table class="data-table">
          <thead><tr><th>${t('vaultKey')}</th><th>${t('vaultVersion')}</th><th>${t('vaultDevice')}</th><th>${t('vaultStatus')}</th><th>${t('thAuth')}</th><th>${t('vaultReason')}</th><th>${t('vaultLabel')}</th><th>${t('vaultTimestamp')}</th></tr></thead>
          <tbody>${distRows}</tbody>
        </table>${distPagNav}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${e.message}</div></div>`;
  }
}

/** Shared URL builder for scoped vault admin endpoints. */
function vaultBase(apiId) {
  return `/api/v1/config-apis/${encodeURIComponent(apiId)}/vault`;
}

async function uploadVaultFile(e, apiId) {
  e.preventDefault();
  const key = document.getElementById('vault-upload-key').value.trim();
  const file = document.getElementById('vault-upload-file').files[0];
  const text = document.getElementById('vault-upload-text')?.value || '';
  const policy = document.getElementById('vault-upload-policy')?.value || 'token';
  const encryption = document.getElementById('vault-upload-encryption')?.value || 'plain';
  if (!key) return;

  // Content comes from EITHER an uploaded file OR the typed text (file wins).
  // Text is sent as UTF-8 octet-stream so the server stores identical bytes.
  let body;
  if (file) {
    body = await file.arrayBuffer();
  } else if (text.trim() !== '') {
    body = new TextEncoder().encode(text);
  } else {
    toast(t('vaultUploadNeedContent'), 'error');
    return;
  }

  try {
    const qs = `?policy=${encodeURIComponent(policy)}&encryption=${encodeURIComponent(encryption)}`;
    const res = await apiFetch(`${vaultBase(apiId)}/${encodeURIComponent(key)}${qs}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body
    });
    if (!res.ok) { toast(t('error'), 'error'); return; }
    const data = await res.json();
    toast(t('vaultUploadSuccess', key, data.version, data.access_policy, data.encryption), 'success');
    setConfigApiTab('vault', apiId);
  } catch (err) { toast(t('error'), 'error'); }
}

/**
 * V2: Generate a per-device token for the given file. Plaintext is
 * returned ONCE; the server stores only SHA-256.
 */
async function generateVaultToken(apiId, key) {
  const deviceInput = document.getElementById(`tk-device-${key}`);
  const deviceId = (deviceInput?.value || '').trim();
  if (!deviceId) { toast(t('tokenDeviceIdRequired'), 'error'); return; }
  try {
    const res = await apiFetch(`${vaultBase(apiId)}/${encodeURIComponent(key)}/tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ deviceId })
    });
    if (!res.ok) { toast(t('tokenGenError'), 'error'); return; }
    const data = await res.json();
    navigator.clipboard?.writeText(data.token).catch(() => {});
    alert(t('tokenGeneratedAlert', data.token));
    if (deviceInput) deviceInput.value = '';
    showVaultFileDetail(apiId, key);
  } catch (err) { toast(err.message, 'error'); }
}

/**
 * Dosya içeriğine dokunmadan erişim politikasını ve şifreleme modunu
 * değiştirir. Kaydedince hem detay hem de vault listesi tazelenir, böylece
 * listedeki rozet anında güncellenir.
 */
async function saveVaultFilePolicy(apiId, key) {
  const policy = document.getElementById(`policy-edit-${key}`)?.value;
  const encryption = document.getElementById(`encryption-edit-${key}`)?.value;
  if (!policy || !encryption) return;
  try {
    const res = await apiFetch(`${vaultBase(apiId)}/${encodeURIComponent(key)}/policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_policy: policy, encryption })
    });
    if (!res.ok) { toast(t('policySaveError'), 'error'); return; }
    toast(t('policySaved', `${policy} / ${encryption}`), 'success');
    showVaultFileDetail(apiId, key);
  } catch (err) { toast(err.message, 'error'); }
}

async function revokeVaultToken(apiId, tokenId, keyForRefresh) {
  if (!confirm(t('tokenRevokeConfirm'))) return;
  try {
    const res = await apiFetch(`${vaultBase(apiId)}/tokens/${tokenId}`, { method: 'DELETE' });
    if (!res.ok) { toast(t('tokenRevokeError'), 'error'); return; }
    toast(t('tokenRevoked'), 'success');
    showVaultFileDetail(apiId, keyForRefresh);
  } catch (err) { toast(err.message, 'error'); }
}

async function deleteVaultFile(apiId, key) {
  if (!confirm(t('deleteFileConfirm', key))) return;
  try {
    await apiFetch(`${vaultBase(apiId)}/${encodeURIComponent(key)}`, { method: 'DELETE' });
    toast(t('fileDeleted', key), 'success');
    setConfigApiTab('vault', apiId);
  } catch (err) { toast(t('error'), 'error'); }
}

async function showVaultFileDetail(apiId, key) {
  const content = document.getElementById('content');
  const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;

  try {
    // Parallel fetch: distribution history + token list + dosya listesi.
    // Dosya listesi, bu anahtarın güncel access_policy / encryption değerini
    // öğrenmek için gerekiyor (ayrı bir "tek dosya" ucu yok).
    const base = vaultBase(apiId);
    const [distRes, tokensRes, filesRes] = await Promise.all([
      apiFetch(`${base}/distributions/${encodeURIComponent(key)}`),
      apiFetch(`${base}/${encodeURIComponent(key)}/tokens`),
      apiFetch(base)
    ]);
    const dists = await distRes.json();
    const tokens = tokensRes.ok ? await tokensRes.json() : [];
    const allFiles = filesRes.ok ? await filesRes.json() : [];
    const entry = (Array.isArray(allFiles) ? allFiles : []).find(f => f.key === key) || {};
    const curPolicy = entry.access_policy || 'token';
    const curEncryption = entry.encryption || 'plain';

    // Version timeline: group by version → first seen, last seen, ok/failed counts
    const byVer = {};
    for (const d of dists) {
      const v = d.version;
      if (!byVer[v]) byVer[v] = { version: v, first: d.timestamp, last: d.timestamp, ok: 0, failed: 0, devices: new Set() };
      const b = byVer[v];
      if (d.timestamp < b.first) b.first = d.timestamp;
      if (d.timestamp > b.last) b.last = d.timestamp;
      if (d.status === 'downloaded' || d.status === 'cached') b.ok++; else b.failed++;
      b.devices.add(d.deviceId);
    }
    const versions = Object.values(byVer).sort((a, b) => b.version - a.version);

    // Device summary: per deviceId → count, last version, last timestamp, ok/failed
    const byDev = {};
    for (const d of dists) {
      const id = d.deviceId;
      if (!byDev[id]) byDev[id] = { deviceId: id, deviceLabel: d.deviceManufacturer ? `${d.deviceManufacturer} ${d.deviceModel || ''}`.trim() : id, enrollmentLabel: d.enrollmentLabel, count: 0, ok: 0, failed: 0, lastVersion: d.version, lastTimestamp: d.timestamp };
      const b = byDev[id];
      b.count++;
      if (d.status === 'downloaded' || d.status === 'cached') b.ok++; else b.failed++;
      if (d.timestamp > b.lastTimestamp) { b.lastTimestamp = d.timestamp; b.lastVersion = d.version; }
    }
    const devices = Object.values(byDev).sort((a, b) => b.count - a.count);

    const verRows = versions.length === 0
      ? `<tr><td colspan="5" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : versions.map((v, i) => `<tr class="${i === 0 ? 'row-latest' : ''}">
          <td style="font-weight:700;color:#a78bfa">v${v.version}</td>
          <td>${v.devices.size}</td>
          <td style="color:#22c55e;font-weight:600">✓ ${v.ok}</td>
          <td style="color:${v.failed > 0 ? '#ef4444' : '#64748b'};font-weight:600">✗ ${v.failed}</td>
          <td style="color:#64748b;font-size:11px">${new Date(v.last).toLocaleString(locale)}</td>
        </tr>`).join('');

    const devRows = devices.length === 0
      ? `<tr><td colspan="5" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : devices.map((d, i) => `<tr class="${i === 0 ? 'row-latest' : ''}" style="cursor:pointer" data-action="showDeviceDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(d.deviceId)}">
          <td><span class="source-badge android-src">📱 ${esc(d.deviceLabel)}</span></td>
          <td>${d.count}</td>
          <td style="color:#22c55e">✓ ${d.ok}</td>
          <td style="color:${d.failed > 0 ? '#ef4444' : '#64748b'}">✗ ${d.failed}</td>
          <td>v${d.lastVersion} <span style="color:#64748b;font-size:11px">· ${new Date(d.lastTimestamp).toLocaleString(locale)}</span></td>
        </tr>`).join('');

    const fullRows = dists.length === 0
      ? `<tr><td colspan="5" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : dists.map((d, i) => {
          const ok = d.status === 'downloaded' || d.status === 'cached';
          const device = d.deviceManufacturer ? `📱 ${esc(d.deviceManufacturer)} ${esc(d.deviceModel || '')}` : esc(d.deviceId);
          return `<tr class="${i === 0 ? 'row-latest' : ''}">
            <td><span class="source-badge android-src" style="cursor:pointer" data-action="showDeviceDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(d.deviceId)}">${device}</span></td>
            <td>v${d.version}</td>
            <td style="color:${vaultStatusStyle(d.status).color};font-weight:600">${vaultStatusStyle(d.status).icon} ${esc(d.status)}</td>
            <td style="color:#64748b;font-size:11px">${esc(d.enrollmentLabel) || '—'}</td>
            <td style="color:#64748b;font-size:11px">${new Date(d.timestamp).toLocaleString(locale)}</td>
          </tr>`;
        }).join('');

    // V2: token management rows. tokens[] returns SHA-256'd rows — plaintext
    // is only returned by POST /tokens (below) at generation time.
    const tokenRows = tokens.length === 0
      ? `<tr><td colspan="4" class="empty-msg">${t('tokenNoRows')}</td></tr>`
      : tokens.map((tk, i) => {
          const revokedColor = tk.revoked ? '#64748b' : '#22c55e';
          const revokedLabel = tk.revoked ? t('tokenStatusRevoked') : t('tokenStatusActive');
          const btn = tk.revoked
            ? `<span style="color:#64748b;font-size:11px">${t('tokenBtnDash')}</span>`
            : `<span style="cursor:pointer;color:#ef4444;font-size:11px" data-action="revokeVaultToken" data-arg0="${esc(apiId)}" data-arg1="${tk.id}" data-arg2="${esc(key)}">${t('tokenBtnRevoke')}</span>`;
          return `<tr class="${i === 0 ? 'row-latest' : ''}">
            <td style="font-family:monospace;color:#7dd3fc">${esc(tk.deviceId)}</td>
            <td style="color:${revokedColor};font-weight:600">${revokedLabel}</td>
            <td style="color:#64748b;font-size:11px">${new Date(tk.createdAt).toLocaleString(locale)}</td>
            <td>${btn}</td>
          </tr>`;
        }).join('');

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="color:#7dd3fc">${esc(key)}</div>
          <div class="section-sub">${t('vaultDistTitle')} — ${dists.length} · ${versions.length} versiyon · ${devices.length} cihaz</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" data-action="setConfigApiTab" data-arg0="vault" data-arg1="${esc(apiId)}">← ${t('back')}</button>
          <span style="cursor:pointer;color:#60a5fa;font-size:16px" data-action="showVaultFileDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(key)}">&#x21bb;</span>
        </div>
      </div>

      <!-- Erişim politikası / şifreleme düzenleme. Sunucuda
           PUT {base}/{key}/policy ucu vardı ama arayüzden erişilemiyordu:
           bir dosyanın politikası ancak yeniden yükleyerek değiştirilebiliyordu. -->
      <div class="card">
        <div class="card-title">${t('policyEditTitle')}</div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:10px">${t('policyEditHint')}</div>
        <div style="display:flex;gap:8px;align-items:end;flex-wrap:wrap">
          <div class="form-group" style="margin:0">
            <label class="form-label">${t('policyLabel')}</label>
            <select id="policy-edit-${esc(key)}" class="form-input" style="width:160px">
              <option value="token" ${curPolicy === 'token' ? 'selected' : ''}>${t('policyTokenOpt')}</option>
              <option value="token_mtls" ${curPolicy === 'token_mtls' ? 'selected' : ''}>${t('policyTokenMtlsOpt')}</option>
              <option value="public" ${curPolicy === 'public' ? 'selected' : ''}>${t('policyPublicOpt')}</option>
              <option value="api_key" ${curPolicy === 'api_key' ? 'selected' : ''}>${t('policyApiKeyOpt')}</option>
            </select>
          </div>
          <div class="form-group" style="margin:0">
            <label class="form-label">${t('encryptionLabel')}</label>
            <select id="encryption-edit-${esc(key)}" class="form-input" style="width:140px">
              <option value="plain" ${curEncryption === 'plain' ? 'selected' : ''}>plain</option>
              <option value="at_rest" ${curEncryption === 'at_rest' ? 'selected' : ''}>at_rest</option>
              <option value="end_to_end" ${curEncryption === 'end_to_end' ? 'selected' : ''}>end_to_end</option>
            </select>
          </div>
          <button class="btn btn-primary" data-action="saveVaultFilePolicy" data-arg0="${esc(apiId)}" data-arg1="${esc(key)}">${t('policySaveBtn')}</button>
          <span style="color:#64748b;font-size:11px">${t('policyCurrent')}: <b style="color:#7dd3fc">${esc(curPolicy)}</b> / <b style="color:#7dd3fc">${esc(curEncryption)}</b></span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">${t('vaultVersionTimeline')} (${versions.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('vaultVersion')}</th><th>${t('vaultDevice')}</th><th>${t('vaultSuccess')}</th><th>${t('vaultFailed')}</th><th>${t('vaultLastFetch')}</th></tr></thead>
          <tbody>${verRows}</tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-title">${t('vaultDeviceSummary')} (${devices.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('vaultDevice')}</th><th>${t('vaultFetchCount')}</th><th>${t('vaultSuccess')}</th><th>${t('vaultFailed')}</th><th>${t('vaultLastVersion')}</th></tr></thead>
          <tbody>${devRows}</tbody>
        </table>
      </div>

      <!-- V2: token management -->
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center;gap:8px">
          <span>${t('tokenMgmtTitle')} (${tokens.length})</span>
          <div style="display:flex;gap:6px;align-items:center">
            <input type="text" id="tk-device-${key}" placeholder="${t('tokenDevicePlaceholder')}" class="form-input" style="width:180px;font-size:12px"/>
            <button class="btn btn-primary" style="padding:4px 10px;font-size:12px" data-action="generateVaultToken" data-arg0="${esc(apiId)}" data-arg1="${esc(key)}">${t('tokenNewBtn')}</button>
          </div>
        </div>
        <div style="color:#94a3b8;font-size:11px;margin-bottom:8px">${t('tokenMgmtHint')}</div>
        <table class="data-table">
          <thead><tr><th>${t('tokenColDeviceId')}</th><th>${t('tokenColStatus')}</th><th>${t('tokenColCreated')}</th><th></th></tr></thead>
          <tbody>${tokenRows}</tbody>
        </table>
      </div>

      <div class="card">
        <div class="card-title">${t('vaultFullHistory')} (${dists.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('vaultDevice')}</th><th>${t('vaultVersion')}</th><th>${t('vaultStatus')}</th><th>${t('vaultLabel')}</th><th>${t('vaultTimestamp')}</th></tr></thead>
          <tbody>${fullRows}</tbody>
        </table>
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${e.message}</div></div>`;
  }
}

async function showDeviceDetail(apiId, deviceId) {
  const content = document.getElementById('content');
  const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;

  try {
    const res = await apiFetch(`${vaultBase(apiId)}/distributions/device/${encodeURIComponent(deviceId)}`);
    const dists = await res.json();
    if (!Array.isArray(dists)) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${JSON.stringify(dists).slice(0, 120)}</div></div>`;
      return;
    }

    const deviceLabel = esc(dists.length > 0 && dists[0].deviceManufacturer
      ? `${dists[0].deviceManufacturer} ${dists[0].deviceModel || ''}`.trim()
      : deviceId);
    const enrollmentLabel = esc(dists.length > 0 ? (dists[0].enrollmentLabel || '—') : '—');

    // Per-file summary
    const byKey = {};
    for (const d of dists) {
      const k = d.vaultKey;
      if (!byKey[k]) byKey[k] = { vaultKey: k, count: 0, ok: 0, failed: 0, lastVersion: d.version, lastTimestamp: d.timestamp, versions: new Set() };
      const b = byKey[k];
      b.count++;
      b.versions.add(d.version);
      if (d.status === 'downloaded' || d.status === 'cached') b.ok++; else b.failed++;
      if (d.timestamp > b.lastTimestamp) { b.lastTimestamp = d.timestamp; b.lastVersion = d.version; }
    }
    const files = Object.values(byKey).sort((a, b) => b.count - a.count);

    const devFilesPagKey = 'dev-files-' + apiId + '-' + deviceId;
    const devFilesPagInfo = pagSlice(files, devFilesPagKey);
    const fileRows = files.length === 0
      ? `<tr><td colspan="5" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : devFilesPagInfo.slice.map((f, i) => `<tr class="${devFilesPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}" style="cursor:pointer" data-action="showVaultFileDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(f.vaultKey)}">
          <td style="font-weight:600;color:#7dd3fc">${esc(f.vaultKey)}</td>
          <td>${f.count}</td>
          <td style="color:#22c55e">✓ ${f.ok}</td>
          <td style="color:${f.failed > 0 ? '#ef4444' : '#64748b'}">✗ ${f.failed}</td>
          <td>v${f.lastVersion} <span style="color:#64748b;font-size:11px">· ${new Date(f.lastTimestamp).toLocaleString(locale)}</span></td>
        </tr>`).join('');
    const devFullPagKey = 'dev-full-' + apiId + '-' + deviceId;
    const devFullPagInfo = pagSlice(dists, devFullPagKey);
    const fullRows = dists.length === 0
      ? `<tr><td colspan="4" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : devFullPagInfo.slice.map((d, i) => {
          const ok = d.status === 'downloaded' || d.status === 'cached';
          return `<tr class="${devFullPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
            <td style="font-weight:600;color:#7dd3fc;cursor:pointer" data-action="showVaultFileDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(d.vaultKey)}">${esc(d.vaultKey)}</td>
            <td>v${d.version}</td>
            <td style="color:${vaultStatusStyle(d.status).color};font-weight:600">${vaultStatusStyle(d.status).icon} ${esc(d.status)}</td>
            <td style="color:#64748b;font-size:11px">${new Date(d.timestamp).toLocaleString(locale)}</td>
          </tr>`;
        }).join('');
    const devReloadKey = '_reloadDeviceDetail_' + (apiId + '_' + deviceId).replace(/[^a-zA-Z0-9]/g,'_');
    window[devReloadKey] = () => showDeviceDetail(apiId, deviceId);
    const devFilesPagNav = devFilesPagInfo ? pagControls(devFilesPagKey, devFilesPagInfo, devReloadKey) : '';
    const devFullPagNav  = devFullPagInfo  ? pagControls(devFullPagKey,  devFullPagInfo,  devReloadKey) : '';

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="color:#7dd3fc">📱 ${deviceLabel}</div>
          <div class="section-sub">${esc(deviceId)} · ${enrollmentLabel} · ${dists.length} ${t('vaultFetchCount').toLowerCase()} · ${files.length} ${t('vaultUniqueKeys').toLowerCase()}</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" data-action="setConfigApiTab" data-arg0="vault" data-arg1="${esc(apiId)}">← ${t('back')}</button>
          <span style="cursor:pointer;color:#60a5fa;font-size:16px" data-action="showDeviceDetail" data-arg0="${esc(apiId)}" data-arg1="${esc(deviceId)}">&#x21bb;</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">${t('vaultFileSummary')} (${files.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('vaultKey')}</th><th>${t('vaultFetchCount')}</th><th>${t('vaultSuccess')}</th><th>${t('vaultFailed')}</th><th>${t('vaultLastVersion')}</th></tr></thead>
          <tbody>${fileRows}</tbody>
        </table>${devFilesPagNav}
      </div>

      <div class="card">
        <div class="card-title">${t('vaultFullHistory')} (${dists.length})</div>
        <table class="data-table">
          <thead><tr><th>${t('vaultKey')}</th><th>${t('vaultVersion')}</th><th>${t('vaultStatus')}</th><th>${t('vaultTimestamp')}</th></tr></thead>
          <tbody>${fullRows}</tbody>
        </table>${devFullPagNav}
      </div>`;
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('error')}: ${e.message}</div></div>`;
  }
}

// Distribution status badge: distinguish a fresh download from a 304 cache-hit.
function vaultStatusStyle(status) {
  if (status === 'cached')     return { icon: '💾', color: '#94a3b8' }; // served from local cache (304)
  if (status === 'downloaded') return { icon: '✓',  color: '#22c55e' }; // fresh download
  return { icon: '✗', color: '#ef4444' };                              // failed / unknown
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ── CSP-safe event delegation ────────────────────────
// Inline handlers (onclick=/onchange=/onsubmit=) violate `script-src 'self'`
// from the M-05 hardening pass. Buttons/inputs/forms use `data-action="<fn>"`
// + `data-arg0..argN` attributes instead. Optional flags on the element:
//   data-stop="1"   → event.stopPropagation() before dispatch
//   data-event="1"  → append the event object as the last argument
// Dispatch is via an explicit `_actionHandlers` table (not bare window lookup)
// so injected HTML can only invoke whitelisted functions.

// Wrappers for inline expressions that combined multiple statements.
/**
 * "+" düğmesi: kapsamı seçip "Yeni Host Ekle" formunu açar.
 *
 * `loadConfig()` şart. "Manuel" sekmesi yeni host'u `currentConfig.pins`
 * listesinin üstüne ekleyip TÜM listeyi seçili kapsama yazıyor; kapsam
 * değişmişken eski kapsamın pin'leri hedef kapsama taşınırdı.
 */
async function showAddHostScoped(apiId) {
  selectedApiId = apiId;
  await loadConfig();
  showAddHost();
}
function setConfigApiTab(tabId, apiId) { configApiTab = tabId; renderConfigApiDetail(apiId); }
function renderEmptyAndHostList() { renderEmpty(); renderHostList(); }
function clickFileInput(id) { document.getElementById(id).click(); }
function updateEditHash(idx, ev) { editHashes[parseInt(idx, 10)] = ev.target.value; }
function removeEditHashEdit(idx, hostname) { editHashes.splice(parseInt(idx, 10), 1); renderEditPins(hostname); }
function removeEditHashInline(idx, hostname) { editHashes.splice(parseInt(idx, 10), 1); renderInlineEditPins(hostname); }
function addEditHashEdit(hostname) { editHashes.push(''); renderEditPins(hostname); }
function addEditHashInline(hostname) { editHashes.push(''); renderInlineEditPins(hostname); }
function setVaultEnabledChange(apiId, ev) { setVaultEnabled(apiId, ev.target.checked); }
function pagSizeChange(key, onChangeGlobalFn, ev) { pagSize(key, ev.target.value, onChangeGlobalFn); }
function setVaultUploadMode(mode) {
  const isText = mode === 'text';
  const fileGroup = document.getElementById('vault-file-group');
  const textGroup = document.getElementById('vault-text-group');
  const fileInput = document.getElementById('vault-upload-file');
  const textInput = document.getElementById('vault-upload-text');
  if (fileGroup) fileGroup.style.display = isText ? 'none' : '';
  if (textGroup) textGroup.style.display = isText ? '' : 'none';
  // Clear the inactive input so a stale value can't be submitted by accident.
  if (isText && fileInput) fileInput.value = '';
  if (!isText && textInput) textInput.value = '';
  const fileBtn = document.getElementById('vault-tab-file');
  const textBtn = document.getElementById('vault-tab-text');
  if (fileBtn) fileBtn.className = 'btn ' + (isText ? 'btn-secondary' : 'btn-primary');
  if (textBtn) textBtn.className = 'btn ' + (isText ? 'btn-primary' : 'btn-secondary');
  if (isText && textInput) textInput.focus();
}
// Localized one-line description for the selected vault encryption mode.
function vaultEncDesc(v) {
  return v === 'at_rest' ? t('encDescAtRest')
    : v === 'end_to_end' ? t('encDescE2E')
    : t('encDescPlain');
}
function updateEncDesc(ev) {
  const el = document.getElementById('vault-enc-desc');
  if (el) el.textContent = vaultEncDesc(ev.target.value);
}

const _actionHandlers = {
  clearForceAll, copyText, createConfigApi, createHostFetch, createHostGenerate,
  createHostManual, createHostUpload,
  deleteConfigApi, deleteHost, deleteVaultFile, editDeviceAcl, fetchBootstrapFromUrl,
  forceUpdateAll, generateClientCert,
  generateEnrollmentToken, generateVaultToken, loadClientDevices, loadHostConnectionHistory,
  pagGo, pagSize, regenerateBootstrapCert, regenerateSigningKey, renderApiVaultTab,
  renderConfigApiDetail, renderEditPins, renderEmpty, renderHostList, renderInlineEditPins,
  renewCertAuto, renewCertUpload, revokeClientCert, revokeVaultToken, runHealthCheck,
  rotateBootstrapToBackup, rotateHostToBackup,
  saveDefaultAcl, saveInlinePins, savePins, saveVaultFilePolicy, selectHost,
  selectHostInApi, setLang,
  setVaultEnabled, setVaultStatusFilter, showAddConfigApi, showAddHost, showCertUploadForm,
  showDeviceAclManager, showDeviceDetail, showVaultFileDetail, switchAddTab,
  showSection,
  testHostConnection, toggleApiTree, toggleBootstrapFetch, toggleBootstrapUpload,
  toggleConfigApi,
  toggleEditPins, toggleForce, toggleHostMtls, toggleMock, uploadBootstrapCert,
  uploadClientCert, uploadHostClientCert, uploadVaultFile,
  showAddHostScoped, setConfigApiTab, renderEmptyAndHostList, clickFileInput,
  updateEditHash, removeEditHashEdit, removeEditHashInline, addEditHashEdit,
  addEditHashInline, setVaultEnabledChange, pagSizeChange, setVaultUploadMode, updateEncDesc,
  // Governance (identity, approvals, audit log, live check, signing keys)
  switchAdminKey, setApprovalsTab, refreshApprovals, toggleChangeDetail, approveChange, rejectChange,
  setAuditActionFilter, toggleAuditDetail, verifyAuditChain, sendTestNotification, refreshAudit,
  uploadKeyset, liveCheckPins
};

function _collectArgs(el) {
  const args = [];
  let i = 0;
  while (el.dataset['arg' + i] !== undefined) {
    args.push(el.dataset['arg' + i]);
    i++;
  }
  return args;
}

function _resolveHandler(name) {
  const fn = _actionHandlers[name];
  if (typeof fn !== 'function') { console.warn('Unknown action:', name); return null; }
  return fn;
}

// click: optional event as LAST arg when data-event="1"
document.body.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  if (el.dataset.stop === '1') e.stopPropagation();
  const fn = _resolveHandler(el.dataset.action);
  if (!fn) return;
  beginUserAction();
  const args = _collectArgs(el);
  if (el.dataset.event === '1') args.push(e);
  fn.apply(null, args);
});

// change: event as LAST arg when data-event="1" (input handlers commonly need this.value/checked)
document.body.addEventListener('change', (e) => {
  const el = e.target.closest('[data-action-change]');
  if (!el) return;
  const fn = _resolveHandler(el.dataset.actionChange);
  if (!fn) return;
  beginUserAction();
  const args = _collectArgs(el);
  if (el.dataset.event === '1') args.push(e);
  fn.apply(null, args);
});

// submit: form handlers always receive event as the FIRST arg
// (they call e.preventDefault() internally and read inputs from the DOM)
document.body.addEventListener('submit', (e) => {
  const el = e.target.closest('[data-action-submit]');
  if (!el) return;
  const fn = _resolveHandler(el.dataset.actionSubmit);
  if (!fn) return;
  beginUserAction();
  fn.apply(null, [e].concat(_collectArgs(el)));
});

// ── Start ────────────────────────────────────────────
init();
