let currentConfig = null;
let allApiConfigs = []; // [{id, port, mode, hosts, version}]
let selectedHost = null;
let selectedApiId = null;
let currentSection = null;

// ── API Key Authentication ──────────────────────────
function getApiKey() { return localStorage.getItem('pinvault_api_key') || ''; }
function setApiKey(key) { localStorage.setItem('pinvault_api_key', key); }

// Authenticated fetch wrapper — adds X-API-Key header
async function apiFetch(url, options = {}) {
    const key = getApiKey();
    if (key) {
        options.headers = { ...options.headers, 'X-API-Key': key };
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
    const resp = await fetch(url, options);
    if (resp.status === 401 || resp.status === 403) {
        const newKey = prompt('API Key gerekli (X-API-Key):');
        if (newKey) {
            setApiKey(newKey);
            options.headers = { ...options.headers, 'X-API-Key': newKey };
            return fetch(url, options);
        }
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
    vaultKeyPlaceholder: 'feature-flags', vaultFilePlaceholder: 'Dosya seçin',
    vaultDistTitle: 'Dağıtım Geçmişi', vaultNoDistHistory: 'Dağıtım kaydı yok', vaultReason: 'Neden',
    vaultStats: 'İstatistikler', vaultTotalDist: 'Toplam Dağıtım',
    vaultUniqueDevices: 'Cihaz', vaultUniqueKeys: 'Dosya', vaultDownloaded: 'İndirilen',
    vaultFailed: 'Başarısız', vaultDevice: 'Cihaz', vaultStatus: 'Durum',
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
    vaultDisabledHint: 'Vault aktif değilken dosya endpoint\'leri 404 döner (enforce edilmez ancak admin izleme için).',
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
    vaultKeyPlaceholder: 'feature-flags', vaultFilePlaceholder: 'Choose file',
    vaultDistTitle: 'Distribution History', vaultNoDistHistory: 'No distribution records', vaultReason: 'Reason',
    vaultStats: 'Statistics', vaultTotalDist: 'Total Distributions',
    vaultUniqueDevices: 'Devices', vaultUniqueKeys: 'Files', vaultDownloaded: 'Downloaded',
    vaultFailed: 'Failed', vaultDevice: 'Device', vaultStatus: 'Status',
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
    vaultDisabledHint: 'When vault is disabled, file endpoints return 404 (not enforced, admin tracking only).',
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
}

// ── Init ─────────────────────────────────────────────

async function init() {
  updateLangUI();
  await loadConfig();
  renderHostList();
  renderEmpty();
}

async function loadConfig() {
  try {
    // Tüm API'lerin özetini al
    const apisRes = await apiFetch('/api/v1/all-configs');
    allApiConfigs = await apisRes.json();

    // Varsayılan API'nin config'ini yükle (management server üzerinden)
    const res = await apiFetch('/api/v1/certificate-config?signed=false');
    currentConfig = await res.json();
    console.log('Config loaded:', currentConfig, 'APIs:', allApiConfigs);
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
  const btn = (label, enabled, newPage) => enabled
    ? `<button class="btn" style="padding:2px 8px;font-size:11px" onclick="pagGo('${key}',${newPage},${onChangeGlobalFn ? `'${onChangeGlobalFn}'` : 'null'})">${label}</button>`
    : `<button class="btn" style="padding:2px 8px;font-size:11px;opacity:.35;cursor:not-allowed" disabled>${label}</button>`;
  const sizeOpts = [10, 25, 50, 100].map(s => `<option value="${s}" ${s === info.size ? 'selected' : ''}>${s}</option>`).join('');
  const shownStart = info.total === 0 ? 0 : info.page * info.size + 1;
  const shownEnd = Math.min(info.total, (info.page + 1) * info.size);
  return `<div style="display:flex;gap:8px;align-items:center;padding:6px 0;font-size:11px;color:#94a3b8;justify-content:flex-end">
    <span>${shownStart}-${shownEnd} / ${info.total}</span>
    <select onchange="pagSize('${key}',this.value,${onChangeGlobalFn ? `'${onChangeGlobalFn}'` : 'null'})" style="background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:4px;padding:2px 4px;font-size:11px">${sizeOpts}</select>
    ${btn('«', prev, 0)}
    ${btn('‹', prev, info.page - 1)}
    <span>${info.page + 1} / ${info.pageCount}</span>
    ${btn('›', next, info.page + 1)}
    ${btn('»', next, info.pageCount - 1)}
  </div>`;
}

function pagGo(key, page, onChangeGlobalFn) {
  const st = _pagState[key] || (_pagState[key] = { page: 0, size: PAG_DEFAULT_SIZE });
  st.page = page;
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
      <div class="api-header" style="padding:6px 10px;font-size:11px;font-weight:700;color:${modeColor};cursor:pointer;${apiBg};display:flex;justify-content:space-between;align-items:center;user-select:none;${!isRunning ? 'opacity:0.6;' : ''}" onclick="toggleApiTree('${api.id}')">
        <span style="display:flex;align-items:center;gap:6px">
          <span style="font-size:9px;color:#64748b">${arrow}</span>
          <span>${modeLabel} :${api.port}${stoppedBadge}</span>
          <span style="color:#475569;font-weight:400;font-size:10px">(${hostCount})</span>
        </span>
        ${isRunning ? `<span style="font-size:16px;color:#60a5fa;cursor:pointer;line-height:1" onclick="event.stopPropagation();selectedApiId='${api.id}';showAddHost()" title="Host ekle">+</span>` : ''}
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
            <div class="host-item ${isSelected ? 'selected' : ''}" style="margin-left:20px" onclick="selectHostInApi('${p.hostname}', '${api.id}')">
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
    `<button class="tab-btn ${configApiTab === tab.id ? 'active' : ''}" onclick="configApiTab='${tab.id}';renderConfigApiDetail('${apiId}')">${tab.label}</button>`
  ).join('');

  const isRunning = api.running !== false;
  const toggleHtml = `
    <div style="display:flex;align-items:center;gap:10px">
      <div style="cursor:pointer;display:flex;align-items:center;gap:10px" onclick="toggleConfigApi('${apiId}')">
        <div style="width:40px;height:22px;border-radius:11px;background:${isRunning ? '#22c55e' : '#334155'};position:relative;transition:background 0.2s">
          <div style="width:18px;height:18px;border-radius:50%;background:white;position:absolute;top:2px;${isRunning ? 'right:2px' : 'left:2px'};transition:all 0.2s"></div>
        </div>
        <span style="color:${isRunning ? '#22c55e' : '#64748b'};font-weight:700;font-size:13px">${isRunning ? 'Çalışıyor' : 'Durduruldu'}</span>
      </div>
      ${!isRunning ? `
        <input id="capi-port-${apiId}" class="form-input" style="width:80px;padding:4px 8px;font-size:12px" value="${api.port}" placeholder="Port">
      ` : ''}
    </div>`;

  document.getElementById('content').innerHTML = `
    <div class="section-header">
      <div>
        <div class="section-title-main" style="display:flex;align-items:center;gap:8px">
          <span style="color:${modeColor};font-weight:700">${api.mode.toUpperCase()}</span>
          :${api.port}
          <span style="color:#64748b;font-size:14px;font-weight:400">${api.id}</span>
        </div>
        <div class="section-sub" style="display:flex;align-items:center;gap:12px">
          <span>${api.pins?.length || 0} host · v${api.version}</span>
          ${toggleHtml}
        </div>
      </div>
      <div class="action-bar">
        <button class="btn btn-danger" onclick="deleteConfigApi('${apiId}')">API Sil</button>
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
            <span style="color:#64748b;font-size:14px;font-weight:400">${api.id}</span>
          </div>
          <div style="margin-top:4px">${toggleHtml}</div>
        </div>
        <div class="action-bar">
          <button class="btn btn-danger" onclick="deleteConfigApi('${apiId}')">API Sil</button>
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
      <div class="card-title">Sunucu Bilgisi</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;color:#94a3b8;font-size:13px">
        <div>Port: <span style="color:#7dd3fc;font-weight:600">:${api.port}</span></div>
        <div>Mod: <span style="color:${api.mode === 'mtls' ? '#f59e0b' : '#22c55e'};font-weight:600">${api.mode.toUpperCase()}</span></div>
        <div>Host sayısı: <span style="color:#7dd3fc;font-weight:600">${api.pins?.length || 0}</span></div>
        <div>Versiyon: <span style="color:#7dd3fc;font-weight:600">v${api.version}</span></div>
      </div>
    </div>
    <!-- V2 Vault toggle + Device ACL shortcut -->
    <div class="card">
      <div class="card-title">${t('vaultV2Section')}</div>
      <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:#e2e8f0">
          <input type="checkbox" id="vault-enabled-${apiId}" ${vaultEnabled ? 'checked' : ''}
                 onchange="setVaultEnabled('${apiId}', this.checked)"/>
          <span>${t('vaultEnabledLabel')}</span>
        </label>
        <button class="btn btn-secondary" style="padding:4px 10px;font-size:12px"
                onclick="showDeviceAclManager('${apiId}')">${t('manageDeviceAcl')}</button>
        <span style="color:#64748b;font-size:11px">${t('vaultDisabledHint')}</span>
      </div>
    </div>
    <div class="card">
      <div class="card-title">${t('hosts')}</div>
      <table class="data-table">
        <thead><tr><th>Hostname</th><th>Versiyon</th><th>Pin</th><th>Force</th></tr></thead>
        <tbody>${hostRows}</tbody>
      </table>${hostsPagNav}
    </div>`;
}

async function setVaultEnabled(apiId, enabled) {
  try {
    const res = await apiFetch(`/api/v1/config-apis/${encodeURIComponent(apiId)}/vault-enabled`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    if (!res.ok) { toast(t('vaultToggleError'), 'error'); return; }
    toast(`${enabled ? t('vaultEnabledOn') : t('vaultEnabledOff')} — ${apiId}`, 'success');
  } catch (err) { toast(err.message, 'error'); }
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
                onclick="editDeviceAcl('${configApiId}','${d.device_id || d.deviceId}')">${t('aclEditBtn')}</button></td>
          </tr>`;
        }).join('');

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="color:#7dd3fc">${t('aclManagerTitle')} — ${configApiId}</div>
          <div class="section-sub">${t('aclManagerSub')}</div>
        </div>
        <button class="btn btn-secondary" onclick="renderConfigApiDetail('${configApiId}')">${t('aclBack')}</button>
      </div>

      <div class="card">
        <div class="card-title">${t('defaultAclTitle')}</div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:8px">${t('defaultAclHint')}</div>
        <div style="display:flex;gap:8px;align-items:center">
          <input type="text" id="default-acl-input" class="form-input" style="flex:1"
                 placeholder="${t('defaultAclPlaceholder')}"
                 value="${defaultStr.replace(/"/g, '&quot;')}"/>
          <button class="btn btn-primary" onclick="saveDefaultAcl('${configApiId}')">${t('aclSave')}</button>
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
      <button class="copy-btn" onclick="copyText('${hash}')">${t('copy')}</button>
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
        <button class="btn btn-danger" onclick="deleteHost('${host.hostname}')">${t('deleteHost')}</button>
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
      <div class="card" style="cursor:pointer" onclick="toggleForce('${host.hostname}')">
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
        <button class="btn btn-primary" style="padding:4px 12px;font-size:11px" onclick="toggleEditPins('${host.hostname}')">${t('editPins')}</button>
      </div>
      <div id="pins-view">${pinsHtml}</div>
      <div id="pins-edit" style="display:none"></div>
    </div>

    <div class="card" id="host-client-cert-card">
      <div class="card-title">Client Cert (mTLS)</div>
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
          <button class="btn btn-primary" style="padding:4px 12px;font-size:11px" onclick="testHostConnection('${host.hostname}')">${t('testConnection')}</button>
          <span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${host.hostname}')" title="Yenile">&#x21bb;</span>
        </div>
      </div>
      <div class="loading">${t('loading')}</div>
    </div>

    <div class="card" id="client-devices-card">
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connectedClients')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadClientDevices('${host.hostname}')" title="Yenile">&#x21bb;</span></div>
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
        <td><span class="ver-badge" style="${latest ? 'background:#1d4ed8;color:#93c5fd' : ''}">v${e.version}</span></td>
        <td style="color:${ev.color}">${ev.icon} ${ev.text}</td>
        <td style="font-family:monospace;font-size:10px;color:#7dd3fc">${e.pinPrefix ? e.pinPrefix + '...' : '&#x2014;'}</td>
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
      card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-primary" style="padding:4px 12px;font-size:11px" onclick="testHostConnection('${hostname}')">${t('testConnection')}</button><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${hostname}')" title="Yenile">&#x21bb;</span></div></div><div class="empty-msg">${t('noConnHistory')}</div>`;
      return;
    }

    const pagKey = 'host-conn-' + hostname;
    const pagInfo = pagSlice(entries, pagKey);
    const rows = pagInfo.slice.map((e, i) => {
      const src = e.source === 'android'
        ? `<span style="color:#60a5fa">📱 ${e.deviceManufacturer || ''} ${e.deviceModel || ''}</span>`
        : '<span style="color:#94a3b8">💻 Web</span>';
      const statusColor = e.status === 'healthy' || e.status === 'ok' ? '#22c55e' : '#ef4444';
      const pinInfo = e.pinMatched === true ? `<span style="color:#22c55e">✓ ${t('matched')}</span>`
        : e.pinMatched === false ? `<span style="color:#ef4444">✗ ${t('mismatch')}</span>`
        : '—';
      const pinVer = e.pinVersion != null ? `v${e.pinVersion}` : '—';
      return `<tr class="${pagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
        <td>${src}</td>
        <td style="color:${statusColor}">${e.status}</td>
        <td>${e.responseTimeMs}ms</td>
        <td>${pinInfo}</td>
        <td>${pinVer}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
        <td style="color:#64748b;font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.errorMessage && e.errorMessage !== 'null' ? e.errorMessage : ''}</td>
      </tr>`;
    }).join('');
    // Pagination callback host-özel; window'a geçici bir reload fonksiyonu yaz.
    window['_reloadHostConn_' + hostname.replace(/[^a-zA-Z0-9]/g,'_')] = () => loadHostConnectionHistory(hostname);
    const pagNav = pagControls(pagKey, pagInfo, '_reloadHostConn_' + hostname.replace(/[^a-zA-Z0-9]/g,'_'));

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-primary" style="padding:4px 12px;font-size:11px" onclick="testHostConnection('${hostname}')">${t('testConnection')}</button><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${hostname}')" title="Yenile">&#x21bb;</span></div></div>
      <table class="data-table">
        <thead><tr>
          <th>${t('thClient')}</th><th>${t('thStatus')}</th><th>${t('thDuration')}</th>
          <th>${t('thPin')}</th><th>${t('thPinVer')}</th><th>${t('thDate')}</th><th>${t('thError')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>${pagNav}`;
  } catch (e) {
    card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-primary" style="padding:4px 12px;font-size:11px" onclick="testHostConnection('${hostname}')">${t('testConnection')}</button><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${hostname}')" title="Yenile">&#x21bb;</span></div></div><div class="empty-msg">${t('error')}</div>`;
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
      card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connectedClients')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadClientDevices('${hostname}')" title="Yenile">&#x21bb;</span></div><div class="empty-msg">${t('noClients')}</div>`;
      return;
    }

    const rows = devices.map((d, i) => {
      const statusColor = d.lastStatus === 'healthy' ? '#22c55e' : '#ef4444';
      const timeAgo = new Date(d.lastSeen).toLocaleString(locale);
      return `<tr class="${i === 0 ? 'row-latest' : ''}">
        <td><span style="color:#60a5fa">📱 ${d.deviceManufacturer || ''} ${d.deviceModel || ''}</span></td>
        <td><span class="ver-badge">v${d.pinVersion}</span></td>
        <td style="color:${statusColor}">${d.lastStatus}</td>
        <td style="color:#64748b;font-size:11px">${timeAgo}</td>
      </tr>`;
    }).join('');

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connectedClients')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadClientDevices('${hostname}')" title="Yenile">&#x21bb;</span></div>
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
      <div style="cursor:pointer;width:40px;height:22px;border-radius:11px;background:${isMtls ? '#22c55e' : '#334155'};position:relative;transition:background 0.2s" onclick="toggleHostMtls('${hostname}',${!isMtls})">
        <div style="width:18px;height:18px;border-radius:50%;background:white;position:absolute;top:2px;${isMtls ? 'right:2px' : 'left:2px'};transition:all 0.2s"></div>
      </div>
      <span style="color:${isMtls ? '#22c55e' : '#64748b'};font-weight:600;font-size:12px">${isMtls ? 'Aktif' : 'Pasif'}</span>
      ${certVer ? `<span class="ver-badge" style="margin-left:auto">cert v${certVer}</span>` : ''}
    </div>`;

  const certSection = certInfo ? `
    <div style="background:#0f172a;border-radius:8px;padding:10px;margin-bottom:12px;font-size:12px">
      <div style="color:#94a3b8">CN: <span style="color:#7dd3fc">${certInfo.commonName || '—'}</span></div>
      <div style="color:#94a3b8">Fingerprint: <span style="color:#7dd3fc;font-family:monospace;font-size:10px">${certInfo.fingerprint ? certInfo.fingerprint.substring(0,20) + '...' : '—'}</span></div>
      <div style="color:#94a3b8">Version: <span style="color:#22c55e">${certInfo.version}</span></div>
    </div>` : `
    <div style="background:#0f172a;border-radius:8px;padding:10px;margin-bottom:12px;font-size:12px">
      <div style="color:#64748b;margin-bottom:6px">${t('hostCertNone')}</div>
      <div style="color:#475569;font-size:11px;line-height:1.5">${t('hostCertGuide')}</div>
    </div>`;

  const uploadBtn = `
    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn btn-secondary" style="padding:4px 12px;font-size:11px" onclick="document.getElementById('host-cc-file').click()">
        ${certInfo ? 'Client Cert Guncelle' : 'Client Cert Yukle'}
      </button>
      <input type="file" id="host-cc-file" accept=".p12,.pfx" style="display:none" onchange="uploadHostClientCert('${hostname}')"/>
      <span style="color:#64748b;font-size:10px">PKCS12 (.p12/.pfx)</span>
    </div>`;

  card.innerHTML = `
    <div class="card-title">Client Cert (mTLS)</div>
    ${mtlsToggle}
    ${certSection}
    ${uploadBtn}
  `;
}

async function toggleHostMtls(hostname, enable) {
  try {
    await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/toggle-mtls`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ mtls: enable })
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
      <div><div class="section-title-main">Yeni Config API</div><div class="section-sub">TLS veya mTLS config API başlatın</div></div>
    </div>
    <div class="card">
      <form onsubmit="createConfigApi(event)">
        <div class="form-group">
          <label class="form-label">API ID</label>
          <input type="text" id="new-api-id" placeholder="tls-8093 veya mtls-8092" required class="form-input"/>
        </div>
        <div class="form-group">
          <label class="form-label">Port</label>
          <input type="number" id="new-api-port" placeholder="8093" required class="form-input"/>
        </div>
        <div class="form-group">
          <label class="form-label">Mod</label>
          <select id="new-api-mode" class="form-input">
            <option value="tls">TLS (tek yönlü)</option>
            <option value="mtls">mTLS (çift yönlü — client cert gerekir)</option>
          </select>
        </div>
        <button type="submit" class="btn btn-primary">Config API Başlat</button>
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
  ];

  const tabsHtml = tabs.map(tb => `
    <button class="tab-btn ${addHostTab === tb.id ? 'tab-active' : ''}" onclick="switchAddTab('${tb.id}')">${tb.label}</button>
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
        <button class="btn btn-primary" onclick="createHostManual()">${t('create')}</button>
        <button class="btn btn-secondary" onclick="renderEmpty(); renderHostList();">${t('cancel')}</button>
      </div>`;
  } else if (addHostTab === 'generate') {
    formHtml = `
      <div class="form-group">
        <label class="form-label">${t('hostname')}</label>
        <input id="gen-hostname" class="form-input" placeholder="${t('hostnamePlaceholder')}" autofocus>
        <div class="form-hint">${t('hostnameHint')}</div>
      </div>
      <div class="form-actions">
        <button class="btn btn-success" id="gen-btn" onclick="createHostGenerate()">${t('create')}</button>
        <button class="btn btn-secondary" onclick="renderEmpty(); renderHostList();">${t('cancel')}</button>
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
        <button class="btn btn-success" id="upload-btn" onclick="createHostUpload()">${t('create')}</button>
        <button class="btn btn-secondary" onclick="renderEmpty(); renderHostList();">${t('cancel')}</button>
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
  if (currentConfig.pins.some(p => p.hostname === hostname)) { toast(t('duplicateHost'), 'error'); return; }

  const newPins = [...currentConfig.pins, { hostname, sha256: [hash0, hash1] }];
  await saveFullConfig(newPins);
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
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); btn.disabled = false; btn.textContent = t('create'); return; }

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

function showEditPins(hostname) {
  const host = getHosts().find(h => h.hostname === hostname);
  if (!host) return;
  editHashes = [...host.sha256];
  renderEditPins(hostname);
}

function renderEditPins(hostname) {
  document.getElementById('content').innerHTML = `
    <div class="section-header"><div>
      <div class="section-title-main">${hostname}</div>
      <div class="section-sub">${t('editPins')}</div>
    </div></div>
    <div class="card">
      ${editHashes.map((hash, i) => `
        <div class="pin-row">
          <input class="form-input" value="${hash}" onchange="editHashes[${i}]=this.value"
                 placeholder="${i === 0 ? t('primaryPlaceholder') : t('backupPlaceholder')}">
          ${editHashes.length > 2 ? `<button class="btn-icon btn-remove" onclick="editHashes.splice(${i},1); renderEditPins('${hostname}')">x</button>` : ''}
        </div>
      `).join('')}
      <button class="btn btn-secondary" style="margin-top:4px;font-size:11px" onclick="editHashes.push(''); renderEditPins('${hostname}')">${t('addHash')}</button>
      <div class="form-actions">
        <button class="btn btn-primary" onclick="savePins('${hostname}')">${t('save')}</button>
        <button class="btn btn-secondary" onclick="selectHost('${hostname}')">${t('cancel')}</button>
      </div>
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
        <input class="form-input" value="${hash}" onchange="editHashes[${i}]=this.value"
               placeholder="${i === 0 ? t('primaryPlaceholder') : t('backupPlaceholder')}">
        ${editHashes.length > 2 ? `<button class="btn-icon btn-remove" onclick="editHashes.splice(${i},1); renderInlineEditPins('${hostname}')">x</button>` : ''}
      </div>
    `).join('')}
    <button class="btn btn-secondary" style="margin-top:4px;font-size:11px" onclick="editHashes.push(''); renderInlineEditPins('${hostname}')">${t('addHash')}</button>
    <div class="form-actions" style="margin-top:8px">
      <button class="btn btn-primary" onclick="saveInlinePins('${hostname}')">${t('save')}</button>
      <button class="btn btn-secondary" onclick="toggleEditPins('${hostname}')">${t('cancel')}</button>
    </div>`;
}

async function saveInlinePins(hostname) {
  const filtered = editHashes.filter(h => h.trim());
  if (filtered.length < 2) { toast(t('saveError'), 'error'); return; }
  const newPins = currentConfig.pins.map(p => p.hostname === hostname ? { hostname, sha256: filtered } : p);
  await saveFullConfig(newPins);
  toast(t('pinsUpdated'), 'success');
  selectHost(hostname);
}

async function savePins(hostname) {
  const filtered = editHashes.filter(h => h.trim());
  if (filtered.length < 2) { toast(t('saveError'), 'error'); return; }
  const newPins = currentConfig.pins.map(p => p.hostname === hostname ? { hostname, sha256: filtered } : p);
  await saveFullConfig(newPins);
  toast(t('pinsUpdated'), 'success');
  selectHost(hostname);
}

// ── Delete Host ──────────────────────────────────────

async function deleteHost(hostname) {
  if (!confirm(`"${hostname}" ${t('deleteConfirm')}`)) return;
  const newPins = currentConfig.pins.filter(p => p.hostname !== hostname);
  await saveFullConfig(newPins);
  toast(t('hostDeleted'), 'success');
  selectedHost = null;
  renderHostList();
  renderEmpty();
}

// ── Save Config ──────────────────────────────────────

async function saveFullConfig(pins) {
  try {
    const res = await apiFetch('/api/v1/certificate-config', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: 0, pins, forceUpdate: false })
    });
    if (!res.ok) {
      const err = await res.json();
      toast((err.errors || [t('saveError')]).join('\n'), 'error');
      return;
    }
    await loadConfig();
  } catch (e) { toast(t('serverError'), 'error'); }
}

// ── Force Update ─────────────────────────────────────

async function toggleForce(hostname) {
  const isActive = currentConfig.pins.find(p => p.hostname === hostname)?.forceUpdate;
  if (!isActive && !confirm(t('forceConfirm'))) return;
  try {
    const endpoint = isActive ? 'clear-force' : 'force-update';
    await apiFetch(`/api/v1/certificate-config/${endpoint}/${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadConfig(); renderHostList();
    if (selectedHost) selectHost(selectedHost);
    toast(isActive ? t('forceDisabled') : t('forceEnabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

async function forceUpdate(hostname) {
  if (!confirm(t('forceConfirm'))) return;
  try {
    await apiFetch(`/api/v1/certificate-config/force-update/${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadConfig(); renderHostList();
    if (selectedHost) selectHost(selectedHost);
    toast(t('forceEnabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

async function clearForce(hostname) {
  try {
    await apiFetch(`/api/v1/certificate-config/clear-force/${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadConfig(); renderHostList();
    if (selectedHost) selectHost(selectedHost);
    toast(t('forceDisabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Section Navigation ───────────────────────────────

function showSection(section) {
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
  }
}

// ── Health Section ───────────────────────────────────

async function renderHealthSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const [historyRes, healthRes] = await Promise.all([apiFetch('/api/v1/connection-history'), apiFetch('/health')]);
    const entries = await historyRes.json();
    const serverHealth = await healthRes.json();
    const webEntries = entries.filter(e => e.source === 'web');
    const androidEntries = entries.filter(e => e.source === 'android');
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

    const sourceBadge = (s, e) => s === 'android'
      ? `<span class="source-badge android-src">&#x1F4F1; ${e.deviceManufacturer ? e.deviceManufacturer + ' ' + (e.deviceModel||'') : 'Android'}</span>`
      : '<span class="source-badge web-src">&#x1F5A5; Web</span>';

    const pinInfo = e => e.source !== 'android' || e.pinMatched == null ? '&#x2014;'
      : e.pinMatched ? `<span class="status-healthy">&#x2713; ${t('matched')}</span>`
      : `<span class="status-error">&#x2717; ${t('mismatch')}</span>`;

    const pagKey = 'health-global';
    const pagInfo = pagSlice(entries, pagKey);
    const rows = pagInfo.slice.map((e, i) => {
      const ok = e.status === 'ok' || e.status === 'healthy';
      return `<tr class="${pagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
        <td>${sourceBadge(e.source, e)}</td>
        <td class="${ok ? 'status-healthy' : 'status-error'}">${ok ? `&#x2713; ${t('success')}` : `&#x2717; ${t('failed')}`}</td>
        <td>${e.responseTimeMs}ms</td>
        <td>${pinInfo(e)}</td>
        <td style="color:#ef4444;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.errorMessage || '&#x2014;'}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
      </tr>`;
    }).join('');
    const healthPagNav = pagControls(pagKey, pagInfo, 'renderHealthSection');

    document.getElementById('content').innerHTML = `
      <div class="section-header">
        <div><div class="section-title-main">${t('healthTitle')}</div><div class="section-sub">${t('healthSub')}</div></div>
        <button class="btn btn-primary" onclick="runHealthCheck()">${t('runHealthCheck')}</button>
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
      </div>
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
        <div style="color:#64748b;font-size:11px;margin-bottom:8px">HTTPS: ${data.hostname}:${data.httpsPort}</div>
        <div class="hash-label">Primary Pin</div>
        <div class="hash-box">
          <span>sha256/${data.primaryPin}</span>
          <button class="copy-btn" onclick="copyText('${data.primaryPin}')">${t('copy')}</button>
        </div>
        ${data.backupPin ? `
        <div class="hash-label">Backup Pin</div>
        <div class="hash-box">
          <span>sha256/${data.backupPin}</span>
          <button class="copy-btn" onclick="copyText('${data.backupPin}')">${t('copy')}</button>
        </div>` : ''}
        <div style="margin-top:16px;padding-top:16px;border-top:1px solid #334155;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-warning" onclick="regenerateBootstrapCert()">${t('regenerateBootstrap')}</button>
          <button class="btn btn-secondary" onclick="toggleBootstrapUpload()">${t('tabUploadJks')}</button>
        </div>
        <div id="bootstrap-upload-form" style="display:none"></div>
      </div>
      <div class="card">
        <div class="card-title">${t('androidIntegration')}</div>
        <div class="key-box">private val BOOTSTRAP_PINS = listOf(
    HostPin("10.0.2.2", listOf(
        "${data.primaryPin}",
        "${data.backupPin || 'BACKUP_PIN'}"
    ))
)

val config = PinVaultConfig.Builder("https://10.0.2.2:${data.httpsPort}/")
    .bootstrapPins(BOOTSTRAP_PINS)
    .build()</div>
      </div>` : ''}

      ${!hasPins ? `<div class="card">
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-warning" onclick="regenerateBootstrapCert()">${t('regenerateBootstrap')}</button>
          <button class="btn btn-secondary" onclick="toggleBootstrapUpload()">${t('tabUploadJks')}</button>
        </div>
        <div id="bootstrap-upload-form" style="display:none"></div>
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
  form.innerHTML = `<form onsubmit="uploadBootstrapCert(event)">
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
    if (data.error) { toast(data.error, 'error'); return; }
    toast(t('bootstrapFetched'), 'success');
    renderBootstrapSection();
  } catch (err) { toast(t('error'), 'error'); }
}

async function regenerateSigningKey() {
  if (!confirm(t('regenerateSigningConfirm'))) return;
  try {
    await apiFetch('/api/v1/signing-key/regenerate', { method: 'POST' });
    toast(t('signingRegenerated'), 'success');
    renderSigningSection();
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
            <td>${!c.revoked ? `<button class="btn btn-danger" style="padding:2px 8px;font-size:11px" onclick="revokeClientCert('${c.id}')">${t('revoke')}</button>` : ''}</td>
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
        <form onsubmit="generateClientCert(event)" style="display:flex;gap:8px;align-items:end">
          <div class="form-group" style="flex:1;margin:0">
            <label class="form-label">${t('clientIdLabel')}</label>
            <input type="text" id="mtls-client-id" placeholder="${t('clientIdPlaceholder')}" required class="form-input"/>
          </div>
          <button type="submit" class="btn btn-primary">${t('generateClientCert')}</button>
          <button type="button" class="btn btn-secondary" onclick="document.getElementById('mtls-upload-file').click()">${t('uploadClientCert')}</button>
          <input type="file" id="mtls-upload-file" accept=".pem,.der,.crt,.cer" style="display:none" onchange="uploadClientCert()"/>
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
val config = PinVaultConfig.Builder("https://10.0.2.2:8091/")
    .bootstrapPins(BOOTSTRAP_PINS)
    .clientKeystore(p12, "changeit")
    .build()</div>
      </div>
      <div class="card">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div class="card-title" style="margin:0">Enrollment Token</div>
          ${enrollMode.tokenRequired
            ? '<span style="background:#166534;color:#bbf7d0;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">&#x1F512; Token zorunlu</span>'
            : '<span style="background:#92400e;color:#fef08a;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">&#x26A0; Açık mod — deviceId ile kayıt aktif (demo)</span>'}
        </div>
        <div style="color:#94a3b8;font-size:12px;margin-bottom:12px;line-height:1.5">
          <strong>Güvenli akış:</strong> Admin token üretir &#x2192; Uygulama token ile kayıt olur &#x2192; Client cert alır &#x2192; mTLS Config API'ye erişir &#x2192; Host cert'leri otomatik indirilir
          ${!enrollMode.tokenRequired ? '<br><span style="color:#fbbf24">ENROLLMENT_MODE=token ile sunucuyu başlatarak deviceId enrollment\'ı kapatabilirsiniz.</span>' : ''}
        </div>
        <form onsubmit="generateEnrollmentToken(event)" style="display:flex;gap:8px;align-items:end">
          <div class="form-group" style="flex:1;margin:0">
            <label class="form-label">${t('clientIdLabel')}</label>
            <input type="text" id="enrollment-client-id" placeholder="${t('clientIdPlaceholder')}" required class="form-input"/>
          </div>
          <button type="submit" class="btn btn-primary">Token Üret</button>
        </form>
        <div id="enrollment-token-list" style="margin-top:12px"></div>
      </div>`;
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

async function startConfigApi(e) {
  e.preventDefault();
  const id = document.getElementById('capi-id').value.trim();
  const port = parseInt(document.getElementById('capi-port').value);
  const mode = document.getElementById('capi-mode').value;
  if (!id || !port) return;
  try {
    const res = await apiFetch('/api/v1/config-apis/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, port, mode })
    });
    const data = await res.json();
    if (data.error) { toast(data.error, 'error'); return; }
    toast(`Config API başlatıldı: ${id} :${port} (${mode.toUpperCase()})`, 'success');
    renderMtlsSection();
  } catch (err) { toast(t('error'), 'error'); }
}

async function stopConfigApi(id) {
  try {
    await apiFetch('/api/v1/config-apis/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
    toast(`Config API durduruldu: ${id}`, 'success');
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
    toast(`Token: ${data.token}`, 'success');
    loadEnrollmentTokens();
  } catch (err) { toast(t('error'), 'error'); }
}

async function loadEnrollmentTokens() {
  const container = document.getElementById('enrollment-token-list');
  if (!container) return;
  try {
    const res = await apiFetch('/api/v1/enrollment-tokens');
    const tokens = await res.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
    if (tokens.length === 0) { container.innerHTML = ''; return; }
    container.innerHTML = `<table class="data-table">
      <thead><tr><th>Token</th><th>Client ID</th><th>Durum</th><th>Tarih</th></tr></thead>
      <tbody>${tokens.map((t, i) => `<tr class="${i === 0 ? 'row-latest' : ''}">
        <td style="font-family:monospace;font-weight:700;color:#7dd3fc;cursor:pointer" onclick="copyText('${t.token}')">${t.token}</td>
        <td>${t.clientId}</td>
        <td>${t.used ? '<span style="color:#64748b">Kullanıldı</span>' : '<span style="color:#22c55e">Bekliyor</span>'}</td>
        <td style="color:#64748b;font-size:11px">${new Date(t.createdAt).toLocaleString(locale)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
  } catch (_) {}
}

async function revokeClientCert(id) {
  if (!confirm(`${id} iptal edilecek. Devam?`)) return;
  try {
    await apiFetch(`/api/v1/client-certs/${encodeURIComponent(id)}`, { method: 'DELETE' });
    toast(t('certRevoked'), 'success');
    renderMtlsSection();
  } catch (err) { toast(t('error'), 'error'); }
}

// ── Signing Key Section ──────────────────────────────

async function renderSigningSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const res = await apiFetch('/api/v1/signing-key');
    const data = await res.json();
    document.getElementById('content').innerHTML = `
      <div class="section-header">
        <div><div class="section-title-main">${t('signingTitle')}</div><div class="section-sub">${t('signingSub')}</div></div>
        <div class="action-bar">
          <button class="btn btn-primary" onclick="copyText('${data.publicKey}')">${t('copy')}</button>
          <button class="btn btn-warning" onclick="regenerateSigningKey()">${t('regenerateSigningKey')}</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title" style="color:#f59e0b">${t('ecdsaWhat')}</div>
        <div style="color:#94a3b8;line-height:1.6;font-size:13px">${t('ecdsaExplain')}</div>
      </div>
      <div class="card"><div class="card-title">${t('publicKey')}</div><div class="key-box">${data.publicKey}</div></div>
      <div class="card"><div class="card-title">${t('androidIntegration')}</div>
        <div class="key-box">val config = PinVaultConfig.Builder("https://api.example.com/")
    .signaturePublicKey("${data.publicKey}")
    .build()</div></div>`;
  } catch (e) {
    document.getElementById('content').innerHTML = `<div class="card"><div class="empty-msg">${t('signingError')}</div></div>`;
  }
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
        <div class="info-row"><span class="info-key">Algorithm</span><span class="info-val">${c.publicKeyAlgorithm} ${c.publicKeyBits}-bit</span></div>
        <div class="info-row"><span class="info-key">Valid Until</span><span class="info-val" style="color:#f59e0b">${new Date(c.validUntil).toLocaleString(lang === 'tr' ? 'tr-TR' : 'en-US')}</span></div>
        <div class="info-row"><span class="info-key">SAN</span><span class="info-val">${c.subjectAltNames.join(', ')}</span></div>
        <div class="info-row" style="border:none"><span class="info-key">Fingerprint</span><span class="info-val" style="font-size:9px;font-family:monospace;color:#94a3b8">${c.sha256Fingerprint}</span></div>
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
      <button class="btn btn-warning" onclick="renewCertAuto('${hostname}')">${t('regenerateCert')}</button>
      <button class="btn btn-secondary" onclick="showCertUploadForm('${hostname}')">${t('renewUpload')}</button>
    </div>
    <div id="cert-upload-form" style="display:none;margin-top:12px"></div>`;
}

function showCertUploadForm(hostname) {
  const form = document.getElementById('cert-upload-form');
  if (!form) return;
  if (form.style.display !== 'none') { form.style.display = 'none'; return; }
  form.style.display = 'block';
  form.innerHTML = `<form onsubmit="renewCertUpload(event, '${hostname}')">
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
    if (!res.ok) { card.innerHTML = `<div class="card-title">Mock Server</div><div class="empty-msg">${t('noCert')}</div>`; return; }
    const data = await res.json();
    const running = data.mockServerRunning;
    const port = data.mockServerPort || 8443;

    if (!data.keystorePath) {
      card.innerHTML = `<div class="card-title">Mock Server</div><div class="empty-msg">${t('noCert')} — mock server için sertifika gerekli</div>`;
      return;
    }

    const mode = data.mockServerMode || 'tls';
    const tlsPort = data.mockTlsPort;
    const mtlsPort = data.mockMtlsPort;

    // Hiç başlatılmamış + port kaydı yok → host mock olarak eklenmedi, sadece
    // remote pinleme için cert üretildi. Kompakt "başlat" sunan küçük kart göster.
    if (!running && tlsPort == null && mtlsPort == null && data.mockServerPort == null) {
      card.innerHTML = `<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          <span>MOCK SERVER</span>
          <span style="color:#64748b;font-size:11px;font-weight:normal">remote-only</span>
        </div>
        <div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Bu host için yerel mock kurulmamış — sertifika sadece pin doğrulama için üretildi.</div>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="mock-port" class="form-input" style="width:80px;padding:4px 8px;font-size:12px" value="8443" placeholder="${t('mockPort')}">
          <label style="display:flex;align-items:center;gap:6px;color:#94a3b8;font-size:12px;cursor:pointer">
            <input type="checkbox" id="mock-mtls" style="accent-color:#f59e0b"> mTLS
          </label>
          <button class="btn btn-primary" style="padding:4px 10px;font-size:11px" onclick="toggleMock('${hostname}')">${t('mockStart') || 'Başlat'}</button>
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
      <div class="card-title">MOCK SERVER</div>
      <div style="display:flex;align-items:center;gap:10px;cursor:pointer" onclick="toggleMock('${hostname}')">
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
    card.innerHTML = `<div class="card-title">Mock Server</div><div class="empty-msg">${t('error')}</div>`;
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

async function regenerateCert(hostname) {
  if (!confirm(t('regenerateCert') + '?')) return;
  try {
    const res = await apiFetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/regenerate-cert`, { method: 'POST' });
    if (!res.ok) { const err = await res.json(); toast(err.error || t('error'), 'error'); return; }
    toast(t('certRegenerated'), 'success');
    await loadConfig();
    renderHostList();
    selectHost(hostname);
  } catch (e) { toast(t('error'), 'error'); }
}

// ── Utils ────────────────────────────────────────────

function copyText(text) { navigator.clipboard.writeText(text).then(() => toast(t('copied'), 'success')); }

function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
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
  renderApiVaultTab(apiId);
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
      content.innerHTML = `<div class="card"><div class="empty-msg">Yetki hatası (${filesRes.status}). Sağ üstten API key gir veya localStorage.setItem('pinvault_api_key', 'testkey') sonra sayfayı yenile.</div></div>`;
      return;
    }
    const files = await filesRes.json();
    const stats = await statsRes.json();
    const dists = await distRes.json();
    if (!Array.isArray(files) || !Array.isArray(dists)) {
      content.innerHTML = `<div class="card"><div class="empty-msg">Beklenmeyen yanıt formatı. Console'a bak: ${JSON.stringify(files).slice(0, 120)}</div></div>`;
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
          return `<tr class="${filesPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}" style="cursor:pointer" onclick="showVaultFileDetail('${apiId}', '${f.key}')">
            <td style="font-weight:700;color:#7dd3fc">${f.key}</td>
            <td>v${f.version}</td>
            <td>${formatBytes(f.size || 0)}</td>
            <td><span style="background:${policyColor};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px">${f.access_policy || 'token'}</span></td>
            <td style="font-size:12px">${encIcon} ${f.encryption || 'plain'}</td>
            <td><span style="cursor:pointer;color:#ef4444;font-size:11px" onclick="event.stopPropagation();deleteVaultFile('${apiId}', '${f.key}')">&#x2715;</span></td>
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
          const statusIcon = ok ? '✓' : '✗';
          const statusColor = ok ? '#22c55e' : '#ef4444';
          const device = d.deviceManufacturer ? `📱 ${d.deviceManufacturer} ${d.deviceModel || ''}` : d.deviceId;
          // Başarısızlık nedeni — HTTP kodu, decrypt fail, network, vs. Uzun
          // string'lere title attribute'le tooltip olarak tam hali verilir.
          const reasonCell = d.failureReason
              ? `<span style="color:#f87171;font-family:monospace;font-size:11px" title="${(d.failureReason+'').replace(/"/g,'&quot;')}">${(d.failureReason+'').slice(0,80)}${(d.failureReason+'').length > 80 ? '…' : ''}</span>`
              : (ok ? '<span style="color:#475569">—</span>' : '<span style="color:#64748b;font-style:italic">reason yok</span>');
          // Auth method rozeti: cihazın hangi yetkilendirmeyle fetch ettiği.
          const authIcon = d.authMethod === 'public' ? '⚡' : d.authMethod === 'token' ? '🔒' : d.authMethod === 'token_mtls' ? '🔐' : d.authMethod === 'api_key' ? '🔑' : '—';
          const authColor = d.authMethod === 'public' ? '#f59e0b' : d.authMethod === 'token' ? '#22c55e' : d.authMethod === 'token_mtls' ? '#06b6d4' : d.authMethod === 'api_key' ? '#8b5cf6' : '#475569';
          const authCell = d.authMethod
              ? `<span style="background:${authColor};color:#fff;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600" title="${d.authMethod}">${authIcon} ${d.authMethod}</span>`
              : '<span style="color:#475569">—</span>';
          return `<tr class="${distPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}">
            <td style="font-weight:600;color:#7dd3fc;cursor:pointer" onclick="showVaultFileDetail('${apiId}', '${d.vaultKey}')">${d.vaultKey}</td>
            <td>v${d.version}</td>
            <td><span class="source-badge android-src" style="cursor:pointer" onclick="showDeviceDetail('${apiId}', '${d.deviceId}')">${device}</span></td>
            <td style="color:${statusColor};font-weight:600">${statusIcon} ${d.status}</td>
            <td>${authCell}</td>
            <td>${reasonCell}</td>
            <td style="color:#64748b;font-size:11px">${d.enrollmentLabel || '—'}</td>
            <td style="color:#64748b;font-size:11px">${new Date(d.timestamp).toLocaleString(locale)}</td>
          </tr>`;
        }).join('');
    // Sayfa değişince tüm tab'ı yeniden render etmek yerine bu konumu yeniden
    // çağır — aktif filter + apiId state zaten scope dışında tutuluyor.
    window['_reloadVaultTab_' + apiId.replace(/[^a-zA-Z0-9]/g,'_')] = () => renderApiVaultTab(apiId);
    const distPagNav = distPagInfo ? pagControls(distPagKey, distPagInfo, '_reloadVaultTab_' + apiId.replace(/[^a-zA-Z0-9]/g,'_')) : '';

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main">${t('vaultTitle')}</div>
          <div class="section-sub">${t('vaultSub')}</div>
        </div>
        <span style="cursor:pointer;color:#60a5fa;font-size:18px" onclick="renderApiVaultTab('${apiId}')">&#x21bb;</span>
      </div>

      <div class="stats">
        <div class="card"><div class="stat-value" style="color:#60a5fa">${files.length}</div><div class="stat-label">${t('vaultUniqueKeys')}</div></div>
        <div class="card" style="cursor:pointer;${activeFilter === 'downloaded' ? 'outline:2px solid #22c55e;' : ''}" onclick="setVaultStatusFilter('${apiId}', 'downloaded')" title="${t('vaultDownloaded')}">
          <div class="stat-value" style="color:#22c55e">${stats.totalDistributions || 0}</div>
          <div class="stat-label">${t('vaultTotalDist')}</div>
        </div>
        <div class="card"><div class="stat-value" style="color:#f59e0b">${stats.uniqueDevices || 0}</div><div class="stat-label">${t('vaultUniqueDevices')}</div></div>
        <div class="card" style="cursor:pointer;${activeFilter === 'failed' ? 'outline:2px solid #ef4444;' : ''}" onclick="setVaultStatusFilter('${apiId}', 'failed')" title="${t('vaultFailed')}">
          <div class="stat-value" style="color:#ef4444">${stats.failed || 0}</div>
          <div class="stat-label">${t('vaultFailed')}</div>
        </div>
      </div>

      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <div class="card-title" style="margin:0">${t('vaultUpload')}</div>
        </div>
        <form onsubmit="uploadVaultFile(event, '${apiId}')" style="display:flex;gap:8px;align-items:end;flex-wrap:wrap">
          <div class="form-group" style="margin:0">
            <label class="form-label">${t('vaultKey')}</label>
            <input type="text" id="vault-upload-key" placeholder="${t('vaultKeyPlaceholder')}" required class="form-input" style="width:180px"/>
          </div>
          <div class="form-group" style="margin:0">
            <label class="form-label">File</label>
            <input type="file" id="vault-upload-file" required style="color:#94a3b8;font-size:12px"/>
          </div>
          <div class="form-group" style="margin:0">
            <label class="form-label">${t('policyLabel')}</label>
            <select id="vault-upload-policy" class="form-input" style="width:140px">
              <option value="token" selected>${t('policyTokenOpt')}</option>
              <option value="public">${t('policyPublicOpt')}</option>
              <option value="api_key">${t('policyApiKeyOpt')}</option>
              <option value="token_mtls">${t('policyTokenMtlsOpt')}</option>
            </select>
          </div>
          <div class="form-group" style="margin:0">
            <label class="form-label">${t('encryptionLabel')}</label>
            <select id="vault-upload-encryption" class="form-input" style="width:130px">
              <option value="plain" selected>plain</option>
              <option value="at_rest">at_rest</option>
              <option value="end_to_end">end_to_end</option>
            </select>
          </div>
          <button type="submit" class="btn btn-primary">${t('vaultUploadBtn')}</button>
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
          ${activeFilter ? `<span style="background:${activeFilter === 'failed' ? '#ef4444' : '#22c55e'};color:#fff;padding:2px 10px;border-radius:12px;font-size:11px;cursor:pointer" onclick="setVaultStatusFilter('${apiId}', '${activeFilter}')" title="${t('filterRemove')}">${activeFilter === 'failed' ? '✗ ' + t('vaultFailed') : '✓ ' + t('vaultDownloaded')} ✕</span>` : ''}
        </div>
        <table class="data-table">
          <thead><tr><th>${t('vaultKey')}</th><th>${t('vaultVersion')}</th><th>${t('vaultDevice')}</th><th>${t('vaultStatus')}</th><th>Auth</th><th>${t('vaultReason') || 'Neden'}</th><th>${t('vaultLabel')}</th><th>${t('vaultTimestamp')}</th></tr></thead>
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
  const policy = document.getElementById('vault-upload-policy')?.value || 'token';
  const encryption = document.getElementById('vault-upload-encryption')?.value || 'plain';
  if (!key || !file) return;

  try {
    const bytes = await file.arrayBuffer();
    const qs = `?policy=${encodeURIComponent(policy)}&encryption=${encodeURIComponent(encryption)}`;
    const res = await apiFetch(`${vaultBase(apiId)}/${encodeURIComponent(key)}${qs}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: bytes
    });
    if (!res.ok) { toast(t('error'), 'error'); return; }
    const data = await res.json();
    toast(t('vaultUploadSuccess', key, data.version, data.access_policy, data.encryption), 'success');
    renderApiVaultTab(apiId);
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
  if (!confirm(`Delete "${key}"?`)) return;
  try {
    await apiFetch(`${vaultBase(apiId)}/${encodeURIComponent(key)}`, { method: 'DELETE' });
    toast(`${key} deleted`, 'success');
    renderApiVaultTab(apiId);
  } catch (err) { toast(t('error'), 'error'); }
}

async function showVaultFileDetail(apiId, key) {
  const content = document.getElementById('content');
  const locale = lang === 'tr' ? 'tr-TR' : 'en-US';
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;

  try {
    // Parallel fetch: distribution history + token list for this file.
    const base = vaultBase(apiId);
    const [distRes, tokensRes] = await Promise.all([
      apiFetch(`${base}/distributions/${encodeURIComponent(key)}`),
      apiFetch(`${base}/${encodeURIComponent(key)}/tokens`)
    ]);
    const dists = await distRes.json();
    const tokens = tokensRes.ok ? await tokensRes.json() : [];

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
      : devices.map((d, i) => `<tr class="${i === 0 ? 'row-latest' : ''}" style="cursor:pointer" onclick="showDeviceDetail('${apiId}', '${d.deviceId}')">
          <td><span class="source-badge android-src">📱 ${d.deviceLabel}</span></td>
          <td>${d.count}</td>
          <td style="color:#22c55e">✓ ${d.ok}</td>
          <td style="color:${d.failed > 0 ? '#ef4444' : '#64748b'}">✗ ${d.failed}</td>
          <td>v${d.lastVersion} <span style="color:#64748b;font-size:11px">· ${new Date(d.lastTimestamp).toLocaleString(locale)}</span></td>
        </tr>`).join('');

    const fullRows = dists.length === 0
      ? `<tr><td colspan="5" class="empty-msg">${t('vaultNoDistHistory')}</td></tr>`
      : dists.map((d, i) => {
          const ok = d.status === 'downloaded' || d.status === 'cached';
          const device = d.deviceManufacturer ? `📱 ${d.deviceManufacturer} ${d.deviceModel || ''}` : d.deviceId;
          return `<tr class="${i === 0 ? 'row-latest' : ''}">
            <td><span class="source-badge android-src" style="cursor:pointer" onclick="showDeviceDetail('${apiId}', '${d.deviceId}')">${device}</span></td>
            <td>v${d.version}</td>
            <td style="color:${ok ? '#22c55e' : '#ef4444'};font-weight:600">${ok ? '✓' : '✗'} ${d.status}</td>
            <td style="color:#64748b;font-size:11px">${d.enrollmentLabel || '—'}</td>
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
            : `<span style="cursor:pointer;color:#ef4444;font-size:11px" onclick="revokeVaultToken('${apiId}', ${tk.id}, '${key}')">${t('tokenBtnRevoke')}</span>`;
          return `<tr class="${i === 0 ? 'row-latest' : ''}">
            <td style="font-family:monospace;color:#7dd3fc">${tk.deviceId}</td>
            <td style="color:${revokedColor};font-weight:600">${revokedLabel}</td>
            <td style="color:#64748b;font-size:11px">${new Date(tk.createdAt).toLocaleString(locale)}</td>
            <td>${btn}</td>
          </tr>`;
        }).join('');

    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="color:#7dd3fc">${key}</div>
          <div class="section-sub">${t('vaultDistTitle')} — ${dists.length} · ${versions.length} versiyon · ${devices.length} cihaz</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="renderApiVaultTab('${apiId}')">← ${t('cancel')}</button>
          <span style="cursor:pointer;color:#60a5fa;font-size:16px" onclick="showVaultFileDetail('${apiId}', '${key}')">&#x21bb;</span>
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
            <button class="btn btn-primary" style="padding:4px 10px;font-size:12px" onclick="generateVaultToken('${apiId}', '${key}')">${t('tokenNewBtn')}</button>
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

    const deviceLabel = dists.length > 0 && dists[0].deviceManufacturer
      ? `${dists[0].deviceManufacturer} ${dists[0].deviceModel || ''}`.trim()
      : deviceId;
    const enrollmentLabel = dists.length > 0 ? (dists[0].enrollmentLabel || '—') : '—';

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
      : devFilesPagInfo.slice.map((f, i) => `<tr class="${devFilesPagInfo.page === 0 && i === 0 ? 'row-latest' : ''}" style="cursor:pointer" onclick="showVaultFileDetail('${apiId}', '${f.vaultKey}')">
          <td style="font-weight:600;color:#7dd3fc">${f.vaultKey}</td>
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
            <td style="font-weight:600;color:#7dd3fc;cursor:pointer" onclick="showVaultFileDetail('${apiId}', '${d.vaultKey}')">${d.vaultKey}</td>
            <td>v${d.version}</td>
            <td style="color:${ok ? '#22c55e' : '#ef4444'};font-weight:600">${ok ? '✓' : '✗'} ${d.status}</td>
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
          <div class="section-sub">${deviceId} · ${enrollmentLabel} · ${dists.length} ${t('vaultFetchCount').toLowerCase()} · ${files.length} ${t('vaultUniqueKeys').toLowerCase()}</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="renderApiVaultTab('${apiId}')">← ${t('cancel')}</button>
          <span style="cursor:pointer;color:#60a5fa;font-size:16px" onclick="showDeviceDetail('${apiId}', '${deviceId}')">&#x21bb;</span>
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

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ── Start ────────────────────────────────────────────
init();
