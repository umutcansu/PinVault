let currentConfig = null;
let allApiConfigs = []; // [{id, port, mode, hosts, version}]
let selectedHost = null;
let selectedApiId = null;
let currentSection = null;

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
  }
};

let lang = localStorage.getItem('pinvault_lang') || 'tr';
function t(key) { return i18n[lang]?.[key] || i18n.tr[key] || key; }

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
    const apisRes = await fetch('/api/v1/all-configs');
    allApiConfigs = await apisRes.json();

    // Varsayılan API'nin config'ini yükle (management server üzerinden)
    const res = await fetch('/api/v1/certificate-config?signed=false');
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

// ── Host List ────────────────────────────────────────

let hostStatuses = {}; // hostname -> { mockServerRunning, mockServerPort, keystorePath }

function getHosts() {
  if (!currentConfig) return [];
  return currentConfig.pins.map(p => ({ hostname: p.hostname, pinCount: p.sha256.length, sha256: p.sha256, version: p.version || 0 }));
}

async function loadAllHostStatuses() {
  for (const api of allApiConfigs) {
    if (!api.pins) continue;
    for (const p of api.pins) {
      try {
        const res = await fetch(`/api/v1/hosts/${encodeURIComponent(p.hostname)}/status`);
        if (res.ok) hostStatuses[p.hostname] = await res.json();
      } catch (_) {}
    }
  }
}

async function renderHostList() {
  const list = document.getElementById('host-list');

  if (allApiConfigs.length === 0) {
    list.innerHTML = `<div class="loading">${t('noPins')}</div>`;
    return;
  }

  // Host durumlarını yükle (mock server çalışıyor mu?)
  await loadAllHostStatuses();

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
        for (const p of api.pins) {
          const isSelected = selectedHost === p.hostname && selectedApiId === api.id;
          const forceBadge = p.forceUpdate ? '<span style="color:#22c55e;font-size:9px;font-weight:700;margin-left:4px">FORCE</span>' : '';
          const hs = hostStatuses[p.hostname];
          const dotClass = hs?.mockServerRunning ? 'host-dot-running' : (hs?.keystorePath ? 'host-dot-cert' : 'host-dot');
          html += `
            <div class="host-item ${isSelected ? 'selected' : ''}" style="margin-left:20px" onclick="selectHostInApi('${p.hostname}', '${api.id}')">
              <div class="${dotClass}"></div>
              <div class="host-info">
                <div class="host-name" style="font-size:13px">${p.hostname}${forceBadge}</div>
                <div class="host-pins">${p.sha256?.length || 0} ${t('pins')} · v${p.version || 0}</div>
              </div>
            </div>`;
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
  renderHostList();
  renderConfigApiDetail(apiId);
}

// ── Config API Detail (tabbed) ──────────────────────

let configApiTab = 'general';

async function renderConfigApiDetail(apiId) {
  const api = allApiConfigs.find(a => a.id === apiId);
  if (!api) return;

  const modeColor = api.mode === 'mtls' ? '#f59e0b' : '#22c55e';
  const tabs = [
    { id: 'general', label: 'Genel' },
    ...(api.mode === 'tls' ? [{ id: 'bootstrap', label: 'Bootstrap Pin' }] : []),
    { id: 'signing', label: 'İmzalama' },
    ...(api.mode === 'mtls' ? [{ id: 'mtls', label: 'Client Sertifikaları' }] : []),
    { id: 'history', label: 'Bağlantı Geçmişi' }
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

function renderApiGeneralTab(apiId) {
  const api = allApiConfigs.find(a => a.id === apiId);
  if (!api) return;
  const container = document.getElementById('config-api-tab-content');
  if (!container) return;

  const hostRows = (api.pins && api.pins.length > 0)
    ? api.pins.map(p => `<tr>
        <td style="font-weight:600">${p.hostname}</td>
        <td><span class="ver-badge">v${p.version}</span></td>
        <td>${p.sha256?.length || 0} pin</td>
        <td>${p.forceUpdate ? '<span style="color:#22c55e;font-weight:700">FORCE</span>' : '<span style="color:#64748b">Normal</span>'}</td>
      </tr>`).join('')
    : `<tr><td colspan="4" style="color:#475569">${t('noPins')}</td></tr>`;

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
    <div class="card">
      <div class="card-title">Host'lar</div>
      <table class="data-table">
        <thead><tr><th>Hostname</th><th>Versiyon</th><th>Pin</th><th>Force</th></tr></thead>
        <tbody>${hostRows}</tbody>
      </table>
    </div>`;
}

async function deleteConfigApi(apiId) {
  if (!confirm(apiId + ' silinecek. Tüm host\'ları ve pin config\'i de silinecek. Devam?')) return;
  try {
    await fetch('/api/v1/config-apis/delete', {
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
  renderHostList();
  // Host detayı için o API'nin config'ini yükle
  loadHostDetail(hostname, apiId);
}

async function loadHostDetail(hostname, apiId) {
  try {
    const res = await fetch(`/api/v1/config/${encodeURIComponent(apiId)}`);
    if (res.ok) {
      currentConfig = await res.json();
      const host = getHosts().find(h => h.hostname === hostname);
      if (host) renderHostDetail(host);
    }
  } catch (e) { console.error('Failed to load host detail', e); }
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

  // Host geçmişini çek
  let historyHtml = `<div class="loading">${t('loading')}</div>`;
  try {
    const res = await fetch('/api/v1/certificate-config/history/' + encodeURIComponent(host.hostname));
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
      historyHtml = `<div class="empty-msg">${t('noHistory')}</div>`;
    } else {
      historyHtml = `<table class="data-table">
        <thead><tr><th>${t('thVersion')}</th><th>${t('thEvent')}</th><th>${t('thPinPrefix')}</th><th>${t('thDate')}</th></tr></thead>
        <tbody>${entries.map((e, i) => {
          const ev = eventLabel(e.event);
          return `<tr class="${i === 0 ? 'row-latest' : ''}">
            <td><span class="ver-badge" style="${i === 0 ? 'background:#1d4ed8;color:#93c5fd' : ''}">v${e.version}</span></td>
            <td style="color:${ev.color}">${ev.icon} ${ev.text}</td>
            <td style="font-family:monospace;font-size:10px;color:#7dd3fc">${e.pinPrefix ? e.pinPrefix + '...' : '&#x2014;'}</td>
            <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
          </tr>`;
        }).join('')}</tbody></table>`;
    }
  } catch (e) { historyHtml = `<div class="empty-msg">${t('error')}</div>`; }

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

    <div class="card">
      <div class="card-title">${t('history')}</div>
      ${historyHtml}
    </div>

    <div class="card" id="conn-history-card">
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${host.hostname}')" title="Yenile">&#x21bb;</span></div>
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
  loadHostConnectionHistory(host.hostname);
  loadClientDevices(host.hostname);
}

async function loadHostConnectionHistory(hostname) {
  const card = document.getElementById('conn-history-card');
  if (!card) return;
  try {
    const res = await fetch('/api/v1/connection-history/' + encodeURIComponent(hostname));
    const entries = await res.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

    if (entries.length === 0) {
      card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${hostname}')" title="Yenile">&#x21bb;</span></div><div class="empty-msg">${t('noConnHistory')}</div>`;
      return;
    }

    const rows = entries.map((e, i) => {
      const src = e.source === 'android'
        ? `<span style="color:#60a5fa">📱 ${e.deviceManufacturer || ''} ${e.deviceModel || ''}</span>`
        : '<span style="color:#94a3b8">💻 Web</span>';
      const statusColor = e.status === 'healthy' || e.status === 'ok' ? '#22c55e' : '#ef4444';
      const pinInfo = e.pinMatched === true ? `<span style="color:#22c55e">✓ ${t('matched')}</span>`
        : e.pinMatched === false ? `<span style="color:#ef4444">✗ ${t('mismatch')}</span>`
        : '—';
      const pinVer = e.pinVersion != null ? `v${e.pinVersion}` : '—';
      return `<tr class="${i === 0 ? 'row-latest' : ''}">
        <td>${src}</td>
        <td style="color:${statusColor}">${e.status}</td>
        <td>${e.responseTimeMs}ms</td>
        <td>${pinInfo}</td>
        <td>${pinVer}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
        <td style="color:#64748b;font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.errorMessage || ''}</td>
      </tr>`;
    }).join('');

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${hostname}')" title="Yenile">&#x21bb;</span></div>
      <table class="data-table">
        <thead><tr>
          <th>${t('thClient')}</th><th>${t('thStatus')}</th><th>${t('thDuration')}</th>
          <th>${t('thPin')}</th><th>${t('thPinVer')}</th><th>${t('thDate')}</th><th>${t('thError')}</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (e) {
    card.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div class="card-title">${t('connHistory')}</div><span style="cursor:pointer;color:#60a5fa;font-size:14px" onclick="loadHostConnectionHistory('${hostname}')" title="Yenile">&#x21bb;</span></div><div class="empty-msg">${t('error')}</div>`;
  }
}

async function loadClientDevices(hostname) {
  const card = document.getElementById('client-devices-card');
  if (!card) return;
  try {
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/clients`);
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/client-cert/info`);
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
    </div>` : '';

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
    await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/toggle-mtls`, {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ mtls: enable })
    });
    await loadConfig();
    loadHostClientCert(hostname);
  } catch (e) { showToast(t('error'), 'error'); }
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/upload-client-cert`, { method: 'POST', body: formData });
    if (!res.ok) { const err = await res.json(); showToast(err.error || t('error'), 'error'); return; }
    const data = await res.json();
    showToast(`Client cert uploaded — v${data.clientCertVersion}`, 'success');
    await loadConfig();
    loadHostClientCert(hostname);
  } catch (e) { showToast(t('error'), 'error'); }
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
    const res = await fetch('/api/v1/config-apis/start', {
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
    const res = await fetch(`/api/v1/management/hosts/${encodeURIComponent(apiId)}/generate-cert`, {
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
    const res = await fetch('/api/v1/hosts/fetch-from-url', {
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
    const res = await fetch('/api/v1/hosts/upload-cert', { method: 'POST', body: formData });
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
    const res = await fetch('/api/v1/certificate-config', {
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
    await fetch(`/api/v1/certificate-config/${endpoint}/${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadConfig(); renderHostList();
    if (selectedHost) selectHost(selectedHost);
    toast(isActive ? t('forceDisabled') : t('forceEnabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

async function forceUpdate(hostname) {
  if (!confirm(t('forceConfirm'))) return;
  try {
    await fetch(`/api/v1/certificate-config/force-update/${encodeURIComponent(hostname)}`, { method: 'POST' });
    await loadConfig(); renderHostList();
    if (selectedHost) selectHost(selectedHost);
    toast(t('forceEnabled'), 'success');
  } catch (e) { toast(t('error'), 'error'); }
}

async function clearForce(hostname) {
  try {
    await fetch(`/api/v1/certificate-config/clear-force/${encodeURIComponent(hostname)}`, { method: 'POST' });
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
    const [historyRes, healthRes] = await Promise.all([fetch('/api/v1/connection-history'), fetch('/health')]);
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

    const rows = entries.slice(0, 50).map((e, i) => {
      const ok = e.status === 'ok' || e.status === 'healthy';
      return `<tr class="${i === 0 ? 'row-latest' : ''}">
        <td>${sourceBadge(e.source, e)}</td>
        <td class="${ok ? 'status-healthy' : 'status-error'}">${ok ? `&#x2713; ${t('success')}` : `&#x2717; ${t('failed')}`}</td>
        <td>${e.responseTimeMs}ms</td>
        <td>${pinInfo(e)}</td>
        <td style="color:#ef4444;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${e.errorMessage || '&#x2014;'}</td>
        <td style="color:#64748b;font-size:11px">${new Date(e.timestamp).toLocaleString(locale)}</td>
      </tr>`;
    }).join('');

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
          <tbody>${rows}</tbody></table>` : `<div class="empty-msg">${t('noConnections')}</div>`}
      </div>`;
  } catch (e) {
    document.getElementById('content').innerHTML = `<div class="card"><div class="empty-msg">${t('error')}</div></div>`;
  }
}

async function runHealthCheck() {
  try {
    const start = Date.now();
    const res = await fetch('/health');
    const elapsed = Date.now() - start;
    const data = await res.json();
    await fetch('/api/v1/connection-history/web', {
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
    const res = await fetch('/api/v1/server-tls-pins');
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
    await fetch('/api/v1/server-tls-pins/regenerate', { method: 'POST' });
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
    const res = await fetch('/api/v1/server-tls-pins/upload', { method: 'POST', body: formData });
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
    const res = await fetch('/api/v1/server-tls-pins/fetch-from-url', {
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
    await fetch('/api/v1/signing-key/regenerate', { method: 'POST' });
    toast(t('signingRegenerated'), 'success');
    renderSigningSection();
  } catch (e) { toast(t('error'), 'error'); }
}

// ── mTLS Section ────────────────────────────────────

async function renderMtlsSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const [statusRes, certsRes] = await Promise.all([
      fetch('/api/v1/mtls-status'),
      fetch('/api/v1/client-certs')
    ]);
    const status = await statusRes.json();
    const certs = await certsRes.json();
    const locale = lang === 'tr' ? 'tr-TR' : 'en-US';

    const certRows = certs.length === 0
      ? `<div class="empty-msg">${t('noClientCerts')}</div>`
      : `<table class="data-table">
          <thead><tr><th>ID</th><th>${t('thFingerprint')}</th><th>${t('thCreated')}</th><th>${t('thRevoked')}</th><th></th></tr></thead>
          <tbody>${certs.map((c, i) => `<tr class="${i === 0 ? 'row-latest' : ''}">
            <td style="font-weight:600">${c.id}</td>
            <td style="font-family:monospace;font-size:10px;color:#7dd3fc">${c.fingerprint.substring(0, 20)}...</td>
            <td style="color:#64748b;font-size:11px">${new Date(c.createdAt).toLocaleString(locale)}</td>
            <td>${c.revoked
              ? `<span style="color:#ef4444">${t('revoked')}</span>`
              : `<span style="color:#22c55e">${t('active')}</span>`}</td>
            <td>${!c.revoked ? `<button class="btn btn-danger" style="padding:2px 8px;font-size:11px" onclick="revokeClientCert('${c.id}')">${t('revoke')}</button>` : ''}</td>
          </tr>`).join('')}</tbody>
        </table>`;

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
        <div class="card-title">Enrollment Token</div>
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
    const res = await fetch('/api/v1/client-certs/generate', {
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
    const res = await fetch('/api/v1/client-certs/upload', { method: 'POST', body: formData });
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
    const res = await fetch('/api/v1/config-apis/start', {
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
    await fetch('/api/v1/config-apis/stop', {
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
      await fetch('/api/v1/config-apis/stop', {
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
      await fetch('/api/v1/config-apis/start', {
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
    const res = await fetch('/api/v1/enrollment-tokens/generate', {
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
    const res = await fetch('/api/v1/enrollment-tokens');
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
    await fetch(`/api/v1/client-certs/${encodeURIComponent(id)}`, { method: 'DELETE' });
    toast(t('certRevoked'), 'success');
    renderMtlsSection();
  } catch (err) { toast(t('error'), 'error'); }
}

// ── Signing Key Section ──────────────────────────────

async function renderSigningSection() {
  document.getElementById('content').innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const res = await fetch('/api/v1/signing-key');
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/cert-info`);
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/upload-cert`, { method: 'POST', body: formData });
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/regenerate-cert`, { method: 'POST' });
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/status`);
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
  const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/status`);
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
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/start-mock`, {
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
    await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/stop-mock`, { method: 'POST' });
    toast(t('mockStoppedMsg'), 'success');
    loadMockStatus(hostname);
    renderHostList();
  } catch (e) { toast(t('error'), 'error'); }
}

async function regenerateCert(hostname) {
  if (!confirm(t('regenerateCert') + '?')) return;
  try {
    const res = await fetch(`/api/v1/hosts/${encodeURIComponent(hostname)}/regenerate-cert`, { method: 'POST' });
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

// ── Start ────────────────────────────────────────────
init();
