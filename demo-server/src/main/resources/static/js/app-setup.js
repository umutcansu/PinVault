// PinVault dashboard — Setup wizard: the server's production checklist and the
// app's PinVault configuration, generated from this server's public values.
// Classic scripts sharing one global scope, loaded in order by index.html.
//
// Read-only toward the server: every server setting is an environment value
// read at start-up, so the wizard shows the `.env` lines to change and never
// writes them. The app code it generates holds only public values (pins,
// public keys, ports).

Object.assign(i18n.tr, {
  navSetup: 'Kurulum Sihirbazı',
  setupTitle: 'Kurulum Sihirbazı',
  setupSub: 'Sunucunun üretime hazır olup olmadığını gösterir ve uygulamanın PinVault ayarlarını bu sunucunun değerleriyle üretir.',
  setupStepServer: '1 · Sunucu', setupStepApp: '2 · Uygulama', setupStepCode: '3 · Kod',
  setupReady: '{0} / {1} madde hazır',
  setupReadOnly: 'Sunucu ayarları açılışta ortam değişkenlerinden okunur. Sihirbaz onları değiştirmez: aşağıdaki satırları .env dosyasına yazıp sunucuyu yeniden başlat.',
  setupColCheck: 'Kontrol', setupColNow: 'Şu an', setupColFix: '.env',
  setupAllEnv: 'Önerilen .env satırları', setupNoFix: 'Değişiklik gerekmiyor.',
  setupCopy: 'Kopyala', setupNext: 'İleri →', setupBack: '← Geri',
  setupLevel_ok: 'HAZIR', setupLevel_warn: 'UYARI', setupLevel_fail: 'EKSİK',
  setup_admin_auth: 'Yönetici kimliği', setup_admin_auth_why: 'Her yöneticinin kendi anahtarı olmalı; ortak API_KEY kimin ne yaptığını göstermez.',
  setup_approvals: 'İki kişi onayı', setup_approvals_why: 'Pin değişikliği ikinci bir yöneticinin onayını beklesin.',
  setup_webhook: 'Güvenlik bildirimleri', setup_webhook_why: 'Pin değişikliği, iptal ve reddedilen anahtar anında bir kanala düşsün.',
  setup_management_tls: 'Yönetim paneli TLS', setup_management_tls_why: 'Yönetici anahtarı ağda düz metin gitmesin.',
  setup_test_hooks: 'Test uçları', setup_test_hooks_why: 'Yalnızca testler içindir; üretimde kapalı olmalı.',
  setup_demo_secrets: 'Demo parolaları', setup_demo_secrets_why: 'Keystore, vault ve imza anahtarı parolaları kaynak koddaki demo değerlerle çalışıyor.',
  setup_signers: 'Config imzalayıcıları', setup_signers_why: 'Pin\'leri imzalayan anahtar çalınırsa saldırgan istediği pin\'i yayınlar. En az iki imzalayıcı, biri bu diskte olmayan.',
  setup_recovery_keys: 'Kurtarma anahtarları', setup_recovery_keys_why: 'İmza anahtarını uygulama güncellemesi olmadan döndürmek ve iptal etmek için.',
  setup_config_ttl: 'Config ömrü', setup_config_ttl_why: 'Config API\'yi engelleyen biri cihazı en fazla bu süre eski pin\'lerde tutabilir.',
  setup_live_check: 'Canlı sertifika kontrolü', setup_live_check_why: 'Host\'un sunmadığı pin\'leri yayınlamayı engeller.',
  setup_enrollment_mode: 'Kayıt modu', setup_enrollment_mode_why: 'open modunda cihaz kimliği söyleyen herkes kayıt olur.',
  setup_attestation: 'Kayıtta donanım belgesi', setup_attestation_why: 'Token\'ı ele geçiren bir script ya da emülatör kayıt olamasın; anahtar gerçek telefonda, senin uygulamanda üretilmiş olsun.',
  setup_attestation_revocation: 'Belge iptal listesi', setup_attestation_revocation_why: 'Google\'ın iptal ettiği belge anahtarları geçmesin.',
  setup_p12: 'Sunucuda üretilen anahtar', setup_p12_why: 'Özel anahtar hiç ağdan geçmesin; cihaz kendi anahtarıyla CSR göndersin.',
  setup_integrity: 'Cihaz bütünlüğü (Play Integrity)', setup_integrity_why: 'Root\'lu ya da kancalanmış cihaz, Play dışından kurulmuş uygulama kayıt olamasın. Karar sunucuda verilir, cihazda atlatılamaz.',
  setupAppIntro: 'Uygulamanın bağlanacağı Config API\'yi ve açılacak korumaları seç. Kod bir sonraki adımda.',
  setupApi: 'Config API', setupHost: 'Uygulamanın bağlanacağı adres (host ya da IP)',
  setupHostHint: 'Telefonun sunucuya ulaştığı adres. Pin\'ler bu ada yazılır.',
  setupEnrollApi: 'Kayıt için TLS Config API', setupEnrollApiHint: 'mTLS bloğunda sertifikası olmayan cihaz kaydı bu adrese yapar.',
  setupLang: 'Dil', setupStopped: 'durdurulmuş',
  setupOptSigned: 'İmzalı config (sunucunun imza anahtarları)',
  setupOptScope: 'Config\'i bu Config API\'ye bağla (serverScope)',
  setupOptRecovery: 'İmza anahtarı döndürme (recoveryPublicKeys)',
  setupOptClientCa: 'İstemci CA\'sını pin\'le (clientCaPins)',
  setupOptRecoveryDoor: 'Süresi dolan sertifikayı kurtarma kapısından yenile',
  setupOptGuard: 'Ortam kontrolü (environmentGuard: root / kanca tespitinin kararı)',
  setupOptIntegrity: 'Kayıtta Play Integrity token\'ı gönder (integrityTokenProvider)',
  setupOptUnlocked: 'Anahtarlar yalnızca telefon kilidi açıkken çalışsın (requireUnlockedDevice)',
  setupOptWipe: 'Cihaz iptal edilince dosyaları sil (wipeVaultFilesOnRevocation)',
  setupOptOffline: 'Vault dosyalarının çevrimdışı ömrü (gün, 0 = sınırsız)',
  setupOptUpdate: 'Pin güncelleme aralığı (saat)',
  setupOptCaTrust: 'Pin + sistem CA onayı istenecek host\'lar (virgülle; requireCaTrust)',
  setupCodeIntro: 'Bu kodu uygulamanın Application sınıfına koy. Değerler bu sunucudan geldi; sertifika ya da imza anahtarı değişirse sihirbazı yeniden çalıştır.',
  setupNotes: 'Notlar',
  setupNoteIntegrityOff: 'Sunucuda INTEGRITY_VERIFICATION kapalı: uygulama token gönderir ama sunucu bakmaz. 1. adımdaki satırları ekle.',
  setupNoteIntegrityDeps: 'integrityTokenProvider için uygulamaya com.google.android.play:integrity bağımlılığını ekle ve StandardIntegrityTokenProvider\'ı açılışta bir kez hazırla.',
  setupNoteGuard: 'environmentGuard içine kendi tespitini bağla (RASP ürünü, RootBeer). PinVault kendisi tespit yapmaz; uygulama içindeki kontrol atlatılabilir, asıl karar sunucudaki bütünlük doğrulamasıdır.',
  setupNoteNoSigning: 'Sunucuda imza anahtarı bulunamadı: config imzasız kalır. Bu üretim için uygun değil.',
  setupNoteMtls: 'mTLS Config API: cihaz ilk açılışta init\'ten önce kayıt olmalı (kod sonunda).',
  setupNoteAttestation: 'Sunucu kayıtta donanım belgesi istiyor ({0}). Emülatörler yazılım köküyle belge üretir; test cihazlarını warn modundaki bir sunucuya kaydet.',
  setupNoteHostIp: 'Adres olarak IP verdin: telefon sunucuya bu IP ile ulaşmalı. Sertifika "{0}" adına kesilmiş; PinVault host adını değil pin\'i doğrular.',
  setupLoadError: 'Kurulum bilgisi alınamadı'
});

Object.assign(i18n.en, {
  navSetup: 'Setup Wizard',
  setupTitle: 'Setup Wizard',
  setupSub: 'Shows whether the server is ready for production and generates the app\'s PinVault configuration from this server\'s values.',
  setupStepServer: '1 · Server', setupStepApp: '2 · App', setupStepCode: '3 · Code',
  setupReady: '{0} of {1} items ready',
  setupReadOnly: 'Server settings are environment values read at start-up. The wizard does not change them: add the lines below to .env and restart the server.',
  setupColCheck: 'Check', setupColNow: 'Now', setupColFix: '.env',
  setupAllEnv: 'Suggested .env lines', setupNoFix: 'Nothing to change.',
  setupCopy: 'Copy', setupNext: 'Next →', setupBack: '← Back',
  setupLevel_ok: 'READY', setupLevel_warn: 'WARNING', setupLevel_fail: 'MISSING',
  setup_admin_auth: 'Admin identity', setup_admin_auth_why: 'Each admin should have their own key; a shared API_KEY does not show who did what.',
  setup_approvals: 'Two-person approval', setup_approvals_why: 'A pin change should wait for a second admin.',
  setup_webhook: 'Security notifications', setup_webhook_why: 'Pin changes, revocations and refused keys reach a channel as they happen.',
  setup_management_tls: 'Admin panel over TLS', setup_management_tls_why: 'The admin key should not cross the network in plain text.',
  setup_test_hooks: 'Test endpoints', setup_test_hooks_why: 'For tests only; off in production.',
  setup_demo_secrets: 'Demo passwords', setup_demo_secrets_why: 'Keystore, vault and signing key passwords are the demo values from the source code.',
  setup_signers: 'Config signers', setup_signers_why: 'Whoever steals the key that signs pins can publish any pin. At least two signers, one not on this disk.',
  setup_recovery_keys: 'Recovery keys', setup_recovery_keys_why: 'Rotate and revoke the signing key without an app update.',
  setup_config_ttl: 'Config lifetime', setup_config_ttl_why: 'Someone blocking the Config API can hold a device on old pins for at most this long.',
  setup_live_check: 'Live certificate check', setup_live_check_why: 'Refuses to publish pins the host does not serve.',
  setup_enrollment_mode: 'Enrollment mode', setup_enrollment_mode_why: 'In open mode anyone naming a device id enrolls.',
  setup_attestation: 'Key attestation at enrollment', setup_attestation_why: 'A script or emulator holding a token cannot enroll: the key must be made on a real phone, by your app.',
  setup_attestation_revocation: 'Attestation revocation list', setup_attestation_revocation_why: 'Attestation keys Google revoked do not pass.',
  setup_p12: 'Server-made keys', setup_p12_why: 'No private key crosses the network; the device sends a CSR over its own key.',
  setup_integrity: 'Device integrity (Play Integrity)', setup_integrity_why: 'A rooted or hooked device, or an app not installed from Play, cannot enroll. The server decides; the device cannot bypass it.',
  setupAppIntro: 'Pick the Config API the app connects to and the protections to turn on. The code is in the next step.',
  setupApi: 'Config API', setupHost: 'Address the app connects to (host or IP)',
  setupHostHint: 'The address the phone reaches the server at. Pins are filed under it.',
  setupEnrollApi: 'TLS Config API for enrollment', setupEnrollApiHint: 'A device without a certificate enrolls here for the mTLS block.',
  setupLang: 'Language', setupStopped: 'stopped',
  setupOptSigned: 'Signed configs (the server\'s signing keys)',
  setupOptScope: 'Bind configs to this Config API (serverScope)',
  setupOptRecovery: 'Signing-key rotation (recoveryPublicKeys)',
  setupOptClientCa: 'Pin the client CA (clientCaPins)',
  setupOptRecoveryDoor: 'Renew an expired certificate through the recovery door',
  setupOptGuard: 'Environment check (environmentGuard: your root / hooking detection\'s verdict)',
  setupOptIntegrity: 'Send a Play Integrity token at enrollment (integrityTokenProvider)',
  setupOptUnlocked: 'Keys work only while the phone is unlocked (requireUnlockedDevice)',
  setupOptWipe: 'Delete files when the device is revoked (wipeVaultFilesOnRevocation)',
  setupOptOffline: 'Offline lifetime of vault files (days, 0 = unlimited)',
  setupOptUpdate: 'Pin update interval (hours)',
  setupOptCaTrust: 'Hosts that need pins and the platform CAs (comma separated; requireCaTrust)',
  setupCodeIntro: 'Put this in the app\'s Application class. The values came from this server; run the wizard again after the certificate or a signing key changes.',
  setupNotes: 'Notes',
  setupNoteIntegrityOff: 'INTEGRITY_VERIFICATION is off on the server: the app sends a token nobody reads. Add the lines from step 1.',
  setupNoteIntegrityDeps: 'For integrityTokenProvider add the com.google.android.play:integrity dependency and prepare a StandardIntegrityTokenProvider once at app start.',
  setupNoteGuard: 'Wire your own detection into environmentGuard (a RASP product, RootBeer). PinVault detects nothing itself; a check inside the app can be bypassed, the server\'s integrity verification is what decides.',
  setupNoteNoSigning: 'The server has no signing key: configs stay unsigned. Not fit for production.',
  setupNoteMtls: 'mTLS Config API: on first start the device enrolls before init (end of the code).',
  setupNoteAttestation: 'The server asks for key attestation at enrollment ({0}). Emulators attest with a software root; enroll test devices against a server in warn mode.',
  setupNoteHostIp: 'You gave an IP address: the phone must reach the server at it. The certificate is issued for "{0}"; PinVault checks the pin, not the host name.',
  setupLoadError: 'Could not load the setup data'
});

let setupData = null;
let setupStep = 'server';
let setupOpts = null;

function defaultSetupOpts(d) {
  const apis = d.configApis || [];
  const first = apis.find(a => a.running && a.mode === 'tls') || apis.find(a => a.running) || apis[0] || null;
  const tls = apis.find(a => a.mode === 'tls') || null;
  return {
    apiId: first ? first.id : '',
    enrollApiId: tls ? tls.id : '',
    // SETUP_PUBLIC_HOST (the sample host sets it from HOST_LAN_IP); else the dashboard's own address.
    host: d.publicHost || location.hostname || 'localhost',
    lang: 'kotlin',
    signed: (d.signingKeys || []).length > 0,
    scope: true,
    recovery: (d.recoveryKeys || []).length > 0,
    clientCa: !!d.clientCaPin,
    recoveryDoor: d.recoveryPort != null && (d.recoveryPins || []).length > 0,
    guard: true,
    integrity: d.integrityMode !== 'off',
    unlocked: false,
    wipe: true,
    offlineDays: '7',
    updateHours: '12',
    caTrust: ''
  };
}

async function renderSetupSection() {
  const content = document.getElementById('content');
  if (!setupData) content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  try {
    const res = await apiFetch('/api/v1/setup');
    if (currentSection !== 'setup') return;
    if (!res.ok) {
      content.innerHTML = `<div class="card"><div class="empty-msg">${t('setupLoadError')} (HTTP ${res.status})</div></div>`;
      return;
    }
    setupData = await res.json();
    if (!setupOpts) setupOpts = defaultSetupOpts(setupData);
    drawSetup();
  } catch (e) {
    content.innerHTML = `<div class="card"><div class="empty-msg">${t('setupLoadError')}: ${esc(e.message)}</div></div>`;
  }
}

function setSetupStep(step) {
  setupStep = ['server', 'app', 'code'].includes(step) ? step : 'server';
  drawSetup();
}

function setSetupOpt(name, ev) {
  if (!setupOpts || !(name in setupOpts)) return;
  const el = ev.target;
  setupOpts[name] = el.type === 'checkbox' ? el.checked : String(el.value);
  if (name === 'apiId' || name === 'lang') drawSetup();
}

function copySetupText(which) {
  const text = which === 'env' ? setupEnvText() : setupCode();
  navigator.clipboard.writeText(text).then(() => toast(t('copied'), 'success'));
}

function setupEnvText() {
  // Plain text (copied, or shown through esc()), never markup.
  return (setupData.checks || []).filter(c => c.fix).map(c => '# ' + t('setup_' + c.id) + '\n' + c.fix).join('\n\n');
}

function drawSetup() {
  if (currentSection !== 'setup' || !setupData) return;
  const tabs = ['server', 'app', 'code'].map(s => {
    const label = t(s === 'server' ? 'setupStepServer' : s === 'app' ? 'setupStepApp' : 'setupStepCode');
    return `<button class="tab-btn ${setupStep === s ? 'tab-active' : ''}" data-action="setSetupStep" data-arg0="${s}">${esc(label)}</button>`;
  }).join('');
  const body = setupStep === 'server' ? setupServerStep() : setupStep === 'app' ? setupAppStep() : setupCodeStep();
  document.getElementById('content').innerHTML = `
    <div id="setup-view">
      <div class="section-header">
        <div><div class="section-title-main">${t('setupTitle')}</div><div class="section-sub">${t('setupSub')}</div></div>
        <span class="refresh-icon" data-action="renderSetupSection" title="${t('refresh')}">&#x21bb;</span>
      </div>
      <div class="tab-bar">${tabs}</div>
      ${body}
    </div>`;
}

function setupSelected(yes) { return yes ? 'selected' : ''; }

/** A check's `.env` fix, escaped; a dash when there is none. */
function setupFixBox(fix) {
  return fix ? `<pre class="json-box">${esc(fix)}</pre>` : '<span class="muted">—</span>';
}

function setupEnvCopyButton(text) {
  return text ? `<button class="btn btn-secondary btn-sm" data-action="copySetupText" data-arg0="env">${t('setupCopy')}</button>` : '';
}

function setupEnvBox(text) {
  return text ? `<pre class="json-box">${esc(text)}</pre>` : `<div class="muted">${t('setupNoFix')}</div>`;
}

function setupLevelBadge(level) {
  const cls = level === 'ok' ? 'act-ok' : level === 'fail' ? 'act-bad' : 'act-warn';
  return `<span class="act-badge ${cls}">${esc(t('setupLevel_' + level))}</span>`;
}

function setupServerStep() {
  const checks = setupData.checks || [];
  const ready = checks.filter(c => c.level === 'ok').length;
  const order = { fail: 0, warn: 1, ok: 2 };
  const rows = checks.slice().sort((a, b) => order[a.level] - order[b.level]).map(c => `
      <tr>
        <td>${setupLevelBadge(c.level)}</td>
        <td><b>${esc(t('setup_' + c.id))}</b><div class="muted small">${esc(t('setup_' + c.id + '_why'))}</div></td>
        <td class="mono small">${esc(c.current)}</td>
        <td>${setupFixBox(c.fix)}</td>
      </tr>`).join('');
  const env = setupEnvText();
  return `
    <div class="card">
      <div class="card-head"><div class="card-title">${esc(t('setupReady', ready, checks.length))}</div></div>
      <div class="card-hint">${esc(t('setupReadOnly'))}</div>
      <table class="data-table">
        <thead><tr><th></th><th>${t('setupColCheck')}</th><th>${t('setupColNow')}</th><th>${t('setupColFix')}</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div class="card">
      <div class="card-head">
        <div class="card-title">${t('setupAllEnv')}</div>
        ${setupEnvCopyButton(env)}
      </div>
      ${setupEnvBox(env)}
    </div>
    <div class="form-actions"><button class="btn btn-primary" data-action="setSetupStep" data-arg0="app">${t('setupNext')}</button></div>`;
}

function setupCheckbox(name, label, disabled) {
  return `<label class="form-hint" style="display:flex;gap:8px;align-items:flex-start;margin:6px 0;font-size:13px;color:#cbd5e1">
      <input type="checkbox" ${setupOpts[name] ? 'checked' : ''} ${disabled ? 'disabled' : ''}
             data-action-change="setSetupOpt" data-arg0="${name}" data-event="1"/> <span>${esc(label)}</span></label>`;
}

function setupInput(name, label, hint, type) {
  return `<div class="form-group">
      <label class="form-label">${esc(label)}</label>
      <input class="form-input" type="${type || 'text'}" value="${esc(setupOpts[name])}"
             data-action-change="setSetupOpt" data-arg0="${name}" data-event="1"/>
      ${hint ? `<div class="form-hint">${esc(hint)}</div>` : ''}
    </div>`;
}

/** The port phones reach a listener at: SETUP_PUBLIC_PORTS (a Docker mapping, a proxy), else its own. */
function setupPort(a) {
  return (a && (a.publicPort || a.port)) || 443;
}

function setupRecoveryPort(d) {
  return d.recoveryPublicPort || d.recoveryPort;
}

function setupSelectedApi() {
  return (setupData.configApis || []).find(a => a.id === setupOpts.apiId) || null;
}

function setupAppStep() {
  const apis = setupData.configApis || [];
  const apiOptions = apis.map(a => `<option value="${esc(a.id)}" ${setupSelected(a.id === setupOpts.apiId)}>${esc(a.id)} · ${esc(a.mode.toUpperCase())} · :${esc(setupPort(a))}${a.running ? '' : ' · ' + esc(t('setupStopped'))}</option>`).join('');
  const api = setupSelectedApi();
  const mtls = api && api.mode === 'mtls';
  const tlsApis = apis.filter(a => a.mode === 'tls');
  const enrollOptions = tlsApis.map(a => `<option value="${esc(a.id)}" ${setupSelected(a.id === setupOpts.enrollApiId)}>${esc(a.id)} · :${esc(setupPort(a))}</option>`).join('');
  const d = setupData;
  return `
    <div class="card">
      <div class="card-hint">${esc(t('setupAppIntro'))}</div>
      <div class="form-group">
        <label class="form-label">${t('setupApi')}</label>
        <select class="form-input" data-action-change="setSetupOpt" data-arg0="apiId" data-event="1">${apiOptions}</select>
      </div>
      ${setupInput('host', t('setupHost'), t('setupHostHint'))}
      ${mtls ? `<div class="form-group">
        <label class="form-label">${t('setupEnrollApi')}</label>
        <select class="form-input" data-action-change="setSetupOpt" data-arg0="enrollApiId" data-event="1">${enrollOptions}</select>
        <div class="form-hint">${esc(t('setupEnrollApiHint'))}</div>
      </div>` : ''}
      <div class="form-group">
        <label class="form-label">${t('setupLang')}</label>
        <select class="form-input" data-action-change="setSetupOpt" data-arg0="lang" data-event="1">
          <option value="kotlin" ${setupOpts.lang === 'kotlin' ? 'selected' : ''}>Kotlin</option>
          <option value="java" ${setupOpts.lang === 'java' ? 'selected' : ''}>Java</option>
        </select>
      </div>
    </div>
    <div class="card">
      ${setupCheckbox('signed', t('setupOptSigned'), !(d.signingKeys || []).length)}
      ${setupCheckbox('scope', t('setupOptScope'))}
      ${setupCheckbox('recovery', t('setupOptRecovery'), !(d.recoveryKeys || []).length)}
      ${setupCheckbox('clientCa', t('setupOptClientCa'), !d.clientCaPin)}
      ${mtls ? setupCheckbox('recoveryDoor', t('setupOptRecoveryDoor'), d.recoveryPort == null) : ''}
      ${setupCheckbox('guard', t('setupOptGuard'))}
      ${setupCheckbox('integrity', t('setupOptIntegrity'))}
      ${setupCheckbox('unlocked', t('setupOptUnlocked'))}
      ${setupCheckbox('wipe', t('setupOptWipe'))}
      ${setupInput('offlineDays', t('setupOptOffline'), '', 'number')}
      ${setupInput('updateHours', t('setupOptUpdate'), '', 'number')}
      ${setupInput('caTrust', t('setupOptCaTrust'), '')}
    </div>
    <div class="form-actions">
      <button class="btn btn-secondary" data-action="setSetupStep" data-arg0="server">${t('setupBack')}</button>
      <button class="btn btn-primary" data-action="setSetupStep" data-arg0="code">${t('setupNext')}</button>
    </div>`;
}

function setupCodeStep() {
  const code = setupCode();
  const notes = setupNotes().map(n => `<li>${esc(n)}</li>`).join('');
  return `
    <div class="card">
      <div class="card-head">
        <div class="card-title" lang="en">${setupOpts.lang === 'java' ? 'Java' : 'Kotlin'}</div>
        <button class="btn btn-primary btn-sm" data-action="copySetupText" data-arg0="code">${t('setupCopy')}</button>
      </div>
      <div class="card-hint">${esc(t('setupCodeIntro'))}</div>
      <pre class="json-box" style="max-height:none;white-space:pre;overflow-x:auto">${esc(code)}</pre>
    </div>
    ${notes ? `<div class="notice notice-info"><b>${t('setupNotes')}</b><ul class="notice-list">${notes}</ul></div>` : ''}
    <div class="form-actions"><button class="btn btn-secondary" data-action="setSetupStep" data-arg0="app">${t('setupBack')}</button></div>`;
}

function setupNotes() {
  const d = setupData, o = setupOpts, api = setupSelectedApi();
  const notes = [];
  if (!(d.signingKeys || []).length) notes.push(t('setupNoteNoSigning'));
  if (api && api.mode === 'mtls') notes.push(t('setupNoteMtls'));
  if (o.guard) notes.push(t('setupNoteGuard'));
  if (o.integrity) {
    notes.push(t('setupNoteIntegrityDeps'));
    if (d.integrityMode === 'off') notes.push(t('setupNoteIntegrityOff'));
  }
  if (d.attestationMode && d.attestationMode !== 'off') notes.push(t('setupNoteAttestation', d.attestationMode));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(o.host || '')) notes.push(t('setupNoteHostIp', d.bootstrapHost || 'localhost'));
  return notes;
}

/** Characters that may go into a generated string literal as they are. */
function setupLiteral(s) {
  return '"' + String(s == null ? '' : s).replace(/[^A-Za-z0-9+/=._:\-*]/g, '') + '"';
}

function setupHostOnly(raw) {
  return String(raw || '').trim().replace(/^https?:\/\//, '').replace(/[/:].*$/, '').replace(/[^A-Za-z0-9.\-]/g, '') || 'localhost';
}

/**
 * The app's configuration, Kotlin or Java. Every value comes from this
 * server's public data or the wizard's own choices; literals are reduced to
 * the characters a host, a port, an id or a Base64 key can have.
 */
function setupCode() {
  const d = setupData, o = setupOpts;
  const api = setupSelectedApi() || { id: 'default-tls', port: 443, mode: 'tls' };
  const host = setupHostOnly(o.host);
  const url = `https://${host}:${setupPort(api)}/`;
  const mtls = api.mode === 'mtls';
  const enrollApi = mtls ? (d.configApis || []).find(a => a.id === o.enrollApiId) : null;
  const door = mtls && o.recoveryDoor && d.recoveryPort != null && (d.recoveryPins || []).length > 0;
  const keys = o.signed ? (d.signingKeys || []) : [];
  const recovery = o.recovery ? (d.recoveryKeys || []) : [];
  const caTrust = String(o.caTrust || '').split(',').map(s => s.trim()).filter(Boolean);
  const offline = parseInt(o.offlineDays, 10);
  const hours = parseInt(o.updateHours, 10);
  const java = o.lang === 'java';
  const L = setupLiteral;
  const pins = (list) => list.map(L).join(', ');

  const blockLines = [];
  const bootstrap = [{ host, pins: d.bootstrapPins || [], note: 'Config API certificate' }];
  if (door) bootstrap.push({ host: `${host}:${setupRecoveryPort(d)}`, pins: d.recoveryPins, note: 'recovery door (server CA)' });
  if (java) {
    const hp = bootstrap.map((b, i) => `                new HostPin(${L(b.host)}, Arrays.asList(${pins(b.pins)}), 0, false, false, null)${i < bootstrap.length - 1 ? ',' : ''}   // ${b.note}`);
    blockLines.push(`            block.bootstrapPins(Arrays.asList(\n${hp.join('\n')}\n            ));`);
    if (keys.length) blockLines.push(`            block.signaturePublicKeys(${pins(keys)});`);
    else blockLines.push(`            block.allowUnsigned();   // the server has no signing key: not for production`);
    if (keys.length && d.requiredSignatures > 1) blockLines.push(`            block.requiredSignatures(${d.requiredSignatures});`);
    if (recovery.length) blockLines.push(`            block.recoveryPublicKeys(${pins(recovery)});`);
    if (o.scope) blockLines.push(`            block.serverScope(${L(api.id)});`);
    if (o.clientCa && d.clientCaPin) blockLines.push(`            block.clientCaPins(${L(d.clientCaPin)});`);
    if (enrollApi) blockLines.push(`            block.enrollmentUrl(${L(`https://${host}:${setupPort(enrollApi)}/`)});`);
    if (door) blockLines.push(`            block.renewalUrl(${L(`https://${host}:${setupRecoveryPort(d)}/`)});`);
    blockLines.push('            return Unit.INSTANCE;');
  } else {
    const hp = bootstrap.map((b, i) => `            HostPin(${L(b.host)}, listOf(${pins(b.pins)}))${i < bootstrap.length - 1 ? ',' : ''}   // ${b.note}`);
    blockLines.push(`        bootstrapPins(listOf(\n${hp.join('\n')}\n        ))`);
    if (keys.length) blockLines.push(`        signaturePublicKeys(${pins(keys)})`);
    else blockLines.push(`        allowUnsigned()   // the server has no signing key: not for production`);
    if (keys.length && d.requiredSignatures > 1) blockLines.push(`        requiredSignatures(${d.requiredSignatures})`);
    if (recovery.length) blockLines.push(`        recoveryPublicKeys(${pins(recovery)})`);
    if (o.scope) blockLines.push(`        serverScope(${L(api.id)})`);
    if (o.clientCa && d.clientCaPin) blockLines.push(`        clientCaPins(${L(d.clientCaPin)})`);
    if (enrollApi) blockLines.push(`        enrollmentUrl(${L(`https://${host}:${setupPort(enrollApi)}/`)})`);
    if (door) blockLines.push(`        renewalUrl(${L(`https://${host}:${setupRecoveryPort(d)}/`)})`);
  }

  const chain = [];
  const dot = java ? '        ' : '    ';
  if (caTrust.length) chain.push(`${dot}.requireCaTrust(${caTrust.map(L).join(', ')})`);
  if (offline > 0) chain.push(`${dot}.vaultFileMaxOfflineAge(${offline}${java ? 'L' : ''}, TimeUnit.DAYS)`);
  if (o.wipe) chain.push(`${dot}.wipeVaultFilesOnRevocation()`);
  if (o.unlocked) chain.push(`${dot}.requireUnlockedDevice()`);
  if (hours > 0) chain.push(`${dot}.updateIntervalHours(${hours}${java ? 'L' : ''})`);
  if (o.guard) {
    chain.push(java
      ? `${dot}// Your root / hooking detection (RASP, RootBeer). INIT stays allowed so pinned traffic keeps working.\n` +
        `${dot}.environmentGuard(operation -> operation == GuardedOperation.INIT || !DeviceShield.isCompromised())`
      : `${dot}// Your root / hooking detection (RASP, RootBeer). INIT stays allowed so pinned traffic keeps working.\n` +
        `${dot}.environmentGuard { operation -> operation == GuardedOperation.INIT || !DeviceShield.isCompromised() }`);
  }
  if (o.integrity) {
    chain.push(java
      ? `${dot}// Play Integrity, bound to the request; the server verifies it (INTEGRITY_VERIFICATION).\n` +
        `${dot}.integrityTokenProvider(requestHash -> {\n` +
        `${dot}    try {\n` +
        `${dot}        return Tasks.await(integrityProvider.request(StandardIntegrityTokenRequest.builder()\n` +
        `${dot}                .setRequestHash(requestHash).build()), 10, TimeUnit.SECONDS).token();\n` +
        `${dot}    } catch (Exception e) {\n` +
        `${dot}        return null;   // enrolls without; a server that enforces refuses\n` +
        `${dot}    }\n` +
        `${dot}})`
      : `${dot}// Play Integrity, bound to the request; the server verifies it (INTEGRITY_VERIFICATION).\n` +
        `${dot}.integrityTokenProvider { requestHash ->\n` +
        `${dot}    Tasks.await(\n` +
        `${dot}        integrityProvider.request(StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()),\n` +
        `${dot}        10, TimeUnit.SECONDS\n` +
        `${dot}    ).token()\n` +
        `${dot}}`);
  }

  const date = new Date().toISOString().slice(0, 10);
  const header = `// PinVault configuration — setup wizard, ${date}, Config API "${api.id}" (${api.mode}).`;
  const importsKt = ['io.github.umutcansu.pinvault.PinVault', 'io.github.umutcansu.pinvault.model.*', 'java.util.concurrent.TimeUnit']
    .concat(o.integrity ? ['com.google.android.gms.tasks.Tasks', 'com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest'] : []);

  if (java) {
    const imports = importsKt.map(i => `import ${i};`).concat(['import java.util.Arrays;', 'import kotlin.Unit;']).join('\n');
    const enroll = mtls ? `\n\n// First start: enroll before init (an mTLS Config API needs the certificate).\n` +
      `// PinVault.enrollForResult(context, config, token) is a suspend function: call it from a small\n` +
      `// Kotlin helper (a coroutine) when PinVault.INSTANCE.isEnrolledWithConfig(context, config) is false,\n` +
      `// then init. README → "mTLS Enrollment".\n` : '\n';
    return `${header}\n${imports}\n\n` +
      `PinVaultConfig config = new PinVaultConfig.Builder()\n` +
      `        .configApi(${L(api.id)}, ${L(url)}, block -> {\n${blockLines.join('\n')}\n        })\n` +
      (chain.length ? chain.join('\n') + '\n' : '') +
      `        .build();\n` + enroll +
      `\nPinVault.INSTANCE.init(context, config, result -> {\n` +
      `    if (result instanceof InitResult.Ready) { /* pinned client: PinVault.INSTANCE.getClient() */ }\n` +
      `    return Unit.INSTANCE;\n` +
      `});\n`;
  }
  const imports = importsKt.map(i => `import ${i}`).join('\n');
  const enroll = mtls ? `\n// First start: enroll before init (an mTLS Config API needs the certificate).\n` +
    `if (!PinVault.isEnrolled(context, config)) {\n` +
    `    PinVault.enrollForResult(context, config, enrollmentToken)   // or autoEnrollForResult(context, config)\n` +
    `}\n` : '';
  return `${header}\n${imports}\n\n` +
    `val config = PinVaultConfig.Builder()\n` +
    `    .configApi(${L(api.id)}, ${L(url)}) {\n${blockLines.join('\n')}\n    }\n` +
    (chain.length ? chain.join('\n') + '\n' : '') +
    `    .build()\n` + enroll +
    `\nval result = PinVault.init(context, config)   // InitResult.Ready → PinVault.getClient()\n`;
}
