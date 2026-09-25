// PinVault dashboard — Health, bootstrap pins, mTLS, signing keys, certificate info and mock servers.
// Classic scripts sharing one global scope, loaded in order by index.html.

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
