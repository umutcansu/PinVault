// PinVault dashboard — Vault files of a Config API.
// Classic scripts sharing one global scope, loaded in order by index.html.

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
