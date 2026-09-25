// PinVault dashboard — Start-up, pagination, host list, Config API detail, host detail, adding hosts, pin editing and saving.
// Classic scripts sharing one global scope, loaded in order by index.html.

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
