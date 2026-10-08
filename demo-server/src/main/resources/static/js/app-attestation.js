// PinVault dashboard — Attestation: per-Config-API policy, attested devices and verdict stats,
// plus the global PinVault-Token secrets (shown on the signing view). See ATTESTATION.md §4–§6.
// Classic scripts sharing one global scope, loaded in order by index.html.

// ── Constants ────────────────────────────────────────

// The 16 flags a report can raise, in the order the policy table shows them (ATTESTATION.md §3/§4/§11/§12).
// play_integrity* are raised only by a server with the Play Integrity keys configured,
// app_attest* only with APP_ATTEST_APP_IDS.
const ATTEST_FLAGS = [
  'rooted', 'emulator', 'debugger', 'debuggable', 'hooking_framework', 'app_integrity',
  'cloner', 'unknown_installer', 'adb_enabled', 'software_key', 'key_unattested', 'old_patch_level',
  'play_integrity', 'play_integrity_missing', 'app_attest', 'app_attest_missing'
];
const ATTEST_LEVELS = ['reject', 'warn', 'ignore'];
const ATTEST_PRESETS = {
  strict: {
    rooted: 'reject', emulator: 'reject', debugger: 'reject', debuggable: 'reject',
    hooking_framework: 'reject', app_integrity: 'reject', cloner: 'reject',
    unknown_installer: 'warn', adb_enabled: 'ignore', software_key: 'warn',
    key_unattested: 'warn', old_patch_level: 'warn',
    play_integrity: 'warn', play_integrity_missing: 'warn',
    app_attest: 'warn', app_attest_missing: 'warn'
  },
  lenient: Object.fromEntries(ATTEST_FLAGS.map(f => [f, 'warn']))
};
const ATTEST_DEVICES_PAG = 'attest-devices';

// ── State ────────────────────────────────────────────

let attestResultFilter = '';   // '', 'pass' or 'reject' — the `result=` query of the device list
let attestQuery = '';          // the `q=` query of the device list
let _attestPolicy = null;      // last policy read for the open Config API ({version, flags, …})
const _attestOpenRows = new Set(); // 'arc:<key>' / 'annot:<key>' detail rows left open across a devices refresh

function attestBase(apiId) { return `/api/v1/config-apis/${encodeURIComponent(apiId)}/attestation`; }

/** A device id as a DOM id fragment (device ids match ^[A-Za-z0-9._:-]{1,64}$, but never trust it). */
function attestDomKey(deviceId) { return String(deviceId ?? '').replace(/[^A-Za-z0-9_-]/g, '_'); }

/** Milliseconds or ISO text → the dashboard's localized time; `—` when absent. */
function attestTime(v) {
  if (v === null || v === undefined || v === '' || v === 0) return '&#x2014;';
  if (typeof v === 'number') return fmtTime(new Date(v).toISOString());
  return fmtTime(v);
}

/**
 * One device of the list / detail answer, with the field names of
 * ATTESTATION.md §6 and a few spellings a server may reasonably use instead,
 * so a renamed field degrades to "—" rather than to a broken tab.
 */
function attestDev(d) {
  const ka = d.keyAttestation && typeof d.keyAttestation === 'object' ? d.keyAttestation : {};
  const report = d.lastReport && typeof d.lastReport === 'object' ? d.lastReport
    : d.report && typeof d.report === 'object' ? d.report : null;
  const provider = d.verdictProvider ?? (report && report.verdictProvider) ?? null;
  return {
    deviceId: d.deviceId ?? d.id ?? '',
    // false = a row an operator annotated before the device ever attested (no key yet)
    registered: d.registered !== false && !(d.registered === undefined && d.spkiSha256 === null),
    result: d.lastResult ?? d.result ?? null,
    arc: d.lastArc ?? d.arc ?? null,
    reasons: d.lastReasons ?? d.rejectionReasons ?? [],
    warnings: d.lastWarnings ?? d.warnings ?? [],
    // The attested level, else (an iPhone: no Android chain) what the last report says.
    keyLevel: ka.securityLevel ?? d.keySecurityLevel ?? (report && report.device && report.device.keySecurityLevel) ?? null,
    attested: ka.attested ?? d.keyAttested ?? null,
    attestReason: ka.reason ?? d.keyAttestationReason ?? null,
    firstSeen: d.firstSeen ?? null,
    lastSeen: d.lastSeen ?? null,
    policyVersion: d.lastPolicyVersion ?? d.policyVersion ?? null,
    sdkVersion: d.lastSdkVersion ?? null,
    attestCount: d.attestCount ?? null,
    annotations: Array.isArray(d.annotations) ? d.annotations : [],
    forcePass: !!d.forcePass,
    forceFail: !!d.forceFail,
    revoked: !!d.revoked,
    keyMismatches: Number(d.keyMismatches) || 0,
    lastKeyMismatchAt: d.lastKeyMismatchAt ?? null,
    report,
    // The device row carries the provider's name; a report carries {name, token}.
    verdictProviderName: typeof provider === 'string' ? provider : (provider && provider.name) || null,
    verdictProviderToken: !!(provider && typeof provider === 'object' && provider.token),
    // Play Integrity, verified on the server (ATTESTATION.md §11): pass | fail, when, and Google's summary.
    playIntegrityResult: d.playIntegrityResult ?? null,
    playIntegrityAt: d.playIntegrityAt ?? null,
    playIntegrity: typeof d.playIntegrity === 'string' ? parseJsonText(d.playIntegrity) : (d.playIntegrity && typeof d.playIntegrity === 'object' ? d.playIntegrity : null),
    // What the last report ran on: 'ios', 'android' (a report without a platform), null before a verdict.
    platform: d.platform ?? (report && report.device && report.device.platform) ?? null,
    // Apple App Attest, verified on the server (ATTESTATION.md §12): pass | fail, when, the key and its summary.
    appAttestResult: d.appAttestResult ?? null,
    appAttestAt: d.appAttestAt ?? null,
    appAttestKeyId: d.appAttestKeyId ?? null,
    appAttestCounter: d.appAttestCounter ?? null,
    appAttest: typeof d.appAttest === 'string' ? parseJsonText(d.appAttest) : (d.appAttest && typeof d.appAttest === 'object' ? d.appAttest : null)
  };
}

/** `ios` → iOS, `android` → Android; anything else as it came (escaped by the caller); null → —. */
function attestPlatformLabel(platform) {
  if (!platform) return null;
  if (platform === 'ios') return 'iOS';
  if (platform === 'android') return 'Android';
  return String(platform);
}

function attestResultBadge(result) {
  if (result === 'pass') return `<span class="attest-badge attest-pass">${esc(t('attResultPass'))}</span>`;
  if (result === 'reject') return `<span class="attest-badge attest-reject">${esc(t('attResultReject'))}</span>`;
  return `<span class="attest-badge attest-none">&#x2014;</span>`;
}

function attestKeyCell(dev) {
  // An iPhone's key has no Android chain: the mark is App Attest's verdict (Apple vouching for the app).
  if (dev.platform === 'ios') {
    const lvl = dev.keyLevel ? esc(String(dev.keyLevel)) : '&#x2014;';
    const mark = dev.appAttestResult === 'pass'
      ? `<span class="status-healthy" title="${esc(t('attAaPassHint'))}">&#x2713;</span>`
      : dev.appAttestResult === 'fail'
        ? `<span class="status-error" title="${esc(t('attAaFailHint', (dev.appAttest && dev.appAttest.reason) || '—'))}">&#x26A0;</span>`
        : `<span class="muted" title="${esc(t('attAaNoneHint'))}">?</span>`;
    return `<span class="mono">${lvl}</span> ${mark}`;
  }
  const level = dev.keyLevel ? esc(String(dev.keyLevel)) : '&#x2014;';
  const att = dev.attested === true
    ? `<span class="status-healthy" title="${esc(t('attKeyAttestedHint'))}">&#x2713;</span>`
    : dev.attested === false
      ? `<span class="status-error" title="${esc(t('attKeyUnattestedHint', dev.attestReason || '—'))}">&#x26A0;</span>`
      : `<span class="muted" title="${esc(t('attKeyUnknownHint'))}">?</span>`;
  return `<span class="mono">${level}</span> ${att}`;
}

function attestChips(list, cls) {
  const arr = Array.isArray(list) ? list : [];
  if (!arr.length) return '<span class="muted">&#x2014;</span>';
  return arr.map(x => `<span class="attest-chip ${cls || ''}">${esc(x)}</span>`).join(' ');
}

/** Short, one-line help for a flag (both languages live in i18n as attHelp_<flag>). */
function attestFlagHelp(flag) { return t('attHelp_' + flag); }

// ── Tab: stats + policy + devices ────────────────────

/** The "Attestation" tab of a Config API. Writes the whole #content, like the other tabs. */
async function renderAttestationTab(apiId) {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  const base = attestBase(apiId);
  // The three reads are independent: a failing one shows its own message, the others still render.
  const [statsRes, policyRes, devicesRes] = await Promise.all([
    apiFetch(`${base}/stats`, { quiet: true }).catch(() => null),
    apiFetch(`${base}/policy`).catch(() => null),
    apiFetch(`${base}/devices?${attestDevicesQuery(apiId)}`, { quiet: true }).catch(() => null)
  ]);
  const stats = statsRes && statsRes.ok ? await statsRes.json().catch(() => null) : null;
  const policy = policyRes && policyRes.ok ? await policyRes.json().catch(() => null) : null;
  const devices = devicesRes && devicesRes.ok ? await devicesRes.json().catch(() => null) : null;
  _attestPolicy = policy;
  content.innerHTML = `
    <div id="attestation-view">
      ${renderAttestStatsCard(stats, statsRes ? statsRes.status : 0)}
      ${renderAttestPolicyCard(apiId, policy, policyRes ? policyRes.status : 0)}
      <div id="attest-devices-card">${renderAttestDevicesCard(apiId, devices, devicesRes ? devicesRes.status : 0)}</div>
    </div>`;
}

/** Re-renders the tab where it is shown (language switch, paging callbacks look it up on window). */
function refreshAttestationView() {
  if (!selectedApiId) return;
  return setConfigApiTab('attestation', selectedApiId);
}

// ── Stats strip ──────────────────────────────────────

function attestWindow(stats, keys) {
  for (const k of keys) if (stats && stats[k] && typeof stats[k] === 'object') return stats[k];
  return null;
}

/** `{passes, rejects, reasons:[{reason,count}]}` of one window, whatever spelling the server used. */
function attestWindowCounts(w) {
  if (!w) return null;
  const passes = Number(w.passes ?? w.pass ?? 0) || 0;
  const rejects = Number(w.rejects ?? w.reject ?? 0) || 0;
  const raw = w.byReason ?? w.reasons ?? w.topReasons ?? {};
  const reasons = Array.isArray(raw)
    ? raw.map(x => ({ reason: x.reason ?? x.name ?? x.key ?? '?', count: Number(x.count ?? x.n ?? 0) || 0 }))
    : Object.entries(raw).map(([reason, count]) => ({ reason, count: Number(count) || 0 }));
  reasons.sort((a, b) => b.count - a.count);
  return { passes, rejects, reasons: reasons.slice(0, 5) };
}

function renderAttestStatsCard(stats, status) {
  const d1 = attestWindowCounts(attestWindow(stats, ['last24h', 'h24', '24h', 'day']));
  const d7 = attestWindowCounts(attestWindow(stats, ['last7d', 'd7', '7d', 'week']));
  const block = (label, w) => {
    if (!w) return `<div class="attest-stat-block"><div class="attest-stat-title">${esc(label)}</div><div class="muted small">${esc(t('attStatsUnavailable'))}</div></div>`;
    const total = w.passes + w.rejects;
    const pct = total ? Math.round(w.rejects * 100 / total) : 0;
    const reasons = w.reasons.length
      ? w.reasons.map(r => `<span class="attest-chip attest-chip-reason" title="${esc(r.reason)}">${esc(r.reason)} <b>${esc(r.count)}</b></span>`).join(' ')
      : `<span class="muted">${esc(t('attNoRejects'))}</span>`;
    return `<div class="attest-stat-block">
        <div class="attest-stat-title">${esc(label)}</div>
        <div class="mini-stats">
          <div><div class="mini-stat-value status-healthy">${esc(w.passes)}</div><div class="mini-stat-label">${esc(t('attStatPasses'))}</div></div>
          <div><div class="mini-stat-value ${w.rejects ? 'status-error' : ''}">${esc(w.rejects)}</div><div class="mini-stat-label">${esc(t('attStatRejects'))}</div></div>
          <div><div class="mini-stat-value">${esc(pct)}%</div><div class="mini-stat-label">${esc(t('attStatRejectRate'))}</div></div>
        </div>
        <div class="attest-stat-reasons"><span class="muted small">${esc(t('attTopReasons'))}:</span> ${reasons}</div>
      </div>`;
  };
  // Fleet counters (`devices` of the stats answer): how many devices are in each state right now.
  const dc = stats && stats.devices && typeof stats.devices === 'object' ? stats.devices : null;
  const fleet = dc ? `<div class="mini-stats attest-fleet">
      <div><div class="mini-stat-value">${esc(dc.total ?? 0)}</div><div class="mini-stat-label">${esc(t('attDevTotal'))}</div></div>
      <div><div class="mini-stat-value">${esc(dc.registered ?? 0)}</div><div class="mini-stat-label">${esc(t('attDevRegistered'))}</div></div>
      <div><div class="mini-stat-value status-healthy">${esc(dc.lastPassed ?? 0)}</div><div class="mini-stat-label">${esc(t('attDevLastPassed'))}</div></div>
      <div><div class="mini-stat-value ${dc.lastRejected ? 'status-error' : ''}">${esc(dc.lastRejected ?? 0)}</div><div class="mini-stat-label">${esc(t('attDevLastRejected'))}</div></div>
      <div><div class="mini-stat-value">${esc(dc.forcePass ?? 0)} / ${esc(dc.forceFail ?? 0)}</div><div class="mini-stat-label">${esc(t('attDevForced'))}</div></div>
      <div><div class="mini-stat-value ${dc.keyMismatches ? 'status-error' : ''}">${esc(dc.keyMismatches ?? 0)}</div><div class="mini-stat-label">${esc(t('attDevKeyMismatch'))}</div></div>
    </div>` : '';
  return `<div class="card" id="attest-stats-card">
      <div class="card-head">
        <div class="card-title">${esc(t('attStatsTitle'))}</div>
        <span class="refresh-icon" data-action="refreshAttestationView" title="${esc(t('refresh'))}">&#x21bb;</span>
      </div>
      <div class="card-hint">${esc(t('attStatsHint'))}</div>
      ${stats ? `<div class="attest-stats">${block(t('attWindow24h'), d1)}${block(t('attWindow7d'), d7)}</div>${fleet}`
              : `<div class="empty-msg">${esc(status === 404 ? t('attNotServed') : t('attStatsUnavailable'))}</div>`}
    </div>`;
}

// ── Policy editor ────────────────────────────────────

function renderAttestPolicyCard(apiId, policy, status) {
  if (!policy || typeof policy !== 'object') {
    return `<div class="card" id="attest-policy-card">
        <div class="card-title">${esc(t('attPolicyTitle'))}</div>
        <div class="empty-msg">${esc(status === 404 ? t('attNotServed') : t('attPolicyLoadError', status || '?'))}</div>
      </div>`;
  }
  const flags = policy.flags || {};
  const rows = ATTEST_FLAGS.map(flag => {
    const current = ATTEST_LEVELS.includes(flags[flag]) ? flags[flag] : 'warn';
    const opts = ATTEST_LEVELS.map(l =>
      `<option value="${l}"${l === current ? ' selected' : ''}>${esc(t('attLevel_' + l))}</option>`).join('');
    return `<tr>
        <td><span class="mono">${esc(flag)}</span></td>
        <td class="muted small attest-help">${esc(attestFlagHelp(flag))}</td>
        <td><select id="attest-flag-${flag}" class="form-input select-sm attest-level attest-level-${current}" data-action-change="attestLevelChanged" data-event="1">${opts}</select></td>
      </tr>`;
  }).join('');
  const ttl = Number(policy.tokenTtlSeconds) || 300;
  const interval = Number(policy.attestIntervalSeconds) || 300;
  return `<div class="card" id="attest-policy-card">
      <div class="card-head">
        <div class="card-title">${esc(t('attPolicyTitle'))}</div>
        <span class="ver-badge" id="attest-policy-version">v${esc(policy.version ?? 0)}</span>
      </div>
      <div class="card-hint">${esc(t('attPolicyHint'))}</div>
      <form id="attest-policy-form" data-action-submit="saveAttestationPolicy" data-arg0="${esc(apiId)}">
        <div class="toolbar" style="margin-bottom:10px">
          <span class="muted small">${esc(t('attPresets'))}:</span>
          <button type="button" class="btn btn-secondary btn-sm" data-action="applyAttestationPreset" data-arg0="strict" title="${esc(t('attPresetStrictHint'))}">${esc(t('attPresetStrict'))}</button>
          <button type="button" class="btn btn-secondary btn-sm" data-action="applyAttestationPreset" data-arg0="lenient" title="${esc(t('attPresetLenientHint'))}">${esc(t('attPresetLenient'))}</button>
        </div>
        <table class="data-table attest-policy-table">
          <thead><tr><th>${esc(t('attThFlag'))}</th><th>${esc(t('attThMeaning'))}</th><th>${esc(t('attThAction'))}</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <div class="attest-policy-opts">
          <label class="attest-check"><input type="checkbox" id="attest-reveal"${policy.revealReasons ? ' checked' : ''}> ${esc(t('attRevealReasons'))}</label>
          <div class="muted small">${esc(t('attRevealReasonsHint'))}</div>
          <div class="attest-policy-nums">
            <div class="form-group">
              <label class="form-label" for="attest-ttl">${esc(t('attTokenTtl'))}</label>
              <input type="number" id="attest-ttl" class="form-input" min="30" max="86400" step="1" value="${esc(ttl)}">
            </div>
            <div class="form-group">
              <label class="form-label" for="attest-interval">${esc(t('attInterval'))}</label>
              <input type="number" id="attest-interval" class="form-input" min="60" max="86400" step="1" value="${esc(interval)}">
            </div>
          </div>
        </div>
        <button type="submit" class="btn btn-primary">${esc(t('attPolicySave'))}</button>
        <span class="muted small" style="margin-left:10px">${esc(t('attPolicySaveHint'))}</span>
      </form>
    </div>`;
}

/** Colours a level select after a change (and after a preset fills it). */
function attestLevelChanged(ev) { attestPaintLevel(ev.target); }
function attestPaintLevel(sel) {
  if (!sel) return;
  sel.classList.remove('attest-level-reject', 'attest-level-warn', 'attest-level-ignore');
  sel.classList.add('attest-level-' + (ATTEST_LEVELS.includes(sel.value) ? sel.value : 'warn'));
}

function applyAttestationPreset(name) {
  const preset = ATTEST_PRESETS[name];
  if (!preset) return;
  for (const flag of ATTEST_FLAGS) {
    const sel = document.getElementById('attest-flag-' + flag);
    if (!sel) continue;
    sel.value = preset[flag];
    attestPaintLevel(sel);
  }
  toast(t('attPresetApplied', t(name === 'strict' ? 'attPresetStrict' : 'attPresetLenient')), 'info', 2500);
}

/** The policy as the editor shows it: the whole object of ATTESTATION.md §4. */
function readAttestationPolicyForm() {
  const flags = {};
  for (const flag of ATTEST_FLAGS) {
    const v = document.getElementById('attest-flag-' + flag)?.value;
    flags[flag] = ATTEST_LEVELS.includes(v) ? v : 'warn';
  }
  const ttl = parseInt(document.getElementById('attest-ttl')?.value, 10);
  const interval = parseInt(document.getElementById('attest-interval')?.value, 10);
  return {
    version: Number(_attestPolicy?.version) || 0,
    flags,
    revealReasons: !!document.getElementById('attest-reveal')?.checked,
    tokenTtlSeconds: Number.isFinite(ttl) ? ttl : 300,
    attestIntervalSeconds: Number.isFinite(interval) ? interval : 300
  };
}

/** PUT …/attestation/policy with the whole object (gated: attestation_policy). */
async function saveAttestationPolicy(e, apiId) {
  e.preventDefault();
  const policy = readAttestationPolicyForm();
  // The server's ranges (AttestationPolicy.TOKEN_TTL_RANGE / INTERVAL_RANGE): 30..86400 and 60..86400.
  if (policy.tokenTtlSeconds < 30 || policy.tokenTtlSeconds > 86400 || policy.attestIntervalSeconds < 60 || policy.attestIntervalSeconds > 86400) {
    toast(t('attPolicyMinSeconds'), 'error'); return;
  }
  try {
    const res = await apiFetch(`${attestBase(apiId)}/policy`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(policy)
    });
    if (res.status === 202) return; // waiting for approval — apiFetch said so
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.message || data.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000); return; }
    const stored = data && data.flags ? data : { ...policy, version: data.version ?? policy.version + 1 };
    _attestPolicy = stored;
    toast(t('attPolicySaved', stored.version ?? '?'), 'success');
    const card = document.getElementById('attest-policy-card');
    if (card) card.outerHTML = renderAttestPolicyCard(apiId, stored, 200);
  } catch (err) { toast(t('error'), 'error'); }
}

// ── Devices ──────────────────────────────────────────

function attestDevicesQuery(apiId) {
  const key = ATTEST_DEVICES_PAG + '-' + apiId;
  const st = _pagState[key] || (_pagState[key] = { page: 0, size: PAG_DEFAULT_SIZE });
  const size = st.size > 0 ? st.size : PAG_DEFAULT_SIZE;
  const params = new URLSearchParams({ page: String(st.page + 1), pageSize: String(size) });
  if (attestResultFilter) params.set('result', attestResultFilter);
  if (attestQuery) params.set('q', attestQuery);
  return params.toString();
}

/** The device list answer: `{devices|items, total, page, pageSize}` or a bare array. */
function attestDevicePage(data) {
  if (Array.isArray(data)) return { items: data, total: data.length, serverPaged: false };
  const items = (data && (data.devices || data.items || data.entries)) || [];
  const total = Number(data && (data.total ?? data.totalCount)) ;
  return { items: Array.isArray(items) ? items : [], total: Number.isFinite(total) ? total : items.length, serverPaged: true };
}

async function refreshAttestationDevices(apiId) {
  const id = apiId || selectedApiId;
  if (!id) return;
  const box = document.getElementById('attest-devices-card');
  if (!box) return refreshAttestationView();
  try {
    const res = await apiFetch(`${attestBase(id)}/devices?${attestDevicesQuery(id)}`);
    const data = res.ok ? await res.json().catch(() => null) : null;
    box.innerHTML = renderAttestDevicesCard(id, data, res.status);
  } catch (e) {
    box.innerHTML = renderAttestDevicesCard(id, null, 0);
  }
}
/** pagControls looks its callback up on window and calls it without arguments. */
function refreshAttestationDevicesCurrent() { return refreshAttestationDevices(selectedApiId); }

function renderAttestDevicesCard(apiId, data, status) {
  const key = ATTEST_DEVICES_PAG + '-' + apiId;
  const st = _pagState[key] || (_pagState[key] = { page: 0, size: PAG_DEFAULT_SIZE });
  const size = st.size > 0 ? st.size : PAG_DEFAULT_SIZE;
  const filterOpts = ['', 'pass', 'reject'].map(v =>
    `<option value="${v}"${v === attestResultFilter ? ' selected' : ''}>${esc(v ? t('attResult_' + v) : t('attFilterAll'))}</option>`).join('');
  const toolbar = `<div class="toolbar">
      <select class="form-input select-sm" data-action-change="setAttestResultFilter" data-arg0="${esc(apiId)}" data-event="1">${filterOpts}</select>
      <form class="attest-search" data-action-submit="searchAttestDevices" data-arg0="${esc(apiId)}">
        <input type="search" id="attest-q" class="form-input select-sm" placeholder="${esc(t('attSearchPlaceholder'))}" value="${esc(attestQuery)}">
        <button type="submit" class="btn btn-secondary btn-sm">${esc(t('attSearch'))}</button>
      </form>
      <span class="refresh-icon" data-action="refreshAttestationDevices" data-arg0="${esc(apiId)}" title="${esc(t('refresh'))}">&#x21bb;</span>
    </div>`;
  if (!data) {
    return `<div class="card">
        <div class="card-head"><div class="card-title">${esc(t('attDevicesTitle'))}</div>${toolbar}</div>
        <div class="empty-msg">${esc(status === 404 ? t('attNotServed') : t('attDevicesLoadError', status || '?'))}</div>
      </div>`;
  }
  const page = attestDevicePage(data);
  let items = page.items;
  let total = page.total;
  if (!page.serverPaged) { // an array answer: page it here
    const info = pagSlice(items, key);
    items = info.slice;
    total = info.total;
  }
  const pageCount = Math.max(1, Math.ceil(total / size));
  const rows = items.map(raw => renderAttestDeviceRow(apiId, attestDev(raw))).join('');
  return `<div class="card">
      <div class="card-head">
        <div class="card-title">${esc(t('attDevicesTitle'))} (${esc(total)})</div>
        ${toolbar}
      </div>
      <div class="card-hint">${esc(t('attDevicesHint'))}</div>
      ${items.length ? `<table class="data-table attest-devices-table">
        <thead><tr>
          <th>${esc(t('attThDevice'))}</th><th>${esc(t('attThPlatform'))}</th><th>${esc(t('attThResult'))}</th><th>ARC</th><th>${esc(t('attThKey'))}</th>
          <th>${esc(t('attThFirstSeen'))}</th><th>${esc(t('attThLastSeen'))}</th><th>${esc(t('attThAnnotations'))}</th><th>${esc(t('attThForce'))}</th><th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>` : `<div class="empty-msg">${esc(attestResultFilter || attestQuery ? t('attNoDevicesFiltered') : t('attNoDevices'))}</div>`}
      ${pagControls(key, { page: Math.min(st.page, pageCount - 1), pageCount, size, total }, 'refreshAttestationDevicesCurrent')}
    </div>`;
}

function renderAttestDeviceRow(apiId, dev) {
  const k = attestDomKey(dev.deviceId);
  const arcOpen = _attestOpenRows.has('arc:' + k);
  const annotOpen = _attestOpenRows.has('annot:' + k);
  const arcTitle = [
    dev.reasons.length ? `${t('attReasons')}: ${dev.reasons.join(', ')}` : '',
    dev.warnings.length ? `${t('attWarnings')}: ${dev.warnings.join(', ')}` : ''
  ].filter(Boolean).join(' · ') || t('attArcHint');
  const force = dev.forceFail ? `<span class="attest-badge attest-reject" title="forceFail">${esc(t('attForceFail'))}</span>`
    : dev.forcePass ? `<span class="attest-badge attest-pass" title="forcePass">${esc(t('attForcePass'))}</span>`
    : '<span class="muted">&#x2014;</span>';
  const revoked = dev.revoked ? ` <span class="attest-badge attest-reject">${esc(t('attRevoked'))}</span>` : '';
  const unregistered = !dev.registered ? ` <span class="attest-badge attest-none" title="${esc(t('attUnregisteredHint'))}">${esc(t('attUnregistered'))}</span>` : '';
  const mismatch = dev.keyMismatches ? ` <span class="attest-badge attest-warn" title="${esc(t('attKeyMismatchHint'))}">${esc(t('attKeyMismatch', dev.keyMismatches))}</span>` : '';
  const annotForm = `<form class="attest-annot-form" data-action-submit="saveAttestDevice" data-arg0="${esc(apiId)}" data-arg1="${esc(dev.deviceId)}">
      <div class="attest-annot-row">
        <label class="attest-check"><input type="checkbox" id="attest-fp-${k}"${dev.forcePass ? ' checked' : ''}> ${esc(t('attForcePassLabel'))}</label>
        <label class="attest-check"><input type="checkbox" id="attest-ff-${k}"${dev.forceFail ? ' checked' : ''}> ${esc(t('attForceFailLabel'))}</label>
      </div>
      <div class="muted small">${esc(t('attForceHint'))}</div>
      <div class="form-group" style="margin:8px 0">
        <label class="form-label" for="attest-an-${k}">${esc(t('attAnnotationsLabel'))}</label>
        <input id="attest-an-${k}" class="form-input" value="${esc(dev.annotations.join(', '))}" placeholder="staff, canary">
        <div class="muted small">${esc(t('attAnnotationsHint'))}</div>
      </div>
      <button type="submit" class="btn btn-primary btn-sm">${esc(t('save'))}</button>
      <button type="button" class="btn btn-secondary btn-sm" data-action="toggleAttestRow" data-arg0="annot" data-arg1="${esc(k)}">${esc(t('cancel'))}</button>
    </form>`;
  return `<tr>
      <td class="mono small">${esc(dev.deviceId)}${revoked}${unregistered}${mismatch}</td>
      <td class="small">${attestPlatformLabel(dev.platform) ? esc(attestPlatformLabel(dev.platform)) : '<span class="muted">&#x2014;</span>'}</td>
      <td>${attestResultBadge(dev.result)}</td>
      <td>${dev.arc
        ? `<span class="attest-arc" data-action="toggleAttestRow" data-arg0="arc" data-arg1="${esc(k)}" title="${esc(arcTitle)}">${esc(dev.arc)}</span>`
        : '<span class="muted">&#x2014;</span>'}</td>
      <td>${attestKeyCell(dev)}</td>
      <td class="muted nowrap small">${attestTime(dev.firstSeen)}</td>
      <td class="muted nowrap small">${attestTime(dev.lastSeen)}</td>
      <td>${attestChips(dev.annotations, 'attest-chip-anno')}</td>
      <td>${force}</td>
      <td class="nowrap">
        <button class="btn btn-secondary btn-sm" data-action="toggleAttestRow" data-arg0="annot" data-arg1="${esc(k)}">${esc(t('attAnnotate'))}</button>
        <button class="btn btn-secondary btn-sm" data-action="showAttestationDevice" data-arg0="${esc(apiId)}" data-arg1="${esc(dev.deviceId)}">${esc(t('attDetails'))}</button>
        <button class="btn btn-danger btn-sm" data-action="forgetAttestDevice" data-arg0="${esc(apiId)}" data-arg1="${esc(dev.deviceId)}" title="${esc(t('attForgetHint'))}">${esc(t('attForget'))}</button>
      </td>
    </tr>
    <tr class="detail-row" id="attest-arc-${k}" style="${arcOpen ? '' : 'display:none'}"><td colspan="10">
      <div class="attest-arc-detail">
        <div><span class="muted small">ARC</span> <span class="mono">${esc(dev.arc || '—')}</span>
          ${dev.policyVersion != null ? `<span class="muted small" style="margin-left:10px">${esc(t('attPolicyVersionShort'))} v${esc(dev.policyVersion)}</span>` : ''}
          ${dev.attestCount != null ? `<span class="muted small" style="margin-left:10px">${esc(t('attAttestCount', dev.attestCount))}</span>` : ''}</div>
        <div><span class="muted small">${esc(t('attReasons'))}:</span> ${attestChips(dev.reasons, 'attest-chip-reason')}</div>
        <div><span class="muted small">${esc(t('attWarnings'))}:</span> ${attestChips(dev.warnings, 'attest-chip-warn')}</div>
      </div>
    </td></tr>
    <tr class="detail-row" id="attest-annot-${k}" style="${annotOpen ? '' : 'display:none'}"><td colspan="10">${annotForm}</td></tr>`;
}

/** Opens / closes a device's ARC detail or its annotate form (kind: 'arc' | 'annot'). */
function toggleAttestRow(kind, k) {
  const id = kind + ':' + k;
  const el = document.getElementById(`attest-${kind}-${k}`);
  if (!el) return;
  const show = el.style.display === 'none';
  el.style.display = show ? '' : 'none';
  if (show) _attestOpenRows.add(id); else _attestOpenRows.delete(id);
}

function setAttestResultFilter(apiId, ev) {
  attestResultFilter = ['pass', 'reject'].includes(ev.target.value) ? ev.target.value : '';
  const st = _pagState[ATTEST_DEVICES_PAG + '-' + apiId];
  if (st) st.page = 0;
  refreshAttestationDevices(apiId);
}

function searchAttestDevices(e, apiId) {
  e.preventDefault();
  attestQuery = (document.getElementById('attest-q')?.value || '').trim().slice(0, 64);
  const st = _pagState[ATTEST_DEVICES_PAG + '-' + apiId];
  if (st) st.page = 0;
  refreshAttestationDevices(apiId);
}

/** PUT …/devices/{deviceId} with forcePass / forceFail / annotations (gated: attestation_device). */
async function saveAttestDevice(e, apiId, deviceId) {
  e.preventDefault();
  const k = attestDomKey(deviceId);
  const forcePass = !!document.getElementById('attest-fp-' + k)?.checked;
  const forceFail = !!document.getElementById('attest-ff-' + k)?.checked;
  if (forcePass && forceFail) { toast(t('attForceBoth'), 'error'); return; }
  const annotations = (document.getElementById('attest-an-' + k)?.value || '')
    .split(',').map(s => s.trim()).filter(Boolean).slice(0, 16);
  for (const a of annotations) {
    if (a.length > 64) { toast(t('attAnnotationTooLong'), 'error'); return; }
  }
  try {
    const res = await apiFetch(`${attestBase(apiId)}/devices/${encodeURIComponent(deviceId)}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ forcePass, forceFail, annotations })
    });
    if (res.status === 202) return;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.message || data.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000); return; }
    _attestOpenRows.delete('annot:' + k);
    toast(t('attDeviceSaved', deviceId), 'success');
    refreshAttestationDevices(apiId);
  } catch (err) { toast(t('error'), 'error'); }
}

/** DELETE …/devices/{deviceId}: forgets the device key so the device can register again (gated). */
async function forgetAttestDevice(apiId, deviceId) {
  if (!confirm(t('attForgetConfirm', deviceId))) return;
  try {
    const res = await apiFetch(`${attestBase(apiId)}/devices/${encodeURIComponent(deviceId)}`, { method: 'DELETE' });
    if (res.status === 202) return;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.message || data.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000); return; }
    toast(t('attDeviceForgotten', deviceId), 'success');
    if (document.getElementById('attest-devices-card')) refreshAttestationDevices(apiId);
    else setConfigApiTab('attestation', apiId);
  } catch (err) { toast(t('error'), 'error'); }
}

/**
 * The Play Integrity card of the device page (ATTESTATION.md §11): what the
 * server last verified for this device, or that it never saw a verdict. The
 * token itself is never shown; the summary is what the verifier stored.
 */
function attestPlayIntegrityCard(dev) {
  const pi = dev.playIntegrity || {};
  const result = dev.playIntegrityResult;
  // An App Attest token is not a Play Integrity one: its own card below.
  if (!result && (!dev.verdictProviderName || dev.verdictProviderName === 'app-attest')) return '';
  const badge = result === 'pass' ? `<span class="attest-badge attest-pass">${esc(t('attPiPass'))}</span>`
    : result === 'fail' ? `<span class="attest-badge attest-reject">${esc(t('attPiFail'))}</span>`
    : `<span class="attest-badge attest-none">${esc(t('attPiNotVerified'))}</span>`;
  const list = (v) => Array.isArray(v) && v.length ? v.map(x => `<span class="attest-chip">${esc(x)}</span>`).join(' ') : '<span class="muted">&#x2014;</span>';
  return `<div class="card">
      <div class="card-title">${esc(t('attPiTitle'))}</div>
      <div class="card-hint">${esc(t('attPiHint'))}</div>
      <div class="info-row"><span class="info-key">${esc(t('attThResult'))}</span><span class="info-val">${badge}${pi.reason && pi.reason !== 'ok' ? ` <span class="mono small">${esc(pi.reason)}</span>` : ''}</span></div>
      <div class="info-row"><span class="info-key">${esc(t('attPiVerifiedAt'))}</span><span class="info-val">${attestTime(dev.playIntegrityAt)}</span></div>
      <div class="info-row"><span class="info-key">${esc(t('attPiDevice'))}</span><span class="info-val">${list(pi.deviceVerdicts)}</span></div>
      <div class="info-row"><span class="info-key">${esc(t('attPiApp'))}</span><span class="info-val">${esc(pi.appVerdict || '—')}${pi.packageName ? ` <span class="mono small">${esc(pi.packageName)}</span>` : ''}${pi.versionCode != null ? ` <span class="muted small">v${esc(pi.versionCode)}</span>` : ''}</span></div>
      <div class="info-row" style="border:none"><span class="info-key">${esc(t('attPiLicensing'))}</span><span class="info-val">${esc(pi.licensing || '—')}</span></div>
    </div>`;
}

/**
 * The App Attest card of the device page (ATTESTATION.md §12): Apple's
 * verdict on this app instance as the server last verified it — an
 * attestation (a new key) or an assertion (a later round, counter rising).
 */
function attestAppAttestCard(dev) {
  const aa = dev.appAttest || {};
  const result = dev.appAttestResult;
  if (!result && dev.verdictProviderName !== 'app-attest' && dev.platform !== 'ios') return '';
  const badge = result === 'pass' ? `<span class="attest-badge attest-pass">${esc(t('attPiPass'))}</span>`
    : result === 'fail' ? `<span class="attest-badge attest-reject">${esc(t('attPiFail'))}</span>`
    : `<span class="attest-badge attest-none">${esc(t('attPiNotVerified'))}</span>`;
  const kind = aa.kind === 'attestation' ? t('attAaKindAttestation') : aa.kind === 'assertion' ? t('attAaKindAssertion') : '—';
  return `<div class="card">
      <div class="card-title">${esc(t('attAaTitle'))}</div>
      <div class="card-hint">${esc(t('attAaHint'))}</div>
      <div class="info-row"><span class="info-key">${esc(t('attThResult'))}</span><span class="info-val">${badge}${aa.reason && aa.reason !== 'ok' ? ` <span class="mono small">${esc(aa.reason)}</span>` : ''}</span></div>
      <div class="info-row"><span class="info-key">${esc(t('attPiVerifiedAt'))}</span><span class="info-val">${attestTime(dev.appAttestAt)}</span></div>
      <div class="info-row"><span class="info-key">${esc(t('attAaKind'))}</span><span class="info-val">${esc(kind)}${aa.environment ? ` <span class="muted small">${esc(aa.environment)}</span>` : ''}</span></div>
      <div class="info-row"><span class="info-key">${esc(t('attAaKeyId'))}</span><span class="info-val mono small">${esc(dev.appAttestKeyId || '—')}</span></div>
      <div class="info-row" style="border:none"><span class="info-key">${esc(t('attAaCounter'))}</span><span class="info-val">${dev.appAttestCounter != null ? esc(dev.appAttestCounter) : '&#x2014;'}</span></div>
    </div>`;
}

// ── Device detail (last trimmed report) ──────────────

/** GET …/devices/{deviceId}: the device with its last report (app, device, signals). Full page, like the vault device view. */
async function showAttestationDevice(apiId, deviceId) {
  const content = document.getElementById('content');
  content.innerHTML = `<div class="loading">${t('loading')}</div>`;
  const back = `<button class="btn btn-secondary" data-action="setConfigApiTab" data-arg0="attestation" data-arg1="${esc(apiId)}">&#x2190; ${esc(t('back'))}</button>`;
  try {
    const res = await apiFetch(`${attestBase(apiId)}/devices/${encodeURIComponent(deviceId)}`);
    const raw = await res.json().catch(() => null);
    if (!res.ok || !raw || typeof raw !== 'object') {
      content.innerHTML = `<div class="section-header"><div class="section-title-main">${esc(deviceId)}</div>${back}</div>
        <div class="card"><div class="empty-msg">${esc(res.status === 404 ? t('attDeviceNotFound') : t('attDevicesLoadError', res.status))}</div></div>`;
      return;
    }
    const dev = attestDev(raw);
    const report = dev.report || (typeof raw.lastReport === 'string' ? parseJsonText(raw.lastReport) : null);
    const kv = (obj) => {
      const entries = obj && typeof obj === 'object' ? Object.entries(obj) : [];
      if (!entries.length) return `<div class="muted small">${esc(t('attNoBlock'))}</div>`;
      return entries.map(([key, v]) => `<div class="info-row"><span class="info-key">${esc(key)}</span><span class="info-val">${esc(Array.isArray(v) ? v.join(', ') : (v && typeof v === 'object' ? JSON.stringify(v) : String(v ?? '—')))}</span></div>`).join('');
    };
    const flagsPolicy = (_attestPolicy && _attestPolicy.flags) || {};
    const signals = report && report.signals && typeof report.signals === 'object' ? report.signals : null;
    const signalRows = signals ? Object.entries(signals).map(([name, s]) => {
      const raised = !!(s && s.flag);
      const evidence = Array.isArray(s && s.evidence) ? s.evidence : [];
      const level = flagsPolicy[name];
      return `<tr>
          <td class="mono">${esc(name)}</td>
          <td>${raised ? `<span class="attest-badge attest-reject">${esc(t('attRaised'))}</span>` : `<span class="attest-badge attest-pass">${esc(t('attClean'))}</span>`}</td>
          <td>${level ? `<span class="attest-level-tag attest-level-${esc(level)}">${esc(t('attLevel_' + level))}</span>` : '<span class="muted">&#x2014;</span>'}</td>
          <td>${evidence.length ? evidence.map(ev => `<span class="attest-chip">${esc(ev)}</span>`).join(' ') : '<span class="muted">&#x2014;</span>'}</td>
        </tr>`;
    }).join('') : '';
    content.innerHTML = `
      <div class="section-header">
        <div>
          <div class="section-title-main" style="display:flex;align-items:center;gap:8px">&#x1F4F1; <span class="mono">${esc(dev.deviceId || deviceId)}</span> ${attestResultBadge(dev.result)}${!dev.registered ? ` <span class="attest-badge attest-none" title="${esc(t('attUnregisteredHint'))}">${esc(t('attUnregistered'))}</span>` : ''}</div>
          <div class="section-sub">${esc(apiId)} · ARC <span class="mono">${esc(dev.arc || '—')}</span>${dev.policyVersion != null ? ` · ${esc(t('attPolicyVersionShort'))} v${esc(dev.policyVersion)}` : ''}${dev.attestCount != null ? ` · ${esc(t('attAttestCount', dev.attestCount))}` : ''}${dev.sdkVersion ? ` · SDK ${esc(dev.sdkVersion)}` : ''}</div>
        </div>
        <div style="display:flex;gap:8px">
          ${back}
          <span class="refresh-icon" data-action="showAttestationDevice" data-arg0="${esc(apiId)}" data-arg1="${esc(deviceId)}" title="${esc(t('refresh'))}">&#x21bb;</span>
        </div>
      </div>
      <div class="attest-detail-grid">
        <div class="card">
          <div class="card-title">${esc(t('attVerdictTitle'))}</div>
          <div class="info-row"><span class="info-key">${esc(t('attThResult'))}</span><span class="info-val">${attestResultBadge(dev.result)}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attThPlatform'))}</span><span class="info-val">${esc(attestPlatformLabel(dev.platform) || '—')}</span></div>
          <div class="info-row"><span class="info-key">ARC</span><span class="info-val">${esc(dev.arc || '—')}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attReasons'))}</span><span class="info-val">${attestChips(dev.reasons, 'attest-chip-reason')}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attWarnings'))}</span><span class="info-val">${attestChips(dev.warnings, 'attest-chip-warn')}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attThAnnotations'))}</span><span class="info-val">${attestChips(dev.annotations, 'attest-chip-anno')}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attThForce'))}</span><span class="info-val">${dev.forceFail ? esc(t('attForceFail')) : dev.forcePass ? esc(t('attForcePass')) : '—'}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attThFirstSeen'))}</span><span class="info-val">${attestTime(dev.firstSeen)}</span></div>
          <div class="info-row" style="border:none"><span class="info-key">${esc(t('attThLastSeen'))}</span><span class="info-val">${attestTime(dev.lastSeen)}</span></div>
        </div>
        <div class="card">
          <div class="card-title">${esc(t('attKeyTitle'))}</div>
          <div class="info-row"><span class="info-key">${esc(t('attKeyLevel'))}</span><span class="info-val">${esc(dev.keyLevel || '—')}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attKeyAttested'))}</span><span class="info-val">${dev.attested === true ? `<span class="status-healthy">${esc(t('attYes'))}</span>` : dev.attested === false ? `<span class="status-error">${esc(t('attNo'))}</span>` : '—'}</span></div>
          <div class="info-row"><span class="info-key">${esc(t('attKeyReason'))}</span><span class="info-val">${esc(dev.attestReason || '—')}</span></div>
          <div class="info-row" style="border:none"><span class="info-key">${esc(t('attKeyMismatches'))}</span><span class="info-val">${esc(dev.keyMismatches)}${dev.lastKeyMismatchAt ? ` <span class="muted">(${attestTime(dev.lastKeyMismatchAt)})</span>` : ''}</span></div>
          ${dev.revoked ? `<div class="notice notice-danger" style="margin-top:10px">${esc(t('attRevokedNotice'))}</div>` : ''}
          <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-danger btn-sm" data-action="forgetAttestDevice" data-arg0="${esc(apiId)}" data-arg1="${esc(deviceId)}">${esc(t('attForget'))}</button>
          </div>
        </div>
      </div>
      ${attestPlayIntegrityCard(dev)}
      ${attestAppAttestCard(dev)}
      ${report ? `
      <div class="attest-detail-grid">
        <div class="card"><div class="card-title">${esc(t('attAppBlock'))}</div>${kv(report.app)}</div>
        <div class="card"><div class="card-title">${esc(t('attDeviceBlock'))}</div>${kv(report.device)}</div>
      </div>
      <div class="card">
        <div class="card-head">
          <div class="card-title">${esc(t('attSignalsTitle'))}</div>
          <span class="muted small">${report.sdkVersion ? `SDK ${esc(report.sdkVersion)} · ` : ''}${report.reportTime ? attestTime(report.reportTime) : ''}</span>
        </div>
        <div class="card-hint">${esc(t('attSignalsHint'))}</div>
        ${signals ? `<table class="data-table">
          <thead><tr><th>${esc(t('attThFlag'))}</th><th>${esc(t('attThState'))}</th><th>${esc(t('attThPolicy'))}</th><th>${esc(t('attThEvidence'))}</th></tr></thead>
          <tbody>${signalRows}</tbody></table>` : `<div class="empty-msg">${esc(t('attNoBlock'))}</div>`}
        ${dev.verdictProviderName ? `<div class="muted small" style="margin-top:10px">${esc(t('attVerdictProvider'))}: <span class="mono">${esc(dev.verdictProviderName)}</span> · ${esc(t('attVerdictProviderToken'))}</div>` : ''}
      </div>` : `<div class="card"><div class="empty-msg">${esc(t('attNoReport'))}</div>${dev.verdictProviderName ? `<div class="muted small" style="padding:0 0 12px">${esc(t('attVerdictProvider'))}: <span class="mono">${esc(dev.verdictProviderName)}</span></div>` : ''}</div>`}`;
  } catch (e) {
    content.innerHTML = `<div class="section-header"><div class="section-title-main">${esc(deviceId)}</div>${back}</div>
      <div class="card"><div class="empty-msg">${esc(t('error'))}: ${esc(e.message)}</div></div>`;
  }
}

// ── PinVault-Token secrets (global; shown on the signing view) ──

const TOKEN_SECRETS_GUIDE_URL = 'https://github.com/umutcansu/PinVault/blob/main/SERVER_IMPLEMENTATION_GUIDE.md#attestation';
let _tokenSecrets = [];               // last listing, kept off the DOM: copy / reveal work by index
const _tokenSecretRevealed = new Set(); // indexes shown in clear

/** The card shell; loadTokenSecrets() fills #token-secrets-body afterwards. */
function renderTokenSecretsCard() {
  return `<div class="card" id="token-secrets-card">
      <div class="card-head">
        <div class="card-title">${esc(t('tokenSecretsTitle'))}</div>
        <button class="btn btn-warning btn-sm" data-action="rotateTokenSecret">${esc(t('tokenSecretsRotate'))}</button>
      </div>
      <div class="card-hint">${esc(t('tokenSecretsHint'))}</div>
      <div class="notice notice-info">${esc(t('tokenSecretsVerifyNote'))}
        <a href="${TOKEN_SECRETS_GUIDE_URL}" target="_blank" rel="noopener noreferrer">SERVER_IMPLEMENTATION_GUIDE.md#attestation</a></div>
      <div id="token-secrets-body"><div class="loading">${t('loading')}</div></div>
    </div>`;
}

/** One secret of the listing, with the names of ATTESTATION.md §5 and the obvious alternatives. */
function tokenSecretEntry(s) {
  return {
    kid: s.kid ?? s.id ?? '',
    createdAt: s.createdAt ?? s.created ?? null,
    active: !!s.active,
    secret: s.secret ?? s.value ?? null
  };
}

/**
 * GET /api/v1/attestation/token-secrets — a secret read, so under two-person
 * approval it answers 202 (requester-run): the GET is repeated once approved.
 */
async function loadTokenSecrets() {
  if (!document.getElementById('token-secrets-body')) return;
  // The element is resolved AFTER each await: renderConfigApiDetail rewrites
  // #content (same ids) once the signing tab has rendered, which detaches any
  // reference taken before the fetch (see loadEnrollmentTokens).
  const body = () => document.getElementById('token-secrets-body');
  const show = (html) => { const el = body(); if (el) el.innerHTML = html; };
  try {
    const res = await apiFetch('/api/v1/attestation/token-secrets');
    if (res.status === 202) {
      const p = await res.json().catch(() => null);
      if (p && p.pendingApproval) notePendingApproval(p);
      show(`<div class="notice notice-warn">${esc(t('tokenSecretsPending', p && p.changeRequestId != null ? '#' + p.changeRequestId : ''))}</div>
        <button class="btn btn-secondary btn-sm" data-action="loadTokenSecrets">${esc(t('tokenSecretsRetry'))}</button>`);
      return;
    }
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      show(`<div class="empty-msg">${esc(res.status === 404 ? t('attNotServed') : t('tokenSecretsLoadError', res.status))}</div>`);
      return;
    }
    const list = Array.isArray(data) ? data : (data && (data.secrets || data.items)) || [];
    _tokenSecrets = (Array.isArray(list) ? list : []).map(tokenSecretEntry);
    _tokenSecretRevealed.clear();
    show(renderTokenSecretsTable());
  } catch (e) {
    show(`<div class="empty-msg">${esc(t('error'))}</div>`);
  }
}

function renderTokenSecretsTable() {
  if (!_tokenSecrets.length) return `<div class="empty-msg">${esc(t('tokenSecretsNone'))}</div>`;
  const rows = _tokenSecrets.map((s, i) => {
    const shown = _tokenSecretRevealed.has(i);
    const secretCell = s.secret
      ? `<span class="mono small">${shown ? esc(s.secret) : '&#x2022;'.repeat(24)}</span>
         <button class="copy-btn" data-action="toggleTokenSecretReveal" data-arg0="${i}">${esc(shown ? t('tokenSecretHide') : t('tokenSecretReveal'))}</button>
         <button class="copy-btn" data-action="copyTokenSecret" data-arg0="${i}">${esc(t('copy'))}</button>`
      : `<span class="muted">${esc(t('tokenSecretHidden'))}</span>`;
    return `<tr>
        <td class="mono">${esc(s.kid)}</td>
        <td class="muted nowrap small">${attestTime(s.createdAt)}</td>
        <td>${s.active ? `<span class="attest-badge attest-pass">${esc(t('tokenSecretActive'))}</span>` : `<span class="attest-badge attest-none">${esc(t('tokenSecretPrevious'))}</span>`}</td>
        <td class="attest-secret-cell">${secretCell}</td>
        <td>${s.active ? '' : `<button class="btn btn-danger btn-sm" data-action="deleteTokenSecret" data-arg0="${esc(s.kid)}">${esc(t('tokenSecretDelete'))}</button>`}</td>
      </tr>`;
  }).join('');
  return `<table class="data-table">
      <thead><tr><th>kid</th><th>${esc(t('thCreated'))}</th><th>${esc(t('thStatus'))}</th><th>${esc(t('tokenSecretValue'))}</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function toggleTokenSecretReveal(idx) {
  const i = parseInt(idx, 10);
  if (_tokenSecretRevealed.has(i)) _tokenSecretRevealed.delete(i); else _tokenSecretRevealed.add(i);
  const body = document.getElementById('token-secrets-body');
  if (body) body.innerHTML = renderTokenSecretsTable();
}

function copyTokenSecret(idx) {
  const s = _tokenSecrets[parseInt(idx, 10)];
  if (s && s.secret) copyText(s.secret);
}

/** POST /api/v1/attestation/token-secrets/rotate — a new active secret; the old ones stay for verification (gated). */
async function rotateTokenSecret() {
  if (!confirm(t('tokenSecretsRotateConfirm'))) return;
  try {
    const res = await apiFetch('/api/v1/attestation/token-secrets/rotate', { method: 'POST' });
    if (res.status === 202) return;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.message || data.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000); return; }
    toast(t('tokenSecretsRotated', data.kid || '?'), 'success');
    loadTokenSecrets();
  } catch (e) { toast(t('error'), 'error'); }
}

/** DELETE /api/v1/attestation/token-secrets/{kid} — drops a previous secret; tokens signed with it stop verifying (gated). */
async function deleteTokenSecret(kid) {
  if (!confirm(t('tokenSecretsDeleteConfirm', kid))) return;
  try {
    const res = await apiFetch(`/api/v1/attestation/token-secrets/${encodeURIComponent(kid)}`, { method: 'DELETE' });
    if (res.status === 202) return;
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { toast(data.message || data.error || `${t('error')} (HTTP ${res.status})`, 'error', 6000); return; }
    toast(t('tokenSecretsDeleted', data.deleted || kid), 'success');
    loadTokenSecrets();
  } catch (e) { toast(t('error'), 'error'); }
}
