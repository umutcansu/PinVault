// PinVault dashboard — Admin identity, approvals, audit log, live certificate check and small utilities.
// Classic scripts sharing one global scope, loaded in order by index.html.

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
