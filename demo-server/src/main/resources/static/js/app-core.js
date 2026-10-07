// PinVault dashboard — Shared state, HTML escaping and API key handling.
// Classic scripts sharing one global scope, loaded in order by index.html.

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
// The admin key lives in sessionStorage: it is gone when the tab is closed,
// and a page opened later in this browser cannot read it. It used to be kept
// in localStorage, where it stayed for good; a copy left there by an earlier
// version of this page is moved over once and deleted.
const API_KEY_STORE = 'pinvault_api_key';
function migrateStoredApiKey() {
    try {
        const old = localStorage.getItem(API_KEY_STORE);
        if (old === null) return;
        if (old && !sessionStorage.getItem(API_KEY_STORE)) sessionStorage.setItem(API_KEY_STORE, old);
        localStorage.removeItem(API_KEY_STORE);
    } catch (_) { /* storage blocked: the key is asked for again */ }
}
migrateStoredApiKey();
function getApiKey() {
    try { return sessionStorage.getItem(API_KEY_STORE) || ''; } catch (_) { return ''; }
}
function setApiKey(key) {
    try { sessionStorage.setItem(API_KEY_STORE, key); } catch (_) { /* asked for again next time */ }
}
function clearApiKey() {
    try { sessionStorage.removeItem(API_KEY_STORE); localStorage.removeItem(API_KEY_STORE); } catch (_) { /* nothing stored */ }
}

// ── In-page input dialog (replaces window.prompt) ───────
// window.prompt() is blocked in embedded/automated browsers (and shows a raw
// "prompt() is not supported" error). This is a theme-matched modal that
// resolves to the entered text, or null when cancelled. Enter submits, Esc or
// a click on the backdrop cancels.
function pvInputDialog({ title, message = '', placeholder = '', value = '', type = 'text', okLabel, cancelLabel } = {}) {
    const label = (k, fallback) => {
        try { return typeof t === 'function' ? t(k) : fallback; } catch (_) { return fallback; }
    };
    return new Promise((resolve) => {
        const existing = document.getElementById('pv-input-dialog');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'pv-input-dialog';
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:2000;display:flex;align-items:center;justify-content:center;padding:16px;';
        const box = document.createElement('div');
        box.style.cssText = 'background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;max-width:440px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,.5);';
        const h = document.createElement('div');
        h.textContent = title || '';
        h.style.cssText = 'font-size:15px;font-weight:600;color:#f1f5f9;margin-bottom:8px;';
        box.appendChild(h);
        if (message) {
            const m = document.createElement('div');
            m.textContent = message;
            m.style.cssText = 'font-size:12px;color:#94a3b8;margin-bottom:14px;white-space:pre-wrap;word-break:break-word;';
            box.appendChild(m);
        }
        const input = document.createElement('input');
        input.type = type;
        input.placeholder = placeholder;
        input.value = value;
        input.autocomplete = 'off';
        input.style.cssText = 'width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 12px;color:#f1f5f9;font-size:13px;margin-bottom:16px;';
        box.appendChild(input);
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;';
        const cancel = document.createElement('button');
        cancel.type = 'button';
        cancel.textContent = cancelLabel || label('cancel', 'İptal');
        cancel.style.cssText = 'padding:8px 16px;border:1px solid #334155;border-radius:8px;background:transparent;color:#94a3b8;font-size:13px;cursor:pointer;';
        const ok = document.createElement('button');
        ok.type = 'button';
        ok.textContent = okLabel || label('save', 'Kaydet');
        ok.style.cssText = 'padding:8px 16px;border:1px solid #3b82f6;border-radius:8px;background:#3b82f6;color:#fff;font-size:13px;cursor:pointer;';
        row.appendChild(cancel);
        row.appendChild(ok);
        box.appendChild(row);
        overlay.appendChild(box);
        document.body.appendChild(overlay);
        input.focus();

        let done = false;
        const close = (val) => {
            if (done) return;
            done = true;
            document.removeEventListener('keydown', onKey, true);
            overlay.remove();
            resolve(val);
        };
        const onKey = (e) => {
            if (e.key === 'Enter') { e.preventDefault(); close(input.value); }
            else if (e.key === 'Escape') { e.preventDefault(); close(null); }
        };
        ok.addEventListener('click', () => close(input.value));
        cancel.addEventListener('click', () => close(null));
        overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) close(null); });
        document.addEventListener('keydown', onKey, true);
    });
}

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
    // X-PinVault-Admin: a header no cross-site form can add. The server refuses
    // admin writes that are neither JSON nor marked like this (CSRF).
    init.headers = { ...init.headers, 'X-PinVault-Admin': '1' };
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
        const newKey = await pvInputDialog({
            title: t('apiKeyDialogTitle'),
            message: t('apiKeyDialogMessage'),
            placeholder: 'X-API-Key',
            type: 'password',
        });
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
                const reason = await pvInputDialog({
                    title: t('liveCheckFailedHeader'),
                    message: '• ' + failures.join('\n• ') + '\n\n' + t('liveCheckOverrideHint'),
                    placeholder: t('liveCheckReasonPlaceholder'),
                });
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
