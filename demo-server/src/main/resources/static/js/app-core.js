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
