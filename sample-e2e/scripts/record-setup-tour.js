#!/usr/bin/env node
// Panelde kurulum turu: gerçek dashboard'u geçici test sunucusunda (lib/freshHost)
// adım adım sürer ve ekran kaydı alır. Her adımda tıklanan öğe vurgulanır,
// sahte bir imleç oraya gider, altta bir alt yazı "burada şunu yapıyoruz,
// çünkü…" der (scripts/setup-tour-captions.js, TR ve EN). Çıktı: webm →
// ffmpeg → mp4 + poster, docs/animation altına.
//
//   E2E_FRESH_PORT_BASE=6950 node scripts/record-setup-tour.js            # tr + en
//   E2E_FRESH_PORT_BASE=6950 node scripts/record-setup-tour.js --lang en  # yalnızca en
//   --keep-host   kayıt bitince geçici sunucuyu silme (yeniden kayıt hızlı olsun)
//   --fresh       her dil için sunucuyu sıfırdan kur (önceki kaydın token'ı, host'u görünmesin)
//   --out <dir>   mp4'lerin yazılacağı dizin (varsayılan ../docs/animation)
//   --zoom <n>    panelin büyütme oranı (varsayılan 1.35: 12–13 px'lik panel yazısı videoda okunsun)
//
// mp4'ün yanına <ad>.chapters.vtt yazılır: her bölümün başladığı saniye (films.html
// bunu videonun altında tıklanır bölüm listesi olarak gösterir).
//
// Telefon gerekmez; Docker gerekir (geçici sunucu ilk kurulumda 3–5 dk derlenir).
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { chromium } = require('@playwright/test');
const fresh = require('../lib/freshHost');
const CAPTIONS = require('./setup-tour-captions');

const args = process.argv.slice(2);
const flag = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const LANGS = flag('--lang', 'tr,en').split(',').map((s) => s.trim()).filter(Boolean);
const OUT_DIR = path.resolve(flag('--out', path.join(__dirname, '../../docs/animation')));
const KEEP_HOST = args.includes('--keep-host');
const FRESH_EACH = args.includes('--fresh');
const FILE_NAMES = { tr: 'pinvault-panelde-kurulum.tr', en: 'pinvault-setup-in-the-dashboard.en' };
const SIZE = { width: 1440, height: 900 };
const ZOOM = Number(flag('--zoom', '1.35'));
const DEMO_HOST = 'api.example.com';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const randomPin = () => crypto.randomBytes(32).toString('base64');

// ── Sayfaya enjekte edilen tur katmanı ───────────────────────────────────────
// Alt yazı, vurgu halkası (etrafı karartır), imleç ve tam ekran kart. Sayfa
// #content'i sık sık yeniden çizdiği için hepsi body'ye bağlıdır. Panelin kendisi
// (body'nin tour-* olmayan çocukları) CSS zoom ile büyütülür; katman büyütülmez,
// getBoundingClientRect zaten görünen koordinatları verir, hesap gerekmez.
const OVERLAY = `(() => {
  const ZOOM = ${ZOOM};
  const CSS = \`
    body > .app{height:calc(100vh / ${ZOOM}) !important} /* zoom altında 100vh viewport'u aşar */
    #tour-dim{position:fixed;inset:0;background:rgba(2,6,23,.34);z-index:2147483000;pointer-events:none;opacity:0;transition:opacity .35s}
    #tour-dim.on{opacity:1}
    #tour-ring{position:fixed;border:3px solid #f59e0b;border-radius:10px;box-shadow:0 0 0 4px rgba(245,158,11,.25),0 0 30px rgba(245,158,11,.35);z-index:2147483001;pointer-events:none;opacity:0;transition:all .45s cubic-bezier(.2,.8,.2,1)}
    #tour-ring.on{opacity:1}
    #tour-cursor{position:fixed;width:22px;height:22px;border-radius:50%;background:rgba(245,158,11,.95);border:2px solid #fff;box-shadow:0 2px 10px rgba(0,0,0,.5);transform:translate(-50%,-50%);z-index:2147483003;pointer-events:none;opacity:0;transition:left .65s cubic-bezier(.3,.7,.2,1),top .65s cubic-bezier(.3,.7,.2,1),opacity .3s}
    #tour-cursor.on{opacity:1}
    #tour-cursor::after{content:"";position:absolute;inset:-4px;border-radius:50%;border:2px solid #f59e0b;opacity:0}
    #tour-cursor.click::after{animation:tour-ripple .5s ease-out}
    @keyframes tour-ripple{0%{transform:scale(.6);opacity:.9}100%{transform:scale(2.4);opacity:0}}
    #tour-caption{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(12px);max-width:1040px;width:calc(100% - 320px);background:rgba(15,23,42,.94);color:#f1f5f9;font:500 21px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:14px 22px;border-radius:12px;border-left:5px solid #f59e0b;box-shadow:0 12px 40px rgba(0,0,0,.55);z-index:2147483002;opacity:0;transition:opacity .3s,transform .3s;pointer-events:none;letter-spacing:.1px}
    #tour-caption.on{opacity:1;transform:translateX(-50%) translateY(0)}
    #tour-caption b{color:#fbbf24}
    #tour-card{position:fixed;inset:0;background:radial-gradient(1200px 700px at 30% 20%,#172554 0%,#0b1220 60%);z-index:2147483004;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:80px;opacity:0;pointer-events:none;transition:opacity .6s;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
    #tour-card.on{opacity:1}
    #tour-card .tc-logo{font-size:64px;margin-bottom:18px}
    #tour-card .tc-title{font-size:50px;font-weight:800;color:#f8fafc;letter-spacing:-.5px}
    #tour-card .tc-sub{font-size:24px;line-height:1.5;color:#cbd5e1;max-width:980px;margin-top:22px}
    #tour-card .tc-foot{position:absolute;bottom:40px;font-size:16px;color:#64748b;letter-spacing:.4px}
    #tour-alert{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:2000;display:none;align-items:center;justify-content:center;padding:16px}
    #tour-alert.on{display:flex}
    #tour-alert .ta-box{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;max-width:680px;width:100%;box-shadow:0 10px 40px rgba(0,0,0,.5);color:#e2e8f0;font:18px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;white-space:pre-wrap;word-break:break-all}
    #tour-alert .ta-actions{display:flex;justify-content:flex-end;margin-top:14px}
    #tour-alert-ok{background:#6366f1;color:#fff;border:0;border-radius:8px;padding:10px 22px;font-size:16px;font-weight:600;cursor:pointer}
  \`;
  let currentSel = null;
  function zoomApp() {
    if (!document.body || ZOOM === 1) return;
    for (const el of document.body.children) {
      if (el.id && el.id.startsWith('tour-')) continue;
      if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE') continue;
      if (el.style.zoom !== String(ZOOM)) el.style.zoom = String(ZOOM);
    }
  }
  function ensure() {
    zoomApp();
    if (document.getElementById('tour-style') || !document.body) return;
    const style = document.createElement('style'); style.id = 'tour-style'; style.textContent = CSS; document.head.appendChild(style);
    for (const id of ['tour-dim', 'tour-ring', 'tour-cursor', 'tour-caption', 'tour-card', 'tour-alert']) {
      const d = document.createElement('div'); d.id = id; document.body.appendChild(d);
    }
    // Tarayıcının yerel alert()'i kayda girmez: aynı metni sayfa içi bir kutuda göster.
    window.alert = (msg) => {
      const a = document.getElementById('tour-alert');
      a.innerHTML = '<div class="ta-box"><div class="ta-text"></div><div class="ta-actions"><button id="tour-alert-ok" type="button">OK</button></div></div>';
      a.querySelector('.ta-text').textContent = String(msg);
      a.querySelector('#tour-alert-ok').addEventListener('click', () => a.classList.remove('on'));
      a.classList.add('on');
    };
    window.addEventListener('scroll', () => { if (currentSel) place(currentSel); }, true);
    window.addEventListener('resize', () => { if (currentSel) place(currentSel); });
  }
  function place(sel) {
    zoomApp();
    const ring = document.getElementById('tour-ring'), dim = document.getElementById('tour-dim');
    const el = sel && document.querySelector(sel);
    if (!el) { ring.classList.remove('on'); dim.classList.remove('on'); dim.style.clipPath = ''; return false; }
    const b = el.getBoundingClientRect(), p = 7;
    const l = b.left - p, t = b.top - p, r = b.right + p, btm = b.bottom + p;
    Object.assign(ring.style, { left: l + 'px', top: t + 'px', width: (r - l) + 'px', height: (btm - t) + 'px' });
    dim.style.clipPath = 'polygon(0 0,0 100%,' + l + 'px 100%,' + l + 'px ' + t + 'px,' + r + 'px ' + t + 'px,' + r + 'px ' + btm + 'px,' + l + 'px ' + btm + 'px,' + l + 'px 100%,100% 100%,100% 0)';
    ring.classList.add('on'); dim.classList.add('on');
    return true;
  }
  window.__tour = {
    caption(text) { ensure(); const c = document.getElementById('tour-caption'); if (!text) { c.classList.remove('on'); return; } c.innerHTML = text; c.classList.add('on'); },
    highlight(sel) { ensure(); currentSel = sel || null; return place(sel); },
    cursor(x, y, click) { ensure(); const c = document.getElementById('tour-cursor'); c.style.left = x + 'px'; c.style.top = y + 'px'; c.classList.add('on'); if (click) { c.classList.remove('click'); void c.offsetWidth; c.classList.add('click'); } },
    hideCursor() { ensure(); document.getElementById('tour-cursor').classList.remove('on'); },
    card(title, sub, foot) { ensure(); const k = document.getElementById('tour-card'); if (!title) { k.classList.remove('on'); return; } k.innerHTML = '<div class="tc-logo">&#x1F512;</div><div class="tc-title"></div><div class="tc-sub"></div><div class="tc-foot"></div>'; k.querySelector('.tc-title').textContent = title; k.querySelector('.tc-sub').textContent = sub || ''; k.querySelector('.tc-foot').textContent = foot || ''; k.classList.add('on'); },
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ensure); else ensure();
})();`;

// ── Tur yardımcıları ─────────────────────────────────────────────────────────
function readTime(text) {
  // Okuma payı: karakter başına ~48 ms, 3.5–10 s arası.
  return Math.min(10000, Math.max(3500, 1800 + text.length * 48));
}

class Tour {
  constructor(page, T) {
    this.page = page;
    this.T = T;
  }

  async say(key, holdMs) {
    const text = this.T[key];
    if (!text) throw new Error(`alt yazı yok: ${key}`);
    const html = text.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]).replace(/"([^"]+)"/g, '<b>"$1"</b>');
    await this.page.evaluate((t) => window.__tour.caption(t), html);
    await sleep(holdMs ?? readTime(text));
  }

  async quiet() {
    await this.page.evaluate(() => { window.__tour.caption(''); window.__tour.highlight(null); });
    await sleep(350);
  }

  async card(titleKey, subKey, foot, holdMs) {
    await this.page.evaluate(([t, s, f]) => window.__tour.card(t, s, f), [this.T[titleKey], this.T[subKey], foot || '']);
    await sleep(holdMs);
  }

  async cardOff() {
    await this.page.evaluate(() => window.__tour.card(''));
    await sleep(700);
  }

  loc(selector) {
    return this.page.locator(selector).first();
  }

  async scrollTo(selector) {
    const loc = this.loc(selector);
    await loc.waitFor({ state: 'visible', timeout: 30_000 });
    await loc.evaluate((el) => el.scrollIntoView({ behavior: 'smooth', block: 'center' }));
    await sleep(750);
    return loc;
  }

  /** Öğeyi ortaya kaydırır ve vurgular. */
  async focus(selector) {
    await this.scrollTo(selector);
    const ok = await this.page.evaluate((s) => window.__tour.highlight(s), selector);
    if (!ok) throw new Error(`vurgulanacak öğe yok: ${selector}`);
    await sleep(400);
  }

  /** İmleci öğeye götürür, tıklar. */
  async click(selector, { highlight = true } = {}) {
    const loc = await this.scrollTo(selector);
    if (highlight) await this.page.evaluate((s) => window.__tour.highlight(s), selector);
    const b = await loc.boundingBox();
    if (!b) throw new Error(`öğenin kutusu yok: ${selector}`);
    const x = b.x + b.width / 2, y = b.y + b.height / 2;
    await this.page.evaluate(([px, py]) => window.__tour.cursor(px, py, false), [x, y]);
    await sleep(800);
    await this.page.evaluate(([px, py]) => window.__tour.cursor(px, py, true), [x, y]);
    await sleep(180);
    await loc.click();
    await sleep(500);
  }

  async type(selector, text, delay = 55) {
    await this.click(selector);
    await this.loc(selector).pressSequentially(text, { delay });
    await sleep(400);
  }

  async hideCursor() {
    await this.page.evaluate(() => window.__tour.hideCursor());
  }
}

// ── Turun kendisi ────────────────────────────────────────────────────────────
async function record(lang, workDir) {
  const T = CAPTIONS[lang];
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: SIZE,
    deviceScaleFactor: 1,
    colorScheme: 'dark',
    locale: lang === 'tr' ? 'tr-TR' : 'en-US',
    recordVideo: { dir: workDir, size: SIZE },
  });
  await context.addInitScript((l) => {
    try { localStorage.setItem('pinvault_lang', l); } catch (_) { /* yoksa varsayılan */ }
  }, lang);
  await context.addInitScript(OVERLAY);
  const page = await context.newPage();
  const t0 = Date.now(); // kayıt sayfayla başlar: bölüm zamanları buna göre
  page.on('dialog', (d) => d.accept());
  const tour = new Tour(page, T);
  const chapters = [];
  const step = (label, chapterKey) => {
    process.stdout.write(`  [${lang}] ${label}\n`);
    if (chapterKey) {
      if (!T.chapters[chapterKey]) throw new Error(`bölüm adı yok: ${chapterKey}`);
      chapters.push({ at: (Date.now() - t0) / 1000, title: T.chapters[chapterKey] });
    }
  };
  let failure = null;
  let webm = null;

  try {
    // Açılış kartı: panelin üstünde (boş sayfadaki kareler kayda girmiyor);
    // kart kalkınca altından API anahtarı penceresi çıkar.
    step('adres + API anahtarı', 'start');
    await page.goto(fresh.WEB_URL + '/', { waitUntil: 'domcontentloaded' });
    await page.evaluate(OVERLAY);
    await tour.card('title', 'subtitle', 'PinVault', 6000);
    await tour.loc('#pv-input-dialog-input').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.cardOff();
    await tour.say('openUrl');
    await tour.focus('#pv-input-dialog');
    await tour.say('apiKey');
    await tour.type('#pv-input-dialog-input', fresh.apiKey(), 28);
    await tour.click('#pv-input-dialog-ok');
    await tour.loc('#host-list .api-header').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.quiet();

    // 2. Kenar çubuğu.
    step('kenar çubuğu');
    await tour.focus('#host-list');
    await tour.say('sidebar');
    await tour.quiet();

    // 3. Sihirbaz, 1 · Sunucu.
    step('sihirbaz: sunucu', 'server');
    await tour.click('#nav-setup');
    await tour.loc('#setup-order').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.focus('#setup-view .tab-bar');
    await tour.say('wizardIntro');
    await tour.focus('#setup-order');
    await tour.say('order');
    await tour.focus('#setup-view .card:has(> table.data-table)');
    await tour.say('checks');
    await tour.quiet();

    // 4. Nasıl yapılır (.env'den değişen satır).
    step('nasıl yapılır: signers', 'howto');
    await tour.click('tr[data-setup-check="signers"] [data-action="toggleSetupHowto"]');
    await tour.focus('tr.setup-howto[data-setup-howto="server:signers"] ol.howto-steps');
    await tour.say('howto');
    await tour.focus('tr.setup-howto[data-setup-howto="server:signers"] pre.json-box');
    await tour.say('howtoEnv');
    await tour.click('tr[data-setup-check="signers"] [data-action="toggleSetupHowto"]');
    await tour.quiet();

    // 5. Panelden değişen satır → Ayarlar kartı.
    step('nasıl yapılır: live_check → ayarlar');
    await tour.click('tr[data-setup-check="live_check"] [data-action="toggleSetupHowto"]');
    await tour.focus('tr.setup-howto[data-setup-howto="server:live_check"]');
    await tour.say('howtoPanel');
    await tour.click('[data-action="setupGoSetting"][data-arg0="PIN_LIVE_CHECK"]');
    await sleep(900);
    await tour.focus('#setting-PIN_LIVE_CHECK');
    await tour.say('settingsCard');
    await tour.focus('[data-action="saveServerSettings"]');
    await tour.say('settingsSave');
    await tour.quiet();

    // 6. 2 · Sertifikalar.
    step('sihirbaz: sertifikalar', 'certs');
    await tour.click('#setup-view .tab-bar [data-action="setSetupStep"][data-arg0="certs"]');
    await tour.loc('#setup-certs-config-api').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.say('certsIntro');
    await tour.focus('#setup-certs-config-api');
    await tour.say('certsOurs');
    await tour.focus('#setup-certs-mtls');
    await tour.say('certsMtls');
    await tour.focus('#setup-certs-hosts');
    await tour.say('certsHosts');
    await tour.quiet();

    // 7. Sunucunun üretim sertifikası: Bootstrap sekmesi.
    step('bootstrap sekmesi', 'bootstrap');
    await tour.click('#host-list [data-action="toggleApiTree"][data-arg0="default-tls"]');
    await tour.click('button.tab-btn[data-action="setConfigApiTab"][data-arg0="bootstrap"][data-arg1="default-tls"]');
    await tour.loc('[data-action="regenerateBootstrapCert"]').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.say('bootstrapWhere');
    await tour.focus('#content .card:has(.hash-box)');
    await tour.say('bootstrapPins');
    await tour.focus('[data-action="regenerateBootstrapCert"]');
    await tour.say('bootstrapRenew');
    await tour.click('[data-action="toggleBootstrapUpload"]');
    await tour.focus('#bootstrap-upload-form');
    await tour.say('bootstrapUpload');
    await tour.click('[data-action="toggleBootstrapUpload"]', { highlight: false });
    await tour.quiet();

    // 8. Kendi API sunucunuz: yeni host.
    step('yeni host', 'host');
    await tour.click('#host-list [data-action="showAddHostScoped"][data-arg0="default-tls"]');
    await tour.loc('[data-action="switchAddTab"][data-arg0="fetch"]').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.say('addHostIntro', 3500);
    await tour.click('[data-action="switchAddTab"][data-arg0="fetch"]');
    await tour.type('#fetch-url', 'https://' + DEMO_HOST);
    await tour.say('fetchUrl');
    await tour.focus('#fetch-backup-pin');
    await tour.say('backupPin');
    await tour.click('[data-action="switchAddTab"][data-arg0="manual"]');
    await tour.type('#add-hostname', DEMO_HOST);
    await tour.type('#add-hash-0', randomPin(), 8);
    await tour.type('#add-hash-1', randomPin(), 8);
    await tour.focus('#content .card');
    await tour.say('manual');
    await tour.click('[data-action="createHostManual"]');
    await tour.loc(`#host-list .host-item[data-arg0="${DEMO_HOST}"]`).waitFor({ state: 'visible', timeout: 30_000 });
    await tour.focus(`#host-list .host-item[data-arg0="${DEMO_HOST}"]`);
    await tour.say('hostAdded');
    await tour.quiet();

    // 9. Cihaz kimliği: kayıt token'ı.
    step('mTLS token', 'token');
    await tour.click('#host-list [data-action="toggleApiTree"][data-arg0="sample-mtls"]');
    await tour.click('button.tab-btn[data-action="setConfigApiTab"][data-arg0="mtls"][data-arg1="sample-mtls"]');
    await tour.loc('#enrollment-client-id').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.focus('#content .card:has(#enrollment-client-id)');
    await tour.say('mtlsIntro');
    await tour.type('#enrollment-client-id', T.clientId);
    await tour.click('form[data-action-submit="generateEnrollmentToken"] button[type="submit"]');
    await tour.loc('#tour-alert .ta-box').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.focus('#tour-alert .ta-box');
    await tour.say('tokenOnce');
    await tour.click('#tour-alert-ok');
    await tour.quiet();

    // 10. 3 · Uygulama.
    step('sihirbaz: uygulama', 'app');
    await tour.click('#nav-setup');
    await tour.loc('#setup-view .tab-bar').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.click('#setup-view .tab-bar [data-action="setSetupStep"][data-arg0="app"]');
    await tour.loc('select[data-arg0="apiId"]').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.say('appIntro');
    await tour.click('select[data-arg0="apiId"]');
    await page.selectOption('select[data-arg0="apiId"]', 'sample-mtls');
    await sleep(600);
    await tour.focus('select[data-arg0="apiId"]');
    await tour.say('appApi');
    await tour.focus('#setup-view .card:has(input[type="checkbox"])');
    await tour.say('appBoxes');
    await tour.quiet();

    // 11. 4 · Kod.
    step('sihirbaz: kod', 'code');
    await tour.click('#setup-view .tab-bar [data-action="setSetupStep"][data-arg0="code"]');
    await tour.loc('#setup-next-steps').waitFor({ state: 'visible', timeout: 30_000 });
    await tour.focus('#setup-view pre.json-box');
    await tour.say('codeIntro');
    await tour.focus('[data-action="copySetupText"][data-arg0="code"]');
    await tour.say('codeCopy');
    await tour.focus('#setup-next-steps');
    await tour.say('nextSteps');
    await tour.quiet();
    await tour.hideCursor();

    // Kapanış kartı.
    await tour.card('endTitle', 'endSub', 'github.com/umutcansu/PinVault · SETUP.md', 6500);
  } catch (e) {
    failure = e;
  } finally {
    await context.close();
    const video = page.video();
    webm = video ? await video.path() : null;
    await browser.close();
  }
  if (failure) {
    process.exitCode = 1;
    if (webm) console.error(`Yarım kalan kayıt: ${webm}`);
    throw failure;
  }
  if (!webm) throw new Error('video dosyası yok');
  return { webm, chapters };
}

function writeChapters(file, chapters, duration) {
  const ts = (s) => {
    s = Math.max(0, s);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = (s % 60).toFixed(3).padStart(6, '0');
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${sec}`;
  };
  const lines = ['WEBVTT', ''];
  chapters.forEach((c, i) => {
    const end = i + 1 < chapters.length ? chapters[i + 1].at : duration;
    lines.push(String(i + 1), `${ts(c.at)} --> ${ts(end)}`, c.title, '');
  });
  fs.writeFileSync(file, lines.join('\n'));
}

function toMp4(webm, mp4, poster) {
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', webm, '-c:v', 'libx264', '-preset', 'slow', '-crf', '23', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-an', mp4]);
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', '2.5', '-i', mp4, '-frames:v', '1', '-q:v', '3', poster]);
}

async function removeDemoHost() {
  const cfg = await fresh.api('/api/v1/certificate-config?signed=false', { withKey: false });
  const keep = (cfg.json?.pins || []).filter((p) => p.hostname !== DEMO_HOST);
  if (keep.length !== (cfg.json?.pins || []).length) {
    await fresh.api('/api/v1/certificate-config', { method: 'PUT', body: { version: 0, forceUpdate: false, pins: keep } });
  }
}

(async () => {
  for (const lang of LANGS) if (!CAPTIONS[lang]) throw new Error(`dil yok: ${lang}`);
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.mkdirSync(path.join(OUT_DIR, 'posters'), { recursive: true });
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pinvault-tour-'));
  if (FRESH_EACH) await fresh.destroy();
  process.stdout.write(`Geçici sunucu hazırlanıyor (${fresh.WEB_URL})…\n`);
  await fresh.ensure();
  try {
    for (const [i, lang] of LANGS.entries()) {
      if (FRESH_EACH && i > 0) {
        process.stdout.write('Geçici sunucu sıfırlanıyor…\n');
        await fresh.destroy();
        await fresh.ensure();
      }
      await removeDemoHost();
      process.stdout.write(`Kayıt: ${lang}\n`);
      const started = Date.now();
      const { webm, chapters } = await record(lang, workDir);
      const base = FILE_NAMES[lang];
      const mp4 = path.join(OUT_DIR, base + '.mp4');
      const poster = path.join(OUT_DIR, 'posters', base + '.jpg');
      toMp4(webm, mp4, poster);
      const duration = Number(execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', mp4], { encoding: 'utf8' }).trim());
      writeChapters(path.join(OUT_DIR, base + '.chapters.vtt'), chapters, duration);
      process.stdout.write(`  → ${mp4} (${Math.round(duration)} s, ${chapters.length} bölüm; kayıt ${Math.round((Date.now() - started) / 1000)} s)\n`);
    }
  } finally {
    await removeDemoHost().catch(() => {});
    if (process.exitCode) process.stdout.write(`Çalışma dizini bırakıldı: ${workDir}\n`);
    else fs.rmSync(workDir, { recursive: true, force: true });
    if (!KEEP_HOST) {
      process.stdout.write('Geçici sunucu siliniyor…\n');
      await fresh.destroy();
    }
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
