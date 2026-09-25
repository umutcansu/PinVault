// Her koşudan sonra evidence/index.html üretir: en üstte kısa bir "nasıl
// okunur" notu ve kapsam matrisi (özellik → senaryo → Geçti/Kaldı), sonra
// sabit grup sırasıyla (K, A, B, C, D, E, F, G, H, S, Y) senaryolar; senaryo
// başına adımlar ve her adımın web (🌐) ile telefon (📱) ekran görüntüleri,
// metin panelleri (📄: terminal, ağ trafiği, cihaz dosyası), sonuç ve süre. Tek
// dosyadır, görüntüler gömülüdür; başka bir şeye ihtiyaç duymadan açılır ve
// paylaşılabilir. macOS'ta görüntüler sips ile küçültülüp JPEG'e çevrilir.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const state = require('./state');
const env = require('./env');
const { GROUPS, FEATURES } = require('./coverage');

const HAS_SIPS = process.platform === 'darwin' && fs.existsSync('/usr/bin/sips');
/** Sayfadaki bölüm sırası: Kurulum en başta, sonra PLAN.md'deki grup sırası. */
const GROUP_ORDER = ['K', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'S', 'Y'];

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const stripAnsi = (s) => String(s || '').replace(/\[[0-9;]*m/g, '');
const duration = (ms) =>
  ms >= 60_000 ? `${(ms / 60_000).toFixed(1).replace('.', ',')} dk` : `${(ms / 1000).toFixed(1).replace('.', ',')} sn`;
/**
 * Ek adındaki U+2024 (one dot leader) noktaya çevrilir: Playwright ek adının
 * son noktasından sonrasını dosya uzantısı saydığı için attachmentName
 * noktaları bu karakterle değiştiriyor; sayfada gerçek nokta gösterilir.
 */
const displayName = (s) => String(s).replace(/․/g, '.');

/** Dosya adı önekinden grup harfi: 00 → K, 01–29 → A/F (tests/ altında dosya adı grup harfiyle başlayabilir). */
function groupOf(file) {
  const name = path.basename(file);
  const m = name.match(/^([A-Z])\d*-/i);
  if (m && GROUPS[m[1].toUpperCase()]) return m[1].toUpperCase();
  const num = name.match(/^(\d+)-/);
  if (!num) return 'A';
  const n = Number(num[1]);
  if (n === 0) return 'K';
  if ([6, 7].includes(n)) return 'F';
  if (n === 12) return 'B';
  if ([13, 14, 15].includes(n)) return 'C';
  return 'A';
}

/** Senaryo dosyası bir kapsam satırının önekleriyle eşleşiyor mu. */
function matches(prefix, file) {
  const name = path.basename(file);
  return name.startsWith(`${prefix}-`) || name === `${prefix}.spec.js`;
}

/**
 * Bölüm kimliği: bir dosyadaki ilk test "s-<dosya>", sonrakiler
 * "s-<dosya>-2", … (aynı dosyada iki test olan F01 gibi durumlar için).
 * Matris bağlantıları ilk teste gider; diğerleri de kendi kimliğiyle ulaşılır.
 */
function sectionId(file, ordinal) {
  const base = path.basename(file, '.spec.js');
  return ordinal <= 1 ? `s-${base}` : `s-${base}-${ordinal}`;
}

function pngSize(buf) {
  if (buf.length > 24 && buf.toString('ascii', 12, 16) === 'IHDR') {
    return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
  }
  return { w: 0, h: 0 };
}

/** PNG'yi gömülebilir bir data URL'e çevirir; [phone] görüntünün hedef genişliğini belirler. */
function embed(buf, phone) {
  const { w } = pngSize(buf);
  if (HAS_SIPS) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pv-evidence-'));
    try {
      const src = path.join(dir, 'in.png');
      const out = path.join(dir, 'out.jpg');
      fs.writeFileSync(src, buf);
      const width = phone ? 540 : 1400;
      const args = ['-s', 'format', 'jpeg', '-s', 'formatOptions', '82'];
      if (w > width) args.push('--resampleWidth', String(width));
      execFileSync('/usr/bin/sips', [...args, src, '--out', out], { stdio: 'ignore' });
      return `data:image/jpeg;base64,${fs.readFileSync(out).toString('base64')}`;
    } catch {
      /* küçültülemedi: PNG olarak göm */
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  return `data:image/png;base64,${buf.toString('base64')}`;
}

function body(a) {
  return a.body || (a.path && fs.existsSync(a.path) ? fs.readFileSync(a.path) : null);
}

function imageAttachments(list) {
  return (list || [])
    .filter((a) => a.contentType === 'image/png')
    .map((a) => ({ name: a.name, buf: body(a) }))
    .filter((a) => a.buf);
}

function textAttachments(list) {
  return (list || [])
    .filter((a) => a.contentType && a.contentType.startsWith('text/'))
    .map((a) => ({ name: a.name, text: body(a) }))
    .filter((a) => a.text != null)
    .map((a) => ({ name: a.name, text: a.text.toString('utf8') }));
}

/** Bir adımın ve alt adımlarının ekleri (ekler en içteki adıma bağlanır). */
function stepImages(step) {
  return imageAttachments(step.attachments).concat(...(step.steps || []).map(stepImages));
}

function stepTexts(step) {
  return textAttachments(step.attachments).concat(...(step.steps || []).map(stepTexts));
}

/**
 * Telefon / web sınıfı ek adının önekinden gelir (📱 / 🌐, bkz.
 * dashboard.attachmentName); öneksiz eklerde en-boy oranına bakılır. Uzun
 * tam sayfa web görüntüleri böylece telefon sütununa düşmez.
 */
function isPhone(att) {
  if (att.name.startsWith('📱')) return true;
  if (att.name.startsWith('🌐')) return false;
  const { w, h } = pngSize(att.buf);
  return h > w;
}

function figure(att) {
  const phone = isPhone(att);
  const src = embed(att.buf, phone);
  const name = esc(displayName(att.name));
  return {
    phone,
    html: `<figure class="shot ${phone ? 'phone' : 'web'}"><img src="${src}" alt="${name}" loading="lazy"><figcaption>${name}</figcaption></figure>`,
  };
}

function panel(att) {
  return `<details class="panel" open><summary>${esc(displayName(att.name))}</summary><pre>${esc(att.text)}</pre></details>`;
}

const CSS = `
:root { --bg:#f6f7f9; --card:#fff; --text:#1c2230; --muted:#667085; --line:#e4e7ec; --ok:#12805c; --okbg:#e7f6ef; --bad:#c0362c; --badbg:#fdecea; --warn:#8a5a00; --warnbg:#fff4d6; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1318; --card:#171c23; --text:#e6e9ef; --muted:#9aa4b2; --line:#2a313b; --ok:#3fcf8e; --okbg:#10291e; --bad:#ff7a6e; --badbg:#321715; --warn:#ffcf6e; --warnbg:#33290f; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
main { max-width:1180px; margin:0 auto; padding:32px 16px 64px; }
h1 { font-size:26px; margin:0 0 6px; }
h2.group { font-size:20px; margin:40px 0 0; padding-bottom:6px; border-bottom:2px solid var(--line); }
.meta { color:var(--muted); margin:0 0 16px; }
.summary { display:inline-block; padding:8px 14px; border-radius:8px; font-weight:600; margin-right:8px; }
.summary.ok { background:var(--okbg); color:var(--ok); } .summary.bad { background:var(--badbg); color:var(--bad); }
.howto { margin:16px 0; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:8px 14px; font-size:14px; }
.howto summary { cursor:pointer; font-weight:600; }
.howto ul { margin:8px 0 4px; padding-left:20px; } .howto li { margin:4px 0; }
table.matrix { width:100%; border-collapse:collapse; margin-top:16px; font-size:13px; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden; }
.matrix th, .matrix td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
.matrix th { color:var(--muted); font-weight:600; font-size:12px; }
.matrix td.g { color:var(--muted); white-space:nowrap; }
.matrix a { color:inherit; }
.scenario { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-top:24px; }
.scenario h3 { font-size:18px; margin:0; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.badge { font-size:12px; font-weight:700; padding:3px 9px; border-radius:999px; white-space:nowrap; }
.badge.ok { background:var(--okbg); color:var(--ok); } .badge.bad { background:var(--badbg); color:var(--bad); } .badge.warn { background:var(--warnbg); color:var(--warn); }
.file { color:var(--muted); font-size:13px; margin:4px 0 12px; }
ol.steps { list-style:none; margin:0; padding:0; display:flex; flex-wrap:wrap; gap:14px; align-items:flex-start; }
.step { background:var(--bg); border:1px solid var(--line); border-radius:10px; padding:12px; min-width:0; }
.step.phone { flex:0 0 250px; }
.step.web { flex:1 1 520px; }
.step.text { flex:1 1 100%; }
.step.bad { border-color:var(--bad); }
.step-head { display:flex; gap:8px; align-items:baseline; font-weight:600; font-size:14px; }
.step-head .title { flex:1; }
.step-head .mark { color:var(--ok); } .step.bad .step-head .mark { color:var(--bad); }
.step-head .dur { color:var(--muted); font-weight:400; font-size:12px; white-space:nowrap; }
.error { white-space:pre-wrap; background:var(--badbg); color:var(--bad); padding:10px 12px; border-radius:8px; font:12px/1.4 ui-monospace, Menlo, monospace; margin-top:8px; overflow-x:auto; }
.shots { display:flex; flex-wrap:wrap; gap:10px; margin-top:10px; align-items:flex-start; }
.shot { margin:0; flex:1 1 100%; min-width:0; }
.shot img { display:block; width:100%; height:auto; border-radius:6px; border:1px solid var(--line); cursor:zoom-in; }
.shot figcaption { font-size:12px; color:var(--muted); margin-top:6px; }
.panel { margin-top:10px; border:1px solid var(--line); border-radius:8px; background:var(--card); }
.panel summary { cursor:pointer; padding:6px 10px; font-size:12px; color:var(--muted); }
.panel pre { margin:0; padding:10px 12px; font:12px/1.45 ui-monospace, Menlo, monospace; overflow-x:auto; white-space:pre-wrap; word-break:break-word; max-height:420px; overflow-y:auto; }
@media (max-width:600px) { .step.phone { flex:1 1 100%; } .step.phone .shot img { max-width:260px; } }
dialog { border:0; padding:0; background:transparent; max-width:96vw; max-height:96vh; }
dialog::backdrop { background:rgba(0,0,0,.8); }
dialog img { max-width:96vw; max-height:92vh; display:block; border-radius:8px; }
`;

const ZOOM_JS = `
const zoom = document.getElementById('zoom');
document.addEventListener('click', (e) => {
  if (e.target.matches('.shot img')) { zoom.querySelector('img').src = e.target.src; zoom.showModal(); }
  else if (e.target.closest('dialog')) { zoom.close(); }
});`;

const HOWTO = `<details class="howto"><summary>Nasıl okunur</summary><ul>
  <li><b>Rozetler:</b> <span class="badge ok">Geçti</span> senaryo başarılı; <span class="badge bad">Kaldı</span> başarısız (hata metni ilgili adımın altında, telefonun hata anındaki görüntüsü senaryonun sonunda); <span class="badge warn">Atlandı</span> çalıştırılmadı (ör. yalnızca emülatörde çalışabilen bir adım var). Adım başındaki ✓ / ✗ da aynı anlamdadır.</li>
  <li><b>📱</b> telefonun ekran görüntüsü (adb screencap): sonuç kutusunun altındaki <code>#N · saat</code> etiketi, sonucun hangi denemeye ait olduğunu gösterir. <b>🌐</b> dashboard görüntüsü (tam sayfa, tek kart ya da birkaç kart). <b>📄</b> metin paneli: terminal çıktısı, API yanıtı, ağ trafiğindeki ham veri (hex), cihazdaki dosya (run-as), sunucu günlüğü.</li>
  <li><b>Kapsam matrisi:</b> her satır bir özellik; "Senaryo" sütunundaki bağlantı, o özelliği kanıtlayan senaryonun bölümüne gider. Bir özellik birden fazla senaryoyla kanıtlanabilir; hepsi geçtiyse satır "Geçti" olur.</li>
  <li>Bölümler şu grup sırasıyla gelir: Sıfırdan kurulum; Pin yönetimi ve imzalı config; mTLS (istemci sertifikası); Vault (uzaktan dosya dağıtımı); Telefonda şifreli saklama; Sunucu işletimi; Sunucuya ulaşılamadığında; Araya girme saldırıları; Kendi sunucusuyla ya da sunucusuz kullanım; İmza anahtarlarının korunması (isteğe bağlı); Değişiklik denetimi ve onay (isteğe bağlı). Gizli değerler sayfaya girmez: token'lar, anahtarlar ve parolalar kısaltılmış ya da maskelidir.</li>
</ul></details>`;

class EvidenceReporter {
  constructor(options = {}) {
    this.outputFolder = options.outputFolder || 'evidence';
    this.entries = [];
    this.run = null;
  }

  onBegin() {
    this.startedAt = new Date();
  }

  onTestEnd(test, result) {
    // Global teardown durum dosyasını siler; bilgiyi testler sürerken al.
    if (!this.run) this.run = state.read();
    this.entries.push({ test, result });
  }

  renderScenario({ test, result }, index, ordinal) {
    const ok = result.status === 'passed';
    const skipped = result.status === 'skipped';
    const steps = result.steps.filter((s) => s.category === 'test.step');
    const stepsHtml = steps
      .map((step) => {
        const figures = stepImages(step).map(figure);
        const panels = stepTexts(step).map(panel).join('');
        // Telefon görüntülü adımlar dar kart olur ve yan yana akar; web
        // görüntülü adımlar satırın kalanını doldurur. Böylece bir web
        // adımı ile ardından gelen telefon adımı çoğu zaman yan yana düşer.
        const kind = figures.length === 0 ? 'text' : figures.every((f) => f.phone) && !panels ? 'phone' : 'web';
        const error = step.error ? `<div class="error">${esc(stripAnsi(step.error.message))}</div>` : '';
        const shots = figures.map((f) => f.html).join('');
        return `<li class="step ${kind} ${step.error ? 'bad' : 'ok'}">
          <div class="step-head"><span class="mark">${step.error ? '✗' : '✓'}</span><span class="title">${esc(step.title)}</span><span class="dur">${duration(step.duration)}</span></div>
          ${error}${shots ? `<div class="shots">${shots}</div>` : ''}${panels}</li>`;
      })
      .join('');
    // Adımlara bağlanmamış ekler (ör. başarısızlıkta alınan ekran görüntüsü).
    const inSteps = new Set(steps.flatMap((s) => stepImages(s).map((a) => a.buf)));
    const loose = imageAttachments(result.attachments).filter((a) => !inSteps.has(a.buf));
    const inStepTexts = new Set(steps.flatMap((s) => stepTexts(s).map((a) => a.text)));
    const looseTexts = textAttachments(result.attachments).filter((a) => !inStepTexts.has(a.text));
    const testError =
      !ok && !skipped && result.error && !steps.some((s) => s.error)
        ? `<div class="error">${esc(stripAnsi(result.error.message))}</div>`
        : '';
    const badge = ok ? '<span class="badge ok">Geçti</span>' : skipped ? '<span class="badge warn">Atlandı</span>' : '<span class="badge bad">Kaldı</span>';
    return `<section class="scenario" id="${esc(sectionId(test.location.file, ordinal))}">
      <h3>${badge}${index}. ${esc(test.title)}</h3>
      <p class="file">${esc(path.relative(env.ROOT, test.location.file))}${ordinal > 1 ? ` · ${ordinal}. test` : ''} · ${duration(result.duration)}</p>
      <ol class="steps">${stepsHtml}</ol>${testError}
      ${loose.length ? `<div class="shots">${loose.map((a) => figure(a).html).join('')}</div>` : ''}
      ${looseTexts.map(panel).join('')}
    </section>`;
  }

  /** Senaryolar grup sırasına, sonra dosya adına ve dosya içi sıraya göre; her birine dosya içi sıra numarası. */
  sortedEntries() {
    const keyOf = (file) => {
      const g = GROUP_ORDER.indexOf(groupOf(file));
      return g < 0 ? GROUP_ORDER.length : g;
    };
    const sorted = [...this.entries].sort((a, b) => {
      const fa = a.test.location.file;
      const fb = b.test.location.file;
      return keyOf(fa) - keyOf(fb) || fa.localeCompare(fb) || a.test.location.line - b.test.location.line;
    });
    const perFile = new Map();
    return sorted.map((entry) => {
      const file = entry.test.location.file;
      const ordinal = (perFile.get(file) || 0) + 1;
      perFile.set(file, ordinal);
      return { ...entry, file, ordinal };
    });
  }

  renderMatrix(sorted) {
    const rows = FEATURES.map((f) => {
      const hits = f.scenarios.map((prefix) => sorted.filter((x) => matches(prefix, x.file)));
      const ran = hits.flat();
      const status =
        ran.length === 0
          ? 'none'
          : ran.every((x) => x.result.status === 'passed')
            ? 'ok'
            : ran.some((x) => x.result.status === 'failed' || x.result.status === 'timedOut')
              ? 'bad'
              : 'warn';
      const label = { ok: 'Geçti', bad: 'Kaldı', warn: 'Kısmen', none: 'Koşmadı' }[status];
      const links = f.scenarios
        .map((prefix, i) =>
          hits[i].length
            ? hits[i]
                .map((hit) => `<a href="#${esc(sectionId(hit.file, hit.ordinal))}">${esc(prefix)}${hit.ordinal > 1 ? ` (${hit.ordinal})` : ''}</a>`)
                .join(', ')
            : `<span class="g">${esc(prefix)}</span>`,
        )
        .join(', ');
      return `<tr><td class="g">${esc(GROUPS[f.group] || f.group)}</td><td>${esc(f.feature)}</td><td>${links}</td><td><span class="badge ${status === 'none' ? 'warn' : status}">${label}</span></td></tr>`;
    }).join('');
    const passed = FEATURES.filter((f) =>
      f.scenarios.every((p) => sorted.some((x) => matches(p, x.file) && x.result.status === 'passed')),
    ).length;
    return `<details open><summary style="cursor:pointer;font-weight:600">Kapsam matrisi — ${passed} / ${FEATURES.length} özellik kanıtlandı</summary>
      <table class="matrix"><thead><tr><th>Grup</th><th>Özellik</th><th>Senaryo</th><th>Durum</th></tr></thead><tbody>${rows}</tbody></table></details>`;
  }

  async onEnd(fullResult) {
    if (this.entries.length === 0) return;

    const passed = this.entries.filter((e) => e.result.status === 'passed').length;
    const total = this.entries.length;
    const allOk = passed === total;
    const when = this.startedAt.toLocaleString('tr-TR');
    const device = this.run ? `${this.run.manufacturer} ${this.run.model} (${this.run.serial})` : 'cihaz bilinmiyor';

    const sorted = this.sortedEntries();
    // Bölümler grup grup: bir grup başlığı yalnızca bir kez, Kurulum en başta.
    let index = 0;
    let currentGroup = null;
    const sections = sorted
      .map((entry) => {
        const group = groupOf(entry.file);
        const header = group !== currentGroup ? `<h2 class="group" id="g-${group}">${esc(GROUPS[group] || group)}</h2>` : '';
        currentGroup = group;
        index += 1;
        return header + this.renderScenario(entry, index, entry.ordinal);
      })
      .join('');

    const html = `<!doctype html>
<html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PinVault E2E kanıtı</title><style>${CSS}</style></head>
<body><main>
  <h1>PinVault uçtan uca test kanıtı</h1>
  <p class="meta">${esc(when)} · ${esc(device)} · web ${esc(env.WEB_URL)} · hedef ${esc(env.TARGET_HOST)}</p>
  <div class="summary ${allOk ? 'ok' : 'bad'}">${passed} / ${total} senaryo geçti · ${duration(fullResult.duration)}</div>
  ${HOWTO}
  ${this.renderMatrix(sorted)}
  ${sections}
</main>
<dialog id="zoom"><img alt=""></dialog>
<script>${ZOOM_JS}</script>
</body></html>`;

    const dir = path.resolve(env.ROOT, this.outputFolder);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'index.html');
    fs.writeFileSync(file, html);
    console.log(`\nKanıt sayfası: ${path.relative(process.cwd(), file)}`);
  }

  printsToStdio() {
    return false;
  }
}

module.exports = EvidenceReporter;
