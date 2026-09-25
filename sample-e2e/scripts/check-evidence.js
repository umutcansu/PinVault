#!/usr/bin/env node
// Kanıt sayfası denetimi (npm run check-evidence): evidence/index.html'i
// ayrıştırır ve şunları listeler:
//   1. kanıtsız adımlar — ne ekran görüntüsü ne metin paneli olan adımlar,
//   2. görüntüsüz senaryolar — hiç ekran görüntüsü olmayan senaryolar,
//   3. tekrarlanan görüntüler — bayt bayt aynı görüntünün birden fazla yerde
//      (özellikle farklı altyazıyla) kullanılması,
//   4. gizli değerler — tam uzunlukta token/anahtar dizileri, bilinen gizli
//      değerler (API anahtarı, imzalama private key'i, vekil/özel backend
//      anahtarları), PEM private key blokları, şifreli anahtar gövdesi.
// Bulgu yoksa "0 bulgu" yazıp 0 ile, varsa bulguları listeleyip 1 ile çıkar.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const env = require('../lib/env');

const FILE = path.resolve(env.ROOT, process.argv[2] || 'evidence/index.html');

const unesc = (s) =>
  String(s)
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, '>')
    .replace(/&lt;/g, '<')
    .replace(/&amp;/g, '&');

function parse(html) {
  const scenarios = [];
  const sections = html.split('<section class="scenario" id="').slice(1);
  for (const sec of sections) {
    const id = sec.slice(0, sec.indexOf('"'));
    const body = sec.slice(0, sec.indexOf('</section>'));
    const h3 = body.match(/<h3><span class="badge [a-z]+">[^<]*<\/span>(\d+)\. ([\s\S]*?)<\/h3>/);
    const scenario = { id, title: h3 ? unesc(h3[2]) : id, steps: [], loose: { figs: [], panels: [] } };
    const olStart = body.indexOf('<ol class="steps">');
    const olEnd = body.indexOf('</ol>', olStart);
    const ol = olStart >= 0 ? body.slice(olStart + '<ol class="steps">'.length, olEnd) : '';
    const after = olStart >= 0 ? body.slice(olEnd + 5) : body;
    const extract = (chunk) => {
      const figs = [];
      for (const f of chunk.matchAll(/<figure class="shot [a-z]+"><img src="data:image\/[a-z]+;base64,([^"]*)" alt="([^"]*)"[^>]*><figcaption>([^<]*)<\/figcaption><\/figure>/g)) {
        const buf = Buffer.from(f[1], 'base64');
        figs.push({ caption: unesc(f[3]), md5: crypto.createHash('md5').update(buf).digest('hex'), bytes: buf.length });
      }
      const panels = [...chunk.matchAll(/<details class="panel" open><summary>([\s\S]*?)<\/summary><pre>([\s\S]*?)<\/pre><\/details>/g)].map((p) => ({
        title: unesc(p[1]),
        text: unesc(p[2]),
      }));
      return { figs, panels };
    };
    ol.split('<li class="step ').slice(1).forEach((li, i) => {
      const head = li.match(/<span class="title">([\s\S]*?)<\/span>/);
      const { figs, panels } = extract(li);
      scenario.steps.push({ n: i + 1, title: head ? unesc(head[1]) : `(adım ${i + 1})`, figs, panels, error: /<div class="error">/.test(li) });
    });
    scenario.loose = extract(after);
    scenarios.push(scenario);
  }
  return scenarios;
}

/** Bilinen gizli değerler: yalnızca ad döner, değer asla yazdırılmaz. */
function knownSecrets() {
  const out = [];
  const add = (name, value) => {
    if (value && value.length >= 12) out.push({ name, value });
  };
  const readLines = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').map((l) => l.trim()) : []);
  const dotEnvKey = (file, key = 'API_KEY') => {
    const line = readLines(file).find((l) => l.startsWith(`${key}=`));
    return line ? line.slice(key.length + 1).replace(/^["']|["']$/g, '') : '';
  };
  add('ana host API_KEY', dotEnvKey(path.join(env.HOST_DIR, '.env')));
  add('geçici test sunucusu API_KEY', dotEnvKey(path.join(env.LOCAL_DIR, 'host-fresh/.env')));
  add('ana host KEYSTORE_PASSWORD', dotEnvKey(path.join(env.HOST_DIR, '.env'), 'KEYSTORE_PASSWORD'));
  add('geçici test sunucusu KEYSTORE_PASSWORD', dotEnvKey(path.join(env.LOCAL_DIR, 'host-fresh/.env'), 'KEYSTORE_PASSWORD'));
  add('ana host imzalama private key (satır 1)', readLines(env.SIGNING_KEY_FILE)[0]);
  add('geçici test sunucusu imzalama private key (satır 1)', readLines(path.join(env.LOCAL_DIR, 'host-fresh/data/signing-key.pem'))[0]);
  const pemBodies = (file, label) => {
    const lines = readLines(file).filter((l) => l && !l.startsWith('-----'));
    lines.forEach((l, i) => add(`${label} gövde satırı ${i + 1}`, l));
  };
  pemBodies(env.PROXY_KEY_FILE, 'araya giren proxy\'nin sunucu anahtarı');
  const custom = path.join(env.LOCAL_DIR, 'custom-backend');
  if (fs.existsSync(custom)) {
    for (const f of fs.readdirSync(custom)) {
      if (/key.*\.pem$/i.test(f) || /\.key$/i.test(f)) {
        if (f === 'signing-key.pem') readLines(path.join(custom, f)).forEach((l, i) => add(`özel backend signing-key.pem satır ${i + 1}`, l));
        else pemBodies(path.join(custom, f), `özel backend ${f}`);
      }
    }
  }
  // Kişisel yönetici anahtarları (lib/admins.js) ve çevrimdışı imza anahtarları
  // (lib/offlineKeys.js): özel yarıları hiçbir kanıta girmemeli.
  const admins = path.join(env.LOCAL_DIR, 'admins.json');
  if (fs.existsSync(admins)) {
    for (const [name, value] of Object.entries(JSON.parse(fs.readFileSync(admins, 'utf8')))) add(`yönetici anahtarı (${name})`, value);
  }
  const offline = path.join(env.LOCAL_DIR, 'offline-keys');
  if (fs.existsSync(offline)) {
    for (const f of fs.readdirSync(offline).filter((n) => n.endsWith('.pem'))) pemBodies(path.join(offline, f), `çevrimdışı anahtar ${f}`);
  }
  // Taze host'un ek yerel imzalayıcı anahtarları (CONFIG_SIGNERS=local,local:<ad>).
  const freshData = path.join(env.LOCAL_DIR, 'host-fresh/data');
  if (fs.existsSync(freshData)) {
    for (const f of fs.readdirSync(freshData).filter((n) => /^signing-key-.+\.pem$/.test(n))) {
      add(`geçici test sunucusu ${f} (satır 1)`, readLines(path.join(freshData, f))[0]);
    }
  }
  return out;
}

function main() {
  if (!fs.existsSync(FILE)) {
    console.error(`Kanıt sayfası yok: ${FILE}`);
    process.exit(2);
  }
  const html = fs.readFileSync(FILE, 'utf8');
  const scenarios = parse(html);
  const findings = { kanitsiz: [], goruntusuz: [], tekrar: [], gizli: [] };

  // 1–2. kanıtsız adımlar, görüntüsüz senaryolar
  const seen = new Map();
  let steps = 0;
  let images = 0;
  let panels = 0;
  for (const s of scenarios) {
    let scenarioImages = s.loose.figs.length;
    for (const st of s.steps) {
      steps += 1;
      images += st.figs.length;
      panels += st.panels.length;
      scenarioImages += st.figs.length;
      if (st.figs.length === 0 && st.panels.length === 0) findings.kanitsiz.push(`${s.id} #${st.n} ${st.title}`);
      for (const f of st.figs) {
        if (!seen.has(f.md5)) seen.set(f.md5, []);
        seen.get(f.md5).push(`${s.id} #${st.n} [${f.caption}]`);
      }
    }
    for (const f of s.loose.figs) {
      images += 1;
      if (!seen.has(f.md5)) seen.set(f.md5, []);
      seen.get(f.md5).push(`${s.id} (adım dışı) [${f.caption}]`);
    }
    panels += s.loose.panels.length;
    if (scenarioImages === 0) findings.goruntusuz.push(`${s.id} — ${s.title}`);
  }

  // 3. tekrarlanan görüntüler (aynı baytlar, başka yerde / başka altyazıyla)
  for (const [, uses] of seen) {
    if (uses.length > 1) findings.tekrar.push(uses.join('  |  '));
  }

  // 4. gizli değerler — yalnızca okunan metin: senaryo/adım başlıkları,
  // altyazılar, panel başlıkları ve panel içerikleri (HTML kimlikleri, öznitelikler
  // ve görüntü verisi değil).
  const parts = [];
  for (const s of scenarios) {
    parts.push(s.title);
    for (const st of s.steps) {
      parts.push(st.title);
      for (const f of st.figs) parts.push(f.caption);
      for (const p of st.panels) parts.push(p.title, p.text);
    }
    for (const f of s.loose.figs) parts.push(f.caption);
    for (const p of s.loose.panels) parts.push(p.title, p.text);
  }
  const text = parts.join('\n');
  for (const s of knownSecrets()) {
    if (text.includes(s.value)) findings.gizli.push(`bilinen gizli değer sayfada: ${s.name}`);
  }
  for (const m of text.matchAll(/-----BEGIN (?:EC |RSA |ENCRYPTED )?PRIVATE KEY-----/g)) {
    findings.gizli.push(`PEM private key bloğu: "${text.slice(Math.max(0, m.index - 40), m.index).replace(/\s+/g, ' ')}"`);
  }
  // Şifreli imzalama anahtarı dosyası "ENCv1:" + Base64(salt+IV+şifreli metin);
  // panele yalnızca kısa bir önek (salt) girebilir, gövdenin tamamı giremez.
  for (const m of text.matchAll(/ENCv1:([A-Za-z0-9+/=]{40,})/g)) {
    findings.gizli.push(`şifreli anahtar gövdesi tam uzunlukta: ENCv1:${m[1].slice(0, 8)}… (${m[1].length} karakter)`);
  }
  // Token biçimi: sunucunun ürettiği kayıt ve vault token'ları 32 rastgele
  // baytın URL güvenli Base64'ü = tam 43 karakter, '=' yok. Tek başına duran
  // (öncesi/sonrası Base64 karakteri olmayan) 43 karakterlik [A-Za-z0-9_-]
  // dizileri aranır; public key PEM blokları taramadan önce çıkarılır (64
  // karakterlik satırları tesadüfen 43'lük parçalar verebilir), düz hex ve
  // UUID atlanır.
  const scanned = text.replace(/-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----/g, '');
  const tokenish = new Map();
  for (const m of scanned.matchAll(/(?<![A-Za-z0-9+/=_-])([A-Za-z0-9_-]{43})(?![A-Za-z0-9+/=_-])/g)) {
    const v = m[1];
    if (/^[0-9a-f-]+$/i.test(v)) continue;
    if (!/[A-Z]/.test(v) || !/[a-z]/.test(v) || !/[0-9]/.test(v)) continue; // rastgele Base64 üç sınıfı da içerir
    const ctx = scanned.slice(Math.max(0, m.index - 60), m.index).replace(/\s+/g, ' ');
    tokenish.set(v, ctx);
  }
  for (const [v, ctx] of tokenish) {
    findings.gizli.push(`token görünümlü dizi: ${v.slice(0, 6)}…${v.slice(-4)} (${v.length} karakter) — bağlam: "${ctx.slice(-60)}"`);
  }

  const total = Object.values(findings).reduce((a, v) => a + v.length, 0);
  console.log(`Kanıt sayfası: ${path.relative(process.cwd(), FILE)}`);
  console.log(`${scenarios.length} senaryo, ${steps} adım, ${images} görüntü, ${panels} panel`);
  const section = (title, list) => {
    console.log(`\n${title}: ${list.length}`);
    for (const l of list) console.log(`  - ${l}`);
  };
  section('Kanıtsız adımlar', findings.kanitsiz);
  section('Görüntüsüz senaryolar', findings.goruntusuz);
  section('Tekrarlanan görüntüler', findings.tekrar);
  section('Gizli değer / tam uzunlukta token', findings.gizli);
  console.log(`\nToplam: ${total} bulgu`);
  process.exit(total === 0 ? 0 : 1);
}

main();
