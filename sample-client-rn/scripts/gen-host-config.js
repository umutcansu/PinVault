#!/usr/bin/env node
// sample-host.properties → src/generated/hostConfig.ts (+ src/generated/testControls.ts)
//
//   node scripts/gen-host-config.js [--props <dosya>] [--release] [--platform android|ios]
//
// Dosya verilmezse SAMPLE_HOST_PROPS, o da yoksa sample-client-rn/sample-host.properties.
// Android'deki BuildConfig alanlarının ve iOS'taki SampleHostConfig.swift'in
// karşılığı; aynı biçim kuralları (sample-client/app/build.gradle.kts): uymayan
// değer derlemeyi durdurur. Değerler TypeScript'e JSON.stringify ile yazılır,
// yani hiçbir değer koda dönüşemez. --release (ya da CONFIGURATION=Release):
// demo değerleri reddedilir ve test kontrolleri pakete hiç girmez.
// Üçüncü parti bağımlılık yok (react-native-config yerine).
'use strict';

const fs = require('fs');
const path = require('path');

const HERE = path.resolve(__dirname, '..');

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const release =
  process.argv.includes('--release') || /^release$/i.test(process.env.CONFIGURATION || '');
const platform = arg('--platform') || '';
let props = arg('--props') || process.env.SAMPLE_HOST_PROPS || path.join(HERE, 'sample-host.properties');
if (!path.isAbsolute(props)) props = path.resolve(HERE, props);
const outDir = path.join(HERE, 'src', 'generated');

function fail(message) {
  // Xcode "error:" ile başlayan satırları hata olarak gösterir.
  console.error(message.split('\n').map((l) => (l ? `error: ${l}` : l)).join('\n'));
  process.exit(1);
}

if (!fs.existsSync(props)) fail(`Host değerleri dosyası yok: ${props}`);
console.log(`gen-host-config: host değerleri ← ${props} (${release ? 'release' : 'debug'})`);

// ── Java Properties okuma (yorum, devam satırı, =/:/boşluk ayırıcı, kaçışlar) ──
function parseProperties(text) {
  const out = {};
  const lines = text.split(/\r?\n/);
  let buf = null;
  const unescape = (s) =>
    s.replace(/\\(.)/g, (_, c) => ('tnrf'.includes(c) ? '\u0001' : c)); // \t \n … → denetim karakteri (reddedilir)
  const emit = (line) => {
    const m = /^((?:\\.|[^=:\s\\])*)\s*[=:\s]?\s*(.*)$/.exec(line);
    if (!m) return;
    out[unescape(m[1])] = unescape(m[2]);
  };
  for (const raw of lines) {
    let line = raw.replace(/^[ \t\f]+/, '');
    if (buf === null && (line === '' || line[0] === '#' || line[0] === '!')) continue;
    if (buf !== null) line = buf + line;
    const trailing = /\\*$/.exec(line)[0].length;
    if (trailing % 2 === 1) {
      buf = line.slice(0, -1);
      continue;
    }
    buf = null;
    emit(line);
  }
  if (buf !== null) emit(buf);
  return out;
}

const values = parseProperties(fs.readFileSync(props, 'utf8'));
const value = (key) => (values[key] ?? '').trim();

// ── Biçim kuralları (build.gradle.kts ile aynı) ──────────────────────────────
const pin = '[A-Za-z0-9+/]{43}=';
const key = '[A-Za-z0-9+/]{40,2048}={0,2}';
const sha = '(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}|[A-Fa-f0-9]{64}';
const list = (p) => `(?:${p})(?:\\s*,\\s*(?:${p}))*`;
const RULES = {
  host: [/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/, 'IP ya da alan adı'],
  port: [/^[0-9]{1,5}$/, 'port'],
  scope: [/^[A-Za-z0-9._:-]{1,64}$/, 'Config API kimliği'],
  pin: [new RegExp(`^${pin}$`), 'Base64 SHA-256 pin'],
  pins: [new RegExp(`^${list(pin)}$`), "virgülle ayrılmış pin'ler"],
  key: [new RegExp(`^${key}$`), 'Base64 public key'],
  keys: [new RegExp(`^${list(key)}$`), "virgülle ayrılmış Base64 public key'ler"],
  sha256s: [new RegExp(`^${list(sha)}$`), 'virgülle ayrılmış SHA-256 (hex)'],
  bool: [/^(?:true|false)$/, 'true ya da false'],
  signatures: [/^[1-9]$/, '1-9 arası sayı'],
};

function checked(name, rule) {
  const v = value(name);
  if (/[\u0000-\u001f\u007f]/.test(v)) fail(`${props}: '${name}' değerinde denetim karakteri var; yazılmadı.`);
  const [re, what] = RULES[rule];
  if (v !== '' && !re.test(v)) fail(`${props}: '${name}' beklenen biçimde değil (${what}). Değer: '${v.slice(0, 60)}'`);
  return v;
}

const csv = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);

const host = {
  ip: checked('host.ip', 'host'),
  httpsPort: checked('host.httpsPort', 'port'),
  mtlsPort: checked('host.mtlsPort', 'port'),
  tlsScope: checked('host.tlsScope', 'scope'),
  mtlsScope: checked('host.mtlsScope', 'scope'),
  attestation: checked('host.attestation', 'bool') !== 'false',
  bootstrapPins: [checked('host.bootstrapPinPrimary', 'pin'), checked('host.bootstrapPinBackup', 'pin')],
  signingPublicKey: checked('host.signingPublicKey', 'key'),
  signingPublicKeys: csv(checked('host.signingPublicKeys', 'keys')),
  requiredSignatures: Number(checked('host.requiredSignatures', 'signatures') || '1'),
  recoveryPublicKeys: csv(checked('host.recoveryPublicKeys', 'keys')),
  recoveryPort: checked('host.recoveryPort', 'port'),
  recoveryPins: csv(checked('host.recoveryPins', 'pins')),
  clientCaPins: csv(checked('host.clientCaPin', 'pins')),
  expectedSignerSha256: csv(checked('host.expectedSignerSha256', 'sha256s')),
  targetHost: checked('target.host', 'host'),
  targetRequireCaTrust: checked('target.requireCaTrust', 'bool') !== 'false',
};
for (const required of ['ip', 'httpsPort', 'mtlsPort', 'signingPublicKey', 'targetHost']) {
  if (!host[required]) fail(`${props}: '${required}' boş; uygulama host'a bağlanamaz.`);
}
if (!host.bootstrapPins.every(Boolean)) fail(`${props}: host.bootstrapPinPrimary / host.bootstrapPinBackup boş.`);

// ── Release kapısı (build.gradle.kts → preReleaseBuild ile aynı kurallar) ─────
if (release) {
  const problems = [];
  if (!host.targetRequireCaTrust) {
    problems.push(
      `${props}: target.requireCaTrust=false. Release derlemesi hedefin CA onayını kapatmaz: hedefin sertifikası herkesin güvendiği bir CA'dan olmalı.`,
    );
  }
  const hostProblems = [];
  const required = host.requiredSignatures;
  if (required < 2) {
    hostProblems.push(
      `host.requiredSignatures=${required}: her config en az 2 ayrı imza taşımalı. Tek imzayla, imza anahtarını ele geçiren biri bütün telefonlara sahte pin gönderebilir.`,
    );
  }
  const trusted = new Set([host.signingPublicKey, ...host.signingPublicKeys].filter(Boolean)).size;
  if (trusted < required + 1) {
    hostProblems.push(
      `host.signingPublicKeys: uygulama ${trusted} imza anahtarına güveniyor, ${required} imza istiyor. En az bir yedek anahtar (${required + 1} anahtar) gerekir.`,
    );
  }
  if (host.recoveryPublicKeys.length === 0) {
    hostProblems.push('host.recoveryPublicKeys boş: kurtarma anahtarı olmadan çalınan bir imza anahtarı telefonlarda iptal edilemez.');
  }
  if (host.clientCaPins.length === 0) {
    hostProblems.push('host.clientCaPin boş: uygulama kayıtta gelen ilk sertifika zincirine güvenirdi.');
  }
  if (!host.tlsScope || !host.mtlsScope) {
    hostProblems.push("host.tlsScope / host.mtlsScope boş: uygulama config'in hangi Config API için imzalandığına bakmaz.");
  }
  if (platform === 'android' && host.expectedSignerSha256.length === 0) {
    hostProblems.push(
      'host.expectedSignerSha256 boş: uygulama kendi imza sertifikasını atestasyon raporunda işaretleyemez (apksigner verify --print-certs).',
    );
  }
  if (hostProblems.length) {
    problems.push(
      `${props} üretim değerlerini taşımıyor (demo dosyası mı?):\n` +
        hostProblems.map((p) => `  - ${p}`).join('\n') +
        "\n  Değerleri sample-host'un üretim profilinden üret:\n    ../sample-host/scripts/client-config.sh --properties > sample-host.properties",
    );
  }
  if (problems.length) fail('Release derlemesi durduruldu:\n\n' + problems.join('\n\n'));
}

// ── Yazma (içerik değişmediyse dosyaya dokunmaz) ─────────────────────────────
function write(file, content) {
  const target = path.join(outDir, file);
  if (fs.existsSync(target) && fs.readFileSync(target, 'utf8') === content) return;
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(target, content);
}

const header = '// scripts/gen-host-config.js üretir; elle düzenleme. Depoda tutulmaz.\n';
write(
  'hostConfig.ts',
  `${header}export const HOST = ${JSON.stringify({ ...host, release }, null, 2)} as const;\n`,
);
// Release'te test kontrolleri modülü hiç içe aktarılmaz: JS paketinde yoktur.
write(
  'testControls.ts',
  release
    ? `${header}export const TestControls = null;\n`
    : `${header}export { TestControls } from '../TestControls';\n`,
);
