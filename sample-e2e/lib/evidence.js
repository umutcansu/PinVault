// Ekran görüntüsü olmayan kanıtlar: terminal çıktısı, kablodaki bayt, cihaz
// dosya dökümü, sunucu kaydı. Rapora metin paneli olarak eklenir; kanıt sayfası
// bunları ilgili adımın altında <pre> olarak gösterir.
const { execFileSync } = require('child_process');

/** Adıma metin paneli ekler. [title] panelin başlığı olur. */
async function attachText(testInfo, title, text) {
  await testInfo.attach(`📄 ${title}`, { body: String(text ?? ''), contentType: 'text/plain' });
}

/**
 * Komutu çalıştırır, "$ komut" başlıklı çıktıyı panel olarak ekler ve çıktıyı
 * döndürür. Hata çıksa da (exit ≠ 0) çıktı panele girer ve hata fırlatılır.
 */
async function attachCommand(testInfo, title, file, args, opts = {}) {
  const cmdline = [file, ...args].join(' ');
  let out;
  let error;
  try {
    out = execFileSync(file, args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 16 * 1024 * 1024, ...opts });
  } catch (e) {
    error = e;
    out = `${e.stdout || ''}${e.stderr || ''}\n[exit ${e.status}]`;
  }
  await attachText(testInfo, title, `$ ${cmdline}\n${out}`);
  if (error) throw error;
  return out;
}

/**
 * Başarısız olması BEKLENEN komut: çıktıyı panele ekler ve döndürür; komut
 * beklenmedik şekilde başarılı olursa hata fırlatır. (Örn. API anahtarı yokken
 * `docker compose config`.)
 */
async function attachFailingCommand(testInfo, title, file, args, opts = {}) {
  const cmdline = [file, ...args].join(' ');
  try {
    const out = execFileSync(file, args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 16 * 1024 * 1024, ...opts });
    await attachText(testInfo, title, `$ ${cmdline}\n${out}\n[exit 0 — hata bekleniyordu]`);
    throw new Error(`Komut başarısız olmalıydı: ${cmdline}`);
  } catch (e) {
    if (e.status === undefined && e.signal === undefined) throw e;
    const out = `${e.stdout || ''}${e.stderr || ''}`;
    await attachText(testInfo, title, `$ ${cmdline}\n${out}\n[exit ${e.status}]`);
    return out;
  }
}

/** Baytların hex dökümü: satır başına 16 bayt, sağda ASCII. */
function hexdump(buf, max = 256) {
  const lines = [];
  for (let i = 0; i < Math.min(buf.length, max); i += 16) {
    const chunk = buf.subarray(i, i + 16);
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...chunk].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${i.toString(16).padStart(6, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (buf.length > max) lines.push(`… (${buf.length - max} bayt daha)`);
  return lines.join('\n');
}

/** HTTP yanıtını (durum, başlıklar, gövde) panel metnine çevirir. */
function describeResponse(res, { bodyHex = false, maxBody = 512 } = {}) {
  const head = [`HTTP ${res.status}`, ...Object.entries(res.headers || {}).map(([k, v]) => `${k}: ${v}`)].join('\n');
  const body = res.body == null ? '' : bodyHex ? hexdump(res.body, maxBody) : String(res.body).slice(0, maxBody);
  return `${head}\n\n${body}`;
}

/** Gizli değerleri panele girmeden önce kısaltır (token, anahtar). */
function redact(value, keep = 6) {
  const s = String(value ?? '');
  return s.length <= keep * 2 ? '…' : `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

module.exports = { attachText, attachCommand, attachFailingCommand, hexdump, describeResponse, redact };
