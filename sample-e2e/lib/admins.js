// E2E'nin kişisel yönetici anahtarları (ADMIN_KEYS). Bir kez üretilir ve
// .local/admins.json'da saklanır; sunucuya yalnızca SHA-256'ları gider. Kanıt
// sayfasında anahtarların kendisi asla görünmez (check-evidence tam uzunluktaki
// değerleri sızıntı olarak işaretler) — panellerde redact() kullanılır.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const env = require('./env');

const FILE = path.join(env.LOCAL_DIR, 'admins.json');
const NAMES = ['alice', 'bob'];

function load() {
  let keys = {};
  if (fs.existsSync(FILE)) keys = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  let changed = false;
  for (const name of NAMES) {
    if (!keys[name]) {
      keys[name] = crypto.randomBytes(32).toString('base64url');
      changed = true;
    }
  }
  if (changed) {
    fs.mkdirSync(env.LOCAL_DIR, { recursive: true });
    fs.writeFileSync(FILE, JSON.stringify(keys, null, 2), { mode: 0o600 });
  }
  return keys;
}

const keys = load();

/** ADMIN_KEYS değeri: ad:sha256hex,… (host'un scripts/add-admin.sh çıktısıyla aynı biçim). */
function adminKeysEnv() {
  return NAMES.map((n) => `${n}:${crypto.createHash('sha256').update(keys[n]).digest('hex')}`).join(',');
}

module.exports = { keys, NAMES, adminKeysEnv };
