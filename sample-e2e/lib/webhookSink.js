// Sunucunun güvenlik bildirimlerini (NOTIFY_WEBHOOK_URL) yakalayan küçük HTTP
// alıcısı. Mac'te dinler; container ona host.docker.internal üzerinden ulaşır.
// Her isteğin gövdesini, başlıklarını ve HMAC imzasının doğru olup olmadığını
// saklar — kanıt panelleri bunları gösterir.
//
// İmza: X-PinVault-Signature = "sha256=" + HMAC-SHA256(gizli anahtar,
// "<X-PinVault-Timestamp>.<gövde>"). Zaman damgası imzanın içinde olduğu için
// yakalanan bir bildirim sonradan yeniden gönderilirse alıcı onu eski diye
// reddedebilir (burada: 5 dakikadan eski ya da ileri tarihli → geçersiz).
const http = require('http');
const crypto = require('crypto');
const env = require('./env');

/**
 * @param {object} opts
 * @param {string} opts.secret NOTIFY_WEBHOOK_SECRET ile aynı değer (HMAC doğrulaması).
 * @param {number} opts.port Dinlenecek port (varsayılan env.WEBHOOK_PORT).
 */
async function start({ secret, port = env.WEBHOOK_PORT } = {}) {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const signature = req.headers['x-pinvault-signature'] || null;
      const timestamp = req.headers['x-pinvault-timestamp'] || null;
      const expected = secret && timestamp ? signatureFor(secret, timestamp, body) : null;
      const fresh = timestamp !== null && /^\d+$/.test(timestamp) && Math.abs(Date.now() / 1000 - Number(timestamp)) <= MAX_AGE_SECONDS;
      let json = null;
      try {
        json = JSON.parse(body);
      } catch {
        /* gövde JSON değil */
      }
      received.push({
        at: new Date().toISOString(),
        path: req.url,
        event: req.headers['x-pinvault-event'] || null,
        signature,
        timestamp,
        timestampFresh: fresh,
        // Gizli anahtar verilmediyse null; verildiyse imza VE zaman damgası tutmalı.
        signatureValid: secret ? expected !== null && signature === expected && fresh : null,
        body,
        json,
      });
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', resolve);
  });
  return {
    port,
    /** Container içinden bu alıcının adresi. */
    url: `http://host.docker.internal:${port}/hook`,
    received,
    /** [predicate]'e uyan ilk bildirimi bekler. */
    async waitFor(predicate, timeoutMs = 20_000) {
      const deadline = Date.now() + timeoutMs;
      for (;;) {
        const hit = received.find(predicate);
        if (hit) return hit;
        if (Date.now() > deadline) {
          throw new Error(`Beklenen bildirim gelmedi (${received.length} bildirim alındı: ${received.map((r) => r.event).join(', ')})`);
        }
        await new Promise((r) => setTimeout(r, 250));
      }
    },
    async stop() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/** Bir alıcının yeniden hesapladığı imza: "sha256=" + HMAC-SHA256(secret, "<timestamp>.<body>"). */
function signatureFor(secret, timestamp, body) {
  return `sha256=${crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

/** Bundan eski (ya da bu kadar ileri) zaman damgalı bildirim geçersiz sayılır. */
const MAX_AGE_SECONDS = 300;

module.exports = { start, signatureFor };
