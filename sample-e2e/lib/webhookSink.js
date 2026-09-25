// Sunucunun güvenlik bildirimlerini (NOTIFY_WEBHOOK_URL) yakalayan küçük HTTP
// alıcısı. Mac'te dinler; container ona host.docker.internal üzerinden ulaşır.
// Her isteğin gövdesini, başlıklarını ve HMAC imzasının doğru olup olmadığını
// saklar — kanıt panelleri bunları gösterir.
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
      const expected = secret
        ? `sha256=${crypto.createHmac('sha256', secret).update(body).digest('hex')}`
        : null;
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
        signatureValid: expected ? signature === expected : null,
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

module.exports = { start };
