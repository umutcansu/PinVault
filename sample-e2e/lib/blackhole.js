// iOS'ta iptables DROP'un karşılığı: bağlantıyı kabul eden, hiçbir şey
// göndermeyen ve hiçbir şey okumayan TCP sunucusu. Simülatörde paket
// düşürülemediği için uygulamanın bağlantısı (E2E denetim dosyasındaki
// yönlendirmeyle, lib/ios.js blockTcp('drop')) buraya gider: TLS el sıkışması
// hiç başlamaz, istek zaman aşımına uğrar. Android'de iptables DROP SYN'i
// düşürür (bağlantı zaman aşımı); burada bağlantı kurulur ama yanıt gelmez
// (okuma zaman aşımı). İkisinde de istemci yanıt alamadan süresini doldurur.
//
// Sunucu, cihaz nesnesini kullanan süreçte (Playwright işçisi) açılır;
// [stop] bütün açık bağlantıları da kapatır.
const net = require('net');

let server = null;
let listening = null;
const sockets = new Set();

/**
 * 127.0.0.1:[port]'u dinlemeye başlar (zaten dinliyorsa bir şey yapmaz).
 * Dinleme hazır olunca çözülen bir söz döndürür; çağıranın beklemesi
 * gerekmez (uygulamanın ilk bağlantısı ancak bir sonraki eylemde gelir).
 */
function start(port) {
  if (server) return listening;
  server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    // Okunan bayt atılır; yanıt hiç yazılmaz.
    socket.on('data', () => {});
  });
  listening = new Promise((resolve, reject) => {
    server.once('error', (e) => {
      console.warn(`[e2e] blackhole 127.0.0.1:${port} açılamadı: ${e.message}`);
      server = null;
      reject(e);
    });
    server.listen(port, '127.0.0.1', resolve);
  });
  listening.catch(() => {});
  return listening;
}

function isRunning() {
  return !!server;
}

/** Sunucuyu ve açık bağlantıları kapatır. */
function stop() {
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  if (server) {
    server.close();
    server = null;
    listening = null;
  }
}

module.exports = { start, stop, isRunning };
