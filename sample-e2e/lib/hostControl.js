// Host container'ını durdurup başlatır ("host kapalıyken" senaryoları için)
// ve sunucu ortam değişkenlerini geçici olarak değiştirir.
const path = require('path');
const { execFileSync } = require('child_process');
const env = require('./env');
const hostApi = require('./hostApi');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function docker(args) {
  return execFileSync('docker', args, { encoding: 'utf8', timeout: 120_000 });
}

function isRunning() {
  try {
    return docker(['inspect', '-f', '{{.State.Running}}', env.CONTAINER]).trim() === 'true';
  } catch {
    return false;
  }
}

async function stop() {
  docker(['stop', env.CONTAINER]);
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (!(await hostApi.isHealthy())) return;
    await sleep(500);
  }
  throw new Error('Host durmadı');
}

/** Container'ı başlatır; sağlık ucu ve mTLS Config API ayağa kalkana kadar bekler. */
async function start({ timeoutMs = 120_000, requireMtls = true } = {}) {
  if (!isRunning()) docker(['start', env.CONTAINER]);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await hostApi.isHealthy()) && (!requireMtls || (await hostApi.mtlsApiRunning()))) return;
    await sleep(1000);
  }
  throw new Error('Host zamanında ayağa kalkmadı');
}

/** Host kapalı kalmışsa (ör. yarıda kesilen bir test) geri açar. */
async function ensureUp() {
  if (!(await hostApi.isHealthy()) || !(await hostApi.mtlsApiRunning())) await start();
}

/**
 * Sunucu ortam değişkenlerini .env'e dokunmadan değiştirir ve container'ı
 * yeni değerlerle yeniden oluşturur (host scripts/env-override.sh). Örn.
 * { CONFIG_TTL_SECONDS: '60', ENROLLMENT_MODE: 'open' }. Test sonunda
 * [resetEnv] ile geri alınmalı.
 */
async function setEnv(overrides) {
  const args = Object.entries(overrides).map(([k, v]) => `${k}=${v}`);
  execFileSync(path.join(env.HOST_DIR, 'scripts/env-override.sh'), ['set', ...args], {
    stdio: 'inherit',
    timeout: 180_000,
  });
  await start();
}

/** Ortam değişkenlerini .env değerlerine döndürür (container yeniden oluşturulur). */
async function resetEnv() {
  execFileSync(path.join(env.HOST_DIR, 'scripts/env-override.sh'), ['reset'], {
    stdio: 'inherit',
    timeout: 180_000,
  });
  await start();
}

/** Container loglarının son [lines] satırı (metin paneli için). */
function logs(lines = 100) {
  try {
    return docker(['logs', '--tail', String(lines), env.CONTAINER]);
  } catch (e) {
    return `${e.stdout || ''}${e.stderr || ''}`;
  }
}

/**
 * Container'ın o anki durumu (metin paneli için): `docker ps -a` satırı ve
 * sağlık ucunun yanıt verip vermediği. "Host durdurulur / başlatılır"
 * adımlarının kanıtı.
 */
async function describeState() {
  let ps;
  try {
    ps = docker(['ps', '-a', '--filter', `name=^${env.CONTAINER}$`, '--format', 'table {{.Names}}\t{{.Status}}\t{{.Ports}}']);
  } catch (e) {
    ps = `${e.stdout || ''}${e.stderr || ''}`;
  }
  const healthy = await hostApi.isHealthy();
  return [
    `$ docker ps -a --filter name=${env.CONTAINER}`,
    ps.trim(),
    '',
    `GET ${env.WEB_URL}/health → ${healthy ? 'HTTP 200 (host ayakta)' : 'bağlantı yok (host kapalı)'}`,
  ].join('\n');
}

module.exports = { stop, start, ensureUp, isRunning, setEnv, resetEnv, logs, describeState };
