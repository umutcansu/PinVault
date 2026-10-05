#!/usr/bin/env bash
# sample-host'u örnek uygulamanın bütün ekranları için hazırlar.
# Container çalışırken çalıştırılır; tekrar çalıştırmak güvenlidir, yalnızca
# eksik olanı ekler:
#
#   1. mTLS Config API: container :8092, dışarıda HOST_MTLS_PORT (varsayılan 6652).
#      İstemci sertifikası olmadan TLS el sıkışmasını kabul etmez.
#   2. Varsayılan Config API'de host'un kendi LAN IP'si için pin kaydı.
#      Uygulamanın mTLS testi bu IP'ye pinli bağlanır.
#
# Gereksinimler: curl, jq
# Kullanım: ./scripts/provision.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=scripts/lib.sh
. "${SCRIPT_DIR}/lib.sh"
load_env

HTTP="http://localhost:${HOST_HTTP_PORT:-6650}"
# Üretim profilinde kişisel yönetici anahtarı: ADMIN_KEY=… ./scripts/provision.sh
KEY="${ADMIN_KEY:-${API_KEY:?API_KEY .env içinde yok — ./scripts/setup.sh}}"
IP="${HOST_LAN_IP:?HOST_LAN_IP .env içinde yok — ./scripts/setup.sh}"
MTLS_ID="sample-mtls"
MTLS_CONTAINER_PORT=8092

# Anahtar komut satırına yazılmaz (lib.sh → curl_with_key).
api() { curl_with_key "${KEY}" -fsS "$@"; }

for _ in $(seq 1 60); do
    curl -fsS "${HTTP}/health" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "${HTTP}/health" >/dev/null 2>&1 || { echo "Host yanıt vermiyor: ${HTTP}" >&2; exit 1; }

# ── 1. mTLS Config API ──────────────────────────────────────────────────────
if api "${HTTP}/api/v1/all-configs" | jq -e --arg id "${MTLS_ID}" 'any(.[]; .id == $id and .running)' >/dev/null; then
    echo ">> mTLS Config API zaten çalışıyor (${MTLS_ID})"
else
    # mTLS dinleyicisi bir truststore ister; sunucu onu ilk istemci
    # sertifikasıyla oluşturur. Tohum sertifikanın P12'si hemen atılır, yani
    # bu sertifikayla kimse bağlanamaz.
    if [ "$(api "${HTTP}/api/v1/client-certs" | jq 'length')" = "0" ]; then
        api -X POST -H 'Content-Type: application/json' -d '{"clientId":"truststore-seed"}' \
            "${HTTP}/api/v1/client-certs/generate" -o /dev/null
        echo ">> Truststore oluşturuldu (truststore-seed)"
    fi
    api -X POST -H 'Content-Type: application/json' \
        -d "{\"id\":\"${MTLS_ID}\",\"port\":${MTLS_CONTAINER_PORT},\"mode\":\"mtls\"}" \
        "${HTTP}/api/v1/config-apis/start" >/dev/null
    echo ">> mTLS Config API başlatıldı (${MTLS_ID}, dışarıda :${HOST_MTLS_PORT:-6652})"
fi

# ── 2. Host'un kendi IP'si için pin kaydı ───────────────────────────────────
PINS="$(host_pins)" || true
[ -n "${PINS}" ] || { echo "Sunucu pin'leri okunamadı (data/certs/demo-server.pins) — host ayakta mı?" >&2; exit 1; }
PRIMARY="$(printf '%s\n' "${PINS}" | sed -n 1p)"
BACKUP="$(printf '%s\n' "${PINS}" | sed -n 2p)"
cfg="$(curl -fsS "${HTTP}/api/v1/certificate-config?signed=false")"

if echo "${cfg}" | jq -e --arg h "${IP}" --arg p "${PRIMARY}" --arg b "${BACKUP}" \
        'any(.pins[]; .hostname == $h and .sha256 == [$p, $b])' >/dev/null; then
    echo ">> ${IP} zaten doğru pin'lerle kayıtlı"
else
    body="$(echo "${cfg}" | jq --arg h "${IP}" --arg p "${PRIMARY}" --arg b "${BACKUP}" '
        {version: 0, forceUpdate: false,
         pins: ([.pins[] | select(.hostname != $h)] + [{hostname: $h, sha256: [$p, $b]}])}')"
    api -X PUT -H 'Content-Type: application/json' -d "${body}" "${HTTP}/api/v1/certificate-config" >/dev/null
    echo ">> ${IP} için pin kaydı eklendi"
fi

# ── 3. Mock hedef host'lar (TLS ve mTLS) ───────────────────────────────────
# Sunucu her biri için kendi imzaladığı bir sertifika üretir ve pin kaydını
# varsayılan Config API'ye ekler; mock dinleyici o sertifikayla açılır.
# Uygulama bu adları host IP'sine çözümler (MockDns) ve pinli bağlanır.
ensure_mock() {
    local host="$1" port="$2" mtls="$3"
    local status
    status="$(api "${HTTP}/api/v1/hosts/${host}/status" 2>/dev/null || echo '{}')"
    if ! echo "${status}" | jq -e '.keystorePath != null' >/dev/null 2>&1; then
        api -X POST -H 'Content-Type: application/json' -d "{\"hostname\":\"${host}\"}" \
            "${HTTP}/api/v1/management/hosts/default-tls/generate-cert" >/dev/null
        echo ">> ${host} için sertifika üretildi ve pin kaydı eklendi"
    fi
    if echo "${status}" | jq -e '.mockServerRunning == true' >/dev/null 2>&1; then
        echo ">> ${host} mock host'u zaten çalışıyor"
    else
        api -X POST -H 'Content-Type: application/json' -d "{\"port\":${port},\"mtls\":${mtls}}" \
            "${HTTP}/api/v1/hosts/${host}/start-mock" >/dev/null
        echo ">> ${host} mock host'u başlatıldı (container :${port}, mtls=${mtls})"
    fi
}
if is_production; then
    # Mock host'lar yalnızca deneme içindir; üretim profilinde portları da yayımlanmaz.
    echo ">> Üretim profili: mock hedef host'lar kurulmadı (yalnızca deneme içindir)"
else
    ensure_mock "mock-tls.sample" 8443 false
    ensure_mock "mock-mtls.sample" 8444 true
fi

echo ""
echo "== Hazır =="
echo "  mTLS Config API : https://${IP}:${HOST_MTLS_PORT:-6652}/ (istemci sertifikası zorunlu)"
if ! is_production; then
    echo "  Mock TLS host   : https://mock-tls.sample:${HOST_MOCK_TLS_PORT:-6653}/health  (ad → ${IP})"
    echo "  Mock mTLS host  : https://mock-mtls.sample:${HOST_MOCK_MTLS_PORT:-6654}/health (ad → ${IP})"
fi
echo "  Pin'li host'lar : $(curl -fsS "${HTTP}/api/v1/certificate-config?signed=false" | jq -r '[.pins[].hostname] | join(", ")')"
