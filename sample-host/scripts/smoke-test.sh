#!/usr/bin/env bash
# sample-host smoke test. Çalışan container'a karşı şunları doğrular:
#   1. /health
#   2. İmzalı config: ECDSA imzası sunucunun GET /api/v1/signing-key ile bildirdiği anahtar(lar)la
#      doğrulanıyor, issuedAt/expiresAt dolu ve süresi geçmemiş
#   3. TLS: sunucu sertifikasının pin'i data/certs/demo-server.pins ile aynı,
#      SAN listesi HOST_LAN_IP'yi içeriyor (telefonun hostname doğrulaması)
#   4. Yetki: yönetim uçları anahtarsız 401, anahtarla 200
#   5. ping-remote komut enjeksiyonu reddediliyor (400)
#   6. mTLS Config API istemci sertifikası olmadan bağlantıyı reddediyor
#   7. Yönetim API'si: düz HTTP yalnızca bu makinede, ağa şifreli port
#   8. Vault dosyalarının parolası dolu ve bütün dosyaları açıyor
#
# Gereksinimler: curl, jq, openssl
# Kullanım: ./scripts/smoke-test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

for tool in curl jq openssl; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "ERROR: '${tool}' gerekli." >&2; exit 2; }
done

HTTP_PORT="${HOST_HTTP_PORT:-6650}"
HTTPS_PORT="${HOST_HTTPS_PORT:-6651}"
HTTP="http://localhost:${HTTP_PORT}"
HTTPS="https://localhost:${HTTPS_PORT}"
KEY="${API_KEY:-}"

tmp="$(mktemp -d -t pinvault-smoke.XXXXXX)"
trap 'rm -rf "${tmp}"' EXIT

pass=0
fail=0
ok()  { echo "    PASS  $*"; pass=$((pass + 1)); }
bad() { echo "    FAIL  $*"; fail=$((fail + 1)); }

# HTTP durum kodu döndürür (bağlantı hatasında 000).
status() { curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }

expect_status() {
    local want="$1" label="$2"; shift 2
    local got
    got="$(status "$@")"
    if [ "${got}" = "${want}" ]; then ok "${label} → ${got}"; else bad "${label} → ${got} (beklenen ${want})"; fi
}

echo "== sample-host smoke test =="
echo "Management : ${HTTP}"
echo "Config API : ${HTTPS}"
echo ""

echo "[1] Sağlık"
if body="$(curl -fsS --max-time 5 "${HTTP}/health" 2>&1)"; then ok "/health → ${body}"; else bad "/health → ${body}"; fi

echo "[2] İmzalı config"
if curl -fsSk --max-time 10 -o "${tmp}/cfg.json" "${HTTPS}/api/v1/certificate-config"; then
    jq -j '.payload' "${tmp}/cfg.json" > "${tmp}/payload"
    jq -r '.signature' "${tmp}/cfg.json" | openssl base64 -d -A > "${tmp}/sig.der"
    # Anahtar sunucudan: imzalayıcı bir HSM/KMS olabilir ya da anahtar dosyası
    # SIGNING_KEY_PASSWORD ile şifreli olabilir — dosyadan okunamaz.
    curl -fsS --max-time 5 "${HTTP}/api/v1/signing-key" > "${tmp}/keys.json"
    pem_of() { echo "-----BEGIN PUBLIC KEY-----"; printf '%s' "$1" | fold -w 64; echo; echo "-----END PUBLIC KEY-----"; }
    pem_of "$(jq -r .publicKey "${tmp}/keys.json")" > "${tmp}/pub.pem"
    if openssl dgst -sha256 -verify "${tmp}/pub.pem" -signature "${tmp}/sig.der" "${tmp}/payload" >/dev/null 2>&1; then
        ok "ECDSA imzası sunucunun birincil imza anahtarıyla doğrulandı ($(jq -r .keyId "${tmp}/keys.json" | cut -c1-12)…)"
    else
        bad "İmza doğrulanamadı (client'taki SIGNING_PUBLIC_KEY ile sunucu anahtarı farklı olabilir)"
    fi
    # Birden çok imzalayıcı (m-of-n): her imza kendi anahtarıyla doğrulanır.
    if jq -e '.signatures | length > 1' "${tmp}/cfg.json" >/dev/null 2>&1; then
        n=0; good=0
        while IFS=$'\t' read -r kid sig; do
            n=$((n + 1))
            pem_of "$(jq -r --arg k "${kid}" '.signers[] | select(.keyId == $k) | .publicKey' "${tmp}/keys.json")" > "${tmp}/k.pem"
            printf '%s' "${sig}" | openssl base64 -d -A > "${tmp}/s.der"
            openssl dgst -sha256 -verify "${tmp}/k.pem" -signature "${tmp}/s.der" "${tmp}/payload" >/dev/null 2>&1 && good=$((good + 1))
        done < <(jq -r '.signatures[] | [.keyId, .signature] | @tsv' "${tmp}/cfg.json")
        if [ "${good}" = "${n}" ]; then ok "${n} imzanın hepsi doğrulandı (m-of-n)"; else bad "${n} imzadan ${good} tanesi doğrulandı"; fi
    fi
    ks="$(jq -r '.keySetVersion // 0' "${tmp}/keys.json")"
    if [ "${ks}" != "0" ]; then echo "          imzalama anahtarı seti: v${ks}"; fi
    if jq -e '.issuedAt > 0 and .expiresAt > (now * 1000)' "${tmp}/payload" >/dev/null; then
        ok "issuedAt/expiresAt dolu, süre geçmemiş"
    else
        bad "issuedAt/expiresAt eksik ya da süresi geçmiş"
    fi
    hosts="$(jq -r '[.pins[] | "\(.hostname) v\(.version)"] | join(", ")' "${tmp}/payload")"
    echo "          pin'li host'lar: ${hosts:-(yok)}"
else
    bad "GET /api/v1/certificate-config cevap vermedi"
fi

echo "[3] Sunucu TLS sertifikası"
echo | openssl s_client -connect "localhost:${HTTPS_PORT}" -servername localhost 2>/dev/null \
    | openssl x509 > "${tmp}/server.pem" 2>/dev/null
if [ -s "${tmp}/server.pem" ]; then
    live_pin="$(openssl x509 -in "${tmp}/server.pem" -pubkey -noout \
        | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64 -A)"
    if grep -qxF "${live_pin}" data/certs/demo-server.pins 2>/dev/null; then
        ok "pin data/certs/demo-server.pins ile aynı (${live_pin:0:12}…)"
    else
        bad "canlı pin (${live_pin:0:12}…) demo-server.pins içinde yok"
    fi
    if [ -n "${HOST_LAN_IP:-}" ]; then
        if openssl x509 -in "${tmp}/server.pem" -noout -text | grep -qE "IP Address:${HOST_LAN_IP//./\\.}(,|$)"; then
            ok "SAN ${HOST_LAN_IP} içeriyor"
        else
            bad "SAN ${HOST_LAN_IP} içermiyor; telefon hostname doğrulamasında reddeder. " \
                "data/certs/demo-server.jks ve demo-server.pins'i silip container'ı yeniden başlat."
        fi
    fi
else
    bad "TLS el sıkışması yapılamadı"
fi

echo "[4] Yetki"
expect_status 401 "PUT  config (anahtarsız, Config API)" \
    -X PUT -H 'Content-Type: application/json' -d '{}' "${HTTPS}/api/v1/certificate-config"
expect_status 401 "GET  vault/distributions (anahtarsız, Config API)" "${HTTPS}/api/v1/vault/distributions"
expect_status 401 "GET  certificate-config/history (anahtarsız)" "${HTTPS}/api/v1/certificate-config/history/x"
if [ -n "${KEY}" ]; then
    expect_status 200 "GET  vault/distributions (anahtarla)" -H "X-API-Key: ${KEY}" "${HTTPS}/api/v1/vault/distributions"
else
    bad "API_KEY .env'de yok; anahtarlı kontrol atlandı"
fi

echo "[5] ping-remote enjeksiyon koruması"
if [ -n "${KEY}" ]; then
    expect_status 400 "hostname='\$(id)'" -H "X-API-Key: ${KEY}" "${HTTP}/api/v1/hosts/%24(id)/ping-remote"
fi

echo "[6] mTLS Config API"
MTLS_PORT="${HOST_MTLS_PORT:-6652}"
if [ -n "${KEY}" ] && curl -fsS -H "X-API-Key: ${KEY}" "${HTTP}/api/v1/all-configs" 2>/dev/null \
        | jq -e 'any(.[]; .mode == "mtls" and .running)' >/dev/null; then
    code="$(status "https://localhost:${MTLS_PORT}/health")"
    if [ "${code}" = "000" ]; then
        ok "istemci sertifikası olmadan el sıkışma reddedildi (:${MTLS_PORT})"
    else
        bad "sertifikasız istek HTTP ${code} aldı; mTLS zorunlu değil (:${MTLS_PORT})"
    fi
else
    echo "    ATLA  mTLS Config API yok; önce ./scripts/provision.sh"
fi

echo "[7] Yönetim API'si: düz HTTP yalnızca bu makinede, ağa şifreli port"
MGMT_TLS_PORT="${HOST_MANAGEMENT_TLS_PORT:-6655}"
bind="$(docker compose port pinvault-host 8080 2>/dev/null | head -1)"
case "${bind}" in
    127.0.0.1:*) ok "düz HTTP yönetim portu yalnızca bu makineye açık (${bind})" ;;
    "") bad "düz HTTP yönetim portu yayımlanmamış" ;;
    *) bad "düz HTTP yönetim portu ağa açık (${bind}); API anahtarı şifresiz gider — HOST_HTTP_BIND=127.0.0.1" ;;
esac
echo | openssl s_client -connect "localhost:${MGMT_TLS_PORT}" -servername localhost 2>/dev/null \
    | openssl x509 > "${tmp}/mgmt.pem" 2>/dev/null
if [ -s "${tmp}/mgmt.pem" ]; then
    mgmt_pin="$(openssl x509 -in "${tmp}/mgmt.pem" -pubkey -noout \
        | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64 -A)"
    if grep -qxF "${mgmt_pin}" data/certs/demo-server.pins 2>/dev/null; then
        ok "şifreli yönetim portu (:${MGMT_TLS_PORT}) config sunucusunun sertifikasını sunuyor: telefonlar aynı pin'lerle raporlar"
    else
        bad "şifreli yönetim portunun pin'i (${mgmt_pin:0:12}…) demo-server.pins içinde yok"
    fi
else
    bad "şifreli yönetim portunda (:${MGMT_TLS_PORT}) TLS el sıkışması yapılamadı"
fi

echo "[8] Vault dosyalarının parolası"
if docker compose exec -T pinvault-host sh -c 'test -n "${VAULT_AT_REST_PASSWORD:-}"' 2>/dev/null; then
    ok "VAULT_AT_REST_PASSWORD dolu: diskteki vault dosyaları demo parolasıyla şifrelenmiyor"
else
    bad "VAULT_AT_REST_PASSWORD boş: sunucu kaynak koddaki demo parolasını kullanıyor (./scripts/setup.sh üretir)"
fi
started="$(docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q pinvault-host)" 2>/dev/null)"
unreadable="$(docker compose logs --no-log-prefix --since "${started}" pinvault-host 2>/dev/null \
    | grep 'VAULT_AT_REST_PASSWORD: .* open with neither' | tail -1)"
if [ -z "${unreadable}" ]; then
    ok "bütün vault dosyaları geçerli parolayla açılıyor"
else
    bad "açılamayan vault dosyaları var: ${unreadable%% open with neither*}"
fi

echo ""
echo "== Sonuç: ${pass} PASS, ${fail} FAIL =="
[ "${fail}" -eq 0 ]
