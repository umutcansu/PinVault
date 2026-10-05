#!/usr/bin/env bash
# sample-host smoke test. Çalışan container'a karşı şunları doğrular:
#   1. /health
#   2. İmzalı config: ECDSA imzası sunucunun GET /api/v1/signing-key ile bildirdiği anahtar(lar)la
#      doğrulanıyor, issuedAt/expiresAt dolu ve süresi geçmemiş
#   3. TLS: sunucu sertifikasının pin'i data/certs/demo-server.pins ile aynı,
#      SAN listesi HOST_LAN_IP'yi içeriyor (telefonun hostname doğrulaması)
#   4. Yetki: yönetim uçları anahtarsız 401, anahtarla 200; vault yönetimi yalnızca
#      yönetim portunda (Config API portunda anahtarla bile yok)
#   5. ping-remote komut enjeksiyonu reddediliyor (400)
#   6. mTLS Config API istemci sertifikası olmadan bağlantıyı reddediyor
#   7. Yönetim API'si: düz HTTP yalnızca bu makinede; üretim profilinde şifreli
#      yönetim portu da yalnızca bu makinede ve mock host portları yayımlanmamış;
#      üretim profilinde ayrıca iki kişi onayı, canlı sertifika kontrolü, donanım
#      belgesi ayarları, en az iki kişisel yönetici, kurtarma anahtarı, en az iki
#      imzalayıcı (biri sunucunun diski dışında, SoftHSM sayılmaz) ve iptal
#      listesinin yaşı
#   8. Parolalar: vault dosyalarının parolası dolu ve bütün dosyaları açıyor; imza
#      anahtarı diskte şifreli; sunucu demo parolalarıyla açılmamış
#   9. Cihaz raporları (telemetri) Config API portundan kabul ediliyor: telefonlar
#      yönetim portuna ihtiyaç duymuyor
#
# Gereksinimler: curl, jq, openssl
# Kullanım: ./scripts/smoke-test.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=scripts/lib.sh
. "${SCRIPT_DIR}/lib.sh"
load_env

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
# Aynısı, yönetim anahtarıyla; anahtar komut satırına yazılmaz (lib.sh).
status_with_key() { curl_with_key "${KEY}" -sk -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
expect_status_with_key() {
    local want="$1" label="$2"; shift 2
    local got
    got="$(status_with_key "$@")"
    if [ "${got}" = "${want}" ]; then ok "${label} → ${got}"; else bad "${label} → ${got} (beklenen ${want})"; fi
}
# Sunucu pin'leri (host'tan okunamazsa container'dan; lib.sh).
PINS_NOW="$(host_pins 2>/dev/null || true)"
pin_known() { printf '%s\n' "${PINS_NOW}" | grep -qxF "$1"; }

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
    if pin_known "${live_pin}"; then
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
expect_status 401 "GET  certificate-config/history (anahtarsız)" "${HTTPS}/api/v1/certificate-config/history/x"
# Vault yönetimi (yükleme, silme, dağıtım listesi, token'lar) yalnızca yönetim
# portunda ve Config API kapsamıyla: /api/v1/config-apis/<kimlik>/vault/…
VAULT_ADMIN="${HTTP}/api/v1/config-apis/default-tls/vault/distributions"
expect_status 401 "GET  vault/distributions (anahtarsız, yönetim portu)" "${VAULT_ADMIN}"
if [ -n "${KEY}" ]; then
    expect_status_with_key 200 "GET  vault/distributions (anahtarla, yönetim portu)" "${VAULT_ADMIN}"
    # Config API portunda vault yönetimi hiç yok: anahtarla da 404.
    expect_status_with_key 404 "GET  vault/distributions (anahtarla, Config API: yönetim yok)" "${HTTPS}/api/v1/vault/distributions"
else
    bad "API_KEY .env'de yok; anahtarlı kontrol atlandı"
fi

echo "[5] ping-remote enjeksiyon koruması"
if [ -n "${KEY}" ]; then
    expect_status_with_key 400 "hostname='\$(id)'" "${HTTP}/api/v1/hosts/%24(id)/ping-remote"
fi

echo "[6] mTLS Config API"
MTLS_PORT="${HOST_MTLS_PORT:-6652}"
if [ -n "${KEY}" ] && curl_with_key "${KEY}" -fsS "${HTTP}/api/v1/all-configs" 2>/dev/null \
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

echo "[7] Yönetim API'si: düz HTTP yalnızca bu makinede"
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
    if pin_known "${mgmt_pin}"; then
        ok "şifreli yönetim portu (:${MGMT_TLS_PORT}) config sunucusunun sertifikasını sunuyor"
    else
        bad "şifreli yönetim portunun pin'i (${mgmt_pin:0:12}…) demo-server.pins içinde yok"
    fi
else
    bad "şifreli yönetim portunda (:${MGMT_TLS_PORT}) TLS el sıkışması yapılamadı"
fi

if is_production; then
    mgmt_bind="$(docker compose port pinvault-host 8082 2>/dev/null | head -1)"
    case "${mgmt_bind}" in
        127.0.0.1:*) ok "üretim: şifreli yönetim portu yalnızca bu makineye açık (${mgmt_bind}); uzaktan VPN ya da SSH tüneliyle" ;;
        *) bad "üretim: şifreli yönetim portu ağa açık (${mgmt_bind:-yayımlanmamış}); docker-compose.production.yml devrede mi? (.env → COMPOSE_FILE)" ;;
    esac
    for mock_port in 8443 8444; do
        if [ -z "$(docker compose port pinvault-host "${mock_port}" 2>/dev/null | head -1)" ]; then
            ok "üretim: mock host portu (container :${mock_port}) yayımlanmamış"
        else
            bad "üretim: mock host portu (container :${mock_port}) yayımlanmış"
        fi
    done
    for flag in ALLOW_TEST_HOOKS ALLOW_ANONYMOUS_ADMIN; do
        if docker compose exec -T pinvault-host sh -c "[ \"\${${flag}:-}\" != true ]" 2>/dev/null; then
            ok "üretim: ${flag} kapalı"
        else
            bad "üretim: ${flag}=true (ya da container'a ulaşılamadı)"
        fi
    done
    # Container'ın gerçekten gördüğü değerler (entrypoint.sh aynılarını açılışta denetler).
    container_env() { docker compose exec -T pinvault-host sh -c "printf '%s' \"\${$1:-}\"" 2>/dev/null || true; }
    for pair in PIN_CHANGE_APPROVALS=2 PIN_LIVE_CHECK=enforce USER_AUTH_ATTESTATION=enforce \
                ENROLLMENT_ATTESTATION=enforce ENROLLMENT_P12=off USER_AUTH_REQUIRE_PER_USE=true \
                ATTESTATION_REQUIRE_VERIFIED_BOOT=true; do
        name="${pair%%=*}" want="${pair#*=}"
        got="$(container_env "${name}" | tr 'A-Z' 'a-z')"
        # Sunucu varsayılanı: boş ATTESTATION_REQUIRE_VERIFIED_BOOT = true.
        [ "${name}" != ATTESTATION_REQUIRE_VERIFIED_BOOT ] || [ -n "${got}" ] || got=true
        if [ "${got}" = "${want}" ]; then ok "üretim: ${name}=${want}"; else bad "üretim: ${name}='${got}' (beklenen ${want})"; fi
    done
    admins="$( { container_env ADMIN_KEYS | tr ',' '\n'; f="$(container_env ADMIN_KEYS_FILE)"; [ -z "${f}" ] || docker compose exec -T pinvault-host cat "${f}" 2>/dev/null; } \
        | sed -e 's/^[[:space:]]*//' -e '/^#/d' -e '/^$/d' | wc -l | tr -d ' ')"
    if [ "${admins}" -ge 2 ]; then ok "üretim: ${admins} kişisel yönetici (iki kişi onayı)"; else bad "üretim: ${admins} kişisel yönetici; en az 2 gerekir (ADMIN_KEYS)"; fi
    if [ -n "$(container_env RECOVERY_PUBLIC_KEYS | tr -d ' ,')" ]; then ok "üretim: kurtarma anahtarı (RECOVERY_PUBLIC_KEYS) dolu"; else bad "üretim: RECOVERY_PUBLIC_KEYS boş"; fi
    # İmzalayıcılar sunucunun kendisinden: en az iki, en az biri diskin dışında (SoftHSM sayılmaz).
    if [ -n "${KEY}" ] && curl_with_key "${ADMIN_KEY:-${KEY}}" -fsS --max-time 10 "${HTTP}/api/v1/signing/status" > "${tmp}/signers.json" 2>/dev/null; then
        n_signers="$(jq -r '.signers | length' "${tmp}/signers.json")"
        n_external="$(jq -r '[.signers[] | select(.type == "command" or (.type == "pkcs11" and ((.description // "") | test("softhsm"; "i") | not)))] | length' "${tmp}/signers.json")"
        if [ "${n_signers}" -ge 2 ] && [ "${n_external}" -ge 1 ]; then
            ok "üretim: ${n_signers} imzalayıcı, ${n_external} tanesi sunucunun diski dışında"
        elif [ "${SAMPLE_EVALUATION:-}" = "single-signer" ]; then
            echo "    UYARI üretim DEĞİL: ${n_signers} imzalayıcı, ${n_external} tanesi diskin dışında (SAMPLE_EVALUATION=single-signer)"
        else
            bad "üretim: ${n_signers} imzalayıcı, ${n_external} tanesi sunucunun diski dışında; en az 2 ve en az 1 HSM/KMS gerekir (SoftHSM sayılmaz)"
        fi
    else
        bad "üretim: GET /api/v1/signing/status okunamadı (yönetici anahtarı: ADMIN_KEY=…)"
    fi
    # Donanım belgesi iptal listesi: varsa yaşı (cron çalışıyor mu).
    list_file="$(container_env ATTESTATION_REVOKED_SERIALS_FILE)"
    if [ -z "${list_file}" ]; then
        bad "üretim: ATTESTATION_REVOKED_SERIALS_FILE boş (Google'ın iptal listesi okunmuyor)"
    elif age_h="$(docker compose exec -T pinvault-host sh -c 'echo $(( ($(date +%s) - $(stat -c %Y "$1")) / 3600 ))' sh "${list_file}" 2>/dev/null)"; then
        max_h="$(container_env ATTESTATION_STATUS_MAX_AGE_HOURS)"
        if [ -n "${max_h}" ] && [ "${age_h}" -ge "${max_h}" ]; then
            bad "üretim: donanım belgesi iptal listesi ${age_h} saatlik (sınır ${max_h}); hiçbir belge geçmiyor. ./scripts/fetch-attestation-status.sh cron'da mı?"
        else
            ok "üretim: donanım belgesi iptal listesi ${age_h} saatlik${max_h:+ (sınır ${max_h})}"
        fi
    else
        bad "üretim: ${list_file} okunamadı (./scripts/fetch-attestation-status.sh)"
    fi
fi

echo "[8] Parolalar"
if docker compose exec -T pinvault-host sh -c 'test -n "${VAULT_AT_REST_PASSWORD:-}"' 2>/dev/null; then
    ok "VAULT_AT_REST_PASSWORD dolu: diskteki vault dosyaları demo parolasıyla şifrelenmiyor"
else
    bad "VAULT_AT_REST_PASSWORD boş: sunucu kaynak koddaki demo parolasını kullanıyor (./scripts/setup.sh üretir)"
fi
if docker compose exec -T pinvault-host sh -c 'test -n "${KEYSTORE_PASSWORD:-}"' 2>/dev/null; then
    ok "KEYSTORE_PASSWORD dolu: sunucunun anahtar depoları \"changeit\" ile korunmuyor"
else
    bad "KEYSTORE_PASSWORD boş (./scripts/setup.sh üretir)"
fi
if docker compose exec -T pinvault-host sh -c '[ "${ALLOW_DEMO_SECRETS:-}" != true ]' 2>/dev/null; then
    ok "ALLOW_DEMO_SECRETS kapalı: sunucu demo parolalarıyla açılmaz"
else
    bad "ALLOW_DEMO_SECRETS=true: eksik parola kaynak koddaki demo değerine düşer (.env'den kaldır)"
fi
# İmza anahtarı dosyası: sunucuda yerel imzalayıcı varsa diskte "ENCv1:" ile şifreli.
key_head="$(docker compose exec -T -u "$(container_user)" pinvault-host sh -c 'head -c 6 /data/signing-key.pem 2>/dev/null' 2>/dev/null || true)"
case "${key_head}" in
    ENCv1:) ok "imza anahtarı diskte şifreli (SIGNING_KEY_PASSWORD)" ;;
    "") echo "    ATLA  data/signing-key.pem yok (sunucuda yerel imzalayıcı yok ya da container'a ulaşılamadı)" ;;
    *) bad "imza anahtarı diskte DÜZ METİN: SIGNING_KEY_PASSWORD boş mu? (./scripts/setup.sh üretir, sunucu açılışta şifreler)" ;;
esac
started="$(docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q pinvault-host)" 2>/dev/null)"
unreadable="$(docker compose logs --no-log-prefix --since "${started}" pinvault-host 2>/dev/null \
    | grep 'VAULT_AT_REST_PASSWORD: .* open with neither' | tail -1)"
if [ -z "${unreadable}" ]; then
    ok "bütün vault dosyaları geçerli parolayla açılıyor"
else
    bad "açılamayan vault dosyaları var: ${unreadable%% open with neither*}"
fi

echo "[9] Cihaz raporları Config API portundan"
# Boş bir rapor: sunucu biçimi reddeder (400) ama ucu bulur ve anahtar istemez.
report_code="$(status -X POST -H 'Content-Type: application/json' -d '{}' "${HTTPS}/api/v1/connection-history/client-report")"
case "${report_code}" in
    200|202|400|422|429) ok "POST connection-history/client-report (Config API, anahtarsız) → ${report_code}: telefonlar yönetim portuna bağlanmadan rapor gönderir" ;;
    000|401|403|404) bad "POST connection-history/client-report (Config API) → ${report_code}; telefonların raporları ulaşmaz" ;;
    *) echo "    ATLA  POST connection-history/client-report → ${report_code} (beklenmeyen kod)" ;;
esac

echo ""
echo "== Sonuç: ${pass} PASS, ${fail} FAIL =="
[ "${fail}" -eq 0 ]
