#!/usr/bin/env bash
# Google'ın donanım belgesi (Android Key Attestation) iptal listesini indirir:
# iptal edilmiş ya da askıya alınmış belge sertifikaları. Sunucu internete hiç
# çıkmaz; listeyi ATTESTATION_REVOKED_SERIALS_FILE'ın gösterdiği dosyadan okur
# (varsayılan /data/attestation-status.json = host'ta data/attestation-status.json),
# dosya değişince yeniden okur (10 dakikada bir bakar). Dosya yoksa sunucu
# açılmaz; ATTESTATION_STATUS_MAX_AGE_HOURS doluysa (üretim: 48) dosya o kadar
# saatten eskiyken hiçbir belge geçmez. Bu yüzden betik cron'dan çalışmalı, ör.
# 6 saatte bir:
#
#   0 */6 * * *  cd /yol/sample-host && PATH=/usr/local/bin:/usr/bin:/bin ./scripts/fetch-attestation-status.sh 2>&1 | logger -t pinvault-attestation
#
# demo-server/scripts/fetch-attestation-status.sh ile aynı işi yapar (aynı curl
# ayarları, aynı denetim), yalnızca sample-host'a göre: hedef yolu .env'den alır,
# data/ bu kullanıcıya yazılabilir değilse (Linux'ta data/ servis kullanıcısına
# aittir) dosyayı çalışan container'ın içinden, servis kullanıcısıyla yerine koyar.
#
# Yeni liste önce geçici dosyaya iner; tam indiyse ve gerçekten iptal listesine
# benziyorsa ("entries" alanı olan bir JSON) tek bir yeniden adlandırmayla eskisinin
# yerine geçer. Sunucu yarım dosya ya da hata sayfası görmez. Bir şey ters giderse
# eski dosya olduğu gibi kalır (ve eskir; ATTESTATION_STATUS_MAX_AGE_HOURS bunu fark eder).
#
# Kullanım: ./scripts/fetch-attestation-status.sh [adres]
#   (varsayılan adres https://android.googleapis.com/attestation/status)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=scripts/lib.sh
. "${SCRIPT_DIR}/lib.sh"
load_env

die() { echo "fetch-attestation-status: $*" >&2; exit 1; }

case "${1:-}" in
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
esac
URL="${1:-https://android.googleapis.com/attestation/status}"

# Container içindeki yol → host'taki yol (data/ bağlaması).
CONTAINER_PATH="${ATTESTATION_REVOKED_SERIALS_FILE:-/data/attestation-status.json}"
case "${CONTAINER_PATH}" in
    /data/*) ;;
    *) die "ATTESTATION_REVOKED_SERIALS_FILE=${CONTAINER_PATH} /data altında değil; bu betik yalnızca data/ bağlamasına yazar." ;;
esac
REL="${CONTAINER_PATH#/data/}"
case "/${REL}/" in
    */../*|*/./*|//) die "ATTESTATION_REVOKED_SERIALS_FILE geçersiz: ${CONTAINER_PATH}" ;;
esac
HOST_PATH="data/${REL}"
HOST_DIR="$(dirname "${HOST_PATH}")"

TMP="$(mktemp -t pinvault-attestation.XXXXXX)"
trap 'rm -f "${TMP}"' EXIT INT TERM

# --fail: HTTP hatası dosya değil hatadır. -R yok: dosyanın zamanı bu indirmenin
# zamanıdır; sunucu yaşı buna göre ölçer.
curl --silent --show-error --fail --location --proto '=https' --tlsv1.2 \
    --max-time 60 --retry 3 --retry-delay 5 \
    --header 'Cache-Control: no-cache' \
    --output "${TMP}" "${URL}"

# Liste "entries" alanı olan bir JSON nesnesi; başka bir şey (boş gövde, otel
# ağının giriş sayfası) kurulmaz.
if command -v jq >/dev/null 2>&1; then
    jq -e 'type == "object" and has("entries")' "${TMP}" >/dev/null 2>&1 \
        || die "${URL} iptal listesi döndürmedi; ${HOST_PATH} olduğu gibi kaldı."
elif ! head -c 4096 "${TMP}" | grep -q '"entries"'; then
    die "${URL} iptal listesi döndürmedi; ${HOST_PATH} olduğu gibi kaldı."
fi

SIZE="$(wc -c < "${TMP}" | tr -d ' ')"
mkdir -p "${HOST_DIR}" 2>/dev/null || true
if [ -d "${HOST_DIR}" ] && [ -w "${HOST_DIR}" ]; then
    # Aynı dizinde geçici dosya: yeniden adlandırma tek adımda olur.
    NEXT="$(mktemp "${HOST_DIR}/.attestation-status.XXXXXX")"
    cat "${TMP}" > "${NEXT}"
    chmod 0644 "${NEXT}"
    mv -f "${NEXT}" "${HOST_PATH}"
elif [ -n "$(docker compose ps -q pinvault-host 2>/dev/null || true)" ]; then
    # data/ servis kullanıcısına ait (Linux): dosyayı container'ın içinden, o
    # kullanıcıyla ve yine tek bir yeniden adlandırmayla koy.
    docker compose exec -T -u "$(container_user)" pinvault-host sh -c \
        'umask 022; d="$(dirname "$1")"; t="$(mktemp "$d/.attestation-status.XXXXXX")" && cat > "$t" && chmod 0644 "$t" && mv -f "$t" "$1"' \
        sh "${CONTAINER_PATH}" < "${TMP}" \
        || die "dosya container'ın içinden yazılamadı; ${HOST_PATH} olduğu gibi kaldı."
else
    die "${HOST_DIR} bu kullanıcıya yazılabilir değil ve container çalışmıyor. Container'ı başlatıp yeniden dene ya da betiği data/'nın sahibi olan kullanıcıyla çalıştır."
fi
trap - EXIT INT TERM
rm -f "${TMP}"
echo "fetch-attestation-status: ${HOST_PATH} güncellendi (${SIZE} bayt)"
