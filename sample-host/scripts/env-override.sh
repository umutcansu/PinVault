#!/usr/bin/env bash
# Sunucu ortam değişkenlerini .env'e dokunmadan geçici olarak değiştirir ve
# container'ı yeni değerlerle yeniden oluşturur; "reset" ile .env değerlerine
# döner. Deneyler ve uçtan uca testler için (örn. kısa config süresi, açık
# kayıt modu, şifreli imzalama anahtarı).
#
#   ./scripts/env-override.sh set CONFIG_TTL_SECONDS=60 ENROLLMENT_MODE=open
#   ./scripts/env-override.sh set SIGNING_KEY_PASSWORD=gizli
#   ./scripts/env-override.sh reset
#
# Compose, kabuk ortamındaki değişkeni .env'dekine tercih eder; bu betik
# değişkenleri dışa aktarıp `docker compose up -d` çalıştırır. Sağlık ucu
# yanıt verene kadar bekler.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

usage() {
    echo "Kullanım: $0 set KEY=VALUE [KEY=VALUE ...] | reset" >&2
    exit 2
}

[ $# -ge 1 ] || usage
cmd="$1"; shift

case "${cmd}" in
    set)
        [ $# -ge 1 ] || usage
        for kv in "$@"; do
            case "${kv}" in
                *=*) export "${kv}" ;;
                *) echo "Geçersiz: ${kv} (KEY=VALUE bekleniyor)" >&2; exit 2 ;;
            esac
        done
        ;;
    reset)
        # Kabukta dışa aktarılmış olabilecek geçici değerleri temizle; .env geçerli olsun.
        for key in CONFIG_TTL_SECONDS ENROLLMENT_MODE SIGNING_KEY_PASSWORD ENROLLMENT_TOKEN_TTL_SECONDS \
                   VAULT_AT_REST_PASSWORD CERT_EXPIRY_WARN_DAYS KEYSTORE_PASSWORD ALLOW_ANONYMOUS_ADMIN; do
            unset "${key}"
        done
        ;;
    *) usage ;;
esac

docker compose up -d --no-build >/dev/null

HTTP_PORT="$(sed -n 's/^HOST_HTTP_PORT=//p' .env 2>/dev/null | tail -1)"
HTTP="http://localhost:${HTTP_PORT:-6650}"
for _ in $(seq 1 60); do
    if curl -fsS "${HTTP}/health" >/dev/null 2>&1; then
        echo "Host hazır: ${HTTP} (${cmd})"
        exit 0
    fi
    sleep 1
done
echo "Host 60 saniyede ayağa kalkmadı: docker compose logs pinvault-host" >&2
exit 1
