#!/usr/bin/env bash
# Kişisel yönetici anahtarı üretir. Sunucuya yalnızca anahtarın SHA-256'sı
# verilir (ADMIN_KEYS=ad:sha256,...); anahtarın kendisi bir kez gösterilir ve
# sahibine güvenli bir kanaldan iletilir. Denetim kaydı değişiklikleri bu adla
# yazar; iki kişi onayı (PIN_CHANGE_APPROVALS=2) isteyenle onaylayanı bu
# adlardan ayırır.
#
#   ./scripts/add-admin.sh alice            # anahtar + ADMIN_KEYS satırı
#   ./scripts/add-admin.sh alice --apply    # ayrıca .env'deki ADMIN_KEYS'e ekler
#
# Değişiklik sonrası: docker compose up -d (ya da env-override.sh ile).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

name="${1:?Kullanım: $0 <ad> [--apply]}"
[[ "${name}" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || { echo "Ad yalnızca harf, rakam, . _ - (en çok 32)" >&2; exit 2; }
[ "${name}" = "admin" ] && { echo "'admin' adı API_KEY'e ayrılmış" >&2; exit 2; }

key="$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-43)"
hash="$(printf '%s' "${key}" | openssl dgst -sha256 | awk '{print $NF}')"
entry="${name}:${hash}"

echo "Yönetici     : ${name}"
echo "Anahtar      : ${key}"
echo "               (bir kez gösterilir; dashboard'da X-API-Key olarak girilir)"
echo "ADMIN_KEYS   : ${entry}"

if [ "${2:-}" = "--apply" ]; then
    [ -f .env ] || { echo ".env yok — önce ./scripts/setup.sh" >&2; exit 1; }
    current="$(sed -n 's/^ADMIN_KEYS=//p' .env | tail -1)"
    if printf '%s' "${current}" | tr ',' '\n' | grep -q "^${name}:"; then
        echo "${name} zaten ADMIN_KEYS içinde; önce çıkar." >&2; exit 1
    fi
    updated="${current:+${current},}${entry}"
    if grep -q '^ADMIN_KEYS=' .env; then
        sed -i.bak "s|^ADMIN_KEYS=.*|ADMIN_KEYS=${updated}|" .env && rm -f .env.bak
    else
        printf '\nADMIN_KEYS=%s\n' "${updated}" >> .env
    fi
    chmod 600 .env
    echo ".env güncellendi. Etkinleştir: docker compose up -d"
fi
