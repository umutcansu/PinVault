#!/usr/bin/env bash
# Örnek uygulamanın (sample-client) Vault ekranındaki dosyaları, uygulamanın
# beklediği politika ve şifrelemeyle yükler. Tekrar çalıştırmak güvenlidir:
# var olan dosyaya dokunmaz (--force ile içeriği yeniler, sürüm artar).
#
#   Herkese açık (Config API default-tls):
#     sample-flags   public     plain        herkese açık demo dosyası
#     sample-atrest  public     at_rest      sunucu diskinde şifreli, ama herkese açık
#     sample-admin   api_key    plain        cihazdan inmez (yalnızca sunucu araçları)
#     sample-model   public     plain        dosya deposu, config ile eşitlenir
#   Gizli (mTLS Config API sample-mtls; provision.sh açar):
#     sample-secret       token_mtls  user_auth   sunucu telefonun ekran kilidi anahtarına kilitler
#     sample-mtls-secret  token_mtls  user_auth   (aynı)
#     sample-e2e          token_mtls  end_to_end  cihazın RSA anahtarıyla; telefon kilitleyip saklar
#
# Gizli dosyalar için ayrıca her cihaza dashboard'dan token üretilir (dosya
# detayı → Token, "Cihaz ID" = telefondaki Vault ekranındaki kimlik). Telefon
# önce mTLS'e kayıt olmalı ve ekran kilidi olmalı.
#
# Uçtan uca testler bunu çalıştırmaz: her senaryo kendi dosyasını yükleyip siler.
#
# Kullanım: ./scripts/seed-vault.sh [--force]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=scripts/lib.sh
. "${SCRIPT_DIR}/lib.sh"
load_env

HTTP="http://localhost:${HOST_HTTP_PORT:-6650}"
KEY="${ADMIN_KEY:-${API_KEY:?API_KEY .env içinde yok — ./scripts/setup.sh}}"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

# Anahtar komut satırına yazılmaz (lib.sh → curl_with_key).
api() { curl_with_key "${KEY}" -fsS "$@"; }

exists() { # $1 = Config API, $2 = anahtar
    api "${HTTP}/api/v1/config-apis/$1/vault" | jq -e --arg k "$2" 'any(.[]; .key == $k)' >/dev/null
}

upload() { # $1 = Config API, $2 = anahtar, $3 = politika, $4 = şifreleme, $5 = içerik
    if [ "${FORCE}" = 0 ] && exists "$1" "$2"; then
        echo ">> $1/$2 zaten var (değiştirmek için --force)"
        return
    fi
    local version
    version="$(printf '%s' "$5" | api -X PUT -H 'Content-Type: application/octet-stream' --data-binary @- \
        "${HTTP}/api/v1/config-apis/$1/vault/$2?policy=$3&encryption=$4" | jq -r .version)"
    echo ">> $1/$2 v${version} yüklendi (politika $3, şifreleme $4)"
}

api "${HTTP}/api/v1/all-configs" | jq -e 'any(.[]; .id == "sample-mtls" and .running)' >/dev/null \
    || { echo "mTLS Config API (sample-mtls) çalışmıyor — önce ./scripts/provision.sh" >&2; exit 1; }

upload default-tls sample-flags  public  plain   '{"yeniOdemeEkrani": true, "not": "herkese açık demo dosyası"}'
upload default-tls sample-atrest public  at_rest 'Herkese açık katalog. Sunucunun diskinde şifreli durur ama isteyen herkes indirir.'
upload default-tls sample-admin  api_key plain   'Yalnızca sunucu araçları içindir; cihazdan inmez.'
upload default-tls sample-model  public  plain   'model v1 (gizli değil; dosya deposu örneği)'

upload sample-mtls sample-secret      token_mtls user_auth  'Gizli: yalnızca bu cihazın sertifikası, token ve ekran kilidiyle açılır.'
upload sample-mtls sample-mtls-secret token_mtls user_auth  'Gizli (mTLS): sertifika + token + ekran kilidi.'
upload sample-mtls sample-e2e         token_mtls end_to_end 'Gizli: cihazın RSA anahtarıyla şifreli gelir, telefonda ekran kilidiyle saklanır.'

cat <<EOF

Gizli dosyalar için her telefona token üret: dashboard → sample-mtls → Vault →
dosya → Token ("Cihaz ID" telefondaki Vault ekranında yazar), token'ı
telefondaki Vault ekranına gir.
EOF
