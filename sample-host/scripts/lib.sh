# shellcheck shell=bash
# sample-host betiklerinin ortak yardımcıları. Tek başına çalıştırılmaz:
#   . "${SCRIPT_DIR}/lib.sh"
# Çağıran betik sample-host kök dizininde (cd "${ROOT_DIR}") olmalıdır.

# Betiklerin ürettiği her dosya yalnızca sahibine açık olsun (.env, anahtarlar,
# dışa aktarılan değerler).
umask 077

# .env'i kabuk değişkenlerine alır (varsa).
load_env() {
    if [ -f .env ]; then
        set -a
        # shellcheck disable=SC1091
        . ./.env
        set +a
    fi
}

# Yönetim anahtarıyla curl. Anahtar komut satırına YAZILMAZ (komut satırı, `ps`
# ile makinedeki herkese görünür): başlık curl'e bir dosya tanıtıcısından
# okutulur (-H @dosya; curl 7.55+). printf kabuğun kendi komutudur, ayrı süreç
# açmaz.
#   curl_with_key "<anahtar>" [curl seçenekleri…] <url>
curl_with_key() {
    local key="$1"; shift
    curl -H @<(printf 'X-API-Key: %s\n' "${key}") "$@"
}

# Sunucu TLS sertifikasının pin'leri (birincil + yedek), satır satır. Dosya
# host'tan okunamıyorsa (Linux'ta data/ servis kullanıcısına aittir ve ilk
# açılışta dosya yalnızca ona açık oluşur) container'ın içinden okunur.
# İçerik gizli değildir.
host_pins() {
    if [ -r data/certs/demo-server.pins ]; then
        cat data/certs/demo-server.pins
    else
        docker compose exec -T -u "$(container_user)" pinvault-host cat /data/certs/demo-server.pins 2>/dev/null
    fi
}

# Container içinde data/ dosyalarının sahibi olan kullanıcı (uid:gid): imajdaki
# pinvault (10001) ya da .env'deki PINVAULT_UID / PINVAULT_GID (entrypoint.sh).
# `docker compose exec -u` ile dosya okuyan betikler bunu kullanır.
container_user() {
    local uid="${PINVAULT_UID:-10001}"
    printf '%s:%s' "${uid}" "${PINVAULT_GID:-${uid}}"
}

# Bu kurulum üretim profilinde mi (.env → SAMPLE_PROFILE)?
is_production() {
    [ "${SAMPLE_PROFILE:-demo}" = "production" ]
}
