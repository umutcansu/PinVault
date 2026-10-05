#!/usr/bin/env bash
# Çevrimdışı anahtarları üretir. BU BETİK SUNUCUDA ÇALIŞTIRILMAZ.
#
# Kurtarma ve yedek imza anahtarları, sunucunun imza anahtarı çalındığında ya da
# kaybolduğunda devreye giren anahtarlardır. Sunucuda üretilir ya da saklanırlarsa
# sunucuyu ele geçiren hepsini birden alır ve anlamları kalmaz. Bu yüzden:
#
#   - Bu dosyayı (yalnızca bu dosyayı; başka hiçbir şeye ihtiyacı yok) internete
#     bağlı olmayan bir makineye kopyala. Gereken tek araç: openssl.
#   - Anahtarları orada üret. Özel yarılar parolayla şifreli yazılır ve o makineden
#     (ya da şifreli bir taşınabilir diskten / donanım token'ından) hiç çıkmaz.
#   - Sunucuya yalnızca ekrana yazılan PUBLIC yarıları götür:
#       ./scripts/setup.sh --production --recovery-public-key … --backup-public-key …
#
# Kullanım:
#   ./offline-keygen.sh keys recovery-1 backup-1   # her ad için <ad>.pem (şifreli) + <ad>.pub
#   ./offline-keygen.sh pub recovery-1             # public yarıyı yeniden yazdır
#   ./offline-keygen.sh admin ayse                 # kişisel yönetici anahtarı + ad:sha256
#
# Çıktı dizini: OFFLINE_KEYS_DIR (varsayılan: bulunduğun dizinde ./offline-keys, 0700).
# Parola sorulur (en az 12 karakter, iki kez). Otomasyon için parola bir dosyadan
# okunabilir: OFFLINE_KEY_PASSPHRASE_FILE=/yol/parola.txt
#
# Anahtar seti imzalamak ya da yedek anahtarı sunucuya kurmak gerektiğinde
# signing-keys.sh de bu çevrimdışı makinede çalıştırılır; openssl parolayı sorar.
#
# Özel anahtarı iki ayrı yerde yedekle (ör. iki ayrı kasadaki iki şifreli disk)
# ve parolayı anahtarla aynı yerde tutma. Parola unutulursa anahtar geri gelmez.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${OFFLINE_KEYS_DIR:-${PWD}/offline-keys}"

die() { echo "!! $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl gerekli."

# Sunucuda mı çalışıyoruz? Betik sample-host/scripts altındaysa ve yanında bir
# kurulum (.env ya da dolu data/) varsa burası sunucudur: üretme.
refuse_on_server() {
    local root
    root="$(cd "${SCRIPT_DIR}/.." && pwd)"
    if [ -f "${root}/.env" ] || [ -n "$(find "${root}/data" -type f ! -name '.gitkeep' 2>/dev/null | head -n 1)" ]; then
        cat >&2 <<EOF
!! Bu makine sunucu gibi görünüyor: ${root} altında bir kurulum var (.env ya da data/).
!! Çevrimdışı anahtarlar sunucuda ÜRETİLMEZ. Bu dosyayı internete kapalı başka bir
!! makineye kopyalayıp orada çalıştır; buraya yalnızca public yarıları getir.
EOF
        exit 1
    fi
}

key_id() { # Base64 SPKI → Base64 SHA-256 (telefonun ve sunucunun gösterdiği anahtar kimliği)
    printf '%s' "$1" | openssl base64 -d -A | openssl dgst -sha256 -binary | openssl base64 -A
}

read_passphrase() {
    if [ -n "${OFFLINE_KEY_PASSPHRASE_FILE:-}" ]; then
        [ -r "${OFFLINE_KEY_PASSPHRASE_FILE}" ] || die "Parola dosyası okunamıyor: ${OFFLINE_KEY_PASSPHRASE_FILE}"
        OFFLINE_KEY_PASSPHRASE="$(head -n 1 "${OFFLINE_KEY_PASSPHRASE_FILE}")"
    else
        [ -t 0 ] || die "Parola sorulamıyor (terminal yok). OFFLINE_KEY_PASSPHRASE_FILE ile bir dosyadan ver."
        local again
        read -r -s -p "Özel anahtarların parolası (en az 12 karakter): " OFFLINE_KEY_PASSPHRASE; echo >&2
        read -r -s -p "Parola (tekrar): " again; echo >&2
        [ "${OFFLINE_KEY_PASSPHRASE}" = "${again}" ] || die "Parolalar aynı değil."
    fi
    [ "${#OFFLINE_KEY_PASSPHRASE}" -ge 12 ] || die "Parola en az 12 karakter olmalı."
    # openssl parolayı ortamdan okur (-pass env:…): komut satırında görünmez.
    export OFFLINE_KEY_PASSPHRASE
}

cmd="${1:-}"; shift || true
case "${cmd}" in
    keys)
        [ $# -ge 1 ] || die "Kullanım: $0 keys <ad> [<ad> …]   (ör. recovery-1 backup-1)"
        refuse_on_server
        for name in "$@"; do
            [[ "${name}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "Ad yalnızca harf, rakam, . _ - olabilir: ${name}"
            [ ! -e "${KEYS_DIR}/${name}.pem" ] || die "Zaten var: ${KEYS_DIR}/${name}.pem (üzerine yazılmaz)"
        done
        read_passphrase
        mkdir -p "${KEYS_DIR}"; chmod 700 "${KEYS_DIR}"
        echo ""
        for name in "$@"; do
            # ECDSA P-256, PKCS#8, AES-256 ile parolayla şifreli. Şifresiz ara dosya yok.
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve \
                -aes-256-cbc -pass env:OFFLINE_KEY_PASSPHRASE -out "${KEYS_DIR}/${name}.pem" 2>/dev/null \
                || die "Anahtar üretilemedi (openssl genpkey)."
            chmod 600 "${KEYS_DIR}/${name}.pem"
            pub="$(openssl pkey -in "${KEYS_DIR}/${name}.pem" -passin env:OFFLINE_KEY_PASSPHRASE -pubout -outform DER | openssl base64 -A)"
            printf '%s\n' "${pub}" > "${KEYS_DIR}/${name}.pub"
            chmod 644 "${KEYS_DIR}/${name}.pub"
            echo "${name}"
            echo "  özel anahtar : ${KEYS_DIR}/${name}.pem  (parolayla şifreli; bu makineden çıkmaz)"
            echo "  public key   : ${pub}"
            echo "  anahtar kimliği: $(key_id "${pub}")"
            echo ""
        done
        unset OFFLINE_KEY_PASSPHRASE
        cat <<'EOF'
Sunucuya götürülecek olan yalnızca yukarıdaki "public key" satırlarıdır:
  ./scripts/setup.sh --production --recovery-public-key <recovery…> --backup-public-key <backup…> …
*.pem dosyalarını sunucuya, e-postaya, sohbet uygulamasına ya da depoya KOYMA.
EOF
        ;;
    pub)
        name="${1:?Kullanım: $0 pub <ad>}"
        [ -f "${KEYS_DIR}/${name}.pub" ] || die "Yok: ${KEYS_DIR}/${name}.pub"
        tr -d ' \n' < "${KEYS_DIR}/${name}.pub"; echo
        ;;
    admin)
        name="${1:?Kullanım: $0 admin <ad>}"
        [[ "${name}" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "Ad yalnızca harf, rakam, . _ - (en çok 32)"
        [ "${name}" != "admin" ] || die "'admin' adı paylaşılan API anahtarına ayrılmış"
        key="$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-43)"
        hash="$(printf '%s' "${key}" | openssl dgst -sha256 | awk '{print $NF}')"
        cat <<EOF
Yönetici : ${name}
Anahtar  : ${key}
           (bir kez gösterilir, hiçbir yere kaydedilmez; parola kasana kaydet.
            Dashboard'da ve betiklerde X-API-Key olarak kullanılır.)
Sunucuya verilecek olan (gizli değil):
  ${name}:${hash}
EOF
        ;;
    *)
        sed -n '2,28p' "$0"; exit 2 ;;
esac
