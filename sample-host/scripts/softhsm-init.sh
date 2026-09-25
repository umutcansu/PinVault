#!/usr/bin/env bash
# İsteğe bağlı HSM imzalayıcısı için SoftHSM token'ı hazırlar ve sunucuyu
# config imzalarını HSM'deki, dışarı ÇIKARILAMAYAN bir anahtarla atacak
# şekilde başlatır. SoftHSM gerçek bir HSM'in PKCS#11 arayüzünü taklit eder;
# üretimde aynı ayarlar HSM üreticisinin PKCS#11 modülüyle kullanılır
# (PKCS11_LIBRARY yolu değişir).
#
#   ./scripts/softhsm-init.sh            # token'ı hazırla (bir kez), PIN'i .env'e yaz
#   ./scripts/softhsm-init.sh enable     # sunucuyu pkcs11 imzalayıcısıyla yeniden başlat
#   ./scripts/softhsm-init.sh show       # token'daki nesneler ve öznitelikleri (pkcs11-tool)
#   ./scripts/softhsm-init.sh disable    # yerel anahtar dosyasına dön (env-override reset)
#
# Token /data/softhsm altında durur (data/ bağlaması): container yeniden
# oluşturulsa da anahtar kaybolmaz.
#
# DİKKAT: HSM anahtarı yeni bir imza anahtarıdır. Mevcut uygulamalar onu
# ancak şu yollardan biriyle kabul eder: APK'ya ikinci anahtar olarak gömülü
# olması (signaturePublicKeys), ya da bir imzalama anahtarı setiyle
# (./scripts/signing-keys.sh keyset …) duyurulması.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

LIB=/usr/lib/softhsm/libsofthsm2.so
LABEL=pinvault

exec_in() { docker compose exec -T -u pinvault pinvault-host "$@"; }

pin_from_env() { sed -n 's/^PKCS11_PIN=//p' .env 2>/dev/null | tail -1; }

case "${1:-init}" in
    init)
        [ -f .env ] || { echo ".env yok — önce ./scripts/setup.sh" >&2; exit 1; }
        pin="$(pin_from_env)"
        if [ -z "${pin}" ]; then
            pin="$(openssl rand -hex 4)"
            if grep -q '^PKCS11_PIN=' .env; then
                sed -i.bak "s|^PKCS11_PIN=.*|PKCS11_PIN=${pin}|" .env && rm -f .env.bak
            else
                printf '\nPKCS11_PIN=%s\n' "${pin}" >> .env
            fi
            chmod 600 .env
            echo "PKCS11_PIN üretildi ve .env'e yazıldı."
        fi
        so_pin="$(openssl rand -hex 8)"
        exec_in sh -s "${pin}" "${so_pin}" "${LABEL}" <<'SH'
set -e
pin="$1"; so_pin="$2"; label="$3"
mkdir -p /data/softhsm/tokens
[ -f "${SOFTHSM2_CONF}" ] || printf 'directories.tokendir = /data/softhsm/tokens/\nobjectstore.backend = file\nlog.level = INFO\n' > "${SOFTHSM2_CONF}"
chmod 700 /data/softhsm /data/softhsm/tokens
if softhsm2-util --show-slots | grep -q "Label: *${label}\$"; then
    echo "SoftHSM token '${label}' zaten hazır."
else
    softhsm2-util --init-token --free --label "${label}" --pin "${pin}" --so-pin "${so_pin}"
    echo "SoftHSM token '${label}' oluşturuldu."
fi
SH
        echo "Sonraki adım: ./scripts/softhsm-init.sh enable"
        ;;
    enable)
        pin="$(pin_from_env)"
        [ -n "${pin}" ] || { echo "PKCS11_PIN yok — önce: $0 init" >&2; exit 1; }
        # İlk açılışta sunucu anahtarı token İÇİNDE üretir (dışarı çıkarılamaz).
        "${SCRIPT_DIR}/env-override.sh" set CONFIG_SIGNERS="${SIGNERS:-pkcs11}" \
            PKCS11_LIBRARY="${LIB}" PKCS11_PIN="${pin}" PKCS11_GENERATE_KEY=true \
            ${EXTRA_ENV:-}
        curl -fsS "http://localhost:$(sed -n 's/^HOST_HTTP_PORT=//p' .env | tail -1)/api/v1/signing-key" \
            | jq -r '"imzalayan anahtar(lar): " + ([.signers[].keyId] | join(", "))'
        ;;
    show)
        pin="$(pin_from_env)"
        exec_in pkcs11-tool --module "${LIB}" --token-label "${LABEL}" --login --pin "${pin}" --list-objects
        ;;
    disable)
        "${SCRIPT_DIR}/env-override.sh" reset
        ;;
    *)
        sed -n '2,20p' "$0"; exit 2 ;;
esac
