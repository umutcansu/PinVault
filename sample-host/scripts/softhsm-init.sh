#!/usr/bin/env bash
# HSM imzalayıcısını DENEMEK için SoftHSM token'ı hazırlar ve sunucuyu config
# imzalarını PKCS#11 üzerinden atacak şekilde başlatır.
#
# SoftHSM BİR HSM DEĞİLDİR: gerçek bir HSM'in PKCS#11 arayüzünü taklit eden bir
# yazılımdır. Anahtar yine sunucunun diskinde (data/softhsm), PIN'i de aynı
# makinedeki .env'dedir; sunucuyu ele geçiren ikisini birden alır. Sağladığı tek
# şey, sunucunun PKCS#11 yolunun çalıştığını gerçek donanım olmadan göstermektir
# (uçtan uca testler S04). Gerçek bir kurulumda anahtar gerçek bir HSM'de ya da
# bulut KMS'te durur: aynı ayarlar HSM üreticisinin PKCS#11 kitaplığıyla
# (PKCS11_LIBRARY) ya da CONFIG_SIGNERS=command ile kullanılır. Üretim profili
# SoftHSM'i "sunucunun diski dışındaki imzalayıcı" SAYMAZ; bu betik orada çalışmaz.
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

if [ "$(sed -n 's/^SAMPLE_PROFILE=//p' .env 2>/dev/null | tail -1)" = "production" ]; then
    echo "Üretim profili: SoftHSM bir deneme aracıdır, gerçek HSM değildir; bu betik üretimde çalışmaz." >&2
    echo "Gerçek HSM için .env'e PKCS11_LIBRARY ve PKCS11_PIN yaz (README → \"Üretim profili\")." >&2
    exit 2
fi

pin_from_env() { sed -n 's/^PKCS11_PIN=//p' .env 2>/dev/null | tail -1; }
# Container'da data/'nın sahibi (entrypoint.sh: pinvault ya da PINVAULT_UID/GID).
env_value() { sed -n "s/^$1=//p" .env 2>/dev/null | tail -1; }
RUN_UID="$(env_value PINVAULT_UID)"; RUN_UID="${RUN_UID:-10001}"
RUN_GID="$(env_value PINVAULT_GID)"; RUN_GID="${RUN_GID:-${RUN_UID}}"

case "${1:-init}" in
    init)
        [ -f .env ] || { echo ".env yok — önce ./scripts/setup.sh" >&2; exit 1; }
        pin="$(pin_from_env)"
        if [ -z "${pin}" ]; then
            # 128 bit rastgele PIN (eskiden 32 bitti).
            pin="$(openssl rand -hex 16)"
            if grep -q '^PKCS11_PIN=' .env; then
                sed -i.bak "s|^PKCS11_PIN=.*|PKCS11_PIN=${pin}|" .env && rm -f .env.bak
            else
                printf '\nPKCS11_PIN=%s\n' "${pin}" >> .env
            fi
            chmod 600 .env
            echo "PKCS11_PIN üretildi ve .env'e yazıldı."
        fi
        so_pin="$(openssl rand -hex 16)"
        # PIN'ler host'ta komut satırına yazılmaz: container'a ortam değişkeni olarak
        # geçer (-e AD: değer bu sürecin ortamından alınır). softhsm2-util PIN'i yalnızca
        # komut satırından alır; o an container içindeki süreç listesinde görünür
        # (SoftHSM'in sınırı; yukarıdaki nota bak).
        SOFTHSM_PIN="${pin}" SOFTHSM_SO_PIN="${so_pin}" \
            docker compose exec -T -u "${RUN_UID}:${RUN_GID}" -e SOFTHSM_PIN -e SOFTHSM_SO_PIN pinvault-host sh -s "${LABEL}" <<'SH'
set -e
pin="${SOFTHSM_PIN}"; so_pin="${SOFTHSM_SO_PIN}"; label="$1"
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
        # PIN komut satırına yazılmaz: compose onu .env'den (PKCS11_PIN) okur.
        "${SCRIPT_DIR}/env-override.sh" set CONFIG_SIGNERS="${SIGNERS:-pkcs11}" \
            PKCS11_LIBRARY="${LIB}" PKCS11_GENERATE_KEY=true \
            ${EXTRA_ENV:-}
        curl -fsS "http://localhost:$(sed -n 's/^HOST_HTTP_PORT=//p' .env | tail -1)/api/v1/signing-key" \
            | jq -r '"imzalayan anahtar(lar): " + ([.signers[].keyId] | join(", "))'
        ;;
    show)
        pin="$(pin_from_env)"
        [ -n "${pin}" ] || { echo "PKCS11_PIN yok — önce: $0 init" >&2; exit 1; }
        # PIN ortamdan okunur (pkcs11-tool --pin env:AD), komut satırında görünmez.
        SOFTHSM_PIN="${pin}" docker compose exec -T -u "${RUN_UID}:${RUN_GID}" -e SOFTHSM_PIN pinvault-host \
            pkcs11-tool --module "${LIB}" --token-label "${LABEL}" --login --pin env:SOFTHSM_PIN --list-objects
        ;;
    disable)
        "${SCRIPT_DIR}/env-override.sh" reset
        ;;
    *)
        sed -n '2,27p' "$0"; exit 2 ;;
esac
