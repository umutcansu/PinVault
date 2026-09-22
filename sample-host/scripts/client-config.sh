#!/usr/bin/env bash
# Android client'ın (SamplePinVaultClient) bu host'a bağlanmak için ihtiyaç
# duyduğu değerleri yazdırır. Sertifika ya da signing key yeniden üretildiğinde
# çalıştır ve çıktıyı client'a aktar.
#
# Not: data/certs/demo-server.pins sunucu ilk açıldığında oluşur; önce
# `docker compose up -d` çalışmış olmalı.
#
# Kullanım:
#   ./scripts/client-config.sh                 # okunabilir özet
#   ./scripts/client-config.sh --properties    # sample-host.properties içeriği
#       > ../SamplePinVaultClient/sample-host.properties
#
# --properties çıktısı hedef sitenin (target.host) canlı sertifika zincirinden
# statik mod için iki pin de hesaplar (openssl s_client). İnternet gerekir;
# hesaplanamazsa target.pins boş kalır ve o modlar kapalı olur.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi

IP="${HOST_LAN_IP:?HOST_LAN_IP .env içinde yok — ./scripts/setup.sh}"
HTTPS_PORT="${HOST_HTTPS_PORT:-6651}"
HTTP_PORT="${HOST_HTTP_PORT:-6650}"
MTLS_PORT="${HOST_MTLS_PORT:-6652}"
MOCK_TLS_PORT="${HOST_MOCK_TLS_PORT:-6653}"
MOCK_MTLS_PORT="${HOST_MOCK_MTLS_PORT:-6654}"
TARGET_HOST="${TARGET_HOST:-www.example.com}"

[ -f data/certs/demo-server.pins ] || { echo "data/certs/demo-server.pins yok — önce 'docker compose up -d'." >&2; exit 1; }
[ -f data/signing-key.pem ] || { echo "data/signing-key.pem yok — önce ./scripts/setup.sh." >&2; exit 1; }

PRIMARY="$(sed -n 1p data/certs/demo-server.pins)"
BACKUP="$(sed -n 2p data/certs/demo-server.pins)"
SIGNING="$(sed -n 2p data/signing-key.pem)"

# Hedefin canlı zincirinden yaprak + ara sertifika SPKI pin'leri (virgülle).
target_pins() {
    local host="$1" chain pins=""
    chain="$(openssl s_client -connect "${host}:443" -servername "${host}" -showcerts </dev/null 2>/dev/null || true)"
    [ -n "${chain}" ] || return 0
    local n=0 block=""
    while IFS= read -r line; do
        block+="${line}"$'\n'
        if [ "${line}" = "-----END CERTIFICATE-----" ]; then
            n=$((n + 1))
            local pin
            pin="$(printf '%s' "${block}" | openssl x509 -pubkey -noout 2>/dev/null \
                | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl base64)"
            pins="${pins:+${pins},}${pin}"
            block=""
            [ "${n}" -ge 2 ] && break
        fi
    done <<<"$(printf '%s\n' "${chain}" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')"
    printf '%s' "${pins}"
}

if [ "${1:-}" = "--properties" ]; then
    TARGET_PINS="$(target_pins "${TARGET_HOST}")"
    cat <<EOF
# SamplePinVaultHost değerleri; scripts/client-config.sh --properties tarafından üretildi.
host.ip=${IP}
host.httpPort=${HTTP_PORT}
host.httpsPort=${HTTPS_PORT}
host.mtlsPort=${MTLS_PORT}
host.bootstrapPinPrimary=${PRIMARY}
host.bootstrapPinBackup=${BACKUP}
host.signingPublicKey=${SIGNING}
target.host=${TARGET_HOST}
target.pins=${TARGET_PINS}
mock.tlsHost=mock-tls.sample
mock.tlsPort=${MOCK_TLS_PORT}
mock.mtlsHost=mock-mtls.sample
mock.mtlsPort=${MOCK_MTLS_PORT}
custom.baseUrl=
custom.bootstrapPins=
custom.signingPublicKey=
EOF
    exit 0
fi

cat <<EOF
== SamplePinVaultClient ayarları ==

sample-host.properties (üretmek için: ./scripts/client-config.sh --properties > ../SamplePinVaultClient/sample-host.properties):

    host.ip=${IP}
    host.httpsPort=${HTTPS_PORT}        # CONFIG_BASE_URL  = https://${IP}:${HTTPS_PORT}/
    host.httpPort=${HTTP_PORT}          # MANAGEMENT_URL   = http://${IP}:${HTTP_PORT}/  (telemetri)
    host.mtlsPort=${MTLS_PORT}          # MTLS_BASE_URL    = https://${IP}:${MTLS_PORT}/
    host.bootstrapPinPrimary=${PRIMARY}
    host.bootstrapPinBackup=${BACKUP}
    host.signingPublicKey=${SIGNING}
    mock.tlsPort=${MOCK_TLS_PORT}, mock.mtlsPort=${MOCK_MTLS_PORT}

app/src/main/res/xml/network_security_config.xml (telemetri için düz HTTP izni):

    <domain includeSubdomains="false">${IP}</domain>
EOF
