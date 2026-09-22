#!/usr/bin/env bash
# SamplePinVaultHost ilk kurulum. Tekrar çalıştırmak güvenlidir; yalnızca eksik
# olanı tamamlar:
#   - .env yoksa .env.example'dan oluşturur (izinler 600)
#   - API_KEY boşsa rastgele üretir
#   - HOST_LAN_IP boşsa makinenin LAN IP'sini bulur
#   - data/signing-key.pem yoksa üretir
#
# Kullanım: ./scripts/setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

cd "${ROOT_DIR}"

if [ ! -f "${ENV_FILE}" ]; then
    cp .env.example "${ENV_FILE}"
    echo ">> .env oluşturuldu (.env.example'dan)"
fi
chmod 600 "${ENV_FILE}"

get_env() {
    grep -E "^$1=" "${ENV_FILE}" | tail -n1 | cut -d= -f2- || true
}

# KEY=VALUE satırını yerinde günceller; yoksa sona ekler. Dosya izinleri korunur.
set_env() {
    local key="$1" value="$2" tmp
    tmp="$(mktemp)"
    if grep -qE "^${key}=" "${ENV_FILE}"; then
        awk -v k="${key}" -v v="${value}" \
            'index($0, k"=") == 1 { print k"="v; next } { print }' "${ENV_FILE}" > "${tmp}"
    else
        cat "${ENV_FILE}" > "${tmp}"
        printf '%s=%s\n' "${key}" "${value}" >> "${tmp}"
    fi
    cat "${tmp}" > "${ENV_FILE}"
    rm -f "${tmp}"
}

random_key() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    else
        head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

detect_lan_ip() {
    local ip=""
    if command -v ipconfig >/dev/null 2>&1; then          # macOS
        for ifc in en0 en1 en2; do
            ip="$(ipconfig getifaddr "${ifc}" 2>/dev/null || true)"
            [ -n "${ip}" ] && break
        done
    fi
    if [ -z "${ip}" ]; then                                # Linux
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi
    printf '%s' "${ip}"
}

if [ -z "$(get_env API_KEY)" ]; then
    set_env API_KEY "$(random_key)"
    echo ">> API_KEY üretildi (.env içinde)"
fi

if [ -z "$(get_env HOST_LAN_IP)" ]; then
    lan_ip="$(detect_lan_ip)"
    if [ -n "${lan_ip}" ]; then
        set_env HOST_LAN_IP "${lan_ip}"
        echo ">> HOST_LAN_IP=${lan_ip}"
    else
        echo "!! LAN IP bulunamadı. .env içinde HOST_LAN_IP'yi elle doldur." >&2
    fi
fi

if [ ! -f data/signing-key.pem ]; then
    "${SCRIPT_DIR}/generate-signing-key.sh"
fi

server_src="$(get_env PINVAULT_SERVER_SRC)"
echo ""
echo "== Hazır =="
echo "  .env          : API_KEY dolu, HOST_LAN_IP=$(get_env HOST_LAN_IP)"
echo "  Sunucu kaynağı: ${server_src:-upstream git @ $(get_env PINVAULT_REF)}"
echo "  Signing key   : data/signing-key.pem"
echo ""
echo "Sıradaki adımlar:"
echo "  docker compose up -d --build"
echo "  ./scripts/smoke-test.sh"
echo "  ./scripts/client-config.sh"
