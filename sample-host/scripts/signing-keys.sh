#!/usr/bin/env bash
# İmzalama anahtarlarının çevrimdışı araçları: yedek ve kurtarma anahtarı
# üretme, imzalama anahtarı setini (anahtar döndürme/iptal) kurtarma
# anahtarıyla imzalayıp sunucuya yükleme, bir anahtarı sunucunun yerel
# imzalayıcısına kurma.
#
# ÜRETİMDE: bu betiği internete bağlı olmayan bir makinede (ya da donanım
# token'ıyla) çalıştır; offline-keys/ dizini sunucuya ASLA kopyalanmaz. Kurtarma
# anahtarının özel yarısı yalnızca anahtar seti imzalarken kullanılır.
#
#   ./scripts/signing-keys.sh gen recovery-1          # offline-keys/recovery-1.{pem,pub}
#   ./scripts/signing-keys.sh gen backup-1            # APK'ya gömülecek yedek imza anahtarı
#   ./scripts/signing-keys.sh pub recovery-1          # Base64 X.509 public key
#   ./scripts/signing-keys.sh server-keys             # sunucunun şu an imzaladığı anahtarlar
#   ./scripts/signing-keys.sh keyset -v 2 -k server,backup-1 -s recovery-1 -o keyset-v2.json
#   ./scripts/signing-keys.sh upload keyset-v2.json   # PUT /api/v1/signing-keyset
#   ./scripts/signing-keys.sh install backup-1        # data/signing-key.pem olarak kur (yeniden başlatma gerekir)
#   ./scripts/signing-keys.sh install backup-1 next   # data/signing-key-next.pem (CONFIG_SIGNERS=local,local:next)
#
# -k listesinde: offline-keys/ altındaki bir ad, bir .pub dosyası, doğrudan
# Base64 anahtar ya da "server" (sunucunun etkin imzalayıcıları).

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
HTTP="http://localhost:${HOST_HTTP_PORT:-6650}"
KEYS_DIR="${OFFLINE_KEYS_DIR:-${ROOT_DIR}/offline-keys}"

die() { echo "$*" >&2; exit 1; }

key_file() { # ad ya da yol → PKCS#8 PEM dosyası
    local ref="$1"
    if [ -f "${ref}" ]; then echo "${ref}"; return; fi
    [ -f "${KEYS_DIR}/${ref}.pem" ] || die "Anahtar yok: ${KEYS_DIR}/${ref}.pem (önce: $0 gen ${ref})"
    echo "${KEYS_DIR}/${ref}.pem"
}

pub_of() { # ad | .pub | .pem | Base64 → Base64 X.509 SubjectPublicKeyInfo
    local ref="$1"
    if [ -f "${KEYS_DIR}/${ref}.pub" ]; then tr -d '\n' < "${KEYS_DIR}/${ref}.pub"; return; fi
    case "${ref}" in
        *.pub) tr -d '\n' < "${ref}"; return ;;
        *.pem) openssl ec -in "${ref}" -pubout -outform DER 2>/dev/null | openssl base64 -A; return ;;
    esac
    [ -f "${KEYS_DIR}/${ref}.pem" ] && { openssl ec -in "${KEYS_DIR}/${ref}.pem" -pubout -outform DER 2>/dev/null | openssl base64 -A; return; }
    # Doğrudan Base64 anahtar: gerçekten bir EC anahtarı mı?
    printf '%s' "${ref}" | openssl base64 -d -A 2>/dev/null | openssl pkey -pubin -inform DER -noout 2>/dev/null \
        || die "Tanınmayan anahtar: ${ref}"
    printf '%s' "${ref}"
}

key_id() { # Base64 SPKI → Base64 SHA-256 (cihazın ve sunucunun gösterdiği anahtar kimliği)
    printf '%s' "$1" | openssl base64 -d -A | openssl dgst -sha256 -binary | openssl base64 -A
}

server_keys() {
    curl -fsS "${HTTP}/api/v1/signing-key" | jq -r '.signers[].publicKey'
}

admin_key() {
    [ -n "${ADMIN_KEY:-}" ] && { echo "${ADMIN_KEY}"; return; }
    [ -n "${API_KEY:-}" ] && { echo "${API_KEY}"; return; }
    die "Yönetici anahtarı yok: ADMIN_KEY=... ile ver ya da .env'de API_KEY olsun."
}

cmd="${1:-}"; shift || true
case "${cmd}" in
    gen)
        name="${1:?Kullanım: $0 gen <ad>}"
        mkdir -p "${KEYS_DIR}"; chmod 700 "${KEYS_DIR}"
        [ -e "${KEYS_DIR}/${name}.pem" ] && die "Zaten var: ${KEYS_DIR}/${name}.pem (üzerine yazılmaz)"
        umask 077
        tmp="$(mktemp)"
        openssl ecparam -name prime256v1 -genkey -noout -out "${tmp}" 2>/dev/null
        openssl pkcs8 -topk8 -nocrypt -in "${tmp}" -out "${KEYS_DIR}/${name}.pem"
        rm -f "${tmp}"
        { pub_of "${KEYS_DIR}/${name}.pem"; echo; } > "${KEYS_DIR}/${name}.pub"
        echo "Üretildi: ${KEYS_DIR}/${name}.pem (özel, 0600) ve ${name}.pub"
        echo "public key : $(cat "${KEYS_DIR}/${name}.pub")"
        echo "key id     : $(key_id "$(cat "${KEYS_DIR}/${name}.pub")")"
        ;;
    pub)
        pub_of "${1:?Kullanım: $0 pub <ad|dosya>}"; echo
        ;;
    server-keys)
        server_keys
        ;;
    keyset)
        version="" keys="" signers="" required="" out=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -v) version="$2"; shift 2 ;;
                -k) keys="$2"; shift 2 ;;
                -s) signers="$2"; shift 2 ;;
                -r) required="$2"; shift 2 ;;
                -o) out="$2"; shift 2 ;;
                *) die "Bilinmeyen seçenek: $1" ;;
            esac
        done
        [ -n "${version}" ] && [ -n "${keys}" ] && [ -n "${signers}" ] \
            || die "Kullanım: $0 keyset -v <sürüm> -k <anahtar,...> -s <kurtarma-anahtarı,...> [-r <eşik>] [-o dosya]"
        list=()
        IFS=',' read -r -a refs <<<"${keys}"
        for ref in "${refs[@]}"; do
            if [ "${ref}" = "server" ]; then
                while IFS= read -r k; do [ -n "${k}" ] && list+=("${k}"); done < <(server_keys)
            else
                list+=("$(pub_of "${ref}")")
            fi
        done
        # Tekrarsız, sıralı: aynı set her seferinde aynı baytlarla imzalansın.
        # (mapfile yok: macOS'un bash 3.2'siyle de çalışsın.)
        sorted="$(printf '%s\n' "${list[@]}" | sort -u)"
        count="$(printf '%s\n' "${sorted}" | grep -c .)"
        keys_json="$(printf '%s\n' "${sorted}" | sed 's/.*/"&"/' | paste -sd, -)"; keys_json="[${keys_json}]"
        payload="{\"type\":\"pinvault-signing-keys\",\"version\":${version},\"keys\":${keys_json}${required:+,\"requiredSignatures\":${required}}}"
        sigs=""
        IFS=',' read -r -a signer_refs <<<"${signers}"
        for s in "${signer_refs[@]}"; do
            file="$(key_file "${s}")"
            sig="$(printf '%s' "${payload}" | openssl dgst -sha256 -sign "${file}" | openssl base64 -A)"
            kid="$(key_id "$(pub_of "${file}")")"
            sigs="${sigs}{\"keyId\":\"${kid}\",\"signature\":\"${sig}\"},"
        done
        wire="{\"payload\":\"${payload//\"/\\\"}\",\"signatures\":[${sigs%,}]}"
        if [ -n "${out}" ]; then
            printf '%s\n' "${wire}" > "${out}"
            echo "Anahtar seti v${version}: ${count} anahtar, ${#signer_refs[@]} kurtarma imzası → ${out}" >&2
        else
            printf '%s\n' "${wire}"
        fi
        ;;
    upload)
        file="${1:?Kullanım: $0 upload <keyset.json>}"
        curl -sS -X PUT "${HTTP}/api/v1/signing-keyset" \
            -H "X-API-Key: $(admin_key)" -H 'Content-Type: application/json' \
            --data-binary @"${file}" -w '\nHTTP %{http_code}\n'
        ;;
    install)
        name="${1:?Kullanım: $0 install <ad> [imzalayıcı-adı]}"
        signer="${2:-}"
        file="$(key_file "${name}")"
        target="data/signing-key${signer:+-${signer}}.pem"
        umask 077
        {
            openssl pkcs8 -topk8 -nocrypt -in "${file}" -outform DER | openssl base64 -A; echo
            pub_of "${file}"
        } > "${target}.tmp"
        mv "${target}.tmp" "${target}"
        echo "Kuruldu: ${target} (SIGNING_KEY_PASSWORD açıksa sunucu ilk açılışta şifreler)."
        if [ -n "${signer}" ]; then
            echo "Etkinleştir: ./scripts/env-override.sh set CONFIG_SIGNERS=local,local:${signer}"
        else
            echo "Etkinleştir: docker compose restart pinvault-host"
        fi
        ;;
    *)
        sed -n '2,24p' "$0"; exit 2 ;;
esac
