#!/usr/bin/env bash
# Android client'ın (sample-client) bu host'a bağlanmak için ihtiyaç
# duyduğu değerleri yazdırır. Sertifika ya da signing key yeniden üretildiğinde
# çalıştır ve çıktıyı client'a aktar.
#
# Not: data/certs/demo-server.pins sunucu ilk açıldığında oluşur; önce
# `docker compose up -d` çalışmış olmalı.
#
# Kullanım:
#   ./scripts/client-config.sh                 # okunabilir özet
#   ./scripts/client-config.sh --properties    # sample-host.properties içeriği
#       > ../sample-client/sample-host.properties
#   ./scripts/client-config.sh --properties --target-private-ca
#       # hedefin sertifikası kurum içi CA'dan ya da kendinden imzalı
#   ./scripts/client-config.sh --properties --no-target-pins
#       # hedefe hiç bağlanma (target.pins boş kalır)
#
# ── Hedefin (target.host) pin'leri ──
# --properties, statik ve gömülü modlar için hedefin canlı sertifika zincirinden
# iki pin hesaplar (sunucu sertifikası + ara sertifika). Pin'ler ancak zincir
# DOĞRULANDIKTAN sonra alınır: zincir bu makinenin güvendiği bir CA'ya
# bağlanmalı ve sertifika hedefin adına kesilmiş olmalı. Doğrulama tutmazsa
# betik DURUR ve hiçbir şey yazmaz. Neden: derleme makinesi trafiği açıp bakan
# bir kurumsal proxy'nin (ya da bir saldırganın) arkasındaysa, doğrulanmadan
# alınan pin o aradakinin sertifikasını uygulamaya gömerdi.
#
#   - Hedefe ulaşılamıyorsa (internet yok): target.pins boş kalır, o modlar kapalı
#     olur, target.requireCaTrust=true yazılır; betik uyarıp devam eder.
#   - Hedefin sertifikası gerçekten kurum içi CA'dan ya da kendinden imzalıysa:
#     --target-private-ca. Yalnızca o zaman pin'ler doğrulanmadan alınır ve
#     target.requireCaTrust=false yazılır (uygulama o hedef için sistemin CA
#     onayını istemez). Pin'leri başka bir yoldan da karşılaştır. Release
#     derlemesi bu değerle derlenmez.
#   - TARGET_REQUIRE_CA_TRUST ortam değişkeni artık tek başına işe yaramaz:
#     false için bayrak şart.
#
# ── İmza katmanları ──
# Uygulamanın güvendiği anahtarlar: sunucunun imzalayıcıları + yedek anahtarlar;
# kurtarma anahtarları ayrı yazılır.
#   Demo profili  : yedek/kurtarma anahtarları OFFLINE_KEYS_DIR (varsayılan
#                   offline-keys/) altındaki backup*.pub ve recovery*.pub;
#                   gereken imza CLIENT_REQUIRED_SIGNATURES, boşsa 1.
#   Üretim profili: yedek/kurtarma anahtarları .env'deki BACKUP_PUBLIC_KEYS ve
#                   RECOVERY_PUBLIC_KEYS (setup.sh --production yazar; özel
#                   yarıları bu makinede yoktur). Sunucu en az iki imzalayıcıyla
#                   imzalamalı, en az biri diskte düz dosya olmamalı (pkcs11 ya da
#                   command) ve gereken imza en az 2 olmalı; değilse betik durur.
#
# ── mTLS: istemci CA'sı ──
# host.clientCaPin: cihaz sertifikalarını (CSR ile kayıt ve yenileme) imzalayan
# sunucu CA'sının SPKI SHA-256 pin'i. Uygulama, kayıtta ve her yenilemede gelen
# zincirin bu CA'nın imzasını taşımasını ister (clientCaPins). Sunucu bu CA'yı
# hiçbir uçta yayımlamaz; betik onu container içinde data/certs/client-ca.jks'ten
# keytool ile okur (KEYSTORE_PASSWORD container'ın kendi ortamından), olmazsa
# sunucunun açılış log'undaki "client CA — SPKI …" satırından alır. İkisi de
# yoksa boş yazar (uygulama ilk zincire güvenir) ve uyarır.
#
# ── Config API kimlikleri (serverScope) ──
# host.tlsScope / host.mtlsScope: uygulama, imzalı config'in (ve vault dosya
# imzalarının, v2) bu Config API için imzalanmış olmasını ister. Betik önce
# sunucunun imzalı config'inde "configApiId" alanı olup olmadığına bakar; yoksa
# (bu alanı henüz yazmayan sunucu sürümü) uygulama hiçbir config'i kabul
# etmezdi: iki değer boş yazılır ve uyarı basılır. Sunucu alanı yazmaya
# başlayınca betiği yeniden çalıştır.
#
# Demo profilinde stderr'e "DEMO PROFİLİ" uyarısı basar; --properties çıktısı
# (stdout) etkilenmez.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# shellcheck source=scripts/lib.sh
. "${SCRIPT_DIR}/lib.sh"
load_env

MODE="summary"
TARGET_PRIVATE_CA=0
NO_TARGET_PINS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --properties) MODE="properties"; shift ;;
        --target-private-ca) TARGET_PRIVATE_CA=1; shift ;;
        --no-target-pins) NO_TARGET_PINS=1; shift ;;
        -h|--help) sed -n '2,68p' "$0"; exit 0 ;;
        *) echo "Bilinmeyen seçenek: $1 (--properties, --target-private-ca, --no-target-pins)" >&2; exit 2 ;;
    esac
done

die() { echo "!! $*" >&2; exit 1; }

IP="${HOST_LAN_IP:?HOST_LAN_IP .env içinde yok — ./scripts/setup.sh}"
HTTPS_PORT="${HOST_HTTPS_PORT:-6651}"
HTTP_PORT="${HOST_HTTP_PORT:-6650}"
MTLS_PORT="${HOST_MTLS_PORT:-6652}"
MOCK_TLS_PORT="${HOST_MOCK_TLS_PORT:-6653}"
MOCK_MTLS_PORT="${HOST_MOCK_MTLS_PORT:-6654}"
RECOVERY_PORT="${HOST_RECOVERY_PORT:-6656}"
TARGET_HOST="${TARGET_HOST:-www.example.com}"
PROFILE="${SAMPLE_PROFILE:-demo}"
# Sunucudaki Config API kimlikleri: uygulama her bloğu kendi kimliğine bağlar
# (serverScope). TLS olanı sunucunun varsayılanı, mTLS olanı provision.sh'ın açtığı.
TLS_SCOPE="${CLIENT_TLS_SCOPE:-default-tls}"
MTLS_SCOPE="${CLIENT_MTLS_SCOPE:-sample-mtls}"

HOST_PINS="$(host_pins || true)"
[ -n "${HOST_PINS}" ] || { echo "data/certs/demo-server.pins yok — önce 'docker compose up -d'." >&2; exit 1; }
PRIMARY="$(printf '%s\n' "${HOST_PINS}" | sed -n 1p)"
BACKUP="$(printf '%s\n' "${HOST_PINS}" | sed -n 2p)"

# İmza anahtarları sunucudan: imzalayıcı bir HSM ya da KMS olabilir (anahtar
# dosyası yok), ya da dosya SIGNING_KEY_PASSWORD ile şifreli olabilir.
KEY_INFO="$(curl -fsS "http://localhost:${HTTP_PORT}/api/v1/signing-key")" \
    || { echo "GET /api/v1/signing-key cevap vermedi — host ayakta mı? (docker compose up -d)" >&2; exit 1; }
SIGNING="$(printf '%s' "${KEY_INFO}" | jq -r .publicKey)"
KEYS_DIR="${OFFLINE_KEYS_DIR:-offline-keys}"
keys_in() { for f in "$@"; do [ -f "${f}" ] && { tr -d ' \n' < "${f}"; echo; }; done; return 0; }
if [ "${PROFILE}" = "production" ]; then
    # Üretim: public yarılar .env'de; bu makinede anahtar dosyası aranmaz.
    BACKUP_KEYS_LIST="$(printf '%s' "${BACKUP_PUBLIC_KEYS:-}" | tr ',' '\n')"
    RECOVERY_KEYS_LIST="$(printf '%s' "${RECOVERY_PUBLIC_KEYS:-}" | tr ',' '\n')"
else
    # Demo: offline-keys/ altındaki *.pub dosyaları (özel yarılar olmasa da olur).
    BACKUP_KEYS_LIST="$(keys_in "${KEYS_DIR}"/backup*.pub)"
    RECOVERY_KEYS_LIST="$(keys_in "${KEYS_DIR}"/recovery*.pub)"
fi
SIGNING_KEYS="$( { printf '%s\n' "${KEY_INFO}" | jq -r '.signers[].publicKey'; printf '%s\n' "${BACKUP_KEYS_LIST}"; } \
    | grep . | awk '!seen[$0]++' | paste -sd, -)"
RECOVERY_KEYS="$(printf '%s\n' "${RECOVERY_KEYS_LIST}" | grep . | awk '!seen[$0]++' | paste -sd, - || true)"
SERVER_SIGNERS="$(printf '%s\n' "${KEY_INFO}" | jq -r '.signers | length' 2>/dev/null || echo 1)"

# Kurtarma kapısının CA pin'leri (sunucu CA'sı + yedeği): uygulama kapıya yalnızca
# bu port için CA'dan pinler, kapının sertifikası yenilense de değişmez.
RECOVERY_PINS="$(curl_with_key "${API_KEY:-}" -fsS "http://localhost:${HTTP_PORT}/api/v1/recovery-door" | jq -r '.caPins | join(",")' 2>/dev/null || true)"

# İstemci CA'sının SPKI pin'i (yukarıdaki "mTLS: istemci CA'sı").
client_ca_pin() {
    local pem pin=""
    pem="$(docker compose exec -T -u "$(container_user)" pinvault-host sh -c \
        'P="${KEYSTORE_PASSWORD:-changeit}"; export P; keytool -exportcert -rfc -alias client-ca -keystore /data/certs/client-ca.jks -storetype JKS -storepass:env P' \
        2>/dev/null || true)"
    if printf '%s' "${pem}" | grep -q -- '-----BEGIN CERTIFICATE-----'; then
        pin="$(printf '%s\n' "${pem}" | openssl x509 -pubkey -noout 2>/dev/null \
            | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A)"
    fi
    if ! [[ "${pin}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        # Sunucu açılışta yazar: "Generated|Loaded client CA — SPKI <pin>, valid until …"
        pin="$(docker compose logs --no-log-prefix pinvault-host 2>/dev/null \
            | sed -n 's/.*client CA .* SPKI \([A-Za-z0-9+/]\{43\}=\).*/\1/p' | tail -n1 || true)"
    fi
    if [[ "${pin}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then printf '%s' "${pin}"; fi
}
CLIENT_CA_PIN="$(client_ca_pin)"
if [ -z "${CLIENT_CA_PIN}" ]; then
    # Üretimde boş pin kabul edilmez: kayıt yanıtını yolda değiştiren biri kendi
    # CA'sıyla imzaladığı sertifikayı telefona kurdurabilirdi.
    [ "${PROFILE}" != "production" ] || die "Üretim profili: istemci CA'sının pin'i okunamadı (container ayakta mı? docker compose ps). host.clientCaPin boş kalamaz; uygulama değerleri yazılmadı."
    echo "!! İstemci CA'sının pin'i okunamadı (container ayakta mı?). host.clientCaPin boş: uygulama kayıtta gelen ilk zincire güvenir." >&2
fi

# Sunucu imzalı config'e Config API kimliğini (configApiId) yazıyor mu? Yazmıyorsa
# serverScope'lu bir uygulama hiçbir config'i kabul etmez: bağlama yapılmaz.
SIGNED_CONFIG="$(curl -fsSk --pinnedpubkey "sha256//${PRIMARY};sha256//${BACKUP}" --max-time 10 \
    "https://localhost:${HTTPS_PORT}/api/v1/certificate-config" 2>/dev/null || true)"
if [ -z "${SIGNED_CONFIG}" ]; then
    [ "${PROFILE}" != "production" ] || die "Üretim profili: Config API'den (:${HTTPS_PORT}) imzalı config okunamadı; host.tlsScope/host.mtlsScope doğrulanamadı. Uygulama değerleri yazılmadı."
    echo "!! Config API'den (:${HTTPS_PORT}) imzalı config okunamadı; host.tlsScope/host.mtlsScope olduğu gibi yazıldı. Uygulama config almazsa sunucunun configApiId yazıp yazmadığına bak." >&2
else
    SIGNED_SCOPE="$(printf '%s' "${SIGNED_CONFIG}" | jq -r '.payload | fromjson | .configApiId // empty' 2>/dev/null || true)"
    if [ "${SIGNED_SCOPE}" != "${TLS_SCOPE}" ]; then
        if [ -n "${SIGNED_SCOPE}" ]; then scope_note="\"${SIGNED_SCOPE}\" (beklenen \"${TLS_SCOPE}\")"; else scope_note="yok"; fi
        # Üretimde bağlamasız uygulama kabul edilmez: aynı imza anahtarının başka bir
        # Config API için imzaladığı config de geçerdi.
        [ "${PROFILE}" != "production" ] || die "Üretim profili: sunucunun imzalı config'inde configApiId ${scope_note}. host.tlsScope/host.mtlsScope boş kalamaz; configApiId yazan bir sunucu sürümüyle derle (ya da CLIENT_TLS_SCOPE'u düzelt). Uygulama değerleri yazılmadı."
        cat >&2 <<EOF
!! Sunucunun imzalı config'inde configApiId ${scope_note}.
!! host.tlsScope ve host.mtlsScope BOŞ yazıldı: uygulama config'in hangi Config API için
!! imzalandığına bakmayacak (aynı imza anahtarının başka bir Config API için imzaladığı
!! config de kabul edilir). Sunucu configApiId ve X-Vault-Signature-V2 yazmaya başlayınca
!! bu betiği yeniden çalıştır.
EOF
        TLS_SCOPE=""
        MTLS_SCOPE=""
    fi
fi

# Sunucunun diskinde düz dosya olmayan imzalayıcı sayısı (pkcs11, command).
# SoftHSM sayılmaz: gerçek HSM değildir, anahtarı yine bu sunucunun diskinde tutar
# (setup.sh ve entrypoint.sh de saymaz). Yönetim ucu imzalayıcı türlerini ve
# açıklamalarını (pkcs11 için kitaplık adı) verir; ulaşılamazsa .env'deki
# CONFIG_SIGNERS ve PKCS11_LIBRARY'ye bakılır.
external_signers() {
    local n
    n="$(curl_with_key "${ADMIN_KEY:-${API_KEY:-}}" -fsS "http://localhost:${HTTP_PORT}/api/v1/signing/status" 2>/dev/null \
        | jq -r '[.signers[] | select(.type == "command" or (.type == "pkcs11" and ((.description // "") | test("softhsm"; "i") | not)))] | length' 2>/dev/null || true)"
    if [ -z "${n}" ]; then
        local softhsm=0
        case "$(printf '%s' "${PKCS11_LIBRARY:-}" | tr 'A-Z' 'a-z')" in *softhsm*) softhsm=1 ;; esac
        n="$(printf '%s' "${CONFIG_SIGNERS:-local}" | tr ',' '\n' | tr -d ' ' | sed 's/:.*//' | tr 'A-Z' 'a-z' \
            | awk -v soft="${softhsm}" '$0 == "command" || ($0 == "pkcs11" && soft == 0) { c++ } END { print c + 0 }')"
    fi
    printf '%s' "${n:-0}"
}

# Gereken imza sayısı.
if [ "${PROFILE}" = "production" ]; then
    REQUIRED_SIGNATURES="${CLIENT_REQUIRED_SIGNATURES:-2}"
    if [ "${SAMPLE_EVALUATION:-}" = "single-signer" ]; then
        REQUIRED_SIGNATURES=1
        cat >&2 <<'EOF'
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! BU DEĞERLER ÜRETİM İÇİN DEĞİLDİR: kurulum tek imzalayıcıyla yapılmış
!! (--evaluation-single-signer-NOT-FOR-PRODUCTION). Uygulama 1 imza isteyecek.
!! Bu değerlerle derlenen uygulamayı gerçek kullanıcıya verme.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
    else
        EXTERNAL_SIGNERS="$(external_signers)"
        [ "${SERVER_SIGNERS}" -ge 2 ] || die "Üretim profili: sunucu ${SERVER_SIGNERS} imzalayıcıyla imzalıyor; en az iki gerekir (CONFIG_SIGNERS=pkcs11,command gibi). Uygulama değerleri yazılmadı."
        [ "${EXTERNAL_SIGNERS}" -ge 1 ] || die "Üretim profili: imzalayıcıların hepsi sunucunun diskinde (local). En az biri HSM (pkcs11) ya da KMS (command) olmalı. Uygulama değerleri yazılmadı."
        case "${REQUIRED_SIGNATURES}" in
            ''|*[!0-9]*) die "CLIENT_REQUIRED_SIGNATURES sayı olmalı: ${REQUIRED_SIGNATURES}" ;;
        esac
        [ "${REQUIRED_SIGNATURES}" -ge 2 ] || die "Üretim profili: gereken imza sayısı ${REQUIRED_SIGNATURES}; en az 2 olmalı (CLIENT_REQUIRED_SIGNATURES). Uygulama değerleri yazılmadı."
        [ "${REQUIRED_SIGNATURES}" -le "${SERVER_SIGNERS}" ] || die "Gereken imza (${REQUIRED_SIGNATURES}) sunucunun imzalayıcı sayısından (${SERVER_SIGNERS}) fazla: hiçbir config kabul edilmezdi."
        [ -n "${RECOVERY_KEYS}" ] || die "Üretim profili: RECOVERY_PUBLIC_KEYS boş. Kurtarma anahtarı olmadan çalınan bir imza anahtarı iptal edilemez (setup.sh --production --recovery-public-key …)."
        # Gereken imzadan en az bir fazla güvenilen anahtar (yedek): bir imzalayıcı
        # kaybolunca telefonlar uygulama güncellemesi olmadan config almaya devam etsin.
        TRUSTED_KEYS="$(printf '%s' "${SIGNING_KEYS}" | tr ',' '\n' | grep -c . || true)"
        [ "${TRUSTED_KEYS}" -gt "${REQUIRED_SIGNATURES}" ] || die "Üretim profili: uygulama ${TRUSTED_KEYS} imza anahtarına güvenecek, ${REQUIRED_SIGNATURES} imza isteyecek; yedek yok. Bir imzalayıcı kaybolursa bütün telefonlar durur. Yedek anahtarın public yarısını ver: setup.sh --production --backup-public-key … Uygulama değerleri yazılmadı."
    fi
elif [ -n "${CLIENT_REQUIRED_SIGNATURES:-}" ]; then
    REQUIRED_SIGNATURES="${CLIENT_REQUIRED_SIGNATURES}"
else
    REQUIRED_SIGNATURES=1
fi

# ── Hedefin pin'leri: önce doğrula, sonra al ────────────────────────────────

# Bu makinedeki openssl'in güvendiği CA listesi var mı?
local_ca_store() {
    local dir
    dir="$(openssl version -d 2>/dev/null | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')"
    [ -s "${SSL_CERT_FILE:-${dir}/cert.pem}" ] && return 0
    [ -n "${SSL_CERT_DIR:-}" ] && ls "${SSL_CERT_DIR}" 2>/dev/null | grep -q . && return 0
    [ -n "${dir}" ] && ls "${dir}/certs" 2>/dev/null | grep -qE '\.(0|pem|crt)$' && return 0
    return 1
}

# Hedefin sunduğu zincir (PEM blokları). Ulaşılamazsa boş.
target_chain() {
    openssl s_client -connect "$1:443" -servername "$1" -showcerts </dev/null 2>&1 || true
}

# Zincirin ilk iki sertifikasının (sunucu + ara) SPKI pin'leri, virgülle.
chain_pins() {
    local pins="" n=0 block="" line pin
    while IFS= read -r line; do
        block+="${line}"$'\n'
        if [ "${line}" = "-----END CERTIFICATE-----" ]; then
            n=$((n + 1))
            pin="$(printf '%s' "${block}" | openssl x509 -pubkey -noout 2>/dev/null \
                | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl base64)"
            pins="${pins:+${pins},}${pin}"
            block=""
            [ "${n}" -ge 2 ] && break
        fi
    done <<<"$(printf '%s\n' "$1" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p')"
    printf '%s' "${pins}"
}

# Sertifika (stdin, PEM) bu ada kesilmiş mi: SAN listesindeki DNS adları ve IP'ler;
# joker (*.ornek.com) yalnızca tek bir alt adı karşılar. (openssl x509 -checkhost
# macOS'un LibreSSL'inde yok; o yüzden elle.)
cert_matches_host() {
    local host names name suffix rest
    host="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
    names="$(openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -n1 \
        | tr ',' '\n' | sed -n -e 's/^ *DNS://p' -e 's/^ *IP Address://p' | tr 'A-Z' 'a-z')"
    for name in ${names}; do
        [ "${name}" = "${host}" ] && return 0
        case "${name}" in
            '*.'*)
                suffix="${name#\*}"
                rest="${host%"${suffix}"}"
                if [ "${rest}" != "${host}" ] && [ -n "${rest}" ]; then
                    case "${rest}" in *.*) ;; *) return 0 ;; esac
                fi
                ;;
        esac
    done
    return 1
}

# Zincir doğrulandı mı: openssl "Verify return code: 0" demeli VE sunucu
# sertifikası hedefin adına kesilmiş olmalı. Sonuç: ok | unreachable | <neden>
verify_target() { # $1 = host, $2 = s_client çıktısı
    local host="$1" out="$2" code leaf
    printf '%s\n' "${out}" | grep -q -- '-----BEGIN CERTIFICATE-----' || { echo unreachable; return; }
    code="$(printf '%s\n' "${out}" | sed -n 's/.*Verify return code: \([0-9][0-9]*\).*/\1/p' | tail -n1)"
    if [ "${code}" != "0" ]; then
        if [ -z "${code}" ]; then echo "openssl doğrulama sonucu vermedi"; return; fi
        if ! local_ca_store; then
            echo "bu makinenin openssl'inde güvenilen CA listesi yok (doğrulama yapılamıyor; SSL_CERT_FILE ile bir CA paketi göster)"
            return
        fi
        echo "zincir güvenilen bir CA'ya bağlanmıyor ($(printf '%s\n' "${out}" | sed -n 's/.*Verify return code: \(.*\)/\1/p' | tail -n1))"
        return
    fi
    leaf="$(printf '%s\n' "${out}" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | sed '/-----END CERTIFICATE-----/q')"
    if ! printf '%s\n' "${leaf}" | cert_matches_host "${host}"; then
        echo "sertifika ${host} adına kesilmemiş"
        return
    fi
    echo ok
}

TARGET_PINS=""
TARGET_CA=true
resolve_target() {
    if [ "${TARGET_REQUIRE_CA_TRUST:-}" = "false" ] && [ "${TARGET_PRIVATE_CA}" = 0 ]; then
        die "TARGET_REQUIRE_CA_TRUST=false artık tek başına kabul edilmiyor. Hedefin sertifikası gerçekten kurum içi CA'dan ya da kendinden imzalıysa bunu açıkça söyle: --target-private-ca"
    fi
    if [ "${NO_TARGET_PINS}" = 1 ]; then
        [ "${TARGET_PRIVATE_CA}" = 0 ] || TARGET_CA=false
        return
    fi
    local chain result
    chain="$(target_chain "${TARGET_HOST}")"
    if [ "${TARGET_PRIVATE_CA}" = 1 ]; then
        TARGET_CA=false
        TARGET_PINS="$(chain_pins "${chain}")"
        cat >&2 <<EOF
!! ${TARGET_HOST}: --target-private-ca verildi. Pin'ler DOĞRULANMADAN alındı ve
!! target.requireCaTrust=false yazıldı. Bu makine ile hedef arasında biri varsa onun
!! sertifikasını pinlemiş olabilirsin: pin'leri hedef sunucunun kendisinden
!! (yöneticisinden) aldığın değerle karşılaştır. Release derlemesi bu değerle derlenmez.
!!   alınan pin'ler: ${TARGET_PINS:-(hedefe ulaşılamadı)}
EOF
        return
    fi
    result="$(verify_target "${TARGET_HOST}" "${chain}")"
    case "${result}" in
        ok)
            TARGET_PINS="$(chain_pins "${chain}")"
            ;;
        unreachable)
            echo "!! ${TARGET_HOST}: hedefe ulaşılamadı (internet yok?). target.pins boş bırakıldı (statik ve gömülü modlar kapalı), target.requireCaTrust=true." >&2
            ;;
        *)
            cat >&2 <<EOF
!! ${TARGET_HOST}: sertifika zinciri DOĞRULANAMADI: ${result}
!! Pin alınmadı ve hiçbir değer yazılmadı. Doğrulanmamış bir zincirden pin almak,
!! bu makine ile hedef arasındaki birinin (trafiği açan kurumsal proxy, saldırgan)
!! sertifikasını uygulamaya gömmek olurdu.
!!   - Kurumsal proxy arkasındaysan: bu komutu proxy'siz bir ağdan çalıştır.
!!   - Hedefin sertifikası gerçekten kurum içi CA'dan ya da kendinden imzalıysa:
!!       ./scripts/client-config.sh --properties --target-private-ca
!!   - Hedefe hiç bağlanmadan devam etmek için (target.pins boş): --no-target-pins
EOF
            exit 1
            ;;
    esac
}

warn_profile() {
    if [ "${PROFILE}" != "production" ]; then
        echo "!! DEMO PROFİLİ: bu değerler deneme ve uçtan uca testler içindir (yedek/kurtarma anahtarı ve iki imza yok). Üretim: ./scripts/setup.sh --production" >&2
    fi
}

if [ "${MODE}" = "properties" ]; then
    resolve_target
    warn_profile
    cat <<EOF
# sample-host değerleri; scripts/client-config.sh --properties tarafından üretildi.
host.ip=${IP}
host.httpsPort=${HTTPS_PORT}
host.mtlsPort=${MTLS_PORT}
host.tlsScope=${TLS_SCOPE}
host.mtlsScope=${MTLS_SCOPE}
# Atestasyon (Approov benzeri): 5 dakikada bir imzalı bütünlük raporu, geçene PinVault-Token. Boş = true.
host.attestation=true
# Uygulamanın yayın imza sertifikasının SHA-256'sı (hex, virgülle birden çok): atestasyon
# raporunda app_integrity buna göre işaretlenir. Sunucudaki ATTESTATION_SIGNER_SHA256 ile aynı
# değer; release derlemesi boşken durur.
host.expectedSignerSha256=${ATTESTATION_SIGNER_SHA256:-}
host.bootstrapPinPrimary=${PRIMARY}
host.bootstrapPinBackup=${BACKUP}
host.signingPublicKey=${SIGNING}
host.signingPublicKeys=${SIGNING_KEYS}
host.requiredSignatures=${REQUIRED_SIGNATURES}
host.recoveryPublicKeys=${RECOVERY_KEYS}
host.recoveryPort=${RECOVERY_PORT}
host.recoveryPins=${RECOVERY_PINS}
host.clientCaPin=${CLIENT_CA_PIN}
target.host=${TARGET_HOST}
target.pins=${TARGET_PINS}
target.requireCaTrust=${TARGET_CA}
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
== sample-client ayarları ==

sample-host.properties (üretmek için: ./scripts/client-config.sh --properties > ../sample-client/sample-host.properties):

    host.ip=${IP}
    host.httpsPort=${HTTPS_PORT}        # CONFIG_BASE_URL  = https://${IP}:${HTTPS_PORT}/  (config, kayıt, vault ve cihaz raporları)
    host.mtlsPort=${MTLS_PORT}          # MTLS_BASE_URL    = https://${IP}:${MTLS_PORT}/
    host.tlsScope=${TLS_SCOPE}, host.mtlsScope=${MTLS_SCOPE}   # sunucudaki Config API kimlikleri (serverScope)
    host.bootstrapPinPrimary=${PRIMARY}
    host.bootstrapPinBackup=${BACKUP}
    host.signingPublicKey=${SIGNING}
    mock.tlsPort=${MOCK_TLS_PORT}, mock.mtlsPort=${MOCK_MTLS_PORT}
    host.recoveryPort=${RECOVERY_PORT}      # kurtarma kapısı = https://${IP}:${RECOVERY_PORT}/  (süresi dolmuş sertifikayı yeniler)
    host.recoveryPins=${RECOVERY_PINS}
    host.clientCaPin=${CLIENT_CA_PIN:-(okunamadı)}   # cihaz sertifikalarını imzalayan CA (clientCaPins)
    host.signingPublicKeys=${SIGNING_KEYS}   # sunucunun imzalayıcıları + yedek anahtar(lar)
    host.recoveryPublicKeys=${RECOVERY_KEYS:-(yok)}
    host.requiredSignatures=${REQUIRED_SIGNATURES}   # profil: ${PROFILE}, sunucudaki imzalayıcı: ${SERVER_SIGNERS}

Düz HTTP izni gerekmez. Telefon yönetim portuna bağlanmaz: cihaz raporları (telemetri) da
Config API portundan, config sunucusunun pin'leriyle gider.
EOF
warn_profile
