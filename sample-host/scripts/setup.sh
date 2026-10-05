#!/usr/bin/env bash
# sample-host ilk kurulum. Tekrar çalıştırmak güvenlidir; yalnızca eksik
# olanı tamamlar:
#   - .env yoksa .env.example'dan (--production ile .env.production.example'dan)
#     oluşturur (izinler 600)
#   - API_KEY, KEYSTORE_PASSWORD, VAULT_AT_REST_PASSWORD, SIGNING_KEY_PASSWORD boşsa
#     rastgele üretir (sunucu bu üç parola olmadan açılmaz)
#   - demo profilinde FETCH_ALLOW_PRIVATE_TARGETS=true yazar (sunucu "URL'den
#     sertifika al" ile bu makineye ve yerel ağdaki host'lara bağlanabilsin);
#     üretim profilinde boş bırakır (yalnızca internetteki adresler)
#   - HOST_LAN_IP boşsa makinenin LAN IP'sini bulur
#   - data/signing-key.pem yoksa üretir (sunucuda yerel imzalayıcı varsa)
#
# ── Üretim profili (--production) ── README → "Üretim profili"
# Çevrimdışı özel anahtarlar (kurtarma, yedek) bu makinede ÜRETİLMEZ ve bu
# makineye hiç gelmez. Onları BAŞKA bir makinede scripts/offline-keygen.sh
# üretir; buraya yalnızca PUBLIC yarıları verilir.
#
#   --production                 üretim profili
#   --fresh                      demo kurulumunun üstüne kurma: eski .env, data/
#                                ve offline-keys/ zaman damgalı bir yedek dizine
#                                taşınır, kurulum boş veriyle başlar
#   --recovery-public-key <B64>  kurtarma anahtar(lar)ının public yarısı (virgülle
#                                birden çok; ya da RECOVERY_PUBLIC_KEYS ortam değişkeni)
#   --backup-public-key <B64>    yedek imza anahtar(lar)ının public yarısı (ya da
#                                BACKUP_PUBLIC_KEYS)
#   --signers <liste>            CONFIG_SIGNERS: en az iki imzalayıcı, en az biri
#                                sunucunun diskinde olmayan (pkcs11 ya da command).
#                                Örn. pkcs11,command ya da local,command
#   --admins a:sha256,b:sha256   kişisel yönetici anahtarlarının SHA-256'ları (her
#                                yönetici kendi anahtarını kendi makinesinde üretir:
#                                offline-keygen.sh admin <ad>). Yalnızca ad verilirse
#                                anahtarlar burada üretilir ve BİR KEZ ekrana yazılır
#   --attestation-signer <SHA>   uygulamanın yayın imza sertifikasının SHA-256'sı
#   --server-ref <commit>        sunucu kaynağı: 40 haneli commit SHA'sı (dal adı kabul
#                                edilmez), ya da
#   --server-src <dizin>         yerel demo-server dizini
#   --evaluation-single-signer-NOT-FOR-PRODUCTION
#                                yalnızca değerlendirme: tek imzalayıcıya izin verir.
#                                Bu kurulum ÜRETİM DEĞİLDİR ve betik bunu yazar.
#
# Betik şu durumlarda durur ve nedenini söyler: demo kurulumunun üstüne
# --fresh'siz çalıştırılırsa; bu dizinde çevrimdışı özel anahtar dosyası
# varsa; imzalayıcılar, sunucu kaynağı, kurtarma anahtarı ya da uygulama imzası
# kurallara uymuyorsa.
#
# Kullanım:
#   ./scripts/setup.sh                                   # demo profili
#   ./scripts/setup.sh --production --fresh \
#       --server-ref <commit> --signers pkcs11,command \
#       --recovery-public-key <B64> --backup-public-key <B64> \
#       --admins ayse:<sha256>,mehmet:<sha256> --attestation-signer <SHA-256>

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
EVALUATION_FLAG="--evaluation-single-signer-NOT-FOR-PRODUCTION"

PRODUCTION=0
FRESH=0
EVALUATION=0
ADMINS=""
ATTESTATION_SIGNER=""
ARG_RECOVERY_KEYS="${RECOVERY_PUBLIC_KEYS:-}"
ARG_BACKUP_KEYS="${BACKUP_PUBLIC_KEYS:-}"
ARG_SIGNERS="${CONFIG_SIGNERS:-}"
ARG_SERVER_REF=""
ARG_SERVER_SRC=""
while [ $# -gt 0 ]; do
    case "$1" in
        --production) PRODUCTION=1; shift ;;
        --fresh) FRESH=1; shift ;;
        "${EVALUATION_FLAG}") EVALUATION=1; shift ;;
        --admins) ADMINS="${2:?--admins ad1:sha256,ad2:sha256}"; shift 2 ;;
        --admins=*) ADMINS="${1#--admins=}"; shift ;;
        --attestation-signer) ATTESTATION_SIGNER="${2:?--attestation-signer <sha256>}"; shift 2 ;;
        --attestation-signer=*) ATTESTATION_SIGNER="${1#--attestation-signer=}"; shift ;;
        --recovery-public-key) ARG_RECOVERY_KEYS="${ARG_RECOVERY_KEYS:+${ARG_RECOVERY_KEYS},}${2:?--recovery-public-key <Base64>}"; shift 2 ;;
        --recovery-public-key=*) ARG_RECOVERY_KEYS="${ARG_RECOVERY_KEYS:+${ARG_RECOVERY_KEYS},}${1#--recovery-public-key=}"; shift ;;
        --backup-public-key) ARG_BACKUP_KEYS="${ARG_BACKUP_KEYS:+${ARG_BACKUP_KEYS},}${2:?--backup-public-key <Base64>}"; shift 2 ;;
        --backup-public-key=*) ARG_BACKUP_KEYS="${ARG_BACKUP_KEYS:+${ARG_BACKUP_KEYS},}${1#--backup-public-key=}"; shift ;;
        --signers) ARG_SIGNERS="${2:?--signers pkcs11,command}"; shift 2 ;;
        --signers=*) ARG_SIGNERS="${1#--signers=}"; shift ;;
        --server-ref) ARG_SERVER_REF="${2:?--server-ref <commit SHA>}"; shift 2 ;;
        --server-ref=*) ARG_SERVER_REF="${1#--server-ref=}"; shift ;;
        --server-src) ARG_SERVER_SRC="${2:?--server-src <dizin>}"; shift 2 ;;
        --server-src=*) ARG_SERVER_SRC="${1#--server-src=}"; shift ;;
        -h|--help) sed -n '2,49p' "$0"; exit 0 ;;
        *) echo "Bilinmeyen seçenek: $1 (yardım: $0 --help)" >&2; exit 2 ;;
    esac
done

cd "${ROOT_DIR}"

die() { echo "!! $*" >&2; exit 2; }

get_env() {
    [ -f "${ENV_FILE}" ] || return 0
    grep -E "^$1=" "${ENV_FILE}" | tail -n1 | cut -d= -f2- \
        | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/" || true
}

# .env'e yazılacak değer. Betikler .env'i kabukla okur (. ./.env): tırnaksız ya
# da çift tırnaklı bir değerdeki $( ), ` ve ; okunurken ÇALIŞIR. Yalnızca
# güvenli karakterlerden oluşan değer (anahtarlar, parolalar, adresler) olduğu
# gibi yazılır; geri kalanı tek tırnak içinde: kabuk da compose da tek tırnaklı
# değeri harfi harfine alır. Tek tırnak ya da satır sonu içeren değer yazılmaz.
env_quote() {
    local value="$1" safe='^[A-Za-z0-9_.,:/+=@%-]*$'
    if [[ "${value}" =~ ${safe} ]]; then
        printf '%s' "${value}"
        return
    fi
    case "${value}" in
        *"'"*|*$'\n'*) die "Bu değer .env'e yazılamaz: tek tırnak ya da satır sonu içeriyor (${value:0:24}…). .env'e elle yaz." ;;
    esac
    printf "'%s'" "${value}"
}

# Komut ya da yol olarak .env'e giden değerde komut çalıştırma ($( ) ya da `) olmasın.
no_command_substitution() { # $1 = ad, $2 = değer
    case "$2" in
        *'$('*|*'`'*) die "$1 içinde \$( ) ya da \` var: .env okunurken komut çalıştırırdı. Komutu bir betik dosyasına koyup onun yolunu ver." ;;
    esac
}

# KEY=VALUE satırını yerinde günceller; yoksa sona ekler. Dosya izinleri korunur.
# Değer ortamdan okunur (awk -v ters bölüleri yorumlardı).
set_env() {
    local key="$1" value tmp
    value="$(env_quote "$2")"
    tmp="$(mktemp)"
    if grep -qE "^${key}=" "${ENV_FILE}"; then
        SET_ENV_VALUE="${value}" awk -v k="${key}" \
            'index($0, k"=") == 1 { print k"="ENVIRON["SET_ENV_VALUE"]; next } { print }' "${ENV_FILE}" > "${tmp}"
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

# Bu kurulum üretim profili mi: bayrakla ya da daha önce üretim olarak kurulmuş .env ile.
env_profile="$(get_env SAMPLE_PROFILE)"
if [ "${PRODUCTION}" = 0 ] && [ "${env_profile}" = "production" ]; then
    PRODUCTION=1
fi
if [ "${PRODUCTION}" = 0 ] && { [ "${FRESH}" = 1 ] || [ "${EVALUATION}" = 1 ]; }; then
    die "--fresh ve ${EVALUATION_FLAG} yalnızca --production ile kullanılır."
fi

# ── Üretim profili: başlamadan önceki kontroller ────────────────────────────

# data/ altında gerçek veri var mı (.gitkeep ve profil işareti sayılmaz).
data_has_content() {
    [ -d data ] || return 1
    [ -n "$(find data -type f ! -name '.gitkeep' ! -name '.sample-profile' ! -name 'attestation-status.json' 2>/dev/null | head -n 1)" ]
}

# Bu dizindeki çevrimdışı özel anahtar dosyaları (olmamaları gerekir).
offline_private_keys() {
    {
        # offline-keys/ altında public yarı ve not dışındaki her şey
        if [ -d offline-keys ]; then
            find offline-keys -type f ! -name '*.pub' ! -name '*.txt' 2>/dev/null
        fi
        # adıyla belli olanlar, nerede olurlarsa olsunlar
        find . \( -name .git -o -name node_modules \) -prune -o -type f \
            \( -name 'recovery*.pem' -o -name 'backup*.pem' -o -name 'recovery*.key' -o -name 'backup*.key' \) -print 2>/dev/null
    } | sed 's|^\./||' | sort -u
}

# Demo kurulumunu zaman damgalı bir dizine taşır; kurulum boş veriyle başlar.
move_demo_aside() {
    local stamp backup item
    if command -v docker >/dev/null 2>&1 && [ -n "$(docker compose ps -q 2>/dev/null || true)" ]; then
        die "Container çalışıyor. Önce durdur: docker compose down   (sonra bu komutu yeniden çalıştır)"
    fi
    stamp="$(date +%Y%m%d-%H%M%S)"
    backup="backup-before-production-${stamp}"
    mkdir -m 700 "${backup}"
    for item in .env data offline-keys; do
        [ -e "${item}" ] || continue
        mv "${item}" "${backup}/" 2>/dev/null \
            || die "${item} taşınamadı (Linux'ta data/ servis kullanıcısına aittir). Elle taşı: sudo mv ${item} ${backup}/   sonra bu komutu yeniden çalıştır."
    done
    mkdir -p data/db data/certs
    : > data/db/.gitkeep; : > data/certs/.gitkeep
    cat >&2 <<EOF
>> Eski kurulum taşındı: ${backup}/
   İçinde demo kurulumunun gizli değerleri var (API anahtarı, imza anahtarı, sunucu
   sertifikası, veritabanı). Üretimde hiçbiri kullanılmaz. İhtiyacın kalmayınca sil:
     rm -rf ${backup}
EOF
}

production_preflight() {
    command -v openssl >/dev/null 2>&1 || die "openssl gerekli."

    # Demo kurulumunun üstüne kurma: demo .env'i, imza anahtarı, veritabanı (açık
    # kayıt ayarı dahil) ve sunucu sertifikası üretime taşınmamalı.
    local demo_env=0 demo_data=0
    if [ -f "${ENV_FILE}" ] && [ "${env_profile}" != "production" ]; then demo_env=1; fi
    if data_has_content && [ "$(cat data/.sample-profile 2>/dev/null || true)" != "production" ]; then demo_data=1; fi
    if [ "${demo_env}" = 1 ] || [ "${demo_data}" = 1 ]; then
        if [ "${FRESH}" = 1 ]; then
            move_demo_aside
            env_profile=""
        else
            cat >&2 <<'EOF'
!! Bu dizinde üretim olarak kurulmamış bir kurulum var:
EOF
            [ "${demo_env}" = 1 ] && echo "!!   .env (demo profili: paylaşılan API anahtarı, test ayarları)" >&2
            [ "${demo_data}" = 1 ] && echo "!!   data/ (demo imza anahtarı, sunucu sertifikası, veritabanı)" >&2
            cat >&2 <<'EOF'
!! Üretim profili bunların üstüne kurulmaz: demo anahtarları ve ayarları üretime
!! taşınırdı. Temiz başlamak için (eskiler zaman damgalı bir dizine taşınır):
!!   docker compose down
!!   ./scripts/setup.sh --production --fresh …
EOF
            exit 2
        fi
    elif [ "${FRESH}" = 1 ] && { [ -f "${ENV_FILE}" ] || data_has_content; }; then
        die "--fresh var olan ÜRETİM kurulumunu taşımaz (veri kaybı olurdu). Gerçekten baştan kurmak istiyorsan .env ve data/ dizinini kendin yedekleyip kaldır."
    fi

    # Uçtan uca testlerin dışa aktardığı sunucu TLS özel anahtarı (düz metin).
    if [ -e data/proxy ]; then
        rm -rf data/proxy
        echo ">> data/proxy silindi (export-server-key.sh çıktısı; üretimde yeri yok)"
    fi

    # Çevrimdışı özel anahtarlar bu makinede olmamalı.
    local found
    found="$(offline_private_keys)"
    if [ -n "${found}" ]; then
        cat >&2 <<EOF
!! Bu dizinde çevrimdışı özel anahtar dosyası var:
$(printf '%s\n' "${found}" | sed 's/^/!!   /')
!! Kurtarma ve yedek anahtarları, sunucunun imza anahtarı çalındığında ONU iptal
!! eden anahtarlardır; sunucuda dururlarsa sunucuyu ele geçiren hepsini birden
!! alır. Bu dosyaları internete kapalı bir makineye taşı ve buradan sil, sonra
!! yeniden çalıştır. Üretim profili yalnızca PUBLIC yarıları ister:
!!   (başka makinede)  ./scripts/offline-keygen.sh keys recovery-1 backup-1
!!   (burada)          ./scripts/setup.sh --production --recovery-public-key … --backup-public-key …
EOF
        exit 2
    fi
}

if [ "${PRODUCTION}" = 1 ]; then
    production_preflight
fi

# ── Ortak adımlar ───────────────────────────────────────────────────────────

if [ ! -f "${ENV_FILE}" ]; then
    if [ "${PRODUCTION}" = 1 ]; then
        cp .env.production.example "${ENV_FILE}"
        echo ">> .env oluşturuldu (.env.production.example'dan)"
    else
        cp .env.example "${ENV_FILE}"
        echo ">> .env oluşturuldu (.env.example'dan)"
    fi
fi
chmod 600 "${ENV_FILE}"

if [ -z "$(get_env API_KEY)" ]; then
    set_env API_KEY "$(random_key)"
    echo ">> API_KEY üretildi (.env içinde)"
fi

if [ -z "$(get_env KEYSTORE_PASSWORD)" ]; then
    set_env KEYSTORE_PASSWORD "$(random_key)"
    echo ">> KEYSTORE_PASSWORD üretildi (.env içinde); var olan anahtar depoları sunucu açılırken bu parolaya geçer"
fi

if [ -z "$(get_env VAULT_AT_REST_PASSWORD)" ]; then
    set_env VAULT_AT_REST_PASSWORD "$(random_key)"
    echo ">> VAULT_AT_REST_PASSWORD üretildi (.env içinde); demo parolasıyla şifrelenmiş vault dosyaları sunucu açılırken bu parolaya geçer"
fi

# İmza anahtarı dosyası (data/signing-key.pem) diskte bu parolayla şifrelenir.
# Sunucu, sunucudaki yerel imzalayıcı için bu parola olmadan açılmaz (yalnızca
# HSM/KMS imzalayıcısı varsa gerekmez; üretilmesi zarar vermez). Düz metin duran
# bir anahtar dosyası sunucu ilk açılışta bu parolayla şifrelenir.
if [ -z "$(get_env SIGNING_KEY_PASSWORD)" ]; then
    set_env SIGNING_KEY_PASSWORD "$(random_key)"
    echo ">> SIGNING_KEY_PASSWORD üretildi (.env içinde); imza anahtarı diskte şifrelenir (var olan düz dosya sunucu açılırken şifrelenir)"
fi

# "URL'den sertifika al": sunucu, loopback ve yerel ağ adreslerine yalnızca bu
# açıkken bağlanır. Demo profili bu makinedeki ve LAN'daki deneme host'larını
# pinlediği için açar; üretim profili kapalı tutar.
if [ "${PRODUCTION}" = 1 ]; then
    # .env.production.example'da boş; biri bilerek true yazdıysa dokunulmaz, yalnızca söylenir.
    if [ "$(get_env FETCH_ALLOW_PRIVATE_TARGETS)" = "true" ]; then
        echo "!! FETCH_ALLOW_PRIVATE_TARGETS=true: sunucu \"URL'den sertifika al\" ile bu makineye ve yerel ağa bağlanabilir. Bilerek açmadıysan .env'de boş bırak." >&2
    fi
elif [ -z "$(get_env FETCH_ALLOW_PRIVATE_TARGETS)" ]; then
    set_env FETCH_ALLOW_PRIVATE_TARGETS true
    echo ">> FETCH_ALLOW_PRIVATE_TARGETS=true (demo: sunucu bu makinedeki ve yerel ağdaki host'ların sertifikasını alabilir)"
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

mkdir -p data/db data/certs
# Anahtar depoları ve veritabanı yalnızca sahibine açık olsun. (Linux'ta dizinler
# sunucu ilk açıldıktan sonra servis kullanıcısına geçer; o zaman dokunulamaz.)
chmod 700 data/db 2>/dev/null || true
chmod 711 data data/certs 2>/dev/null || true

# ── Üretim profili ──────────────────────────────────────────────────────────

# Base64 X.509 public key gerçekten bir EC P-256 anahtarı mı?
valid_public_key() {
    local text
    text="$(printf '%s' "$1" | openssl base64 -d -A 2>/dev/null | openssl pkey -pubin -inform DER -noout -text 2>/dev/null)" || return 1
    printf '%s' "${text}" | grep -qiE 'prime256v1|P-256'
}

# Virgülle ayrılmış public key listesi: boşlukları atar, her birini doğrular,
# tekrarları çıkarır. Geçersiz anahtarda durur.
normalize_public_keys() { # $1 = liste, $2 = ne olduğu (hata mesajı için)
    local out="" item
    local -a items
    IFS=',' read -r -a items <<<"$1"
    for item in "${items[@]:-}"; do
        item="$(printf '%s' "${item}" | tr -d ' \t\r\n')"
        [ -z "${item}" ] && continue
        valid_public_key "${item}" || die "$2 geçerli bir EC P-256 public key değil (Base64 X.509 bekleniyor): ${item:0:24}…"
        case ",${out}," in *",${item},"*) continue ;; esac
        out="${out:+${out},}${item}"
    done
    printf '%s' "${out}"
}

# Yayın imza sertifikalarının SHA-256'ları (virgülle; ':' ve büyük harf olabilir):
# geçerliyse küçük harf ve ':'siz yazar, değilse hiçbir şey yazmaz.
normalize_signers() {
    local out="" item
    local -a items
    IFS=',' read -r -a items <<<"$1"
    for item in "${items[@]:-}"; do
        item="$(printf '%s' "${item}" | tr -d ': \t' | tr 'A-F' 'a-f')"
        [ -z "${item}" ] && continue
        [[ "${item}" =~ ^[0-9a-f]{64}$ ]] || return 0
        out="${out:+${out},}${item}"
    done
    printf '%s' "${out}"
}

# USER_AUTH_ATTESTATION=enforce uygulamanın imzası bilinmeden çalışmaz: imza
# sertifikası sabitlenmezse herhangi bir uygulama, herhangi bir cihaz adına
# geçerli bir donanım belgesi üretebilir. Sunucu bunsuz açılmayı reddeder.
attestation_signer() {
    local current signer normalized
    current="$(get_env ATTESTATION_SIGNER_SHA256)"
    signer="${ATTESTATION_SIGNER:-${current}}"
    if [ -z "${signer}" ] && [ -t 0 ]; then
        cat <<'EOF'

Uygulamanın YAYIN imza sertifikasının SHA-256 parmak izi gerekli
(ATTESTATION_SIGNER_SHA256): ekran kilidiyle açılan dosyaların anahtarını
yalnızca sizin imzanızı taşıyan uygulama kaydedebilsin diye. İmzalı APK'dan:
  apksigner verify --print-certs app-release.apk | grep SHA-256
  keytool -printcert -jarfile app-release.apk | grep SHA256
Google Play uygulamayı kendisi imzalıyorsa (Play App Signing): Play Console →
Uygulama bütünlüğü → Uygulama imzalama anahtarı sertifikası → SHA-256.
Uygulama DexProtector gibi bir araçtan geçiyorsa: telefona kurulan SON dosyanın
imzası. Birden fazlaysa virgülle ayırın; ':' olabilir.
EOF
        read -r -p "ATTESTATION_SIGNER_SHA256: " signer
    fi
    if [ -z "${signer}" ]; then
        cat >&2 <<'EOF'
!! ATTESTATION_SIGNER_SHA256 boş. Üretim profili USER_AUTH_ATTESTATION=enforce
!! kullanır; sunucu uygulamanın imza sertifikası olmadan açılmaz. Yayın
!! APK'sından alın:
!!   apksigner verify --print-certs app-release.apk | grep SHA-256
!!   (ya da: keytool -printcert -jarfile app-release.apk | grep SHA256)
!! sonra: ./scripts/setup.sh --production --attestation-signer <SHA-256>
EOF
        exit 2
    fi
    normalized="$(normalize_signers "${signer}")"
    if [ -z "${normalized}" ]; then
        die "ATTESTATION_SIGNER_SHA256 geçersiz: her biri 64 onaltılık karakter olmalı (':' olabilir): ${signer}"
    fi
    if [ "${normalized}" != "${current}" ]; then
        set_env ATTESTATION_SIGNER_SHA256 "${normalized}"
        echo ">> ATTESTATION_SIGNER_SHA256 yazıldı"
    fi
}

# Sunucu kaynağı değişmez olmalı: ya tam bir commit SHA'sı ya da yerel dizin.
# "main" gibi bir dal adı her derlemede başka bir kodu getirebilir.
server_source() {
    if [ -n "${ARG_SERVER_SRC}" ]; then
        no_command_substitution --server-src "${ARG_SERVER_SRC}"
        set_env PINVAULT_SERVER_SRC "${ARG_SERVER_SRC}"
    fi
    if [ -n "${ARG_SERVER_REF}" ]; then set_env PINVAULT_REF "${ARG_SERVER_REF}"; fi
    local src ref
    src="$(get_env PINVAULT_SERVER_SRC)"
    ref="$(get_env PINVAULT_REF)"
    if [ -n "${src}" ]; then
        no_command_substitution PINVAULT_SERVER_SRC "${src}"
        [ -f "${src}/build.gradle.kts" ] || die "PINVAULT_SERVER_SRC bir demo-server dizini değil: ${src}"
        echo ">> Sunucu kaynağı: yerel dizin ${src} (hangi commit'ten derlediğini sen kaydet)"
        return
    fi
    if [[ "${ref}" =~ ^[0-9a-f]{40}$ ]]; then
        echo ">> Sunucu kaynağı: $(get_env PINVAULT_REPO) @ ${ref}"
        return
    fi
    cat >&2 <<EOF
!! Sunucu kaynağı sabit değil: PINVAULT_REF='${ref}'.
!! Dal ya da etiket adı (main, v2.1.1 …) zamanla başka bir kodu gösterebilir; üretim
!! imajı her zaman aynı, gözden geçirilmiş koddan derlenmeli. İkisinden biri:
!!   --server-ref <40 haneli commit SHA'sı>     (git rev-parse <etiket>^{commit})
!!   --server-src <yerel demo-server dizini>    (ör. ../demo-server)
EOF
    exit 2
}

# İmzalayıcılar: en az iki, en az biri sunucunun diskinde düz dosya olmayan.
signers() {
    [ -n "${ARG_SIGNERS}" ] && set_env CONFIG_SIGNERS "${ARG_SIGNERS}"
    local list count=0 external=0 spec type
    local -a specs
    list="$(get_env CONFIG_SIGNERS)"
    IFS=',' read -r -a specs <<<"${list:-local}"
    for spec in "${specs[@]}"; do
        spec="$(printf '%s' "${spec}" | tr -d ' ')"
        [ -z "${spec}" ] && continue
        type="$(printf '%s' "${spec%%:*}" | tr 'A-Z' 'a-z')"
        count=$((count + 1))
        case "${type}" in
            local) ;;
            pkcs11)
                [ "${spec}" = "${type}" ] || die "CONFIG_SIGNERS: adlı pkcs11 imzalayıcısı (${spec}) bu compose dosyasıyla desteklenmiyor; 'pkcs11' yaz."
                # Ortamdan verildiyse .env'e al (PIN komut satırına yazılmasın diye bayrağı yok).
                for var in PKCS11_LIBRARY PKCS11_PIN PKCS11_SLOT_INDEX PKCS11_KEY_LABEL; do
                    if [ -z "$(get_env "${var}")" ] && [ -n "${!var:-}" ]; then set_env "${var}" "${!var}"; fi
                done
                [ -n "$(get_env PKCS11_LIBRARY)" ] || die "pkcs11 imzalayıcısı için PKCS11_LIBRARY gerekli (HSM üreticisinin PKCS#11 kitaplığının container içindeki yolu). .env'e yaz ya da ortam değişkeni olarak ver."
                [ -n "$(get_env PKCS11_PIN)" ] || die "pkcs11 imzalayıcısı için PKCS11_PIN gerekli. .env'e yaz ya da ortam değişkeni olarak ver (komut satırına yazma)."
                case "$(get_env PKCS11_LIBRARY | tr 'A-Z' 'a-z')" in
                    *softhsm*)
                        # SoftHSM gerçek HSM değil: anahtar yine bu sunucunun diskinde durur.
                        echo "!! PKCS11_LIBRARY SoftHSM'i gösteriyor: SoftHSM bir deneme aracıdır, anahtarı yine bu sunucunun diskinde tutar; 'sunucunun diski dışındaki imzalayıcı' sayılmadı." >&2
                        ;;
                    *) external=$((external + 1)) ;;
                esac
                ;;
            command)
                external=$((external + 1))
                [ "${spec}" = "${type}" ] || die "CONFIG_SIGNERS: adlı command imzalayıcısı (${spec}) bu compose dosyasıyla desteklenmiyor; 'command' yaz."
                for var in SIGNER_COMMAND SIGNER_PUBLIC_KEY SIGNER_PUBLIC_KEY_FILE SIGNER_INPUT; do
                    if [ -z "$(get_env "${var}")" ] && [ -n "${!var:-}" ]; then
                        no_command_substitution "${var}" "${!var}"
                        set_env "${var}" "${!var}"
                    fi
                done
                [ -n "$(get_env SIGNER_COMMAND)" ] || die "command imzalayıcısı için SIGNER_COMMAND gerekli (KMS ya da imza servisini çağıran komut)."
                no_command_substitution SIGNER_COMMAND "$(get_env SIGNER_COMMAND)"
                [ -n "$(get_env SIGNER_PUBLIC_KEY)$(get_env SIGNER_PUBLIC_KEY_FILE)" ] || die "command imzalayıcısı için SIGNER_PUBLIC_KEY (ya da SIGNER_PUBLIC_KEY_FILE) gerekli."
                ;;
            *) die "CONFIG_SIGNERS: bilinmeyen imzalayıcı türü '${spec}' (local, pkcs11, command)." ;;
        esac
    done

    if [ "${count}" -ge 2 ] && [ "${external}" -ge 1 ]; then
        set_env CLIENT_REQUIRED_SIGNATURES 2
        [ -z "$(get_env SAMPLE_EVALUATION)" ] || set_env SAMPLE_EVALUATION ""
        echo ">> İmzalayıcılar: ${list} (${count} imzalayıcı, ${external} tanesi sunucunun diski dışında); uygulama her config'te 2 imza isteyecek"
        return
    fi
    if [ "${EVALUATION}" = 1 ]; then
        set_env SAMPLE_EVALUATION single-signer
        set_env CLIENT_REQUIRED_SIGNATURES 1
        cat >&2 <<EOF

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!! BU KURULUM ÜRETİM DEĞİLDİR (${EVALUATION_FLAG}).
!! İmzalayıcılar: ${list:-local}. Pin'leri tek bir anahtar imzalıyor ve o anahtar
!! sunucunun diskinde: sunucuyu ele geçiren, bütün telefonların güveneceği pin
!! yayımlayabilir. Yalnızca değerlendirme için kullan; gerçek kullanıcıya açma.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
EOF
        return
    fi
    cat >&2 <<EOF
!! Üretim profili en az İKİ imzalayıcı ister ve en az biri sunucunun diskinde
!! düz dosya OLMAMALI. Şu anki ayar: CONFIG_SIGNERS='${list:-local}'.
!! Neden: tek ve diskteki bir anahtarla, sunucuyu ele geçiren (ya da o dosyayı
!! kopyalayan) herkes bütün telefonların kabul edeceği pin'leri imzalayabilir.
!! İki ayrı sistemde iki imza olunca (ve uygulama 2 imza isteyince) tek birini ele
!! geçirmek yetmez.
!!   --signers pkcs11,command   HSM + bulut KMS (önerilen)
!!   --signers local,command    sunucudaki anahtar + KMS
!!   --signers local,pkcs11     sunucudaki anahtar + HSM
!! pkcs11 için PKCS11_LIBRARY ve PKCS11_PIN, command için SIGNER_COMMAND ve
!! SIGNER_PUBLIC_KEY gerekir (.env'e ya da ortam değişkeni olarak).
!! Yalnızca denemek için, üretim OLMADIĞINI kabul ederek: ${EVALUATION_FLAG}
EOF
    exit 2
}

# Kişisel yönetici anahtarları: sunucuya yalnızca SHA-256'ları gider.
admins() {
    local entries="" name hash key generated=0
    local -a items
    if [ -z "${ADMINS}" ]; then
        local count
        count="$(get_env ADMIN_KEYS | tr ',' '\n' | grep -c . || true)"
        [ "${count}" -ge 2 ] && return
        die "İki kişi onayı için en az iki yönetici gerekir: --admins ad1:sha256,ad2:sha256 (her yönetici kendi makinesinde: ./scripts/offline-keygen.sh admin <ad>)."
    fi
    IFS=',' read -r -a items <<<"${ADMINS}"
    [ "${#items[@]}" -ge 2 ] || die "İki kişi onayı için en az iki yönetici gerekir (--admins ad1:sha256,ad2:sha256)."
    for item in "${items[@]}"; do
        name="${item%%:*}"
        hash=""
        case "${item}" in *:*) hash="$(printf '%s' "${item#*:}" | tr 'A-F' 'a-f')" ;; esac
        [[ "${name}" =~ ^[A-Za-z0-9._-]{1,32}$ ]] || die "Yönetici adı yalnızca harf, rakam, . _ - (en çok 32): ${name}"
        [ "${name}" = "admin" ] && die "'admin' adı API_KEY'e ayrılmış"
        if [ -z "${hash}" ]; then
            # Anahtar burada üretilir, yalnızca ekrana yazılır; diske düşmez.
            key="$(openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-43)"
            hash="$(printf '%s' "${key}" | openssl dgst -sha256 | awk '{print $NF}')"
            if [ "${generated}" = 0 ]; then
                echo "" >&2
                echo "== Kişisel yönetici anahtarları (BİR KEZ gösterilir, hiçbir yere kaydedilmez) ==" >&2
                generated=1
            fi
            printf '   %-16s %s\n' "${name}" "${key}" >&2
        else
            [[ "${hash}" =~ ^[0-9a-f]{64}$ ]] || die "${name}: SHA-256 64 onaltılık karakter olmalı."
        fi
        entries="${entries:+${entries},}${name}:${hash}"
    done
    if [ "${generated}" = 1 ]; then
        cat >&2 <<'EOF'
   Her anahtarı sahibine güvenli bir kanaldan ver ve bu ekranı temizle. Daha iyisi:
   her yönetici anahtarını kendi makinesinde üretsin (offline-keygen.sh admin <ad>)
   ve buraya yalnızca ad:sha256 verilsin; o zaman anahtar bu makineden hiç geçmez.

EOF
    fi
    set_env ADMIN_KEYS "${entries}"
    echo ">> ADMIN_KEYS: ${#items[@]} kişisel yönetici (sunucuda yalnızca SHA-256'ları)"
}

production_profile() {
    # Compose üretim dosyası `!override` kullanır: Docker Compose 2.24.4+.
    if command -v docker >/dev/null 2>&1; then
        local version
        version="$(docker compose version --short 2>/dev/null | sed 's/^v//' || true)"
        if [ -n "${version}" ] && [ "$(printf '%s\n2.24.4\n' "${version}" | sort -V | head -n 1)" != "2.24.4" ]; then
            die "Docker Compose ${version} bulundu; üretim profili 2.24.4 ya da yenisini ister (docker-compose.production.yml)."
        fi
    fi

    set_env SAMPLE_PROFILE production
    set_env COMPOSE_FILE docker-compose.yml:docker-compose.production.yml
    # Yönetim portları yalnızca bu makineye (compose üretim dosyası da sabitler).
    set_env HOST_HTTP_BIND 127.0.0.1
    set_env HOST_MANAGEMENT_TLS_BIND 127.0.0.1

    server_source
    signers

    # Çevrimdışı anahtarların PUBLIC yarıları.
    local recovery backup
    [ -n "${ARG_RECOVERY_KEYS}" ] || ARG_RECOVERY_KEYS="$(get_env RECOVERY_PUBLIC_KEYS)"
    [ -n "${ARG_BACKUP_KEYS}" ] || ARG_BACKUP_KEYS="$(get_env BACKUP_PUBLIC_KEYS)"
    recovery="$(normalize_public_keys "${ARG_RECOVERY_KEYS}" "Kurtarma anahtarı")"
    backup="$(normalize_public_keys "${ARG_BACKUP_KEYS}" "Yedek imza anahtarı")"
    if [ -z "${recovery}" ]; then
        cat >&2 <<'EOF'
!! Kurtarma anahtarının public yarısı verilmedi (--recovery-public-key).
!! Kurtarma anahtarı, çalınan ya da kaybolan bir imza anahtarını bütün telefonlarda
!! uygulama güncellemesi olmadan değiştirmenin tek yoludur. BAŞKA bir makinede üret:
!!   ./scripts/offline-keygen.sh keys recovery-1 backup-1
!! ve yazdırdığı public key'leri buraya ver:
!!   ./scripts/setup.sh --production --recovery-public-key <B64> --backup-public-key <B64> …
EOF
        exit 2
    fi
    case ",${backup}," in *",${recovery%%,*},"*) die "Kurtarma anahtarı yedek imza anahtarıyla aynı olamaz: iki ayrı anahtar üret." ;; esac
    if [ -z "${backup}" ]; then
        cat >&2 <<'EOF'
!! Yedek imza anahtarının public yarısı verilmedi (--backup-public-key).
!! Yedek anahtar, imzalayıcılardan biri (HSM, KMS) kaybolduğunda telefonların
!! uygulama güncellemesi olmadan config almaya devam etmesini sağlar. Uygulama her
!! config'te 2 imza ister; yedek olmadan bir imzalayıcının kaybı bütün telefonları
!! durdurur. Release derlemesi de yedeksiz değerlerle derlenmez. BAŞKA bir makinede üret:
!!   ./scripts/offline-keygen.sh keys recovery-1 backup-1
!!   ./scripts/setup.sh --production --recovery-public-key <B64> --backup-public-key <B64> …
EOF
        exit 2
    fi
    set_env RECOVERY_PUBLIC_KEYS "${recovery}"
    set_env BACKUP_PUBLIC_KEYS "${backup}"
    echo ">> RECOVERY_PUBLIC_KEYS yazıldı ($(printf '%s' "${recovery}" | tr ',' '\n' | grep -c .) anahtar); özel yarısı bu makinede yok"
    echo ">> BACKUP_PUBLIC_KEYS yazıldı: client-config.sh uygulamanın güvendiği anahtarlara ekler"

    admins

    set_env ENROLLMENT_MODE token
    set_env PIN_CHANGE_APPROVALS 2
    set_env PIN_LIVE_CHECK enforce
    # Ekran kilidiyle açılan dosyaların anahtarı: donanım belgesi şart, belge
    # örnek uygulamanın paket adını taşımalı (başka bir uygulama yazılmışsa elle).
    set_env USER_AUTH_ATTESTATION enforce
    [ -n "$(get_env ATTESTATION_PACKAGE_NAMES)" ] || set_env ATTESTATION_PACKAGE_NAMES com.example.sampleclient
    attestation_signer
    # Kayıtta donanım belgesi, P12 ile kayıt kapalı, kilitli dosyada her kullanımda onay.
    set_env ENROLLMENT_ATTESTATION enforce
    set_env ENROLLMENT_P12 off
    set_env USER_AUTH_REQUIRE_PER_USE true
    # Donanım belgesi: kilidi açılmış (bootloader) telefon geçmez; Google'ın iptal
    # listesi data/'daki dosyadan okunur ve 48 saatten eskiyse hiçbir belge geçmez
    # (liste aşağıda bir kez indirilir; cron'a koymak README → "Donanım belgesi iptal listesi").
    set_env ATTESTATION_REQUIRE_VERIFIED_BOOT true
    [ -n "$(get_env ATTESTATION_REVOKED_SERIALS_FILE)" ] || set_env ATTESTATION_REVOKED_SERIALS_FILE /data/attestation-status.json
    [ -n "$(get_env ATTESTATION_STATUS_MAX_AGE_HOURS)" ] || set_env ATTESTATION_STATUS_MAX_AGE_HOURS 48
    # Test anahtarları: boş bırakılır; compose üretim dosyası ayrıca "false" sabitler.
    set_env ALLOW_TEST_HOOKS ""
    set_env ALLOW_ANONYMOUS_ADMIN ""
    # Ret sınırı: sunucu varsayılanı (demo'daki 0 = sınırsız değeri üretime taşınmasın).
    [ "$(get_env DEVICE_REFUSAL_RATE_LIMIT)" != "0" ] || set_env DEVICE_REFUSAL_RATE_LIMIT ""
    echo ">> Üretim ayarları: ENROLLMENT_MODE=token, PIN_CHANGE_APPROVALS=2, PIN_LIVE_CHECK=enforce," \
        "USER_AUTH_ATTESTATION=enforce, ENROLLMENT_ATTESTATION=enforce, ENROLLMENT_P12=off, USER_AUTH_REQUIRE_PER_USE=true," \
        "ATTESTATION_REQUIRE_VERIFIED_BOOT=true, ATTESTATION_STATUS_MAX_AGE_HOURS=$(get_env ATTESTATION_STATUS_MAX_AGE_HOURS)"

    # Sunucunun yerel imzalayıcısı varsa (CONFIG_SIGNERS boş ya da "local" içeriyor)
    # anahtar dosyası diskte şifreli olmalı: parola yukarıda üretildi; boşsa dur.
    if has_local_signer && [ -z "$(get_env SIGNING_KEY_PASSWORD)" ]; then
        die "SIGNING_KEY_PASSWORD boş: sunucudaki yerel imza anahtarı diskte şifresiz kalırdı. .env'den silinmiş olabilir; boş satırı kaldırıp yeniden çalıştır."
    fi
    # Demo değerleriyle açılma izni üretimde yok.
    if [ -n "$(get_env ALLOW_DEMO_SECRETS)" ]; then
        set_env ALLOW_DEMO_SECRETS ""
        echo ">> ALLOW_DEMO_SECRETS kaldırıldı (üretimde sunucu demo parolalarıyla açılmaz)"
    fi
    # Eski kütüphane sürümlerine giden P12 paketinin parolası: varsayılan "changeit" kalmasın.
    if [ -z "$(get_env CLIENT_P12_PASSWORD)" ]; then
        set_env CLIENT_P12_PASSWORD "$(random_key)"
        echo ">> CLIENT_P12_PASSWORD üretildi (P12 ile kayıt kapalı olsa da varsayılan parola kalmasın)"
    fi

    # Canlı sertifika kontrolü sunucunun içinden yapılır: host'un kendi IP'si oradan
    # doğrudan görünmez, container içindeki dinleyiciye yönlenir.
    if [ -z "$(get_env LIVE_CHECK_HOST_MAP)" ]; then
        local ip; ip="$(get_env HOST_LAN_IP)"
        if [ -n "${ip}" ]; then
            # set_env gerekirse tek tırnak koyar (birden çok eşleme ';' ile ayrılır).
            set_env LIVE_CHECK_HOST_MAP "${ip}=127.0.0.1:8081"
            echo ">> LIVE_CHECK_HOST_MAP yazıldı (host IP'si container içindeki dinleyiciye)"
        fi
    fi

    printf 'production\n' > data/.sample-profile

    # Donanım belgesi iptal listesi: sunucu dosya olmadan açılmaz. İlk kopya şimdi
    # indirilir; sonrası cron'un işi (README → "Donanım belgesi iptal listesi").
    local list_file; list_file="$(get_env ATTESTATION_REVOKED_SERIALS_FILE)"
    if [ -n "${list_file}" ] && [ ! -f "data/${list_file#/data/}" ]; then
        if "${SCRIPT_DIR}/fetch-attestation-status.sh"; then
            echo ">> Donanım belgesi iptal listesi indirildi (data/${list_file#/data/}). Cron'a koy: README → \"Donanım belgesi iptal listesi\""
        else
            cat >&2 <<EOF
!! Google'ın donanım belgesi iptal listesi indirilemedi. Sunucu bu dosya olmadan
!! AÇILMAZ (ATTESTATION_REVOKED_SERIALS_FILE=${list_file}). İnternet bağlantısı
!! olunca: ./scripts/fetch-attestation-status.sh   (sonra cron'a koy, README)
EOF
        fi
    fi
}

# Sunucuda yerel (dosya) imzalayıcı var mı: CONFIG_SIGNERS boşsa ya da "local" içeriyorsa.
has_local_signer() {
    local list
    list="$(get_env CONFIG_SIGNERS)"
    [ -z "${list}" ] && return 0
    printf '%s' "${list}" | tr ',' '\n' | tr -d ' ' | grep -qx 'local'
}

if [ "${PRODUCTION}" = 1 ]; then
    production_profile
fi

if has_local_signer; then
    if [ ! -f data/signing-key.pem ]; then
        if [ "${PRODUCTION}" = 1 ]; then
            # Üretimde bu anahtar imzalayıcılardan yalnızca biridir; tek başına pin yayımlayamaz.
            "${SCRIPT_DIR}/generate-signing-key.sh" >/dev/null
            echo ">> Sunucunun yerel imza anahtarı üretildi (data/signing-key.pem; ilk açılışta SIGNING_KEY_PASSWORD ile şifrelenir)"
        else
            "${SCRIPT_DIR}/generate-signing-key.sh"
        fi
    fi
    signing_key_note="data/signing-key.pem"
else
    signing_key_note="sunucunun diskinde imza anahtarı yok ($(get_env CONFIG_SIGNERS))"
fi

server_src="$(get_env PINVAULT_SERVER_SRC)"
echo ""
echo "== Hazır =="
echo "  .env          : API_KEY, KEYSTORE_PASSWORD, VAULT_AT_REST_PASSWORD ve SIGNING_KEY_PASSWORD dolu, HOST_LAN_IP=$(get_env HOST_LAN_IP)"
echo "  Sertifika alma: FETCH_ALLOW_PRIVATE_TARGETS=$(get_env FETCH_ALLOW_PRIVATE_TARGETS)$([ "$(get_env FETCH_ALLOW_PRIVATE_TARGETS)" = true ] && printf ' (bu makine ve yerel ağ dahil)' || printf ' (boş: yalnızca internetteki adresler)')"
echo "  Sunucu kaynağı: ${server_src:-upstream git @ $(get_env PINVAULT_REF)}"
echo "  Signing key   : ${signing_key_note}"
echo ""
echo "Sıradaki adımlar:"
echo "  docker compose up -d --build"
echo "  ./scripts/provision.sh"
echo "  ./scripts/smoke-test.sh"
echo "  ./scripts/client-config.sh"

if [ "$(get_env SAMPLE_PROFILE)" = "production" ]; then
    cat <<EOF

== ÜRETİM PROFİLİ ==
  Kişisel yöneticiler : $(get_env ADMIN_KEYS | tr ',' '\n' | cut -d: -f1 | paste -sd, -)  (iki kişi onayı açık)
  İmzalayıcılar       : $(get_env CONFIG_SIGNERS)  → uygulama $(get_env CLIENT_REQUIRED_SIGNATURES) imza ister
  Kurtarma anahtarı   : RECOVERY_PUBLIC_KEYS dolu (özel yarısı bu makinede yok)
  Canlı sertifika     : enforce
  Ekran kilitli dosya : USER_AUTH_ATTESTATION=enforce, paket $(get_env ATTESTATION_PACKAGE_NAMES), imza SHA-256 $(get_env ATTESTATION_SIGNER_SHA256 | cut -c1-16)…
  Yönetim portları    : yalnızca bu makine (127.0.0.1:$(get_env HOST_HTTP_PORT), 127.0.0.1:$(get_env HOST_MANAGEMENT_TLS_PORT)).
                        Uzaktan: VPN ya da  ssh -L $(get_env HOST_MANAGEMENT_TLS_PORT):127.0.0.1:$(get_env HOST_MANAGEMENT_TLS_PORT) <sunucu>

  provision.sh'ın pin yazmaları bu profilde ikinci bir yöneticinin onayını bekler
  (dashboard → Onaylar). Kişisel anahtarla çalıştır: ADMIN_KEY=… ./scripts/provision.sh
EOF
    if [ "$(get_env SAMPLE_EVALUATION)" = "single-signer" ]; then
        cat >&2 <<EOF

!! BU KURULUM ÜRETİM DEĞİLDİR: tek imzalayıcıyla kuruldu (${EVALUATION_FLAG}).
!! Gerçek kullanıcıya açmadan önce iki imzalayıcıyla yeniden kur (--signers …).
EOF
    fi
else
    cat >&2 <<'EOF'

!! DEMO PROFİLİ: bu kurulum yalnızca denemek ve uçtan uca testler içindir.
!! Tek paylaşılan API anahtarı, iki kişi onayı yok, canlı sertifika kontrolü
!! kapalı, imza anahtarı sunucunun diskinde, yedek/kurtarma anahtarı yok.
!! Gerçek kullanım için: ./scripts/setup.sh --production (README → "Üretim profili").
EOF
fi
