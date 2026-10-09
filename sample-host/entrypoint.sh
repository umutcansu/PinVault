#!/bin/sh
# Sunucu root olarak çalışmaz (demo-server imajı da uid 10001 ile çalışır; bu
# imaj aynı kullanıcıyı kendisi oluşturur). data/ çoğunlukla docker compose'u çalıştıran
# kullanıcının oluşturduğu bir bağlamadır (bind mount); açılışta sahipliği
# servis kullanıcısına verilir, sonra yetkiler bırakılıp sunucu başlatılır.
# `docker compose exec` ile çalıştırılan araçlar (keytool, softhsm2-util)
# root kalır; oluşturdukları dosyalar bir sonraki açılışta yine düzelir.
#
# Dosya izinleri: data/ altındaki anahtar depoları (*.jks), veritabanı ve imza
# anahtarı yalnızca servis kullanıcısına açıktır (umask 077 + aşağıdaki chmod).
# Tek istisna data/certs/demo-server.pins: içinde yalnızca herkese açık pin'ler
# vardır ve host'taki betikler (client-config.sh, provision.sh) onu okur.
#
# Üretim profilinde (SAMPLE_PROFILE=production) sunucu şu durumlarda AÇILMAZ:
#   - /data altında çevrimdışı özel anahtar ya da demo kalıntısı varsa,
#   - test anahtarları açıksa ya da kayıt modu token değilse,
#   - iki kişi onayı, canlı sertifika kontrolü, donanım belgesi ayarları (App Attest /
#     Play Integrity v2 bağı ve strict varsayılan politika dahil) üretim değerlerinde değilse, ikiden az kişisel yönetici varsa, kurtarma anahtarı
#     yoksa, imzalayıcılar ikiden azsa ya da hiçbiri sunucunun diski dışında
#     değilse (SoftHSM sayılmaz),
#   - sunucu kaynağı sabit bir commit değilse (PINVAULT_REF 40 haneli SHA ya da
#     PINVAULT_SERVER_SRC dolu).
# setup.sh --production bunları kurulurken denetler; burada her açılışta yeniden
# denetlenir: .env sonradan elle değiştirilse de kurallara uymayan sunucu açılmaz.
set -eu

umask 077

fail() {
    echo "pinvault-entrypoint: $*" >&2
    exit 78
}

production_checks() {
    # 1. Çevrimdışı anahtarlar (kurtarma, yedek) sunucuya hiç gelmemeli. Bunlar
    #    sunucunun imza anahtarı çalındığında ONU iptal eden anahtarlardır;
    #    sunucuda dururlarsa sunucuyu ele geçiren hepsini birden alır.
    found="$(find /data \( -type d -name 'offline-keys' -o -type f \( -name 'recovery*.pem' -o -name 'backup*.pem' -o -name 'recovery*.key' -o -name 'backup*.key' \) \) 2>/dev/null | head -n 5)"
    [ -z "${found}" ] || fail "üretim profili: /data altında çevrimdışı özel anahtar var; sunucu açılmıyor.
${found}
Bu dosyaları internete kapalı bir makineye taşıyıp buradan silin (README → \"Üretim profili\")."

    # 2. Demo kalıntısı: uçtan uca testlerin dışa aktardığı sunucu TLS özel anahtarı.
    [ ! -e /data/proxy ] || fail "üretim profili: /data/proxy duruyor (export-server-key.sh çıktısı: sunucunun TLS özel anahtarı, düz metin). Silin: rm -rf data/proxy"

    # 3. Test anahtarları ve kayıt modu.
    [ "${ALLOW_TEST_HOOKS:-}" != "true" ] || fail "üretim profili: ALLOW_TEST_HOOKS=true ile açılmaz."
    [ "${ALLOW_ANONYMOUS_ADMIN:-}" != "true" ] || fail "üretim profili: ALLOW_ANONYMOUS_ADMIN=true ile açılmaz."
    [ "${ENROLLMENT_MODE:-token}" = "token" ] || fail "üretim profili: ENROLLMENT_MODE=${ENROLLMENT_MODE} ile açılmaz (token olmalı)."
    [ -n "${API_KEY:-}" ] || fail "üretim profili: API_KEY boş."
    [ "${ALLOW_DEMO_SECRETS:-}" != "true" ] || fail "üretim profili: ALLOW_DEMO_SECRETS=true ile açılmaz (kaynak koddaki demo parolaları)."
    for required in KEYSTORE_PASSWORD VAULT_AT_REST_PASSWORD; do
        eval "value=\${${required}:-}"
        [ -n "${value}" ] || fail "üretim profili: ${required} boş (./scripts/setup.sh --production üretir)."
    done
    # Sunucudaki yerel imzalayıcı (CONFIG_SIGNERS boş ya da "local" içeriyor): anahtar
    # dosyası diskte şifreli olmalı.
    case ",$(printf '%s' "${CONFIG_SIGNERS:-local}" | tr -d ' ' | tr 'A-Z' 'a-z')," in
        *,local,*|*,local:*)
            [ -n "${SIGNING_KEY_PASSWORD:-}" ] || fail "üretim profili: SIGNING_KEY_PASSWORD boş; sunucudaki imza anahtarı diskte şifresiz kalırdı (./scripts/setup.sh --production üretir)." ;;
    esac

    # 4. Yönetişim ve donanım belgesi. docker-compose.production.yml bunları sabitler;
    #    compose dışından başlatılan bir container için burada da denetlenir.
    case "${PIN_CHANGE_APPROVALS:-}" in
        ''|*[!0-9]*) fail "üretim profili: PIN_CHANGE_APPROVALS='${PIN_CHANGE_APPROVALS:-}' ile açılmaz (en az 2: pin değişikliği ikinci bir yöneticinin onayını bekler)." ;;
    esac
    [ "${PIN_CHANGE_APPROVALS}" -ge 2 ] || fail "üretim profili: PIN_CHANGE_APPROVALS=${PIN_CHANGE_APPROVALS} ile açılmaz (en az 2 olmalı)."
    expect_value PIN_LIVE_CHECK enforce
    expect_value USER_AUTH_ATTESTATION enforce
    expect_value ENROLLMENT_ATTESTATION enforce
    expect_value ENROLLMENT_P12 off
    expect_value USER_AUTH_REQUIRE_PER_USE true
    expect_value HOST_CLIENT_CERT_REQUIRE_GRANT true
    expect_value CONFIG_API_ADMIN_ROUTES off
    expect_value ATTESTATION_KEY_POLICY enforce
    expect_value ATTESTATION_POLICY_DEFAULT production
    expect_value MOCK_HOST_REQUIRE_TOKEN true
    expect_value APP_ATTEST_REQUIRE_V2 true
    expect_value PLAY_INTEGRITY_REQUIRE_V2 true

    # 5. Kişisel yöneticiler: iki kişi onayı en az iki ayrı yönetici ister.
    admins="$(printf '%s' "${ADMIN_KEYS:-}" | tr ',' '\n')"
    if [ -n "${ADMIN_KEYS_FILE:-}" ]; then
        [ -r "${ADMIN_KEYS_FILE}" ] || fail "üretim profili: ADMIN_KEYS_FILE=${ADMIN_KEYS_FILE} okunamıyor."
        admins="${admins}
$(cat "${ADMIN_KEYS_FILE}")"
    fi
    admin_count="$(printf '%s\n' "${admins}" | sed -e 's/^[[:space:]]*//' -e '/^#/d' -e '/^$/d' | wc -l | tr -d ' ')"
    [ "${admin_count}" -ge 2 ] || fail "üretim profili: ${admin_count} kişisel yönetici var (ADMIN_KEYS); iki kişi onayı için en az iki gerekir (./scripts/setup.sh --production --admins ad1:sha256,ad2:sha256)."

    # 6. Kurtarma anahtarı: çalınan bir imza anahtarını bütün telefonlarda iptal etmenin tek yolu.
    [ -n "$(printf '%s' "${RECOVERY_PUBLIC_KEYS:-}" | tr -d ' ,')" ] || fail "üretim profili: RECOVERY_PUBLIC_KEYS boş; çalınan bir imza anahtarı iptal edilemezdi (./scripts/setup.sh --production --recovery-public-key …)."

    # 7. İmzalayıcılar: en az iki, en az biri sunucunun diskinde olmayan (pkcs11 ya da
    #    command). SoftHSM bir deneme aracıdır, anahtarı yine bu diskte tutar: sayılmaz.
    count_signers
    if [ "${signer_count}" -lt 2 ] || [ "${external_signers}" -lt 1 ]; then
        if [ "${SAMPLE_EVALUATION:-}" = "single-signer" ]; then
            echo "pinvault-entrypoint: !! BU KURULUM ÜRETİM DEĞİLDİR: ${signer_count} imzalayıcı, ${external_signers} tanesi sunucunun diski dışında (SAMPLE_EVALUATION=single-signer). Gerçek kullanıcıya açma." >&2
        else
            fail "üretim profili: CONFIG_SIGNERS='${CONFIG_SIGNERS:-local}' ile açılmaz: ${signer_count} imzalayıcı, ${external_signers} tanesi sunucunun diski dışında. En az iki imzalayıcı ve en az biri HSM (pkcs11, SoftHSM değil) ya da KMS (command) olmalı."
        fi
    fi

    # 8. Sunucu kaynağı sabit olmalı: dal ya da etiket adı zamanla başka bir kodu gösterir.
    if [ -z "${PINVAULT_SERVER_SRC:-}" ]; then
        printf '%s' "${PINVAULT_REF:-}" | grep -Eq '^[0-9a-f]{40}$' || fail "üretim profili: PINVAULT_REF='${PINVAULT_REF:-}' 40 haneli bir commit SHA'sı değil ve PINVAULT_SERVER_SRC boş. Dal ya da etiket adı zamanla başka bir kodu gösterebilir (./scripts/setup.sh --production --server-ref <commit SHA>)."
    fi

    # 9. Donanım belgesi iptal listesi: dosya yoksa sunucu zaten açılmaz; nedeni burada söylenir.
    if [ -n "${ATTESTATION_REVOKED_SERIALS_FILE:-}" ] && [ ! -f "${ATTESTATION_REVOKED_SERIALS_FILE}" ]; then
        fail "üretim profili: ATTESTATION_REVOKED_SERIALS_FILE=${ATTESTATION_REVOKED_SERIALS_FILE} yok. Google'ın iptal listesini indir: ./scripts/fetch-attestation-status.sh (README → \"Donanım belgesi iptal listesi\")."
    fi
}

# Ortam değişkeni tam olarak beklenen değerde mi (büyük/küçük harf ve boşluk önemsiz).
expect_value() { # $1 = ad, $2 = beklenen
    eval "actual=\${$1:-}"
    actual="$(printf '%s' "${actual}" | tr -d ' ' | tr 'A-Z' 'a-z')"
    [ "${actual}" = "$2" ] || fail "üretim profili: $1='${actual}' ile açılmaz ($2 olmalı; docker-compose.production.yml sabitler)."
}

# CONFIG_SIGNERS'taki imzalayıcı sayısı (signer_count) ve sunucunun diski dışında
# olanların sayısı (external_signers). Adlı pkcs11 imzalayıcısı (pkcs11:ad) kendi
# kitaplığını PKCS11_LIBRARY_<AD>'dan okur.
count_signers() {
    signer_count=0
    external_signers=0
    set -f
    old_ifs="${IFS}"
    IFS=','
    for spec in $(printf '%s' "${CONFIG_SIGNERS:-local}" | tr -d ' ' | tr 'A-Z' 'a-z'); do
        [ -n "${spec}" ] || continue
        signer_count=$((signer_count + 1))
        case "${spec%%:*}" in
            command) external_signers=$((external_signers + 1)) ;;
            pkcs11)
                library="${PKCS11_LIBRARY:-}"
                case "${spec}" in
                    *:*)
                        suffix="$(printf '%s' "${spec#*:}" | tr 'a-z' 'A-Z' | tr -c 'A-Z0-9' '_')"
                        eval "library=\${PKCS11_LIBRARY_${suffix}:-}" ;;
                esac
                case "$(printf '%s' "${library}" | tr 'A-Z' 'a-z')" in
                    *softhsm*) ;;
                    *) external_signers=$((external_signers + 1)) ;;
                esac
                ;;
        esac
    done
    IFS="${old_ifs}"
    set +f
}

# Sunucunun çalışacağı kullanıcı: imajdaki pinvault (10001) ya da PINVAULT_UID /
# PINVAULT_GID (Linux'ta data/'yı kendi kullanıcınla okumak için). root olamaz.
RUN_UID="${PINVAULT_UID:-10001}"
RUN_GID="${PINVAULT_GID:-${RUN_UID}}"
case "${RUN_UID}:${RUN_GID}" in
    *[!0-9:]*|:*|*:) fail "PINVAULT_UID / PINVAULT_GID sayı olmalı: ${RUN_UID}:${RUN_GID}" ;;
esac
[ "${RUN_UID}" != "0" ] && [ "${RUN_GID}" != "0" ] || fail "sunucu root olarak çalıştırılmaz (PINVAULT_UID / PINVAULT_GID 0 olamaz)."

if [ "${SAMPLE_PROFILE:-demo}" = "production" ]; then
    production_checks
fi

if [ "$(id -u)" = "0" ]; then
    chown -R "${RUN_UID}:${RUN_GID}" /data
    # Var olan dosyalar: grup ve diğerleri hiçbir şey okuyamasın.
    chmod -R go-rwx /data 2>/dev/null || true
    # Host'taki betiklerin okuduğu herkese açık pin dosyası (gizli değil).
    # Root olarak çalışıyoruz: sembolik bağlar izlenmez. /data ya da /data/certs
    # bir bağsa dokunulmaz; dosyalar `find -type f` ile seçilir (bağ değil, gerçek
    # dosya) ve chmod onları bulduğu yerde değiştirir. Yoksa /data altına konan
    # bir bağ, root'a container'daki başka bir dosyanın iznini açtırabilirdi.
    if [ -d /data/certs ] && [ ! -L /data ] && [ ! -L /data/certs ]; then
        chmod 711 /data /data/certs 2>/dev/null || true
        find /data/certs -maxdepth 1 -type f -name '*.pins' -exec chmod 644 {} + 2>/dev/null || true
    fi
    if [ "${RUN_UID}" = "10001" ] && [ "${RUN_GID}" = "10001" ]; then
        exec setpriv --reuid=pinvault --regid=pinvault --init-groups "$@"
    fi
    # İmajda adı olmayan bir kullanıcı: ek grup yok, HOME /data.
    export HOME=/data
    exec setpriv --reuid="${RUN_UID}" --regid="${RUN_GID}" --clear-groups "$@"
fi
exec "$@"
