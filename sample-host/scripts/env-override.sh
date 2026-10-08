#!/usr/bin/env bash
# Sunucu ortam değişkenlerini .env'e dokunmadan geçici olarak değiştirir ve
# container'ı yeni değerlerle yeniden oluşturur; "reset" ile .env değerlerine
# döner. Deneyler ve uçtan uca testler için (örn. kısa config süresi, açık
# kayıt modu, şifreli imzalama anahtarı).
#
#   ./scripts/env-override.sh set CONFIG_TTL_SECONDS=60 ENROLLMENT_MODE=open
#   ./scripts/env-override.sh set SIGNING_KEY_PASSWORD=gizli
#   ./scripts/env-override.sh reset
#
# Compose, kabuk ortamındaki değişkeni .env'dekine tercih eder; bu betik
# değişkenleri dışa aktarıp `docker compose up -d` çalıştırır. Sağlık ucu
# yanıt verene kadar bekler.
#
# Geçici değer container yeniden oluşturulana kadar KALIR: işin bitince mutlaka
# `reset` çalıştır (yarıda kalan bir test koşusu açık kayıt modunu ya da test
# kancalarını açık bırakabilir).
#
# ÜRETİM PROFİLİNDE ÇALIŞMAZ: üretimde ayar değişikliği .env'de yapılır (kalıcı,
# gözden geçirilebilir) ve `docker compose up -d` ile uygulanır. Test anahtarları
# (ALLOW_TEST_HOOKS, ALLOW_ANONYMOUS_ADMIN) üretimde hiçbir yoldan açılamaz.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

usage() {
    echo "Kullanım: $0 set KEY=VALUE [KEY=VALUE ...] | reset" >&2
    exit 2
}

[ $# -ge 1 ] || usage
cmd="$1"; shift

if [ "$(sed -n 's/^SAMPLE_PROFILE=//p' .env 2>/dev/null | tail -1)" = "production" ]; then
    cat >&2 <<'EOF'
Üretim profili: geçici ayar değişikliği yapılmaz.
Ayarı .env'de değiştir ve uygula:  docker compose up -d
(ALLOW_TEST_HOOKS ve ALLOW_ANONYMOUS_ADMIN üretimde açılamaz.)
EOF
    exit 2
fi

case "${cmd}" in
    set)
        [ $# -ge 1 ] || usage
        for kv in "$@"; do
            case "${kv}" in
                *=*) export "${kv}" ;;
                *) echo "Geçersiz: ${kv} (KEY=VALUE bekleniyor)" >&2; exit 2 ;;
            esac
        done
        ;;
    reset)
        # Kabukta dışa aktarılmış olabilecek geçici değerleri temizle; .env geçerli olsun.
        for key in CONFIG_TTL_SECONDS ENROLLMENT_MODE SIGNING_KEY_PASSWORD ENROLLMENT_TOKEN_TTL_SECONDS \
                   ALLOW_TEST_HOOKS ENROLLMENT_REQUEST_TTL_HOURS OPEN_ENROLLMENT_RATE_LIMIT OPEN_ENROLLMENT_MAX_PENDING CLIENT_CERT_TTL_DAYS \
                   USER_AUTH_ATTESTATION ATTESTATION_PACKAGE_NAMES ATTESTATION_SIGNER_SHA256 ATTESTATION_REQUIRE_VERIFIED_BOOT \
                   ATTESTATION_REVOKED_SERIALS_FILE ATTESTATION_STATUS_MAX_AGE_HOURS ATTESTATION_MIN_PATCH_LEVEL ENROLLMENT_ATTESTATION ENROLLMENT_P12 USER_AUTH_REQUIRE_PER_USE \
                   ATTESTATION_ENABLED ATTESTATION_KEY_POLICY ATTESTATION_POLICY_DEFAULT ATTESTATION_TOKEN_TTL_SECONDS ATTESTATION_INTERVAL_SECONDS \
                   ATTESTATION_NONCE_TTL_SECONDS ATTESTATION_REVEAL_REASONS ATTESTATION_RATE_LIMIT ATTESTATION_DEVICE_RATE_LIMIT MOCK_HOST_REQUIRE_TOKEN \
                   ATTESTATION_DEVICE_LIMIT ATTESTATION_TRUSTED_BOOT_KEYS PINVAULT_TOKEN_REQUIRE_CERT_BINDING APP_ATTEST_REQUIRE_V2 \
                   PLAY_INTEGRITY_STALE_PASS_SECONDS PLAY_INTEGRITY_REQUIRE_V2 PLAY_INTEGRITY_REQUIRE_LICENSED \
                   DEVICE_REFUSAL_RATE_LIMIT REPORT_RATE_LIMIT REPORT_DEVICE_RATE_LIMIT DEVICE_KEY_RATE_LIMIT DEVICE_KEY_LIMIT \
                   VAULT_MAX_FILE_BYTES MTLS_RESTART_MIN_INTERVAL_SECONDS \
                   VAULT_AT_REST_PASSWORD VAULT_AT_REST_PASSWORD_PREVIOUS CERT_EXPIRY_WARN_DAYS KEYSTORE_PASSWORD KEYSTORE_PASSWORD_PREVIOUS CLIENT_P12_PASSWORD ALLOW_ANONYMOUS_ADMIN \
                   CONFIG_SIGNERS CONFIG_SIGNATURE_CACHE PKCS11_LIBRARY PKCS11_SLOT_INDEX PKCS11_PIN \
                   PKCS11_KEY_LABEL PKCS11_GENERATE_KEY SIGNER_COMMAND SIGNER_PUBLIC_KEY SIGNER_PUBLIC_KEY_FILE \
                   SIGNER_INPUT SIGNER_TIMEOUT_MS RECOVERY_PUBLIC_KEYS RECOVERY_REQUIRED_SIGNATURES ADMIN_KEYS \
                   ADMIN_KEYS_FILE PIN_CHANGE_APPROVALS APPROVAL_TTL_HOURS NOTIFY_WEBHOOK_URL NOTIFY_WEBHOOK_SECRET \
                   NOTIFY_EVENTS PIN_LIVE_CHECK PIN_LIVE_CHECK_ALLOW_OVERRIDE LIVE_CHECK_HOST_MAP LIVE_CHECK_TIMEOUT_MS \
                   ALLOW_DEMO_SECRETS FETCH_ALLOW_PRIVATE_TARGETS MANAGEMENT_BIND MANAGEMENT_ALLOWED_HOSTS ADMIN_ALLOWED_ORIGINS \
                   ADMIN_UPLOAD_MAX_BYTES APPROVAL_EXEMPT_OPERATIONS SIGNER_PASS_ENV PINVAULT_UID PINVAULT_GID; do
            unset "${key}"
        done
        ;;
    *) usage ;;
esac

docker compose up -d --no-build >/dev/null

HTTP_PORT="$(sed -n 's/^HOST_HTTP_PORT=//p' .env 2>/dev/null | tail -1)"
HTTP="http://localhost:${HTTP_PORT:-6650}"
for _ in $(seq 1 60); do
    if curl -fsS "${HTTP}/health" >/dev/null 2>&1; then
        echo "Host hazır: ${HTTP} (${cmd})"
        exit 0
    fi
    sleep 1
done
echo "Host 60 saniyede ayağa kalkmadı: docker compose logs pinvault-host" >&2
exit 1
