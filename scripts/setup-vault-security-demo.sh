#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# VaultSecurityDemoActivity — tek seferde kurulum
#
# Bu script demo-server'da 3 vault dosyası yaratır, Mi 9T cihazı için
# token'lar üretir ve cihazın SharedPreferences'ına yazar. Sonrasında
# "Fetch All" butonuna basınca tüm satırların ✓ yeşil gelmesi beklenir.
#
# Kullanım:
#   ./scripts/setup-vault-security-demo.sh
#
# Env override (opsiyonel):
#   MANAGEMENT_URL=http://192.168.1.80:8090  # demo-server management
#   API_KEY=testkey                          # X-API-Key header
#   CONFIG_API=default-tls                   # scope
#   DEVICE_SERIAL=4360fdf2                   # adb -s ile kullanılacak cihaz
#   DEVICE_SUFFIX=mi-9t                      # activity'deki MODEL.lowercase()
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

MANAGEMENT_URL="${MANAGEMENT_URL:-http://192.168.1.80:8090}"
API_KEY="${API_KEY:-testkey}"
CONFIG_API="${CONFIG_API:-default-tls}"
DEVICE_SERIAL="${DEVICE_SERIAL:-4360fdf2}"
DEVICE_SUFFIX="${DEVICE_SUFFIX:-mi-9t}"
APP_PKG="com.example.pinvault.demo"
PREFS_NAME="vault_security_demo"

# Activity'deki key naming convention'ı birebir
KEY_PUBLIC="demo-public-v2-${DEVICE_SUFFIX}"
KEY_TOKEN="demo-token-v2-${DEVICE_SUFFIX}"
KEY_E2E="demo-e2e-v2-${DEVICE_SUFFIX}"

log()  { printf "\033[36m[%s]\033[0m %s\n" "$(date +%H:%M:%S)" "$*" >&2; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*" >&2; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

curl_mgmt() {
  curl -s -H "X-API-Key: $API_KEY" "$@"
}

# ── Pre-flight ───────────────────────────────────────────────────────

log "Ön-kontrol: demo-server ayakta mı?"
if ! curl_mgmt -o /dev/null -w "" "$MANAGEMENT_URL/api/v1/all-configs"; then
  fail "demo-server'a ulaşılamıyor: $MANAGEMENT_URL"
fi
ok "Management API erişilebilir"

log "Ön-kontrol: cihaz bağlı mı?"
if ! adb -s "$DEVICE_SERIAL" get-state >/dev/null 2>&1; then
  fail "Cihaz bulunamadı (serial=$DEVICE_SERIAL)"
fi
ok "Cihaz bağlı: $DEVICE_SERIAL"

DEVICE_ID=$(adb -s "$DEVICE_SERIAL" shell settings get secure android_id | tr -d '\r\n ')
if [[ -z "$DEVICE_ID" ]]; then fail "ANDROID_ID alınamadı"; fi
ok "ANDROID_ID: $DEVICE_ID"

# ── 1. Dosyaları yükle ──────────────────────────────────────────────

log "Adım 1/4 — Vault dosyalarını $CONFIG_API scope'una yükle"

VAULT_BASE="$MANAGEMENT_URL/api/v1/config-apis/$CONFIG_API/vault"

upload() {
  local key="$1" policy="$2" encryption="$3" payload="$4"
  local code
  code=$(printf '%s' "$payload" | curl_mgmt -X PUT --data-binary @- \
    "$VAULT_BASE/$key?policy=$policy&encryption=$encryption" \
    -o /dev/null -w "%{http_code}")
  if [[ "$code" == "200" ]]; then
    ok "$key  policy=$policy  encryption=$encryption  (${#payload} B)"
  else
    fail "$key upload HTTP $code"
  fi
}

upload "$KEY_PUBLIC" public     plain       '{"appVersion":"2.0.0","banner":"demo release"}'
upload "$KEY_TOKEN"  token      plain       '{"feature_flags":{"newCheckout":true,"darkMode":true}}'
upload "$KEY_E2E"    token      end_to_end  '{"model":"tflite-v3","size":"large","rotationKey":"abc123"}'

# ── 2. Cihazın RSA public key'i kayıtlı mı? ─────────────────────────
#
# E2E fetch için cihazın kendi RSA pub key'i server'a register olmuş olmalı.
# Activity init olurken bunu otomatik yapar. Yoksa kullanıcıya hatırlat.

log "Adım 2/4 — Cihazın RSA public key kaydını kontrol et"
pub_check=$(curl_mgmt "$MANAGEMENT_URL/api/v1/vault/devices/$DEVICE_ID/public-key?configApiId=$CONFIG_API" -o /dev/null -w "%{http_code}" 2>&1 || true)
if [[ "$pub_check" == "200" ]]; then
  ok "Device public key zaten kayıtlı"
else
  printf "  \033[33m!\033[0m Device public key henüz kayıtlı değil (HTTP %s).\n" "$pub_check"
  printf "    → Cihazda VaultSecurityDemoActivity'yi en az 1 kere aç ki\n"
  printf "      PinVault.init() RSA key'i üretip server'a register etsin.\n"
fi

# ── 3. Token'ları üret ─────────────────────────────────────────────

log "Adım 3/4 — Per-cihaz token üret (token + e2e dosyaları için)"

gen_token() {
  local key="$1"
  local resp
  resp=$(curl_mgmt -X POST -H "Content-Type: application/json" \
    -d "{\"deviceId\":\"$DEVICE_ID\"}" \
    "$VAULT_BASE/$key/tokens")
  local plaintext
  plaintext=$(printf '%s' "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)
  if [[ -z "$plaintext" ]]; then
    fail "$key için token parse edilemedi. Yanıt: $resp"
  fi
  ok "$key token üretildi (${#plaintext} karakter)"
  printf '%s' "$plaintext"
}

TOKEN_FOR_TOKEN_FILE=$(gen_token "$KEY_TOKEN")
TOKEN_FOR_E2E_FILE=$(gen_token "$KEY_E2E")

# ── 4. Token'ları cihazın SharedPreferences'ına yaz ────────────────

log "Adım 4/4 — Token'ları cihaza SharedPreferences üzerinden yaz"

# Önce uygulamanın çalışır halde olmadığından emin ol — yoksa write race.
adb -s "$DEVICE_SERIAL" shell "am force-stop $APP_PKG" >/dev/null 2>&1 || true

# Activity'deki tokenForKey() şu key'leri okuyor:
#   token_$keyToken  ve  token_$keyE2E
# Preferences XML'i doğrudan yazmak için run-as gerekiyor (debuggable build lazım).

PREFS_PATH="/data/data/$APP_PKG/shared_prefs/${PREFS_NAME}.xml"

xml_escape() {
  # SharedPreferences XML'inde plain text olarak yer alıyor.
  sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g' <<<"$1"
}

TK=$(xml_escape "$TOKEN_FOR_TOKEN_FILE")
EK=$(xml_escape "$TOKEN_FOR_E2E_FILE")

PREFS_XML="<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name=\"token_${KEY_TOKEN}\">${TK}</string>
    <string name=\"token_${KEY_E2E}\">${EK}</string>
</map>"

# /data/local/tmp'e yaz sonra run-as ile kopyala
TMP_PATH="/data/local/tmp/${PREFS_NAME}.xml"
echo "$PREFS_XML" | adb -s "$DEVICE_SERIAL" shell "cat > $TMP_PATH"

# shared_prefs klasörünü garantile ve dosyayı kopyala (debuggable app şart)
if adb -s "$DEVICE_SERIAL" shell "run-as $APP_PKG sh -c 'mkdir -p /data/data/$APP_PKG/shared_prefs && cp $TMP_PATH $PREFS_PATH && chmod 660 $PREFS_PATH'" 2>&1 | grep -qi "not debuggable\|unknown package"; then
  printf "\n  \033[33m!\033[0m run-as başarısız oldu (app debuggable değil mi?).\n"
  printf "    → Cihazda elle şu token'ları uygulamaya gir (Save Tokens):\n"
  printf "      %s için: %s\n" "$KEY_TOKEN" "$TOKEN_FOR_TOKEN_FILE"
  printf "      %s için: %s\n" "$KEY_E2E" "$TOKEN_FOR_E2E_FILE"
else
  ok "SharedPreferences yazıldı: $PREFS_PATH"
fi

adb -s "$DEVICE_SERIAL" shell rm -f "$TMP_PATH" >/dev/null 2>&1 || true

# ── Özet ────────────────────────────────────────────────────────────

printf '\n\033[32m══════════════════════════════════════════════════════════════\033[0m\n'
printf '\033[32m  Kurulum tamam\033[0m\n'
printf '\033[32m══════════════════════════════════════════════════════════════\033[0m\n\n'
printf "Server'da yüklenen dosyalar (%s scope):\n" "$CONFIG_API"
printf "  %-30s policy=public   encryption=plain\n"      "$KEY_PUBLIC"
printf "  %-30s policy=token    encryption=plain\n"      "$KEY_TOKEN"
printf "  %-30s policy=token    encryption=end_to_end\n" "$KEY_E2E"
printf "\nToken'lar (deviceId=%s):\n" "$DEVICE_ID"
printf "  → %s:  %s\n" "$KEY_TOKEN" "$TOKEN_FOR_TOKEN_FILE"
printf "  → %s:  %s\n" "$KEY_E2E"   "$TOKEN_FOR_E2E_FILE"
printf "\nCihaz hazır. Şimdi uygulamada:\n"
printf "  1. VaultSecurityDemoActivity'yi aç\n"
printf "  2. \"Fetch All\" butonuna bas\n"
printf "  3. 3 satırın da ✓ yeşil olmasını bekle\n\n"
