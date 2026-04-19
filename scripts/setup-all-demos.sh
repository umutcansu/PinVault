#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Demo app içindeki TÜM vault activity'leri için tek seferde kurulum
#
# Bu script demo-server'a:
#   VaultFileDemoActivity için 3 dosya (feature-flags, ml-model, remote-config)
#   VaultSecurityDemoActivity için 3 dosya (demo-public-v2, demo-token-v2, demo-e2e-v2)
# yükler. Token-protected olanlar için per-device token üretir ve cihazın
# SharedPreferences'ına yazar.
#
# Kullanım:
#   ./scripts/setup-all-demos.sh
#
# Env override (opsiyonel):
#   MANAGEMENT_URL=http://192.168.1.80:8090
#   API_KEY=testkey
#   CONFIG_API=default-tls
#   DEVICE_SERIAL=4360fdf2
#   DEVICE_SUFFIX=mi-9t          # activity'deki Build.MODEL.lowercase()
#   ONLY=security                # ya "file" ya "security" ya boş (ikisi)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

MANAGEMENT_URL="${MANAGEMENT_URL:-http://192.168.1.80:8090}"
API_KEY="${API_KEY:-testkey}"
CONFIG_API="${CONFIG_API:-default-tls}"
DEVICE_SERIAL="${DEVICE_SERIAL:-4360fdf2}"
DEVICE_SUFFIX="${DEVICE_SUFFIX:-mi-9t}"
ONLY="${ONLY:-}"
APP_PKG="com.example.pinvault.demo"
VAULT_BASE="$MANAGEMENT_URL/api/v1/config-apis/$CONFIG_API/vault"

log()  { printf "\033[36m[%s]\033[0m %s\n" "$(date +%H:%M:%S)" "$*" >&2; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*" >&2; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*" >&2; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

curl_mgmt() { curl -s -H "X-API-Key: $API_KEY" "$@"; }

# ── Ön-kontrol ──────────────────────────────────────────────────────

log "Ön-kontrol: demo-server ayakta mı?"
curl_mgmt -o /dev/null -w "" "$MANAGEMENT_URL/api/v1/all-configs" || fail "demo-server erişilmiyor: $MANAGEMENT_URL"
ok "Management API erişilebilir"

log "Ön-kontrol: cihaz bağlı mı?"
adb -s "$DEVICE_SERIAL" get-state >/dev/null 2>&1 || fail "Cihaz bulunamadı: $DEVICE_SERIAL"
ok "Cihaz bağlı: $DEVICE_SERIAL"

# NOT: adb shell'den gelen ANDROID_ID (shell user) uygulamanınkinden FARKLI (Android 8+).
# App'in ANDROID_ID'sini almak için uygulamayı bir kere açıp logcat'ten yakalıyoruz.
log "Ön-kontrol: uygulamanın gerçek ANDROID_ID'sini tespit et (app-scoped)"
adb -s "$DEVICE_SERIAL" shell am force-stop "$APP_PKG" >/dev/null 2>&1
adb -s "$DEVICE_SERIAL" logcat -c
adb -s "$DEVICE_SERIAL" shell am start -n "$APP_PKG/.MainActivity" >/dev/null 2>&1
# VaultSecurityDemoActivity'yi aç ki registerDevicePublicKey tetiklensin
sleep 2
adb -s "$DEVICE_SERIAL" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
adb -s "$DEVICE_SERIAL" pull /sdcard/ui.xml /tmp/_pv_ui.xml >/dev/null 2>&1
SEC_COORDS=$(python3 -c "
import re
try: xml = open('/tmp/_pv_ui.xml').read()
except: print(''); exit()
m = re.search(r'text=\"Vault Security \(V2\)\"[^>]*bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"', xml)
if m:
    print((int(m.group(1))+int(m.group(3)))//2, (int(m.group(2))+int(m.group(4)))//2)
")
if [[ -n "$SEC_COORDS" ]]; then
  adb -s "$DEVICE_SERIAL" shell input tap $SEC_COORDS >/dev/null 2>&1
fi

# Logcat'ten deviceId'yi yakala (registerDevicePublicKey log'undan)
for i in {1..15}; do
  DEVICE_ID=$(adb -s "$DEVICE_SERIAL" logcat -d | grep -oE "Registered device public key: [0-9a-f]+" | tail -1 | awk '{print $NF}')
  if [[ -n "$DEVICE_ID" ]]; then break; fi
  sleep 1
done
if [[ -z "$DEVICE_ID" ]]; then
  warn "Logcat'ten deviceId alınamadı, shell ANDROID_ID'ye düşüyor (app-scoped ID'den farklı olabilir)"
  DEVICE_ID=$(adb -s "$DEVICE_SERIAL" shell settings get secure android_id | tr -d '\r\n ')
fi
[[ -n "$DEVICE_ID" ]] || fail "deviceId tespit edilemedi"
ok "App ANDROID_ID: $DEVICE_ID"

# ── Yardımcı fonksiyonlar ───────────────────────────────────────────

upload() {
  local key="$1" policy="$2" encryption="$3" payload="$4"
  local code
  code=$(printf '%s' "$payload" | curl_mgmt -X PUT --data-binary @- \
    "$VAULT_BASE/$key?policy=$policy&encryption=$encryption" \
    -o /dev/null -w "%{http_code}")
  if [[ "$code" == "200" ]]; then
    ok "$key  policy=$policy  enc=$encryption  (${#payload} B)"
  else
    fail "$key upload HTTP $code"
  fi
}

gen_token() {
  local key="$1"
  local resp
  resp=$(curl_mgmt -X POST -H "Content-Type: application/json" \
    -d "{\"deviceId\":\"$DEVICE_ID\"}" "$VAULT_BASE/$key/tokens")
  local plaintext
  plaintext=$(printf '%s' "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)
  [[ -n "$plaintext" ]] || fail "$key token parse edilemedi: $resp"
  ok "$key token üretildi"
  printf '%s' "$plaintext"
}

# SharedPreferences XML'ini cihaza yaz
write_prefs() {
  local prefs_name="$1"
  shift
  # Kalan args: key1 val1 key2 val2 ...
  local entries=""
  while [[ $# -gt 0 ]]; do
    local k="$1" v="$2"
    shift 2
    # XML escape
    local ve
    ve=$(sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&apos;/g' <<<"$v")
    entries+="    <string name=\"$k\">$ve</string>\n"
  done

  local xml
  xml="<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n${entries}</map>"

  adb -s "$DEVICE_SERIAL" shell "am force-stop $APP_PKG" >/dev/null 2>&1 || true

  local tmp="/data/local/tmp/${prefs_name}.xml"
  local dst="/data/data/$APP_PKG/shared_prefs/${prefs_name}.xml"
  printf "%b" "$xml" | adb -s "$DEVICE_SERIAL" shell "cat > $tmp"

  local runas_out
  runas_out=$(adb -s "$DEVICE_SERIAL" shell "run-as $APP_PKG sh -c 'mkdir -p /data/data/$APP_PKG/shared_prefs && cp $tmp $dst && chmod 660 $dst' 2>&1" || true)
  adb -s "$DEVICE_SERIAL" shell rm -f "$tmp" >/dev/null 2>&1 || true

  if [[ -n "$runas_out" ]] && ! grep -qi "not debuggable\|unknown package" <<<"$runas_out"; then
    ok "SharedPreferences yazıldı: $dst"
    return 0
  elif [[ -z "$runas_out" ]]; then
    ok "SharedPreferences yazıldı: $dst"
    return 0
  else
    warn "run-as başarısız ($runas_out). App debuggable olmalı."
    return 1
  fi
}

# ── VaultFileDemoActivity: 3 dosya, tümü public (token gerektirmez) ──

setup_vault_file_demo() {
  log "VaultFileDemoActivity için 3 dosya yükleniyor (policy=public)"

  local K1="feature-flags-${DEVICE_SUFFIX}"
  local K2="ml-model-${DEVICE_SUFFIX}"
  local K3="remote-config-${DEVICE_SUFFIX}"

  upload "$K1" public plain '{"feature_flags":{"newCheckout":true,"darkMode":true,"betaApi":false}}'
  upload "$K2" public plain "$(python3 -c "import os,base64;print(base64.b64encode(os.urandom(256)).decode())")"
  upload "$K3" public plain '{"apiTimeout":30,"retryCount":3,"region":"eu-west-1"}'

  printf "\n\033[32m▶ VaultFileDemoActivity hazır\033[0m — \"Fetch Files\" butonuna bas, 3 satır da ✓ yeşil olmalı.\n\n"
}

# ── VaultSecurityDemoActivity: 3 dosya + token'lar ──────────────────

setup_vault_security_demo() {
  log "VaultSecurityDemoActivity için 3 dosya + token'lar"

  local K_PUB="demo-public-v2-${DEVICE_SUFFIX}"
  local K_TOK="demo-token-v2-${DEVICE_SUFFIX}"
  local K_E2E="demo-e2e-v2-${DEVICE_SUFFIX}"

  upload "$K_PUB" public plain      '{"appVersion":"2.0.0","banner":"demo release"}'
  upload "$K_TOK" token  plain      '{"feature_flags":{"newCheckout":true}}'
  upload "$K_E2E" token  end_to_end '{"model":"tflite-v3","rotationKey":"abc123"}'

  # Device public key kontrolü (e2e için şart)
  local pub_check
  pub_check=$(curl_mgmt "$MANAGEMENT_URL/api/v1/vault/devices/$DEVICE_ID/public-key?configApiId=$CONFIG_API" -o /dev/null -w "%{http_code}")
  if [[ "$pub_check" == "200" ]]; then
    ok "Device RSA public key kayıtlı"
  else
    warn "Device RSA public key yok (HTTP $pub_check). VaultSecurityDemoActivity'yi en az 1 kere aç, init register eder."
  fi

  # Token'lar
  local TOK_FOR_TOK TOK_FOR_E2E
  TOK_FOR_TOK=$(gen_token "$K_TOK")
  TOK_FOR_E2E=$(gen_token "$K_E2E")

  # Cihaza yaz
  write_prefs "vault_security_demo" \
    "token_${K_TOK}" "$TOK_FOR_TOK" \
    "token_${K_E2E}" "$TOK_FOR_E2E" || {
    printf "\n  \033[33m!\033[0m run-as başarısız. Elle gir:\n"
    printf "    %s  →  %s\n" "$K_TOK" "$TOK_FOR_TOK"
    printf "    %s  →  %s\n" "$K_E2E" "$TOK_FOR_E2E"
  }

  printf "\n\033[32m▶ VaultSecurityDemoActivity hazır\033[0m — \"Fetch All\", 3 satır ✓ yeşil.\n\n"
}

# ── Main ────────────────────────────────────────────────────────────

case "$ONLY" in
  file)     setup_vault_file_demo ;;
  security) setup_vault_security_demo ;;
  "")       setup_vault_file_demo; setup_vault_security_demo ;;
  *)        fail "ONLY env hatalı: '$ONLY'. Seçenekler: file / security / (boş)" ;;
esac

printf "\033[32m══════════════════════════════════════════════════════════════\033[0m\n"
printf "\033[32m  Kurulum tamam\033[0m\n"
printf "\033[32m══════════════════════════════════════════════════════════════\033[0m\n"
printf "Scope      : %s\n" "$CONFIG_API"
printf "Cihaz      : %s (ANDROID_ID=%s)\n" "$DEVICE_SERIAL" "$DEVICE_ID"
printf "Suffix     : %s\n" "$DEVICE_SUFFIX"
