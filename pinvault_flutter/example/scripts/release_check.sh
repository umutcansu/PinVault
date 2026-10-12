#!/bin/sh
# Builds the example in release mode with a native security file for the
# local demo-server, runs integration_test/release_check.dart on an Android
# device, and prints its results. The security file is removed afterwards.
#
#   scripts/release_check.sh [device-serial]     (default: emulator-5554)
set -eu
cd "$(dirname "$0")/.."
serial=${1:-emulator-5554}
host=10.0.2.2
key=$(curl -sf http://localhost:8090/api/v1/signing-key | python3 -c 'import json,sys; print(json.load(sys.stdin)["publicKey"])')
assets=android/app/src/main/assets
file=$assets/pinvault_security.json
mkdir -p "$assets"
trap 'rm -f "$file"; rmdir "$assets" 2>/dev/null || true' EXIT
pins="[{\"hostname\":\"$host\",\"sha256\":[\"ziA0hyMDbayVXZ0g8AkkJz+wmKPZYjMAwb+GdNg5HYM=\",\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]},{\"hostname\":\"$host:8093\",\"sha256\":[\"WnVy/WigjwYatqBdJv6lM32kkpxMxYXwzgdlyrvVrTU=\",\"TOZS0AAIaxwCKUEIKWb3X/4h0S27clD6Aijou32QiQo=\"]}]"
cat > "$file" <<JSON
{"configApis": [
  {"id": "default-tls", "url": "https://$host:8091/", "bootstrapPins": $pins,
   "signaturePublicKeys": ["$key"], "serverScope": "default-tls"},
  {"id": "unsigned-tls", "url": "https://$host:8091/", "bootstrapPins": $pins,
   "allowUnsigned": true}
]}
JSON
flutter build apk --release -t integration_test/release_check.dart --dart-define=PINVAULT_HOST=$host
adb -s "$serial" install -r build/app/outputs/flutter-apk/app-release.apk >/dev/null
adb -s "$serial" shell pm clear com.example.example >/dev/null
adb -s "$serial" logcat -c
adb -s "$serial" shell am start -n com.example.example/.MainActivity >/dev/null
for _ in $(seq 1 60); do
  if adb -s "$serial" logcat -d -s flutter | grep -q 'PVRC DONE'; then break; fi
  sleep 1
done
adb -s "$serial" logcat -d -s flutter | grep 'PVRC' | sed 's/^.*PVRC/PVRC/'
# Exit 0 only when every check passed.
adb -s "$serial" logcat -d -s flutter | awk '/PVRC DONE/ { split($NF, n, "/"); ok = (n[1] == n[2]) } END { exit !ok }'
