#!/bin/sh
# Runs the screen-lock vault test on an Android emulator (API 30+): puts a
# temporary PIN on it, types the PIN when the unlock prompt shows, and removes
# the PIN afterwards (a PIN left on the emulator breaks the Espresso runs).
#
#   scripts/screen_lock_check.sh [serial] [flutter test args…]
set -eu
cd "$(dirname "$0")/.."
serial=${1:-emulator-5556}; [ $# -gt 0 ] && shift
pin=1234
sh_() { adb -s "$serial" shell "$@"; }

stay=$(sh_ settings get global stay_on_while_plugged_in | tr -d '\r')
sh_ svc power stayon true; sh_ input keyevent KEYCODE_WAKEUP
if ! sh_ locksettings verify 2>&1 | grep -qi 'verified successfully'; then
  echo "the emulator already has a screen lock: not touching it" >&2; exit 2
fi
sh_ locksettings set-pin $pin >/dev/null
cleanup() {
  kill "$helper" 2>/dev/null || true
  sh_ locksettings clear --old $pin >/dev/null 2>&1 || true
  if [ -n "$stay" ] && [ "$stay" != null ]; then sh_ settings put global stay_on_while_plugged_in "$stay"; else sh_ svc power stayon false; fi
}
trap cleanup EXIT

# Types the PIN into the system's credential screen whenever it is up.
(
  while :; do
    ui=$(sh_ 'uiautomator dump /sdcard/pv-ui.xml >/dev/null 2>&1; cat /sdcard/pv-ui.xml' 2>/dev/null || true)
    field=$(printf '%s' "$ui" | grep -oE 'resource-id="[^"]*(lockPassword|password_entry|pinEntry)"[^>]*bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | head -1 || true)
    if [ -n "$field" ]; then
      set -- $(printf '%s' "$field" | sed 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/')
      sh_ input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 )); sleep 0.4
      sh_ input text $pin; sh_ input keyevent KEYCODE_ENTER
      sleep 3
    fi
    sleep 1
  done
) &
helper=$!

key=$(curl -sf http://localhost:8090/api/v1/signing-key | python3 -c 'import json,sys; print(json.load(sys.stdin)["publicKey"])')
flutter test integration_test/demo_server_test.dart -d "$serial" --plain-name 'screen-lock vault file' \
  --dart-define=PINVAULT_SIGNING_KEY="$key" --dart-define=PINVAULT_SCREEN_LOCK_PIN=$pin "$@"
