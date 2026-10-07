#!/bin/sh
# Runs every test suite of the iOS library:
#   1. swift test                       — macOS, the pure-logic suites
#   2. xcodebuild test PinVault-Package — the same suites on an iOS simulator
#   3. IdentityKeychainHost             — Secure Enclave / Keychain identity tests in an app host
#   4. VaultKeychainHost                — Keychain device / screen-lock key tests in an app host
#
#   sh pinvault-ios/scripts/test.sh                 # 1 only
#   sh pinvault-ios/scripts/test.sh <simulator udid> # 1–4
#
# SwiftPM's test runner has no Keychain entitlement on the simulator
# (errSecMissingEntitlement): those tests skip in 1 and 2 and run in 3 and 4,
# which are ad-hoc signed app hosts. Needs Xcode and, for 3–4, XcodeGen.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
UDID=${1:-}
cd "$ROOT"

echo "== swift test (macOS)"
swift test

[ -n "$UDID" ] || { echo "No simulator given: skipped the simulator suites."; exit 0; }
xcrun simctl bootstatus "$UDID" -b >/dev/null

echo "== PinVault-Package on $UDID"
xcodebuild test -scheme PinVault-Package -destination "platform=iOS Simulator,id=$UDID" -quiet

echo "== IdentityKeychainHost on $UDID"
sh pinvault-ios/Tests/IdentityKeychainHost/run-tests.sh "$UDID"

echo "== VaultKeychainHost on $UDID"
HOST="$ROOT/pinvault-ios/Tests/VaultKeychainHost"
( cd "$HOST" && xcodegen generate --quiet )
trap 'rm -rf "$HOST/VaultKeychainHost.xcodeproj"' EXIT
xcodebuild test -project "$HOST/VaultKeychainHost.xcodeproj" -scheme VaultKeychainHost \
  -destination "platform=iOS Simulator,id=$UDID" -quiet
echo "All iOS library suites passed."
