#!/bin/sh
# Runs the Keychain / Secure Enclave tests of the mTLS identity inside an
# ad-hoc signed host app on a simulator (see project.yml for why).
#
#   sh pinvault-ios/Tests/IdentityKeychainHost/run-tests.sh <simulator udid> [derived data dir]
#
# Needs XcodeGen and the TLS fixtures (Tests/PinVaultTests/Fixtures/tls/generate.sh).
# The project is generated next to project.yml (XcodeGen resolves the local
# package relative to it) and removed again afterwards.
set -eu
UDID=${1:?usage: run-tests.sh <simulator udid> [derived data dir]}
HERE=$(cd "$(dirname "$0")" && pwd)
DERIVED=${2:-$HERE/.build}
PROJECT="$HERE/PinVaultIdentityKeychain.xcodeproj"
trap 'rm -rf "$PROJECT"' EXIT
xcodegen generate --quiet --spec "$HERE/project.yml" --project "$HERE"
xcodebuild test -project "$PROJECT" -scheme PinVaultIdentityKeychainTests \
  -destination "platform=iOS Simulator,id=$UDID" -derivedDataPath "$DERIVED"
