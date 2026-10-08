#!/bin/sh
# Makes the throwaway test keys of the iOS library's tests. They are not in the
# repository (the key-material safety net of .gitignore): every checkout makes
# its own.
#   - Tests/PinVaultTests/Fixtures/tls/   chains and PKCS#12 bundles for the in-process TLS servers
#   - Tests/PinVaultTests/Fixtures/vault/ an RSA key made by the iOS provider and the envelopes
#                                         the demo server wraps for it (cross-check)
#
#   sh pinvault-ios/scripts/generate-test-keys.sh              # make what is missing
#   sh pinvault-ios/scripts/generate-test-keys.sh --force      # make everything again
#
# Needs openssl (LibreSSL 3.3+ or OpenSSL 3), Swift, and JDK 17 for the server side.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FIX="$ROOT/pinvault-ios/Tests/PinVaultTests/Fixtures"
FORCE=${1:-}

if [ "$FORCE" = "--force" ] || [ ! -f "$FIX/tls/server.p12" ]; then
    echo "== TLS test keys"
    sh "$FIX/tls/generate.sh"
fi

if [ "$FORCE" = "--force" ] || [ ! -f "$FIX/vault/server-user-auth.envelope.bin" ]; then
    echo "== vault cross-check key (Swift) and envelopes (demo server)"
    mkdir -p "$FIX/vault"
    ( cd "$ROOT" && PINVAULT_WRITE_IOS_FIXTURES=1 swift test --filter DeviceKeyServerCrossCheckTests/testWriteTheCrossCheckKey )
    if [ -z "${JAVA_HOME:-}" ] && [ -d "$HOME/Library/Java/JavaVirtualMachines/jbr-17.0.14/Contents/Home" ]; then
        JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/jbr-17.0.14/Contents/Home"; export JAVA_HOME
    fi
    ( cd "$ROOT/demo-server" && PINVAULT_WRITE_IOS_FIXTURES=1 ../gradlew test -q --tests '*IosDeviceKeyCrossCheckTest*' )
fi
echo "Test keys ready."
