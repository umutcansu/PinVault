#!/bin/sh
# Xcode "Bundle React Native code and images" aşaması çağırır (with-environment.sh
# ile, NODE_BINARY .xcode.env / .xcode.env.local'dan). CONFIGURATION=Release ise
# gen-host-config.js demo değerlerini reddeder ve test kontrollerini pakete almaz.
set -e
"$NODE_BINARY" "$SRCROOT/../scripts/gen-host-config.js" --platform ios
