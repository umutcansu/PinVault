#!/bin/sh
# Xcode "Bundle React Native code and images" aşaması çağırır (with-environment.sh
# ile, NODE_BINARY .xcode.env / .xcode.env.local'dan). CONFIGURATION=Release ise
# gen-host-config.js demo değerlerini reddeder, test kontrollerini pakete almaz
# ve eklentinin yerel güvenlik dosyasını (pinvault_security.json) uygulama
# paketine yazar; imzalama bu aşamadan sonra geldiği için dosya imzanın içindedir.
set -e
case "$CONFIGURATION" in
  [Rr]elease)
    "$NODE_BINARY" "$SRCROOT/../scripts/gen-host-config.js" --platform ios \
      --native-out "$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH"
    ;;
  *)
    "$NODE_BINARY" "$SRCROOT/../scripts/gen-host-config.js" --platform ios
    ;;
esac
