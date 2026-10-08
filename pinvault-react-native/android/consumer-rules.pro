# @umutcansu/react-native-pinvault — R8 rules for apps.
# The TurboModule is looked up by the generated code (no reflection); the
# PinVault library ships its own consumer rules. Keep the module and package
# names readable in crash reports only.
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultPackage { *; }
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultModule { *; }
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultNetworking { public *; }
