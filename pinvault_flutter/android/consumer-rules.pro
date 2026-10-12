# pinvault_flutter — R8 rules for apps. The plugin class is registered by the
# generated GeneratedPluginRegistrant (no reflection); the PinVault library
# ships its own consumer rules. Found by the example's release build
# (example/scripts/release_check.sh), as in the React Native bridge.
#
# Tink (under the PinVault library's encrypted storage) references Error Prone's
# compile-time annotations, which no Flutter app has on its classpath; R8
# stops a release build on the missing classes otherwise.
-dontwarn com.google.errorprone.annotations.**
# PinVault's periodic updates use WorkManager, which opens its Room database by
# reflection (WorkDatabase_Impl's no-argument constructor); R8 full mode
# (AGP 9) can drop that constructor and the app dies at launch.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
