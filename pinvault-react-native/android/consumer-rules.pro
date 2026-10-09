# @umutcansu/react-native-pinvault — R8 rules for apps.
# The TurboModule is looked up by the generated code (no reflection); the
# PinVault library ships its own consumer rules. Keep the module and package
# names readable in crash reports only.
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultPackage { *; }
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultModule { *; }
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultNetworking { public *; }
-keep class io.github.umutcansu.pinvault.reactnative.PinVaultNetworkingInitializer { <init>(); }
# PinVaultNetworking.status() reads React Native's two networking hooks by name
# to detect another library replacing them.
-keepclassmembers class com.facebook.react.modules.network.OkHttpClientProvider {
    private static com.facebook.react.modules.network.OkHttpClientFactory factory;
}
-keepclassmembers class com.facebook.react.modules.network.NetworkingModule {
    private static com.facebook.react.modules.network.CustomClientBuilder customClientBuilder;
}
-keepclassmembers class com.facebook.react.modules.websocket.WebSocketModule {
    private static com.facebook.react.modules.network.CustomClientBuilder customClientBuilder;
}
# Tink (under the PinVault library's encrypted storage) references Error Prone's
# compile-time annotations, which no React Native app has on its classpath; R8
# stops a release build on the missing classes otherwise.
-dontwarn com.google.errorprone.annotations.**
# PinVault's periodic updates use WorkManager, which opens its Room database by
# reflection (WorkDatabase_Impl's no-argument constructor). In a React Native
# 0.87 release build (AGP 9, R8 full mode) R8 dropped that constructor and the
# app died at launch in androidx.startup's InitializationProvider.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
