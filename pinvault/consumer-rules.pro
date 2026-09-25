# PinVault — ProGuard Consumer Rules

-keep class io.github.umutcansu.pinvault.PinVault { *; }
-keep class io.github.umutcansu.pinvault.model.** { *; }
-keep class io.github.umutcansu.pinvault.api.CertificateConfigApi { *; }
-keep,allowobfuscation interface io.github.umutcansu.pinvault.api.DynamicConfigService { *; }
-keepclassmembers class io.github.umutcansu.pinvault.model.** { <fields>; }

# Keep class names (members are still shrunk and renamed): Timber's DebugTree
# tags each line with the calling class, so a minified app would otherwise log
# "D/f: Pin verified ✓" instead of "D/DynamicSSLManager: ...". Costs a few
# kilobytes of class names; the library is open source, nothing is hidden.
-keepnames class io.github.umutcansu.pinvault.**
