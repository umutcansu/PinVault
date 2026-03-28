# PinVault — ProGuard Consumer Rules

-keep class io.github.umutcansu.pinvault.PinVault { *; }
-keep class io.github.umutcansu.pinvault.model.** { *; }
-keep class io.github.umutcansu.pinvault.api.CertificateConfigApi { *; }
-keep,allowobfuscation interface io.github.umutcansu.pinvault.api.DynamicConfigService { *; }
-keepclassmembers class io.github.umutcansu.pinvault.model.** { <fields>; }
