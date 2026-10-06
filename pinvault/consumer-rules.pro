# PinVault — ProGuard Consumer Rules

-keep class io.github.umutcansu.pinvault.PinVault { *; }
-keep class io.github.umutcansu.pinvault.model.** { *; }
-keep class io.github.umutcansu.pinvault.api.CertificateConfigApi { *; }
-keep,allowobfuscation interface io.github.umutcansu.pinvault.api.DynamicConfigService { *; }
-keepclassmembers class io.github.umutcansu.pinvault.model.** { <fields>; }

# Class names are NOT kept. Until 2.2.0 a `-keepnames class io.github.umutcansu.pinvault.**`
# rule kept them so that Timber's DebugTree could tag log lines with the
# calling class. The price was that every consumer's release APK carried the
# library's class names, so the two methods a hooking script needs to disable
# pinning (the trust manager's checkServerTrusted and the per-request
# interceptor's intercept) could be found by their source names in any app.
# Renaming is not protection — a determined attacker finds them anyway — but
# there is no reason to publish the map. In a minified app PinVault's log
# tags are the obfuscated class names; plant your own tree with a fixed tag
# or keep the names yourself with the rule above if you need them in logs.
