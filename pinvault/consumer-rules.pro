# PinVault — ProGuard Consumer Rules
#
# The library is shipped unminified and the app's R8 sees all of it, so
# nothing the app calls needs a keep rule. Only what is reached by
# reflection is kept: the JSON wire types Gson reads and writes, and the
# Retrofit service. Everything else — PinVault, the configuration types,
# the trust manager, the integrity probes — may be renamed and shrunk.
#
# Until 2.3.2 these rules kept `PinVault { *; }` and every member of
# `model.**`. That kept internal members and configuration fields under
# their source names (allowUnsigned, environmentGuard, …), a ready map for
# a hooking script. Renaming is not protection, but there is no reason to
# publish the map. A Gson type added later must be listed here.

# Gson: field names are the wire names; class names may change.
-keepattributes Signature, *Annotation*, InnerClasses, EnclosingMethod
-keep,allowobfuscation class io.github.umutcansu.pinvault.model.CertificateConfig
-keep,allowobfuscation class io.github.umutcansu.pinvault.model.HostPin
-keep,allowobfuscation class io.github.umutcansu.pinvault.model.SignedConfigResponse
-keep,allowobfuscation class io.github.umutcansu.pinvault.model.SignatureEntry
-keep,allowobfuscation class io.github.umutcansu.pinvault.model.SignedKeySet
-keep,allowobfuscation class io.github.umutcansu.pinvault.model.SigningKeySetPayload
-keepclassmembers class io.github.umutcansu.pinvault.model.CertificateConfig { <fields>; <init>(...); }
-keepclassmembers class io.github.umutcansu.pinvault.model.HostPin { <fields>; <init>(...); }
-keepclassmembers class io.github.umutcansu.pinvault.model.SignedConfigResponse { <fields>; <init>(...); }
-keepclassmembers class io.github.umutcansu.pinvault.model.SignatureEntry { <fields>; <init>(...); }
-keepclassmembers class io.github.umutcansu.pinvault.model.SignedKeySet { <fields>; <init>(...); }
-keepclassmembers class io.github.umutcansu.pinvault.model.SigningKeySetPayload { <fields>; <init>(...); }

# Retrofit builds the service by reflection; its own rules keep the
# annotations and return types of annotated methods.
-keep,allowobfuscation interface io.github.umutcansu.pinvault.api.DynamicConfigService { *; }
