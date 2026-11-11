package io.github.umutcansu.pinvault.reactnative

/**
 * What a release build lets JS decide, for every key [ConfigParser.parse]
 * reads (review 2026-11-12). A key the parser reads must be listed here
 * (`ConfigFieldPolicyTest` fails otherwise), so adding one forces the
 * decision instead of leaving the new field JS's by default.
 *
 * The same table holds for the Flutter bridge (`pinvault_flutter`, Android
 * and iOS) and the RN iOS side; their tests compare against the same paths.
 */
internal object ConfigFieldPolicy {

    enum class Policy {
        /**
         * A trust anchor, a relaxation, or where the device's token and
         * identity go: with a native security file a release build takes it
         * from the file only (JS may repeat it); a relaxation is refused from
         * JS without one.
         */
        NATIVE,
        /** A protection: JS may only make it stricter; the file's value is the floor (or the cap). */
        TIGHTEN,
        /** Shaped by a rule that keeps it harmless whoever sets it (a relative path, a declared id, a signed view). */
        CHECKED,
        /** Operational: no effect on what the device trusts or who gets its credentials. */
        FREE,
    }

    private const val API = "config.configApis[]"
    private const val VAULT = "config.vaultFiles[]"
    private const val STATIC = "config.staticPins"

    val POLICY: Map<String, Policy> = buildMap {
        fun put(policy: Policy, vararg keys: String) = keys.forEach { put(it, policy) }

        // Containers: what they hold is classified below.
        put(Policy.FREE, "config.configApis", "config.vaultFiles", "config.android", "config.ios", "config.environmentGuard")

        // ── Config API blocks ────────────────────────────────────────────
        put(Policy.NATIVE,
            "$API.url", "$API.enrollmentUrl", "$API.renewalUrl", "$API.tokenHosts", "$API.clientCertHosts",
            "$API.bootstrapPins", "$API.bootstrapPins[].hostname", "$API.bootstrapPins[].sha256", "$API.bootstrapPins[].version",
            "$API.bootstrapPins[].forceUpdate", "$API.bootstrapPins[].mtls", "$API.bootstrapPins[].clientCertVersion",
            "$API.signaturePublicKey", "$API.signaturePublicKeys", "$API.requiredSignatures",
            "$API.recoveryPublicKeys", "$API.requiredRecoverySignatures", "$API.serverScope", "$API.clientCaPins",
            "$API.allowUnsigned", "$API.allowUnpinnedConfigApi", "$API.allowServerGeneratedKey",
            // An unhealthy answer rolls every new config back: the path is the file's in a release build.
            "$API.healthEndpoint")
        put(Policy.TIGHTEN,
            // On from JS, or forced on by the file; never off against it.
            "$API.attestation", "$API.proofOfPossession",
            // Lowered by JS only; the file (or the library's 825 days) is the cap in a release build.
            "$API.maxClientCertLifetimeDays")
        put(Policy.CHECKED,
            // Must be a block the native file declares.
            "$API.id",
            // Relative paths under the block's pinned URL, never absolute.
            "$API.configEndpoint", "$API.enrollmentEndpoint", "$API.clientCertEndpoint", "$API.vaultReportEndpoint",
            // The server signs the view it answers; the library refuses a view of another request.
            "$API.wantPinsFor")
        put(Policy.FREE,
            "$API.clientCertLabel", "$API.clientCertRenewalThreshold", "$API.disableClientCertRenewal",
            "$API.attestationInterval", "$API.attestationInterval.amount", "$API.attestationInterval.unit")

        // ── Vault files ──────────────────────────────────────────────────
        // Release with a native file: only files its vaultFiles section declares, which fixes these.
        put(Policy.NATIVE, "$VAULT.signaturePublicKey", "$VAULT.encryption", "$VAULT.userAuth")
        put(Policy.TIGHTEN, "$VAULT.maxOfflineAge", "$VAULT.maxOfflineAge.amount", "$VAULT.maxOfflineAge.unit", "$VAULT.wipeWhenStale")
        // A declared key; a relative endpoint without `..`; a declared Config API.
        put(Policy.CHECKED, "$VAULT.key", "$VAULT.endpoint", "$VAULT.configApi")
        // Where the copy is kept and when it is fetched; the server decides who may download it.
        put(Policy.FREE, "$VAULT.storage", "$VAULT.updateWithPins", "$VAULT.accessPolicy")

        // ── Static pins (declared in the native file or refused) ─────────
        put(Policy.NATIVE, STATIC, "$STATIC.version", "$STATIC.forceUpdate", "$STATIC.pins",
            "$STATIC.pins[].hostname", "$STATIC.pins[].sha256", "$STATIC.pins[].version",
            "$STATIC.pins[].forceUpdate", "$STATIC.pins[].mtls", "$STATIC.pins[].clientCertVersion")

        // ── Config-wide ──────────────────────────────────────────────────
        put(Policy.NATIVE,
            // Widens trust to hosts without a pin entry.
            "config.managedTrustRoots",
            // Taking RN's own networking out of pinning, and a weaker key where the ROM refuses the flag.
            "config.android.pinGlobalNetworking", "config.requirePinnedReactNativeNetworking",
            "config.android.requireUnlockedDeviceAllowFallback")
        put(Policy.TIGHTEN,
            // Fixed where the file names it; without it, JS adding one only adds a check.
            "config.expectedSignerSha256",
            "config.requireUnlockedDevice", "config.requireHardwareBackedKeys", "config.requireCaTrust",
            "config.wipeVaultFilesOnRevocation",
            "config.expiredConfigGrace", "config.expiredConfigGrace.amount", "config.expiredConfigGrace.unit",
            "config.vaultFileMaxOfflineAge", "config.vaultFileMaxOfflineAge.amount", "config.vaultFileMaxOfflineAge.unit")
        put(Policy.FREE,
            "config.deviceAlias", "config.maxRetryCount", "config.updateIntervalHours", "config.updateIntervalMinutes",
            // A JS signal by nature: what the app's own checks say.
            "config.environmentGuard.timeoutMs",
            // Storage choices for RN's own fetch (cache and cookie jar on disk): not trust.
            "config.android.keepReactNativeHttpCache", "config.android.keepReactNativeCookies")
    }
}
