// What a release build lets Dart decide, for every key `ConfigParser.parse`
// reads (review 2026-11-12; the Swift twin of the RN Android bridge's
// ConfigFieldPolicy.kt). A key the parser reads must be listed here
// (`ConfigFieldPolicyTests` fails otherwise), so adding one forces the
// decision instead of leaving the new field Dart's by default.
//
// The paths differ from Android's where the platforms do: no React Native
// networking keys, and the iOS-only settings live under `config.ios`
// (`config.android` is read only as a container here).
import Foundation

public enum ConfigFieldPolicy {

    public enum Policy: String {
        /// A trust anchor, a relaxation, or where the device's token, identity and
        /// connections go: with a native security file a release build takes it from
        /// the file only (Dart may repeat it); a relaxation is refused from Dart without one.
        case native = "NATIVE"
        /// A protection: Dart may only make it stricter; the file's value is the floor (or the cap).
        case tighten = "TIGHTEN"
        /// Shaped by a rule that keeps it harmless whoever sets it (a relative path, a declared id, a signed view).
        case checked = "CHECKED"
        /// Operational: no effect on what the device trusts or who gets its credentials.
        case free = "FREE"
    }

    private static let api = "config.configApis[]"
    private static let vault = "config.vaultFiles[]"
    private static let staticPins = "config.staticPins"

    public static let policy: [String: Policy] = {
        var map: [String: Policy] = [:]
        func put(_ policy: Policy, _ keys: String...) {
            for k in keys {
                precondition(map[k] == nil, "ConfigFieldPolicy: '\(k)' classified twice")
                map[k] = policy
            }
        }

        // Containers: what they hold is classified below.
        put(.free, "config.configApis", "config.vaultFiles", "config.android", "config.ios", "config.environmentGuard")

        // ── Config API blocks ────────────────────────────────────────────
        put(.native,
            "\(api).url", "\(api).enrollmentUrl", "\(api).renewalUrl", "\(api).tokenHosts", "\(api).clientCertHosts",
            "\(api).bootstrapPins", "\(api).bootstrapPins[].hostname", "\(api).bootstrapPins[].sha256", "\(api).bootstrapPins[].version",
            "\(api).bootstrapPins[].forceUpdate", "\(api).bootstrapPins[].mtls", "\(api).bootstrapPins[].clientCertVersion",
            "\(api).signaturePublicKey", "\(api).signaturePublicKeys", "\(api).requiredSignatures",
            "\(api).recoveryPublicKeys", "\(api).requiredRecoverySignatures", "\(api).serverScope", "\(api).clientCaPins",
            "\(api).allowUnsigned", "\(api).allowUnpinnedConfigApi", "\(api).allowServerGeneratedKey",
            // An unhealthy answer rolls every new config back: the path is the file's in a release build.
            "\(api).healthEndpoint")
        put(.tighten,
            // On from Dart, or forced on by the file; never off against it.
            "\(api).attestation", "\(api).proofOfPossession",
            // Lowered by Dart only; the file (or the library's 825 days) is the cap in a release build.
            "\(api).maxClientCertLifetimeDays")
        put(.checked,
            // Must be a block the native file declares.
            "\(api).id",
            // Relative paths under the block's pinned URL, never absolute.
            "\(api).configEndpoint", "\(api).enrollmentEndpoint", "\(api).clientCertEndpoint", "\(api).vaultReportEndpoint",
            // The server signs the view it answers; the library refuses a view of another request.
            "\(api).wantPinsFor")
        put(.free,
            "\(api).clientCertLabel", "\(api).clientCertRenewalThreshold", "\(api).disableClientCertRenewal",
            "\(api).attestationInterval", "\(api).attestationInterval.amount", "\(api).attestationInterval.unit")

        // ── Vault files ──────────────────────────────────────────────────
        // Release with a native file: only files its vaultFiles section declares, which fixes these.
        put(.native, "\(vault).signaturePublicKey", "\(vault).encryption", "\(vault).userAuth")
        put(.tighten, "\(vault).maxOfflineAge", "\(vault).maxOfflineAge.amount", "\(vault).maxOfflineAge.unit", "\(vault).wipeWhenStale")
        // A declared key; a relative endpoint without `..`; a declared Config API.
        put(.checked, "\(vault).key", "\(vault).endpoint", "\(vault).configApi")
        // Where the copy is kept and when it is fetched; the server decides who may download it.
        put(.free, "\(vault).storage", "\(vault).updateWithPins", "\(vault).accessPolicy")

        // ── Static pins (declared in the native file or refused) ─────────
        put(.native, staticPins, "\(staticPins).version", "\(staticPins).forceUpdate", "\(staticPins).pins",
            "\(staticPins).pins[].hostname", "\(staticPins).pins[].sha256", "\(staticPins).pins[].version",
            "\(staticPins).pins[].forceUpdate", "\(staticPins).pins[].mtls", "\(staticPins).pins[].clientCertVersion")

        // ── Config-wide ──────────────────────────────────────────────────
        put(.native,
            // Widens trust to hosts without a pin entry.
            "config.managedTrustRoots",
            // Where a pinned host's TCP connection goes.
            "config.ios.resolve",
            // A weaker key where the unlocked-only flag cannot be had.
            "config.ios.requireUnlockedDeviceAllowFallback")
        put(.tighten,
            "config.requireUnlockedDevice", "config.requireHardwareBackedKeys", "config.requireCaTrust",
            "config.wipeVaultFilesOnRevocation",
            "config.expiredConfigGrace", "config.expiredConfigGrace.amount", "config.expiredConfigGrace.unit",
            "config.vaultFileMaxOfflineAge", "config.vaultFileMaxOfflineAge.amount", "config.vaultFileMaxOfflineAge.unit",
            // Expectations the attestation checks against; fixed where the file names them.
            "config.ios.expectedBundleIds", "config.ios.expectedTeamIds",
            // DEVICE_OWNER (the default) or the stricter BIOMETRIC_CURRENT_SET; fixed where the file names it.
            "config.ios.userAuthStrength",
            // Android's signer digests (fixed from the file there); the iOS library reports none,
            // so here it only adds an expectation.
            "config.expectedSignerSha256")
        put(.free,
            "config.deviceAlias", "config.maxRetryCount", "config.updateIntervalHours", "config.updateIntervalMinutes",
            // A Dart signal by nature: what the app's own checks say.
            "config.environmentGuard.timeoutMs")
        return map
    }()
}
