// What a release build lets JS decide, for every key `ConfigParser.parse` reads
// (the Swift twin of ConfigFieldPolicy.kt, review 2026-11-12). A key the parser
// reads must be listed here (`ConfigFieldPolicyTests` fails otherwise), so adding
// one forces the decision instead of leaving the new field JS's by default.
//
// The paths follow the Android table; where the platforms read different keys:
// - `config.android` is a container only here (its keys are the Android side's;
//   `android.pinGlobalNetworking` / `android.requireUnlockedDeviceAllowFallback`
//   are not read on iOS);
// - `config.ios.*` holds the iOS keys: `requireUnlockedDeviceAllowFallback` (the
//   twin of Android's), `resolve`, `expectedBundleIds`, `expectedTeamIds`,
//   `userAuthStrength`, `reactNativeMaxResponseBytes`;
// - `config.expectedSignerSha256` is Android's signer digests: the iOS library
//   keeps it for parity and never checks it, so it is FREE here (NATIVE on Android).
import Foundation

public enum ConfigFieldPolicy {

    public enum Policy: String {
        /// A trust anchor, a relaxation, or where the device's token, identity and
        /// connections go: with a native security file a release build takes it from
        /// the file only (JS may repeat it); a relaxation is refused from JS without one.
        case native = "NATIVE"
        /// A protection: JS may only make it stricter; the file's value is the floor (or the cap, or fixed).
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
        var m: [String: Policy] = [:]
        func put(_ p: Policy, _ keys: String...) {
            for k in keys {
                precondition(m[k] == nil, "\(k) classified twice")
                m[k] = p
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
            // On from JS, or forced on by the file; never off against it.
            "\(api).attestation", "\(api).proofOfPossession",
            // Lowered by JS only; the file (or the library's 825 days) is the cap in a release build.
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
            // Start going on although RN's own networking is not pinned, and a weaker key where the device refuses the flag.
            "config.requirePinnedReactNativeNetworking",
            "config.ios.requireUnlockedDeviceAllowFallback",
            // Where a pinned host's TCP connection goes.
            "config.ios.resolve")
        put(.tighten,
            "config.requireUnlockedDevice", "config.requireHardwareBackedKeys", "config.requireCaTrust",
            "config.wipeVaultFilesOnRevocation",
            "config.expiredConfigGrace", "config.expiredConfigGrace.amount", "config.expiredConfigGrace.unit",
            "config.vaultFileMaxOfflineAge", "config.vaultFileMaxOfflineAge.amount", "config.vaultFileMaxOfflineAge.unit",
            // Checks the device adds (app_integrity) and the screen-lock strength (default the weakest):
            // JS can only add them; fixed where the file names them.
            "config.ios.expectedBundleIds", "config.ios.expectedTeamIds", "config.ios.userAuthStrength")
        put(.free,
            "config.deviceAlias", "config.maxRetryCount", "config.updateIntervalHours", "config.updateIntervalMinutes",
            // A JS signal by nature: what the app's own checks say.
            "config.environmentGuard.timeoutMs",
            // Android's signer digests: kept for parity by the iOS library, never checked here.
            "config.expectedSignerSha256",
            // The bound of a React Native https answer kept in memory: not trust.
            "config.ios.reactNativeMaxResponseBytes")
        return m
    }()
}
