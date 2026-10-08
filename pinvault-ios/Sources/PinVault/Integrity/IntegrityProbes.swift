import Foundation

/*
 * The iOS probes behind the report's `signals` (`ATTESTATION.md` §3,
 * `PORTING.md` §4) — the counterparts of `integrity/Probes.kt`. Each one is a
 * small value over plain inputs or reader closures, so the decision can be
 * tested without a device; `DeviceIntegrityProbe` wires the real readers in
 * (`IntegrityProbeInputs.live`). None of them claims "clean" for what it could
 * not look at: a reader that throws is caught by the orchestrator and becomes
 * `error:<probe>` evidence.
 */

/// `rooted`: jailbreak artefacts — the package managers' apps, the roots and
/// markers of rootless (Dopamine, palera1n) and rootful jailbreaks, the tweak
/// loaders' folders, apt state, sshd and bash (which a stock iPhone does not
/// have) — and a write that succeeds outside the sandbox. Rootless jailbreaks
/// leave App Store apps sandboxed and the system volume sealed, so the write
/// test catches only older, rootful ones; and a hiding tweak (Shadow,
/// RootHide) can hide every path from the app: the server's App Attest
/// verdict is what does not depend on this probe. `cydia://` / `sileo://`
/// are not queried (that needs `LSApplicationQueriesSchemes`).
struct JailbreakProbe {
    let fileExists: (String) -> Bool
    /// True when a file could be written (and was removed again) directly under `/private`.
    let canWriteOutsideSandbox: () throws -> Bool
    /// The simulator and macOS see the Mac's own file system, where these
    /// paths are part of the system: not evidence there.
    let onMacHost: Bool

    func probe() throws -> IntegritySignal {
        var evidence: [String] = []
        for path in Self.paths where !(onMacHost && Self.macSystemPaths.contains(path)) {
            if fileExists(path) { evidence.append("file:\(path)") }
        }
        if try canWriteOutsideSandbox() { evidence.append("fs:/private-writable") }
        return .from(evidence)
    }

    static let paths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app", "/Applications/Filza.app",
        "/var/jb", "/var/jb/.installed_dopamine", "/var/jb/.procursus_strapped", "/var/jb/basebin",
        "/var/jb/usr/lib/TweakInject", "/var/jb/Library/MobileSubstrate/DynamicLibraries",
        "/var/binpack", "/cores/binpack", "/private/preboot/procursus",
        "/Library/MobileSubstrate/MobileSubstrate.dylib", "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/lib/TweakInject", "/.bootstrapped", "/.installed_unc0ver",
        "/private/var/lib/apt", "/usr/sbin/sshd", "/bin/bash", "/etc/apt",
    ]

    /// Present on every Mac.
    static let macSystemPaths: Set<String> = ["/usr/sbin/sshd", "/bin/bash"]
}

/// `emulator`: a simulator build, or the simulator's environment.
struct SimulatorProbe {
    let isSimulatorBuild: Bool
    let environment: [String: String]

    func probe() -> IntegritySignal {
        var evidence: [String] = []
        if isSimulatorBuild { evidence.append("build:simulator") }
        if let name = environment["SIMULATOR_DEVICE_NAME"], !name.isEmpty { evidence.append("env:SIMULATOR_DEVICE_NAME") }
        return .from(evidence)
    }
}

/// `debugger`: the process is being traced (`sysctl` `kinfo_proc.p_flag & P_TRACED`).
struct DebuggerProbe {
    let isTraced: () throws -> Bool

    func probe() throws -> IntegritySignal {
        try isTraced() ? .raised("sysctl:p_traced") : .clean
    }
}

/// `debuggable`: the `get-task-allow` entitlement, read from the binary's own
/// code signature and from the embedded provisioning profile (a re-signed app
/// can carry it with no profile at all); on the simulator (which has neither)
/// a debug build.
struct DebuggableProbe {
    /// `Entitlements.get-task-allow` of the embedded profile; nil without a profile.
    let getTaskAllow: Bool?
    let isSimulatorBuild: Bool
    let isDebugBuild: Bool
    /// `get-task-allow` in the main executable's code signature; nil when unread.
    var signedGetTaskAllow: Bool? = nil

    /// The value for `app.debuggable`.
    var debuggable: Bool {
        if signedGetTaskAllow == true { return true }
        if let getTaskAllow { return getTaskAllow }
        // No profile: an App Store / TestFlight build (never get-task-allow),
        // or the simulator, where the build configuration is all there is.
        return isSimulatorBuild && isDebugBuild
    }

    func probe() -> IntegritySignal {
        if signedGetTaskAllow == true && getTaskAllow != true { return .raised("codesign:get-task-allow") }
        if getTaskAllow == true { return .raised("entitlement:get-task-allow") }
        if getTaskAllow == nil && isSimulatorBuild && isDebugBuild { return .raised("build:debug") }
        return .clean
    }
}

/// `hooking_framework`: Frida / Substrate / Substitute / libhooker / ElleKit /
/// Cycript / SSL Kill Switch / tweak loaders among the loaded dyld images, by
/// name and by where they were loaded from (a jailbreak's folders, or — on a
/// device — anywhere outside the shared cache and the app's bundle, which
/// catches a tweak or gadget of any name), Frida's threads,
/// `DYLD_INSERT_LIBRARIES` set, Frida's default port open on 127.0.0.1.
struct HookingProbe {
    /// Paths of the loaded images (`_dyld_get_image_name`).
    let loadedImages: () -> [String]
    let environment: [String: String]
    /// True when 127.0.0.1:27042 accepts a connection.
    let fridaPortOpen: () -> Bool
    /// Names of this process's threads.
    var threadNames: () -> [String] = { [] }
    /// Whether an image path is part of the dyld shared cache.
    var inSharedCache: (String) -> Bool = { _ in true }
    /// The app bundle's path; images under it are the app's own.
    var bundlePath: String = ""
    /// The simulator and macOS load the Mac's own libraries: the location rule does not apply.
    var onMacHost: Bool = true

    func probe() -> IntegritySignal {
        var evidence: [String] = []
        for image in loadedImages() {
            let name = (image.split(separator: "/").last.map(String.init) ?? image).lowercased()
            // Every marker a name carries (`FridaGadget` is `frida` and `fridagadget`).
            for marker in Self.imageMarkers where name.contains(marker) {
                evidence.append("dyld:\(marker)")
            }
            let fromJailbreak = Self.jailbreakFolders.contains(where: { image.hasPrefix($0) }) && !image.contains("/Cryptexes/")
            if fromJailbreak || Self.loaderFolders.contains(where: { image.contains($0) }) {
                evidence.append("dyld-path:\(String(name.prefix(48)))")
            } else if !onMacHost, isForeign(image) {
                evidence.append("dyld-foreign:\(String(name.prefix(48)))")
            }
        }
        for thread in threadNames() {
            let name = thread.lowercased()
            if Self.threadMarkers.contains(where: { name == $0 || name.hasPrefix($0) }) { evidence.append("thread:\(thread)") }
        }
        if let inserted = environment["DYLD_INSERT_LIBRARIES"], !inserted.isEmpty {
            evidence.append("env:DYLD_INSERT_LIBRARIES")
        }
        if fridaPortOpen() { evidence.append("port:\(Self.fridaPort)") }
        var seen = Set<String>()
        return .from(evidence.filter { seen.insert($0).inserted })
    }

    /// Not the system's (shared cache, or the sealed system volume — accessibility
    /// bundles, for one, load from there outside the cache), not the app's
    /// (bundle), not Xcode's debugging aids.
    private func isForeign(_ image: String) -> Bool {
        if !bundlePath.isEmpty && image.hasPrefix(bundlePath) { return false }
        if Self.systemVolume.contains(where: { image.hasPrefix($0) }) { return false }
        if Self.debuggerSupport.contains(where: { image.hasSuffix($0) }) || image.hasPrefix("/Developer/") { return false }
        return !inSharedCache(image)
    }

    /// Lower case; matched against the image's file name.
    static let imageMarkers = [
        "frida", "fridagadget", "substrate", "substitute", "libhooker", "ellekit", "cycript", "sslkillswitch",
        "tweakinject", "systemhook", "libshadow", "choicy", "rocketbootstrap",
    ]

    /// Roots of jailbreak file systems: anything loaded from there is a tweak
    /// (bar the system's own cryptexes, which also live under /private/preboot).
    static let jailbreakFolders = ["/var/jb/", "/private/var/jb/", "/private/preboot/", "/var/binpack/", "/cores/binpack/"]
    /// Tweak loader folders, wherever the jailbreak keeps them.
    static let loaderFolders = ["/MobileSubstrate/", "/TweakInject/", "/CydiaSubstrate.framework/"]
    /// The sealed system volume, which a rootless jailbreak cannot write.
    static let systemVolume = ["/System/", "/usr/lib/", "/usr/libexec/"]
    /// What Xcode injects into a process it runs (debug runs only).
    static let debuggerSupport = ["/libMainThreadChecker.dylib", "/libViewDebuggerSupport.dylib", "/libLogRedirect.dylib", "/libRPAC.dylib"]
    /// Threads only Frida's agent starts (GLib's `gmain` / `gdbus` are left out:
    /// GLib-based SDKs such as GStreamer name their threads so too).
    static let threadMarkers = ["gum-js-loop", "pool-frida", "frida"]

    static let fridaPort: UInt16 = 27042
}

/// `app_integrity`: the client raises it only when the app named the bundle
/// ids / team ids it expects (`PinVaultConfig.expectedBundleIds` /
/// `expectedTeamIds`) and the running app is not one of them; the server
/// compares both with its own lists either way.
struct AppIntegrityProbe {
    let bundleId: String?
    let teamId: String?
    let expectedBundleIds: Set<String>
    let expectedTeamIds: Set<String>
    /// Where the app says it came from.
    var installer: AppInstaller = .unknown
    /// `cryptid` of the main executable's `LC_ENCRYPTION_INFO`; nil when unread.
    var mainImageEncrypted: Bool? = nil

    func probe() -> IntegritySignal {
        var evidence: [String] = []
        // Apple encrypts every App Store and TestFlight binary; one that runs
        // decrypted was taken out of its package and signed again.
        if (installer == .appStore || installer == .testFlight) && mainImageEncrypted == false {
            evidence.append("macho:decrypted")
        }
        if !expectedBundleIds.isEmpty {
            if let bundleId, !bundleId.isEmpty {
                if !expectedBundleIds.contains(bundleId) { evidence.append("bundle:\(String(bundleId.prefix(64)))") }
            } else {
                evidence.append("bundle:unreadable")
            }
        }
        if !expectedTeamIds.isEmpty {
            if let teamId, !teamId.isEmpty {
                if !expectedTeamIds.contains(teamId) { evidence.append("team:\(String(teamId.prefix(16)))") }
            } else {
                evidence.append("team:unreadable")
            }
        }
        return .from(evidence)
    }
}

/// Where the app came from, as far as the app itself can tell.
enum AppInstaller: String, Sendable, Equatable, CaseIterable {
    case appStore = "app-store"
    case testFlight = "testflight"
    /// An embedded provisioning profile: development, ad hoc or enterprise.
    case provisioned = "provisioned"
    case simulator = "simulator"
    case unknown = "unknown"

    /// The simulator first, then an embedded profile, then the receipt's name
    /// (`sandboxReceipt` = TestFlight, `receipt` = App Store). With no receipt
    /// on disk (a restored or migrated phone can lack one) a binary still
    /// encrypted by the App Store counts as an App Store install: only Apple
    /// encrypts, and a re-signed copy runs decrypted.
    static func resolve(isSimulator: Bool, hasEmbeddedProfile: Bool, receiptName: String?, mainImageEncrypted: Bool? = nil) -> AppInstaller {
        if isSimulator { return .simulator }
        if hasEmbeddedProfile { return .provisioned }
        switch receiptName {
        case "sandboxReceipt": return .testFlight
        case "receipt": return .appStore
        default: return mainImageEncrypted == true ? .appStore : .unknown
        }
    }
}

/// `unknown_installer`: not from the App Store or TestFlight.
struct InstallerProbe {
    let installer: AppInstaller

    func probe() -> IntegritySignal {
        switch installer {
        case .appStore, .testFlight: return .clean
        default: return .raised("installer:\(installer.rawValue)")
        }
    }
}

/// `software_key` and `key_unattested` from the device key and the verdict.
struct KeyProbe {
    let level: KeySecurityLevel
    /// True when an App Attest verdict travels with this report.
    let appAttestVerdict: Bool

    func softwareKey() -> IntegritySignal {
        level.hardwareBacked ? .clean : .raised("key:\(level.wireName)")
    }

    /// Decided by the server: an iOS key has no attestation chain, and only an
    /// App Attest verdict the server verified lifts the flag (§12). Raising it
    /// here would keep it raised whatever App Attest says, so it goes down,
    /// with a note when no App Attest verdict travels with the report.
    func keyUnattested() -> IntegritySignal {
        appAttestVerdict ? .clean : IntegritySignal(false, ["app-attest:none"])
    }
}
