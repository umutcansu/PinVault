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

/// `rooted`: jailbreak artefacts — the package managers' apps, rootless
/// jailbreak roots, apt state, sshd and bash (which a stock iPhone does not
/// have) — and a write that succeeds outside the sandbox. `cydia://` /
/// `sileo://` are not queried (that needs `LSApplicationQueriesSchemes`).
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
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/var/jb", "/private/var/lib/apt", "/usr/sbin/sshd", "/bin/bash", "/etc/apt",
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

/// `debuggable`: the `get-task-allow` entitlement, read from the embedded
/// provisioning profile; on the simulator (which has none) a debug build.
struct DebuggableProbe {
    /// `Entitlements.get-task-allow` of the embedded profile; nil without a profile.
    let getTaskAllow: Bool?
    let isSimulatorBuild: Bool
    let isDebugBuild: Bool

    /// The value for `app.debuggable`.
    var debuggable: Bool {
        if let getTaskAllow { return getTaskAllow }
        // No profile: an App Store / TestFlight build (never get-task-allow),
        // or the simulator, where the build configuration is all there is.
        return isSimulatorBuild && isDebugBuild
    }

    func probe() -> IntegritySignal {
        if getTaskAllow == true { return .raised("entitlement:get-task-allow") }
        if getTaskAllow == nil && isSimulatorBuild && isDebugBuild { return .raised("build:debug") }
        return .clean
    }
}

/// `hooking_framework`: Frida / Substrate / Substitute / libhooker / ElleKit /
/// Cycript / SSL Kill Switch among the loaded dyld images,
/// `DYLD_INSERT_LIBRARIES` set, Frida's default port open on 127.0.0.1.
struct HookingProbe {
    /// Paths of the loaded images (`_dyld_get_image_name`).
    let loadedImages: () -> [String]
    let environment: [String: String]
    /// True when 127.0.0.1:27042 accepts a connection.
    let fridaPortOpen: () -> Bool

    func probe() -> IntegritySignal {
        var evidence: [String] = []
        for image in loadedImages() {
            let name = (image.split(separator: "/").last.map(String.init) ?? image).lowercased()
            // Every marker a name carries (`FridaGadget` is `frida` and `fridagadget`).
            for marker in Self.imageMarkers where name.contains(marker) {
                evidence.append("dyld:\(marker)")
            }
        }
        if let inserted = environment["DYLD_INSERT_LIBRARIES"], !inserted.isEmpty {
            evidence.append("env:DYLD_INSERT_LIBRARIES")
        }
        if fridaPortOpen() { evidence.append("port:\(Self.fridaPort)") }
        return .from(evidence)
    }

    /// Lower case; matched against the image's file name.
    static let imageMarkers = [
        "frida", "fridagadget", "substrate", "substitute", "libhooker", "ellekit", "cycript", "sslkillswitch",
    ]

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

    func probe() -> IntegritySignal {
        var evidence: [String] = []
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
    /// (`sandboxReceipt` = TestFlight, `receipt` = App Store).
    static func resolve(isSimulator: Bool, hasEmbeddedProfile: Bool, receiptName: String?) -> AppInstaller {
        if isSimulator { return .simulator }
        if hasEmbeddedProfile { return .provisioned }
        switch receiptName {
        case "sandboxReceipt": return .testFlight
        case "receipt": return .appStore
        default: return .unknown
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
