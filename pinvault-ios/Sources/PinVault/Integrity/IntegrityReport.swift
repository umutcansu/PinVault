import Foundation

/// One probe's finding: whether the flag is raised and what was seen. A probe
/// that could not run contributes `error:<probe>` evidence with the flag down,
/// so the server can tell "clean" from "could not look".
struct IntegritySignal: Sendable, Equatable {
    let flag: Bool
    let evidence: [String]

    init(_ flag: Bool, _ evidence: [String] = []) {
        self.flag = flag
        self.evidence = evidence
    }

    static let clean = IntegritySignal(false)

    /// Android-only signals (`cloner`, `adb_enabled`): present, never raised.
    static let notApplicable = IntegritySignal(false, ["n/a:ios"])

    static func raised(_ evidence: String...) -> IntegritySignal { IntegritySignal(true, evidence) }

    static func error(_ probe: String) -> IntegritySignal { IntegritySignal(false, ["error:\(probe)"]) }

    /// Raised when there is evidence (duplicates dropped, order kept).
    static func from(_ evidence: [String]) -> IntegritySignal {
        let distinct = evidence.distinctPreservingOrder()
        return IntegritySignal(!distinct.isEmpty, distinct)
    }

    var json: IntegrityJSON {
        .object([.init("flag", .bool(flag)), .init("evidence", .strings(evidence))])
    }
}

/// The report the library signs and sends with an attestation request — the
/// iOS shape of `ATTESTATION.md` §3 / `PORTING.md` §4. Built by
/// ``DeviceIntegrityProbe``; serialised once with ``jsonString()``, and that
/// string is what is sent and hashed into the canonical string, so there is
/// no canonicalisation.
struct IntegrityReport: Sendable, Equatable {

    /// The `app` block. `packageName` repeats the bundle id so a server that
    /// reads Android reports finds the app under the same key.
    struct App: Sendable, Equatable {
        var bundleId: String
        /// The Apple team id the app is signed by; nil when it cannot be read.
        var teamId: String?
        /// `CFBundleVersion` as an integer, else 0.
        var versionCode: Int64
        /// `CFBundleShortVersionString`.
        var versionName: String?
        /// `app-store`, `testflight`, `provisioned`, `simulator` or `unknown`.
        var installer: String
        /// The `get-task-allow` entitlement.
        var debuggable: Bool

        var json: IntegrityJSON {
            .object([
                .init("packageName", .string(bundleId)),
                .init("bundleId", .string(bundleId)),
                .init("teamId", .optional(teamId)),
                .init("versionCode", .int(versionCode)),
                .init("versionName", .optional(versionName)),
                // iOS has no signer digests; the server judges bundle and team ids instead.
                .init("signerSha256", .array([])),
                .init("installer", .string(installer)),
                .init("debuggable", .bool(debuggable)),
            ])
        }
    }

    /// The `device` block.
    struct Device: Sendable, Equatable {
        var osVersion: String
        /// The machine identifier (`iPhone17,1`).
        var machine: String
        /// `UIDevice.model` (`iPhone`, `iPad`).
        var model: String
        /// `kern.osversion` (`23F79`), or nil.
        var osBuild: String?
        var osName: String
        /// ``KeySecurityLevel/wireName`` of the device key.
        var keySecurityLevel: String
        /// True when an App Attest verdict travels with the report (the server verifies it).
        var keyAttested: Bool

        var sdkInt: Int64 {
            Int64(osVersion.split(separator: ".").first.flatMap { Int($0) } ?? 0)
        }

        var fingerprint: String {
            "\(osName)/\(osVersion)/\(osBuild ?? "unknown")"
        }

        var json: IntegrityJSON {
            .object([
                .init("platform", .string(IntegrityReport.platform)),
                .init("osVersion", .string(osVersion)),
                .init("manufacturer", .string(DeviceInfo.manufacturer)),
                .init("brand", .string(DeviceInfo.manufacturer)),
                .init("model", .string(machine)),
                .init("device", .string(model)),
                .init("product", .string(machine)),
                .init("hardware", .string(machine)),
                .init("fingerprint", .string(fingerprint)),
                .init("sdkInt", .int(sdkInt)),
                .init("securityPatch", .null),
                .init("verifiedBootState", .null),
                .init("keySecurityLevel", .string(keySecurityLevel)),
                .init("keyAttested", .bool(keyAttested)),
            ])
        }
    }

    var sdkVersion: String
    var reportTime: Int64
    var app: App
    var device: Device
    /// One entry per ``signalKeys``; a missing one is sent as `error:<key>`.
    var signals: [String: IntegritySignal]
    var verdict: IntegrityVerdict?

    var json: IntegrityJSON {
        // Every key of §3 is present, raised or not: a missing key would read
        // as "not probed" on the server.
        let signalsJson = IntegrityJSON.object(Self.signalKeys.map { key in
            .init(key, (signals[key] ?? .error(key)).json)
        })
        var members: [IntegrityJSON.Member] = [
            .init("sdkVersion", .string(sdkVersion)),
            .init("reportTime", .int(reportTime)),
            .init("app", app.json),
            .init("device", device.json),
            .init("signals", signalsJson),
        ]
        if let verdict {
            members.append(.init("verdictProvider", .object([.init("name", .string(verdict.name)), .init("token", .string(verdict.token))])))
        }
        return .object(members)
    }

    /// The report as the one string that is signed, hashed and sent.
    func jsonString() -> String { json.serialized }

    /// The library version the report names.
    static let sdkVersion = "2.3.2"

    /// `device.platform`: switches the server to its iOS rules.
    static let platform = "ios"

    static let rooted = "rooted"
    static let emulator = "emulator"
    static let debugger = "debugger"
    static let debuggable = "debuggable"
    static let hookingFramework = "hooking_framework"
    static let appIntegrity = "app_integrity"
    static let cloner = "cloner"
    static let unknownInstaller = "unknown_installer"
    static let adbEnabled = "adb_enabled"
    static let softwareKey = "software_key"
    static let keyUnattested = "key_unattested"
    /// Decided by the server from `device.osVersion`; the client always sends it down.
    static let oldPatchLevel = "old_patch_level"

    /// The signal keys of `ATTESTATION.md` §3, in report order.
    static let signalKeys = [
        rooted, emulator, debugger, debuggable, hookingFramework, appIntegrity, cloner,
        unknownInstaller, adbEnabled, softwareKey, keyUnattested, oldPatchLevel,
    ]
}
