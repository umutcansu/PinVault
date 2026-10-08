import Foundation

/// A verdict provider that binds its verdict to the round's device id as
/// well as its nonce, keeps per-block state, and hears the server's answer
/// — the library's own App Attest provider (`PORTING.md` §6). Other
/// providers get the plain ``IntegrityVerdictProvider/verdict(nonce:)``.
protocol AttestationRoundVerdictProvider: IntegrityVerdictProvider {
    /// The verdict for one attestation round of block `scope`, bound to `nonce` and `deviceId` (v1).
    func verdict(nonce: String, deviceId: String, scope: String) async throws -> IntegrityVerdict?

    /// True when this provider binds its verdict to the report (v2): the
    /// report is then built without it and ``verdict(canonical:scope:)`` is
    /// asked for the verdict that travels beside the report.
    var bindsReport: Bool { get }

    /// The verdict for one round of block `scope`, bound to `canonical` — the
    /// string the identity key signs, which carries the report's digest (v2).
    func verdict(canonical: String, scope: String) async throws -> IntegrityVerdict?

    /// The server answered block `scope`'s round with a verdict (pass or reject).
    func roundAnswered(scope: String, warnings: [String], rejectionReasons: [String])

    /// The server refused block `scope`'s round because it wants the device
    /// key registered with an attestation (`key_unknown`, `attestation_required`,
    /// `attestation_invalid`): the next round must carry a fresh one.
    func registrationWanted(scope: String)
}

/// Builds the ``IntegrityReport`` of `ATTESTATION.md` §3 (iOS shape,
/// `PORTING.md` §4) from the probes in this folder. Best effort throughout:
/// a probe that throws contributes `error:<probe>` evidence, never a crash,
/// and never a false "clean"; a reader of the app or device blocks that
/// fails leaves its field empty.
///
/// The report is a measurement by code the attacker can hook — see §3 of the
/// design for why it is still worth making. App Attest (or another provider)
/// adds a second opinion; its token goes along verbatim.
final class DeviceIntegrityProbe: Sendable {

    /// How long an ``IntegrityVerdictProvider`` may take.
    static let verdictTimeoutMs: Int64 = 10_000

    private let expectedBundleIds: Set<String>
    private let expectedTeamIds: Set<String>
    let verdictProvider: (any IntegrityVerdictProvider)?
    private let clock: @Sendable () -> Int64
    private let inputs: IntegrityProbeInputs
    private let verdictTimeoutMs: Int64
    private let log = PinVaultLog.tag("DeviceIntegrityProbe")

    /// - Parameters:
    ///   - expectedBundleIds / expectedTeamIds: what the app expects to run as
    ///     (`PinVaultConfig`); empty = the client does not judge `app_integrity`.
    ///   - verdictProvider: the second opinion, or nil for none.
    init(
        expectedBundleIds: [String] = [],
        expectedTeamIds: [String] = [],
        verdictProvider: (any IntegrityVerdictProvider)? = nil,
        clock: @escaping @Sendable () -> Int64 = LibraryClock.wallMillis,
        inputs: IntegrityProbeInputs = .live,
        verdictTimeoutMs: Int64 = DeviceIntegrityProbe.verdictTimeoutMs
    ) {
        self.expectedBundleIds = Set(expectedBundleIds)
        self.expectedTeamIds = Set(expectedTeamIds)
        self.verdictProvider = verdictProvider
        self.clock = clock
        self.inputs = inputs
        self.verdictTimeoutMs = verdictTimeoutMs
    }

    /// The probe for `config`: its expected bundle and team ids and its
    /// verdict provider — the library's own App Attest provider when the app
    /// registered none (no verdict where App Attest is unsupported).
    static func forConfig(_ config: PinVaultConfig, defaultVerdictProvider: @autoclosure () -> (any IntegrityVerdictProvider)? = AppAttestVerdictProvider()) -> DeviceIntegrityProbe {
        DeviceIntegrityProbe(
            expectedBundleIds: config.expectedBundleIds,
            expectedTeamIds: config.expectedTeamIds,
            verdictProvider: config.integrityVerdictProvider ?? defaultVerdictProvider()
        )
    }

    /// The report for this attestation round. `nonce` and `deviceId` go to the
    /// verdict provider only; the report itself is bound to them by the
    /// signature over the canonical string. `key` is the block's device key,
    /// for the key signals; nil when it cannot be read (reported as unknown).
    /// `scope` names the block, for a provider that keeps per-block state.
    func report(nonce: String, deviceId: String, scope: String, key: (any ClientIdentityKeyProvider)?) async -> IntegrityReport {
        let inputs = self.inputs
        let environment = inputs.environment()
        let keyLevel = key?.securityLevel() ?? .unknown
        // A provider bound to the report (App Attest, v2) answers after it is
        // built (``roundVerdict(canonical:scope:)``); the report then says
        // only that a verdict will travel with it.
        let roundAware = verdictProvider as? any AttestationRoundVerdictProvider
        let deferred = roundAware?.bindsReport == true
        let verdict = deferred ? nil : await verdict(nonce: nonce, deviceId: deviceId, scope: scope)
        let appAttestVerdict = deferred || verdict?.name == AppAttestToken.provider

        // App block.
        let bundleId = inputs.bundleId()
        var profileFailed = false
        let profile: ProvisioningProfile?
        do {
            profile = try inputs.provisioningProfile()
        } catch {
            log.w("Integrity probe 'provisioning-profile' failed", error)
            profile = nil
            profileFailed = true
        }
        let teamId = profile?.teamId ?? TeamId.fromAccessGroup(inputs.keychainAccessGroup())
        let installer = AppInstaller.resolve(
            isSimulator: inputs.isSimulatorBuild,
            hasEmbeddedProfile: profile != nil || profileFailed,
            receiptName: inputs.receiptName()
        )
        let debuggableProbe = DebuggableProbe(
            getTaskAllow: profile?.getTaskAllow, isSimulatorBuild: inputs.isSimulatorBuild, isDebugBuild: inputs.isDebugBuild
        )
        let app = IntegrityReport.App(
            bundleId: bundleId ?? "",
            teamId: teamId,
            versionCode: inputs.bundleVersion().flatMap { Int64($0.trimmingCharacters(in: .whitespaces)) } ?? 0,
            versionName: inputs.shortVersion(),
            installer: installer.rawValue,
            debuggable: debuggableProbe.debuggable
        )

        // Device block.
        let device = IntegrityReport.Device(
            osVersion: inputs.osVersion(),
            machine: inputs.machine(),
            model: await inputs.deviceModel(),
            osBuild: inputs.osBuild(),
            osName: inputs.osName,
            keySecurityLevel: keyLevel.wireName,
            keyAttested: appAttestVerdict
        )

        let keyProbe = KeyProbe(level: keyLevel, appAttestVerdict: appAttestVerdict)
        var signals: [String: IntegritySignal] = [:]
        signals[IntegrityReport.rooted] = safe(IntegrityReport.rooted) {
            try JailbreakProbe(
                fileExists: inputs.fileExists,
                canWriteOutsideSandbox: inputs.canWriteOutsideSandbox,
                onMacHost: inputs.onMacHost
            ).probe()
        }
        signals[IntegrityReport.emulator] = safe(IntegrityReport.emulator) {
            SimulatorProbe(isSimulatorBuild: inputs.isSimulatorBuild, environment: environment).probe()
        }
        signals[IntegrityReport.debugger] = safe(IntegrityReport.debugger) {
            try DebuggerProbe(isTraced: inputs.isTraced).probe()
        }
        signals[IntegrityReport.debuggable] = profileFailed && !inputs.isSimulatorBuild
            ? .error(IntegrityReport.debuggable)
            : debuggableProbe.probe()
        signals[IntegrityReport.hookingFramework] = safe(IntegrityReport.hookingFramework) {
            HookingProbe(
                loadedImages: inputs.loadedImages,
                environment: environment,
                fridaPortOpen: { inputs.localPortOpen(HookingProbe.fridaPort) }
            ).probe()
        }
        signals[IntegrityReport.appIntegrity] = safe(IntegrityReport.appIntegrity) {
            AppIntegrityProbe(
                bundleId: bundleId, teamId: teamId,
                expectedBundleIds: expectedBundleIds, expectedTeamIds: expectedTeamIds
            ).probe()
        }
        // Android's app-cloner and adb checks have no iOS counterpart: present, never raised.
        signals[IntegrityReport.cloner] = .notApplicable
        signals[IntegrityReport.unknownInstaller] = InstallerProbe(installer: installer).probe()
        signals[IntegrityReport.adbEnabled] = .notApplicable
        signals[IntegrityReport.softwareKey] = keyProbe.softwareKey()
        signals[IntegrityReport.keyUnattested] = keyProbe.keyUnattested()
        // Decided by the server from device.osVersion; sent down so the key is always present.
        signals[IntegrityReport.oldPatchLevel] = .clean

        return IntegrityReport(
            sdkVersion: IntegrityReport.sdkVersion,
            reportTime: clock(),
            app: app,
            device: device,
            signals: signals,
            verdict: verdict
        )
    }

    /// Runs one probe; a failure of any kind is evidence, not an exception.
    private func safe(_ name: String, _ probe: () throws -> IntegritySignal) -> IntegritySignal {
        do {
            return try probe()
        } catch {
            log.w("Integrity probe '\(name)' failed", error)
            return .error(name)
        }
    }

    /// The verdict that travels beside the report (v2), bound to `canonical`;
    /// nil when the provider does not bind reports or has no verdict.
    func roundVerdict(canonical: String, scope: String) async -> IntegrityVerdict? {
        guard let roundAware = verdictProvider as? any AttestationRoundVerdictProvider, roundAware.bindsReport else { return nil }
        return await timed { try await roundAware.verdict(canonical: canonical, scope: scope) }
    }

    private func verdict(nonce: String, deviceId: String, scope: String) async -> IntegrityVerdict? {
        guard let provider = verdictProvider else { return nil }
        return await timed { () async throws -> IntegrityVerdict? in
            if let roundAware = provider as? any AttestationRoundVerdictProvider {
                return try await roundAware.verdict(nonce: nonce, deviceId: deviceId, scope: scope)
            }
            return try await provider.verdict(nonce: nonce)
        }
    }

    private func timed(_ work: @escaping @Sendable () async throws -> IntegrityVerdict?) async -> IntegrityVerdict? {
        let outcome = await Self.withTimeout(verdictTimeoutMs, work)
        switch outcome {
        case .value(let verdict):
            return verdict
        case .failure(let error):
            log.w("Integrity verdict provider failed — attesting without it", error)
            return nil
        case .timedOut:
            log.w("Integrity verdict provider took longer than \(verdictTimeoutMs) ms — attesting without it")
            return nil
        }
    }

    enum TimedOutcome<Value: Sendable>: Sendable {
        case value(Value)
        case failure(any Error)
        case timedOut
    }

    /// Runs `work`, giving up on it after `timeoutMs`. Unlike a task group this
    /// returns at the deadline even when `work` ignores cancellation (a
    /// DeviceCheck call does): `work` is cancelled and left to finish alone.
    static func withTimeout<Value: Sendable>(
        _ timeoutMs: Int64,
        _ work: @escaping @Sendable () async throws -> Value
    ) async -> TimedOutcome<Value> {
        let pending = Locked(TimeoutPending<Value>())
        let finish: @Sendable (TimedOutcome<Value>) -> Void = { outcome in
            let (continuation, tasks) = pending.withLock { state -> (CheckedContinuation<TimedOutcome<Value>, Never>?, [Task<Void, Never>]) in
                let taken = (state.continuation, state.tasks)
                state.continuation = nil
                state.tasks = []
                return taken
            }
            guard let continuation else { return }
            tasks.forEach { $0.cancel() }
            continuation.resume(returning: outcome)
        }
        return await withCheckedContinuation { continuation in
            pending.withLock { $0.continuation = continuation }
            let worker = Task {
                do {
                    finish(.value(try await work()))
                } catch {
                    finish(.failure(error))
                }
            }
            let timer = Task {
                do {
                    try await Task.sleep(nanoseconds: UInt64(max(0, timeoutMs)) * 1_000_000)
                } catch {
                    return
                }
                finish(.timedOut)
            }
            let alreadyDone = pending.withLock { state -> Bool in
                guard state.continuation != nil else { return true }
                state.tasks = [worker, timer]
                return false
            }
            if alreadyDone { timer.cancel() }
        }
    }
}

/// The open state of one ``DeviceIntegrityProbe/withTimeout(_:_:)`` call.
private struct TimeoutPending<Value: Sendable>: Sendable {
    var continuation: CheckedContinuation<DeviceIntegrityProbe.TimedOutcome<Value>, Never>?
    var tasks: [Task<Void, Never>] = []
}
