import Foundation

/// The façade's attestation flow over the blocks of one started config —
/// what Kotlin's `PinVault.attestNow`, `fetchAttestationToken`,
/// `attestationStatus`, the attestation at `init` and the periodic worker's
/// `attestAll` do — with every collaborator handed in, so `PinVault.swift`
/// only forwards (after its own "not initialized" checks) and tests drive it
/// without a façade.
///
/// One ``AttestationManager`` per block with `attestation()`; a block whose
/// API is not the library's own (no ``AttestationApi``) gets one that reports
/// `UNSUPPORTED`, as in Kotlin.
final class AttestationCoordinator: Sendable {

    let config: PinVaultConfig
    /// Attesting blocks in config order.
    let managers: [AttestationManager]
    private let byId: [String: AttestationManager]
    private let log = PinVaultLog.tag("PinVault")

    /// Over managers built elsewhere (one per attesting block, e.g. by `ConfigApiClient`).
    init(config: PinVaultConfig, managers: [AttestationManager]) {
        self.config = config
        self.managers = managers
        var byId: [String: AttestationManager] = [:]
        for manager in managers where byId[manager.block.id] == nil { byId[manager.block.id] = manager }
        self.byId = byId
    }

    /// Builds a manager for every block of `config` with `attestation()`.
    ///
    /// - Parameters:
    ///   - api: the block's ``CertificateConfigApi``; attestation goes through
    ///     it when it is the library's own (adopts ``AttestationApi``).
    ///   - identityKey: the block's device key (its mTLS identity key, `clientCertLabel`).
    ///   - deviceId: the device id requests carry (`identifierForVendor`).
    ///   - clock: epoch ms (the library's wall clock).
    ///   - onEvent: the connection-event dispatch (`DynamicSSLManager.dispatchEvent`).
    ///   - currentConfigVersion / currentIssuedAt / liveConfig: the block's active config, by block id.
    ///   - applyConfig: applies a signed config that rode along with a pass (`SSLCertificateUpdater.applySigned`).
    ///   - onConfigApplied: told the result, like a recovery update (block id, result).
    ///   - probe: the report builder; nil = ``DeviceIntegrityProbe/forConfig(_:defaultVerdictProvider:)``.
    convenience init(
        config: PinVaultConfig,
        api: (ConfigApiBlock) -> (any CertificateConfigApi)?,
        identityKey: @escaping @Sendable (ConfigApiBlock) throws -> any ClientIdentityKeyProvider,
        deviceId: @escaping @Sendable () -> String?,
        clock: @escaping @Sendable () -> Int64,
        onEvent: @escaping @Sendable (PinVaultConnectionEvent) -> Void,
        currentConfigVersion: @escaping @Sendable (_ configApiId: String) -> Int,
        currentIssuedAt: @escaping @Sendable (_ configApiId: String) -> Int64,
        liveConfig: @escaping @Sendable (_ configApiId: String) -> CertificateConfig?,
        applyConfig: @escaping @Sendable (_ configApiId: String, SignedConfigResponse) async throws -> UpdateResult,
        onConfigApplied: @escaping @Sendable (_ configApiId: String, UpdateResult) -> Void = { _, _ in },
        probe: DeviceIntegrityProbe? = nil,
        jitter: @escaping @Sendable () -> Double = { Double.random(in: 0..<1) },
        sleep: @escaping @Sendable (Int64) async throws -> Void = { ms in
            try await Task.sleep(nanoseconds: UInt64(max(0, ms)) * 1_000_000)
        }
    ) {
        let attesting = config.orderedConfigApis.filter(\.attestationEnabled)
        let probe = attesting.isEmpty ? nil : (probe ?? DeviceIntegrityProbe.forConfig(config))
        let roundAware = probe?.verdictProvider as? any AttestationRoundVerdictProvider
        let managers = attesting.map { block -> AttestationManager in
            let id = block.id
            return AttestationManager(
                block: block,
                api: api(block) as? any AttestationApi,
                identityKey: { try identityKey(block) },
                deviceId: deviceId,
                currentConfigVersion: { currentConfigVersion(id) },
                currentIssuedAt: { currentIssuedAt(id) },
                liveConfig: { liveConfig(id) },
                buildReport: { nonce, did, key in
                    guard let probe else { return "{}" }
                    return await probe.report(nonce: nonce, deviceId: did, scope: id, key: key).jsonString()
                },
                applyConfig: { signed in try await applyConfig(id, signed) },
                onConfigApplied: { result in onConfigApplied(id, result) },
                onEvent: onEvent,
                onVerdict: { warnings, reasons in
                    roundAware?.roundAnswered(scope: id, warnings: warnings, rejectionReasons: reasons)
                },
                clock: clock,
                jitter: jitter,
                sleep: sleep
            )
        }
        self.init(config: config, managers: managers)
    }

    /// The manager of a block, or nil when it does not attest.
    func manager(_ configApiId: String) -> AttestationManager? { byId[configApiId] }

    /// What the token interceptor reads: every attesting block, default block first.
    var tokenSources: [any AttestationTokenSource] { managers }

    /// The token interceptor for sessions the app owns (`applyTo`,
    /// `session(settings:)`): every attesting block's token, or nil when no block attests.
    func tokenInterceptor() -> AttestationTokenInterceptor? {
        guard !managers.isEmpty else { return nil }
        let sources = managers
        return AttestationTokenInterceptor(sources: { sources })
    }

    // MARK: The façade's calls

    /// `PinVault.attestNow(configApiId:)` once started: the block's manager, or `UNSUPPORTED`.
    func attestNow(configApiId: String?) async -> AttestationStatus {
        let id = configApiId ?? config.defaultConfigApi?.id ?? ""
        guard let manager = byId[id] else { return notAttesting(id) }
        return await manager.attestNow()
    }

    /// `PinVault.fetchAttestationToken(host:)` once started: the block whose
    /// token hosts cover `host` (`host` or `host:port`; nil = the default block).
    func fetchAttestationToken(host: String?) async -> AttestationTokenResult {
        let manager: AttestationManager?
        if let host {
            let parts = host.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            let name = String(parts[0]).trimmingCharacters(in: .whitespaces)
            let port = parts.count > 1 ? Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? -1 : -1
            manager = managers.first { $0.handlesHost(name, port: port) }
        } else {
            manager = config.defaultConfigApi.flatMap { byId[$0.id] }
        }
        guard let manager else { return .unsupported }
        return await manager.fetchToken()
    }

    /// `PinVault.attestationStatus(configApiId:)` once started: from memory.
    func attestationStatus(configApiId: String?) -> AttestationStatus {
        let id = configApiId ?? config.defaultConfigApi?.id ?? ""
        return byId[id]?.status ?? notAttesting(id)
    }

    /// The status of a block that does not attest (or does not exist).
    func notAttesting(_ configApiId: String) -> AttestationStatus {
        AttestationStatus(
            configApiId: configApiId,
            result: .unsupported,
            lastError: config.configApis[configApiId] != nil
                ? "Config API '\(configApiId)' does not attest: call attestation() on the block"
                : "No Config API block '\(configApiId)'"
        )
    }

    // MARK: Lifecycle

    /// At `start`, once the stored config is loaded and the mTLS renewal check
    /// ran: every attesting block attests once and keeps re-attesting in the
    /// background. A reject (or a failure) never fails `start`: the app reads
    /// `attestationStatus()`; no token and no config come through this
    /// channel until the next pass.
    func attestAtStart() async {
        for manager in managers {
            let status = await manager.attestNow()
            log.d("ConfigApi[\(manager.block.id)] attestation at init: \(status.result.rawValue)")
            manager.start()
        }
    }

    /// Every attesting block attests, for the periodic task (a process the
    /// background task woke ran no `start`: the loop starts here).
    func attestAll() async {
        for manager in managers {
            _ = await manager.attestNow()
            manager.start()
        }
    }

    /// Stops every refresh loop; tokens and statuses stay.
    func stopAll() {
        managers.forEach { $0.stop() }
    }

    /// `PinVault.reset()` / unenroll: loops stop, tokens and statuses go; the next `start` attests again.
    func resetAll() {
        managers.forEach { $0.reset() }
    }
}
