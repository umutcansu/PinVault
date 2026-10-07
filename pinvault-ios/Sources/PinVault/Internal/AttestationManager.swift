import Foundation

/// Attestation of one Config API block (`ATTESTATION.md`): the challenge /
/// report / verdict round trip, the token it yields, the refresh loop that
/// keeps the token fresh while the process lives, and the token source the
/// ``AttestationTokenInterceptor`` reads.
///
/// Everything here is in memory: the token, the status, the schedule.
/// Nothing new is written to disk.
final class AttestationManager: AttestationTokenSource, @unchecked Sendable {

    static let protocolVersion = 1

    static let unsupportedReason =
        "This Config API block does not attest: attestation needs the library's own HTTP client, not a custom CertificateConfigApi"

    /// Shortest wait between two scheduled attestations.
    static let minDelayMs: Int64 = 30_000
    /// Re-attest this long before the token expires.
    static let expiryMarginMs: Int64 = 60_000
    /// Backoff after failures: 30 s, 60 s, 2 min, 4 min, then 5 min.
    static let backoffMinMs: Int64 = 30_000
    static let backoffMaxMs: Int64 = 5 * 60 * 1000
    /// ±10 % on every scheduled delay.
    static let jitterSpread = 0.10
    /// A held token with less life than this is replaced before it is used.
    static let tokenMinRemainingMs: Int64 = 30_000
    /// A 401 forces at most one re-attestation per this many ms.
    static let reattestGapMs: Int64 = 5_000
    /// When the server names neither a TTL nor an expiry.
    static let defaultTokenTtlMs: Int64 = 5 * 60 * 1000

    /// The server's rule for `deviceId`.
    static let unknownDeviceId = "unknown-device"

    /// Server errors after which the next request carries the key's attestation chain again.
    static let chainWantedAgain: Set<String> = ["key_unknown", "attestation_required", "attestation_invalid"]

    let block: ConfigApiBlock
    private let api: (any AttestationApi)?
    private let identityKey: @Sendable () throws -> any ClientIdentityKeyProvider
    private let deviceId: @Sendable () -> String?
    private let currentConfigVersion: @Sendable () -> Int
    private let currentIssuedAt: @Sendable () -> Int64
    private let liveConfig: @Sendable () -> CertificateConfig?
    private let buildReport: @Sendable (_ nonce: String, _ deviceId: String, _ key: any ClientIdentityKeyProvider) async -> String
    private let applyConfig: @Sendable (SignedConfigResponse) async throws -> UpdateResult
    private let onConfigApplied: @Sendable (UpdateResult) -> Void
    private let onEvent: @Sendable (PinVaultConnectionEvent) -> Void
    private let onVerdict: @Sendable (_ warnings: [String], _ rejectionReasons: [String]) -> Void
    private let onRegistrationWanted: @Sendable () -> Void
    private let clock: @Sendable () -> Int64
    private let jitter: @Sendable () -> Double
    private let sleep: @Sendable (Int64) async throws -> Void

    private let initialStatus: AttestationStatus
    private let configApiListener: String?
    private let log = PinVaultLog.tag("AttestationManager")

    private struct State {
        /// The last outcome; what `PinVault.attestationStatus` returns.
        var status: AttestationStatus
        var token: String?
        /// Device-clock expiry of `token`; 0 without one.
        var tokenExpiresAt: Int64 = 0
        /// When the last attempt ran, pass, reject or failure; nil = never.
        var lastAttemptAt: Int64?
        /// Whether the next request carries the key's attestation chain: on the
        /// first attempt of the process, and again after the server said it
        /// does not know the key or wants its attestation. (Always empty on iOS.)
        var chainWanted = true
        var consecutiveFailures = 0
        /// The attestation running now; callers that arrive meanwhile share its result.
        var inFlight: Task<AttestationStatus, Never>?
        var flightId: UInt64 = 0
        var loop: Task<Void, Never>?
    }

    private let state: Locked<State>

    /// - Parameters:
    ///   - api: the block's attest endpoints (the library's own client), or nil
    ///     for a custom `CertificateConfigApi` — attestation is then `UNSUPPORTED`.
    ///   - identityKey: the block's device key (the mTLS identity key); made
    ///     with the identity attestation challenge if it does not exist yet.
    ///   - deviceId: the device id the request carries (`identifierForVendor`); nil = unknown.
    ///   - currentConfigVersion / currentIssuedAt: what the device holds, so the
    ///     server can embed a fresh config when the device is behind.
    ///   - liveConfig: the block's active config, for the token hosts when the block names none.
    ///   - buildReport: the report JSON for a nonce, as a string — what is
    ///     signed and sent, byte for byte.
    ///   - applyConfig: applies a signed config from the answer (`SSLCertificateUpdater.applySigned`).
    ///   - onConfigApplied: told the result of `applyConfig`, the way the
    ///     recovery interceptor reports its updates.
    ///   - onEvent: receives one ``PinVaultConnectionEvent/attestation(configApiId:status:arc:rejectionReasons:warnings:tokenExpiresAt:deviceManufacturer:deviceModel:failureReason:)`` per attempt.
    ///   - onVerdict: told the warnings and reasons of every verdict (the App Attest provider drops an unknown key).
    ///   - onRegistrationWanted: told when the server wants the key's attestation again
    ///     (`key_unknown`, `attestation_required`, `attestation_invalid`); the App Attest
    ///     provider then attests a fresh key in the next round's report.
    ///   - jitter: a value in [0, 1) per call. Tests fix it.
    ///   - sleep: waits the given ms (the refresh loop). Tests replace it.
    init(
        block: ConfigApiBlock,
        api: (any AttestationApi)?,
        identityKey: @escaping @Sendable () throws -> any ClientIdentityKeyProvider,
        deviceId: @escaping @Sendable () -> String?,
        currentConfigVersion: @escaping @Sendable () -> Int,
        currentIssuedAt: @escaping @Sendable () -> Int64,
        liveConfig: @escaping @Sendable () -> CertificateConfig?,
        buildReport: @escaping @Sendable (_ nonce: String, _ deviceId: String, _ key: any ClientIdentityKeyProvider) async -> String,
        applyConfig: @escaping @Sendable (SignedConfigResponse) async throws -> UpdateResult,
        onConfigApplied: @escaping @Sendable (UpdateResult) -> Void = { _ in },
        onEvent: @escaping @Sendable (PinVaultConnectionEvent) -> Void = { _ in },
        onVerdict: @escaping @Sendable (_ warnings: [String], _ rejectionReasons: [String]) -> Void = { _, _ in },
        onRegistrationWanted: @escaping @Sendable () -> Void = {},
        clock: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
        jitter: @escaping @Sendable () -> Double = { Double.random(in: 0..<1) },
        sleep: @escaping @Sendable (Int64) async throws -> Void = { ms in
            try await Task.sleep(nanoseconds: UInt64(max(0, ms)) * 1_000_000)
        }
    ) {
        self.block = block
        self.api = api
        self.identityKey = identityKey
        self.deviceId = deviceId
        self.currentConfigVersion = currentConfigVersion
        self.currentIssuedAt = currentIssuedAt
        self.liveConfig = liveConfig
        self.buildReport = buildReport
        self.applyConfig = applyConfig
        self.onConfigApplied = onConfigApplied
        self.onEvent = onEvent
        self.onVerdict = onVerdict
        self.onRegistrationWanted = onRegistrationWanted
        self.clock = clock
        self.jitter = jitter
        self.sleep = sleep
        initialStatus = AttestationStatus(
            configApiId: block.id,
            result: api == nil ? .unsupported : .notAttested,
            lastError: api == nil ? Self.unsupportedReason : nil
        )
        state = Locked(State(status: initialStatus))
        configApiListener = Self.listener(of: block.configUrl)
    }

    /// The last outcome; what `PinVault.attestationStatus` returns.
    var status: AttestationStatus { state.withLock { $0.status } }

    /// True when this block attests (an `attestation()` block with the library's own client).
    var supported: Bool { api != nil }

    // MARK: Attesting

    /// Attests now and returns the outcome. Single flight: a caller that
    /// arrives while an attestation is running waits for that one and gets
    /// its result instead of starting another.
    func attestNow() async -> AttestationStatus {
        let (flight, id, mine) = state.withLock { state -> (Task<AttestationStatus, Never>, UInt64, Bool) in
            if let running = state.inFlight { return (running, state.flightId, false) }
            state.flightId &+= 1
            let task = Task { await self.attestOnce() }
            state.inFlight = task
            return (task, state.flightId, true)
        }
        if !mine {
            log.d("Attestation [\(block.id)] already running — waiting for its result")
            return await flight.value
        }
        let result = await flight.value
        state.withLock { state in
            if state.flightId == id { state.inFlight = nil }
        }
        return result
    }

    /// The token for the header, attesting first when none with enough life
    /// is held: ``AttestationTokenResult/token(value:expiresAt:)``, or why there is none.
    func fetchToken() async -> AttestationTokenResult {
        guard api != nil else { return .unsupported }
        if let held = heldToken(now: clock()) { return held }
        let outcome = await attestNow()
        if let held = heldToken(now: clock(), minRemainingMs: 0) { return held }
        if outcome.result == .reject { return .rejected(status: outcome) }
        return .failed(message: outcome.lastError ?? "The server passed the device but issued no token")
    }

    private func heldToken(now: Int64, minRemainingMs: Int64 = AttestationManager.tokenMinRemainingMs) -> AttestationTokenResult? {
        state.withLock { state in
            guard let value = state.token else { return nil }
            let expiresAt = state.tokenExpiresAt
            guard expiresAt - now >= minRemainingMs, expiresAt > now else { return nil }
            return .token(value: value, expiresAt: expiresAt)
        }
    }

    private func attestOnce() async -> AttestationStatus {
        guard let api else { return status }
        let startedAt = clock()
        let (previousSkew, chainWanted) = state.withLock { state -> (Int64?, Bool) in
            state.lastAttemptAt = startedAt
            return (state.status.clockSkewMs, state.chainWanted)
        }
        var skew = previousSkew
        do {
            let key = try identityKey()
            let did = Self.resolveDeviceId(deviceId())
            // The same key, with the same challenge, as an mTLS enrollment
            // makes: a device that never enrolls still has it from here on.
            try key.ensureKeyPair(attestationChallenge: ClientIdentityKeys.attestationChallenge(deviceUid: did))

            let challengeBody = try await api.attestChallenge()
            guard let challenge = LenientJSON.object(challengeBody) else {
                throw AttestationAnswerError("The attestation challenge answer is not JSON (\(Self.preview(challengeBody)))")
            }
            let nonce = LenientJSON.string(challenge, "nonce")
            if nonce.isBlank {
                throw AttestationAnswerError("The attestation challenge carries no nonce", kotlinName: "IllegalStateException")
            }
            let serverTime = LenientJSON.long(challenge, "serverTime", 0)
            if serverTime > 0 { skew = serverTime - clock() }

            let report = await buildReport(nonce, did, key)
            let canonical = Self.canonicalString(nonce: nonce, deviceId: did, report: report)
            let signature = Base64.encode(try key.sign(Data(canonical.utf8)))
            let chain = chainWanted ? attestationChain(of: key) : []

            var members: [IntegrityJSON.Member] = [
                .init("v", .int(Int64(Self.protocolVersion))),
                .init("nonce", .string(nonce)),
                .init("deviceId", .string(did)),
                .init("publicKey", .string(Base64.encode(try SPKI.der(for: key.publicKey())))),
                .init("report", .string(report)),
                .init("signature", .string(signature)),
                .init("currentConfigVersion", .int(Int64(currentConfigVersion()))),
                .init("currentIssuedAt", .int(currentIssuedAt())),
            ]
            if !chain.isEmpty { members.append(.init("attestationChain", .strings(chain))) }
            if !block.wantPinsFor.isEmpty { members.append(.init("hosts", .strings(block.wantPinsFor))) }

            let answerBody = try await api.attest(body: Data(IntegrityJSON.object(members).serialized.utf8))
            guard let answer = LenientJSON.object(answerBody) else {
                throw AttestationAnswerError("The attestation attest answer is not JSON (\(Self.preview(answerBody)))")
            }
            // Answered with a verdict: the key is registered; the chain has done its work.
            state.withLock { $0.chainWanted = false }
            return await handleVerdict(answer, skew: skew)
        } catch let error as AttestationHttpError {
            if Self.chainWantedAgain.contains(error.serverError ?? "") {
                state.withLock { $0.chainWanted = true }
                // iOS: the App Attest attestation stands in for the chain (PORTING.md §6).
                onRegistrationWanted()
            }
            return failed(error.message, skew: skew)
        } catch is CancellationError {
            // Cancelled (reset during a round): nothing to report.
            return status
        } catch {
            return failed("\(Self.errorName(error)): \(Self.errorMessage(error))", skew: skew)
        }
    }

    private func handleVerdict(_ answer: [String: Any], skew: Int64?) async -> AttestationStatus {
        let now = clock()
        let arc = LenientJSON.nonBlankString(answer, "arc")
        let warnings = LenientJSON.strings(answer, "warnings")
        let reasons = LenientJSON.strings(answer, "rejectionReasons")
        let policyVersion = LenientJSON.hasValue(answer, "policyVersion") ? Int(clamping: LenientJSON.long(answer, "policyVersion", 0)) : nil
        let nextAttestIn = LenientJSON.long(answer, "nextAttestIn", 0)
        let nextAttestInMs: Int64? = nextAttestIn > 0 ? nextAttestIn * 1000 : nil

        switch LenientJSON.string(answer, "result") {
        case "pass":
            let issued = LenientJSON.nonBlankString(answer, "token")
            let ttl = LenientJSON.long(answer, "tokenTtlSeconds", 0)
            // Device-clock expiry: the server's `tokenExpiresAt` is in its
            // own time, so the TTL is preferred and the skew applied otherwise.
            let expiresAt: Int64?
            if issued == nil {
                expiresAt = nil
            } else if ttl > 0 {
                expiresAt = now + ttl * 1000
            } else {
                let serverExpiry = LenientJSON.long(answer, "tokenExpiresAt", 0)
                expiresAt = serverExpiry > 0 ? serverExpiry - (skew ?? 0) : now + Self.defaultTokenTtlMs
            }
            if issued == nil {
                log.w("Attestation [\(block.id)] passed, but the server issued no token")
            }
            let delay = Self.refreshDelayMs(
                nextAttestInMs: nextAttestInMs, blockIntervalMs: block.attestationIntervalMs,
                tokenExpiresAt: expiresAt, now: now, jitter: jitter()
            )
            let passed = AttestationStatus(
                configApiId: block.id,
                result: .pass,
                arc: arc,
                rejectionReasons: [],
                warnings: warnings,
                tokenExpiresAt: expiresAt,
                lastAttestedAt: now,
                nextAttestAt: now + delay,
                clockSkewMs: skew,
                lastError: nil,
                policyVersion: policyVersion
            )
            state.withLock { state in
                state.token = issued
                state.tokenExpiresAt = issued == nil ? 0 : (expiresAt ?? 0)
                state.consecutiveFailures = 0
            }
            log.i("Attestation [\(block.id)] passed (arc=\(Self.text(arc)), warnings=\(Self.text(warnings)), token until \(Self.text(expiresAt)))")
            publish(passed, .pass, failureReason: nil)
            onVerdict(warnings, [])
            // The config rides along only on a pass, and goes through the
            // same checks as a fetched one.
            if let config = answer["config"] as? [String: Any] {
                await applyEmbeddedConfig(config)
            }
            return passed

        case "reject":
            let delay = Self.refreshDelayMs(
                nextAttestInMs: nextAttestInMs, blockIntervalMs: block.attestationIntervalMs,
                tokenExpiresAt: nil, now: now, jitter: jitter()
            )
            let rejected = AttestationStatus(
                configApiId: block.id,
                result: .reject,
                arc: arc,
                rejectionReasons: reasons,
                warnings: warnings,
                tokenExpiresAt: nil,
                lastAttestedAt: now,
                nextAttestAt: now + delay,
                clockSkewMs: skew,
                lastError: nil,
                policyVersion: policyVersion
            )
            state.withLock { state in
                state.token = nil
                state.tokenExpiresAt = 0
                state.consecutiveFailures = 0
            }
            log.w("Attestation [\(block.id)] rejected (arc=\(Self.text(arc)), reasons=\(Self.text(reasons)))")
            publish(rejected, .reject, failureReason: nil)
            onVerdict(warnings, reasons)
            return rejected

        case let result:
            return failed("The attestation answer has an unknown result '\(String(result.prefix(32)))'", skew: skew)
        }
    }

    private func applyEmbeddedConfig(_ json: [String: Any]) async {
        let signed: SignedConfigResponse
        do {
            let data = try JSONSerialization.data(withJSONObject: json, options: [])
            signed = try JSONDecoder().decode(SignedConfigResponse.self, from: data)
        } catch {
            log.w("Attestation [\(block.id)]: the embedded config is not a signed envelope — ignored", error)
            return
        }
        let result: UpdateResult
        do {
            result = try await applyConfig(signed)
        } catch {
            result = .failed(reason: Self.errorMessage(error), exception: error)
        }
        log.d("Attestation [\(block.id)]: embedded config → \(result)")
        onConfigApplied(result)
    }

    private func failed(_ reason: String, skew: Int64?) -> AttestationStatus {
        let now = clock()
        let (failedStatus, attempt) = state.withLock { state -> (AttestationStatus, Int) in
            state.consecutiveFailures += 1
            // The last token is kept until it expires (the loop keeps trying).
            if state.tokenExpiresAt <= now {
                state.token = nil
                state.tokenExpiresAt = 0
            }
            var next = state.status
            next.result = .failed
            next.tokenExpiresAt = state.token == nil ? nil : state.tokenExpiresAt
            next.nextAttestAt = now + Self.backoffMs(consecutiveFailures: state.consecutiveFailures)
            next.clockSkewMs = skew ?? state.status.clockSkewMs
            next.lastError = reason
            return (next, state.consecutiveFailures)
        }
        log.w("Attestation [\(block.id)] failed: \(reason) (attempt \(attempt))")
        publish(failedStatus, .failed, failureReason: reason)
        return failedStatus
    }

    private func publish(_ newStatus: AttestationStatus, _ eventStatus: AttestationEventStatus, failureReason: String?) {
        state.withLock { $0.status = newStatus }
        onEvent(.attestation(
            configApiId: block.id,
            status: eventStatus,
            arc: newStatus.arc,
            rejectionReasons: newStatus.rejectionReasons,
            warnings: newStatus.warnings,
            tokenExpiresAt: newStatus.tokenExpiresAt,
            deviceManufacturer: DeviceInfo.manufacturer,
            deviceModel: DeviceInfo.model,
            failureReason: failureReason
        ))
    }

    private func attestationChain(of key: any ClientIdentityKeyProvider) -> [String] {
        key.attestationChain().map(Base64.encode)
    }

    // MARK: The refresh loop

    /// Starts re-attesting in the background at `min(nextAttestIn, interval,
    /// tokenExpiry − 60 s)` with jitter, backing off 30 s → 5 min on failure.
    /// No-op for an unsupported block, and while already running.
    func start() {
        guard api != nil else { return }
        let sleep = self.sleep
        state.withLock { state in
            guard state.loop == nil else { return }
            state.loop = Task { [weak self] in
                while !Task.isCancelled {
                    guard let wait = self?.nextWaitMs() else { return }
                    do {
                        try await sleep(wait)
                    } catch {
                        return
                    }
                    if Task.isCancelled { return }
                    guard let self else { return }
                    _ = await self.attestNow()
                }
            }
        }
    }

    /// Stops the refresh loop. The token and the status stay.
    func stop() {
        let loop = state.withLock { state -> Task<Void, Never>? in
            let loop = state.loop
            state.loop = nil
            return loop
        }
        loop?.cancel()
    }

    /// True while the refresh loop runs.
    var isRunning: Bool { state.withLock { $0.loop != nil } }

    /// ``stop()``, and forgets the token and the status — `PinVault.reset()`.
    func reset() {
        stop()
        let initial = initialStatus
        state.withLock { state in
            state.token = nil
            state.tokenExpiresAt = 0
            state.consecutiveFailures = 0
            state.chainWanted = true
            state.lastAttemptAt = nil
            state.status = initial
        }
    }

    private func nextWaitMs() -> Int64 {
        let now = clock()
        let next = state.withLock { $0.status.nextAttestAt }
        return max(next.map { $0 - now } ?? block.attestationIntervalMs, Self.minDelayMs)
    }

    // MARK: AttestationTokenSource

    func handlesHost(_ host: String, port: Int) -> Bool {
        api != nil && PinHostMatcher.match(tokenHostMap(), host, port: port) != nil
    }

    /// The hosts whose requests carry the token: the block's `tokenHosts`,
    /// or — when it names none — every host pinned by the live config and
    /// the block's own Config API listener.
    private func tokenHostMap() -> PinHostMap<Bool> {
        let hosts: [String]
        if !block.tokenHosts.isEmpty {
            hosts = block.tokenHosts
        } else {
            hosts = (liveConfig()?.pins.map(\.hostname) ?? []) + [configApiListener].compactMap { $0 }
        }
        return PinHostMatcher.build(hosts.map { ($0.lowercased(), true) })
    }

    func token(host: String, port: Int, forceRefresh: Bool) async -> String? {
        guard api != nil else { return nil }
        let now = clock()
        let (held, mayAttest) = state.withLock { state -> (String?, Bool) in
            let held = state.token.flatMap { state.tokenExpiresAt - now >= Self.tokenMinRemainingMs ? $0 : nil }
            return (held, Self.mayAttestOnDemand(state, now: now, force: forceRefresh))
        }
        if !forceRefresh, let held { return held }
        if !mayAttest { return held }
        _ = await attestNow()
        let after = clock()
        return state.withLock { state in
            state.token.flatMap { state.tokenExpiresAt > after ? $0 : nil }
        }
    }

    /// Whether a request may trigger an attestation now. A passing device
    /// whose token ran out always may (a forced one after a 401 only once per
    /// ``reattestGapMs``, so a backend that refuses every token does not make
    /// every request attest); a rejected or failing device waits for its
    /// scheduled next attempt, so requests do not turn a reject into a storm.
    private static func mayAttestOnDemand(_ state: State, now: Int64, force: Bool) -> Bool {
        guard let last = state.lastAttemptAt else { return true }
        switch state.status.result {
        case .pass, .notAttested:
            return !force || now - last >= reattestGapMs
        default:
            return now >= (state.status.nextAttestAt ?? 0)
        }
    }

    // MARK: Helpers

    /// `pinvault-attest:v1:<nonce>:<deviceId>:<sha256-hex(report)>` (`ATTESTATION.md` §2.2).
    static func canonicalString(nonce: String, deviceId: String, report: String) -> String {
        "pinvault-attest:v1:\(nonce):\(deviceId):\(sha256Hex(Data(report.utf8)))"
    }

    static func sha256Hex(_ bytes: Data) -> String {
        Hashing.sha256Hex(bytes)
    }

    /// The device id as the request carries it: the server's rule for the
    /// field (`^[A-Za-z0-9._:-]{1,64}$`), or `unknown-device` — a device
    /// without an id still attests, under a fixed name, as it enrolls.
    static func resolveDeviceId(_ id: String?) -> String {
        let trimmed = (id ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let valid = !trimmed.isEmpty && trimmed.utf8.count <= 64 && trimmed.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
                || byte == 0x2E || byte == 0x5F || byte == 0x3A || byte == 0x2D
        }
        return valid ? trimmed : unknownDeviceId
    }

    /// How long to wait before the next scheduled attestation after a
    /// verdict: the least of the server's `nextAttestIn`, the block's
    /// interval and the token's expiry minus ``expiryMarginMs``, at least
    /// ``minDelayMs``, spread by ±``jitterSpread`` with `jitter` in [0, 1).
    static func refreshDelayMs(nextAttestInMs: Int64?, blockIntervalMs: Int64, tokenExpiresAt: Int64?, now: Int64, jitter: Double) -> Int64 {
        var base = min(nextAttestInMs ?? blockIntervalMs, blockIntervalMs)
        if let tokenExpiresAt { base = min(base, tokenExpiresAt - now - expiryMarginMs) }
        base = max(base, minDelayMs)
        let spread = Int64(Double(base) * jitterSpread * (2 * min(max(jitter, 0), 1) - 1))
        return max(base + spread, minDelayMs)
    }

    /// The wait after the `consecutiveFailures`-th failure in a row: 30 s doubling up to 5 min.
    static func backoffMs(consecutiveFailures: Int) -> Int64 {
        let exponent = min(max(consecutiveFailures - 1, 0), 10)
        return min(backoffMinMs << Int64(exponent), backoffMaxMs)
    }

    /// `host:port` of the block's Config API listener (the scheme's port when none is given).
    static func listener(of configUrl: String) -> String? {
        guard let components = URLComponents(string: configUrl), let host = components.host, !host.isEmpty else { return nil }
        let port = components.port ?? (components.scheme?.lowercased() == "http" ? 80 : 443)
        return "\(host.lowercased()):\(port)"
    }

    /// Kotlin's `e.javaClass.simpleName` for the failure text.
    static func errorName(_ error: any Error) -> String {
        switch error {
        case let error as PinVaultError: return error.exceptionName
        case let error as AttestationAnswerError: return error.kotlinName
        case is URLError: return "URLError"
        default: return String(describing: type(of: error))
        }
    }

    /// Kotlin's `e.message`: the library's own texts, the system's localized description otherwise.
    static func errorMessage(_ error: any Error) -> String {
        switch error {
        case let error as PinVaultError: return error.message
        case let error as AttestationAnswerError: return error.description
        case let error as AttestationHttpError: return error.message
        case let error as AppAttestServiceError: return error.description
        case let error as ProbeReadError: return error.description
        default: return error.localizedDescription
        }
    }

    private static func preview(_ body: Data) -> String {
        String(decoding: body.prefix(80), as: UTF8.self)
    }

    /// Kotlin `toString()` of the values in the log lines: `null`, `[a, b]`.
    private static func text(_ value: String?) -> String { value ?? "null" }
    private static func text(_ value: Int64?) -> String { value.map(String.init) ?? "null" }
    private static func text(_ values: [String]) -> String { "[" + values.joined(separator: ", ") + "]" }
}

/// An attestation answer the library cannot use (not JSON, no nonce).
struct AttestationAnswerError: Error, CustomStringConvertible {
    let description: String
    /// The Kotlin exception class the same failure is reported as.
    let kotlinName: String

    init(_ description: String, kotlinName: String = "Exception") {
        self.description = description
        self.kotlinName = kotlinName
    }
}
