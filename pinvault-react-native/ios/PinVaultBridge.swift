// The Swift side of the TurboModule (RNPinVault.mm forwards every method here).
// It calls PinVault.shared and nothing else: no pinning, key handling or vault
// decryption happens in this file. Inputs are parsed by Core/ConfigParser and
// Core/PinnedFetch, results mapped by Core/ResultMapper.
import Foundation
import PinVault
#if canImport(UIKit)
import UIKit
#endif

@objc(RNPinVaultBridge)
public final class PinVaultBridge: NSObject {
    public typealias Resolve = (Any?) -> Void
    public typealias Reject = (String, String, [String: Any]?) -> Void

    // Process-wide, like the library: a JS reload makes a new module, not a new PinVault.
    private static let tokens = VaultTokenStore()
    private static let lock = NSLock()
    private static var startedInProcess = false
    private static var jsGuard: JSEnvironmentGuard?
    private static weak var current: PinVaultBridge?
    private static let startQueue = StartQueue()

    private let mapper = ResultMapper(tokens: PinVaultBridge.tokens)

    @objc public var emitConnectionEvent: (([String: Any]) -> Void)?
    @objc public var emitGuardRequest: (([String: Any]) -> Void)?

    /// `PinVault.shared.registerBackgroundTask()` for the app's AppDelegate (before launch ends):
    /// the app target does not link the PinVault package itself.
    @objc public static func registerBackgroundTask() -> Bool {
        PinVault.shared.registerBackgroundTask()
    }

    @objc public override init() {
        super.init()
        Self.lock.lock()
        Self.current = self
        Self.lock.unlock()
    }

    private static func locked<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    private static var started: Bool {
        lock.lock(); defer { lock.unlock() }
        return startedInProcess
    }

    // MARK: helpers

    private func run(_ resolve: @escaping Resolve, _ reject: @escaping Reject, _ body: @escaping () async throws -> Any?) {
        Task.detached {
            do {
                resolve(try await body() ?? NSNull())
            } catch let e as BridgeInputError {
                reject("E_INVALID_ARGUMENT", Self.tokens.redact(e.message) ?? "", nil)
            } catch {
                reject("E_NATIVE", Self.tokens.redact("\(error)") ?? "", self.exceptionInfo(error))
            }
        }
    }

    private func exceptionInfo(_ error: any Error) -> [String: Any] {
        let mapped = mapper.exception(error) as? [String: Any] ?? [:]
        return ["exceptionName": mapped["name"] ?? "Error", "exceptionMessage": mapped["message"] ?? NSNull()]
    }

    private static func checkKey(_ key: String) throws {
        if key.isEmpty || key.count > 128 { throw BridgeInputError("key: must be 1 to 128 characters") }
    }

    private static func checkToken(_ token: String?) throws {
        if let token, token.count > 4096 { throw BridgeInputError("token: longer than 4096 characters") }
    }

    // MARK: start / config

    @objc public func start(_ json: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        Task.detached {
            await Self.startQueue.run {
                let parsed: ParsedConfig
                do {
                    parsed = try ConfigParser.parse(
                        json, tokens: Self.tokens,
                        guardFactory: { timeout in
                            let g = JSEnvironmentGuard(timeoutMs: timeout) { requestId, operation in
                                let bridge = Self.locked { Self.current }
                                bridge?.emitGuardRequest?(["requestId": requestId, "operation": operation])
                            }
                            Self.locked { Self.jsGuard = g }
                            return g
                        },
                        listener: { event in
                            let bridge = Self.locked { Self.current }
                            guard let bridge else { return }
                            bridge.emitConnectionEvent?(bridge.mapper.event(event))
                        }
                    )
                } catch let e as BridgeInputError {
                    reject("E_INVALID_CONFIG", Self.tokens.redact(e.message) ?? "", nil)
                    return
                } catch {
                    let message = (error as? PinVaultError)?.message ?? "\(error)"
                    reject("E_INVALID_CONFIG", Self.tokens.redact(message) ?? "", nil)
                    return
                }
                if parsed.guardTimeoutMs == nil { Self.locked { Self.jsGuard = nil } }
                NSLog(
                    "PinVault: on iOS, React Native's own fetch / XMLHttpRequest / WebSocket are NOT pinned; "
                        + "send pinned requests with PinVault.fetch (README, \"Networking\")."
                )
                // A second start applies the new config: the library keeps the
                // first one otherwise (the samples restart the same way).
                if Self.started { PinVault.shared.reset() }
                let result = await PinVault.shared.start(config: parsed.config)
                Self.locked { Self.startedInProcess = true }
                resolve(self.mapper.initResult(result))
            }
        }
    }

    @objc public func updateNow(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { self.mapper.update(await PinVault.shared.updateNow()) }
    }

    @objc public func currentVersion(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.currentVersion() }
    }

    @objc public func hostPinVersions(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.hostPinVersions() }
    }

    @objc public func pinsForHost(_ hostname: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { ["pins": PinVault.shared.pinsForHost(hostname) ?? NSNull()] as [String: Any] }
    }

    @objc public func signingStatus(_ configApiId: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.signingStatus(configApiId: configApiId).map(self.mapper.signing) }
    }

    @objc public func isForceUpdate(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.isForceUpdate() }
    }

    @objc public func reset(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.reset(); return nil }
    }

    @objc public func schedulePeriodicUpdates(_ intervalHours: NSNumber?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            guard Self.started else { return false }
            if let h = intervalHours?.int64Value, h < 1 || h > 24 * 30 {
                throw BridgeInputError("intervalHours: must be between 1 and 720")
            }
            return PinVault.shared.schedulePeriodicUpdates(intervalHours: intervalHours?.int64Value)
        }
    }

    @objc public func cancelPeriodicUpdates(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.cancelPeriodicUpdates(); return nil }
    }

    @objc public func enableDebugLogging(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            #if DEBUG
            PinVault.enableDebugLogging()
            return true
            #else
            return false
            #endif
        }
    }

    // MARK: pinned HTTP

    @objc public func fetch(_ json: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        Task.detached {
            let request: FetchRequest
            do {
                request = try PinnedFetch.parse(json)
            } catch let e as BridgeInputError {
                reject("E_INVALID_ARGUMENT", Self.tokens.redact(e.message) ?? "", nil)
                return
            } catch {
                reject("E_INVALID_ARGUMENT", Self.tokens.redact("\(error)") ?? "", nil)
                return
            }
            guard Self.started else {
                reject("E_NOT_STARTED", "PinVault has not started: call start() first", nil)
                return
            }
            let session = request.settings.map { PinVault.shared.session(settings: $0) } ?? PinVault.shared.session()
            do {
                resolve(try await PinnedFetch.execute(session, request))
            } catch {
                let info = self.exceptionInfo(error)
                let name = info["exceptionName"] as? String ?? "Error"
                let message = info["exceptionMessage"] as? String ?? ""
                reject("E_FETCH", "\(name): \(message)", info)
            }
        }
    }

    // MARK: enrollment

    @objc public func deviceId(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            #if canImport(UIKit)
            return await MainActor.run { UIDevice.current.identifierForVendor?.uuidString.lowercased() }
            #else
            return nil
            #endif
        }
    }

    @objc public func enrollForResult(_ token: String, label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            if token.isEmpty || token.count > 4096 { throw BridgeInputError("token: must be 1 to 4096 characters") }
            return await Self.tokens.withTransientSecret(token) {
                self.mapper.enrollment(await PinVault.shared.enrollForResult(token: token, label: label))
            }
        }
    }

    @objc public func autoEnrollForResult(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { self.mapper.enrollment(await PinVault.shared.autoEnrollForResult()) }
    }

    @objc public func checkPendingEnrollment(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { self.mapper.enrollment(await PinVault.shared.checkPendingEnrollment()) }
    }

    @objc public func isEnrolled(_ label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.isEnrolled(label: label) }
    }

    @objc public func isEnrollmentPending(_ label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.isEnrollmentPending(label: label) }
    }

    @objc public func enrollmentVerificationCode(_ label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.enrollmentVerificationCode(label: label) }
    }

    @objc public func enrolledClientCN(_ label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.enrolledClientCN(label: label) }
    }

    @objc public func enrolledClientNotAfter(_ label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.enrolledClientNotAfter(label: label) }
    }

    @objc public func unenroll(_ label: String?, wipeVaultFiles: Bool, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.unenroll(label: label, wipeVaultFiles: wipeVaultFiles); return nil }
    }

    @objc public func identityKeySecurityLevel(_ label: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { PinVault.shared.identityKeySecurityLevel(label: label)?.rawValue }
    }

    // MARK: vault files

    @objc public func setVaultToken(_ key: String, token: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            try Self.checkKey(key)
            try Self.checkToken(token)
            Self.tokens.put(key, token)
            return nil
        }
    }

    @objc public func clearVaultTokens(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { Self.tokens.clear() }
    }

    @objc public func fetchFile(_ key: String, token: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            try Self.checkKey(key)
            try Self.checkToken(token)
            if let token { Self.tokens.put(key, token) }
            return self.mapper.vaultFile(await PinVault.shared.fetchFile(key))
        }
    }

    @objc public func loadFile(_ key: String, encoding: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            try Self.checkKey(key)
            let enc = try ResultMapper.checkEncoding(encoding)
            return PinVault.shared.loadFile(key).map { ResultMapper.encode($0, enc) }
        }
    }

    @objc public func fileStatus(_ key: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { try Self.checkKey(key); return PinVault.shared.fileStatus(key).rawValue }
    }

    @objc public func unlockFile(_ key: String, prompt json: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) {
            try Self.checkKey(key)
            let (prompt, encoding) = try ConfigParser.unlockPrompt(json)
            // LAContext's Face ID / passcode prompt is the library's.
            return self.mapper.unlock(await PinVault.shared.unlockFile(key: key, prompt: prompt), encoding: encoding)
        }
    }

    @objc public func isFileLocked(_ key: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { try Self.checkKey(key); return PinVault.shared.isFileLocked(key) }
    }

    @objc public func hasFile(_ key: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { try Self.checkKey(key); return PinVault.shared.hasFile(key) }
    }

    @objc public func fileVersion(_ key: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { try Self.checkKey(key); return PinVault.shared.fileVersion(key) }
    }

    @objc public func clearFile(_ key: String, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { try Self.checkKey(key); PinVault.shared.clearFile(key); return nil }
    }

    @objc public func syncAllFiles(resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { (await PinVault.shared.syncAllFiles()).mapValues(self.mapper.vaultFile) }
    }

    // MARK: attestation

    @objc public func attestNow(_ configApiId: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { self.mapper.attestation(await PinVault.shared.attestNow(configApiId: configApiId)) }
    }

    @objc public func fetchAttestationToken(_ host: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { self.mapper.attestationToken(await PinVault.shared.fetchAttestationToken(host: host)) }
    }

    @objc public func attestationStatus(_ configApiId: String?, resolve: @escaping Resolve, reject: @escaping Reject) {
        run(resolve, reject) { self.mapper.attestation(PinVault.shared.attestationStatus(configApiId: configApiId)) }
    }

    // MARK: environmentGuard

    @objc public func answerGuard(_ requestId: String, allowed: Bool) {
        let g = Self.locked { Self.jsGuard }
        g?.answer(requestId, allowed: allowed)
    }
}

/// Serialises `start` calls (a second start resets and starts again).
private actor StartQueue {
    private var tail: Task<Void, Never>?

    func run(_ body: @escaping @Sendable () async -> Void) async {
        let previous = tail
        let task = Task {
            await previous?.value
            await body()
        }
        tail = task
        await task.value
    }
}
