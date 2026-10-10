// The Swift side of the Flutter plugin (the MethodChannel delegate). It calls
// PinVault.shared and nothing else: no pinning, key handling or vault
// decryption happens in this file. Inputs are parsed by ConfigParser and
// PinnedFetch, results mapped by ResultMapper, guard requests emitted to the
// `pinvault_flutter/guard` EventChannel.
import Foundation
import PinVault
import Flutter
#if canImport(UIKit)
import UIKit
#endif

public class SwiftPinVaultFlutterPlugin: NSObject, FlutterPlugin {

    // Process-wide, like the library: a Dart hot reload makes a new plugin
    // object, not a new PinVault. These stay put across reloads.
    static let tokens = VaultTokenStore()
    private static let lock = NSLock()
    private static var startedInProcess = false
    private static var dartGuard: DartEnvironmentGuard?
    private static weak var current: SwiftPinVaultFlutterPlugin?
    private static let startQueue = StartQueue()

    // The connection events and guard requests cross the EventChannels; their
    // sinks are process-wide (a hot reload replaces the stream handlers, not
    // the library).
    private static var eventsSink: FlutterEventSink?
    private static var guardSink: FlutterEventSink?

    // The messenger for the per-socket channels `ws_connect` creates.
    private static var messenger: FlutterBinaryMessenger?

    // Live WebSocket connections, by socket id.
    private static var sockets: [String: PinVaultWebSocketConnection] = [:]

    private let mapper = ResultMapper(tokens: SwiftPinVaultFlutterPlugin.tokens)

    // MARK: registration

    public static func register(with registrar: FlutterPluginRegistrar) {
        Self.messenger = registrar.messenger()

        let method = FlutterMethodChannel(name: "pinvault_flutter", binaryMessenger: registrar.messenger())
        let instance = SwiftPinVaultFlutterPlugin()
        registrar.addMethodCallDelegate(instance, channel: method)

        let events = FlutterEventChannel(name: "pinvault_flutter/events", binaryMessenger: registrar.messenger())
        events.setStreamHandler(EventsStreamHandler())

        let guardChannel = FlutterEventChannel(name: "pinvault_flutter/guard", binaryMessenger: registrar.messenger())
        guardChannel.setStreamHandler(GuardStreamHandler())
    }

    // MARK: helpers

    private static func locked<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    private static var started: Bool {
        lock.lock(); defer { lock.unlock() }
        return startedInProcess
    }

    fileprivate static func setEventsSink(_ sink: FlutterEventSink?) {
        lock.lock(); eventsSink = sink; lock.unlock()
    }

    fileprivate static func setGuardSink(_ sink: FlutterEventSink?) {
        lock.lock(); guardSink = sink; lock.unlock()
    }

    private static func emitGuardRequest(_ requestId: String, _ operation: String) {
        let sink = locked { guardSink }
        sink?(["requestId": requestId, "operation": operation])
    }

    private static func emitConnectionEvent(_ event: PinVaultConnectionEvent) {
        let sink = locked { eventsSink }
        sink?(ResultMapper(tokens: tokens).event(event))
    }

    static func addSocket(_ id: String, _ connection: PinVaultWebSocketConnection) {
        lock.lock(); defer { lock.unlock() }
        sockets[id] = connection
    }

    static func removeSocket(_ id: String) {
        lock.lock(); defer { lock.unlock() }
        sockets.removeValue(forKey: id)
    }

    /// Runs a library call with the Dart guard's verdicts on `operations` asked
    /// beforehand, so the library's synchronous guard check holds no thread.
    private static func guarded<T>(_ operations: [GuardedOperation], _ body: () async throws -> T) async rethrows -> T {
        guard let g = locked({ dartGuard }) else { return try await body() }
        return try await g.withVerdicts(operations, body)
    }

    private func run(_ result: @escaping FlutterResult, _ body: @escaping () async throws -> Any?) {
        Task.detached {
            do {
                result(try await body() ?? NSNull())
            } catch let e as BridgeInputError {
                result(FlutterError(code: "E_INVALID_ARGUMENT", message: Self.tokens.redact(e.message) ?? "", details: nil))
            } catch {
                result(FlutterError(
                    code: "E_NATIVE",
                    message: Self.tokens.redact("\(error)") ?? "",
                    details: self.exceptionInfo(error)
                ))
            }
        }
    }

    private func exceptionInfo(_ error: any Error) -> [String: Any] {
        let mapped = mapper.exception(error) as? [String: Any] ?? [:]
        return ["exceptionName": mapped["name"] ?? "Error", "exceptionMessage": mapped["message"] ?? NSNull()]
    }

    /// A vault file key: the library's rule (it names the stored copy's file).
    private static func checkKey(_ key: String) throws {
        let allowed = key.utf8.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) ||
                byte == 0x2E || byte == 0x5F || byte == 0x2D
        }
        if key.isEmpty || key.utf8.count > 64 || !allowed || key.allSatisfy({ $0 == "." }) {
            throw BridgeInputError("key: must match [A-Za-z0-9._-]{1,64} and not be only dots")
        }
    }

    private static func checkToken(_ token: String?) throws {
        if let token, token.count > 4096 { throw BridgeInputError("token: longer than 4096 characters") }
    }

    private static func invalidArgument(_ result: @escaping FlutterResult, _ message: String) {
        result(FlutterError(code: "E_INVALID_ARGUMENT", message: message, details: nil))
    }

    // MARK: dispatch

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        Self.lock.lock(); Self.current = self; Self.lock.unlock()

        switch call.method {
        case "start":
            guard let json = call.arguments as? String else {
                return Self.invalidArgument(result, "start: expected a JSON string")
            }
            handleStart(json, result: result)

        case "updateNow":
            run(result) { self.mapper.update(await PinVault.shared.updateNow()) }

        case "currentVersion":
            run(result) { PinVault.shared.currentVersion() }

        case "hostPinVersions":
            run(result) { PinVault.shared.hostPinVersions() }

        case "pinsForHost":
            guard let hostname = call.arguments as? String else {
                return Self.invalidArgument(result, "pinsForHost: expected a hostname string")
            }
            run(result) { ["pins": PinVault.shared.pinsForHost(hostname) ?? NSNull()] as [String: Any] }

        case "signingStatus":
            let configApiId = call.arguments as? String
            run(result) { PinVault.shared.signingStatus(configApiId: configApiId).map(self.mapper.signing) }

        case "isForceUpdate":
            run(result) { PinVault.shared.isForceUpdate() }

        case "reset":
            run(result) { PinVault.shared.reset(); return nil }

        case "schedulePeriodicUpdates":
            let intervalHours = Self.intValue(call.arguments)
            run(result) {
                guard Self.started else { return false }
                if let h = intervalHours, h < 1 || h > 24 * 30 {
                    throw BridgeInputError("intervalHours: must be between 1 and 720")
                }
                return PinVault.shared.schedulePeriodicUpdates(intervalHours: intervalHours.map { Int64($0) })
            }

        case "cancelPeriodicUpdates":
            run(result) { PinVault.shared.cancelPeriodicUpdates(); return nil }

        case "enableDebugLogging":
            run(result) {
                #if DEBUG
                PinVault.enableDebugLogging()
                return true
                #else
                return false
                #endif
            }

        case "fetch":
            guard let json = call.arguments as? String else {
                return Self.invalidArgument(result, "fetch: expected a JSON string")
            }
            handleFetch(json, result: result)

        case "deviceId":
            run(result) {
                #if canImport(UIKit)
                return await MainActor.run { UIDevice.current.identifierForVendor?.uuidString.lowercased() }
                #else
                return nil
                #endif
            }

        case "enrollForResult":
            let args = call.arguments as? [String: Any]
            guard let token = args?["token"] as? String else {
                return Self.invalidArgument(result, "enrollForResult: expected {token, label}")
            }
            let label = args?["label"] as? String
            run(result) {
                if token.isEmpty || token.count > 4096 { throw BridgeInputError("token: must be 1 to 4096 characters") }
                return await Self.tokens.withTransientSecret(token) {
                    self.mapper.enrollment(await Self.guarded([.enroll]) { await PinVault.shared.enrollForResult(token: token, label: label) })
                }
            }

        case "autoEnrollForResult":
            run(result) { self.mapper.enrollment(await Self.guarded([.enroll]) { await PinVault.shared.autoEnrollForResult() }) }

        case "checkPendingEnrollment":
            run(result) { self.mapper.enrollment(await Self.guarded([.enroll]) { await PinVault.shared.checkPendingEnrollment() }) }

        case "isEnrolled":
            let label = call.arguments as? String
            run(result) { PinVault.shared.isEnrolled(label: label) }

        case "isEnrollmentPending":
            let label = call.arguments as? String
            run(result) { PinVault.shared.isEnrollmentPending(label: label) }

        case "enrollmentVerificationCode":
            let label = call.arguments as? String
            run(result) { PinVault.shared.enrollmentVerificationCode(label: label) }

        case "enrolledClientCN":
            let label = call.arguments as? String
            run(result) { PinVault.shared.enrolledClientCN(label: label) }

        case "enrolledClientNotAfter":
            let label = call.arguments as? String
            run(result) { PinVault.shared.enrolledClientNotAfter(label: label) }

        case "unenroll":
            let args = call.arguments as? [String: Any]
            let label = args?["label"] as? String
            let wipe = (args?["wipeVaultFiles"] as? Bool) ?? false
            run(result) { PinVault.shared.unenroll(label: label, wipeVaultFiles: wipe); return nil }

        case "identityKeySecurityLevel":
            let label = call.arguments as? String
            run(result) { PinVault.shared.identityKeySecurityLevel(label: label)?.rawValue }

        case "setVaultToken":
            let args = call.arguments as? [String: Any]
            guard let key = args?["key"] as? String else {
                return Self.invalidArgument(result, "setVaultToken: expected {key, token}")
            }
            let token = args?["token"] as? String
            run(result) {
                try Self.checkKey(key)
                try Self.checkToken(token)
                Self.tokens.put(key, token)
                return nil
            }

        case "clearVaultTokens":
            run(result) { Self.tokens.clear() }

        case "fetchFile":
            let args = call.arguments as? [String: Any]
            guard let key = args?["key"] as? String else {
                return Self.invalidArgument(result, "fetchFile: expected {key, token}")
            }
            let token = args?["token"] as? String
            run(result) {
                try Self.checkKey(key)
                try Self.checkToken(token)
                if let token { Self.tokens.put(key, token) }
                return self.mapper.vaultFile(await Self.guarded([.fetchFile]) { await PinVault.shared.fetchFile(key) })
            }

        case "loadFile":
            let args = call.arguments as? [String: Any]
            guard let key = args?["key"] as? String else {
                return Self.invalidArgument(result, "loadFile: expected {key, encoding}")
            }
            let encoding = args?["encoding"] as? String ?? ResultMapper.utf8
            run(result) {
                try Self.checkKey(key)
                let enc = try ResultMapper.checkEncoding(encoding)
                return await Self.guarded([.loadFile]) { PinVault.shared.loadFile(key) }.map { ResultMapper.encode($0, enc) }
            }

        case "fileStatus":
            guard let key = call.arguments as? String else {
                return Self.invalidArgument(result, "fileStatus: expected a key string")
            }
            run(result) { try Self.checkKey(key); return PinVault.shared.fileStatus(key).rawValue }

        case "unlockFile":
            let args = call.arguments as? [String: Any]
            guard let key = args?["key"] as? String, let promptJSON = args?["prompt"] as? String else {
                return Self.invalidArgument(result, "unlockFile: expected {key, prompt}")
            }
            run(result) {
                try Self.checkKey(key)
                let (prompt, encoding) = try ConfigParser.unlockPrompt(promptJSON)
                // LAContext's Face ID / passcode prompt is the library's.
                return self.mapper.unlock(
                    await Self.guarded([.unlockFile]) { await PinVault.shared.unlockFile(key: key, prompt: prompt) },
                    encoding: encoding
                )
            }

        case "isFileLocked":
            guard let key = call.arguments as? String else {
                return Self.invalidArgument(result, "isFileLocked: expected a key string")
            }
            run(result) { try Self.checkKey(key); return PinVault.shared.isFileLocked(key) }

        case "hasFile":
            guard let key = call.arguments as? String else {
                return Self.invalidArgument(result, "hasFile: expected a key string")
            }
            run(result) { try Self.checkKey(key); return PinVault.shared.hasFile(key) }

        case "fileVersion":
            guard let key = call.arguments as? String else {
                return Self.invalidArgument(result, "fileVersion: expected a key string")
            }
            run(result) { try Self.checkKey(key); return PinVault.shared.fileVersion(key) }

        case "clearFile":
            guard let key = call.arguments as? String else {
                return Self.invalidArgument(result, "clearFile: expected a key string")
            }
            run(result) { try Self.checkKey(key); PinVault.shared.clearFile(key); return nil }

        case "syncAllFiles":
            run(result) { (await Self.guarded([.fetchFile]) { await PinVault.shared.syncAllFiles() }).mapValues(self.mapper.vaultFile) }

        case "attestNow":
            let configApiId = call.arguments as? String
            run(result) { self.mapper.attestation(await PinVault.shared.attestNow(configApiId: configApiId)) }

        case "fetchAttestationToken":
            let host = call.arguments as? String
            run(result) { self.mapper.attestationToken(await PinVault.shared.fetchAttestationToken(host: host)) }

        case "attestationStatus":
            let configApiId = call.arguments as? String
            run(result) { self.mapper.attestation(PinVault.shared.attestationStatus(configApiId: configApiId)) }

        case "answerGuard":
            let args = call.arguments as? [String: Any]
            guard let requestId = args?["requestId"] as? String, let allowed = args?["allowed"] as? Bool else {
                return Self.invalidArgument(result, "answerGuard: expected {requestId, allowed}")
            }
            let g = Self.locked { Self.dartGuard }
            g?.answer(requestId, allowed: allowed)
            result(nil)

        case "ws_connect":
            handleWebSocket(call.arguments, result: result)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private static func intValue(_ v: Any?) -> Int? {
        if let n = v as? NSNumber { return n.intValue }
        if let i = v as? Int { return i }
        return nil
    }

    // MARK: start

    private func handleStart(_ json: String, result: @escaping FlutterResult) {
        Task.detached {
            await Self.startQueue.run {
                let parsed: ParsedConfig
                var newGuard: DartEnvironmentGuard?
                do {
                    #if DEBUG
                    let release = false
                    #else
                    let release = true
                    #endif
                    parsed = try ConfigParser.parse(
                        json, tokens: Self.tokens,
                        guardFactory: { timeout in
                            let g = DartEnvironmentGuard(timeoutMs: timeout) { requestId, operation in
                                Self.emitGuardRequest(requestId, operation)
                            }
                            newGuard = g
                            return g
                        },
                        listener: { event in
                            Self.emitConnectionEvent(event)
                        },
                        native: try NativeSecurity.load(),
                        release: release,
                        noFileAllowed: NativeSecurity.noFileAllowed()
                    )
                } catch let e as BridgeInputError {
                    // The guard of the running config stays: a refused config changes nothing.
                    result(FlutterError(code: "E_INVALID_CONFIG", message: Self.tokens.redact(e.message) ?? "", details: nil))
                    return
                } catch {
                    let message = (error as? PinVaultError)?.message ?? "\(error)"
                    result(FlutterError(code: "E_INVALID_CONFIG", message: Self.tokens.redact(message) ?? "", details: nil))
                    return
                }
                Self.locked { Self.dartGuard = newGuard }
                // A second start applies the new config: the library keeps the
                // first one otherwise (the samples restart the same way).
                if Self.started { PinVault.shared.reset() }
                // INIT, and ENROLL for a pending enrollment the start picks up.
                let initResult = await Self.guarded([.start, .enroll]) { await PinVault.shared.start(config: parsed.config) }
                Self.locked { Self.startedInProcess = true }
                // Says whether the anchors came from the native security file (README "Native security file").
                var answer = ResultMapper(tokens: Self.tokens).initResult(initResult)
                answer["nativeSecurityApplied"] = parsed.nativeSecurityApplied
                result(answer)
            }
        }
    }

    // MARK: pinned HTTP

    private func handleFetch(_ json: String, result: @escaping FlutterResult) {
        Task.detached {
            let request: FetchRequest
            do {
                request = try PinnedFetch.parse(json)
            } catch let e as BridgeInputError {
                result(FlutterError(code: "E_INVALID_ARGUMENT", message: Self.tokens.redact(e.message) ?? "", details: nil))
                return
            } catch {
                result(FlutterError(code: "E_INVALID_ARGUMENT", message: Self.tokens.redact("\(error)") ?? "", details: nil))
                return
            }
            guard Self.started else {
                result(FlutterError(code: "E_NOT_STARTED", message: "PinVault has not started: call start() first", details: nil))
                return
            }
            let session = request.settings.map { PinVault.shared.session(settings: $0) } ?? PinVault.shared.session()
            do {
                result(try await PinnedFetch.execute(session, request))
            } catch {
                let info = self.exceptionInfo(error)
                let name = info["exceptionName"] as? String ?? "Error"
                let message = info["exceptionMessage"] as? String ?? ""
                result(FlutterError(code: "E_FETCH", message: "\(name): \(message)", details: info))
            }
        }
    }

    // MARK: WebSocket

    private func handleWebSocket(_ arguments: Any?, result: @escaping FlutterResult) {
        let args = arguments as? [String: Any]
        guard let socketId = args?["socketId"] as? String, !socketId.isEmpty else {
            return Self.invalidArgument(result, "ws_connect: expected {socketId, url, headers}")
        }
        guard let urlString = args?["url"] as? String, let url = URL(string: urlString) else {
            return Self.invalidArgument(result, "ws_connect: url is not a valid URL")
        }
        // Fail closed: only wss://, only with a host.
        guard url.scheme?.lowercased() == "wss", url.host != nil else {
            return Self.invalidArgument(result, "ws_connect: only wss:// URLs are accepted")
        }
        var headers: [String: String] = [:]
        if let raw = args?["headers"] as? [String: Any] {
            for (name, value) in raw {
                if let value = value as? String { headers[name] = value }
            }
        }

        guard let messenger = Self.messenger else {
            return Self.invalidArgument(result, "ws_connect: no Flutter binary messenger")
        }

        let connection = PinVaultWebSocketConnection(socketId: socketId, url: url, headers: headers)
        Self.addSocket(socketId, connection)

        let eventChannel = FlutterEventChannel(name: "pinvault_flutter/ws/\(socketId)/events", binaryMessenger: messenger)
        eventChannel.setStreamHandler(WebSocketStreamHandler(connection))

        let methodChannel = FlutterMethodChannel(name: "pinvault_flutter/ws/\(socketId)/methods", binaryMessenger: messenger)
        methodChannel.setMethodCallHandler { call, result in
            switch call.method {
            case "send":
                let a = call.arguments as? [String: Any]
                connection.send(data: a?["data"], binary: (a?["binary"] as? Bool) ?? false, result: result)
            case "close":
                let a = call.arguments as? [String: Any]
                let code = SwiftPinVaultFlutterPlugin.intValue(a?["code"]) ?? 1000
                let reason = a?["reason"] as? String
                connection.close(code: code, reason: reason, result: result)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

        result(nil)
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

// MARK: Event channel stream handlers

private final class EventsStreamHandler: NSObject, FlutterStreamHandler {
    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        SwiftPinVaultFlutterPlugin.setEventsSink(events)
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        SwiftPinVaultFlutterPlugin.setEventsSink(nil)
        return nil
    }
}

private final class GuardStreamHandler: NSObject, FlutterStreamHandler {
    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        SwiftPinVaultFlutterPlugin.setGuardSink(events)
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        SwiftPinVaultFlutterPlugin.setGuardSink(nil)
        return nil
    }
}

// MARK: WebSocket

/// One `wss://` connection over the library's pinned session
/// (`PinVault.shared.session().webSocketTask(with:)`), so the TLS handshake
/// runs the library's server-trust AND client-certificate (mTLS) decision —
/// the same delegate that answers data tasks' challenges. Fail closed: before
/// `start` (or after a failed one) the library refuses the socket, and only
/// `wss://` is accepted by the caller. The shared session is never invalidated
/// here (other requests ride it); only this socket's task is cancelled.
final class PinVaultWebSocketConnection: NSObject {
    let socketId: String
    let url: URL
    let headers: [String: String]

    private let lock = NSLock()
    private var task: URLSessionWebSocketTask?
    private var session: PinnedSession?
    private var events: FlutterEventSink?
    private var closed = false

    init(socketId: String, url: URL, headers: [String: String]) {
        self.socketId = socketId
        self.url = url
        self.headers = headers
        super.init()
    }

    /// Starts the connection; `events` receives the frames. Called when the
    /// Dart side listens on `pinvault_flutter/ws/<socketId>/events`.
    func open(events: @escaping FlutterEventSink) {
        lock.lock(); self.events = events; lock.unlock()

        do {
            let session = PinVault.shared.session()
            var request = URLRequest(url: url)
            for (name, value) in headers { request.addValue(value, forHTTPHeaderField: name) }
            let task = try session.webSocketTask(for: request)
            lock.lock(); self.session = session; self.task = task; lock.unlock()
            task.resume()
            receive()
        } catch {
            emit(["type": "error", "error": Self.describe(error)])
            finish()
        }
    }

    private func receive() {
        lock.lock(); let t = task; lock.unlock()
        t?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self.emit(["type": "message", "data": text])
                case .data(let data):
                    self.emit(["type": "message", "data": FlutterStandardTypedData(bytes: data)])
                @unknown default:
                    break
                }
                self.receive()
            case .failure(let error):
                // The library's session delegate is not a WebSocket delegate, so
                // a clean close also arrives here, not as a didClose callback.
                // A normal close leaves the task's closeCode set; an abnormal
                // failure leaves it `.invalid`.
                if let t, t.closeCode != .invalid {
                    self.emit(["type": "closed"])
                } else {
                    self.emit(["type": "error", "error": Self.describe(error)])
                }
                self.finish()
            }
        }
    }

    func send(data: Any?, binary: Bool, result: @escaping FlutterResult) {
        lock.lock(); let t = task; lock.unlock()
        guard let t else {
            result(FlutterError(code: "E_NO_ACTIVITY", message: "WebSocket is not connected", details: nil))
            return
        }
        let message: URLSessionWebSocketTask.Message
        if binary || data is FlutterStandardTypedData {
            let bytes: Data
            if let typed = data as? FlutterStandardTypedData {
                bytes = typed.data
            } else if let text = data as? String {
                bytes = Data(text.utf8)
            } else {
                result(FlutterError(code: "E_INVALID_ARGUMENT", message: "send: data must be a string or binary", details: nil))
                return
            }
            message = .data(bytes)
        } else {
            guard let text = data as? String else {
                result(FlutterError(code: "E_INVALID_ARGUMENT", message: "send: data must be a string or binary", details: nil))
                return
            }
            message = .string(text)
        }
        t.send(message) { error in
            if let error {
                result(FlutterError(code: "E_FETCH", message: Self.describe(error), details: nil))
            } else {
                result(nil)
            }
        }
    }

    func close(code: Int, reason: String?, result: @escaping FlutterResult) {
        lock.lock(); let t = task; lock.unlock()
        if let t {
            t.cancel(with: URLSessionWebSocketTask.CloseCode(rawValue: code) ?? .normalClosure, reason: reason.map { Data($0.utf8) })
        } else {
            finish()
        }
        result(nil)
    }

    func cancel() {
        lock.lock(); let t = task; lock.unlock()
        t?.cancel(with: .normalClosure, reason: nil)
        finish()
    }

    private func emit(_ map: [String: Any]) {
        lock.lock(); let sink = events; lock.unlock()
        sink?(map)
    }

    private func finish() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        events = nil
        task = nil
        session = nil
        lock.unlock()
        SwiftPinVaultFlutterPlugin.removeSocket(socketId)
    }

    static func describe(_ error: Error) -> String {
        let mapped = ResultMapper(tokens: SwiftPinVaultFlutterPlugin.tokens).exception(error) as? [String: Any] ?? [:]
        let name = mapped["name"] as? String ?? "Error"
        let message = mapped["message"] as? String ?? ""
        return "\(name): \(message)"
    }
}

private final class WebSocketStreamHandler: NSObject, FlutterStreamHandler {
    let connection: PinVaultWebSocketConnection

    init(_ connection: PinVaultWebSocketConnection) { self.connection = connection }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        connection.open(events: events)
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        connection.cancel()
        return nil
    }
}
