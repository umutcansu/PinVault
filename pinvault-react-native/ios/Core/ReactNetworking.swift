// React Native's own https traffic (fetch, XMLHttpRequest, <Image>) through
// PinVault's pinned session — the engine behind RNPinVaultURLRequestHandler,
// the RCTURLRequestHandler that RCTNetworking prefers over its
// RCTHTTPRequestHandler for https. Foundation only, so it is tested on the Mac.
//
// The rules are the Android hook's:
// - before `start()` (and after a start that failed: the library's session
//   then refuses every request) every https request fails — fail closed;
// - pinning, `PinVault-Token`, pin-mismatch recovery: the library's session;
//   a redirect from https into plain http is not followed (the library's
//   sessions never follow one; the 3xx is the answer);
// - no cookies and no cache (the library's sessions are ephemeral, without a
//   cookie store or URL cache);
// - a release build (`#if DEBUG` off) refuses plain http and ws, every host,
//   before and after `start()` (`cleartextRefused`); a debug build leaves
//   them to RN (Metro, the dev tools). No switch other than the Info.plist
//   opt-out of the whole hook (`PinVaultPinReactNativeNetworking` = NO), as
//   Android's only way out is removing its networking provider;
// - the answer is bounded (`maxResponseBytes`, default 50 MiB): the library
//   stops reading past it.
//
// The library hands out whole answers (`PinnedSession.data(for:)`), so RN
// gets the response, then the body in chunks, then the completion — after the
// body has been read; progress events arrive at the end.
import Foundation

public enum ReactNetworking {
    public static let defaultMaxResponseBytes: Int64 = 50 * 1024 * 1024
    public static let maxResponseBytesLimit: Int64 = 256 * 1024 * 1024
    /// Body pieces handed to RN's delegate.
    public static let chunkSize = 64 * 1024
    public static let errorDomain = "PinVault"

    /// What a request needs: `send` = the pinned session's bounded `data(for:maxResponseBytes:)`,
    /// nil before `start()`.
    public typealias Send = @Sendable (URLRequest, Int64) async throws -> (Data, URLResponse)

    /// RN's `RCTURLRequestDelegate`, as blocks (Core does not link React).
    public struct Callbacks: @unchecked Sendable {
        public let didSendData: (Int64) -> Void
        public let didReceiveResponse: (URLResponse) -> Void
        public let didReceiveData: (Data) -> Void
        public let didComplete: ((any Error)?) -> Void

        public init(
            didSendData: @escaping (Int64) -> Void,
            didReceiveResponse: @escaping (URLResponse) -> Void,
            didReceiveData: @escaping (Data) -> Void,
            didComplete: @escaping ((any Error)?) -> Void
        ) {
            self.didSendData = didSendData
            self.didReceiveResponse = didReceiveResponse
            self.didReceiveData = didReceiveData
            self.didComplete = didComplete
        }
    }

    /// https always. Plain http only with [httpsOnly] (a release build): it is
    /// claimed so that it can be refused (``prepare``) instead of going to RN's
    /// own, unpinned handler. Without it (debug: Metro, the dev tools) plain
    /// http stays with RN's handler (ATS refuses it unless the app allows it).
    /// Other schemes (file, data, blob) are never claimed.
    public static func handles(_ request: URLRequest, httpsOnly: Bool = false) -> Bool {
        switch request.url?.scheme?.lowercased() {
        case "https": return true
        case "http": return httpsOnly
        default: return false
        }
    }

    /// The refusal of plain http / ws through React Native's networking in a
    /// release build — Android's rule (PinVaultNetworking.kt: no cleartext
    /// connection spec on any client its hooks touch, before and after
    /// `start()`, every host): nothing checks a pin on a request that goes
    /// out in the clear. OkHttp's wording.
    public static func cleartextRefused() -> NSError {
        error(
            "UnknownServiceException",
            "CLEARTEXT communication not enabled for client: a release build refuses plain http / ws through React Native's networking"
        )
    }

    /// RNPinVaultURLRequestHandler's `canHandleRequest:`. [enabled] = the
    /// Info.plist switch `PinVaultPinReactNativeNetworking` (NO: nothing is
    /// claimed, http and https stay with RN — Android's "remove the provider").
    public static func claims(_ request: URLRequest, enabled: Bool, httpsOnly: Bool) -> Bool {
        enabled && handles(request, httpsOnly: httpsOnly)
    }

    /// The error a WebSocket to [url] fails with before it connects
    /// (RNPinVaultWebSocketPinning.mm), nil when it may connect: with
    /// [httpsOnly] (a release build) every URL SocketRocket would open without
    /// TLS is refused (its SRURLRequiresSSL: only wss / https get TLS).
    /// [enabled] = the Info.plist switch, which also leaves the hook out.
    public static func webSocketRefusal(_ url: URL?, enabled: Bool, httpsOnly: Bool) -> NSError? {
        guard enabled, httpsOnly else { return nil }
        let scheme = url?.scheme?.lowercased()
        return scheme == "wss" || scheme == "https" ? nil : cleartextRefused()
    }

    /// The error RN hands to JS (`fetch` rejects with "Network request failed").
    public static func error(_ name: String, _ message: String) -> NSError {
        NSError(domain: errorDomain, code: 1, userInfo: [
            NSLocalizedDescriptionKey: "\(name): \(message)",
            "exceptionName": name,
        ])
    }

    /// ``prepare(_:send:maxResponseBytes:describe:callbacks:)`` + `resume()`.
    @discardableResult
    public static func start(
        _ request: URLRequest,
        send: Send?,
        maxResponseBytes: Int64,
        describe: @escaping @Sendable (any Error) -> (String, String),
        callbacks: Callbacks
    ) -> ReactNetworkingTask {
        let task = prepare(request, send: send, maxResponseBytes: maxResponseBytes, describe: describe, callbacks: callbacks)
        task.resume()
        return task
    }

    /// The request, not started yet: the task is the request token RN keeps,
    /// and nothing reaches the delegate before `resume()` (RN's rule: the
    /// token first, then the callbacks).
    /// - Parameter describe: an error → (exception name, message) for JS.
    public static func prepare(
        _ request: URLRequest,
        send: Send?,
        maxResponseBytes: Int64,
        describe: @escaping @Sendable (any Error) -> (String, String),
        callbacks: Callbacks
    ) -> ReactNetworkingTask {
        let task = ReactNetworkingTask(callbacks)
        let sent = Int64(request.httpBody?.count ?? 0)
        // Only https is sent: anything else that reached this handler was
        // claimed to be refused (``handles(_:httpsOnly:)``), before start or after.
        let https = request.url?.scheme?.lowercased() == "https"
        task.body = {
            guard https else { throw ReactNetworking.cleartextRefused() }
            guard let send else {
                throw ReactNetworking.error(
                    "IllegalStateException", "PinVault has not started: https requests are refused until start() returns"
                )
            }
            do {
                let (data, response) = try await send(request, maxResponseBytes)
                return (data, response, sent)
            } catch {
                let (name, message) = describe(error)
                throw ReactNetworking.error(name, message)
            }
        }
        return task
    }
}

/// One React Native request: its token, and its cancellation.
@objc(RNPinVaultReactNetworkingTask)
public final class ReactNetworkingTask: NSObject, @unchecked Sendable {
    private let callbacks: ReactNetworking.Callbacks
    private let lock = NSLock()
    private var work: _Concurrency.Task<Void, Never>?
    private var cancelled = false
    /// Set by `prepare`, run by `resume`.
    var body: (@Sendable () async throws -> (Data, URLResponse, Int64))?

    init(_ callbacks: ReactNetworking.Callbacks) {
        self.callbacks = callbacks
    }

    public var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    /// RN cancelled (`cancelRequest:`): the request stops, the delegate hears nothing more.
    @objc public func cancel() {
        lock.lock()
        cancelled = true
        let w = work
        lock.unlock()
        w?.cancel()
    }

    /// Sends the request (once).
    @objc public func resume() {
        lock.lock()
        let body = self.body
        self.body = nil
        lock.unlock()
        guard let body else { return }
        let callbacks = self.callbacks
        let w = _Concurrency.Task.detached { [self] in
            do {
                let (data, response, sent) = try await body()
                if isCancelled { return }
                if sent > 0 { callbacks.didSendData(sent) }
                callbacks.didReceiveResponse(response)
                var offset = 0
                while offset < data.count {
                    if isCancelled { return }
                    let end = min(offset + ReactNetworking.chunkSize, data.count)
                    callbacks.didReceiveData(data.subdata(in: offset..<end))
                    offset = end
                }
                callbacks.didComplete(nil)
            } catch {
                if isCancelled { return }
                callbacks.didComplete(error)
            }
        }
        lock.lock()
        work = w
        let alreadyCancelled = cancelled
        lock.unlock()
        if alreadyCancelled { w.cancel() }
    }
}
