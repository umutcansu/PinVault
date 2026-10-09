// The Swift side of RNPinVaultURLRequestHandler.mm: React Native's https
// requests (fetch, XMLHttpRequest, <Image>) through PinVault's pinned session.
// The rules live in Core/ReactNetworking.swift.
import Foundation
import Security
import PinVault

@objc(RNPinVaultReactNetworking)
public final class PinVaultReactNetworking: NSObject {

    /// Info.plist `PinVaultPinReactNativeNetworking` = NO hands https back to
    /// React Native's own (unpinned) handler — a native opt-out, which a JS
    /// bundle cannot flip. Default: on.
    @objc public static let enabled: Bool =
        (Bundle.main.object(forInfoDictionaryKey: "PinVaultPinReactNativeNetworking") as? Bool) ?? true

    @objc public static func canHandle(_ request: URLRequest) -> Bool {
        enabled && ReactNetworking.handles(request)
    }

    /// The server-trust check of a `wss` WebSocket (RNPinVaultWebSocketPinning.mm):
    /// the decision of every PinVault session for the host and port the socket
    /// was opened for. Fail-closed: before `start`, after a failed one, or
    /// while a restart resets the library, every handshake is refused.
    @objc public static func acceptsWebSocketTrust(_ trust: SecTrust, host: String, port: Int) -> Bool {
        do {
            try PinVault.shared.evaluateServerTrust(trust, host: host, port: port)
            return true
        } catch {
            let (name, message) = PinVaultBridge.describe(error)
            NSLog("PinVault: WebSocket to %@:%ld refused (%@: %@)", host, port, name, message)
            return false
        }
    }

    /// The request token for RN; nothing reaches the blocks before `resume()`.
    @objc public static func prepare(
        _ request: URLRequest,
        didSendData: @escaping (Int64) -> Void,
        didReceiveResponse: @escaping (URLResponse) -> Void,
        didReceiveData: @escaping (Data) -> Void,
        didComplete: @escaping (NSError?) -> Void
    ) -> ReactNetworkingTask {
        var send: ReactNetworking.Send?
        if PinVaultBridge.isStarted {
            send = { (request: URLRequest, limit: Int64) async throws -> (Data, URLResponse) in
                try await PinVault.shared.session().data(for: request, maxResponseBytes: limit)
            }
        }
        return ReactNetworking.prepare(
            request,
            send: send,
            maxResponseBytes: PinVaultBridge.reactNativeMaxResponseBytes,
            describe: PinVaultBridge.describe,
            callbacks: ReactNetworking.Callbacks(
                didSendData: didSendData,
                didReceiveResponse: didReceiveResponse,
                didReceiveData: didReceiveData,
                didComplete: { didComplete($0.map { $0 as NSError }) }
            )
        )
    }
}
