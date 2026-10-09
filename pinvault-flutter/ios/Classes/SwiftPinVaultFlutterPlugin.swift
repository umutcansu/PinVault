import Flutter
import UIKit
import PinVault

public class SwiftPinVaultFlutterPlugin: NSObject, FlutterPlugin {
  private var activeSockets: [String: URLSessionWebSocketTask] = [:]
  private let registrar: FlutterPluginRegistrar

  init(registrar: FlutterPluginRegistrar) {
    self.registrar = registrar
  }

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "pinvault_flutter", binaryMessenger: registrar.messenger())
    let instance = SwiftPinVaultFlutterPlugin(registrar: registrar)
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    if call.method == "start" {
      // TODO: Parse config from call.arguments
      // let config = PinVaultConfig(builder: ...)
      // do {
      //     try PinVault.shared.start(config: config)
      //     result(["type": "ready", "version": 1])
      // } catch {
      //     result(FlutterError(code: "E_START", message: error.localizedDescription, details: nil))
      // }
      result(["type": "ready", "version": 1])
    } else if call.method == "fetch" {
      // TODO: Execute HTTP request using PinVault.shared.session()
      result(["status": 200, "body": "Success"])
    } else if call.method == "ws_connect" {
      guard let args = call.arguments as? [String: Any],
            let socketId = args["socketId"] as? String,
            let urlString = args["url"] as? String,
            let url = URL(string: urlString) else {
          result(FlutterError(code: "INVALID_ARGS", message: "Missing socketId or url", details: nil))
          return
      }
      setupWebSocket(socketId: socketId, url: url)
      result(nil)
    } else {
      result(FlutterMethodNotImplemented)
    }
  }

  private func setupWebSocket(socketId: String, url: URL) {
      let eventChannel = FlutterEventChannel(name: "pinvault_flutter/ws/\(socketId)/events", binaryMessenger: registrar.messenger())
      
      let streamHandler = WebSocketStreamHandler(socketId: socketId, url: url, plugin: self)
      eventChannel.setStreamHandler(streamHandler)
  }
}

class WebSocketStreamHandler: NSObject, FlutterStreamHandler {
    let socketId: String
    let url: URL
    weak var plugin: SwiftPinVaultFlutterPlugin?
    var task: URLSessionWebSocketTask?

    init(socketId: String, url: URL, plugin: SwiftPinVaultFlutterPlugin) {
        self.socketId = socketId
        self.url = url
        self.plugin = plugin
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        let request = URLRequest(url: url)
        
        // Ensure we use the session protected by PinVault!
        do {
            let session = try PinVault.shared.session()
            task = session.webSocketTask(with: request)
            
            task?.resume()
            receiveMessages(events: events)
        } catch {
            events(["type": "error", "error": error.localizedDescription])
        }
        
        return nil
    }

    private func receiveMessages(events: @escaping FlutterEventSink) {
        task?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    events(["type": "message", "data": text])
                case .data(_):
                    // Handle binary data if needed
                    break
                @unknown default:
                    break
                }
                self?.receiveMessages(events: events) // Continue listening
            case .failure(let error):
                events(["type": "error", "error": error.localizedDescription])
            }
        }
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        task?.cancel(with: .normalClosure, reason: nil)
        return nil
    }
}
