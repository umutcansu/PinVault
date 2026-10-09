import 'dart:async';
import 'package:flutter/services.dart';

/// OWASP MASVS compliant WebSocket.
/// Delegates wss:// connection entirely to the Native layer (OkHttp/URLSession).
/// Keeps TLS and mTLS keys strictly within native memory.
class PinVaultWebSocket {
  final MethodChannel _methodChannel;
  final EventChannel _eventChannel;
  
  final String socketId;
  final String url;

  StreamSubscription? _eventSubscription;
  final StreamController<dynamic> _messageController = StreamController.broadcast();

  Stream<dynamic> get messages => _messageController.stream;

  PinVaultWebSocket._(this.socketId, this.url)
      : _methodChannel = MethodChannel('pinvault_flutter/ws/$socketId/methods'),
        _eventChannel = EventChannel('pinvault_flutter/ws/$socketId/events');

  /// Connects to a WSS endpoint. Will fail if URL is not wss:// to enforce Fail-Closed security.
  static Future<PinVaultWebSocket> connect(String url, {Map<String, String>? headers}) async {
    if (!url.startsWith('wss://')) {
      throw Exception('Security Violation: Only wss:// is allowed by PinVault.');
    }
    
    // Request native to establish connection
    final String socketId = DateTime.now().millisecondsSinceEpoch.toString();
    final methodChannel = const MethodChannel('pinvault_flutter');
    
    await methodChannel.invokeMethod('ws_connect', {
      'socketId': socketId,
      'url': url,
      'headers': headers ?? {},
    });

    final socket = PinVaultWebSocket._(socketId, url);
    socket._initListener();
    return socket;
  }

  void _initListener() {
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen((event) {
      final map = Map<String, dynamic>.from(event);
      if (map['type'] == 'message') {
        _messageController.add(map['data']);
      } else if (map['type'] == 'closed') {
        _closeInternal();
      } else if (map['type'] == 'error') {
        _messageController.addError(Exception(map['error']));
      }
    });
  }

  Future<void> send(dynamic data) async {
    await _methodChannel.invokeMethod('send', {'data': data});
  }

  Future<void> close([int code = 1000, String? reason]) async {
    await _methodChannel.invokeMethod('close', {
      'code': code,
      'reason': reason,
    });
    _closeInternal();
  }

  void _closeInternal() {
    _eventSubscription?.cancel();
    if (!_messageController.isClosed) {
      _messageController.close();
    }
  }
}
