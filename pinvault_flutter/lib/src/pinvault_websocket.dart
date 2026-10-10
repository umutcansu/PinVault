import 'dart:async';

import 'package:flutter/services.dart';

/// OWASP MASVS compliant WebSocket.
/// Delegates the whole `wss://` connection to the native layer (OkHttp /
/// URLSessionWebSocketTask over the pinned client), so the TLS session and the
/// mTLS identity keys stay strictly within native memory. Fail closed: only
/// `wss://` is accepted, and every error surfaces on [messages].
class PinVaultWebSocket {
  final MethodChannel _methodChannel;
  final EventChannel _eventChannel;

  final String socketId;
  final String url;

  StreamSubscription<dynamic>? _eventSubscription;
  final StreamController<dynamic> _messageController =
      StreamController.broadcast();

  /// Text and binary messages. A frame is a [String] (text) or a [Uint8List] (binary).
  /// Connection errors are delivered through this stream's error handler.
  Stream<dynamic> get messages => _messageController.stream;

  /// Completes when the peer (or this side) closed the connection.
  Future<dynamic> get done => _messageController.done;

  PinVaultWebSocket._(this.socketId, this.url)
    : _methodChannel = MethodChannel('pinvault_flutter/ws/$socketId/methods'),
      _eventChannel = EventChannel('pinvault_flutter/ws/$socketId/events');

  static int _counter = 0;

  /// Connects to a WSS endpoint. Fails closed if the URL is not `wss://`.
  static Future<PinVaultWebSocket> connect(
    String url, {
    Map<String, String>? headers,
  }) async {
    if (!url.startsWith('wss://')) {
      throw PinVaultWebSocketError(
        'Security Violation: only wss:// is allowed by PinVault.',
      );
    }
    if (headers != null) {
      for (final entry in headers.entries) {
        if (entry.value.contains('\r') || entry.value.contains('\n')) {
          throw PinVaultWebSocketError(
            'headers.${entry.key}: line breaks are not allowed',
          );
        }
      }
    }

    // A monotonic counter, not the wall clock: two sockets in the same millisecond
    // must never share an id (the id names their method/event channels).
    final socketId = '${DateTime.now().microsecondsSinceEpoch}-${_counter++}';
    const methodChannel = MethodChannel('pinvault_flutter');

    try {
      await methodChannel.invokeMethod<void>('ws_connect', {
        'socketId': socketId,
        'url': url,
        'headers': headers ?? const <String, String>{},
      });
    } on PlatformException catch (e) {
      throw PinVaultWebSocketError(e.message ?? 'WebSocket connect failed');
    }

    final socket = PinVaultWebSocket._(socketId, url);
    socket._initListener();
    return socket;
  }

  void _initListener() {
    _eventSubscription = _eventChannel.receiveBroadcastStream().listen(
      (event) {
        final map = Map<String, dynamic>.from(event as Map);
        switch (map['type']) {
          case 'message':
            _messageController.add(map['data']);
          case 'closed':
            _closeInternal();
          case 'error':
            _messageController.addError(
              PinVaultWebSocketError(
                map['error'] as String? ?? 'WebSocket error',
              ),
            );
        }
      },
      onError: (Object e) {
        _messageController.addError(PinVaultWebSocketError(e.toString()));
      },
      onDone: () {
        _closeInternal();
      },
    );
  }

  /// Sends a text frame.
  Future<void> send(String data) =>
      _methodChannel.invokeMethod<void>('send', {'data': data});

  /// Sends a binary frame.
  Future<void> sendBytes(Uint8List data) =>
      _methodChannel.invokeMethod<void>('send', {'data': data, 'binary': true});

  /// Closes the connection (normal closure, code 1000 by default).
  Future<void> close([int code = 1000, String? reason]) async {
    try {
      await _methodChannel.invokeMethod<void>('close', {
        'code': code,
        'reason': reason,
      });
    } finally {
      _closeInternal();
    }
  }

  void _closeInternal() {
    _eventSubscription?.cancel();
    _eventSubscription = null;
    if (!_messageController.isClosed) {
      _messageController.close();
    }
  }
}

/// A refused or failed WebSocket operation. Never carries TLS material.
class PinVaultWebSocketError implements Exception {
  final String message;
  PinVaultWebSocketError(this.message);

  @override
  String toString() => 'PinVaultWebSocketError: $message';
}
