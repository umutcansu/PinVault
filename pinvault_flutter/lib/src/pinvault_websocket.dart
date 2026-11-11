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
  /// A connection error is delivered through this stream's error handler and
  /// ends the stream: a failed socket is closed, never reused.
  Stream<dynamic> get messages => _messageController.stream;

  /// Completes when the connection ended: closed by either side, or failed.
  Future<dynamic> get done => _messageController.done;

  PinVaultWebSocket._(this.socketId, this.url)
    : _methodChannel = MethodChannel('pinvault_flutter/ws/$socketId/methods'),
      _eventChannel = EventChannel('pinvault_flutter/ws/$socketId/events');

  static int _counter = 0;

  /// Connects to a WSS endpoint. Fails closed if the URL is not `wss://`.
  ///
  /// [protocols] are the subprotocols to ask for (`Sec-WebSocket-Protocol`,
  /// which [headers] may not carry): at most 8 tokens of at most 64
  /// characters, none twice. Which one the server picked is not reported.
  static Future<PinVaultWebSocket> connect(
    String url, {
    Map<String, String>? headers,
    List<String>? protocols,
  }) async {
    if (!url.startsWith('wss://')) {
      throw PinVaultWebSocketError(
        'Security Violation: only wss:// is allowed by PinVault.',
      );
    }
    if (headers != null) {
      for (final entry in headers.entries) {
        if (!_headerName.hasMatch(entry.key)) {
          throw PinVaultWebSocketError(
            'headers: "${entry.key}" is not a valid header name',
          );
        }
        final name = entry.key.toLowerCase();
        if (_libraryHeaders.contains(name)) {
          throw PinVaultWebSocketError(
            'headers: "${entry.key}" is set by PinVault itself (a token host\'s socket carries it)',
          );
        }
        // The upgrade is an HTTP request on the pinned connection: the headers
        // `PinVault.fetch` refuses are refused here too (the native side checks again).
        if (_clientHeaders.contains(name)) {
          throw PinVaultWebSocketError(
            'headers: "${entry.key}" is set by the HTTP client (host, connection and framing headers)',
          );
        }
        if (name.startsWith('sec-websocket-')) {
          throw PinVaultWebSocketError(
            'headers: "${entry.key}" is set by the WebSocket handshake',
          );
        }
        if (entry.value.contains('\r') || entry.value.contains('\n')) {
          throw PinVaultWebSocketError(
            'headers.${entry.key}: line breaks are not allowed',
          );
        }
      }
    }

    if (protocols != null) {
      if (protocols.length > 8) {
        throw PinVaultWebSocketError('protocols: at most 8');
      }
      for (final name in protocols) {
        // A token: no comma, space or control character can add a second value.
        if (name.length > 64 || !_headerName.hasMatch(name)) {
          throw PinVaultWebSocketError(
            'protocols: each must be a token (RFC 7230) of at most 64 characters',
          );
        }
      }
      if (protocols.toSet().length != protocols.length) {
        throw PinVaultWebSocketError('protocols: an entry is listed twice');
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
        if (protocols != null && protocols.isNotEmpty) 'protocols': protocols,
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
        if (_messageController.isClosed) return;
        final map = Map<String, dynamic>.from(event as Map);
        switch (map['type']) {
          case 'message':
            _messageController.add(map['data']);
          case 'closed':
            _closeInternal();
          case 'error':
            // Both natives report a failure once, as the socket's last event.
            _fail(map['error'] as String? ?? 'WebSocket error');
        }
      },
      onError: (Object e) => _fail(e.toString()),
      onDone: _closeInternal,
    );
  }

  /// Sends a text frame.
  Future<void> send(String data) =>
      _invoke('send', {'data': data});

  /// Sends a binary frame.
  Future<void> sendBytes(Uint8List data) =>
      _invoke('send', {'data': data, 'binary': true});

  /// Closes the connection (normal closure, code 1000 by default). A no-op once it has ended.
  Future<void> close([int code = 1000, String? reason]) async {
    if (_messageController.isClosed) return;
    try {
      await _invoke('close', {'code': code, 'reason': reason});
    } finally {
      _closeInternal();
    }
  }

  Future<void> _invoke(String method, Map<String, Object?> arguments) async {
    try {
      await _methodChannel.invokeMethod<void>(method, arguments);
    } on PlatformException catch (e) {
      throw PinVaultWebSocketError(e.message ?? 'WebSocket $method failed');
    } on MissingPluginException {
      // The native side dropped this socket's channels: it has ended.
      throw PinVaultWebSocketError('WebSocket is closed');
    }
  }

  void _fail(String message) {
    if (_messageController.isClosed) return;
    _messageController.addError(PinVaultWebSocketError(message));
    _closeInternal();
  }

  /// Ends the Dart side; cancelling the event stream makes the native side
  /// close the socket and drop its channels.
  void _closeInternal() {
    _eventSubscription?.cancel();
    _eventSubscription = null;
    if (!_messageController.isClosed) {
      _messageController.close();
    }
  }
}

// RFC 9110 token: what OkHttp and URLSession accept as a header name.
final RegExp _headerName = RegExp(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$");

/// The attestation headers: only the library sets them, for its token hosts.
const Set<String> _libraryHeaders = {'pinvault-token', 'pinvault-proof'};

/// The HTTP client's own headers (the native `PinnedFetch` list, lower case):
/// the host the URL names, the connection and the body's framing.
const Set<String> _clientHeaders = {
  'host',
  'connection',
  'keep-alive',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-length',
};

/// A refused or failed WebSocket operation. Never carries TLS material.
class PinVaultWebSocketError implements Exception {
  final String message;
  PinVaultWebSocketError(this.message);

  @override
  String toString() => 'PinVaultWebSocketError: $message';
}
