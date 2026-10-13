import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pinvault_flutter/pinvault_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  /// Answers ws_connect and hands back the sink of the socket's event channel.
  Future<(PinVaultWebSocket, MockStreamHandlerEventSink, List<String>)> connect() async {
    final cancelled = <String>[];
    MockStreamHandlerEventSink? sink;
    String? socketId;
    messenger.setMockMethodCallHandler(const MethodChannel('pinvault_flutter'), (call) async {
      if (call.method != 'ws_connect') return null;
      socketId = (call.arguments as Map)['socketId'] as String;
      messenger.setMockStreamHandler(
        EventChannel('pinvault_flutter/ws/$socketId/events'),
        MockStreamHandler.inline(
          onListen: (_, events) => sink = events,
          onCancel: (_) => cancelled.add(socketId!),
        ),
      );
      return null;
    });
    final socket = await PinVaultWebSocket.connect('wss://h.example/ws');
    await pumpEventQueue();
    return (socket, sink!, cancelled);
  }

  test('a failure is delivered once and ends the socket', () async {
    final (socket, sink, cancelled) = await connect();
    final errors = <Object>[];
    socket.messages.listen(null, onError: errors.add);

    sink.success({'type': 'error', 'error': 'SSLPeerUnverifiedException: pin mismatch'});
    await socket.done.timeout(const Duration(seconds: 1));
    expect(errors.single, isA<PinVaultWebSocketError>());
    expect(cancelled, hasLength(1)); // the native side is told to let go

    sink.success({'type': 'closed'}); // a late native event changes nothing
    await pumpEventQueue();
    await socket.close(); // a no-op once ended
  });

  test('a close from the peer completes done', () async {
    final (socket, sink, _) = await connect();
    final frames = <Object?>[];
    socket.messages.listen(frames.add);

    sink.success({'type': 'message', 'data': 'hello'});
    sink.success({'type': 'closed', 'code': 1000, 'reason': ''});
    await socket.done.timeout(const Duration(seconds: 1));
    expect(frames, ['hello']);
  });

  test('connect refuses non-wss URLs and bad header names', () async {
    expect(() => PinVaultWebSocket.connect('ws://h.example/'), throwsA(isA<PinVaultWebSocketError>()));
    expect(() => PinVaultWebSocket.connect('wss://h.example/', headers: {'Bad Name': 'v'}),
        throwsA(isA<PinVaultWebSocketError>()));
    expect(() => PinVaultWebSocket.connect('wss://h.example/', headers: {'X-Token': 'a\r\nb'}),
        throwsA(isA<PinVaultWebSocketError>()));
    expect(() => PinVaultWebSocket.connect('wss://h.example/', headers: {'PinVault-Token': 't'}),
        throwsA(isA<PinVaultWebSocketError>()));
    expect(() => PinVaultWebSocket.connect('wss://h.example/', headers: {'pinvault-proof': 'p'}),
        throwsA(isA<PinVaultWebSocketError>()));
  });
}
