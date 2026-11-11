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

  test('subprotocols go to the native side as a checked list', () async {
    Map<Object?, Object?>? sent;
    messenger.setMockMethodCallHandler(const MethodChannel('pinvault_flutter'), (call) async {
      sent = call.arguments as Map<Object?, Object?>;
      return null;
    });
    await PinVaultWebSocket.connect('wss://h.example/', protocols: ['graphql-transport-ws', 'v2.chat']);
    expect(sent!['protocols'], ['graphql-transport-ws', 'v2.chat']);
    await PinVaultWebSocket.connect('wss://h.example/');
    expect(sent!.containsKey('protocols'), isFalse);

    sent = null;
    for (final bad in [
      ['a, b'], ['a b'], [''], ['a\r\nX-Injected: 1'], ['ä'], ['a;q=1'], ['a', 'a'],
      ['x' * 65], List.generate(9, (i) => 'p$i'),
    ]) {
      await expectLater(
        PinVaultWebSocket.connect('wss://h.example/', protocols: bad),
        throwsA(isA<PinVaultWebSocketError>().having((e) => e.message, 'message', startsWith('protocols:'))),
        reason: '$bad',
      );
    }
    expect(sent, isNull, reason: 'refused before the native side is asked');
  });

  test('connect refuses the headers the HTTP client and the handshake set', () async {
    var asked = 0;
    messenger.setMockMethodCallHandler(const MethodChannel('pinvault_flutter'), (call) async {
      asked++;
      return null;
    });
    for (final name in [
      'Host', 'host', 'Connection', 'Keep-Alive', 'Proxy-Connection', 'TE', 'Trailer',
      'Transfer-Encoding', 'Upgrade', 'Content-Length',
      'Sec-WebSocket-Key', 'sec-websocket-protocol', 'Sec-WebSocket-Extensions',
    ]) {
      await expectLater(
        PinVaultWebSocket.connect('wss://h.example/', headers: {name: 'v'}),
        throwsA(isA<PinVaultWebSocketError>().having((e) => e.message, 'message', contains(name))),
        reason: name,
      );
    }
    expect(asked, 0, reason: 'refused before the native side is asked');
  });
}
